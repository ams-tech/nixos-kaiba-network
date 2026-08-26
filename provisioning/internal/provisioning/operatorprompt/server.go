package operatorprompt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

var (
	ErrPromptActive  = errors.New("an operator prompt is already active")
	ErrPromptExpired = errors.New("operator prompt expired")
	ErrPromptReplay  = errors.New("operator prompt acknowledgement was already attempted")
	ErrServerClosed  = errors.New("operator prompt server is closed")
)

// PeerCredentialsFunc reads kernel-authenticated credentials for an accepted
// Unix-stream peer. Config.PeerCredentials is an injectable test seam; normal
// callers must leave it nil to use SO_PEERCRED.
type PeerCredentialsFunc func(*net.UnixConn) (laneguard.OperatorPeer, error)

type Config struct {
	SocketPath        string
	AllowedPrimaryGID uint32
	PeerCredentials   PeerCredentialsFunc
}

type socketIdentity struct {
	device uint64
	inode  uint64
}

type activePrompt struct {
	prompt      Prompt
	result      chan Acknowledgement
	closeOnce   sync.Once
	connections map[*net.UnixConn]struct{}
	accepted    bool
}

func (active *activePrompt) closeConnections() {
	active.closeOnce.Do(func() {
		for connection := range active.connections {
			_ = connection.Close()
		}
	})
}

// Server owns one reusable private AF_UNIX listener. Exactly one Prompt may be
// active at a time; connections arriving outside that window are rejected.
type Server struct {
	config   Config
	listener *net.UnixListener
	identity socketIdentity

	mu       sync.Mutex
	active   *activePrompt
	closed   bool
	closedCh chan struct{}
	closeOne sync.Once
	wait     sync.WaitGroup
}

// Listen creates a mode-0660 socket owned by the server UID and the fixed
// allowed primary GID. Its parent must already be a non-symlink 0750 directory
// with the same UID/GID; Listen never removes a pre-existing path.
func Listen(config Config) (*Server, error) {
	if err := validateSocketPath(config.SocketPath); err != nil {
		return nil, err
	}
	if config.PeerCredentials == nil {
		config.PeerCredentials = systemPeerCredentials
	}
	if err := validateSocketDirectory(filepath.Dir(config.SocketPath), uint32(os.Geteuid()), config.AllowedPrimaryGID); err != nil {
		return nil, fmt.Errorf("operator socket directory: %w", err)
	}
	if _, err := os.Lstat(config.SocketPath); err == nil {
		return nil, errors.New("operator socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect operator socket path: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on operator socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	cleanup := func() {
		_ = listener.Close()
		if info, statErr := os.Lstat(config.SocketPath); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(config.SocketPath)
		}
	}
	if err := os.Chown(config.SocketPath, os.Geteuid(), int(config.AllowedPrimaryGID)); err != nil {
		cleanup()
		return nil, fmt.Errorf("set operator socket ownership: %w", err)
	}
	if err := os.Chmod(config.SocketPath, 0o660); err != nil {
		cleanup()
		return nil, fmt.Errorf("set operator socket mode: %w", err)
	}
	identity, err := validateCreatedSocket(config.SocketPath, uint32(os.Geteuid()), config.AllowedPrimaryGID)
	if err != nil {
		cleanup()
		return nil, err
	}
	server := &Server{
		config: config, listener: listener, identity: identity,
		closedCh: make(chan struct{}),
	}
	server.wait.Add(1)
	go server.acceptLoop()
	return server, nil
}

// Present exposes prompt until one authenticated peer acknowledges it, the
// context ends, the prompt expires, or the server closes.
func (server *Server) Present(ctx context.Context, prompt Prompt) (Acknowledgement, error) {
	if err := prompt.Validate(); err != nil {
		return Acknowledgement{}, err
	}
	if err := context.Cause(ctx); err != nil {
		return Acknowledgement{}, err
	}
	now := time.Now().UTC()
	if !now.Before(prompt.ExpiresAt) {
		return Acknowledgement{}, ErrPromptExpired
	}
	active := &activePrompt{
		prompt: prompt, result: make(chan Acknowledgement, 1),
		connections: make(map[*net.UnixConn]struct{}),
	}
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return Acknowledgement{}, ErrServerClosed
	}
	if server.active != nil {
		server.mu.Unlock()
		return Acknowledgement{}, ErrPromptActive
	}
	server.active = active
	server.mu.Unlock()

	defer server.retire(active)
	timer := time.NewTimer(time.Until(prompt.ExpiresAt))
	defer timer.Stop()
	select {
	case acknowledgement := <-active.result:
		return acknowledgement, nil
	case <-ctx.Done():
		return Acknowledgement{}, context.Cause(ctx)
	case <-timer.C:
		return Acknowledgement{}, ErrPromptExpired
	case <-server.closedCh:
		return Acknowledgement{}, ErrServerClosed
	}
}

func (server *Server) retire(active *activePrompt) {
	server.mu.Lock()
	if server.active == active {
		server.active = nil
	}
	active.closeConnections()
	server.mu.Unlock()
}

func (server *Server) acceptLoop() {
	defer server.wait.Done()
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			server.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		server.wait.Add(1)
		go func() {
			defer server.wait.Done()
			server.handle(connection)
		}()
	}
}

func (server *Server) handle(connection *net.UnixConn) {
	defer connection.Close()
	peer, err := server.config.PeerCredentials(connection)
	if err != nil || peer.PID <= 0 || peer.GID != server.config.AllowedPrimaryGID {
		_ = writeFrame(connection, errorFrame(errorUnauthorized))
		return
	}

	server.mu.Lock()
	active := server.active
	if active == nil || active.accepted {
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorNoActive))
		return
	}
	if !time.Now().UTC().Before(active.prompt.ExpiresAt) {
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorExpired))
		return
	}
	active.connections[connection] = struct{}{}
	prompt := active.prompt
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		delete(active.connections, connection)
		server.mu.Unlock()
	}()

	if err := writeFrame(connection, wireFrame{SchemaVersion: wireSchemaVersion, Type: framePrompt, Prompt: &prompt}); err != nil {
		return
	}
	frame, err := readFinalFrame(connection, prompt.ExpiresAt)
	if err != nil || frame.Type != frameAck {
		_ = writeFrame(connection, errorFrame(errorInvalid))
		return
	}

	server.mu.Lock()
	now := time.Now().UTC()
	switch {
	case server.active != active:
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorReplay))
		return
	case active.accepted:
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorReplay))
		return
	case !now.Before(prompt.ExpiresAt):
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorExpired))
		return
	case frame.PromptID != prompt.ID || frame.PromptDigest != prompt.Digest:
		server.mu.Unlock()
		_ = writeFrame(connection, errorFrame(errorMismatch))
		return
	}
	acknowledgement := Acknowledgement{
		SchemaVersion: AcknowledgementSchemaVersion,
		PromptID:      prompt.ID, PromptDigest: prompt.Digest, Peer: peer, AcknowledgedAt: now,
	}
	active.accepted = true
	server.active = nil
	server.mu.Unlock()

	_ = writeFrame(connection, wireFrame{SchemaVersion: wireSchemaVersion, Type: frameResult, Acknowledgement: &acknowledgement})
	active.result <- acknowledgement
}

func errorFrame(code string) wireFrame {
	return wireFrame{SchemaVersion: wireSchemaVersion, Type: frameError, ErrorCode: code}
}

// Close stops accepting clients, releases any waiter, and removes only the
// socket inode created by this Server. It is safe to call more than once.
func (server *Server) Close() error {
	var closeErr error
	server.closeOne.Do(func() {
		server.mu.Lock()
		server.closed = true
		close(server.closedCh)
		if server.active != nil {
			server.active.closeConnections()
			server.active = nil
		}
		server.mu.Unlock()
		closeErr = server.listener.Close()
		server.wait.Wait()
		if err := removeOwnedSocket(server.config.SocketPath, server.identity); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	})
	return closeErr
}

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || strings.IndexByte(path, 0) >= 0 {
		return errors.New("operator socket path must be a clean, short absolute path")
	}
	return nil
}

func validateSocketDirectory(path string, uid, gid uint32) error {
	evaluated, err := filepath.EvalSymlinks(path)
	if err != nil || evaluated != path {
		return errors.New("operator socket directory must not contain symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 || stat.Uid != uid || stat.Gid != gid {
		return errors.New("operator socket directory must be a non-symlink 0750 directory owned by the server UID and allowed GID")
	}
	return nil
}

func validateCreatedSocket(path string, uid, gid uint32) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return socketIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || stat.Uid != uid || stat.Gid != gid {
		return socketIdentity{}, errors.New("created operator path is not the configured private Unix socket")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func removeOwnedSocket(path string, identity socketIdentity) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || uint64(stat.Dev) != identity.device || stat.Ino != identity.inode {
		return errors.New("operator socket path changed; refusing cleanup")
	}
	return os.Remove(path)
}
