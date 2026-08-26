package operatorprompt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Client is a single received-prompt session. Acknowledge accepts no caller
// fields: it sends only the ID and digest retained from the server frame.
type Client struct {
	connection *net.UnixConn
	prompt     Prompt
	mu         sync.Mutex
	attempted  bool
}

// Connect receives the server-selected active prompt from one clean absolute
// Unix socket. It does not accept an action, operation, phase, mode, or selector.
func Connect(ctx context.Context, socketPath string) (*Client, error) {
	if err := validateSocketPath(socketPath); err != nil {
		return nil, err
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		return nil, fmt.Errorf("inspect operator socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		return nil, errors.New("operator endpoint is not a mode-0660 Unix socket")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to operator prompt server: %w", contextOrError(ctx, err))
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("operator prompt connection is not a Unix socket")
	}
	stopContextWatch := context.AfterFunc(ctx, func() {
		_ = unixConnection.SetDeadline(time.Now())
	})
	defer stopContextWatch()
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	frame, err := readInitialFrame(unixConnection, deadline)
	if err != nil {
		_ = unixConnection.Close()
		return nil, contextOrError(ctx, err)
	}
	if frame.Type == frameError {
		_ = unixConnection.Close()
		return nil, RemoteError{Code: frame.ErrorCode}
	}
	if frame.Type != framePrompt || frame.Prompt == nil || !time.Now().UTC().Before(frame.Prompt.ExpiresAt) {
		_ = unixConnection.Close()
		return nil, ErrPromptExpired
	}
	return &Client{connection: unixConnection, prompt: *frame.Prompt}, nil
}

func (client *Client) Prompt() Prompt { return client.prompt }

// Acknowledge sends the exact received binding once and returns the
// kernel-authenticated peer evidence recorded by the server.
func (client *Client) Acknowledge(ctx context.Context) (Acknowledgement, error) {
	client.mu.Lock()
	if client.attempted {
		client.mu.Unlock()
		return Acknowledgement{}, ErrPromptReplay
	}
	client.attempted = true
	client.mu.Unlock()
	stopContextWatch := context.AfterFunc(ctx, func() {
		_ = client.connection.SetDeadline(time.Now())
	})
	defer stopContextWatch()
	deadline := client.prompt.ExpiresAt
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if !time.Now().Before(deadline) {
		return Acknowledgement{}, ErrPromptExpired
	}
	if err := client.connection.SetDeadline(deadline); err != nil {
		return Acknowledgement{}, contextOrError(ctx, err)
	}
	frame := wireFrame{
		SchemaVersion: wireSchemaVersion, Type: frameAck,
		PromptID: client.prompt.ID, PromptDigest: client.prompt.Digest,
	}
	if err := writeFrame(client.connection, frame); err != nil {
		return Acknowledgement{}, contextOrError(ctx, err)
	}
	if err := client.connection.CloseWrite(); err != nil {
		return Acknowledgement{}, contextOrError(ctx, err)
	}
	response, err := readFinalFrame(client.connection, deadline)
	if err != nil {
		return Acknowledgement{}, contextOrError(ctx, err)
	}
	if response.Type == frameError {
		return Acknowledgement{}, RemoteError{Code: response.ErrorCode}
	}
	if response.Type != frameResult || response.Acknowledgement == nil {
		return Acknowledgement{}, errors.New("operator prompt server returned an invalid result")
	}
	if err := response.Acknowledgement.validateFor(client.prompt); err != nil {
		return Acknowledgement{}, err
	}
	return *response.Acknowledgement, nil
}

func (client *Client) Close() error { return client.connection.Close() }

func contextOrError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return err
}
