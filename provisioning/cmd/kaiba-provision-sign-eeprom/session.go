package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	maxSessionResponseBytes = 4096
	maxCommandOutputBytes   = 64 * 1024
	sessionIOTimeout        = 2 * time.Minute
)

type runtimeConfig struct {
	GateSocketPath                 string
	UpdaterExecutablePath          string
	ExtractorExecutablePath        string
	FixedToolPATH                  string
	WrapperExecutablePath          string
	ExpectedEEPROMReleaseDigest    bundle.Digest
	ExpectedOriginalEEPROMDigest   bundle.Digest
	ExpectedOriginalRecoveryDigest bundle.Digest
	ExpectedOriginalBootcodeDigest bundle.Digest
	ExpectedOriginalBootsysDigest  bundle.Digest
	ExpectedFirmwareBuildEpoch     uint64
}

type hsmCallback func(context.Context, []byte) (string, error)

type updateInvocation struct {
	WorkDir         string
	SourceDateEpoch uint64
	SignRecovery    bool
	Config          runtimeConfig
}

type updaterRunner func(context.Context, updateInvocation, hsmCallback) error
type wrapperClient func(context.Context, string, []byte) (string, error)

type sessionResponse struct {
	SignatureHex string `json:"signature_hex,omitempty"`
	Error        string `json:"error,omitempty"`
}

func runHiddenWrapper(
	ctx context.Context,
	inputPath string,
	stdout io.Writer,
	getenv func(string) string,
	client wrapperClient,
) error {
	if ctx == nil || stdout == nil || getenv == nil || client == nil {
		return errors.New("invalid private signing-session configuration")
	}
	socketPath := getenv(sessionSocketEnvironment)
	if err := validatePrivateSocketPath(socketPath); err != nil {
		return err
	}
	artifact, err := readWrapperInput(inputPath)
	if err != nil {
		return fmt.Errorf("read signing input: %w", err)
	}
	signatureHex, err := client(ctx, socketPath, artifact)
	if err != nil {
		return err
	}
	signature, err := signing.ParseSignatureHex([]byte(signatureHex))
	if err != nil {
		return fmt.Errorf("private signing session returned an invalid signature: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "%x\n", signature); err != nil {
		return fmt.Errorf("write HSM-wrapper signature: %w", err)
	}
	return nil
}

func readWrapperInput(path string) ([]byte, error) {
	if filepath.IsAbs(path) {
		return readAbsoluteRegularFile(path, maxComponentBytes)
	}
	// The pinned rpi-eeprom-digest invokes the wrapper with the literal
	// relative path boot.conf; rpi-sign-bootcode uses absolute temporary paths.
	// No other relative namespace is accepted.
	if path == "" || filepath.Base(path) != path || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("relative signing input must be one plain filename")
	}
	directory, err := os.OpenFile(".", os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return readRegularFileAt(directory, path, maxComponentBytes)
}

func productionWrapperClient(ctx context.Context, socketPath string, artifact []byte) (string, error) {
	if ctx == nil {
		return "", errors.New("private signing session requires a context")
	}
	if err := validatePrivateSocketPath(socketPath); err != nil {
		return "", err
	}
	if err := validatePrivateSocketEndpoint(socketPath); err != nil {
		return "", err
	}
	if len(artifact) == 0 || len(artifact) > maxComponentBytes {
		return "", errors.New("private signing-session artifact has an invalid size")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to private signing session: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return "", errors.New("private signing session is not a Unix socket")
	}
	defer unixConnection.Close()
	if err := unixConnection.SetDeadline(time.Now().Add(sessionIOTimeout)); err != nil {
		return "", err
	}
	if _, err := io.Copy(unixConnection, bytes.NewReader(artifact)); err != nil {
		return "", fmt.Errorf("send private signing-session input: %w", err)
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return "", fmt.Errorf("finish private signing-session input: %w", err)
	}
	encoded, err := io.ReadAll(io.LimitReader(unixConnection, maxSessionResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read private signing-session response: %w", err)
	}
	response, err := parseSessionResponse(encoded)
	if err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", errors.New(response.Error)
	}
	return response.SignatureHex, nil
}

func parseSessionResponse(encoded []byte) (sessionResponse, error) {
	if len(encoded) == 0 || len(encoded) > maxSessionResponseBytes {
		return sessionResponse{}, errors.New("private signing-session response has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var response sessionResponse
	if err := decoder.Decode(&response); err != nil {
		return sessionResponse{}, fmt.Errorf("decode private signing-session response: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return sessionResponse{}, fmt.Errorf("decode private signing-session response: %w", err)
		}
		return sessionResponse{}, fmt.Errorf("private signing-session response has trailing JSON value %v", token)
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		return sessionResponse{}, fmt.Errorf("encode canonical private signing-session response: %w", err)
	}
	if !bytes.Equal(encoded, canonical.Bytes()) {
		return sessionResponse{}, errors.New("private signing-session response is not canonical JSON")
	}
	if (response.SignatureHex == "") == (response.Error == "") {
		return sessionResponse{}, errors.New("private signing-session response must contain exactly one result")
	}
	if response.Error != "" {
		if len(response.Error) > 512 || strings.ContainsAny(response.Error, "\r\n\x00") {
			return sessionResponse{}, errors.New("private signing-session error is malformed")
		}
		return response, nil
	}
	signature, err := signing.ParseSignatureHex([]byte(response.SignatureHex))
	if err != nil {
		return sessionResponse{}, fmt.Errorf("private signing-session signature: %w", err)
	}
	if hex.EncodeToString(signature) != response.SignatureHex {
		return sessionResponse{}, errors.New("private signing-session signature is not canonical")
	}
	return response, nil
}

func productionUpdater(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
	if ctx == nil || callback == nil {
		return errors.New("updater requires a context and signing callback")
	}
	if err := validateRuntimeConfig(invocation.Config); err != nil {
		return err
	}
	if invocation.SourceDateEpoch == 0 {
		return errors.New("updater SOURCE_DATE_EPOCH must be fixed")
	}
	if err := validateExistingAbsolutePath(invocation.WorkDir); err != nil {
		return fmt.Errorf("updater work directory: %w", err)
	}
	workInfo, err := os.Lstat(invocation.WorkDir)
	workStat, statOK := workInfoSys(workInfo)
	if err != nil || !workInfo.IsDir() || workInfo.Mode()&os.ModeSymlink != 0 || workInfo.Mode().Perm()&0o077 != 0 || !statOK || workStat.Uid != uint32(os.Geteuid()) {
		return errors.New("updater work directory must be an owner-only, owned, non-symlink directory")
	}
	temporaryDirectory := filepath.Join(invocation.WorkDir, "tmp")
	if err := os.Mkdir(temporaryDirectory, 0o700); err != nil {
		return fmt.Errorf("create updater temporary directory: %w", err)
	}
	socketPath := filepath.Join(invocation.WorkDir, "signing.sock")
	if err := validatePrivateSocketPath(socketPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen for private updater callbacks: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("restrict private updater callback socket: %w", err)
	}

	sessionContext, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- servePrivateSession(sessionContext, listener, callback)
	}()

	arguments := updaterArguments(invocation.Config, invocation.SignRecovery)
	command := exec.CommandContext(ctx, invocation.Config.UpdaterExecutablePath, arguments...)
	command.Dir = invocation.WorkDir
	command.Env = updaterEnvironment(invocation.Config, invocation.SourceDateEpoch, temporaryDirectory, socketPath)
	command.WaitDelay = 2 * time.Second
	var stdout, stderr cappedBuffer
	stdout.maximum = maxCommandOutputBytes
	stderr.maximum = maxCommandOutputBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	commandError := command.Run()
	cancelSession()
	_ = listener.Close()
	serverError := <-serverDone
	if commandError != nil {
		return fmt.Errorf("pinned update-pieeprom failed: %w (stdout %q, stderr %q)", commandError, stdout.String(), stderr.String())
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("pinned update-pieeprom output exceeded %d bytes", maxCommandOutputBytes)
	}
	if serverError != nil {
		return fmt.Errorf("private updater callback session: %w", serverError)
	}
	return nil
}

func workInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func servePrivateSession(ctx context.Context, listener *net.UnixListener, callback hsmCallback) error {
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := handlePrivateSessionConnection(ctx, connection, callback); err != nil {
			return err
		}
	}
}

func handlePrivateSessionConnection(ctx context.Context, connection *net.UnixConn, callback hsmCallback) error {
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(sessionIOTimeout)); err != nil {
		return err
	}
	artifact, err := io.ReadAll(io.LimitReader(connection, maxComponentBytes+1))
	if err != nil || len(artifact) == 0 || len(artifact) > maxComponentBytes {
		return writeSessionResponse(connection, sessionResponse{Error: "private signing session rejected the input"})
	}
	signatureHex, callbackError := callback(ctx, artifact)
	if callbackError != nil {
		message := callbackError.Error()
		if len(message) > 512 || strings.ContainsAny(message, "\r\n\x00") {
			message = "private signing session denied the request"
		}
		return writeSessionResponse(connection, sessionResponse{Error: message})
	}
	signature, err := signing.ParseSignatureHex([]byte(signatureHex))
	if err != nil || hex.EncodeToString(signature) != signatureHex {
		return writeSessionResponse(connection, sessionResponse{Error: "private signing session produced an invalid signature"})
	}
	return writeSessionResponse(connection, sessionResponse{SignatureHex: signatureHex})
}

func writeSessionResponse(output io.Writer, response sessionResponse) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

func updaterArguments(config runtimeConfig, signRecovery bool) []string {
	mode := "-f"
	if signRecovery {
		mode = "-fr"
	}
	return []string{
		mode,
		"-c", "boot.conf",
		"-i", "pieeprom.original.bin",
		"-o", "pieeprom.bin",
		"-p", "public.pem",
		"-H", config.WrapperExecutablePath,
	}
}

func updaterEnvironment(config runtimeConfig, epoch uint64, temporaryDirectory, socketPath string) []string {
	return []string{
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"PATH=" + config.FixedToolPATH,
		"SOURCE_DATE_EPOCH=" + strconv.FormatUint(epoch, 10),
		"TMPDIR=" + temporaryDirectory,
		sessionSocketEnvironment + "=" + socketPath,
	}
}

func validateRuntimeConfig(config runtimeConfig) error {
	for label, path := range map[string]string{
		"signing gate socket":  config.GateSocketPath,
		"updater executable":   config.UpdaterExecutablePath,
		"extractor executable": config.ExtractorExecutablePath,
		"wrapper executable":   config.WrapperExecutablePath,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
			return fmt.Errorf("linker-fixed %s path must be absolute and clean", label)
		}
	}
	if config.FixedToolPATH == "" || strings.IndexByte(config.FixedToolPATH, 0) >= 0 {
		return errors.New("linker-fixed tool PATH is invalid")
	}
	for _, directory := range strings.Split(config.FixedToolPATH, ":") {
		if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
			return errors.New("every linker-fixed tool PATH entry must be absolute and clean")
		}
	}
	if err := config.ExpectedEEPROMReleaseDigest.Validate(); err != nil {
		return fmt.Errorf("linker-fixed expected EEPROM release digest: %w", err)
	}
	for label, digest := range map[string]bundle.Digest{
		"original EEPROM":   config.ExpectedOriginalEEPROMDigest,
		"original recovery": config.ExpectedOriginalRecoveryDigest,
		"original bootcode": config.ExpectedOriginalBootcodeDigest,
		"original bootsys":  config.ExpectedOriginalBootsysDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("linker-fixed expected %s digest: %w", label, err)
		}
	}
	if config.ExpectedFirmwareBuildEpoch == 0 {
		return errors.New("linker-fixed expected EEPROM firmware build epoch is invalid")
	}
	return nil
}

func validatePrivateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || strings.IndexByte(path, 0) >= 0 {
		return errors.New("private signing-session socket path must be absolute, clean, and short")
	}
	return nil
}

func validatePrivateSocketEndpoint(path string) error {
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("private signing-session directory: %w", err)
	}
	parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 || !parentOK || parentStat.Uid != uint32(os.Geteuid()) {
		return errors.New("private signing-session directory must be owned by this user and inaccessible to other users")
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("private signing-session socket: %w", err)
	}
	socketStat, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode()&os.ModeSymlink != 0 || socketInfo.Mode().Perm()&0o077 != 0 || !socketOK || socketStat.Uid != uint32(os.Geteuid()) {
		return errors.New("private signing-session endpoint must be an owner-only Unix socket")
	}
	return nil
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *cappedBuffer) Write(contents []byte) (int, error) {
	if buffer.maximum <= 0 {
		return 0, errors.New("invalid command-output limit")
	}
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return len(contents), nil
	}
	if len(contents) > remaining {
		_, _ = buffer.buffer.Write(contents[:remaining])
		buffer.overflow = true
		return len(contents), nil
	}
	_, _ = buffer.buffer.Write(contents)
	return len(contents), nil
}

func (buffer *cappedBuffer) String() string {
	text := buffer.buffer.String()
	if buffer.overflow {
		return text + "[truncated]"
	}
	return text
}
