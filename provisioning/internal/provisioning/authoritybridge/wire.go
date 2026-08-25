package authoritybridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

const (
	maxWireRequestBytes      = 1 << 20
	maxWireResponseBytes     = 1 << 20
	wireReadTimeout          = 15 * time.Second
	wireResponseWriteTimeout = 30 * time.Second
	authorityReadsPerBinding = 3 // control, audit, then control again to freeze authority
	wireRoundTripTimeout     = authorityReadsPerBinding*AuthorityReadTimeout + 15*time.Second

	responseStatusOK    = "ok"
	responseStatusError = "error"
)

const (
	ErrorCodeInvalidRequest           = "invalid_request"
	ErrorCodeAuthorityUnavailable     = "authority_unavailable"
	ErrorCodeAuthorityChanged         = "authority_changed"
	ErrorCodeAuthorityRecordMissing   = "authority_record_missing"
	ErrorCodeAuthorityRecordDuplicate = "authority_record_duplicate"
	ErrorCodeAuthorityRejected        = "authority_rejected"
	ErrorCodeInternal                 = "internal"
)

type BridgeResponse struct {
	SchemaVersion    string                      `json:"schema_version"`
	Status           string                      `json:"status"`
	Plan             *laneguard.Plan             `json:"plan,omitempty"`
	ExecuteRequest   *laneguard.ExecuteRequest   `json:"execute_request,omitempty"`
	ReconcileRequest *laneguard.ReconcileRequest `json:"reconcile_request,omitempty"`
	ErrorCode        string                      `json:"error_code,omitempty"`
}

type ServerConfig struct {
	SocketPath    string
	OwnerUID      uint32
	OwnerGID      uint32
	DirectoryMode os.FileMode
	SocketMode    os.FileMode
	Binder        *Binder
	ErrorLog      io.Writer
}

// Serve exposes one strictly bounded request per Unix-stream connection. The
// socket is private to its managed directory; no network listener exists.
func Serve(ctx context.Context, config ServerConfig) error {
	if config.Binder == nil || config.ErrorLog == nil {
		return errors.New("authority bridge server requires a binder and error log")
	}
	if err := validateSocketPath(config.SocketPath); err != nil {
		return err
	}
	if err := validateSocketModes(config.DirectoryMode, config.SocketMode); err != nil {
		return err
	}
	if err := validateSocketDirectory(filepath.Dir(config.SocketPath), config.OwnerUID, config.OwnerGID, config.DirectoryMode); err != nil {
		return fmt.Errorf("authority bridge socket directory: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on authority bridge socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	defer listener.Close()
	if err := os.Chmod(config.SocketPath, config.SocketMode); err != nil {
		return fmt.Errorf("restrict authority bridge socket: %w", err)
	}
	if err := validateCreatedSocket(config.SocketPath, config.OwnerUID, config.OwnerGID, config.SocketMode); err != nil {
		return fmt.Errorf("authority bridge socket: %w", err)
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept authority bridge client: %w", err)
		}
		handleConnection(ctx, connection, config.Binder, config.ErrorLog)
	}
}

func handleConnection(ctx context.Context, connection *net.UnixConn, binder *Binder, errorLog io.Writer) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(wireReadTimeout))
	requestBytes, err := io.ReadAll(io.LimitReader(connection, maxWireRequestBytes+1))
	_ = connection.SetReadDeadline(time.Time{})
	if err != nil || len(requestBytes) == 0 || len(requestBytes) > maxWireRequestBytes {
		if err != nil {
			fmt.Fprintf(errorLog, "read authority bridge request: %v\n", err)
		}
		writeResponse(connection, errorResponse(ErrorCodeInvalidRequest), errorLog)
		return
	}
	var request BridgeRequest
	if err := decodeStrict(requestBytes, &request); err != nil {
		fmt.Fprintf(errorLog, "reject malformed authority bridge request: %v\n", err)
		writeResponse(connection, errorResponse(ErrorCodeInvalidRequest), errorLog)
		return
	}
	binding, err := binder.Bind(ctx, request)
	if err != nil {
		fmt.Fprintf(errorLog, "deny authority bridge request for transaction %q: %v\n", request.TransactionID, err)
		writeResponse(connection, errorResponse(errorCode(err)), errorLog)
		return
	}
	writeResponse(connection, BridgeResponse{
		SchemaVersion:    ResponseSchemaVersion,
		Status:           responseStatusOK,
		Plan:             &binding.Plan,
		ExecuteRequest:   binding.ExecuteRequest,
		ReconcileRequest: binding.ReconcileRequest,
	}, errorLog)
}

func writeResponse(connection *net.UnixConn, response BridgeResponse, errorLog io.Writer) {
	encoded, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(errorLog, "encode authority bridge response: %v\n", err)
		return
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxWireResponseBytes {
		fmt.Fprintln(errorLog, "authority bridge response exceeds its fixed limit")
		return
	}
	_ = connection.SetWriteDeadline(time.Now().Add(wireResponseWriteTimeout))
	if _, err := io.Copy(connection, bytes.NewReader(encoded)); err != nil {
		fmt.Fprintf(errorLog, "write authority bridge response: %v\n", err)
	}
}

func errorResponse(code string) BridgeResponse {
	return BridgeResponse{SchemaVersion: ResponseSchemaVersion, Status: responseStatusError, ErrorCode: code}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return ErrorCodeInvalidRequest
	case errors.Is(err, ErrAuthorityChanged):
		return ErrorCodeAuthorityChanged
	case errors.Is(err, ErrAuthorityRecordMissing):
		return ErrorCodeAuthorityRecordMissing
	case errors.Is(err, ErrAuthorityRecordDuplicate):
		return ErrorCodeAuthorityRecordDuplicate
	case errors.Is(err, ErrAuthoritySource):
		return ErrorCodeAuthorityUnavailable
	case errors.Is(err, ErrAuthorityRejected):
		return ErrorCodeAuthorityRejected
	default:
		return ErrorCodeInternal
	}
}

// Request obtains one freshly authority-bound execution from the fixed Unix
// socket. It revalidates both the authority-free plan body and the complete
// lane-guard plan/request binding before returning.
func Request(ctx context.Context, socketPath string, request BridgeRequest) (BoundRequest, error) {
	if err := validateSocketPath(socketPath); err != nil {
		return BoundRequest{}, err
	}
	if err := validateBridgeRequest(request); err != nil {
		return BoundRequest{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("encode authority bridge request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxWireRequestBytes {
		return BoundRequest{}, ErrInvalidRequest
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("connect to authority bridge: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return BoundRequest{}, errors.New("authority bridge connection is not a Unix socket")
	}
	defer unixConnection.Close()
	deadline := time.Now().Add(wireRoundTripTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := unixConnection.SetDeadline(deadline); err != nil {
		return BoundRequest{}, fmt.Errorf("set authority bridge deadline: %w", err)
	}
	if _, err := io.Copy(unixConnection, bytes.NewReader(encoded)); err != nil {
		return BoundRequest{}, fmt.Errorf("send authority bridge request: %w", err)
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return BoundRequest{}, fmt.Errorf("finish authority bridge request: %w", err)
	}
	responseBytes, err := io.ReadAll(io.LimitReader(unixConnection, maxWireResponseBytes+1))
	if err != nil {
		return BoundRequest{}, fmt.Errorf("read authority bridge response: %w", err)
	}
	if len(responseBytes) == 0 || len(responseBytes) > maxWireResponseBytes {
		return BoundRequest{}, errors.New("authority bridge response has invalid size")
	}
	var response BridgeResponse
	if err := decodeStrict(responseBytes, &response); err != nil {
		return BoundRequest{}, fmt.Errorf("decode authority bridge response: %w", err)
	}
	return validateResponse(response, request)
}

func validateResponse(response BridgeResponse, source BridgeRequest) (BoundRequest, error) {
	if response.SchemaVersion != ResponseSchemaVersion {
		return BoundRequest{}, fmt.Errorf("unsupported authority bridge response schema %q", response.SchemaVersion)
	}
	switch response.Status {
	case responseStatusError:
		if response.Plan != nil || response.ExecuteRequest != nil || response.ReconcileRequest != nil || !knownErrorCode(response.ErrorCode) {
			return BoundRequest{}, errors.New("authority bridge returned a malformed error response")
		}
		return BoundRequest{}, BridgeError{Code: response.ErrorCode}
	case responseStatusOK:
		if response.Plan == nil || response.ErrorCode != "" || (response.ExecuteRequest == nil) == (response.ReconcileRequest == nil) {
			return BoundRequest{}, errors.New("authority bridge returned a malformed success response")
		}
	default:
		return BoundRequest{}, errors.New("authority bridge returned an invalid status")
	}
	binding := BoundRequest{Plan: *response.Plan, ExecuteRequest: response.ExecuteRequest, ReconcileRequest: response.ReconcileRequest}
	if err := validateBoundRequest(binding, source); err != nil {
		return BoundRequest{}, fmt.Errorf("reject authority bridge binding: %w", err)
	}
	return binding, nil
}

type BridgeError struct{ Code string }

func (err BridgeError) Error() string { return "authority bridge denied request: " + err.Code }

func knownErrorCode(code string) bool {
	switch code {
	case ErrorCodeInvalidRequest, ErrorCodeAuthorityUnavailable,
		ErrorCodeAuthorityChanged, ErrorCodeAuthorityRecordMissing, ErrorCodeAuthorityRecordDuplicate,
		ErrorCodeAuthorityRejected, ErrorCodeInternal:
		return true
	default:
		return false
	}
}

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || bytes.IndexByte([]byte(path), 0) >= 0 {
		return errors.New("authority bridge socket path must be a clean, short absolute path")
	}
	return nil
}

func validateSocketModes(directoryMode, socketMode os.FileMode) error {
	if directoryMode != directoryMode.Perm() || socketMode != socketMode.Perm() {
		return errors.New("authority bridge socket modes must contain permission bits only")
	}
	private := directoryMode == 0o700 && socketMode == 0o600
	sharedGroup := directoryMode == 0o750 && socketMode == 0o660
	if !private && !sharedGroup {
		return errors.New("authority bridge socket modes must be private 0700/0600 or shared-group 0750/0660")
	}
	return nil
}

func validateSocketDirectory(path string, ownerUID, ownerGID uint32, expectedMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != expectedMode {
		return errors.New("socket directory must be a non-symlink directory with the configured mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != ownerGID {
		return errors.New("socket directory has the wrong owner or group")
	}
	return nil
}

func validateCreatedSocket(path string, ownerUID, ownerGID uint32, expectedMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != expectedMode {
		return errors.New("created path is not a Unix socket with the configured mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != ownerGID {
		return errors.New("created socket has the wrong owner or group")
	}
	return nil
}
