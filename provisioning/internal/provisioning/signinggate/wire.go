package signinggate

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
	"path/filepath"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	WireResponseSchemaV1Alpha2 = "kaiba.provisioning.signing-gate-response/v1alpha2"
	maxWireResponseBytes       = 16 * 1024
	wireReadTimeout            = 30 * time.Second
)

type WireResponse struct {
	SchemaVersion       string        `json:"schema_version"`
	Status              string        `json:"status"`
	SignatureHex        string        `json:"signature_hex,omitempty"`
	ReceiptDigest       bundle.Digest `json:"receipt_digest,omitempty"`
	ReleaseIntentDigest bundle.Digest `json:"release_intent_digest,omitempty"`
	ErrorCode           string        `json:"error_code,omitempty"`
}

type ServerConfig struct {
	SocketPath string
	OwnerUID   uint32
	Gate       *Gate
	ErrorLog   io.Writer
}

type deadlineConnection interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
}

// Serve accepts raw artifact bytes over a fixed Unix socket. There is no
// request metadata channel through which a client could choose a role, grant,
// key, PKCS#11 URI, executable, backend argument, or backend path.
func Serve(ctx context.Context, config ServerConfig) error {
	if config.Gate == nil || config.ErrorLog == nil {
		return errors.New("signing gate server requires a gate and error log")
	}
	if err := validateSocketPath(config.SocketPath); err != nil {
		return err
	}
	if err := validateManagedDirectory(filepath.Dir(config.SocketPath), config.OwnerUID, true); err != nil {
		return fmt.Errorf("signing socket directory: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on signing socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	defer listener.Close()
	if err := os.Chmod(config.SocketPath, 0o600); err != nil {
		return fmt.Errorf("restrict signing socket: %w", err)
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept signing client: %w", err)
		}
		handleConnection(ctx, connection, config.Gate, config.ErrorLog)
	}
}

func handleConnection(ctx context.Context, connection deadlineConnection, gate *Gate, errorLog io.Writer) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(wireReadTimeout))
	artifact, err := io.ReadAll(io.LimitReader(connection, int64(signing.MaxArtifactBytes)+1))
	_ = connection.SetReadDeadline(time.Time{})
	if err != nil || len(artifact) == 0 || len(artifact) > signing.MaxArtifactBytes {
		if err != nil {
			fmt.Fprintf(errorLog, "read signing client artifact: %v\n", err)
		}
		_ = writeWireResponse(connection, WireResponse{
			SchemaVersion: WireResponseSchemaV1Alpha2,
			Status:        "error",
			ErrorCode:     "invalid_artifact",
		})
		return
	}
	result, err := gate.Sign(ctx, artifact)
	if err != nil {
		fmt.Fprintf(errorLog, "deny signing request for %s: %v\n", bundle.Sum(artifact), err)
		_ = writeWireResponse(connection, WireResponse{
			SchemaVersion: WireResponseSchemaV1Alpha2,
			Status:        "error",
			ErrorCode:     "signing_denied",
		})
		return
	}
	if err := writeWireResponse(connection, WireResponse{
		SchemaVersion:       WireResponseSchemaV1Alpha2,
		Status:              "ok",
		SignatureHex:        result.SignatureHex,
		ReceiptDigest:       result.ReceiptDigest,
		ReleaseIntentDigest: result.ReleaseIntentDigest,
	}); err != nil {
		fmt.Fprintf(errorLog, "write signing response: %v\n", err)
	}
}

func writeWireResponse(output io.Writer, response WireResponse) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

// RequestSignature sends exactly artifact bytes to the fixed gate socket and
// returns the gate-approved signature and durable receipt digest.
func RequestSignature(ctx context.Context, socketPath string, artifact []byte) (Result, error) {
	if err := validateSocketPath(socketPath); err != nil {
		return Result{}, err
	}
	if len(artifact) == 0 || len(artifact) > signing.MaxArtifactBytes {
		return Result{}, fmt.Errorf("artifact size must be between 1 and %d bytes", signing.MaxArtifactBytes)
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Result{}, fmt.Errorf("connect to signing gate: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return Result{}, errors.New("signing gate connection is not a Unix socket")
	}
	defer unixConnection.Close()
	if _, err := io.Copy(unixConnection, bytes.NewReader(artifact)); err != nil {
		return Result{}, fmt.Errorf("send artifact to signing gate: %w", err)
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return Result{}, fmt.Errorf("finish signing gate request: %w", err)
	}
	responseBytes, err := io.ReadAll(io.LimitReader(unixConnection, maxWireResponseBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read signing gate response: %w", err)
	}
	if len(responseBytes) == 0 || len(responseBytes) > maxWireResponseBytes {
		return Result{}, errors.New("signing gate response has invalid size")
	}
	return parseWireResponse(responseBytes)
}

func parseWireResponse(responseBytes []byte) (Result, error) {
	var response WireResponse
	if err := strictDecode(responseBytes, &response); err != nil {
		return Result{}, fmt.Errorf("decode signing gate response: %w", err)
	}
	if response.SchemaVersion != WireResponseSchemaV1Alpha2 {
		return Result{}, fmt.Errorf("unsupported signing gate response schema_version %q", response.SchemaVersion)
	}
	if response.Status == "error" {
		if response.SignatureHex != "" || response.ReceiptDigest != "" || response.ReleaseIntentDigest != "" || response.ErrorCode == "" {
			return Result{}, errors.New("signing gate returned a malformed error response")
		}
		if response.ErrorCode != "invalid_artifact" && response.ErrorCode != "signing_denied" {
			return Result{}, errors.New("signing gate returned an unknown error code")
		}
		return Result{}, fmt.Errorf("signing gate denied request: %s", response.ErrorCode)
	}
	if response.Status != "ok" || response.ErrorCode != "" {
		return Result{}, errors.New("signing gate returned an invalid status")
	}
	signature, err := signing.ParseSignatureHex([]byte(response.SignatureHex))
	if err != nil {
		return Result{}, fmt.Errorf("signing gate signature: %w", err)
	}
	if hex.EncodeToString(signature) != response.SignatureHex {
		return Result{}, errors.New("signing gate signature is not canonical lowercase hexadecimal")
	}
	if err := response.ReceiptDigest.Validate(); err != nil {
		return Result{}, fmt.Errorf("signing gate receipt digest: %w", err)
	}
	if err := response.ReleaseIntentDigest.Validate(); err != nil {
		return Result{}, fmt.Errorf("signing gate release-intent digest: %w", err)
	}
	return Result{
		SignatureHex:        response.SignatureHex,
		ReceiptDigest:       response.ReceiptDigest,
		ReleaseIntentDigest: response.ReleaseIntentDigest,
		Replayed:            false,
		GrantID:             "",
	}, nil
}

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("signing gate socket path must be absolute and clean")
	}
	if len(path) > 100 || bytes.IndexByte([]byte(path), 0) >= 0 {
		return errors.New("signing gate socket path is invalid")
	}
	return nil
}
