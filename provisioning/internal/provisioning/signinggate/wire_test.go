package signinggate

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

type memoryDeadlineConnection struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *memoryDeadlineConnection) Read(data []byte) (int, error)   { return c.input.Read(data) }
func (c *memoryDeadlineConnection) Write(data []byte) (int, error)  { return c.output.Write(data) }
func (c *memoryDeadlineConnection) Close() error                    { return nil }
func (c *memoryDeadlineConnection) SetReadDeadline(time.Time) error { return nil }

func TestConnectionHandlerAcceptsOnlyRawArtifactBytes(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "memory", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &inspectingBackend{store: store, grant: grant}
	gate := testGate(t, testRegistry(t, grant), store, backend)
	connection := &memoryDeadlineConnection{input: bytes.NewReader(artifact)}
	var errorLog bytes.Buffer
	handleConnection(context.Background(), connection, gate, &errorLog)
	if errorLog.Len() != 0 {
		t.Fatalf("error log = %q", errorLog.String())
	}
	result, err := parseWireResponse(connection.output.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result.SignatureHex == "" || result.ReceiptDigest == "" || result.ReleaseIntentDigest != grant.Request.Approval.ReleaseIntentDigest || backend.calls != 2 {
		t.Fatalf("result/backend = %#v/%d", result, backend.calls)
	}
	if _, err := io.ReadAll(connection.input); err != nil {
		t.Fatal(err)
	}
}

func TestUnixBridgeSendsOnlyArtifactAndReturnsSignature(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "wire", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &inspectingBackend{store: store, grant: grant}
	gate := testGate(t, testRegistry(t, grant), store, backend)
	socketDirectory := t.TempDir()
	if err := os.Chmod(socketDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketDirectory, "signing.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var errorLog bytes.Buffer
	go func() {
		done <- Serve(ctx, ServerConfig{
			SocketPath: socketPath,
			OwnerUID:   uint32(os.Getuid()),
			Gate:       gate,
			ErrorLog:   &errorLog,
		})
	}()
	waitForSocket(t, socketPath, done)

	first, err := RequestSignature(context.Background(), socketPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RequestSignature(context.Background(), socketPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if first.SignatureHex != second.SignatureHex || first.ReceiptDigest != second.ReceiptDigest || first.ReleaseIntentDigest != grant.Request.Approval.ReleaseIntentDigest || second.ReleaseIntentDigest != first.ReleaseIntentDigest || backend.calls != 2 {
		t.Fatalf("wire replay = %#v/%#v, calls=%d", first, second, backend.calls)
	}
	if _, err := signing.ParseSignatureHex([]byte(first.SignatureHex)); err != nil {
		t.Fatal(err)
	}
	if errorLog.Len() != 0 {
		t.Fatalf("server error log = %q", errorLog.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestUnixBridgeRejectsBytesWithoutGrant(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "wire", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &signing.DeterministicFakeBackend{}
	gate := testGate(t, testRegistry(t, grant), store, backend)
	socketDirectory := t.TempDir()
	if err := os.Chmod(socketDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketDirectory, "signing.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var errorLog bytes.Buffer
	go func() {
		done <- Serve(ctx, ServerConfig{
			SocketPath: socketPath, OwnerUID: uint32(os.Getuid()), Gate: gate, ErrorLog: &errorLog,
		})
	}()
	waitForSocket(t, socketPath, done)
	if _, err := RequestSignature(context.Background(), socketPath, []byte("different artifact")); err == nil || !strings.Contains(err.Error(), "signing_denied") {
		t.Fatalf("unapproved request error = %v", err)
	}
	if backend.Calls != 0 || !strings.Contains(errorLog.String(), "no current signing grant") {
		t.Fatalf("backend/log = %d/%q", backend.Calls, errorLog.String())
	}
}

func waitForSocket(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-done:
			if err != nil && strings.Contains(err.Error(), "operation not permitted") {
				t.Skip("Unix sockets are blocked by this test sandbox")
			}
			t.Fatalf("server exited before socket was ready: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("signing socket was not created")
}
