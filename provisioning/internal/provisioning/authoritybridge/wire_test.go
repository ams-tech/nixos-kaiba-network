package authoritybridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

func TestUnixBridgeRoundTripReturnsRevalidatedBoundExecution(t *testing.T) {
	fixture := newBridgeFixture(t)
	socketPath, stop := startBridgeServer(t, fixedBinder(fixture, fixture.records))
	defer stop()
	execution, err := Request(context.Background(), socketPath, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Plan.PlanDigest != fixture.request.DraftSnapshot.PlanDigest ||
		execution.Request.IntentReceipt != fixture.intentReceiptID || execution.Request.Sequence != 1 {
		t.Fatalf("wire execution = %#v / %#v", execution.Plan, execution.Request)
	}
	encoded, err := json.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"rpiboot", "gpio", "uart", "executable", "artifact_path", "device_selector"} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
			t.Fatalf("wire request contains forbidden selector %q", forbidden)
		}
	}
}

func TestUnixBridgeSharedGroupSocketPermissions(t *testing.T) {
	fixture := newBridgeFixture(t)
	directory := shortTempDir(t)
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "shared.sock")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	binder := fixedBinder(fixture, fixture.records)
	go func() {
		result <- Serve(ctx, ServerConfig{
			SocketPath: socketPath, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
			DirectoryMode: 0o750, SocketMode: 0o660, Binder: &binder, ErrorLog: io.Discard,
		})
	}()
	waitForSocket(t, socketPath, result)
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o660 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		t.Fatalf("shared socket mode/owner = %04o %d:%d", info.Mode().Perm(), stat.Uid, stat.Gid)
	}
	if _, err := Request(context.Background(), socketPath, fixture.request); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
}

func TestUnixBridgeRejectsUnsafeSocketModePairs(t *testing.T) {
	for _, modes := range [][2]os.FileMode{{0o700, 0o660}, {0o750, 0o600}, {0o755, 0o666}, {0o750 | os.ModeSetgid, 0o660}} {
		if err := validateSocketModes(modes[0], modes[1]); err == nil {
			t.Fatalf("validateSocketModes(%04o, %04o) accepted unsafe pair", modes[0], modes[1])
		}
	}
}

func TestUnixBridgeRejectsMalformedOversizedAndReconcileInputs(t *testing.T) {
	fixture := newBridgeFixture(t)
	socketPath, stop := startBridgeServer(t, fixedBinder(fixture, fixture.records))
	defer stop()
	valid, err := json.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := fixture.request
	reconcile.Mode = ModeReconcile
	reconcileJSON, err := json.Marshal(reconcile)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body []byte
		code string
	}{
		{name: "empty", body: nil, code: ErrorCodeInvalidRequest},
		{name: "malformed", body: []byte(`{"schema_version":`), code: ErrorCodeInvalidRequest},
		{name: "trailing", body: append(append([]byte(nil), valid...), []byte(` {}`)...), code: ErrorCodeInvalidRequest},
		{name: "unknown field", body: bytes.Replace(valid, []byte(`"mode"`), []byte(`"unknown":true,"mode"`), 1), code: ErrorCodeInvalidRequest},
		{name: "duplicate field", body: bytes.Replace(valid, []byte(`"mode":"execute"`), []byte(`"mode":"execute","mode":"execute"`), 1), code: ErrorCodeInvalidRequest},
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxWireRequestBytes+1), code: ErrorCodeInvalidRequest},
		{name: "reconciliation", body: reconcileJSON, code: ErrorCodeReconciliationUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := rawBridgeRequest(t, socketPath, test.body)
			if response.Status != responseStatusError || response.ErrorCode != test.code || response.Plan != nil || response.Request != nil {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestClientRejectsMalformedOversizedOrMismatchedSuccess(t *testing.T) {
	fixture := newBridgeFixture(t)
	execution, err := fixedBinder(fixture, fixture.records).Bind(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	valid := BridgeResponse{
		SchemaVersion: ResponseSchemaVersion, Status: responseStatusOK,
		Plan: &execution.Plan, Request: &execution.Request,
	}
	tests := []struct {
		name string
		body func() []byte
	}{
		{name: "duplicate response field", body: func() []byte {
			encoded, _ := json.Marshal(valid)
			return bytes.Replace(encoded, []byte(`"status":"ok"`), []byte(`"status":"ok","status":"ok"`), 1)
		}},
		{name: "oversized response", body: func() []byte { return bytes.Repeat([]byte("x"), maxWireResponseBytes+1) }},
		{name: "changed operation request", body: func() []byte {
			changed := valid
			request := *valid.Request
			request.OperationDigest = bridgeDigest("f")
			changed.Request = &request
			encoded, _ := json.Marshal(changed)
			return encoded
		}},
		{name: "changed plan body", body: func() []byte {
			changed := valid
			plan := *valid.Plan
			plan.Operations = append([]laneguard.OperationSpec(nil), valid.Plan.Operations...)
			plan.Operations[0].MaximumDuration++
			changed.Plan = &plan
			encoded, _ := json.Marshal(changed)
			return encoded
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath, closeServer := startFixedResponseServer(t, test.body())
			defer closeServer()
			if _, err := Request(context.Background(), socketPath, fixture.request); err == nil {
				t.Fatal("Request() accepted invalid response")
			}
		})
	}
}

func TestClientRejectsUnknownOrMalformedErrorResponse(t *testing.T) {
	fixture := newBridgeFixture(t)
	tests := []BridgeResponse{
		{SchemaVersion: ResponseSchemaVersion, Status: responseStatusError, ErrorCode: "invented"},
		{SchemaVersion: ResponseSchemaVersion, Status: responseStatusError, ErrorCode: ErrorCodeAuthorityRejected, Plan: &fixture.request.DraftSnapshot},
		{SchemaVersion: "other", Status: responseStatusError, ErrorCode: ErrorCodeAuthorityRejected},
	}
	for index, response := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			socketPath, closeServer := startFixedResponseServer(t, encoded)
			defer closeServer()
			if _, err := Request(context.Background(), socketPath, fixture.request); err == nil {
				t.Fatal("Request() accepted malformed error response")
			}
		})
	}
}

func TestClientReturnsTypedBridgeDenial(t *testing.T) {
	fixture := newBridgeFixture(t)
	response := errorResponse(ErrorCodeAuthorityChanged)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, closeServer := startFixedResponseServer(t, encoded)
	defer closeServer()
	_, err = Request(context.Background(), socketPath, fixture.request)
	var denial BridgeError
	if !errors.As(err, &denial) || denial.Code != ErrorCodeAuthorityChanged {
		t.Fatalf("Request() error = %v", err)
	}
}

func TestClientDeadlineBoundsAStalledSocket(t *testing.T) {
	fixture := newBridgeFixture(t)
	directory := shortTempDir(t)
	socketPath := filepath.Join(directory, "stall.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Request(ctx, socketPath, fixture.request); err == nil {
		t.Fatal("Request() did not time out against a stalled bridge")
	}
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("stalled server did not accept the client")
	}
}

func TestClientRoundTripBudgetCoversAllSequentialAuthorityReads(t *testing.T) {
	minimum := authorityReadsPerBinding * AuthorityReadTimeout
	if wireRoundTripTimeout <= minimum {
		t.Fatalf("wire round-trip timeout %s does not exceed authority-read budget %s", wireRoundTripTimeout, minimum)
	}
}

func startBridgeServer(t *testing.T, binder Binder) (string, func()) {
	t.Helper()
	directory := shortTempDir(t)
	socketPath := filepath.Join(directory, "bridge.sock")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, ServerConfig{
			SocketPath: socketPath, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
			DirectoryMode: 0o700, SocketMode: 0o600, Binder: &binder, ErrorLog: io.Discard,
		})
	}()
	waitForSocket(t, socketPath, result)
	stop := func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve() did not stop")
		}
	}
	return socketPath, stop
}

func rawBridgeRequest(t *testing.T, socketPath string, body []byte) BridgeResponse {
	t.Helper()
	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	unixConnection := connection.(*net.UnixConn)
	if len(body) != 0 {
		if _, err := unixConnection.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := unixConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	responseBytes, err := io.ReadAll(unixConnection)
	_ = unixConnection.Close()
	if err != nil {
		t.Fatal(err)
	}
	var response BridgeResponse
	if err := decodeStrict(responseBytes, &response); err != nil {
		t.Fatalf("decode server response: %v; body=%q", err, responseBytes)
	}
	return response
}

func startFixedResponseServer(t *testing.T, response []byte) (string, func()) {
	t.Helper()
	directory := shortTempDir(t)
	socketPath := filepath.Join(directory, "response.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		_, _ = io.ReadAll(connection)
		_, _ = connection.Write(response)
		result <- connection.Close()
	}()
	closeServer := func() {
		_ = listener.Close()
		select {
		case err := <-result:
			if err != nil && !strings.Contains(err.Error(), "closed") {
				t.Errorf("fixed response server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("fixed response server did not stop")
		}
	}
	return socketPath, closeServer
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "kab-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove short socket directory: %v", err)
		}
	})
	return directory
}

func waitForSocket(t *testing.T, socketPath string, result <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("Serve() stopped before creating socket: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("authority bridge socket did not appear")
		}
		time.Sleep(time.Millisecond)
	}
}
