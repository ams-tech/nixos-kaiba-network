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
	if execution.Plan.PlanDigest != fixture.request.DraftSnapshot.PlanDigest || execution.ExecuteRequest == nil ||
		execution.ExecuteRequest.IntentReceipt != fixture.intentReceiptID || execution.ExecuteRequest.Sequence != 1 ||
		execution.ExecuteRequest.RequiredBootMode != laneguard.BootModeRPIBoot {
		t.Fatalf("wire execution = %#v / %#v", execution.Plan, execution.ExecuteRequest)
	}
	encoded, err := json.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"required_boot_mode":"rpiboot"`)) {
		t.Fatalf("wire request omitted digest-bound boot policy: %s", encoded)
	}
	for _, forbidden := range []string{
		`"executable"`, `"executable_path"`, `"artifact_path"`, `"bundle_path"`,
		`"device_selector"`, `"rpiboot_sysfs_path"`, `"usb_path"`, `"usb_selector"`,
		`"power_gpio"`, `"gpio"`, `"uart_path"`, `"uart_selector"`,
		`/nix/store/`, `/sys/`, `/dev/`,
	} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
			t.Fatalf("wire request contains forbidden selector %q", forbidden)
		}
	}
}

func TestUnixBridgeRoundTripReturnsOnlyReconciliationAuthority(t *testing.T) {
	fixture := newReconciliationBridgeFixture(t, "station-reconcile", "lane-reconcile")
	socketPath, stop := startBridgeServer(t, fixedBinder(fixture, fixture.records))
	defer stop()
	binding, err := Request(context.Background(), socketPath, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if binding.ExecuteRequest != nil || binding.ReconcileRequest == nil ||
		binding.ReconcileRequest.Claim.ClaimID != fixture.transaction.ActiveClaim.ID ||
		binding.ReconcileRequest.OriginalRequest.IntentReceipt != fixture.intentReceiptID {
		t.Fatalf("wire reconciliation = %#v", binding)
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
		{name: "caller boot selector", body: injectBridgeField(valid, `"required_boot_mode":"normal"`), code: ErrorCodeInvalidRequest},
		{name: "caller executable path", body: injectBridgeField(valid, `"executable_path":"/tmp/rpiboot"`), code: ErrorCodeInvalidRequest},
		{name: "caller bundle path", body: injectBridgeField(valid, `"bundle_path":"/tmp/bundle"`), code: ErrorCodeInvalidRequest},
		{name: "caller USB selector", body: injectBridgeField(valid, `"rpiboot_sysfs_path":"/sys/bus/usb/devices/9-9"`), code: ErrorCodeInvalidRequest},
		{name: "caller GPIO selector", body: injectBridgeField(valid, `"power_gpio":"/dev/gpiochip9:2"`), code: ErrorCodeInvalidRequest},
		{name: "caller UART selector", body: injectBridgeField(valid, `"uart_path":"/dev/serial/by-id/caller"`), code: ErrorCodeInvalidRequest},
		{name: "duplicate field", body: bytes.Replace(valid, []byte(`"mode":"execute"`), []byte(`"mode":"execute","mode":"execute"`), 1), code: ErrorCodeInvalidRequest},
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxWireRequestBytes+1), code: ErrorCodeInvalidRequest},
		{name: "reconciliation without claim", body: reconcileJSON, code: ErrorCodeAuthorityRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := rawBridgeRequest(t, socketPath, test.body)
			if response.Status != responseStatusError || response.ErrorCode != test.code || response.Plan != nil || response.ExecuteRequest != nil || response.ReconcileRequest != nil {
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
		Plan: &execution.Plan, ExecuteRequest: execution.ExecuteRequest,
	}
	tests := []struct {
		name string
		body func() []byte
	}{
		{name: "previous response schema", body: func() []byte {
			changed := valid
			changed.SchemaVersion = "provisioning.kaiba.network/authority-bridge-response/v1alpha2"
			encoded, _ := json.Marshal(changed)
			return encoded
		}},
		{name: "duplicate response field", body: func() []byte {
			encoded, _ := json.Marshal(valid)
			return bytes.Replace(encoded, []byte(`"status":"ok"`), []byte(`"status":"ok","status":"ok"`), 1)
		}},
		{name: "oversized response", body: func() []byte { return bytes.Repeat([]byte("x"), maxWireResponseBytes+1) }},
		{name: "changed operation request", body: func() []byte {
			changed := valid
			request := *valid.ExecuteRequest
			request.OperationDigest = bridgeDigest("f")
			changed.ExecuteRequest = &request
			encoded, _ := json.Marshal(changed)
			return encoded
		}},
		{name: "changed required boot mode", body: func() []byte {
			changed := valid
			request := *valid.ExecuteRequest
			request.RequiredBootMode = laneguard.BootModeNormal
			changed.ExecuteRequest = &request
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
		{name: "both request variants", body: func() []byte {
			changed := valid
			changed.ReconcileRequest = &laneguard.ReconcileRequest{}
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

func injectBridgeField(encoded []byte, field string) []byte {
	return bytes.Replace(encoded, []byte(`"mode"`), []byte(field+`,"mode"`), 1)
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
	if authorityReadsPerBinding != 4 {
		t.Fatalf("authority requests per binding = %d, want 4", authorityReadsPerBinding)
	}
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
