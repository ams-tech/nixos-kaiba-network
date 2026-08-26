package operatorprompt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

func TestPromptBindsExactActionInstructionsKindAndExpiry(t *testing.T) {
	action := testAction(laneguard.BootModeRPIBoot)
	prompt := testPrompt(t, action, KindHoldBOOTSEL, 2*time.Second)
	if err := prompt.Validate(); err != nil {
		t.Fatal(err)
	}
	phrase, err := ConfirmationPhrase(prompt)
	if err != nil || !strings.Contains(phrase, prompt.ID) || !strings.Contains(phrase, strings.TrimPrefix(prompt.Digest, "sha256:")[:16]) {
		t.Fatalf("confirmation phrase = %q, %v", phrase, err)
	}

	mutations := []func(*Prompt){
		func(value *Prompt) { value.Instructions += " now" },
		func(value *Prompt) { value.Action.TransactionID = "different" },
		func(value *Prompt) { value.Kind = KindReleaseBOOTSEL },
		func(value *Prompt) { value.ExpiresAt = value.ExpiresAt.Add(time.Second) },
	}
	for index, mutate := range mutations {
		changed := prompt
		mutate(&changed)
		if err := changed.Validate(); err == nil {
			t.Fatalf("mutation %d retained a valid digest", index)
		}
	}
	if _, err := New(action, KindNormalNoAction, "prompt", "Do not press BOOTSEL.", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("normal prompt accepted an RPIBOOT action")
	}
	normal := testAction(laneguard.BootModeNormal)
	if _, err := New(normal, KindNormalNoAction, "prompt", "Do not press BOOTSEL.", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("normal prompt rejected: %v", err)
	}
	if _, err := New(action, KindHoldBOOTSEL, "prompt", "unsafe\x1b[2J", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("terminal control sequence accepted in instructions")
	}
}

func TestServerRoundTripAuthenticatesAndRecordsSO_PEERCRED(t *testing.T) {
	server, socketPath := testServer(t, nil)
	defer server.Close()
	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 3*time.Second)
	result := presentAsync(server, prompt)
	client := connectEventually(t, socketPath)
	acknowledgement, err := client.Acknowledge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if acknowledgement.PromptID != prompt.ID || acknowledgement.PromptDigest != prompt.Digest ||
		acknowledgement.Peer.UID != uint32(os.Geteuid()) || acknowledgement.Peer.GID != uint32(os.Getegid()) ||
		acknowledgement.Peer.PID != int32(os.Getpid()) {
		t.Fatalf("acknowledgement = %#v", acknowledgement)
	}
	if presented := awaitPresented(t, result); presented.err != nil || presented.ack != acknowledgement {
		t.Fatalf("Present() = %#v, %v", presented.ack, presented.err)
	}
}

func TestServerRejectsWrongPrimaryGroup(t *testing.T) {
	peerLookup := func(*net.UnixConn) (laneguard.OperatorPeer, error) {
		return laneguard.OperatorPeer{UID: 1001, GID: uint32(os.Getegid()) + 1, PID: 42}, nil
	}
	server, socketPath := testServer(t, peerLookup)
	defer server.Close()
	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 3*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := presentAsyncContext(server, ctx, prompt)
	var remote RemoteError
	for deadline := time.Now().Add(time.Second); ; {
		_, err := Connect(context.Background(), socketPath)
		if errors.As(err, &remote) && remote.Code == errorUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unauthorized Connect() error = %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if got := awaitPresented(t, result); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("Present() after cancellation = %v", got.err)
	}
}

func TestMismatchAndMalformedMessagesDoNotConsumePrompt(t *testing.T) {
	server, socketPath := testServer(t, fixedPeer())
	defer server.Close()
	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 4*time.Second)
	result := presentAsync(server, prompt)
	waitForPrompt(t, socketPath)

	validAck := wireFrame{SchemaVersion: wireSchemaVersion, Type: frameAck, PromptID: prompt.ID, PromptDigest: prompt.Digest}
	encoded, err := json.Marshal(validAck)
	if err != nil {
		t.Fatal(err)
	}
	malformed := [][]byte{
		bytes.Replace(encoded, []byte(`"prompt_digest":"`), []byte(`"unknown":true,"prompt_digest":"`), 1),
		bytes.Replace(encoded, []byte(`"type":"acknowledgement"`), []byte(`"type":"acknowledgement","type":"acknowledgement"`), 1),
		append(append([]byte(nil), encoded...), []byte(` {}`)...),
		bytes.Repeat([]byte("x"), maxWireBytes+1),
	}
	for index, body := range malformed {
		response := rawAcknowledgement(t, socketPath, body)
		if response.Type != frameError || response.ErrorCode != errorInvalid {
			t.Fatalf("malformed response %d = %#v", index, response)
		}
	}

	mismatch := validAck
	mismatch.PromptDigest = "sha256:" + strings.Repeat("f", 64)
	mismatchBody, _ := json.Marshal(mismatch)
	response := rawAcknowledgement(t, socketPath, mismatchBody)
	if response.Type != frameError || response.ErrorCode != errorMismatch {
		t.Fatalf("mismatch response = %#v", response)
	}

	client := connectEventually(t, socketPath)
	if _, err := client.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if got := awaitPresented(t, result); got.err != nil {
		t.Fatal(got.err)
	}
}

func TestPromptExpiryAndReplayAreRejected(t *testing.T) {
	server, socketPath := testServer(t, fixedPeer())
	defer server.Close()

	expiring := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 80*time.Millisecond)
	expiryResult := presentAsync(server, expiring)
	client := connectEventually(t, socketPath)
	time.Sleep(120 * time.Millisecond)
	if got := awaitPresented(t, expiryResult); !errors.Is(got.err, ErrPromptExpired) {
		t.Fatalf("expired Present() = %v", got.err)
	}
	if _, err := client.Acknowledge(context.Background()); err == nil {
		t.Fatal("expired client acknowledgement succeeded")
	}
	_ = client.Close()

	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 2*time.Second)
	result := presentAsync(server, prompt)
	client = connectEventually(t, socketPath)
	if _, err := client.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if got := awaitPresented(t, result); got.err != nil {
		t.Fatal(got.err)
	}
	if _, err := client.Acknowledge(context.Background()); err == nil {
		t.Fatal("same client replay succeeded")
	}
	if _, err := Connect(context.Background(), socketPath); err == nil {
		t.Fatal("connection without an active prompt succeeded")
	} else {
		var remote RemoteError
		if !errors.As(err, &remote) || remote.Code != errorNoActive {
			t.Fatalf("post-consumption Connect() = %v", err)
		}
	}
}

func TestConcurrentReplayOnlyOneAcknowledgementWins(t *testing.T) {
	server, socketPath := testServer(t, fixedPeer())
	defer server.Close()
	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 2*time.Second)
	presented := presentAsync(server, prompt)
	first := connectEventually(t, socketPath)
	defer first.Close()
	second := connectEventually(t, socketPath)
	defer second.Close()

	results := make(chan error, 2)
	go func() {
		_, err := first.Acknowledge(context.Background())
		results <- err
	}()
	go func() {
		_, err := second.Acknowledge(context.Background())
		results <- err
	}()
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent acknowledgements succeeded %d times", successes)
	}
	if got := awaitPresented(t, presented); got.err != nil {
		t.Fatal(got.err)
	}
}

func TestOnlyOneActivePromptAndCloseReleasesWaiter(t *testing.T) {
	server, _ := testServer(t, fixedPeer())
	prompt := testPrompt(t, testAction(laneguard.BootModeRPIBoot), KindHoldBOOTSEL, 3*time.Second)
	result := presentAsync(server, prompt)
	time.Sleep(10 * time.Millisecond)
	if _, err := server.Present(context.Background(), prompt); !errors.Is(err, ErrPromptActive) {
		t.Fatalf("second Present() = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if got := awaitPresented(t, result); !errors.Is(got.err, ErrServerClosed) {
		t.Fatalf("closed Present() = %v", got.err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
}

func TestSocketSafetyModeAndCleanup(t *testing.T) {
	directory := testSocketDirectory(t)
	path := filepath.Join(directory, "operator.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(Config{SocketPath: path, AllowedPrimaryGID: uint32(os.Getegid())}); err == nil {
		t.Fatal("Listen replaced a pre-existing regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "do not replace" {
		t.Fatalf("pre-existing path changed: %q, %v", contents, err)
	}
	if _, err := Listen(Config{SocketPath: filepath.Join(directory, "sub", "..", "operator.sock"), AllowedPrimaryGID: uint32(os.Getegid())}); err == nil {
		t.Fatal("Listen accepted a non-clean path")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(Config{SocketPath: path, AllowedPrimaryGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, %v", info, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after close: %v", err)
	}
}

type presentResult struct {
	ack Acknowledgement
	err error
}

func presentAsync(server *Server, prompt Prompt) <-chan presentResult {
	return presentAsyncContext(server, context.Background(), prompt)
}

func presentAsyncContext(server *Server, ctx context.Context, prompt Prompt) <-chan presentResult {
	result := make(chan presentResult, 1)
	go func() {
		ack, err := server.Present(ctx, prompt)
		result <- presentResult{ack: ack, err: err}
	}()
	return result
}

func awaitPresented(t *testing.T, result <-chan presentResult) presentResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("Present() did not return")
		return presentResult{}
	}
}

func testServer(t *testing.T, peer PeerCredentialsFunc) (*Server, string) {
	t.Helper()
	directory := testSocketDirectory(t)
	path := filepath.Join(directory, "operator.sock")
	server, err := Listen(Config{SocketPath: path, AllowedPrimaryGID: uint32(os.Getegid()), PeerCredentials: peer})
	if err != nil {
		t.Fatal(err)
	}
	return server, path
}

func testSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "kaiba-op-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	return directory
}

func connectEventually(t *testing.T, path string) *Client {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		client, err := Connect(context.Background(), path)
		if err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatalf("Connect() did not receive active prompt: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForPrompt(t *testing.T, path string) {
	t.Helper()
	client := connectEventually(t, path)
	_ = client.Close()
}

func rawAcknowledgement(t *testing.T, path string, body []byte) wireFrame {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	promptFrame, err := readInitialFrame(connection, time.Now().Add(time.Second))
	if err != nil || promptFrame.Type != framePrompt {
		t.Fatalf("read raw prompt = %#v, %v", promptFrame, err)
	}
	if _, err := connection.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := readFinalFrame(connection, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func fixedPeer() PeerCredentialsFunc {
	return func(*net.UnixConn) (laneguard.OperatorPeer, error) {
		return laneguard.OperatorPeer{UID: 1000, GID: uint32(os.Getegid()), PID: 1234}, nil
	}
}

func testPrompt(t *testing.T, action laneguard.HardwareAction, kind Kind, lifetime time.Duration) Prompt {
	t.Helper()
	prompt, err := New(action, kind, "prompt-123", "Follow the displayed physical boot-selection instruction.", time.Now().UTC().Add(lifetime))
	if err != nil {
		t.Fatal(err)
	}
	return prompt
}

func testAction(mode laneguard.BootMode) laneguard.HardwareAction {
	operation := laneguard.OperationOwnedReadback
	if mode == laneguard.BootModeNormal {
		operation = laneguard.OperationColdPowerCycle
	}
	return laneguard.HardwareAction{
		SchemaVersion: laneguard.BootTransitionActionSchemaVersion,
		StationID:     "station", LaneID: "lane", TransactionID: "transaction",
		PlanDigest: digest("a"), TargetFingerprint: "target", FenceEpoch: 1,
		ApprovalID: "approval", IntentReceipt: "intent", IntentSequence: 1, Sequence: 1,
		Operation: operation, OperationDigest: digest("b"), AuthorizationID: "authorization",
		Phase: laneguard.HardwarePhaseExecute, OperationRequiredBootMode: mode, RequestedBootMode: mode,
	}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
