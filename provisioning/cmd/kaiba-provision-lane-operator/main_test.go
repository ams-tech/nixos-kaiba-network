package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt"
)

func TestRunDisplaysServerPromptAndRequiresBoundTypedConfirmation(t *testing.T) {
	server, socketPath := commandTestServer(t)
	defer server.Close()
	prompt := commandTestPrompt(t, 3*time.Second)
	result := make(chan error, 1)
	go func() {
		_, err := server.Present(context.Background(), prompt)
		result <- err
	}()
	waitForActivePrompt(t, socketPath)
	phrase, err := operatorprompt.ConfirmationPhrase(prompt)
	if err != nil {
		t.Fatal(err)
	}
	var output, errorOutput bytes.Buffer
	if err := run(context.Background(), []string{"--socket", socketPath}, strings.NewReader(phrase+"\n"), &output, &errorOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		prompt.Instructions, prompt.ID, prompt.Digest, string(prompt.Kind),
		string(prompt.Action.Phase), string(prompt.Action.RequestedBootMode), phrase,
		"uid=", "gid=", "pid=",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("operator output omitted %q:\n%s", expected, output.String())
		}
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Present() did not receive the acknowledgement")
	}
}

func TestRunRejectsBareOrMismatchedConfirmationWithoutAcknowledging(t *testing.T) {
	for _, confirmation := range []string{"yes\n", "CONFIRM\n", strings.Repeat("x", maximumConfirmationBytes+1)} {
		t.Run(confirmation[:min(len(confirmation), 8)], func(t *testing.T) {
			server, socketPath := commandTestServer(t)
			defer server.Close()
			prompt := commandTestPrompt(t, 3*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				_, err := server.Present(ctx, prompt)
				result <- err
			}()
			waitForActivePrompt(t, socketPath)
			if err := run(context.Background(), []string{"--socket", socketPath}, strings.NewReader(confirmation), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("run accepted an unbound confirmation")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Present() = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Present() did not stop")
			}
		})
	}
}

func TestRunExposesOnlySocketFlag(t *testing.T) {
	tests := [][]string{
		{},
		{"--yes"},
		{"--mode", "rpiboot"},
		{"--operation", "owned_readback"},
		{"--path", "/tmp/payload"},
		{"--socket", "/tmp/operator.sock", "prompt-selector"},
	}
	for _, arguments := range tests {
		if err := run(context.Background(), arguments, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("run(%q) accepted forbidden or incomplete arguments", arguments)
		}
	}
}

func commandTestServer(t *testing.T) (*operatorprompt.Server, string) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "kaiba-op-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "operator.sock")
	server, err := operatorprompt.Listen(operatorprompt.Config{
		SocketPath: path, AllowedPrimaryGID: uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, path
}

func waitForActivePrompt(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		client, err := operatorprompt.Connect(context.Background(), socketPath)
		if err == nil {
			_ = client.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("prompt did not become active: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func commandTestPrompt(t *testing.T, lifetime time.Duration) operatorprompt.Prompt {
	t.Helper()
	action := laneguard.HardwareAction{
		SchemaVersion: laneguard.BootTransitionActionSchemaVersion,
		StationID:     "station", LaneID: "lane", TransactionID: "transaction",
		PlanDigest: commandDigest("a"), TargetFingerprint: "target", FenceEpoch: 1,
		ApprovalID: "approval", IntentReceipt: "intent", IntentSequence: 1, Sequence: 1,
		Operation: laneguard.OperationOwnedReadback, OperationDigest: commandDigest("b"), AuthorizationID: "authorization",
		Phase:                     laneguard.HardwarePhaseExecute,
		OperationRequiredBootMode: laneguard.BootModeRPIBoot,
		RequestedBootMode:         laneguard.BootModeRPIBoot,
	}
	prompt, err := operatorprompt.New(action, operatorprompt.KindHoldBOOTSEL, "hold-prompt-1", "Hold BOOTSEL while applying target power.", time.Now().UTC().Add(lifetime))
	if err != nil {
		t.Fatal(err)
	}
	return prompt
}

func commandDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
