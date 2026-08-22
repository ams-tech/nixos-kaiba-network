package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

func TestRunImplementsExactHSMWrapperProtocol(t *testing.T) {
	input := filepath.Join(t.TempDir(), "boot.img")
	if err := os.WriteFile(input, []byte("approved artifact"), 0o400); err != nil {
		t.Fatal(err)
	}
	called := false
	requester := func(_ context.Context, artifact []byte) (signinggate.Result, error) {
		called = true
		if string(artifact) != "approved artifact" {
			t.Fatalf("artifact = %q", artifact)
		}
		return signinggate.Result{
			SignatureHex:        strings.Repeat("01", signing.RSASignatureBytes),
			ReceiptDigest:       bundle.Sum([]byte("receipt")),
			ReleaseIntentDigest: bundle.Sum([]byte("release intent")),
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-a", "rsa2048-sha256", input}, &stdout, &stderr, requester)
	if code != exitOK || !called || stderr.Len() != 0 {
		t.Fatalf("run() = %d, called = %v, stderr = %s", code, called, stderr.String())
	}
	if stdout.String() != strings.Repeat("01", signing.RSASignatureBytes)+"\n" {
		t.Fatalf("signature output = %q", stdout.String())
	}
}

func TestRunRejectsOtherArgumentsWithoutCallingGate(t *testing.T) {
	requester := func(context.Context, []byte) (signinggate.Result, error) {
		t.Fatal("invalid arguments reached signing gate")
		return signinggate.Result{}, nil
	}
	for _, args := range [][]string{
		nil,
		{"-a"},
		{"--algorithm", "rsa2048-sha256", "input"},
		{"-a", "other", "input"},
		{"-a", "rsa2048-sha256", "input", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr, requester); code != exitUsage {
			t.Fatalf("run(%q) = %d", args, code)
		}
	}
}

func TestRunDoesNotExposeGateDiagnosticsOnStdout(t *testing.T) {
	input := filepath.Join(t.TempDir(), "boot.img")
	if err := os.WriteFile(input, []byte("unapproved"), 0o400); err != nil {
		t.Fatal(err)
	}
	requester := func(context.Context, []byte) (signinggate.Result, error) {
		return signinggate.Result{}, errors.New("signing_denied")
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-a", "rsa2048-sha256", input}, &stdout, &stderr, requester); code != exitDenied {
		t.Fatalf("run() = %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "signing_denied") {
		t.Fatalf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}
