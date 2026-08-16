package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

type fakeFileSigner struct {
	signature []byte
	err       error
	path      string
}

func (f *fakeFileSigner) Sign(_ context.Context, path string) ([]byte, error) {
	f.path = path
	return append([]byte(nil), f.signature...), f.err
}

func TestRunImplementsExactWrapperCLI(t *testing.T) {
	fake := &fakeFileSigner{signature: bytes.Repeat([]byte{0xab}, signing.RSASignatureBytes)}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-a", "rsa2048-sha256", "/private/input"}, &stdout, &stderr, dependencies{signer: fake})
	if code != exitOK || stderr.Len() != 0 || fake.path != "/private/input" {
		t.Fatalf("code/stderr/path = %d/%q/%q", code, stderr.String(), fake.path)
	}
	if output := strings.TrimSuffix(stdout.String(), "\n"); len(output) != 512 || strings.Trim(output, "ab") != "" {
		t.Fatalf("signature output = %q", output)
	}
}

func TestRunRejectsEveryOtherRuntimeSurface(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--help"},
		{"-a", "rsa2048-sha256"},
		{"-a", "rsa2048-sha512", "/input"},
		{"--key", "pkcs11:object=attacker", "-a", "rsa2048-sha256", "/input"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr, dependencies{}); code != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
			t.Fatalf("args/code/stdout/stderr = %#v/%d/%q/%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestRunFailsClosedWithoutVerifiedSignature(t *testing.T) {
	tests := []dependencies{
		{err: errors.New("bad immutable config")},
		{},
		{signer: &fakeFileSigner{err: errors.New("touch timed out")}},
		{signer: &fakeFileSigner{signature: []byte("short")}},
	}
	for _, deps := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"-a", "rsa2048-sha256", "/input"}, &stdout, &stderr, deps); code == exitOK || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("code/stdout/stderr = %d/%q/%q", code, stdout.String(), stderr.String())
		}
	}
}
