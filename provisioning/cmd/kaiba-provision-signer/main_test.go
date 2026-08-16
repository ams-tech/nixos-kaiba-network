package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

func commandDependencies(t *testing.T) (dependencies, *signing.DeterministicFakeBackend) {
	t.Helper()
	policy, err := signing.NewDevelopmentYubiKeyPolicy(
		"signer:development-01",
		"cohort:rpi5-development",
		"pkcs11:token=Kaiba;object=Boot;id=%02;type=private",
		bundle.Sum([]byte("public key")),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &signing.DeterministicFakeBackend{Domain: "command-test"}
	return dependencies{backend: backend, policy: policy}, backend
}

func TestRunImplementsExactRaspberryPiHSMWrapperContract(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "boot.img")
	if err := os.WriteFile(inputPath, []byte("approved boot image"), 0o400); err != nil {
		t.Fatal(err)
	}
	deps, backend := commandDependencies(t)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-a", "rsa2048-sha256", inputPath}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	output := stdout.String()
	if len(output) != signing.RSASignatureBytes*2+1 || output[len(output)-1] != '\n' || output != strings.ToLower(output) {
		t.Fatalf("stdout is not one lowercase signature line: %q", output)
	}
	if backend.Calls != 1 {
		t.Fatalf("backend calls = %d", backend.Calls)
	}
}

func TestRunRejectsEveryOtherArgumentShape(t *testing.T) {
	deps, backend := commandDependencies(t)
	for _, args := range [][]string{
		nil,
		{"-a"},
		{"--algorithm", "rsa2048-sha256", "input"},
		{"-a", "RSA2048-SHA256", "input"},
		{"-a", "rsa2048-sha256", "input", "extra"},
		{"-a", "rsa2048-sha256", ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr, deps); code != exitUsage {
			t.Fatalf("run(%q) = %d, want %d", args, code, exitUsage)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
			t.Fatalf("run(%q) stdout/stderr = %q/%q", args, stdout.String(), stderr.String())
		}
	}
	if backend.Calls != 0 {
		t.Fatalf("invalid arguments reached backend %d times", backend.Calls)
	}
}

func TestRunRejectsSymlinkAndEmptyInput(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "link")
	if err := os.Symlink(empty, symlink); err != nil {
		t.Fatal(err)
	}
	deps, backend := commandDependencies(t)
	for _, path := range []string{empty, symlink} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"-a", "rsa2048-sha256", path}, &stdout, &stderr, deps); code != exitInput {
			t.Fatalf("run(%q) = %d, stderr = %s", path, code, stderr.String())
		}
	}
	if backend.Calls != 0 {
		t.Fatalf("invalid inputs reached backend %d times", backend.Calls)
	}
}

func TestProductionConfigurationHasNoFlagsOrEnvironmentFallback(t *testing.T) {
	original := []string{
		approvalGatedSignerPath,
		approvalGatedSignerArgumentsJSON,
		developmentSignerID,
		developmentCohortID,
		developmentPKCS11URI,
		developmentPublicKeyFingerprint,
	}
	t.Cleanup(func() {
		approvalGatedSignerPath = original[0]
		approvalGatedSignerArgumentsJSON = original[1]
		developmentSignerID = original[2]
		developmentCohortID = original[3]
		developmentPKCS11URI = original[4]
		developmentPublicKeyFingerprint = original[5]
	})
	approvalGatedSignerPath = "relative/browser-selected"
	approvalGatedSignerArgumentsJSON = `[]`
	developmentSignerID = "signer:development-01"
	developmentCohortID = "cohort:rpi5-development"
	developmentPKCS11URI = "pkcs11:token=Kaiba;object=Boot;id=%02;type=private"
	developmentPublicKeyFingerprint = string(bundle.Sum([]byte("public key")))
	if deps := productionDependencies(); deps.err == nil || !strings.Contains(deps.err.Error(), "absolute clean path") {
		t.Fatalf("relative production executable error = %v", deps.err)
	}
}

func TestParseFixedArgumentsIsStrict(t *testing.T) {
	arguments, err := parseFixedArguments(`["--socket","/run/kaiba/signer.sock"]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(arguments) != 2 || arguments[1] != "/run/kaiba/signer.sock" {
		t.Fatalf("arguments = %#v", arguments)
	}
	for _, invalid := range []string{"", `null`, `{}`, `[] {}`} {
		if _, err := parseFixedArguments(invalid); err == nil {
			t.Fatalf("parseFixedArguments(%q) succeeded", invalid)
		}
	}
}
