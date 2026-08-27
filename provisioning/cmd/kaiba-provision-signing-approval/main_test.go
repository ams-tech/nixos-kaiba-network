package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
)

func TestAuthorAndValidateCanonicalFiveGrantAuthorization(t *testing.T) {
	intentPath := writeTestIntent(t)
	outputPath := filepath.Join(t.TempDir(), "authorization")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"author",
		"--release-intent", intentPath,
		"--reviewer-id", "reviewer:alice",
		"--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z",
		"--output", outputPath,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("author exit = %d, stderr = %s", code, stderr.String())
	}
	var result struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
		GrantCount int    `json:"grant_count"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "authored" || !strings.HasPrefix(result.ApprovalID, "approval:") || result.GrantCount != 5 {
		t.Fatalf("author result = %#v", result)
	}
	for _, name := range []string{approvalFilename, registryFilename} {
		info, err := os.Stat(filepath.Join(outputPath, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"validate",
		"--release-intent", intentPath,
		"--approval", filepath.Join(outputPath, approvalFilename),
		"--registry", filepath.Join(outputPath, registryFilename),
	}, &stdout, &stderr)
	if code != exitOK || !strings.Contains(stdout.String(), `"status":"valid"`) {
		t.Fatalf("validate exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
}

func TestAuthorRefusesExistingOutputAndNoncanonicalIntent(t *testing.T) {
	intentPath := writeTestIntent(t)
	arguments := []string{
		"author",
		"--release-intent", intentPath,
		"--reviewer-id", "reviewer:alice",
		"--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z",
	}
	existing := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(append(arguments, "--output", existing), &stdout, &stderr)
	if code != exitInternal || !strings.Contains(stderr.String(), "create new output directory") {
		t.Fatalf("existing output exit = %d, stderr = %s", code, stderr.String())
	}

	canonical, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalPath := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(noncanonicalPath, append([]byte(" "), canonical...), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run(append(arguments[:1:1],
		"--release-intent", noncanonicalPath,
		"--reviewer-id", "reviewer:alice",
		"--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z",
		"--output", filepath.Join(t.TempDir(), "out"),
	), &stdout, &stderr)
	if code != exitInvalid || !strings.Contains(stderr.String(), "canonical") {
		t.Fatalf("noncanonical intent exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestValidateRejectsTamperedRegistry(t *testing.T) {
	intentPath := writeTestIntent(t)
	outputPath := filepath.Join(t.TempDir(), "authorization")
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"author", "--release-intent", intentPath, "--reviewer-id", "reviewer:alice",
		"--approved-at", "2026-08-18T12:00:00Z", "--expires-at", "2026-08-18T16:00:00Z",
		"--output", outputPath,
	}, &stdout, &stderr); code != exitOK {
		t.Fatalf("author: %s", stderr.String())
	}
	registryPath := filepath.Join(outputPath, registryFilename)
	registry, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(registry, []byte("rpi5.boot_image"), []byte("rpi5.eeprom_config"), 1)
	if err := os.WriteFile(registryPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"validate", "--release-intent", intentPath,
		"--approval", filepath.Join(outputPath, approvalFilename), "--registry", registryPath,
	}, &stdout, &stderr)
	if code != exitInvalid || stderr.Len() == 0 {
		t.Fatalf("tampered registry exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestUsageRejectsMissingOrArbitraryAuthoringInputs(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"author"},
		{"validate"},
		{"author", "--role", "rpi5.boot_image"},
		{"unknown"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitUsage {
			t.Fatalf("run(%q) exit = %d", arguments, code)
		}
	}
}

func writeTestIntent(t *testing.T) string {
	t.Helper()
	previousClock := clockNow
	clockNow = func() time.Time {
		return time.Date(2026, time.August, 18, 13, 0, 0, 0, time.UTC)
	}
	t.Cleanup(func() { clockNow = previousClock })
	roles := releaseintent.SigningInputRoles()
	inputs := make([]bundle.Artifact, len(roles))
	for index, role := range roles {
		inputs[index] = bundle.Artifact{
			Role: role, Digest: bundle.Digest("sha256:" + strings.Repeat(string(rune('a'+index)), 64)),
			SizeBytes: uint64(100 + index),
		}
	}
	intent, err := releaseintent.New(releaseintent.Parameters{
		ReleaseID: "release:rpi5:1", SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		SourceDateEpoch: 1786968000, UnsignedArtifactSetDigest: cliDigest("1"),
		EEPROMReleaseManifestDigest: cliDigest("2"), PublicKeyFingerprint: cliDigest("3"),
		SigningPolicyDigest: cliDigest("4"), ExpectedCustomerKeyHash: cliDigest("5"), SigningInputs: inputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-intent.json")
	if err := os.WriteFile(path, append(canonical, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuthorRejectsFutureOrExpiredApprovalWindow(t *testing.T) {
	intentPath := writeTestIntent(t)
	for _, testCase := range []struct {
		name       string
		approvedAt string
		expiresAt  string
		message    string
	}{
		{
			name: "future", approvedAt: "2026-08-18T14:00:00Z",
			expiresAt: "2026-08-18T16:00:00Z", message: "future",
		},
		{
			name: "expired", approvedAt: "2026-08-18T12:00:00Z",
			expiresAt: "2026-08-18T12:30:00Z", message: "expired",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{
				"author", "--release-intent", intentPath,
				"--reviewer-id", "reviewer:alice",
				"--approved-at", testCase.approvedAt,
				"--expires-at", testCase.expiresAt,
				"--output", filepath.Join(t.TempDir(), "authorization"),
			}, &stdout, &stderr)
			if code != exitInvalid || !strings.Contains(stderr.String(), testCase.message) {
				t.Fatalf("author exit = %d, stderr = %s", code, stderr.String())
			}
		})
	}
}

func cliDigest(character string) bundle.Digest {
	return bundle.Digest("sha256:" + strings.Repeat(character, 64))
}
