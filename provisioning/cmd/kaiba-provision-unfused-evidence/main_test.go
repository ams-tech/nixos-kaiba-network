package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence"
)

func TestCommandVerifiesOperatorObservation(t *testing.T) {
	compatibilityPath, observationPath, uartPath := commandEvidence(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"verify-operator-observation",
		"--compatibility-outcome", compatibilityPath,
		"--observation", observationPath,
		"--uart-capture", uartPath,
	}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result unfusedevidence.Outcome
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != unfusedevidence.StatusCompatibilityPassed || result.EvidenceMode != unfusedevidence.EvidenceModeOperatorHardware {
		t.Fatalf("unexpected outcome: %#v", result)
	}
	if !result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("command emitted the wrong hardware or policy claim: %#v", result)
	}
	if !result.SignatureVerified || result.BootPublicKeyFingerprint == "" || result.SignatureVerificationReceipt == "" {
		t.Fatalf("command omitted signed-capsule verification: %#v", result)
	}
	if result.CustomerKeyHashBefore != unfusedevidence.ZeroCustomerKeyHash || result.CustomerKeyHashAfter != unfusedevidence.ZeroCustomerKeyHash {
		t.Fatalf("command omitted all-zero key evidence: %#v", result)
	}
}

func TestCommandRejectsIncompleteOrExpandedInterface(t *testing.T) {
	compatibilityPath, observationPath, uartPath := commandEvidence(t)
	tests := [][]string{
		nil,
		{"other"},
		{"verify-operator-observation"},
		{"verify-operator-observation", "--compatibility-outcome", compatibilityPath, "--observation", observationPath},
		{"verify-operator-observation", "--compatibility-outcome", compatibilityPath, "--observation", observationPath, "--uart-capture", uartPath, "extra"},
		{"verify-operator-observation", "--compatibility-outcome", compatibilityPath, "--observation", observationPath, "--uart-capture", uartPath, "--device", "/dev/example"},
	}
	for _, arguments := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandReturnsVerificationFailureWithoutResult(t *testing.T) {
	compatibilityPath, observationPath, uartPath := commandEvidence(t)
	if err := os.WriteFile(uartPath, []byte("no evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"verify-operator-observation",
		"--compatibility-outcome", compatibilityPath,
		"--observation", observationPath,
		"--uart-capture", uartPath,
	}, &stdout, &stderr)
	if code != exitVerification || stdout.Len() != 0 || !strings.Contains(stderr.String(), "verify unfused hardware evidence") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandImportsOnlyTheOfflineHardwareEvidenceContract(t *testing.T) {
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.HasPrefix(dependency, "github.com/ams-tech/nixos-kaiba-network/provisioning/") && dependency != "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence" {
			t.Fatalf("command gained a production repository dependency %q", dependency)
		}
		if dependency == "os/exec" || dependency == "net" || strings.HasPrefix(dependency, "net/") {
			t.Fatalf("command gained a process or network dependency %q", dependency)
		}
	}
}

func commandEvidence(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	compatibility := unfusedcompat.Outcome{
		SchemaVersion: unfusedcompat.OutcomeSchemaVersion,
		Status:        unfusedcompat.StatusCompatibilityPassed, EvidenceMode: unfusedcompat.EvidenceModeOfflineFixture,
		FixtureID: "command-fixture", CapsuleID: "command-capsule",
		ManifestDigest: commandDigest([]byte("manifest")), CapsuleDigest: commandDigest([]byte("capsule")),
		BootImageDigest: commandDigest([]byte("boot image")), BootSignatureDigest: commandDigest([]byte("boot signature")),
		BootPublicKeyFingerprint:     commandDigest([]byte("boot public key")),
		SignatureVerificationReceipt: commandDigest([]byte("signature receipt")), SignatureVerified: true,
		RootDataDigest: commandDigest([]byte("root data")), RootHashDigest: commandDigest([]byte("root hash")),
		FixtureDigest: commandDigest([]byte("fixture")), FilesVerified: 4,
	}
	compatibilityDigest, err := unfusedevidence.CompatibilityOutcomeDigest(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := unfusedevidence.ExpectedUARTMarkers(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	uart := []byte(strings.Join(markers, "\n") + "\n")
	fingerprint := commandDigest([]byte("target"))
	observation := unfusedevidence.HardwareObservation{
		SchemaVersion: unfusedevidence.ObservationSchemaVersion, ObservationID: "command-observation",
		CompatibilityOutcomeDigest: compatibilityDigest,
		CapsuleID:                  compatibility.CapsuleID, CapsuleDigest: compatibility.CapsuleDigest,
		BootImageDigest: compatibility.BootImageDigest, BootSignatureDigest: compatibility.BootSignatureDigest,
		BootPublicKeyFingerprint:     compatibility.BootPublicKeyFingerprint,
		SignatureVerificationReceipt: compatibility.SignatureVerificationReceipt,
		RootDataDigest:               compatibility.RootDataDigest, RootHashDigest: compatibility.RootHashDigest,
		UARTCaptureDigest:                  commandDigest(uart),
		ManualBOOTSELConfirmation:          unfusedevidence.ManualBOOTSELConfirmation,
		PreBOOTSELPowerRemovalConfirmation: unfusedevidence.CompletePowerRemoval,
		ModeChangePowerRemovalConfirmation: unfusedevidence.CompletePowerRemoval,
		ManualNormalBootConfirmation:       unfusedevidence.ManualNormalBootConfirmation,
		PostBootPowerRemovalConfirmation:   unfusedevidence.CompletePowerRemoval,
		Before:                             unfusedevidence.TargetObservation{LaneID: "lane-1", TargetFingerprint: fingerprint, CustomerKeyHash: unfusedevidence.ZeroCustomerKeyHash},
		After:                              unfusedevidence.TargetObservation{LaneID: "lane-1", TargetFingerprint: fingerprint, CustomerKeyHash: unfusedevidence.ZeroCustomerKeyHash},
	}
	compatibilityPath := filepath.Join(base, "compatibility.json")
	observationPath := filepath.Join(base, "observation.json")
	uartPath := filepath.Join(base, "uart.txt")
	writeCommandJSON(t, compatibilityPath, compatibility)
	writeCommandJSON(t, observationPath, observation)
	if err := os.WriteFile(uartPath, uart, 0o600); err != nil {
		t.Fatal(err)
	}
	return compatibilityPath, observationPath, uartPath
}

func writeCommandJSON(t *testing.T, filePath string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func commandDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
