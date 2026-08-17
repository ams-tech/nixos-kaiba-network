package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence"
)

type commandInputs struct {
	manifestPath      string
	capsuleRoot       string
	fixturePath       string
	publicKeyPath     string
	observationPath   string
	uartPath          string
	signerFingerprint string
}

var (
	commandSigningKeyOnce sync.Once
	commandSigningKey     *rsa.PrivateKey
	commandSigningKeyErr  error
)

func TestCommandVerifiesOfflineOperatorCorrelation(t *testing.T) {
	inputs := commandEvidence(t)
	setTrustedSigner(t, inputs.signerFingerprint)
	var stdout, stderr bytes.Buffer
	code := run(commandArguments(inputs), &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result unfusedevidence.Outcome
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != unfusedevidence.StatusRecordConsistent || result.EvidenceMode != unfusedevidence.EvidenceModeOfflineOperatorCorrelation {
		t.Fatalf("unexpected outcome: %#v", result)
	}
	if !result.RecordConsistent || result.CaptureAuthenticated || result.FreshnessEstablished || result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("command emitted the wrong evidence or policy claim: %#v", result)
	}
	if !result.SignatureVerified || !result.SignerTrustAnchored || result.BootPublicKeyFingerprint == "" || result.SignatureVerificationReceipt == "" || result.SignerTrustPolicyDigest == "" {
		t.Fatalf("command omitted anchored signed-capsule verification: %#v", result)
	}
	if result.CustomerKeyHashBefore != unfusedevidence.ZeroCustomerKeyHash || result.CustomerKeyHashAfter != unfusedevidence.ZeroCustomerKeyHash {
		t.Fatalf("command omitted correlated all-zero key record: %#v", result)
	}
}

func TestCommandRejectsIncompleteExpandedAndLegacyInterface(t *testing.T) {
	inputs := commandEvidence(t)
	setTrustedSigner(t, inputs.signerFingerprint)
	valid := commandArguments(inputs)
	tests := [][]string{
		nil,
		{"other"},
		{"verify-operator-observation"},
		valid[:len(valid)-2],
		append(append([]string(nil), valid...), "extra"),
		append(append([]string(nil), valid...), "--device", "/dev/example"),
		{"verify-operator-observation", "--compatibility-outcome", filepath.Join(t.TempDir(), "outcome.json"), "--observation", inputs.observationPath, "--uart-capture", inputs.uartPath},
	}
	for _, arguments := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandGenericBuildFailsClosedWithoutSignerAnchor(t *testing.T) {
	inputs := commandEvidence(t)
	setTrustedSigner(t, "")
	var stdout, stderr bytes.Buffer
	code := run(commandArguments(inputs), &stdout, &stderr)
	if code != exitVerification || stdout.Len() != 0 || !strings.Contains(stderr.String(), "trusted signer anchor") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandReturnsVerificationFailureWithoutResult(t *testing.T) {
	inputs := commandEvidence(t)
	setTrustedSigner(t, inputs.signerFingerprint)
	if err := os.WriteFile(inputs.uartPath, []byte("no evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(commandArguments(inputs), &stdout, &stderr)
	if code != exitVerification || stdout.Len() != 0 || !strings.Contains(stderr.String(), "verify unfused evidence correlation") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandImportsOnlyEvidenceAndCompatibilityContracts(t *testing.T) {
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if !strings.HasPrefix(dependency, "github.com/ams-tech/nixos-kaiba-network/provisioning/") {
			continue
		}
		if dependency != "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat" && dependency != "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence" {
			t.Fatalf("command gained a production repository dependency %q", dependency)
		}
	}
}

func commandArguments(inputs commandInputs) []string {
	return []string{
		"verify-operator-observation",
		"--manifest", inputs.manifestPath,
		"--capsule-root", inputs.capsuleRoot,
		"--fixture", inputs.fixturePath,
		"--public-key", inputs.publicKeyPath,
		"--observation", inputs.observationPath,
		"--uart-capture", inputs.uartPath,
	}
}

func commandEvidence(t *testing.T) commandInputs {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "capsule")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testCommandSigningKey(t)
	bootImage := []byte("command immutable boot capsule")
	bootHash := sha256.Sum256(bootImage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, bootHash[:])
	if err != nil {
		t.Fatal(err)
	}
	contents := []struct {
		path string
		data []byte
	}{
		{"boot.img", bootImage},
		{"boot.sig", signature},
		{"nvme/root-data.img", []byte("command immutable root data")},
		{"nvme/root-hash.img", []byte("command immutable verity hash tree")},
	}
	files := make([]unfusedcompat.CapsuleFile, 0, len(contents))
	for _, content := range contents {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, content.path)), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWriteCommand(t, filepath.Join(root, content.path), content.data)
		files = append(files, unfusedcompat.CapsuleFile{Path: content.path, SizeBytes: int64(len(content.data)), SHA256: commandDigest(content.data)})
	}
	capsuleDigest, err := unfusedcompat.ComputeCapsuleDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := unfusedcompat.CapsuleManifest{
		SchemaVersion: unfusedcompat.ManifestSchemaVersion, CapsuleID: "command-capsule",
		CapsuleDigest: capsuleDigest, BootImagePath: "boot.img", BootSignaturePath: "boot.sig",
		RootDataPath: "nvme/root-data.img", RootHashPath: "nvme/root-hash.img", Files: files,
	}
	fixture := unfusedcompat.OfflineFixture{
		SchemaVersion: unfusedcompat.FixtureSchemaVersion, FixtureID: "command-fixture",
		CapsuleID: manifest.CapsuleID, CapsuleDigest: manifest.CapsuleDigest,
		BootImageDigest: files[0].SHA256, BootSignatureDigest: files[1].SHA256,
		RootDataDigest: files[2].SHA256, RootHashDigest: files[3].SHA256,
		BootMode:       unfusedcompat.BootModeRAMDisk,
		FirmwareLoaded: true, KernelStarted: true, InitramfsStarted: true,
		CompatibilityMarkerObserved: true,
	}
	manifestPath := filepath.Join(base, "manifest.json")
	fixturePath := filepath.Join(base, "fixture.json")
	publicKeyPath := filepath.Join(base, "public.pem")
	writeCommandJSON(t, manifestPath, manifest)
	writeCommandJSON(t, fixturePath, fixture)
	fingerprint := writeCommandPublicKey(t, publicKeyPath, &privateKey.PublicKey)
	policy, err := unfusedcompat.NewTrustedSignerPolicy(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	compatibility, err := unfusedcompat.VerifySignedOfflineFixture(manifestPath, root, fixturePath, publicKeyPath, policy)
	if err != nil {
		t.Fatal(err)
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
	targetFingerprint := commandDigest([]byte("target"))
	observation := unfusedevidence.HardwareObservation{
		SchemaVersion: unfusedevidence.ObservationSchemaVersion, ObservationID: "command-observation",
		CompatibilityOutcomeDigest: compatibilityDigest,
		CapsuleID:                  compatibility.CapsuleID, CapsuleDigest: compatibility.CapsuleDigest,
		BootImageDigest: compatibility.BootImageDigest, BootSignatureDigest: compatibility.BootSignatureDigest,
		BootPublicKeyFingerprint:     compatibility.BootPublicKeyFingerprint,
		SignatureVerificationReceipt: compatibility.SignatureVerificationReceipt,
		SignerTrustPolicyDigest:      compatibility.SignerTrustPolicyDigest,
		RootDataDigest:               compatibility.RootDataDigest, RootHashDigest: compatibility.RootHashDigest,
		UARTCaptureDigest:                  commandDigest(uart),
		ManualBOOTSELConfirmation:          unfusedevidence.ManualBOOTSELConfirmation,
		PreBOOTSELPowerRemovalConfirmation: unfusedevidence.CompletePowerRemoval,
		ModeChangePowerRemovalConfirmation: unfusedevidence.CompletePowerRemoval,
		ManualNormalBootConfirmation:       unfusedevidence.ManualNormalBootConfirmation,
		PostBootPowerRemovalConfirmation:   unfusedevidence.CompletePowerRemoval,
		Before:                             unfusedevidence.TargetObservation{LaneID: "lane-1", TargetFingerprint: targetFingerprint, CustomerKeyHash: unfusedevidence.ZeroCustomerKeyHash},
		After:                              unfusedevidence.TargetObservation{LaneID: "lane-1", TargetFingerprint: targetFingerprint, CustomerKeyHash: unfusedevidence.ZeroCustomerKeyHash},
	}
	observationPath := filepath.Join(base, "observation.json")
	uartPath := filepath.Join(base, "uart.txt")
	writeCommandJSON(t, observationPath, observation)
	mustWriteCommand(t, uartPath, uart)
	return commandInputs{
		manifestPath: manifestPath, capsuleRoot: root, fixturePath: fixturePath, publicKeyPath: publicKeyPath,
		observationPath: observationPath, uartPath: uartPath, signerFingerprint: fingerprint,
	}
}

func setTrustedSigner(t *testing.T, fingerprint string) {
	t.Helper()
	previous := trustedSignerFingerprint
	trustedSignerFingerprint = fingerprint
	t.Cleanup(func() { trustedSignerFingerprint = previous })
}

func testCommandSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	commandSigningKeyOnce.Do(func() {
		commandSigningKey, commandSigningKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if commandSigningKeyErr != nil {
		t.Fatal(commandSigningKeyErr)
	}
	return commandSigningKey
}

func writeCommandPublicKey(t *testing.T, filePath string, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteCommand(t, filePath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return commandDigest(der)
}

func writeCommandJSON(t *testing.T, filePath string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteCommand(t, filePath, data)
}

func mustWriteCommand(t *testing.T, filePath string, value []byte) {
	t.Helper()
	if err := os.WriteFile(filePath, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func commandDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
