package unfusedevidence

import (
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
)

type evidenceInputs struct {
	manifestPath    string
	capsuleRoot     string
	fixturePath     string
	publicKeyPath   string
	observationPath string
	uartPath        string
	policy          unfusedcompat.TrustedSignerPolicy
	manifest        unfusedcompat.CapsuleManifest
	fixture         unfusedcompat.OfflineFixture
	compatibility   unfusedcompat.Outcome
	observation     HardwareObservation
	uart            []byte
}

var (
	evidenceSigningKeyOnce sync.Once
	evidenceSigningKey     *rsa.PrivateKey
	evidenceSigningKeyErr  error
)

func TestVerifyProducesOfflineCorrelationWithoutHardwareClaim(t *testing.T) {
	inputs := makeEvidenceInputs(t)
	result, err := verifyEvidence(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != OutcomeSchemaVersion || result.Status != StatusRecordConsistent || result.EvidenceMode != EvidenceModeOfflineOperatorCorrelation {
		t.Fatalf("unexpected result identity: %#v", result)
	}
	if !result.RecordConsistent || result.CaptureAuthenticated || result.FreshnessEstablished || result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("correlation result contains the wrong policy claims: %#v", result)
	}
	if !result.SignatureVerified || !result.SignerTrustAnchored || result.BootPublicKeyFingerprint != inputs.compatibility.BootPublicKeyFingerprint ||
		result.SignatureVerificationReceipt != inputs.compatibility.SignatureVerificationReceipt ||
		result.SignerTrustPolicyDigest != inputs.compatibility.SignerTrustPolicyDigest {
		t.Fatalf("correlation result lost signed-capsule verification: %#v", result)
	}
	if result.LaneID != inputs.observation.Before.LaneID || result.TargetFingerprint != inputs.observation.Before.TargetFingerprint {
		t.Fatalf("result lost target correlation: %#v", result)
	}
	if result.CustomerKeyHashBefore != ZeroCustomerKeyHash || result.CustomerKeyHashAfter != ZeroCustomerKeyHash {
		t.Fatalf("result lost recorded unfused state: %#v", result)
	}
	if result.CompatibilityOutcomeDigest != inputs.observation.CompatibilityOutcomeDigest || result.UARTCaptureDigest != inputs.observation.UARTCaptureDigest {
		t.Fatalf("result lost input evidence binding: %#v", result)
	}
	if result.ObservationDigest == "" || result.BootImageDigest != inputs.compatibility.BootImageDigest || result.RootHashDigest != inputs.compatibility.RootHashDigest {
		t.Fatalf("result lost capsule correlation: %#v", result)
	}
}

func TestHardwareObservationRejectsBindingContinuityAndCeremonyTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HardwareObservation)
		want   string
	}{
		{"legacy schema", func(value *HardwareObservation) {
			value.SchemaVersion = "provisioning.kaiba.network/rpi5-unfused-hardware-observation/v1alpha1"
		}, "unsupported"},
		{"observation id", func(value *HardwareObservation) { value.ObservationID = "../observation" }, "observation_id"},
		{"compatibility result", func(value *HardwareObservation) { value.CompatibilityOutcomeDigest = digestBytes([]byte("other")) }, "compatibility outcome"},
		{"capsule id", func(value *HardwareObservation) { value.CapsuleID = "other" }, "capsule binding"},
		{"capsule digest", func(value *HardwareObservation) { value.CapsuleDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot image", func(value *HardwareObservation) { value.BootImageDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot signature", func(value *HardwareObservation) { value.BootSignatureDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot key", func(value *HardwareObservation) { value.BootPublicKeyFingerprint = digestBytes([]byte("other")) }, "capsule binding"},
		{"signature receipt", func(value *HardwareObservation) { value.SignatureVerificationReceipt = digestBytes([]byte("other")) }, "capsule binding"},
		{"signer policy", func(value *HardwareObservation) { value.SignerTrustPolicyDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"root data", func(value *HardwareObservation) { value.RootDataDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"root hash", func(value *HardwareObservation) { value.RootHashDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"UART digest", func(value *HardwareObservation) { value.UARTCaptureDigest = digestBytes([]byte("other")) }, "UART digest"},
		{"BOOTSEL", func(value *HardwareObservation) { value.ManualBOOTSELConfirmation = "assumed" }, "BOOTSEL"},
		{"normal boot", func(value *HardwareObservation) { value.ManualNormalBootConfirmation = "assumed" }, "normal-boot"},
		{"pre power", func(value *HardwareObservation) { value.PreBOOTSELPowerRemovalConfirmation = "partial" }, "every mode boundary"},
		{"mode power", func(value *HardwareObservation) { value.ModeChangePowerRemovalConfirmation = "partial" }, "every mode boundary"},
		{"post power", func(value *HardwareObservation) { value.PostBootPowerRemovalConfirmation = "partial" }, "every mode boundary"},
		{"before key", func(value *HardwareObservation) { value.Before.CustomerKeyHash = digestBytes([]byte("set")) }, "all-zero"},
		{"after key", func(value *HardwareObservation) { value.After.CustomerKeyHash = digestBytes([]byte("set")) }, "all-zero"},
		{"lane replacement", func(value *HardwareObservation) { value.After.LaneID = "lane-2" }, "continuity changed"},
		{"target replacement", func(value *HardwareObservation) { value.After.TargetFingerprint = digestBytes([]byte("replacement")) }, "continuity changed"},
		{"invalid target", func(value *HardwareObservation) { value.Before.TargetFingerprint = "target" }, "canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeEvidenceInputs(t)
			test.mutate(&inputs.observation)
			writeJSON(t, inputs.observationPath, inputs.observation)
			_, err := verifyEvidence(inputs)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestVerifyRecomputesSignedCompatibilityOutcome(t *testing.T) {
	t.Run("untrusted signer", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		policy, err := unfusedcompat.NewTrustedSignerPolicy(digestBytes([]byte("different signer")))
		if err != nil {
			t.Fatal(err)
		}
		inputs.policy = policy
		_, err = verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "not authorized") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("tampered manifest", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		inputs.manifest.SchemaVersion = "provisioning.kaiba.network/rpi5-unfused-capsule-manifest/v0"
		writeJSON(t, inputs.manifestPath, inputs.manifest)
		_, err := verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "unsupported capsule manifest") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("tampered fixture", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		inputs.fixture.CompatibilityMarkerObserved = false
		writeJSON(t, inputs.fixturePath, inputs.fixture)
		_, err := verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "complete compatibility sequence") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("tampered capsule", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		mustWrite(t, filepath.Join(inputs.capsuleRoot, inputs.manifest.RootDataPath), []byte("tampered root data"))
		_, err := verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "verify capsule file") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("substituted public key", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		writePublicKey(t, inputs.publicKeyPath, &wrong.PublicKey)
		_, err = verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "not authorized") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestUARTCaptureRequiresExactlyBoundCompatibilityAndIntegrityMarkers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(evidenceInputs) []byte
		want   string
	}{
		{"empty", func(evidenceInputs) []byte { return nil }, "empty"},
		{"missing compatibility", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			return []byte(markers[1] + "\n")
		}, "contains 0 exact"},
		{"duplicate compatibility", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			return []byte(markers[0] + "\n" + markers[0] + "\n" + markers[1] + "\n")
		}, "contains 2 exact"},
		{"missing verity", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			return []byte(markers[0] + "\n")
		}, "contains 0 exact"},
		{"duplicate verity", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			return []byte(markers[0] + "\n" + markers[1] + "\n" + markers[1] + "\n")
		}, "contains 2 exact"},
		{"wrong boot digest", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			markers[0] = strings.Replace(markers[0], value.compatibility.BootImageDigest, digestBytes([]byte("other")), 1)
			return []byte(strings.Join(markers, "\n") + "\n")
		}, "does not exactly match"},
		{"wrong root hash", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			markers[1] = strings.Replace(markers[1], value.compatibility.RootHashDigest, digestBytes([]byte("other")), 1)
			return []byte(strings.Join(markers, "\n") + "\n")
		}, "does not exactly match"},
		{"extra marker field", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			markers[0] += " unexpected=true"
			return []byte(strings.Join(markers, "\n") + "\n")
		}, "does not exactly match"},
		{"long line", func(value evidenceInputs) []byte {
			markers, _ := ExpectedUARTMarkers(value.compatibility)
			return []byte(strings.Repeat("x", maximumUARTLineBytes+1) + "\n" + strings.Join(markers, "\n") + "\n")
		}, "line longer"},
		{"NUL", func(value evidenceInputs) []byte { return append(append([]byte(nil), value.uart...), 0) }, "NUL-free"},
		{"invalid UTF-8", func(value evidenceInputs) []byte { return append(append([]byte(nil), value.uart...), 0xff) }, "UTF-8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeEvidenceInputs(t)
			inputs.uart = test.mutate(inputs)
			mustWrite(t, inputs.uartPath, inputs.uart)
			inputs.observation.UARTCaptureDigest = rawDigest(inputs.uart)
			writeJSON(t, inputs.observationPath, inputs.observation)
			_, err := verifyEvidence(inputs)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestStrictInputsRejectUnknownDuplicateTrailingSymlinkAndOversize(t *testing.T) {
	t.Run("unknown observation field", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		raw, err := os.ReadFile(inputs.observationPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), `"observation_id":`, `"device_path":"/dev/example","observation_id":`, 1))
		mustWrite(t, inputs.observationPath, raw)
		_, err = verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("duplicate nested field", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		raw, err := os.ReadFile(inputs.observationPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), `"lane_id":`, `"lane_id":"duplicate","lane_id":`, 1))
		mustWrite(t, inputs.observationPath, raw)
		_, err = verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("trailing observation", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		file, err := os.OpenFile(inputs.observationPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(` {}`)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("append: %v close: %v", writeErr, closeErr)
		}
		_, err = verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("UART symlink", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		link := filepath.Join(filepath.Dir(inputs.uartPath), "uart-link.txt")
		if err := os.Symlink(inputs.uartPath, link); err != nil {
			t.Fatal(err)
		}
		inputs.uartPath = link
		_, err := verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("oversize UART", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		mustWrite(t, inputs.uartPath, []byte(strings.Repeat("x", maximumUARTCaptureBytes+1)))
		_, err := verifyEvidence(inputs)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestPackageDependsOnlyOnTheOfflineCompatibilityContract(t *testing.T) {
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.HasPrefix(dependency, "github.com/ams-tech/nixos-kaiba-network/provisioning/") && dependency != "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat" {
			t.Fatalf("evidence correlation package gained a production repository dependency %q", dependency)
		}
		if dependency == "os/exec" || dependency == "net" || strings.HasPrefix(dependency, "net/") {
			t.Fatalf("evidence correlation package gained a process or network dependency %q", dependency)
		}
	}
}

func verifyEvidence(inputs evidenceInputs) (Outcome, error) {
	return Verify(inputs.manifestPath, inputs.capsuleRoot, inputs.fixturePath, inputs.publicKeyPath, inputs.observationPath, inputs.uartPath, inputs.policy)
}

func makeEvidenceInputs(t *testing.T) evidenceInputs {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "capsule")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := testEvidenceSigningKey(t)
	bootImage := []byte("immutable boot capsule")
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
		{"nvme/root-data.img", []byte("immutable root data")},
		{"nvme/root-hash.img", []byte("immutable verity hash tree")},
	}
	files := make([]unfusedcompat.CapsuleFile, 0, len(contents))
	for _, content := range contents {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, content.path)), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(root, content.path), content.data)
		files = append(files, unfusedcompat.CapsuleFile{Path: content.path, SizeBytes: int64(len(content.data)), SHA256: digestBytes(content.data)})
	}
	capsuleDigest, err := unfusedcompat.ComputeCapsuleDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := unfusedcompat.CapsuleManifest{
		SchemaVersion: unfusedcompat.ManifestSchemaVersion, CapsuleID: "capsule-fixture-1",
		CapsuleDigest: capsuleDigest, BootImagePath: "boot.img", BootSignaturePath: "boot.sig",
		RootDataPath: "nvme/root-data.img", RootHashPath: "nvme/root-hash.img", Files: files,
	}
	fixture := unfusedcompat.OfflineFixture{
		SchemaVersion: unfusedcompat.FixtureSchemaVersion, FixtureID: "fixture-1",
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
	writeJSON(t, manifestPath, manifest)
	writeJSON(t, fixturePath, fixture)
	publicKeyFingerprint := writePublicKey(t, publicKeyPath, &privateKey.PublicKey)
	policy, err := unfusedcompat.NewTrustedSignerPolicy(publicKeyFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	compatibility, err := unfusedcompat.VerifySignedOfflineFixture(manifestPath, root, fixturePath, publicKeyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	compatibilityDigest, err := CompatibilityOutcomeDigest(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := ExpectedUARTMarkers(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	uart := []byte("boot log\r\n" + markers[0] + "\r\n" + markers[1] + "\r\nshutdown\r\n")
	observation := HardwareObservation{
		SchemaVersion: ObservationSchemaVersion, ObservationID: "observation-1",
		CompatibilityOutcomeDigest: compatibilityDigest,
		CapsuleID:                  compatibility.CapsuleID, CapsuleDigest: compatibility.CapsuleDigest,
		BootImageDigest: compatibility.BootImageDigest, BootSignatureDigest: compatibility.BootSignatureDigest,
		BootPublicKeyFingerprint:     compatibility.BootPublicKeyFingerprint,
		SignatureVerificationReceipt: compatibility.SignatureVerificationReceipt,
		SignerTrustPolicyDigest:      compatibility.SignerTrustPolicyDigest,
		RootDataDigest:               compatibility.RootDataDigest, RootHashDigest: compatibility.RootHashDigest,
		UARTCaptureDigest:                  rawDigest(uart),
		ManualBOOTSELConfirmation:          ManualBOOTSELConfirmation,
		PreBOOTSELPowerRemovalConfirmation: CompletePowerRemoval,
		ModeChangePowerRemovalConfirmation: CompletePowerRemoval,
		ManualNormalBootConfirmation:       ManualNormalBootConfirmation,
		PostBootPowerRemovalConfirmation:   CompletePowerRemoval,
		Before:                             TargetObservation{LaneID: "lane-1", TargetFingerprint: digestBytes([]byte("target")), CustomerKeyHash: ZeroCustomerKeyHash},
		After:                              TargetObservation{LaneID: "lane-1", TargetFingerprint: digestBytes([]byte("target")), CustomerKeyHash: ZeroCustomerKeyHash},
	}
	observationPath := filepath.Join(base, "observation.json")
	uartPath := filepath.Join(base, "uart.txt")
	writeJSON(t, observationPath, observation)
	mustWrite(t, uartPath, uart)
	return evidenceInputs{
		manifestPath: manifestPath, capsuleRoot: root, fixturePath: fixturePath, publicKeyPath: publicKeyPath,
		observationPath: observationPath, uartPath: uartPath, policy: policy,
		manifest: manifest, fixture: fixture, compatibility: compatibility, observation: observation, uart: uart,
	}
}

func testEvidenceSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	evidenceSigningKeyOnce.Do(func() {
		evidenceSigningKey, evidenceSigningKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if evidenceSigningKeyErr != nil {
		t.Fatal(evidenceSigningKeyErr)
	}
	return evidenceSigningKey
}

func writePublicKey(t *testing.T, filePath string, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filePath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return digestBytes(der)
}

func writeJSON(t *testing.T, filePath string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filePath, data)
}

func mustWrite(t *testing.T, filePath string, value []byte) {
	t.Helper()
	if err := os.WriteFile(filePath, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
