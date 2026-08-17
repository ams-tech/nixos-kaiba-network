package unfusedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
)

type evidenceInputs struct {
	compatibilityPath string
	observationPath   string
	uartPath          string
	compatibility     unfusedcompat.Outcome
	observation       HardwareObservation
	uart              []byte
}

func TestVerifyProducesBoundedHardwareObservationWithoutEnforcement(t *testing.T) {
	inputs := makeEvidenceInputs(t)
	result, err := Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != OutcomeSchemaVersion || result.Status != StatusCompatibilityPassed || result.EvidenceMode != EvidenceModeOperatorHardware {
		t.Fatalf("unexpected result identity: %#v", result)
	}
	if !result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("hardware result contains the wrong policy claims: %#v", result)
	}
	if !result.SignatureVerified || result.BootPublicKeyFingerprint != inputs.compatibility.BootPublicKeyFingerprint || result.SignatureVerificationReceipt != inputs.compatibility.SignatureVerificationReceipt {
		t.Fatalf("hardware result lost signed-capsule verification: %#v", result)
	}
	if result.LaneID != inputs.observation.Before.LaneID || result.TargetFingerprint != inputs.observation.Before.TargetFingerprint {
		t.Fatalf("result lost target continuity: %#v", result)
	}
	if result.CustomerKeyHashBefore != ZeroCustomerKeyHash || result.CustomerKeyHashAfter != ZeroCustomerKeyHash {
		t.Fatalf("result lost unfused state: %#v", result)
	}
	if result.CompatibilityOutcomeDigest != inputs.observation.CompatibilityOutcomeDigest || result.UARTCaptureDigest != inputs.observation.UARTCaptureDigest {
		t.Fatalf("result lost input evidence binding: %#v", result)
	}
	if result.ObservationDigest == "" || result.BootImageDigest != inputs.compatibility.BootImageDigest || result.RootHashDigest != inputs.compatibility.RootHashDigest {
		t.Fatalf("result lost capsule evidence: %#v", result)
	}
}

func TestHardwareObservationRejectsBindingContinuityAndCeremonyTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HardwareObservation)
		want   string
	}{
		{"schema", func(value *HardwareObservation) { value.SchemaVersion = "other" }, "unsupported"},
		{"observation id", func(value *HardwareObservation) { value.ObservationID = "../observation" }, "observation_id"},
		{"compatibility result", func(value *HardwareObservation) { value.CompatibilityOutcomeDigest = digestBytes([]byte("other")) }, "compatibility outcome"},
		{"capsule id", func(value *HardwareObservation) { value.CapsuleID = "other" }, "capsule binding"},
		{"capsule digest", func(value *HardwareObservation) { value.CapsuleDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot image", func(value *HardwareObservation) { value.BootImageDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot signature", func(value *HardwareObservation) { value.BootSignatureDigest = digestBytes([]byte("other")) }, "capsule binding"},
		{"boot key", func(value *HardwareObservation) { value.BootPublicKeyFingerprint = digestBytes([]byte("other")) }, "capsule binding"},
		{"signature receipt", func(value *HardwareObservation) { value.SignatureVerificationReceipt = digestBytes([]byte("other")) }, "capsule binding"},
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
			_, err := Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCompatibilityOutcomeMustRemainOfflineAndNonEnforcing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*unfusedcompat.Outcome)
		want   string
	}{
		{"schema", func(value *unfusedcompat.Outcome) { value.SchemaVersion = "other" }, "successful offline"},
		{"status", func(value *unfusedcompat.Outcome) { value.Status = "failed" }, "successful offline"},
		{"mode", func(value *unfusedcompat.Outcome) { value.EvidenceMode = "hardware" }, "successful offline"},
		{"hardware", func(value *unfusedcompat.Outcome) { value.HardwareObserved = true }, "prohibited"},
		{"enforcement", func(value *unfusedcompat.Outcome) { value.SecurityEnforced = true }, "prohibited"},
		{"eligibility", func(value *unfusedcompat.Outcome) { value.MutationEligible = true }, "prohibited"},
		{"roles", func(value *unfusedcompat.Outcome) { value.FilesVerified = 3 }, "required capsule roles"},
		{"signature", func(value *unfusedcompat.Outcome) { value.SignatureVerified = false }, "detached boot signature"},
		{"boot key", func(value *unfusedcompat.Outcome) { value.BootPublicKeyFingerprint = "sha256:UPPER" }, "canonical"},
		{"signature receipt", func(value *unfusedcompat.Outcome) { value.SignatureVerificationReceipt = "sha256:UPPER" }, "canonical"},
		{"digest", func(value *unfusedcompat.Outcome) { value.RootHashDigest = "sha256:UPPER" }, "canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeEvidenceInputs(t)
			test.mutate(&inputs.compatibility)
			writeJSON(t, inputs.compatibilityPath, inputs.compatibility)
			_, err := Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
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
			_, err := Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
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
		_, err = Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
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
		_, err = Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("trailing outcome", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		file, err := os.OpenFile(inputs.compatibilityPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(` {}`)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("append: %v close: %v", writeErr, closeErr)
		}
		_, err = Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
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
		_, err := Verify(inputs.compatibilityPath, inputs.observationPath, link)
		if err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("oversize UART", func(t *testing.T) {
		inputs := makeEvidenceInputs(t)
		mustWrite(t, inputs.uartPath, []byte(strings.Repeat("x", maximumUARTCaptureBytes+1)))
		_, err := Verify(inputs.compatibilityPath, inputs.observationPath, inputs.uartPath)
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
			t.Fatalf("hardware evidence package gained a production repository dependency %q", dependency)
		}
		if dependency == "os/exec" || dependency == "net" || strings.HasPrefix(dependency, "net/") {
			t.Fatalf("hardware evidence package gained a process or network dependency %q", dependency)
		}
	}
}

func makeEvidenceInputs(t *testing.T) evidenceInputs {
	t.Helper()
	base := t.TempDir()
	compatibility := unfusedcompat.Outcome{
		SchemaVersion: unfusedcompat.OutcomeSchemaVersion,
		Status:        unfusedcompat.StatusCompatibilityPassed, EvidenceMode: unfusedcompat.EvidenceModeOfflineFixture,
		FixtureID: "fixture-1", CapsuleID: "capsule-1",
		ManifestDigest: digestBytes([]byte("manifest")), CapsuleDigest: digestBytes([]byte("capsule")),
		BootImageDigest: digestBytes([]byte("boot image")), BootSignatureDigest: digestBytes([]byte("boot signature")),
		BootPublicKeyFingerprint:     digestBytes([]byte("boot public key")),
		SignatureVerificationReceipt: digestBytes([]byte("signature receipt")), SignatureVerified: true,
		RootDataDigest: digestBytes([]byte("root data")), RootHashDigest: digestBytes([]byte("root hash")),
		FixtureDigest: digestBytes([]byte("fixture")), FilesVerified: 4,
		HardwareObserved: false, SecurityEnforced: false, MutationEligible: false,
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
	compatibilityPath := filepath.Join(base, "compatibility.json")
	observationPath := filepath.Join(base, "observation.json")
	uartPath := filepath.Join(base, "uart.txt")
	writeJSON(t, compatibilityPath, compatibility)
	writeJSON(t, observationPath, observation)
	mustWrite(t, uartPath, uart)
	return evidenceInputs{
		compatibilityPath: compatibilityPath, observationPath: observationPath, uartPath: uartPath,
		compatibility: compatibility, observation: observation, uart: uart,
	}
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
