package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const testMetadata = `{
  "USER_SERIAL_NUM": "A7EB274C",
  "MAC_ADDR": "2C:CF:67:70:76:F3",
  "CUSTOMER_KEY_HASH": "0000000000000000000000000000000000000000000000000000000000000000",
  "BOOT_ROM": "0000000A",
  "BOARD_ATTR": "00000000",
  "USER_BOARDREV": "B04170",
  "JTAG_LOCKED": "0",
  "MAC_WIFI_ADDR": "2C:CF:67:70:76:F4",
  "MAC_BT_ADDR": "2C:CF:67:70:76:F5",
  "FACTORY_UUID": "001000911006186073",
  "SIGNATURE_MODE": "0",
  "ADVANCED_BOOT": "00000000"
}`

type fakeEvidenceSource struct {
	wantRequest rpi5.ProbeRequest
	evidence    rpi5.RawEvidence
	err         error
	called      bool
}

func (s *fakeEvidenceSource) Acquire(_ context.Context, request rpi5.ProbeRequest) (rpi5.RawEvidence, error) {
	s.called = true
	if request != s.wantRequest {
		return rpi5.RawEvidence{}, errors.New("unexpected probe request")
	}
	return s.evidence, s.err
}

func TestRunOfflineProbeProducesDeterministicResult(t *testing.T) {
	profilePath := repositoryProfilePath(t)
	fixed := time.Date(2026, 8, 11, 12, 30, 0, 0, time.UTC)
	deps := dependencies{
		now: func() time.Time { return fixed },
		liveSource: func() rpi5.EvidenceSource {
			t.Fatal("offline probe attempted to construct a live evidence source")
			return nil
		},
	}

	var firstOut, firstErr bytes.Buffer
	code := run(context.Background(), []string{
		"probe", "--profile", profilePath, "--metadata", "-",
	}, strings.NewReader(testMetadata), &firstOut, &firstErr, deps)
	if code != exitOK {
		t.Fatalf("run() = %d, stderr = %s", code, firstErr.String())
	}
	if firstErr.Len() != 0 {
		t.Fatalf("stderr = %q", firstErr.String())
	}

	var result probeResult
	if err := json.Unmarshal(firstOut.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v\n%s", err, firstOut.String())
	}
	if result.SchemaVersion != resultSchemaVersion || result.ObservedAt != fixed {
		t.Fatalf("result header = %#v", result)
	}
	if result.Source.Source != "offline-metadata" || result.Source.ToolDigest != "" {
		t.Fatalf("offline provenance = %#v", result.Source)
	}
	if result.Assessment.Class.Status != provisioning.StatusPass || result.Assessment.ObservableBaseline.Status != provisioning.StatusPass {
		t.Fatalf("assessment = %#v", result.Assessment)
	}
	if !result.Assessment.EligibleForReversibleQualification || result.Assessment.MutationEligible {
		t.Fatalf("eligibility = %#v", result.Assessment)
	}
	if result.Assessment.FullUnprovisionedState != provisioning.FullUnprovisionedStateNotEstablished {
		t.Fatalf("full state = %q", result.Assessment.FullUnprovisionedState)
	}
	if len(result.Observation.TargetFingerprint) != len("sha256:")+64 || len(result.Observation.EvidenceDigest) != len("sha256:")+64 {
		t.Fatalf("observation digests = %#v", result.Observation)
	}
	if result.Observation.EEPROMHash != "" {
		t.Fatalf("optional EEPROM hash = %q, want absent", result.Observation.EEPROMHash)
	}

	var secondOut, secondErr bytes.Buffer
	code = run(context.Background(), []string{
		"probe", "--profile", profilePath, "--metadata", "-",
	}, strings.NewReader(testMetadata), &secondOut, &secondErr, deps)
	if code != exitOK || secondErr.Len() != 0 {
		t.Fatalf("second run = %d, stderr = %s", code, secondErr.String())
	}
	if !bytes.Equal(firstOut.Bytes(), secondOut.Bytes()) {
		t.Fatalf("output is not deterministic:\nfirst: %s\nsecond: %s", firstOut.String(), secondOut.String())
	}
}

func TestRunLiveProbeUsesExactTargetAndProvenance(t *testing.T) {
	request := rpi5.ProbeRequest{LaneID: "lane-1", USBPath: "1-2.3"}
	source := &fakeEvidenceSource{
		wantRequest: request,
		evidence: rpi5.RawEvidence{
			Metadata: []byte(testMetadata),
			Provenance: rpi5.Provenance{
				Source: "live-rpiboot", LaneID: request.LaneID, USBPath: request.USBPath,
				ToolDigest: "sha256:tool", BundleDigest: "sha256:bundle",
			},
		},
	}
	deps := dependencies{
		now:        func() time.Time { return time.Unix(1, 0) },
		liveSource: func() rpi5.EvidenceSource { return source },
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"probe", "--profile", repositoryProfilePath(t), "--lane-id", request.LaneID, "--usb-path", request.USBPath,
	}, strings.NewReader("must not be read"), &stdout, &stderr, deps)
	if code != exitOK || !source.called {
		t.Fatalf("run() = %d, called = %v, stderr = %s", code, source.called, stderr.String())
	}
	var result probeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Source != source.evidence.Provenance {
		t.Fatalf("source = %#v, want %#v", result.Source, source.evidence.Provenance)
	}
}

func TestRunAssessmentExitCodesStillEmitJSON(t *testing.T) {
	tests := []struct {
		name         string
		metadata     string
		wantCode     int
		wantClass    provisioning.Status
		wantBaseline provisioning.Status
	}{
		{
			name:         "compute module 5",
			metadata:     strings.Replace(testMetadata, "B04170", "804180", 1),
			wantCode:     exitDeviceClass,
			wantClass:    provisioning.StatusFail,
			wantBaseline: provisioning.StatusIndeterminate,
		},
		{
			name:         "pi 500",
			metadata:     strings.Replace(testMetadata, "B04170", "8041A0", 1),
			wantCode:     exitDeviceClass,
			wantClass:    provisioning.StatusFail,
			wantBaseline: provisioning.StatusIndeterminate,
		},
		{
			name:         "locked JTAG",
			metadata:     strings.Replace(testMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "1"`, 1),
			wantCode:     exitBaseline,
			wantClass:    provisioning.StatusPass,
			wantBaseline: provisioning.StatusFail,
		},
		{
			name:         "missing optional EEPROM hash",
			metadata:     testMetadata,
			wantCode:     exitOK,
			wantClass:    provisioning.StatusPass,
			wantBaseline: provisioning.StatusPass,
		},
		{
			name:         "future metadata field",
			metadata:     strings.Replace(testMetadata, `"FACTORY_UUID"`, `"FUTURE_SECURITY_STATE": "unknown", "FACTORY_UUID"`, 1),
			wantCode:     exitBaseline,
			wantClass:    provisioning.StatusPass,
			wantBaseline: provisioning.StatusIndeterminate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{
				"probe", "--profile", repositoryProfilePath(t), "--metadata", "-",
			}, strings.NewReader(tt.metadata), &stdout, &stderr, testDependencies(t))
			if code != tt.wantCode {
				t.Fatalf("run() = %d, want %d, stderr = %s", code, tt.wantCode, stderr.String())
			}
			if stdout.Len() == 0 || !json.Valid(stdout.Bytes()) {
				t.Fatalf("stdout is not a JSON result: %q", stdout.String())
			}
			var result probeResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Assessment.Class.Status != tt.wantClass {
				t.Fatalf("class status = %q, want %q", result.Assessment.Class.Status, tt.wantClass)
			}
			if result.Assessment.ObservableBaseline.Status != tt.wantBaseline {
				t.Fatalf("baseline status = %q, want %q", result.Assessment.ObservableBaseline.Status, tt.wantBaseline)
			}
		})
	}
}

func TestRunRejectsUsageProfileAndEvidenceWithoutJSON(t *testing.T) {
	validProfile := repositoryProfilePath(t)
	badProfile := filepath.Join(t.TempDir(), "bad-profile.json")
	if err := os.WriteFile(badProfile, []byte(`{"apiVersion":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		in   string
		want int
	}{
		{"missing subcommand", nil, "", exitUsageOrProfile},
		{"both sources", []string{"probe", "--profile", validProfile, "--metadata", "-", "--lane-id", "lane-1", "--usb-path", "1-2"}, testMetadata, exitUsageOrProfile},
		{"partial live source", []string{"probe", "--profile", validProfile, "--usb-path", "1-2"}, "", exitUsageOrProfile},
		{"invalid profile", []string{"probe", "--profile", badProfile, "--metadata", "-"}, testMetadata, exitUsageOrProfile},
		{"malformed evidence", []string{"probe", "--profile", validProfile, "--metadata", "-"}, `{`, exitEvidence},
		{"oversized evidence", []string{"probe", "--profile", validProfile, "--metadata", "-"}, strings.Repeat("x", rpi5.MaxMetadataSize+1), exitEvidence},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, strings.NewReader(tt.in), &stdout, &stderr, testDependencies(t))
			if code != tt.want {
				t.Fatalf("run() = %d, want %d, stderr = %s", code, tt.want, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatal("stderr is empty")
			}
		})
	}
}

func TestRunLiveAcquisitionError(t *testing.T) {
	source := &fakeEvidenceSource{
		wantRequest: rpi5.ProbeRequest{LaneID: "lane-1", USBPath: "1-2"},
		err:         errors.New("USB transfer failed"),
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"probe", "--profile", repositoryProfilePath(t), "--lane-id", "lane-1", "--usb-path", "1-2",
	}, strings.NewReader(""), &stdout, &stderr, dependencies{
		now:        time.Now,
		liveSource: func() rpi5.EvidenceSource { return source },
	})
	if code != exitEvidence || stdout.Len() != 0 || !strings.Contains(stderr.String(), "USB transfer failed") {
		t.Fatalf("run = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunQualificationEmitsOnlyRedactedPublicEvidence(t *testing.T) {
	profilePath := repositoryProfilePath(t)
	profileFile, err := os.Open(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := provisioning.LoadProfile(profileFile)
	if closeErr := profileFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	observation, err := rpi5.ParseMetadata([]byte(testMetadata))
	if err != nil {
		t.Fatal(err)
	}
	assessment := provisioning.Evaluate(profile, provisioning.TargetObservation{
		AdapterID:      observation.AdapterID,
		AdapterVersion: observation.AdapterVersion,
		Facts:          observation.Facts(),
		UnknownFields:  observation.UnknownFields,
	})
	result := probeResult{
		SchemaVersion: resultSchemaVersion,
		ObservedAt:    time.Unix(10, 0).UTC(),
		Profile: profileReference{
			ID: profile.Metadata.ID, Status: profile.Metadata.Status,
			Digest: profile.Digest, PolicyDigest: profile.PolicyDigest,
		},
		Adapter: adapterReference{ID: rpi5.AdapterID, Version: rpi5.AdapterVersion},
		Source: rpi5.Provenance{
			Source: "live-rpiboot", LaneID: "lane-1", USBPath: "1-2.3", ToolVersion: "test",
			ToolDigest: "sha256:" + strings.Repeat("1", 64), BundleDigest: "sha256:" + strings.Repeat("2", 64),
			FirmwareDigest: "sha256:" + strings.Repeat("3", 64), ConfigDigest: "sha256:" + strings.Repeat("4", 64),
		},
		Observation: observation,
		Assessment:  assessment,
	}
	firstPath := writePrivateProbeResult(t, result, "probe-1.json")
	result.ObservedAt = time.Unix(20, 0).UTC()
	secondPath := writePrivateProbeResult(t, result, "probe-2.json")

	args := []string{
		"qualify",
		"--profile", profilePath,
		"--first-result", firstPath,
		"--second-result", secondPath,
		"--source-revision", strings.Repeat("a", 40),
		"--system-closure", "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-kaiba-station-1",
		"--power-cycle-confirmation", "complete",
		"--pre-probe-normal-boot", "confirmed",
		"--normal-boot-confirmation", "unchanged",
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, strings.NewReader("unused"), &stdout, &stderr, dependencies{})
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("run = %d, stderr = %s", code, stderr.String())
	}
	var record rpi5.QualificationRecord
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Status != rpi5.QualificationStatusPassed || record.MutationEligible {
		t.Fatalf("record = %#v", record)
	}
	if len(record.Probes) != 2 || record.Probes[0].EEPROMHash != nil || record.Probes[1].EEPROMHash != nil {
		t.Fatalf("absent EEPROM hashes were not redacted as null: %#v", record.Probes)
	}
	eepromComparisonObserved := false
	for _, comparison := range record.Comparisons {
		if comparison.Field != "eeprom_hash" {
			continue
		}
		eepromComparisonObserved = true
		if comparison.Status != "not_observed" {
			t.Fatalf("EEPROM comparison status = %q, want not_observed", comparison.Status)
		}
	}
	if !eepromComparisonObserved {
		t.Fatal("qualification record omitted EEPROM comparison")
	}
	for _, privateValue := range []string{
		observation.UserSerial, observation.FactoryUUID, observation.EthernetMAC,
		observation.WiFiMAC, observation.BluetoothMAC, result.Source.LaneID, result.Source.USBPath,
		"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-kaiba-station-1",
	} {
		if strings.Contains(stdout.String(), privateValue) {
			t.Fatalf("public output leaked %q", privateValue)
		}
	}

	args[len(args)-1] = "pending"
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), args, strings.NewReader("unused"), &stdout, &stderr, dependencies{})
	if code != exitIncomplete || stderr.Len() != 0 {
		t.Fatalf("pending boot run = %d, stderr = %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Status != rpi5.QualificationStatusIncomplete || record.QuarantineRequired {
		t.Fatalf("pending boot record = %#v", record)
	}

	args[len(args)-1] = "failed"
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), args, strings.NewReader("unused"), &stdout, &stderr, dependencies{})
	if code != exitQualification || stderr.Len() != 0 {
		t.Fatalf("failed boot run = %d, stderr = %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Status != rpi5.QualificationStatusFailed || !record.QuarantineRequired {
		t.Fatalf("failed boot record = %#v", record)
	}
}

func TestRunQualificationRequiresExplicitCeremonyConfirmations(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"qualify", "--profile", repositoryProfilePath(t), "--first-result", "first.json", "--second-result", "second.json",
		"--source-revision", strings.Repeat("a", 40),
		"--system-closure", "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-kaiba-station-1",
		"--power-cycle-confirmation", "complete", "--pre-probe-normal-boot", "confirmed",
	}, strings.NewReader(""), &stdout, &stderr, dependencies{})
	if code != exitUsageOrProfile || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("run = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func repositoryProfilePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "profiles", "device-classes", "raspberry-pi-5-model-b-v1alpha1.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locate repository profile: %v", err)
	}
	return path
}

func testDependencies(t *testing.T) dependencies {
	t.Helper()
	return dependencies{
		now: func() time.Time { return time.Unix(1, 0) },
		liveSource: func() rpi5.EvidenceSource {
			t.Fatal("unexpected live source")
			return nil
		},
	}
}

func writePrivateProbeResult(t *testing.T, result probeResult, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
