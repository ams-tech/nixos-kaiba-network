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
  "EEPROM_HASH": "dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137",
  "CUSTOMER_KEY_HASH": "0000000000000000000000000000000000000000000000000000000000000000",
  "BOOT_ROM": "0000000A",
  "BOARD_ATTR": "00000000",
  "USER_BOARDREV": "B04170",
  "JTAG_LOCKED": "0",
  "MAC_WIFI_ADDR": "2C:CF:67:70:76:F4",
  "MAC_BT_ADDR": "2C:CF:67:70:76:F5",
  "FACTORY_UUID": "001000911006186073"
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
		name     string
		metadata string
		wantCode int
		want     provisioning.Status
	}{
		{
			name:     "compute module 5",
			metadata: strings.Replace(testMetadata, "B04170", "804180", 1),
			wantCode: exitDeviceClass,
			want:     provisioning.StatusFail,
		},
		{
			name:     "pi 500",
			metadata: strings.Replace(testMetadata, "B04170", "8041A0", 1),
			wantCode: exitDeviceClass,
			want:     provisioning.StatusFail,
		},
		{
			name:     "locked JTAG",
			metadata: strings.Replace(testMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "1"`, 1),
			wantCode: exitBaseline,
			want:     provisioning.StatusPass,
		},
		{
			name:     "missing optional EEPROM hash",
			metadata: removeLine(testMetadata, `"EEPROM_HASH"`),
			wantCode: exitBaseline,
			want:     provisioning.StatusPass,
		},
		{
			name:     "future metadata field",
			metadata: strings.Replace(testMetadata, `"FACTORY_UUID"`, `"FUTURE_SECURITY_STATE": "unknown", "FACTORY_UUID"`, 1),
			wantCode: exitBaseline,
			want:     provisioning.StatusPass,
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
			if result.Assessment.Class.Status != tt.want {
				t.Fatalf("class status = %q, want %q", result.Assessment.Class.Status, tt.want)
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

func removeLine(raw, marker string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if strings.Contains(line, marker) {
			return strings.Join(append(lines[:i], lines[i+1:]...), "\n")
		}
	}
	return raw
}
