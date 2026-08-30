//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

func init() {
	requireApprovedPlan = func(mediacontract.Plan) error { return nil }
	hardwareConfigurationID = "hardware-configuration:test-station:1"
	expectedHostname = "test-station"
	targetDevicePath = "/dev/sda"
	hostname = func() (string, error) { return "test-station", nil }
}

func testConfiguredStation(t *testing.T) configuredStation {
	t.Helper()
	policy, err := mediadevice.NewStationPolicy("test-station", "")
	if err != nil {
		t.Fatal(err)
	}
	return configuredStation{
		HardwareConfigurationID: "hardware-configuration:test-station:1",
		Hostname:                "test-station", TargetDevicePath: "/dev/sda", Policy: policy,
	}
}

func testDevicePreflightBytes(t *testing.T, plan mediacontract.Plan) []byte {
	t.Helper()
	report := newDevicePreflight(plan, testConfiguredStation(t), mediainventory.TargetFacts{
		RequestedPath: "/dev/sda", ResolvedPath: "/dev/sda",
		BootID: "11111111-1111-4111-8111-111111111111", DiskSequence: 23,
	})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCommandSeparatesDryRunAndDestructiveStage(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalDryRun, originalStage, originalRead := dryRunAndEncode, stageAndEncode, readPreflight
	originalValidate, originalWrite := validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		dryRunAndEncode, stageAndEncode, readPreflight = originalDryRun, originalStage, originalRead
		validateEvidence, writeEvidence = originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/evidence/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	preflight := testDevicePreflightBytes(t, mediacontract.Plan{})
	dryRunAndEncode = func(_ context.Context, _ mediacontract.Plan, station configuredStation) ([]byte, error) {
		if station.TargetDevicePath != "/dev/sda" {
			t.Fatalf("station target = %q", station.TargetDevicePath)
		}
		return preflight, nil
	}
	stageAndEncode = func(_ context.Context, _ mediacontract.Plan, _ configuredStation, reviewed devicePreflight) ([]byte, error) {
		if reviewed.ResolvedDevicePath != "/dev/sda" {
			t.Fatalf("reviewed target = %q", reviewed.ResolvedDevicePath)
		}
		return []byte("{\"status\":\"staged_readback_required\"}"), nil
	}
	readPreflight = func(path string) ([]byte, error) {
		if path != "/evidence/preflight.json" {
			t.Fatalf("preflight path = %q", path)
		}
		return preflight, nil
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(path string, data []byte) error {
		validPreflight := path == "/evidence/preflight.json" && bytes.Equal(data, preflight)
		validStage := path == "/evidence/stage.json" && bytes.Contains(data, []byte("staged_readback_required"))
		if !validPreflight && !validStage {
			t.Fatalf("writeEvidence(%q, %q)", path, data)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"dry-run", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 || stdout.String() != string(preflight)+"\n" {
		t.Fatalf("dry-run exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stage exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestV1Alpha3PreflightReportsReviewedOperationalSelection(t *testing.T) {
	report := devicePreflight{
		SchemaVersion:           devicePreflightSchemaVersion,
		Status:                  "validated_no_write",
		EvidenceMode:            "device_preflight",
		Target:                  mediacontract.TargetBinding{SizeBytes: 8 * mediacontract.AlignmentBytes, LogicalSectorSizeBytes: 512},
		HardwareConfigurationID: "hardware-configuration:test-station:1",
		ExecutionHostname:       "test-station",
		RequestedDeviceSelector: "/dev/disk/by-path/platform-test",
		ResolvedDevicePath:      "/dev/sda",
		SourcesVerified:         true,
		TargetUsageClear:        true,
		TargetWholeDevice:       true,
		TargetGeometryVerified:  true,
		TargetLocked:            true,
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"schema_version":"kaiba.provisioning.rpi5-media-device-preflight/v1alpha3"`,
		`"hardware_configuration_id":"hardware-configuration:test-station:1"`,
		`"execution_hostname":"test-station"`,
		`"requested_device_selector":"/dev/disk/by-path/platform-test"`,
		`"resolved_device_path":"/dev/sda"`,
		`"target_whole_device":true`,
		`"target_geometry_verified":true`,
	} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("preflight is missing %s: %s", required, encoded)
		}
	}
	for _, prohibited := range []string{"initial_media_digest", "full_prestate_verified", "by_id_path", "serial", "wwid", "model"} {
		if bytes.Contains(encoded, []byte(prohibited)) {
			t.Fatalf("preflight retained prohibited field %q: %s", prohibited, encoded)
		}
	}
}

func TestDestructiveBinaryExposesNoFixtureOrOverrideFlags(t *testing.T) {
	originalUID := effectiveUID
	t.Cleanup(func() { effectiveUID = originalUID })
	effectiveUID = func() int { return 0 }
	for _, arguments := range [][]string{
		nil,
		{"stage"},
		{"dry-run", "--plan", "/evidence/plan.json", "--receipt", "/evidence/out.json"},
		{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/out.json", "--target", "/dev/sda"},
		{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/out.json", "--fixture"},
		{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/out.json", "--force"},
		{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/out.json", "--root-data", "/tmp/root.img"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandRequiresRootBeforeReadingPlan(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	t.Cleanup(func() { effectiveUID, loadPlan = originalUID, originalLoad })
	effectiveUID = func() int { return 1000 }
	loadPlan = func(string) (mediacontract.Plan, error) {
		t.Fatal("loadPlan called without root")
		return mediacontract.Plan{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"dry-run", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStageFailurePublishesNoReceipt(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalStage, originalRead := stageAndEncode, readPreflight
	originalValidate, originalWrite := validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		stageAndEncode, readPreflight = originalStage, originalRead
		validateEvidence, writeEvidence = originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	readPreflight = func(string) ([]byte, error) { return testDevicePreflightBytes(t, mediacontract.Plan{}), nil }
	stageAndEncode = func(context.Context, mediacontract.Plan, configuredStation, devicePreflight) ([]byte, error) {
		return nil, errors.New("TARGET MUTATED; quarantine")
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error {
		t.Fatal("writeEvidence called after staging failure")
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "quarantine") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestReceiptPublicationFailureReportsMutatedTargetQuarantine(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalStage, originalRead := stageAndEncode, readPreflight
	originalValidate, originalWrite := validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		stageAndEncode, readPreflight = originalStage, originalRead
		validateEvidence, writeEvidence = originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	readPreflight = func(string) ([]byte, error) { return testDevicePreflightBytes(t, mediacontract.Plan{}), nil }
	stageAndEncode = func(context.Context, mediacontract.Plan, configuredStation, devicePreflight) ([]byte, error) {
		return []byte("{}"), nil
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error { return errors.New("injected durable publication failure") }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitInternal || stdout.Len() != 0 || !strings.Contains(stderr.String(), "TARGET MUTATED; quarantine") || !strings.Contains(stderr.String(), "do not retry automatically") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestExecutionHostMismatchFailsBeforePlanLoad(t *testing.T) {
	originalUID, originalHostname, originalLoad := effectiveUID, hostname, loadPlan
	t.Cleanup(func() { effectiveUID, hostname, loadPlan = originalUID, originalHostname, originalLoad })
	effectiveUID = func() int { return 0 }
	hostname = func() (string, error) { return "malak", nil }
	loadPlan = func(string) (mediacontract.Plan, error) {
		t.Fatal("loadPlan called on the wrong execution host")
		return mediacontract.Plan{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"dry-run", "--plan", "/evidence/plan.json", "--preflight", "/evidence/preflight.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "bound to execution host") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestOperationalPreflightIsCanonicalAndAttachmentBound(t *testing.T) {
	plan := mediacontract.Plan{
		PlanDigest: mediacontract.Digest("sha256:" + strings.Repeat("a", 64)),
		Target:     mediacontract.TargetBinding{SizeBytes: 8 * mediacontract.AlignmentBytes, LogicalSectorSizeBytes: 512},
	}
	station := testConfiguredStation(t)
	canonical := testDevicePreflightBytes(t, plan)
	report, err := parseDevicePreflight(canonical, plan, station)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.validateCurrent(mediainventory.TargetFacts{
		RequestedPath: "/dev/sda", ResolvedPath: "/dev/sda",
		BootID: "11111111-1111-4111-8111-111111111111", DiskSequence: 23,
	}); err != nil {
		t.Fatal(err)
	}

	for _, mutate := range []func(*devicePreflight){
		func(value *devicePreflight) { value.HardwareConfigurationID = "hardware-configuration:other:1" },
		func(value *devicePreflight) { value.ExecutionHostname = "other-host" },
		func(value *devicePreflight) { value.RequestedDeviceSelector = "/dev/sdb" },
	} {
		changed := report
		mutate(&changed)
		encoded, marshalErr := json.Marshal(changed)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err := parseDevicePreflight(encoded, plan, station); err == nil {
			t.Fatalf("parseDevicePreflight accepted changed binding: %s", encoded)
		}
	}
	for _, mutate := range []func(*devicePreflight){
		func(value *devicePreflight) { value.ResolvedDevicePath = "/dev/sdb" },
		func(value *devicePreflight) { value.AttachmentSequence++ },
	} {
		changed := report
		mutate(&changed)
		if err := changed.validateCurrent(mediainventory.TargetFacts{
			RequestedPath: "/dev/sda", ResolvedPath: "/dev/sda",
			BootID: "11111111-1111-4111-8111-111111111111", DiskSequence: 23,
		}); err == nil {
			t.Fatal("validateCurrent accepted a changed attachment binding")
		}
	}

	pretty, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		pretty,
		append(append([]byte{}, canonical...), '\n'),
		bytes.Replace(canonical, []byte(`"status":`), []byte(`"unknown":true,"status":`), 1),
		bytes.Replace(canonical, []byte(`"status":`), []byte(`"status":"validated_no_write","status":`), 1),
	} {
		if _, err := parseDevicePreflight(invalid, plan, station); err == nil {
			t.Fatalf("parseDevicePreflight accepted noncanonical JSON: %s", invalid)
		}
	}
}

func TestGenericBuildHasNoSourceAuthority(t *testing.T) {
	original := []string{primaryGPTPath, bootFilesystemPath, rootDataPath, rootHashPath, backupGPTPath}
	t.Cleanup(func() {
		primaryGPTPath, bootFilesystemPath, rootDataPath, rootHashPath, backupGPTPath = original[0], original[1], original[2], original[3], original[4]
	})
	primaryGPTPath, bootFilesystemPath, rootDataPath, rootHashPath, backupGPTPath = "", "", "", "", ""
	if _, err := immutableAssetPaths(); err == nil || !strings.Contains(err.Error(), "linker-fixed") {
		t.Fatalf("immutableAssetPaths() error = %v", err)
	}
}
