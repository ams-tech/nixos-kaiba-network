//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func init() { requireApprovedPlan = func(mediacontract.Plan) error { return nil } }

func TestCommandSeparatesDryRunAndDestructiveStage(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalDryRun, originalStage, originalValidate, originalWrite := dryRunAndEncode, stageAndEncode, validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		dryRunAndEncode, stageAndEncode, validateEvidence, writeEvidence = originalDryRun, originalStage, originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/evidence/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	dryRunAndEncode = func(context.Context, mediacontract.Plan) ([]byte, error) {
		return []byte("{\"status\":\"validated_no_write\"}"), nil
	}
	stageAndEncode = func(context.Context, mediacontract.Plan) ([]byte, error) {
		return []byte("{\"status\":\"staged_readback_required\"}"), nil
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(path string, data []byte) error {
		if path != "/evidence/stage.json" || !bytes.Contains(data, []byte("staged_readback_required")) {
			t.Fatalf("writeEvidence(%q, %q)", path, data)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"dry-run", "--plan", "/evidence/plan.json"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 || stdout.String() != "{\"status\":\"validated_no_write\"}\n" {
		t.Fatalf("dry-run exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stage exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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
		{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/out.json", "--target", "/dev/sda"},
		{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/out.json", "--fixture"},
		{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/out.json", "--force"},
		{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/out.json", "--root-data", "/tmp/root.img"},
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
	code := run(context.Background(), []string{"dry-run", "--plan", "/evidence/plan.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStageFailurePublishesNoReceipt(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalStage, originalValidate, originalWrite := stageAndEncode, validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		stageAndEncode, validateEvidence, writeEvidence = originalStage, originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	stageAndEncode = func(context.Context, mediacontract.Plan) ([]byte, error) {
		return nil, errors.New("TARGET MUTATED; quarantine")
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error {
		t.Fatal("writeEvidence called after staging failure")
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "quarantine") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestReceiptPublicationFailureReportsMutatedTargetQuarantine(t *testing.T) {
	originalUID, originalLoad := effectiveUID, loadPlan
	originalStage, originalValidate, originalWrite := stageAndEncode, validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan = originalUID, originalLoad
		stageAndEncode, validateEvidence, writeEvidence = originalStage, originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	stageAndEncode = func(context.Context, mediacontract.Plan) ([]byte, error) { return []byte("{}"), nil }
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error { return errors.New("injected durable publication failure") }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--receipt", "/evidence/stage.json"}, &stdout, &stderr)
	if code != exitInternal || stdout.Len() != 0 || !strings.Contains(stderr.String(), "TARGET MUTATED; quarantine") || !strings.Contains(stderr.String(), "do not retry automatically") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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
