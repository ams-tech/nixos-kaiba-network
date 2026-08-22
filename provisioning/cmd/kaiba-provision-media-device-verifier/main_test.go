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

func TestCommandExposesOnlyReadOnlyProductionVerification(t *testing.T) {
	originalUID, originalPlan, originalReadStage, originalParseStage := effectiveUID, loadPlan, readStageReceipt, parseStageReceipt
	originalVerify, originalValidate, originalWrite := verifyAndEncodeDevice, validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan, readStageReceipt, parseStageReceipt = originalUID, originalPlan, originalReadStage, originalParseStage
		verifyAndEncodeDevice, validateEvidence, writeEvidence = originalVerify, originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/evidence/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	readStageReceipt = func(path string) ([]byte, error) {
		if path != "/evidence/stage.json" {
			t.Fatalf("stage path = %q", path)
		}
		return []byte("trusted stage bytes"), nil
	}
	parseStageReceipt = func(data []byte, _ mediacontract.Plan) (mediacontract.StageReceipt, error) {
		if string(data) != "trusted stage bytes" {
			t.Fatalf("stage bytes = %q", data)
		}
		return mediacontract.StageReceipt{}, nil
	}
	verifyAndEncodeDevice = func(context.Context, mediacontract.Plan, mediacontract.StageReceipt) ([]byte, error) {
		return []byte("{\"verification_mode\":\"independent_read_only_device\"}"), nil
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(path string, data []byte) error {
		if path != "/evidence/verify.json" || !bytes.Contains(data, []byte("independent_read_only_device")) {
			t.Fatalf("writeEvidence(%q, %q)", path, data)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"verify", "--plan", "/evidence/plan.json", "--stage-receipt", "/evidence/stage.json", "--receipt", "/evidence/verify.json"}, &stdout, &stderr)
	if code != exitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, arguments := range [][]string{
		nil,
		{"verify"},
		{"verify-device", "--plan", "/evidence/plan.json"},
		{"verify", "--plan", "/evidence/plan.json", "--stage-receipt", "/evidence/stage.json", "--receipt", "/evidence/verify.json", "--target", "/dev/sda"},
		{"verify", "--plan", "/evidence/plan.json", "--stage-receipt", "/evidence/stage.json", "--receipt", "/evidence/verify.json", "--fixture"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandRequiresRootBeforeReadingEvidence(t *testing.T) {
	originalUID, originalPlan := effectiveUID, loadPlan
	t.Cleanup(func() { effectiveUID, loadPlan = originalUID, originalPlan })
	effectiveUID = func() int { return 1000 }
	loadPlan = func(string) (mediacontract.Plan, error) {
		t.Fatal("loadPlan called without root")
		return mediacontract.Plan{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"verify", "--plan", "/evidence/plan.json", "--stage-receipt", "/evidence/stage.json", "--receipt", "/evidence/verify.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestVerificationFailurePublishesNothing(t *testing.T) {
	originalUID, originalPlan, originalReadStage, originalParseStage := effectiveUID, loadPlan, readStageReceipt, parseStageReceipt
	originalVerify, originalValidate, originalWrite := verifyAndEncodeDevice, validateEvidence, writeEvidence
	t.Cleanup(func() {
		effectiveUID, loadPlan, readStageReceipt, parseStageReceipt = originalUID, originalPlan, originalReadStage, originalParseStage
		verifyAndEncodeDevice, validateEvidence, writeEvidence = originalVerify, originalValidate, originalWrite
	})
	effectiveUID = func() int { return 0 }
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	readStageReceipt = func(string) ([]byte, error) { return []byte("trusted stage bytes"), nil }
	parseStageReceipt = func([]byte, mediacontract.Plan) (mediacontract.StageReceipt, error) {
		return mediacontract.StageReceipt{}, nil
	}
	verifyAndEncodeDevice = func(context.Context, mediacontract.Plan, mediacontract.StageReceipt) ([]byte, error) {
		return nil, errors.New("full media tampered")
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error {
		t.Fatal("writeEvidence called after verification failure")
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"verify", "--plan", "/evidence/plan.json", "--stage-receipt", "/evidence/stage.json", "--receipt", "/evidence/verify.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "full media tampered") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
