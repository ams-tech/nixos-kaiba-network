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

func TestCommandExposesOnlyRegularFileReadback(t *testing.T) {
	originalLoad, originalVerify := loadPlan, verifyTarget
	t.Cleanup(func() { loadPlan, verifyTarget = originalLoad, originalVerify })
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/absolute/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	verifyTarget = func(_ context.Context, path string, _ mediacontract.Plan) (mediacontract.VerificationReport, error) {
		if path != "/absolute/target.img" {
			t.Fatalf("target path = %q", path)
		}
		return mediacontract.VerificationReport{SchemaVersion: mediacontract.VerificationReportSchemaVersion, GPTVerified: true, FATVerified: true, PartitionDigestsVerified: true, DMVerityVerified: true}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"verify-regular-file", "--plan", "/absolute/plan.json", "--target", "/absolute/target.img"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"gpt_verified":true`) || !strings.Contains(stdout.String(), `"hardware_observed":false`) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, arguments := range [][]string{
		nil,
		{"verify-regular-file"},
		{"verify-regular-file", "--plan", "/absolute/plan.json", "--target", "/absolute/target.img", "extra"},
		{"verify-device", "--plan", "/absolute/plan.json", "--target", "/dev/disk/by-id/example"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestRegularFileVerifierFailsClosedWithoutFixedVeritysetup(t *testing.T) {
	original := veritysetupPath
	t.Cleanup(func() { veritysetupPath = original })
	veritysetupPath = ""
	if _, err := verifyRegularFileTarget(context.Background(), "/tmp/nonexistent-target.img", mediacontract.Plan{}); err == nil || !strings.Contains(err.Error(), "linker-fixed veritysetup") {
		t.Fatalf("verifyRegularFileTarget() error = %v", err)
	}
	if _, err := verifyRegularFileTarget(context.Background(), "/dev/example", mediacontract.Plan{}); err == nil || !strings.Contains(err.Error(), "outside /dev") {
		t.Fatalf("device-like fixture path error = %v", err)
	}
}

func TestVerificationFailureEmitsNoReport(t *testing.T) {
	originalLoad, originalVerify := loadPlan, verifyTarget
	t.Cleanup(func() { loadPlan, verifyTarget = originalLoad, originalVerify })
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	verifyTarget = func(context.Context, string, mediacontract.Plan) (mediacontract.VerificationReport, error) {
		return mediacontract.VerificationReport{}, errors.New("tampered full media")
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"verify-regular-file", "--plan", "/absolute/plan.json", "--target", "/absolute/target.img"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "tampered full media") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
