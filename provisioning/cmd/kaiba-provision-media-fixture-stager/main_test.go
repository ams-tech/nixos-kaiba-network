//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func init() { requireApprovedPlan = func(mediacontract.Plan) error { return nil } }

func TestCommandIsRegularFileOnlyAndPublishesFixtureResult(t *testing.T) {
	originalLoad, originalStage, originalValidate, originalWrite := loadPlan, stageAndEncode, validateEvidence, writeEvidence
	t.Cleanup(func() {
		loadPlan, stageAndEncode, validateEvidence, writeEvidence = originalLoad, originalStage, originalValidate, originalWrite
	})
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/evidence/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	stageAndEncode = func(_ context.Context, _ mediacontract.Plan, path string) ([]byte, error) {
		if path != "/tmp/media.img" {
			t.Fatalf("target path = %q", path)
		}
		return []byte("{\"evidence_mode\":\"regular_file_fixture\",\"block_device_access\":false}"), nil
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(path string, data []byte) error {
		if path != "/evidence/fixture.json" || !bytes.Contains(data, []byte("regular_file_fixture")) {
			t.Fatalf("writeEvidence(%q, %q)", path, data)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--target", "/tmp/media.img", "--result", "/evidence/fixture.json"}, &stdout, &stderr)
	if code != exitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, arguments := range [][]string{
		nil,
		{"stage"},
		{"stage", "--plan", "/evidence/plan.json", "--target", "/tmp/media.img", "--result", "/evidence/fixture.json", "--device"},
		{"stage", "--plan", "/evidence/plan.json", "--target", "/tmp/media.img", "--result", "/evidence/fixture.json", "--force"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestFixtureResultCannotClaimProductionEvidence(t *testing.T) {
	result := fixtureResult{
		SchemaVersion: fixtureResultSchemaVersion, Status: "fixture_staged_and_reopened", EvidenceMode: "regular_file_fixture",
		PlanDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetPath:      "/tmp/media.img",
		FullMediaDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BytesWritten:    1, ReopenedTarget: true,
	}
	digest, err := result.derivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	result.ResultDigest = digest
	if canonical, err := result.canonicalJSON(); err != nil || !bytes.Contains(canonical, []byte("\"block_device_access\":false")) {
		t.Fatalf("canonicalJSON() = %q, %v", canonical, err)
	}
	result.HardwareObserved = true
	result.ResultDigest, _ = result.derivedDigest()
	if _, err := result.canonicalJSON(); err == nil {
		t.Fatal("fixture result accepted a hardware observation claim")
	}
}

func TestProductionFixtureAdapterRefusesDeviceNamespaceFirst(t *testing.T) {
	if _, err := productionStageAndEncode(context.Background(), mediacontract.Plan{}, "/dev/disk/by-id/example"); err == nil || !strings.Contains(err.Error(), "outside /dev") {
		t.Fatalf("productionStageAndEncode() error = %v", err)
	}
}

func TestFixtureBinaryHasNoProductionReceiptConstructor(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"NewStageReceipt", "StageReceiptSchemaVersion", "independent_read_only_device"} {
		if bytes.Contains(source, []byte(prohibited)) {
			t.Fatalf("fixture binary contains production receipt authority %q", prohibited)
		}
	}
}

func TestFixtureChecksTargetSourceIdentityBeforeWriter(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	identityCheck := bytes.Index(source, []byte("sources.ValidateDistinctRegularTarget(target)"))
	writerCall := bytes.Index(source, []byte("mediawriter.Stage(ctx, target, plan, sources)"))
	if identityCheck < 0 || writerCall < 0 || identityCheck > writerCall {
		t.Fatal("fixture adapter does not pin and reject a target/source inode alias before its first writer call")
	}
}

func TestFixtureFailurePublishesNothing(t *testing.T) {
	originalLoad, originalStage, originalValidate, originalWrite := loadPlan, stageAndEncode, validateEvidence, writeEvidence
	t.Cleanup(func() {
		loadPlan, stageAndEncode, validateEvidence, writeEvidence = originalLoad, originalStage, originalValidate, originalWrite
	})
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, nil }
	stageAndEncode = func(context.Context, mediacontract.Plan, string) ([]byte, error) {
		return nil, errors.New("fixture tampered")
	}
	validateEvidence = func(string) error { return nil }
	writeEvidence = func(string, []byte) error {
		t.Fatal("writeEvidence called after fixture failure")
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"stage", "--plan", "/evidence/plan.json", "--target", "/tmp/media.img", "--result", "/evidence/fixture.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "fixture tampered") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
