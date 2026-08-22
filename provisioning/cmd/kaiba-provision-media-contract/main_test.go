package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func TestValidatePlanCommandHasNarrowCanonicalInterface(t *testing.T) {
	original := loadPlan
	t.Cleanup(func() { loadPlan = original })
	loadPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/absolute/plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-plan", "--plan", "/absolute/plan.json"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"valid"`) || !strings.Contains(stdout.String(), `"plan_digest":"sha256:aaaa`) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, arguments := range [][]string{
		nil,
		{"validate-plan"},
		{"validate-plan", "--plan", "/absolute/plan.json", "extra"},
		{"validate-plan", "--plan", "/absolute/plan.json", "--device", "/dev/example"},
		{"other"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestValidatePlanFailureEmitsNoReceipt(t *testing.T) {
	original := loadPlan
	t.Cleanup(func() { loadPlan = original })
	loadPlan = func(string) (mediacontract.Plan, error) { return mediacontract.Plan{}, errors.New("not canonical") }
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-plan", "--plan", "/absolute/plan.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "not canonical") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
