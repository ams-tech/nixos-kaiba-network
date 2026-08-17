package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
)

func TestRunEmitsDeterministicSevenOperationReport(t *testing.T) {
	var first, second bytes.Buffer
	var firstError, secondError bytes.Buffer
	arguments := []string{"--rehearsal-id", "cli-happy-path"}
	if code := run(context.Background(), arguments, &first, &firstError); code != exitPassed {
		t.Fatalf("first run code/stderr = %d/%q", code, firstError.String())
	}
	if code := run(context.Background(), arguments, &second, &secondError); code != exitPassed {
		t.Fatalf("second run code/stderr = %d/%q", code, secondError.String())
	}
	if first.String() != second.String() {
		t.Fatalf("output is not deterministic:\n%s\n%s", first.String(), second.String())
	}
	var report rehearsal.Report
	if err := json.Unmarshal(first.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Outcome != rehearsal.OutcomeRehearsalPassed || len(report.Evidence) != rehearsal.OperationCount {
		t.Fatalf("outcome/evidence = %q/%d", report.Outcome, len(report.Evidence))
	}
	forbiddenProductionOutcome := "security" + "_applied"
	if strings.Contains(first.String(), forbiddenProductionOutcome) {
		t.Fatalf("output contains forbidden production outcome: %s", first.String())
	}
}

func TestRunReturnsDistinctInjectedOutcomeExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		outcome  string
		exitCode int
		want     rehearsal.Outcome
	}{
		{"failed", "failed", exitFailed, rehearsal.OutcomeRehearsalFailed},
		{"uncertain", "uncertain", exitUncertain, rehearsal.OutcomeRehearsalUncertain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{
				"--rehearsal-id", "cli-injection", "--inject-at", "4", "--inject-outcome", test.outcome,
			}, &stdout, &stderr)
			if code != test.exitCode || stderr.Len() != 0 {
				t.Fatalf("code/stderr = %d/%q", code, stderr.String())
			}
			var report rehearsal.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Outcome != test.want || report.State.CompletedOperations != 3 || len(report.Evidence) != 4 {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestRunRejectsInvalidArgumentsWithoutReport(t *testing.T) {
	tests := [][]string{
		{"positional"},
		{"--inject-at", "8"},
		{"--inject-outcome", "uncertain"},
		{"--inject-at", "2", "--inject-outcome", "passed"},
		{"--rehearsal-id", "Bad ID"},
	}
	for _, arguments := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr); code != exitUsage && code != exitInternal {
			t.Fatalf("run(%q) code = %d", arguments, code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("run(%q) stdout/stderr = %q/%q", arguments, stdout.String(), stderr.String())
		}
	}
}
