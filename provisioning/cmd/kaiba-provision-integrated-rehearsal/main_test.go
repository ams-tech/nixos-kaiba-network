package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsalorchestrator"
)

//go:embed *.go
var commandSources embed.FS

func TestRunEmitsExplicitSoftwareOnlyReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	directory := filepath.Join(t.TempDir(), "state")
	code := run(context.Background(), []string{
		"--state-dir", directory, "--rehearsal-id", "cli-integrated",
	}, &stdout, &stderr, fixedClock)
	if code != exitPassed || stderr.Len() != 0 {
		t.Fatalf("code/stderr = %d/%q", code, stderr.String())
	}
	var report rehearsalorchestrator.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.HardwareObserved || report.SecurityEnforced || report.MutationEligible ||
		report.ExecutionMode != rehearsalorchestrator.ExecutionMode || report.AuthorityClass != rehearsalorchestrator.AuthorityClass {
		t.Fatalf("unsafe report = %#v", report)
	}
}

func TestRunUsesDistinctSimulatorExitCodes(t *testing.T) {
	tests := []struct {
		outcome string
		code    int
		want    rehearsal.Outcome
	}{
		{"failed", exitFailed, rehearsal.OutcomeRehearsalFailed},
		{"uncertain", exitUncertain, rehearsal.OutcomeRehearsalUncertain},
	}
	for _, test := range tests {
		t.Run(test.outcome, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{
				"--state-dir", filepath.Join(t.TempDir(), "state"),
				"--rehearsal-id", "cli-" + test.outcome,
				"--inject-at", "5", "--inject-outcome", test.outcome,
			}, &stdout, &stderr, fixedClock)
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("code/stderr = %d/%q", code, stderr.String())
			}
			var report rehearsalorchestrator.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Simulation.Outcome != test.want || report.MutationEligible {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestRunRejectsUnsafeOrReusedState(t *testing.T) {
	for _, arguments := range [][]string{
		{}, {"--state-dir", "relative"}, {"--state-dir", string(filepath.Separator)},
		{"--state-dir", filepath.Join(t.TempDir(), "state"), "positional"},
		{"--state-dir", filepath.Join(t.TempDir(), "state"), "--inject-outcome", "uncertain"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr, fixedClock); code != exitUsage {
			t.Fatalf("run(%q) code = %d", arguments, code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
		}
	}

	directory := filepath.Join(t.TempDir(), "state")
	arguments := []string{"--state-dir", directory, "--rehearsal-id", "cli-reuse"}
	if code := run(context.Background(), arguments, &bytes.Buffer{}, &bytes.Buffer{}, fixedClock); code != exitPassed {
		t.Fatalf("initial run code = %d", code)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), arguments, &stdout, &stderr, fixedClock); code != exitInternal || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("reused state code/stdout/stderr = %d/%q/%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandSourceHasNoExecutionOrTransportDependency(t *testing.T) {
	entries, err := commandSources.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		`"os/exec"`, `"net"`, "physicalrpi5", "laneguard", "rpiboot", `"/dev/`, `"/sys/`,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := commandSources.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if strings.Contains(string(data), value) {
				t.Fatalf("command source %s contains forbidden dependency %q", entry.Name(), value)
			}
		}
	}
}

func fixedClock() time.Time { return time.Date(2026, 8, 17, 18, 0, 0, 0, time.UTC) }
