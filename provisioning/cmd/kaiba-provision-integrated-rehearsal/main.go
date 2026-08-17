package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsalorchestrator"
)

const (
	exitPassed    = 0
	exitInternal  = 1
	exitUsage     = 2
	exitFailed    = 3
	exitUncertain = 4
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("kaiba-provision-integrated-rehearsal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", "", "fresh absolute directory for control and audit rehearsal state")
	rehearsalID := flags.String("rehearsal-id", "integrated-software-rehearsal", "canonical rehearsal identifier")
	injectAt := flags.Int("inject-at", 0, "software operation sequence at which to inject a failure (1-7)")
	injectOutcome := flags.String("inject-outcome", "failed", "injected software outcome: failed or uncertain")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return exitUsage
	}
	if err := validateStateDirectory(*stateDirectory); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if now == nil {
		fmt.Fprintln(stderr, "clock is unavailable")
		return exitInternal
	}
	config := rehearsalorchestrator.Config{RehearsalID: *rehearsalID, Now: now().UTC()}
	if *injectAt != 0 {
		disposition, err := parseDisposition(*injectOutcome)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		config.Failure = &rehearsal.FailureInjection{Sequence: *injectAt, Disposition: disposition}
	} else if *injectOutcome != "failed" {
		fmt.Fprintln(stderr, "--inject-outcome requires --inject-at")
		return exitUsage
	}
	report, err := rehearsalorchestrator.Run(ctx, config, rehearsalorchestrator.Stores{
		Control: controlplane.FileStore{Path: filepath.Join(*stateDirectory, "control.json")},
		Audit:   auditlog.FileStore{Path: filepath.Join(*stateDirectory, "audit.json")},
	})
	if err != nil {
		fmt.Fprintf(stderr, "integrated software rehearsal: %v\n", err)
		return exitInternal
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(stderr, "encode integrated rehearsal report: %v\n", err)
		return exitInternal
	}
	switch report.Simulation.Outcome {
	case rehearsal.OutcomeRehearsalPassed:
		return exitPassed
	case rehearsal.OutcomeRehearsalFailed:
		return exitFailed
	case rehearsal.OutcomeRehearsalUncertain:
		return exitUncertain
	default:
		fmt.Fprintf(stderr, "unsupported rehearsal outcome %q\n", report.Simulation.Outcome)
		return exitInternal
	}
}

func validateStateDirectory(value string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return errors.New("--state-dir must be a clean absolute directory other than the filesystem root")
	}
	return nil
}

func parseDisposition(value string) (rehearsal.StepDisposition, error) {
	switch value {
	case "failed":
		return rehearsal.StepFailed, nil
	case "uncertain":
		return rehearsal.StepUncertain, nil
	default:
		return "", errors.New("--inject-outcome must be failed or uncertain")
	}
}
