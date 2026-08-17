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
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
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
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-provision-rehearsal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	rehearsalID := flags.String("rehearsal-id", "local-software-rehearsal", "canonical identifier included in synthetic evidence")
	injectAt := flags.Int("inject-at", 0, "operation sequence at which to inject a synthetic failure (1-7)")
	injectOutcome := flags.String("inject-outcome", "failed", "injected outcome: failed or uncertain")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return exitUsage
	}

	config := rehearsal.SimulatorConfig{}
	if *injectAt != 0 {
		disposition, err := parseInjectedDisposition(*injectOutcome)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		config.Failure = &rehearsal.FailureInjection{
			Sequence: *injectAt, Disposition: disposition,
		}
	} else if *injectOutcome != "failed" {
		fmt.Fprintln(stderr, "--inject-outcome requires --inject-at")
		return exitUsage
	}

	simulator, err := rehearsal.NewSimulator(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	report, err := rehearsal.Run(ctx, rehearsal.NewContract(*rehearsalID), simulator)
	if err != nil {
		fmt.Fprintf(stderr, "run software rehearsal: %v\n", err)
		return exitInternal
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(stderr, "encode software rehearsal report: %v\n", err)
		return exitInternal
	}
	switch report.Outcome {
	case rehearsal.OutcomeRehearsalPassed:
		return exitPassed
	case rehearsal.OutcomeRehearsalFailed:
		return exitFailed
	case rehearsal.OutcomeRehearsalUncertain:
		return exitUncertain
	default:
		fmt.Fprintf(stderr, "unsupported software rehearsal outcome %q\n", report.Outcome)
		return exitInternal
	}
}

func parseInjectedDisposition(value string) (rehearsal.StepDisposition, error) {
	switch value {
	case "failed":
		return rehearsal.StepFailed, nil
	case "uncertain":
		return rehearsal.StepUncertain, nil
	default:
		return "", errors.New("--inject-outcome must be failed or uncertain")
	}
}
