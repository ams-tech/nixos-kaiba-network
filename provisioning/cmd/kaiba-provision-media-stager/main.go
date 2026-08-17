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

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediastager"
)

var effectiveUID = os.Geteuid

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-media-stager: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return usageError()
	}
	mode, action, err := parseSubcommand(arguments[0])
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("kaiba-provision-media-stager "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "clean absolute path to the exact staging plan JSON")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *planPath == "" {
		return usageError()
	}
	if mode == mediastager.ModeDevice && effectiveUID() != 0 {
		return errors.New("device media staging requires root")
	}
	plan, err := mediastager.LoadPlan(*planPath, mode)
	if err != nil {
		return err
	}
	executor := mediastager.Executor{}
	var result mediastager.Result
	switch action {
	case mediastager.ActionDryRun:
		result, err = executor.DryRun(ctx, plan, mode)
	case mediastager.ActionStage:
		result, err = executor.Stage(ctx, plan, mode)
	case mediastager.ActionReadback:
		result, err = executor.Readback(ctx, plan, mode)
	default:
		return usageError()
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func parseSubcommand(value string) (mediastager.Mode, mediastager.Action, error) {
	switch value {
	case "dry-run":
		return mediastager.ModeDevice, mediastager.ActionDryRun, nil
	case "stage":
		return mediastager.ModeDevice, mediastager.ActionStage, nil
	case "readback":
		return mediastager.ModeDevice, mediastager.ActionReadback, nil
	case "fixture-dry-run":
		return mediastager.ModeFixture, mediastager.ActionDryRun, nil
	case "fixture-stage":
		return mediastager.ModeFixture, mediastager.ActionStage, nil
	case "fixture-readback":
		return mediastager.ModeFixture, mediastager.ActionReadback, nil
	default:
		return "", "", usageError()
	}
}

func usageError() error {
	return errors.New("usage: kaiba-provision-media-stager {dry-run|stage|readback|fixture-dry-run|fixture-stage|fixture-readback} --plan /absolute/plan.json")
}
