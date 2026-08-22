package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3
)

var (
	loadRuntimeFacts = mediacontract.LoadRuntimeFacts
	loadMediaPlan    = mediacontract.LoadPlan
	validateFacts    = func(facts mediacontract.RuntimeFacts, plan mediacontract.Plan) error {
		return facts.ValidateAgainst(plan)
	}
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "emit" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("emit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	factsPath := flags.String("facts", "", "absolute canonical runtime-facts path")
	planPath := flags.String("plan", "", "absolute canonical approved media-plan path")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *factsPath == "" || *planPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	facts, err := loadRuntimeFacts(*factsPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate unfused runtime facts: %v\n", err)
		return exitInvalid
	}
	plan, err := loadMediaPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate approved media plan: %v\n", err)
		return exitInvalid
	}
	if err := validateFacts(facts, plan); err != nil {
		fmt.Fprintf(stderr, "correlate unfused runtime facts with approved media plan: %v\n", err)
		return exitInvalid
	}
	records, err := mediacontract.BuildUARTRecords(facts)
	if err != nil {
		fmt.Fprintf(stderr, "build unfused runtime records: %v\n", err)
		return exitInvalid
	}
	text, err := records.Text(facts)
	if err != nil {
		fmt.Fprintf(stderr, "encode unfused runtime records: %v\n", err)
		return exitInternal
	}
	if _, err := stdout.Write(text); err != nil {
		fmt.Fprintf(stderr, "write unfused runtime records: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-unfused-runtime-record emit --facts ABSOLUTE_PATH --plan ABSOLUTE_PATH")
}
