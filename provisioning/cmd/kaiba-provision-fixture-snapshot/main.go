//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/fixturesnapshot"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-fixture-snapshot: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("kaiba-provision-fixture-snapshot", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "clean absolute path to the synthetic regular-file source")
	destination := flags.String("destination", "", "clean absolute path for the new regular-file snapshot")
	expectedSize := flags.Uint64("expected-size", 0, "exact expected source size in bytes")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	seen := make(map[string]bool)
	flags.Visit(func(candidate *flag.Flag) {
		seen[candidate.Name] = true
	})
	if flags.NArg() != 0 || !seen["source"] || !seen["destination"] || !seen["expected-size"] || *source == "" || *destination == "" {
		return usageError(nil)
	}
	return fixturesnapshot.Snapshot(fixturesnapshot.Options{
		Source:       *source,
		Destination:  *destination,
		ExpectedSize: *expectedSize,
	})
}

func usageError(cause error) error {
	usage := errors.New("usage: kaiba-provision-fixture-snapshot --source ABS --destination ABS --expected-size N")
	if cause == nil {
		return usage
	}
	return fmt.Errorf("%w: %v", usage, cause)
}
