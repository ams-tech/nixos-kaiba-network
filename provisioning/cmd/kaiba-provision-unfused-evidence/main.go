package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence"
)

const (
	exitOK           = 0
	exitInternal     = 1
	exitUsage        = 2
	exitVerification = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "verify-operator-observation" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("kaiba-provision-unfused-evidence verify-operator-observation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	compatibilityOutcomePath := flags.String("compatibility-outcome", "", "absolute verified unfused compatibility outcome JSON path")
	observationPath := flags.String("observation", "", "absolute operator hardware-observation JSON path")
	uartCapturePath := flags.String("uart-capture", "", "absolute bounded UART capture path")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *compatibilityOutcomePath == "" || *observationPath == "" || *uartCapturePath == "" {
		flags.Usage()
		return exitUsage
	}

	result, err := unfusedevidence.Verify(*compatibilityOutcomePath, *observationPath, *uartCapturePath)
	if err != nil {
		fmt.Fprintf(stderr, "verify unfused hardware evidence: %v\n", err)
		return exitVerification
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode unfused hardware evidence: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-unfused-evidence verify-operator-observation --compatibility-outcome ABSOLUTE_PATH --observation ABSOLUTE_PATH --uart-capture ABSOLUTE_PATH")
}
