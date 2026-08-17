package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedevidence"
)

const (
	exitOK           = 0
	exitInternal     = 1
	exitUsage        = 2
	exitVerification = 3
)

// trustedSignerFingerprint is empty in the generic build and is fixed with
// -ldflags by the trusted-signer Nix factory. It is deliberately not
// configurable through flags or the environment.
var trustedSignerFingerprint string

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
	manifestPath := flags.String("manifest", "", "absolute capsule manifest JSON path")
	capsuleRoot := flags.String("capsule-root", "", "absolute root of the exact capsule file tree")
	fixturePath := flags.String("fixture", "", "absolute offline compatibility fixture JSON path")
	publicKeyPath := flags.String("public-key", "", "absolute reviewed RSA-2048 public key PEM path")
	observationPath := flags.String("observation", "", "absolute operator hardware-observation JSON path")
	uartCapturePath := flags.String("uart-capture", "", "absolute bounded UART capture path")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *manifestPath == "" || *capsuleRoot == "" || *fixturePath == "" || *publicKeyPath == "" || *observationPath == "" || *uartCapturePath == "" {
		flags.Usage()
		return exitUsage
	}

	policy, err := unfusedcompat.NewTrustedSignerPolicy(trustedSignerFingerprint)
	if err != nil {
		fmt.Fprintf(stderr, "verify unfused evidence correlation: trusted signer anchor: %v\n", err)
		return exitVerification
	}
	result, err := unfusedevidence.Verify(*manifestPath, *capsuleRoot, *fixturePath, *publicKeyPath, *observationPath, *uartCapturePath, policy)
	if err != nil {
		fmt.Fprintf(stderr, "verify unfused evidence correlation: %v\n", err)
		return exitVerification
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode unfused evidence correlation: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-unfused-evidence verify-operator-observation --manifest ABSOLUTE_PATH --capsule-root ABSOLUTE_PATH --fixture ABSOLUTE_PATH --public-key ABSOLUTE_PATH --observation ABSOLUTE_PATH --uart-capture ABSOLUTE_PATH")
}
