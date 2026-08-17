package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
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
	if len(arguments) == 0 || (arguments[0] != "verify-offline-fixture" && arguments[0] != "verify-signed-offline-fixture") {
		printUsage(stderr)
		return exitUsage
	}
	subcommand := arguments[0]
	flags := flag.NewFlagSet("kaiba-provision-unfused-compat "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	manifestPath := flags.String("manifest", "", "absolute capsule manifest JSON path")
	capsuleRoot := flags.String("capsule-root", "", "absolute root of the exact capsule file tree")
	fixturePath := flags.String("fixture", "", "absolute offline compatibility fixture JSON path")
	publicKeyPath := flags.String("public-key", "", "absolute reviewed RSA-2048 public key PEM path")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *manifestPath == "" || *capsuleRoot == "" || *fixturePath == "" ||
		(subcommand == "verify-signed-offline-fixture" && *publicKeyPath == "") ||
		(subcommand == "verify-offline-fixture" && *publicKeyPath != "") {
		flags.Usage()
		return exitUsage
	}

	var result unfusedcompat.Outcome
	var err error
	if subcommand == "verify-signed-offline-fixture" {
		result, err = unfusedcompat.VerifySignedOfflineFixture(*manifestPath, *capsuleRoot, *fixturePath, *publicKeyPath)
	} else {
		result, err = unfusedcompat.VerifyOfflineFixture(*manifestPath, *capsuleRoot, *fixturePath)
	}
	if err != nil {
		fmt.Fprintf(stderr, "verify offline compatibility fixture: %v\n", err)
		return exitVerification
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode compatibility result: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-unfused-compat verify-offline-fixture --manifest ABSOLUTE_PATH --capsule-root ABSOLUTE_PATH --fixture ABSOLUTE_PATH")
	fmt.Fprintln(output, "       kaiba-provision-unfused-compat verify-signed-offline-fixture --manifest ABSOLUTE_PATH --capsule-root ABSOLUTE_PATH --fixture ABSOLUTE_PATH --public-key ABSOLUTE_PATH")
}
