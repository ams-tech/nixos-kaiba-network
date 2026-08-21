package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// All signing authority and signer identity values are injected by the
// immutable build. There is deliberately no runtime flag or environment
// override for a socket, key, provider, URI, signer, or cohort.
var (
	signingGateSocketPath        string
	signerID                     string
	cohortID                     string
	signingPKCS11URI             string
	expectedPublicKeyPath        string
	expectedPublicKeyFingerprint string
)

type signOperation func(context.Context, string, string) error
type finalizeOperation func(string, string, string) error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr, productionSign, signedboot.Finalize))
}

func productionSign(ctx context.Context, planDirectory, outputDirectory string) error {
	fingerprint, err := bundle.ParseDigest(expectedPublicKeyFingerprint)
	if err != nil {
		return fmt.Errorf("linker-fixed public-key fingerprint: %w", err)
	}
	return signedboot.Sign(ctx, planDirectory, outputDirectory, signedboot.SignConfig{
		GateSocketPath: signingGateSocketPath, SignerID: signerID, CohortID: cohortID,
		PKCS11URI: signingPKCS11URI, ExpectedPublicKeyPath: expectedPublicKeyPath,
		ExpectedPublicKeyFingerprint: fingerprint,
	})
}

func run(ctx context.Context, args []string, stderr io.Writer, sign signOperation, finalize finalizeOperation) int {
	if stderr == nil || ctx == nil {
		return exitFailure
	}
	command, planDirectory, secondaryDirectory, outputDirectory, err := parseArguments(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, "usage: kaiba-provision-sign-boot sign --plan ABSOLUTE_PLAN_DIR --output ABSOLUTE_OUTPUT_DIR")
		fmt.Fprintln(stderr, "       kaiba-provision-sign-boot finalize --plan ABSOLUTE_PLAN_DIR --signed ABSOLUTE_SIGNED_DIR --output ABSOLUTE_OUTPUT_DIR")
		return exitUsage
	}
	switch command {
	case "sign":
		if sign == nil {
			fmt.Fprintln(stderr, "signing adapter configuration is unavailable")
			return exitFailure
		}
		err = sign(ctx, planDirectory, outputDirectory)
	case "finalize":
		if finalize == nil {
			fmt.Fprintln(stderr, "finalizer configuration is unavailable")
			return exitFailure
		}
		err = finalize(planDirectory, secondaryDirectory, outputDirectory)
	default:
		panic("unreachable command")
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s signed boot: %v\n", command, err)
		return exitFailure
	}
	return exitOK
}

func parseArguments(args []string) (command, planDirectory, secondaryDirectory, outputDirectory string, err error) {
	if len(args) == 5 && args[0] == "sign" && args[1] == "--plan" && args[2] != "" && args[3] == "--output" && args[4] != "" {
		return args[0], args[2], "", args[4], nil
	}
	if len(args) == 7 && args[0] == "finalize" && args[1] == "--plan" && args[2] != "" && args[3] == "--signed" && args[4] != "" && args[5] == "--output" && args[6] != "" {
		return args[0], args[2], args[4], args[6], nil
	}
	return "", "", "", "", errors.New("invalid command arguments")
}
