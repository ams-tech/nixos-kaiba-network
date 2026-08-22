package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpibootbundle"
)

const (
	exitOK = iota
	exitFailure
	exitUsage
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "build":
		return runBuild(arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", arguments[0])
		usage(stderr)
		return exitUsage
	}
}

func runBuild(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var config rpibootbundle.BuildConfig
	var releaseIntentDigest string
	flags.StringVar(&releaseIntentDigest, "release-intent-digest", "", "canonical cohort release-intent digest")
	flags.StringVar(&config.FreshRecovery, "fresh-recovery", "", "verified unsigned fresh recovery bootcode")
	flags.StringVar(&config.OwnedRecovery, "owned-recovery", "", "verified customer-counter-signed recovery bootcode")
	flags.StringVar(&config.SignedEEPROM, "signed-eeprom", "", "verified signed EEPROM image")
	flags.StringVar(&config.EEPROMMetadata, "eeprom-metadata", "", "verified EEPROM update metadata")
	flags.StringVar(&config.BootImage, "boot-image", "", "verified signed boot image")
	flags.StringVar(&config.BootSignature, "boot-signature", "", "verified canonical boot signature")
	flags.StringVar(&config.BootPublicKey, "boot-public-key", "", "reviewed boot public key")
	flags.StringVar(&config.RootDataImage, "root-data", "", "root data image")
	flags.StringVar(&config.RootHashTreeImage, "root-hash-tree", "", "root hash-tree image")
	flags.StringVar(&config.Output, "output", "", "new output directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "build requires only the documented named flags")
		return exitUsage
	}
	digest, err := bundle.ParseDigest(releaseIntentDigest)
	if err != nil {
		fmt.Fprintf(stderr, "release-intent-digest: %v\n", err)
		return exitUsage
	}
	config.ReleaseIntentDigest = digest
	set, err := rpibootbundle.Build(config)
	if err != nil {
		fmt.Fprintf(stderr, "build RPIBOOT bundle set: %v\n", err)
		return exitFailure
	}
	digest, err = set.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "digest RPIBOOT bundle set: %v\n", err)
		return exitFailure
	}
	fmt.Fprintln(stdout, digest)
	return exitOK
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var input string
	flags.StringVar(&input, "input", "", "published RPIBOOT bundle-set directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || input == "" {
		fmt.Fprintln(stderr, "verify requires exactly --input")
		return exitUsage
	}
	set, err := rpibootbundle.Verify(input)
	if err != nil {
		fmt.Fprintf(stderr, "verify RPIBOOT bundle set: %v\n", err)
		return exitFailure
	}
	digest, err := set.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "digest RPIBOOT bundle set: %v\n", err)
		return exitFailure
	}
	fmt.Fprintln(stdout, digest)
	return exitOK
}

func usage(output io.Writer) {
	if output == nil {
		panic(errors.New("nil usage output"))
	}
	fmt.Fprintln(output, "usage: kaiba-provision-rpiboot-bundles <build|verify> [flags]")
}
