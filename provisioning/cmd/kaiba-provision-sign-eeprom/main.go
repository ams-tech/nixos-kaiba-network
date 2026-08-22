package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2

	sessionSocketEnvironment = "KAIBA_EEPROM_SIGNING_SESSION_SOCKET"
)

// Every authority or executable selector is injected by the immutable build.
// No public command-line flag or inherited environment variable can choose a
// gate, updater, extractor, wrapper, key, provider, or tool PATH.
var (
	signingGateSocketPath               string
	pinnedUpdatePieepromExecutablePath  string
	pinnedRpiEEPROMConfigExecutablePath string
	pinnedToolRuntimePath               string
	eepromSigningWrapperExecutablePath  string
	expectedEEPROMReleaseManifestDigest string
	expectedOriginalEEPROMDigest        string
	expectedOriginalRecoveryDigest      string
	expectedOriginalBootcodeDigest      string
	expectedOriginalBootsysDigest       string
	expectedEEPROMFirmwareBuildEpoch    string
)

type signatureRequester func(context.Context, string, []byte) (signinggate.Result, error)

type dependencies struct {
	config    runtimeConfig
	request   signatureRequester
	updater   updaterRunner
	extractor extractorRunner
	err       error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	deps := productionDependencies()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, deps, os.Getenv, productionWrapperClient))
}

func productionDependencies() dependencies {
	releaseDigest, err := bundle.ParseDigest(expectedEEPROMReleaseManifestDigest)
	if err != nil {
		return dependencies{err: fmt.Errorf("linker-fixed EEPROM release manifest digest: %w", err)}
	}
	wrapperPath := eepromSigningWrapperExecutablePath
	if wrapperPath == "" {
		wrapperPath, err = resolvedSelfExecutable()
		if err != nil {
			return dependencies{err: fmt.Errorf("resolve immutable EEPROM HSM wrapper executable: %w", err)}
		}
	}
	originalEEPROMDigest, err := parseLinkerDigest("original EEPROM", expectedOriginalEEPROMDigest)
	if err != nil {
		return dependencies{err: err}
	}
	originalRecoveryDigest, err := parseLinkerDigest("original recovery", expectedOriginalRecoveryDigest)
	if err != nil {
		return dependencies{err: err}
	}
	originalBootcodeDigest, err := parseLinkerDigest("original bootcode", expectedOriginalBootcodeDigest)
	if err != nil {
		return dependencies{err: err}
	}
	originalBootsysDigest, err := parseLinkerDigest("original bootsys", expectedOriginalBootsysDigest)
	if err != nil {
		return dependencies{err: err}
	}
	firmwareBuildEpoch, err := strconv.ParseUint(expectedEEPROMFirmwareBuildEpoch, 10, 64)
	if err != nil || firmwareBuildEpoch == 0 || strconv.FormatUint(firmwareBuildEpoch, 10) != expectedEEPROMFirmwareBuildEpoch {
		return dependencies{err: errors.New("linker-fixed EEPROM firmware build epoch is invalid")}
	}
	config := runtimeConfig{
		GateSocketPath:                 signingGateSocketPath,
		UpdaterExecutablePath:          pinnedUpdatePieepromExecutablePath,
		ExtractorExecutablePath:        pinnedRpiEEPROMConfigExecutablePath,
		FixedToolPATH:                  pinnedToolRuntimePath,
		WrapperExecutablePath:          wrapperPath,
		ExpectedEEPROMReleaseDigest:    releaseDigest,
		ExpectedOriginalEEPROMDigest:   originalEEPROMDigest,
		ExpectedOriginalRecoveryDigest: originalRecoveryDigest,
		ExpectedOriginalBootcodeDigest: originalBootcodeDigest,
		ExpectedOriginalBootsysDigest:  originalBootsysDigest,
		ExpectedFirmwareBuildEpoch:     firmwareBuildEpoch,
	}
	return dependencies{
		config:    config,
		request:   signinggate.RequestSignature,
		updater:   productionUpdater,
		extractor: productionExtractor,
	}
}

func parseLinkerDigest(label, encoded string) (bundle.Digest, error) {
	digest, err := bundle.ParseDigest(encoded)
	if err != nil {
		return "", fmt.Errorf("linker-fixed %s digest: %w", label, err)
	}
	return digest, nil
}

func resolvedSelfExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(executable) {
		executable, err = filepath.Abs(executable)
		if err != nil {
			return "", err
		}
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("self executable did not resolve to an absolute clean path")
	}
	return resolved, nil
}

func run(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	deps dependencies,
	getenv func(string) string,
	wrapperClient wrapperClient,
) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return exitFailure
	}
	// This exact Raspberry Pi HSM-wrapper surface is intentionally hidden from
	// normal usage and is useful only while a private adapter session is live.
	if len(args) == 3 && args[0] == "-a" && args[1] == string(signing.AlgorithmRSA2048SHA256) && args[2] != "" {
		if err := runHiddenWrapper(ctx, args[2], stdout, getenv, wrapperClient); err != nil {
			fmt.Fprintf(stderr, "EEPROM signing session: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	command, planDirectory, signedDirectory, outputDirectory, err := parseArguments(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printUsage(stderr)
		return exitUsage
	}
	if deps.err != nil {
		fmt.Fprintf(stderr, "EEPROM signing adapter configuration: %v\n", deps.err)
		return exitFailure
	}
	switch command {
	case "sign":
		err = signEEPROM(ctx, planDirectory, outputDirectory, deps)
	case "finalize":
		err = finalizeEEPROM(ctx, planDirectory, signedDirectory, outputDirectory, deps)
	default:
		panic("unreachable command")
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s EEPROM: %v\n", command, err)
		return exitFailure
	}
	return exitOK
}

func parseArguments(args []string) (command, planDirectory, signedDirectory, outputDirectory string, err error) {
	if len(args) == 5 && args[0] == "sign" && args[1] == "--plan" && validCLIPath(args[2]) && args[3] == "--output" && validCLIPath(args[4]) {
		return args[0], args[2], "", args[4], nil
	}
	if len(args) == 7 && args[0] == "finalize" && args[1] == "--plan" && validCLIPath(args[2]) && args[3] == "--signed" && validCLIPath(args[4]) && args[5] == "--output" && validCLIPath(args[6]) {
		return args[0], args[2], args[4], args[6], nil
	}
	return "", "", "", "", errors.New("invalid command arguments")
}

func validCLIPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-sign-eeprom sign --plan ABSOLUTE_PLAN_DIR --output ABSOLUTE_OUTPUT_DIR")
	fmt.Fprintln(output, "       kaiba-provision-sign-eeprom finalize --plan ABSOLUTE_PLAN_DIR --signed ABSOLUTE_SIGNED_DIR --output ABSOLUTE_OUTPUT_DIR")
}
