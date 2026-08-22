package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedrelease"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// This executable selector is fixed by the immutable build. There is no flag
// or environment-variable override for the EEPROM replay boundary.
var eepromFinalizerExecutablePath string

type finalizeOperation func(context.Context, signedrelease.Inputs, string, signedrelease.Options) error

type dependencies struct {
	finalize finalizeOperation
	options  signedrelease.Options
	err      error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func productionDependencies() dependencies {
	path := eepromFinalizerExecutablePath
	if !validAbsolutePath(path) {
		return dependencies{err: errors.New("linker-fixed EEPROM finalizer executable must be a clean absolute path")}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return dependencies{err: errors.New("linker-fixed EEPROM finalizer executable is not an executable non-symlink regular file")}
	}
	return dependencies{
		finalize: signedrelease.Finalize,
		options:  signedrelease.Options{EEPROMReplayVerifier: commandReplayVerifier{executable: path}},
	}
}

type commandReplayVerifier struct{ executable string }

func (verifier commandReplayVerifier) VerifyEEPROMReplay(ctx context.Context, plan, signed, finalized string) error {
	return verifier.verify(ctx, "finalize", plan, signed, finalized)
}

func (verifier commandReplayVerifier) VerifyOwnedRecoveryReplay(ctx context.Context, plan, signed, finalized string) error {
	return verifier.verify(ctx, "finalize-owned-recovery", plan, signed, finalized)
}

func (verifier commandReplayVerifier) verify(ctx context.Context, operation, plan, signed, finalized string) error {
	work, err := os.MkdirTemp("", "kaiba-eeprom-release-replay-")
	if err != nil {
		return err
	}
	defer removeWorkDirectory(work)
	output := filepath.Join(work, "finalized")
	command := exec.CommandContext(ctx, verifier.executable,
		operation, "--plan", plan, "--signed", signed, "--output", output,
	)
	command.Dir = "/"
	command.Env = []string{}
	var diagnostic limitedBuffer
	command.Stdout = &diagnostic
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(diagnostic.String())
		if message == "" {
			return fmt.Errorf("pinned EEPROM finalizer failed: %w", err)
		}
		return fmt.Errorf("pinned EEPROM finalizer failed: %w: %s", err, message)
	}
	if err := signedrelease.CompareExactDirectories(output, finalized); err != nil {
		return fmt.Errorf("pinned EEPROM finalizer replay differs: %w", err)
	}
	return nil
}

type limitedBuffer struct{ bytes.Buffer }

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	const maximum = 64 * 1024
	accepted := len(value)
	remaining := maximum - buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = buffer.Buffer.Write(value)
	}
	return accepted, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return exitFailure
	}
	inputs, output, err := parseArguments(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printUsage(stderr)
		return exitUsage
	}
	if deps.err != nil {
		fmt.Fprintf(stderr, "signed-release finalizer configuration: %v\n", deps.err)
		return exitFailure
	}
	if deps.finalize == nil {
		fmt.Fprintln(stderr, "signed-release finalizer configuration: finalizer is unavailable")
		return exitFailure
	}
	if err := deps.finalize(ctx, inputs, output, deps.options); err != nil {
		fmt.Fprintf(stderr, "finalize signed release: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "published signed release: %s\n", output)
	return exitOK
}

func parseArguments(args []string) (signedrelease.Inputs, string, error) {
	names := []string{
		"--release-intent", "--unsigned-artifacts-manifest", "--eeprom-release-manifest",
		"--signed-boot", "--signed-eeprom", "--eeprom-replay-plan", "--eeprom-replay-signed", "--owned-recovery",
		"--owned-replay-plan", "--owned-replay-signed",
		"--device-profile", "--platform-adapter", "--root-integrity",
		"--fresh-commit-bundle", "--fresh-readback-bundle", "--negative-boot-bundle",
		"--owned-readback-bundle", "--owned-recovery-bundle", "--root-integrity-test-bundle",
		"--root-data-image", "--root-hash-tree-image", "--output",
	}
	if len(args) != 1+len(names)*2 || args[0] != "finalize" {
		return signedrelease.Inputs{}, "", errors.New("invalid command arguments")
	}
	values := make([]string, len(names))
	for index, name := range names {
		if args[1+index*2] != name || !validAbsolutePath(args[2+index*2]) {
			return signedrelease.Inputs{}, "", errors.New("invalid command arguments")
		}
		values[index] = args[2+index*2]
	}
	return signedrelease.Inputs{
		ReleaseIntentPath: values[0], UnsignedArtifactsManifestPath: values[1], EEPROMReleaseManifestPath: values[2],
		SignedBootDirectory: values[3], SignedEEPROMDirectory: values[4], EEPROMReplayPlanDirectory: values[5],
		EEPROMReplaySignedDirectory: values[6], OwnedRecoveryDirectory: values[7], OwnedReplayPlanDirectory: values[8],
		OwnedReplaySignedDirectory: values[9], DeviceProfilePath: values[10], PlatformAdapterPath: values[11],
		RootIntegrityPath: values[12], FreshCommitBundle: values[13], FreshReadbackBundle: values[14],
		NegativeBootBundle: values[15], OwnedReadbackBundle: values[16], OwnedRecoveryBundle: values[17],
		RootIntegrityTestBundle: values[18], RootDataImagePath: values[19], RootHashTreeImagePath: values[20],
	}, values[21], nil
}

func validAbsolutePath(value string) bool {
	return value != "" && value != string(filepath.Separator) && filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexByte(value, 0) < 0
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-finalize-release finalize \\")
	fmt.Fprintln(output, "  --release-intent ABSOLUTE_FILE --unsigned-artifacts-manifest ABSOLUTE_FILE --eeprom-release-manifest ABSOLUTE_FILE \\")
	fmt.Fprintln(output, "  --signed-boot ABSOLUTE_DIR --signed-eeprom ABSOLUTE_DIR --eeprom-replay-plan ABSOLUTE_DIR --eeprom-replay-signed ABSOLUTE_DIR --owned-recovery ABSOLUTE_DIR \\")
	fmt.Fprintln(output, "  --owned-replay-plan ABSOLUTE_DIR --owned-replay-signed ABSOLUTE_DIR \\")
	fmt.Fprintln(output, "  --device-profile ABSOLUTE_FILE --platform-adapter ABSOLUTE_FILE --root-integrity ABSOLUTE_FILE \\")
	fmt.Fprintln(output, "  --fresh-commit-bundle ABSOLUTE_DIR --fresh-readback-bundle ABSOLUTE_DIR --negative-boot-bundle ABSOLUTE_DIR \\")
	fmt.Fprintln(output, "  --owned-readback-bundle ABSOLUTE_DIR --owned-recovery-bundle ABSOLUTE_DIR --root-integrity-test-bundle ABSOLUTE_DIR \\")
	fmt.Fprintln(output, "  --root-data-image ABSOLUTE_FILE --root-hash-tree-image ABSOLUTE_FILE --output ABSOLUTE_DIR")
}

func removeWorkDirectory(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0700)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}
