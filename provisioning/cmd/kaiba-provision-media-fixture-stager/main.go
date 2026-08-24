//go:build linux

// kaiba-provision-media-fixture-stager is a regular-file-only CI adapter. It
// cannot open anything below /dev and its result is structurally incapable of
// becoming a production stage receipt.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediawriter"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/planapproval"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3

	fixtureResultSchemaVersion = "kaiba.provisioning.rpi5-media-fixture-result/v1alpha1"
	fixtureResultDigestDomain  = "kaiba.provisioning.rpi5-media-fixture-result.v1alpha1"
)

// Nix linker-fixes this closed asset set for CI. It cannot be changed by CLI
// flags or environment variables.
var (
	primaryGPTPath     string
	bootFilesystemPath string
	rootDataPath       string
	rootHashPath       string
	backupGPTPath      string
	approvedPlanPath   string
)

var (
	loadPlan            = mediacontract.LoadPlan
	requireApprovedPlan = func(plan mediacontract.Plan) error { return planapproval.Require(plan, approvedPlanPath) }
	stageAndEncode      = productionStageAndEncode
	validateEvidence    = evidencefile.ValidateNewPath
	writeEvidence       = evidencefile.WriteCanonicalNew
)

type fixtureResult struct {
	SchemaVersion          string               `json:"schema_version"`
	Status                 string               `json:"status"`
	EvidenceMode           string               `json:"evidence_mode"`
	PlanDigest             mediacontract.Digest `json:"plan_digest"`
	TargetPath             string               `json:"target_path"`
	FullMediaDigest        mediacontract.Digest `json:"full_media_digest"`
	BytesWritten           uint64               `json:"bytes_written"`
	ReopenedTarget         bool                 `json:"reopened_target"`
	BlockDeviceAccess      bool                 `json:"block_device_access"`
	ColdPowerCycleObserved bool                 `json:"cold_power_cycle_observed"`
	HardwareObserved       bool                 `json:"hardware_observed"`
	SecurityEnforced       bool                 `json:"security_enforced"`
	MutationEligible       bool                 `json:"mutation_eligible"`
	OneTimeSettingsChanged bool                 `json:"one_time_settings_changed"`
	ResultDigest           mediacontract.Digest `json:"result_digest"`
}

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "stage" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("stage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "absolute canonical media plan path")
	targetPath := flags.String("target", "", "absolute pre-existing regular-file target outside /dev")
	resultPath := flags.String("result", "", "absolute new fixture result path outside /dev")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *planPath == "" || *targetPath == "" || *resultPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	plan, err := loadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "stage regular-file fixture: load plan: %v\n", err)
		return exitInvalid
	}
	if err := requireApprovedPlan(plan); err != nil {
		fmt.Fprintf(stderr, "stage regular-file fixture: approve plan: %v\n", err)
		return exitInvalid
	}
	if err := validateEvidence(*resultPath); err != nil {
		fmt.Fprintf(stderr, "stage regular-file fixture: validate result output: %v\n", err)
		return exitInvalid
	}
	canonical, err := stageAndEncode(ctx, plan, *targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "stage regular-file fixture: %v\n", err)
		return exitInvalid
	}
	if err := writeEvidence(*resultPath, canonical); err != nil {
		fmt.Fprintf(stderr, "stage regular-file fixture: publish result: %v\n", err)
		return exitInternal
	}
	_ = stdout
	return exitOK
}

func immutableAssetPaths() (mediawriter.AssetPaths, error) {
	paths := mediawriter.AssetPaths{
		PrimaryGPT: primaryGPTPath, BootFilesystem: bootFilesystemPath,
		RootData: rootDataPath, RootHash: rootHashPath, BackupGPT: backupGPTPath,
	}
	for _, asset := range []struct{ role, path string }{
		{"primary GPT", primaryGPTPath}, {"boot filesystem", bootFilesystemPath},
		{"root data", rootDataPath}, {"root hash", rootHashPath}, {"backup GPT", backupGPTPath},
	} {
		if asset.path == "" || !filepath.IsAbs(asset.path) || filepath.Clean(asset.path) != asset.path || !strings.HasPrefix(asset.path, "/nix/store/") {
			return mediawriter.AssetPaths{}, fmt.Errorf("generic build has no linker-fixed %s store asset", asset.role)
		}
	}
	return paths, nil
}

func productionStageAndEncode(ctx context.Context, plan mediacontract.Plan, targetPath string) ([]byte, error) {
	if targetPath == "" || !filepath.IsAbs(targetPath) || filepath.Clean(targetPath) != targetPath || targetPath == "/dev" || strings.HasPrefix(targetPath, "/dev/") {
		return nil, errors.New("fixture target must be a clean absolute path outside /dev")
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	paths, err := immutableAssetPaths()
	if err != nil {
		return nil, err
	}
	for _, sourcePath := range []string{paths.PrimaryGPT, paths.BootFilesystem, paths.RootData, paths.RootHash, paths.BackupGPT} {
		if sourcePath == targetPath {
			return nil, errors.New("fixture target cannot also be an immutable source")
		}
	}
	target, err := openLockedRegular(targetPath, true, plan.Target.SizeBytes)
	if err != nil {
		return nil, err
	}
	targetOpen := true
	defer func() {
		if targetOpen {
			_ = closeLockedRegular(target)
		}
	}()
	sources, err := mediawriter.OpenSources(ctx, plan, paths)
	if err != nil {
		return nil, err
	}
	sourcesOpen := true
	defer func() {
		if sourcesOpen {
			_ = sources.Close()
		}
	}()
	if err := sources.ValidateDistinctRegularTarget(target); err != nil {
		return nil, err
	}
	written, err := mediawriter.Stage(ctx, target, plan, sources)
	if err != nil {
		if written > 0 {
			return nil, fmt.Errorf("FIXTURE MUTATED; discard it: %w", err)
		}
		return nil, err
	}
	ambiguous := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("FIXTURE MUTATED; discard it: %w", err)
	}
	if err := target.Sync(); err != nil {
		return ambiguous(fmt.Errorf("fsync fixture target: %w", err))
	}
	if err := validateOpenedRegular(target, plan.Target.SizeBytes); err != nil {
		return ambiguous(err)
	}
	if err := closeLockedRegular(target); err != nil {
		targetOpen = false
		return ambiguous(err)
	}
	targetOpen = false
	if err := sources.Close(); err != nil {
		sourcesOpen = false
		return ambiguous(err)
	}
	sourcesOpen = false
	readback, err := openLockedRegular(targetPath, false, plan.Target.SizeBytes)
	if err != nil {
		return ambiguous(fmt.Errorf("reopen fixture target read-only: %w", err))
	}
	readbackOpen := true
	defer func() {
		if readbackOpen {
			_ = closeLockedRegular(readback)
		}
	}()
	observed, err := mediawriter.HashRange(ctx, readback, 0, plan.Target.SizeBytes)
	if err != nil {
		return ambiguous(fmt.Errorf("hash reopened fixture: %w", err))
	}
	if observed != plan.ExpectedMediaDigest {
		return ambiguous(fmt.Errorf("reopened fixture digest is %s, expected %s", observed, plan.ExpectedMediaDigest))
	}
	if err := closeLockedRegular(readback); err != nil {
		readbackOpen = false
		return ambiguous(err)
	}
	readbackOpen = false
	result := fixtureResult{
		SchemaVersion: fixtureResultSchemaVersion, Status: "fixture_staged_and_reopened",
		EvidenceMode: "regular_file_fixture", PlanDigest: plan.PlanDigest,
		TargetPath: targetPath, FullMediaDigest: observed, BytesWritten: written, ReopenedTarget: true,
	}
	result.ResultDigest, err = result.derivedDigest()
	if err != nil {
		return nil, err
	}
	return result.canonicalJSON()
}

func (result fixtureResult) digestMaterial() ([]byte, error) {
	material := result
	material.ResultDigest = ""
	return json.Marshal(material)
}

func (result fixtureResult) derivedDigest() (mediacontract.Digest, error) {
	material, err := result.digestMaterial()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(fixtureResultDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(material)
	return mediacontract.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func (result fixtureResult) canonicalJSON() ([]byte, error) {
	if result.SchemaVersion != fixtureResultSchemaVersion || result.Status != "fixture_staged_and_reopened" || result.EvidenceMode != "regular_file_fixture" ||
		result.TargetPath == "" || !filepath.IsAbs(result.TargetPath) || filepath.Clean(result.TargetPath) != result.TargetPath ||
		result.TargetPath == "/dev" || strings.HasPrefix(result.TargetPath, "/dev/") || result.BytesWritten == 0 || !result.ReopenedTarget ||
		result.BlockDeviceAccess || result.ColdPowerCycleObserved || result.HardwareObserved || result.SecurityEnforced || result.MutationEligible || result.OneTimeSettingsChanged {
		return nil, errors.New("fixture result contains a prohibited production or mutation claim")
	}
	if err := result.PlanDigest.Validate(); err != nil {
		return nil, fmt.Errorf("fixture result plan digest: %w", err)
	}
	if err := result.FullMediaDigest.Validate(); err != nil {
		return nil, fmt.Errorf("fixture result full-media digest: %w", err)
	}
	if err := result.ResultDigest.Validate(); err != nil {
		return nil, fmt.Errorf("fixture result digest: %w", err)
	}
	derived, err := result.derivedDigest()
	if err != nil {
		return nil, err
	}
	if result.ResultDigest != derived {
		return nil, errors.New("fixture result digest does not match canonical content")
	}
	return json.Marshal(result)
}

func openLockedRegular(path string, writable bool, expectedSize uint64) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	if writable {
		flags = syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	}
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open no-follow fixture target: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct fixture target handle")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock fixture target exclusively: %w", err)
	}
	if err := validateOpenedRegular(file, expectedSize); err != nil {
		_ = closeLockedRegular(file)
		return nil, err
	}
	return file, nil
}

func validateOpenedRegular(file *os.File, expectedSize uint64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != expectedSize {
		return errors.New("fixture target is not one exact-size regular non-symlink file")
	}
	return nil
}

func closeLockedRegular(file *os.File) error {
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-media-fixture-stager stage --plan ABSOLUTE_PATH --target ABSOLUTE_REGULAR_FILE --result ABSOLUTE_NEW_PATH")
}
