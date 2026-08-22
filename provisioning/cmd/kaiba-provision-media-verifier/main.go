package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediarelease"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediaverity"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/planapproval"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3
)

// Generic builds deliberately cannot select an executable at runtime. Nix
// integration must linker-fix one reviewed veritysetup store path.
var veritysetupPath string
var approvedPlanPath string
var signedReleasePath string
var mtypePath string

var (
	loadPlan            = mediacontract.LoadPlan
	requireApprovedPlan = func(plan mediacontract.Plan) error { return planapproval.Require(plan, approvedPlanPath) }
	verifyTarget        = verifyRegularFileTarget
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "verify-regular-file" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("verify-regular-file", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "absolute canonical media plan path")
	targetPath := flags.String("target", "", "absolute regular-file fixture target outside /dev")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *planPath == "" || *targetPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	plan, err := loadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify regular-file media: load plan: %v\n", err)
		return exitInvalid
	}
	if err := requireApprovedPlan(plan); err != nil {
		fmt.Fprintf(stderr, "verify regular-file media: approve plan: %v\n", err)
		return exitInvalid
	}
	report, err := verifyTarget(ctx, *targetPath, plan)
	if err != nil {
		fmt.Fprintf(stderr, "verify regular-file media: %v\n", err)
		return exitInvalid
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(stderr, "encode regular-file verification report: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func verifyRegularFileTarget(ctx context.Context, path string, plan mediacontract.Plan) (mediacontract.VerificationReport, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return mediacontract.VerificationReport{}, errors.New("fixture target must be a clean absolute path outside /dev")
	}
	verity := mediaverity.FixedVerifier{Path: veritysetupPath}
	if err := verity.Validate(); err != nil {
		return mediacontract.VerificationReport{}, err
	}
	release := mediarelease.FixedVerifier{ReleaseRoot: signedReleasePath, MTypePath: mtypePath}
	if err := release.Validate(); err != nil {
		return mediacontract.VerificationReport{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_EXCL, 0)
	if err != nil {
		return mediacontract.VerificationReport{}, fmt.Errorf("open no-follow fixture target: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return mediacontract.VerificationReport{}, errors.New("construct fixture target handle")
	}
	defer file.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return mediacontract.VerificationReport{}, fmt.Errorf("lock fixture target exclusively: %w", err)
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck
	info, err := file.Stat()
	if err != nil {
		return mediacontract.VerificationReport{}, fmt.Errorf("inspect fixture target: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != plan.Target.SizeBytes {
		return mediacontract.VerificationReport{}, errors.New("fixture target is not one exact-size regular file")
	}
	return mediacontract.VerifyFullMedia(ctx, file, uint64(info.Size()), plan, verity, release)
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-media-verifier verify-regular-file --plan ABSOLUTE_PATH --target ABSOLUTE_PATH")
}
