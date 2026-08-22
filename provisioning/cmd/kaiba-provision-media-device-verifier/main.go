//go:build linux

// kaiba-provision-media-device-verifier is the production, read-only half of
// the media ceremony. It has no target override, source-image, fixture, force,
// retry, or write capability.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediarelease"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/planapproval"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3

	maximumTrustedReceiptBytes = 4 * 1024 * 1024
)

// Nix must linker-fix this to the reviewed veritysetup store executable.
// There is deliberately no flag or environment fallback.
var veritysetupPath string
var approvedPlanPath string
var signedReleasePath string
var mtypePath string

var (
	effectiveUID        = os.Geteuid
	loadPlan            = mediacontract.LoadPlan
	requireApprovedPlan = func(plan mediacontract.Plan) error { return planapproval.Require(plan, approvedPlanPath) }
	readStageReceipt    = func(path string) ([]byte, error) {
		return evidencefile.ReadTrustedExisting(path, maximumTrustedReceiptBytes)
	}
	parseStageReceipt     = mediacontract.ParseStageReceipt
	verifyAndEncodeDevice = productionVerifyAndEncode
	validateEvidence      = evidencefile.ValidateTrustedNewPath
	writeEvidence         = evidencefile.WriteCanonicalNewTrusted
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "verify" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "absolute canonical media plan path")
	stagePath := flags.String("stage-receipt", "", "absolute canonical stage receipt path")
	receiptPath := flags.String("receipt", "", "absolute new verification receipt path outside /dev")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *planPath == "" || *stagePath == "" || *receiptPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	if effectiveUID() != 0 {
		fmt.Fprintln(stderr, "verify device media: production block-device verification requires root")
		return exitInvalid
	}
	plan, err := loadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify device media: load plan: %v\n", err)
		return exitInvalid
	}
	if err := requireApprovedPlan(plan); err != nil {
		fmt.Fprintf(stderr, "verify device media: approve plan: %v\n", err)
		return exitInvalid
	}
	stageBytes, err := readStageReceipt(*stagePath)
	if err != nil {
		fmt.Fprintf(stderr, "verify device media: read trusted stage receipt: %v\n", err)
		return exitInvalid
	}
	stage, err := parseStageReceipt(stageBytes, plan)
	if err != nil {
		fmt.Fprintf(stderr, "verify device media: parse trusted stage receipt: %v\n", err)
		return exitInvalid
	}
	if err := validateEvidence(*receiptPath); err != nil {
		fmt.Fprintf(stderr, "verify device media: validate receipt output: %v\n", err)
		return exitInvalid
	}
	canonical, err := verifyAndEncodeDevice(ctx, plan, stage)
	if err != nil {
		fmt.Fprintf(stderr, "verify device media: %v\n", err)
		return exitInvalid
	}
	if err := writeEvidence(*receiptPath, canonical); err != nil {
		fmt.Fprintf(stderr, "verify device media: publish receipt: %v\n", err)
		return exitInternal
	}
	_ = stdout
	return exitOK
}

func productionVerifyAndEncode(ctx context.Context, plan mediacontract.Plan, stage mediacontract.StageReceipt) ([]byte, error) {
	if err := stage.ValidateAgainst(plan); err != nil {
		return nil, err
	}
	release := mediarelease.FixedVerifier{ReleaseRoot: signedReleasePath, MTypePath: mtypePath}
	if err := release.Validate(); err != nil {
		return nil, err
	}
	inspector := mediadevice.Inspector{}
	facts, err := inspector.InspectApproved(ctx, plan)
	if err != nil {
		return nil, err
	}
	if facts.BootID == stage.AttachmentBootID && facts.DiskSequence == stage.AttachmentSequence {
		return nil, errors.New("independent verification requires a fresh (boot_id, block-device attachment sequence) identity")
	}
	target, err := mediadevice.OpenLocked(facts, false)
	if err != nil {
		return nil, err
	}
	defer mediadevice.CloseLocked(target) //nolint:errcheck
	current, err := inspector.ReinspectSame(ctx, plan, facts)
	if err != nil {
		return nil, err
	}
	if err := mediadevice.ValidateOpened(target, current); err != nil {
		return nil, err
	}
	verity := mediadevice.PartitionVerityVerifier{Path: veritysetupPath, Whole: current}
	if err := verity.Validate(); err != nil {
		return nil, err
	}
	report, err := mediacontract.VerifyFullMedia(ctx, target, current.SizeBytes, plan, verity, release)
	if err != nil {
		return nil, err
	}
	if err := mediadevice.ValidateOpened(target, current); err != nil {
		return nil, fmt.Errorf("revalidate verified target: %w", err)
	}
	finalDigest, err := mediadevice.HashRange(ctx, target, 0, current.SizeBytes)
	if err != nil {
		return nil, fmt.Errorf("final complete-media revalidation after dm-verity: %w", err)
	}
	if finalDigest != plan.ExpectedMediaDigest {
		return nil, fmt.Errorf("final complete-media digest after dm-verity is %s, expected %s", finalDigest, plan.ExpectedMediaDigest)
	}
	receipt, err := mediacontract.NewVerificationReceipt(plan, stage, mediacontract.VerificationIndependentDevice, current.BootID, current.DiskSequence, report)
	if err != nil {
		return nil, err
	}
	return receipt.CanonicalJSON(plan, stage)
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-media-device-verifier verify --plan ABSOLUTE_PATH --stage-receipt ABSOLUTE_PATH --receipt ABSOLUTE_NEW_PATH")
}
