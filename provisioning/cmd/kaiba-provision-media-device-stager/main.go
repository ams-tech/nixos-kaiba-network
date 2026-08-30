//go:build linux

// kaiba-provision-media-device-stager is the only production binary in this
// slice that can mutate a block device. It exposes no fixture mode, target
// override, source-image flag, force switch, or automatic retry.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediawriter"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/planapproval"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3

	devicePreflightSchemaVersion = "kaiba.provisioning.rpi5-media-device-preflight/v1alpha3"
	maximumPreflightBytes        = 64 * 1024
)

var operationalIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// Nix must linker-fix the source and plan variables to immutable reviewed store
// assets and targetDevicePath to one explicit station-local selector. There are
// deliberately no flag or environment fallbacks.
var (
	primaryGPTPath          string
	bootFilesystemPath      string
	rootDataPath            string
	rootHashPath            string
	backupGPTPath           string
	approvedPlanPath        string
	targetDevicePath        string
	hardwareConfigurationID string
	expectedHostname        string
	protectedDevicePathsCSV string
)

var (
	effectiveUID        = os.Geteuid
	hostname            = os.Hostname
	loadPlan            = mediacontract.LoadPlan
	requireApprovedPlan = func(plan mediacontract.Plan) error { return planapproval.Require(plan, approvedPlanPath) }
	dryRunAndEncode     = productionDryRunAndEncode
	stageAndEncode      = productionStageAndEncode
	readPreflight       = func(path string) ([]byte, error) {
		return evidencefile.ReadTrustedExisting(path, maximumPreflightBytes)
	}
	validateEvidence = evidencefile.ValidateTrustedNewPath
	writeEvidence    = evidencefile.WriteCanonicalNewTrusted
)

type configuredStation struct {
	HardwareConfigurationID string
	Hostname                string
	TargetDevicePath        string
	Policy                  mediadevice.StationPolicy
}

type devicePreflight struct {
	SchemaVersion           string                      `json:"schema_version"`
	Status                  string                      `json:"status"`
	EvidenceMode            string                      `json:"evidence_mode"`
	PlanDigest              mediacontract.Digest        `json:"plan_digest"`
	Target                  mediacontract.TargetBinding `json:"target"`
	HardwareConfigurationID string                      `json:"hardware_configuration_id"`
	ExecutionHostname       string                      `json:"execution_hostname"`
	RequestedDeviceSelector string                      `json:"requested_device_selector"`
	ResolvedDevicePath      string                      `json:"resolved_device_path"`
	AttachmentBootID        string                      `json:"attachment_boot_id"`
	AttachmentSequence      uint64                      `json:"attachment_sequence"`
	SourcesVerified         bool                        `json:"sources_verified"`
	TargetUsageClear        bool                        `json:"target_usage_clear"`
	TargetWholeDevice       bool                        `json:"target_whole_device"`
	TargetGeometryVerified  bool                        `json:"target_geometry_verified"`
	TargetLocked            bool                        `json:"target_locked"`
	WritePerformed          bool                        `json:"write_performed"`
}

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || (arguments[0] != "dry-run" && arguments[0] != "stage") {
		printUsage(stderr)
		return exitUsage
	}
	command := arguments[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "absolute canonical media plan path")
	preflightPath := flags.String("preflight", "", "absolute trusted operational preflight path")
	var receiptPath *string
	if command == "stage" {
		receiptPath = flags.String("receipt", "", "absolute new stage receipt path outside /dev")
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *planPath == "" || *preflightPath == "" || (command == "stage" && (receiptPath == nil || *receiptPath == "")) {
		printUsage(stderr)
		return exitUsage
	}
	if effectiveUID() != 0 {
		fmt.Fprintln(stderr, "stage device media: production block-device access requires root")
		return exitInvalid
	}
	station, err := loadConfiguredStation()
	if err != nil {
		fmt.Fprintf(stderr, "stage device media: validate execution station: %v\n", err)
		return exitInvalid
	}
	plan, err := loadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "stage device media: load plan: %v\n", err)
		return exitInvalid
	}
	if err := requireApprovedPlan(plan); err != nil {
		fmt.Fprintf(stderr, "stage device media: approve plan: %v\n", err)
		return exitInvalid
	}
	if command == "dry-run" {
		if err := validateEvidence(*preflightPath); err != nil {
			fmt.Fprintf(stderr, "stage device media: validate preflight output: %v\n", err)
			return exitInvalid
		}
		canonical, err := dryRunAndEncode(ctx, plan, station)
		if err != nil {
			fmt.Fprintf(stderr, "stage device media: dry-run: %v\n", err)
			return exitInvalid
		}
		if err := writeEvidence(*preflightPath, canonical); err != nil {
			fmt.Fprintf(stderr, "stage device media: publish non-mutating preflight: %v\n", err)
			return exitInternal
		}
		if _, err := stdout.Write(append(canonical, '\n')); err != nil {
			fmt.Fprintf(stderr, "stage device media: write dry-run report: %v\n", err)
			return exitInternal
		}
		return exitOK
	}
	preflightBytes, err := readPreflight(*preflightPath)
	if err != nil {
		fmt.Fprintf(stderr, "stage device media: read trusted preflight: %v\n", err)
		return exitInvalid
	}
	preflight, err := parseDevicePreflight(preflightBytes, plan, station)
	if err != nil {
		fmt.Fprintf(stderr, "stage device media: validate trusted preflight: %v\n", err)
		return exitInvalid
	}
	if err := validateEvidence(*receiptPath); err != nil {
		fmt.Fprintf(stderr, "stage device media: validate receipt output: %v\n", err)
		return exitInvalid
	}
	canonical, err := stageAndEncode(ctx, plan, station, preflight)
	if err != nil {
		fmt.Fprintf(stderr, "stage device media: %v\n", err)
		return exitInvalid
	}
	if err := writeEvidence(*receiptPath, canonical); err != nil {
		fmt.Fprintf(stderr, "stage device media: TARGET MUTATED; quarantine it and do not retry automatically; publish receipt: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func loadConfiguredStation() (configuredStation, error) {
	if !operationalIdentifierPattern.MatchString(hardwareConfigurationID) {
		return configuredStation{}, errors.New("linker-fixed hardware-configuration ID is not canonical")
	}
	if targetDevicePath == "" || !filepath.IsAbs(targetDevicePath) || filepath.Clean(targetDevicePath) != targetDevicePath || !strings.HasPrefix(targetDevicePath, "/dev/") {
		return configuredStation{}, errors.New("linker-fixed target selector is not one clean absolute /dev path")
	}
	policy, err := mediadevice.NewStationPolicy(expectedHostname, protectedDevicePathsCSV)
	if err != nil {
		return configuredStation{}, err
	}
	actualHostname, err := hostname()
	if err != nil {
		return configuredStation{}, fmt.Errorf("read execution hostname: %w", err)
	}
	if err := policy.ValidateHost(actualHostname); err != nil {
		return configuredStation{}, err
	}
	return configuredStation{
		HardwareConfigurationID: hardwareConfigurationID,
		Hostname:                actualHostname,
		TargetDevicePath:        targetDevicePath,
		Policy:                  policy,
	}, nil
}

func immutableAssetPaths() (mediawriter.AssetPaths, error) {
	paths := mediawriter.AssetPaths{
		PrimaryGPT:     primaryGPTPath,
		BootFilesystem: bootFilesystemPath,
		RootData:       rootDataPath,
		RootHash:       rootHashPath,
		BackupGPT:      backupGPTPath,
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

func newDevicePreflight(plan mediacontract.Plan, station configuredStation, facts mediainventory.TargetFacts) devicePreflight {
	return devicePreflight{
		SchemaVersion: devicePreflightSchemaVersion, Status: "validated_no_write", EvidenceMode: "device_preflight",
		PlanDigest: plan.PlanDigest, Target: plan.Target,
		HardwareConfigurationID: station.HardwareConfigurationID,
		ExecutionHostname:       station.Hostname, RequestedDeviceSelector: facts.RequestedPath,
		ResolvedDevicePath: facts.ResolvedPath, AttachmentBootID: facts.BootID, AttachmentSequence: facts.DiskSequence,
		SourcesVerified: true, TargetUsageClear: true, TargetWholeDevice: true,
		TargetGeometryVerified: true, TargetLocked: true, WritePerformed: false,
	}
}

func (report devicePreflight) validateStatic(plan mediacontract.Plan, station configuredStation) error {
	if report.SchemaVersion != devicePreflightSchemaVersion || report.Status != "validated_no_write" || report.EvidenceMode != "device_preflight" {
		return errors.New("operational preflight has an unsupported schema, status, or evidence mode")
	}
	if report.PlanDigest != plan.PlanDigest || report.Target != plan.Target {
		return errors.New("operational preflight is bound to a different media plan or target geometry")
	}
	if report.HardwareConfigurationID != station.HardwareConfigurationID || report.ExecutionHostname != station.Hostname || report.RequestedDeviceSelector != station.TargetDevicePath {
		return errors.New("operational preflight is bound to a different hardware configuration, host, or selector")
	}
	if report.ResolvedDevicePath == "" || !filepath.IsAbs(report.ResolvedDevicePath) || filepath.Clean(report.ResolvedDevicePath) != report.ResolvedDevicePath || !strings.HasPrefix(report.ResolvedDevicePath, "/dev/") {
		return errors.New("operational preflight resolved path is not one clean absolute /dev node")
	}
	if report.AttachmentBootID == "" || report.AttachmentSequence == 0 {
		return errors.New("operational preflight has no boot-scoped attachment identity")
	}
	if !report.SourcesVerified || !report.TargetUsageClear || !report.TargetWholeDevice || !report.TargetGeometryVerified || !report.TargetLocked || report.WritePerformed {
		return errors.New("operational preflight does not assert the complete non-mutating safety boundary")
	}
	return nil
}

func (report devicePreflight) validateCurrent(facts mediainventory.TargetFacts) error {
	if report.RequestedDeviceSelector != facts.RequestedPath || report.ResolvedDevicePath != facts.ResolvedPath || report.AttachmentBootID != facts.BootID || report.AttachmentSequence != facts.DiskSequence {
		return errors.New("selected block-device attachment differs from the reviewed operational preflight")
	}
	return nil
}

func parseDevicePreflight(data []byte, plan mediacontract.Plan, station configuredStation) (devicePreflight, error) {
	if len(data) == 0 || len(data) > maximumPreflightBytes {
		return devicePreflight{}, errors.New("operational preflight exceeds its fixed size bound")
	}
	var report devicePreflight
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return devicePreflight{}, fmt.Errorf("decode operational preflight: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return devicePreflight{}, errors.New("operational preflight contains trailing JSON data")
	}
	canonical, err := json.Marshal(report)
	if err != nil {
		return devicePreflight{}, fmt.Errorf("encode operational preflight: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return devicePreflight{}, errors.New("operational preflight is not canonical JSON")
	}
	if err := report.validateStatic(plan, station); err != nil {
		return devicePreflight{}, err
	}
	return report, nil
}

func productionDryRunAndEncode(ctx context.Context, plan mediacontract.Plan, station configuredStation) ([]byte, error) {
	paths, err := immutableAssetPaths()
	if err != nil {
		return nil, err
	}
	inspector := mediadevice.Inspector{}
	facts, err := inspector.InspectSelected(ctx, plan, station.TargetDevicePath)
	if err != nil {
		return nil, err
	}
	if err := station.Policy.ValidateTarget(facts); err != nil {
		return nil, err
	}
	target, err := mediadevice.OpenLocked(facts, false)
	if err != nil {
		return nil, err
	}
	defer mediadevice.CloseLocked(target) //nolint:errcheck
	sources, err := mediawriter.OpenSources(ctx, plan, paths)
	if err != nil {
		return nil, err
	}
	defer sources.Close() //nolint:errcheck
	current, err := inspector.ReinspectSame(ctx, plan, station.TargetDevicePath, facts)
	if err != nil {
		return nil, err
	}
	if err := mediadevice.ValidateOpened(target, current); err != nil {
		return nil, err
	}
	if err := station.Policy.ValidateTarget(current); err != nil {
		return nil, err
	}
	report := newDevicePreflight(plan, station, current)
	return json.Marshal(report)
}

func productionStageAndEncode(ctx context.Context, plan mediacontract.Plan, station configuredStation, preflight devicePreflight) ([]byte, error) {
	if err := preflight.validateStatic(plan, station); err != nil {
		return nil, err
	}
	paths, err := immutableAssetPaths()
	if err != nil {
		return nil, err
	}
	inspector := mediadevice.Inspector{}
	facts, err := inspector.InspectSelected(ctx, plan, station.TargetDevicePath)
	if err != nil {
		return nil, err
	}
	if err := station.Policy.ValidateTarget(facts); err != nil {
		return nil, err
	}
	if err := preflight.validateCurrent(facts); err != nil {
		return nil, err
	}
	target, err := mediadevice.OpenLocked(facts, true)
	if err != nil {
		return nil, err
	}
	targetOpen := true
	defer func() {
		if targetOpen {
			_ = mediadevice.CloseLocked(target)
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
	current, err := inspector.ReinspectSame(ctx, plan, station.TargetDevicePath, facts)
	if err != nil {
		return nil, err
	}
	if err := mediadevice.ValidateOpened(target, current); err != nil {
		return nil, err
	}
	if err := station.Policy.ValidateTarget(current); err != nil {
		return nil, err
	}
	if err := preflight.validateCurrent(current); err != nil {
		return nil, err
	}

	written, err := mediawriter.Stage(ctx, target, plan, sources)
	if err != nil {
		if written > 0 {
			return nil, fmt.Errorf("TARGET MUTATED; quarantine it and do not retry automatically: %w", err)
		}
		return nil, err
	}
	ambiguous := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("TARGET MUTATED; quarantine it and do not retry automatically: %w", err)
	}
	if err := target.Sync(); err != nil {
		return ambiguous(fmt.Errorf("fsync staged target: %w", err))
	}
	if err := mediadevice.ValidateOpened(target, current); err != nil {
		return ambiguous(fmt.Errorf("revalidate staged target: %w", err))
	}
	if _, err := inspector.ReinspectSame(ctx, plan, station.TargetDevicePath, current); err != nil {
		return ambiguous(fmt.Errorf("reinspect staged target: %w", err))
	}
	if err := mediadevice.CloseLocked(target); err != nil {
		targetOpen = false
		return ambiguous(fmt.Errorf("close staged target: %w", err))
	}
	targetOpen = false
	if err := sources.Close(); err != nil {
		sourcesOpen = false
		return ambiguous(fmt.Errorf("close immutable sources: %w", err))
	}
	sourcesOpen = false

	reopenedFacts, err := inspector.ReinspectSame(ctx, plan, station.TargetDevicePath, facts)
	if err != nil {
		return ambiguous(fmt.Errorf("reinspect target for same-phase readback: %w", err))
	}
	readback, err := mediadevice.OpenLocked(reopenedFacts, false)
	if err != nil {
		return ambiguous(fmt.Errorf("reopen target read-only: %w", err))
	}
	readbackOpen := true
	defer func() {
		if readbackOpen {
			_ = mediadevice.CloseLocked(readback)
		}
	}()
	observed, err := mediadevice.HashRange(ctx, readback, 0, reopenedFacts.SizeBytes)
	if err != nil {
		return ambiguous(fmt.Errorf("hash reopened complete target: %w", err))
	}
	receiptFacts, err := inspector.ReinspectSame(ctx, plan, station.TargetDevicePath, reopenedFacts)
	if err != nil {
		return ambiguous(fmt.Errorf("reinspect reopened target after final hash: %w", err))
	}
	if err := mediadevice.ValidateOpened(readback, receiptFacts); err != nil {
		return ambiguous(fmt.Errorf("revalidate reopened target after final hash: %w", err))
	}
	if observed != plan.ExpectedMediaDigest {
		return ambiguous(fmt.Errorf("reopened complete target digest is %s, expected %s", observed, plan.ExpectedMediaDigest))
	}
	if err := mediadevice.CloseLocked(readback); err != nil {
		readbackOpen = false
		return ambiguous(fmt.Errorf("close reopened target: %w", err))
	}
	readbackOpen = false
	receipt, err := mediacontract.NewStageReceipt(plan, receiptFacts.BootID, receiptFacts.DiskSequence, observed)
	if err != nil {
		return ambiguous(fmt.Errorf("construct stage receipt: %w", err))
	}
	if receipt.BytesWritten != written {
		return ambiguous(fmt.Errorf("writer reported %d bytes but receipt requires %d", written, receipt.BytesWritten))
	}
	canonical, err := receipt.CanonicalJSON(plan)
	if err != nil {
		return ambiguous(fmt.Errorf("encode stage receipt: %w", err))
	}
	return canonical, nil
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  kaiba-provision-media-device-stager dry-run --plan ABSOLUTE_PATH --preflight ABSOLUTE_NEW_PATH")
	fmt.Fprintln(output, "  kaiba-provision-media-device-stager stage --plan ABSOLUTE_PATH --preflight ABSOLUTE_PATH --receipt ABSOLUTE_NEW_PATH")
}
