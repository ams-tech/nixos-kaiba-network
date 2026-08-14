package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const (
	exitOK              = 0
	exitInternal        = 1
	exitUsageOrProfile  = 2
	exitEvidence        = 3
	exitDeviceClass     = 4
	exitBaseline        = 5
	exitQualification   = 6
	exitIncomplete      = 7
	resultSchemaVersion = rpi5.ProbeResultSchemaVersion
)

// These paths are deliberately populated by the Nix build. They are not
// configurable through flags or the environment because their immutable
// closure is part of the live probe's safety boundary.
var (
	rpibootPath       string
	probeBundlePath   string
	probeManifestPath string
	buildSystem       string
)

type dependencies struct {
	now        func() time.Time
	liveSource func() rpi5.EvidenceSource
}

type profileReference = rpi5.ProfileReference
type adapterReference = rpi5.AdapterReference
type probeResult = rpi5.ProbeResult

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, productionDependencies()))
}

func productionDependencies() dependencies {
	return dependencies{
		now: time.Now,
		liveSource: func() rpi5.EvidenceSource {
			return rpi5.LiveSource{Config: rpi5.LiveConfig{
				BinaryPath:   rpibootPath,
				BundlePath:   probeBundlePath,
				ManifestPath: probeManifestPath,
			}}
		},
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsageOrProfile
	}
	switch args[0] {
	case "probe":
		return runProbe(ctx, args, stdin, stdout, stderr, deps)
	case "qualify":
		return runQualify(args, stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsageOrProfile
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision probe --profile FILE (--metadata FILE|- | --lane-id ID --usb-path PATH)")
	fmt.Fprintln(output, "       kaiba-provision qualify --profile FILE --first-result FILE --second-result FILE --source-revision HEX --system-closure /nix/store/PATH --power-cycle-confirmation complete --pre-probe-normal-boot confirmed --normal-boot-confirmation pending|unchanged|failed")
}

func runProbe(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	if deps.now == nil || deps.liveSource == nil {
		fmt.Fprintln(stderr, "internal error: command dependencies are unavailable")
		return exitInternal
	}

	flags := flag.NewFlagSet("kaiba-provision probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: kaiba-provision probe --profile FILE (--metadata FILE|- | --lane-id ID --usb-path PATH)")
	}
	profilePath := flags.String("profile", "", "device-class profile JSON file")
	metadataPath := flags.String("metadata", "", "rpiboot metadata JSON file, or - for standard input")
	laneID := flags.String("lane-id", "", "permanent provisioning lane identifier")
	usbPath := flags.String("usb-path", "", "exact Linux USB topology path, such as 1-2.3")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsageOrProfile
	}
	if flags.NArg() != 0 || *profilePath == "" {
		flags.Usage()
		return exitUsageOrProfile
	}
	live := *usbPath != "" || *laneID != ""
	offline := *metadataPath != ""
	if live == offline || (live && (*usbPath == "" || *laneID == "")) {
		fmt.Fprintln(stderr, "probe requires exactly one complete source: --metadata, or both --lane-id and --usb-path")
		return exitUsageOrProfile
	}

	profileFile, err := os.Open(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", err)
		return exitUsageOrProfile
	}
	profile, profileErr := provisioning.LoadProfile(profileFile)
	closeErr := profileFile.Close()
	if profileErr != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", profileErr)
		return exitUsageOrProfile
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", closeErr)
		return exitUsageOrProfile
	}

	var evidence rpi5.RawEvidence
	if offline {
		metadata, err := readMetadata(*metadataPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "acquire metadata: %v\n", err)
			return exitEvidence
		}
		evidence = rpi5.RawEvidence{
			Metadata: metadata,
			Provenance: rpi5.Provenance{
				Source: "offline-metadata",
			},
		}
	} else {
		evidence, err = deps.liveSource().Acquire(ctx, rpi5.ProbeRequest{
			LaneID:  *laneID,
			USBPath: *usbPath,
		})
		if err != nil {
			fmt.Fprintf(stderr, "acquire live metadata: %v\n", err)
			return exitEvidence
		}
	}

	var adapter provisioning.Adapter = rpi5.Adapter{}
	normalized, err := adapter.Normalize(provisioning.RawEvidence{Payload: evidence.Metadata})
	if err != nil {
		fmt.Fprintf(stderr, "normalize metadata: %v\n", err)
		return exitEvidence
	}
	observation, ok := normalized.Native.(rpi5.Observation)
	if !ok {
		fmt.Fprintln(stderr, "internal error: adapter did not return a Raspberry Pi observation")
		return exitInternal
	}
	assessment := provisioning.Evaluate(profile, normalized)
	result := probeResult{
		SchemaVersion: resultSchemaVersion,
		ObservedAt:    deps.now().UTC(),
		Profile: profileReference{
			ID:           profile.Metadata.ID,
			Status:       profile.Metadata.Status,
			Digest:       profile.Digest,
			PolicyDigest: profile.PolicyDigest,
		},
		Adapter: adapterReference{
			ID:      observation.AdapterID,
			Version: observation.AdapterVersion,
		},
		Source:      evidence.Provenance,
		Observation: observation,
		Assessment:  assessment,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return exitInternal
	}

	if assessment.Class.Status != provisioning.StatusPass {
		return exitDeviceClass
	}
	if assessment.ObservableBaseline.Status != provisioning.StatusPass {
		return exitBaseline
	}
	return exitOK
}

func runQualify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-provision qualify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: kaiba-provision qualify --profile FILE --first-result FILE --second-result FILE --source-revision HEX --system-closure /nix/store/PATH --power-cycle-confirmation complete --pre-probe-normal-boot confirmed --normal-boot-confirmation pending|unchanged|failed")
	}
	profilePath := flags.String("profile", "", "device-class profile JSON file used for both probes")
	firstPath := flags.String("first-result", "", "private JSON result from the first live probe")
	secondPath := flags.String("second-result", "", "private JSON result from the second live probe")
	sourceRevision := flags.String("source-revision", "", "exact lowercase 40- or 64-hex Git revision")
	systemClosure := flags.String("system-closure", "", "exact NixOS system closure store path")
	powerCycle := flags.String("power-cycle-confirmation", "", "operator confirmation: complete")
	preProbeBoot := flags.String("pre-probe-normal-boot", "", "operator confirmation: confirmed")
	normalBoot := flags.String("normal-boot-confirmation", "", "operator result: pending, unchanged, or failed")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsageOrProfile
	}
	if flags.NArg() != 0 || *profilePath == "" || *firstPath == "" || *secondPath == "" ||
		*sourceRevision == "" || *systemClosure == "" || *powerCycle == "" || *preProbeBoot == "" || *normalBoot == "" {
		flags.Usage()
		return exitUsageOrProfile
	}
	if *firstPath == *secondPath {
		fmt.Fprintln(stderr, "qualification requires two different private result files")
		return exitUsageOrProfile
	}
	if *powerCycle != "complete" || *preProbeBoot != "confirmed" || (*normalBoot != "pending" && *normalBoot != "unchanged" && *normalBoot != "failed") {
		fmt.Fprintln(stderr, "qualification confirmations must be: power cycle complete, pre-probe normal boot confirmed, and normal boot pending, unchanged, or failed")
		return exitUsageOrProfile
	}

	context := rpi5.QualificationContext{
		SourceRevision:           *sourceRevision,
		StationSystem:            qualificationStationSystem(),
		NixSystemClosure:         *systemClosure,
		PowerCycleConfirmation:   rpi5.PowerCycleOperatorConfirmed,
		PreProbeBootConfirmation: rpi5.PreProbeBootOperatorConfirmed,
		NormalBootConfirmation:   rpi5.NormalBootUnchanged,
	}
	if *normalBoot == "failed" {
		context.NormalBootConfirmation = rpi5.NormalBootFailed
	} else if *normalBoot == "pending" {
		context.NormalBootConfirmation = rpi5.NormalBootPending
	}
	if err := rpi5.ValidateQualificationContext(context); err != nil {
		fmt.Fprintf(stderr, "invalid qualification context: %v\n", err)
		return exitUsageOrProfile
	}

	profileFile, err := os.Open(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", err)
		return exitUsageOrProfile
	}
	profile, profileErr := provisioning.LoadProfile(profileFile)
	closeErr := profileFile.Close()
	if profileErr != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", profileErr)
		return exitUsageOrProfile
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "load profile: %v\n", closeErr)
		return exitUsageOrProfile
	}
	first, err := rpi5.LoadProbeResult(*firstPath)
	if err != nil {
		fmt.Fprintf(stderr, "load first probe result: %v\n", err)
		return exitEvidence
	}
	second, err := rpi5.LoadProbeResult(*secondPath)
	if err != nil {
		fmt.Fprintf(stderr, "load second probe result: %v\n", err)
		return exitEvidence
	}
	record, err := rpi5.BuildQualificationRecord(profile, first, second, context)
	if err != nil {
		fmt.Fprintf(stderr, "qualify hardware: %v\n", err)
		return exitEvidence
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		fmt.Fprintf(stderr, "encode qualification record: %v\n", err)
		return exitInternal
	}
	if record.Status != rpi5.QualificationStatusPassed {
		if record.Status == rpi5.QualificationStatusIncomplete {
			return exitIncomplete
		}
		return exitQualification
	}
	return exitOK
}

func qualificationStationSystem() string {
	if buildSystem != "" {
		return buildSystem
	}
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return "x86_64-linux"
	case "linux/arm64":
		return "aarch64-linux"
	default:
		return ""
	}
}

func readMetadata(path string, stdin io.Reader) ([]byte, error) {
	var reader io.Reader
	var file *os.File
	if path == "-" {
		reader = stdin
	} else {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, rpi5.MaxMetadataSize+1))
	if file != nil {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return nil, err
	}
	if len(data) > rpi5.MaxMetadataSize {
		return nil, fmt.Errorf("metadata exceeds %d bytes", rpi5.MaxMetadataSize)
	}
	if len(data) == 0 {
		return nil, errors.New("metadata is empty")
	}
	return data, nil
}
