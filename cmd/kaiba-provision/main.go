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
	"syscall"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/provisioning"
	"github.com/kaiba-network/dns-pilot/internal/provisioning/rpi5"
)

const (
	exitOK              = 0
	exitInternal        = 1
	exitUsageOrProfile  = 2
	exitEvidence        = 3
	exitDeviceClass     = 4
	exitBaseline        = 5
	resultSchemaVersion = "provisioning.kaiba.network/target-observation/v1alpha1"
)

// These paths are deliberately populated by the Nix build. They are not
// configurable through flags or the environment because their immutable
// closure is part of the live probe's safety boundary.
var (
	rpibootPath       string
	probeBundlePath   string
	probeManifestPath string
)

type dependencies struct {
	now        func() time.Time
	liveSource func() rpi5.EvidenceSource
}

type profileReference struct {
	ID     string                     `json:"id"`
	Status provisioning.ProfileStatus `json:"status"`
	Digest string                     `json:"digest"`
}

type adapterReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type probeResult struct {
	SchemaVersion string                  `json:"schema_version"`
	ObservedAt    time.Time               `json:"observed_at"`
	Profile       profileReference        `json:"profile"`
	Adapter       adapterReference        `json:"adapter"`
	Source        rpi5.Provenance         `json:"source"`
	Observation   rpi5.Observation        `json:"observation"`
	Assessment    provisioning.Assessment `json:"assessment"`
}

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
	if len(args) == 0 || args[0] != "probe" {
		fmt.Fprintln(stderr, "usage: kaiba-provision probe --profile FILE (--metadata FILE|- | --lane-id ID --usb-path PATH)")
		return exitUsageOrProfile
	}
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
			ID:     profile.Metadata.ID,
			Status: profile.Metadata.Status,
			Digest: profile.Digest,
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
