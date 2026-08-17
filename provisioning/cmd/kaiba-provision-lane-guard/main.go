package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

// These values are immutable build inputs populated with -X linker flags by
// the station package. There are intentionally no runtime flags for them.
var (
	rpibootBinary               string
	gpioSetBinary               string
	freshReadbackBundle         string
	freshCommitBundle           string
	ownedReadbackBundle         string
	ownedRecoveryBundle         string
	negativeBootBundle          string
	rootIntegrityBundle         string
	signedReleaseManifestDigest string
	laneGuardPackageDigest      string
	compiledArtifactSetDigest   string
	expectedCustomerKeyHash     string
	expectedEEPROMHash          string
	expectedBootImageDigest     string
)

var effectiveUID = os.Geteuid

type hardwareFactory func(physicalrpi5.Config) (laneguard.Hardware, error)

var buildHardware hardwareFactory = func(config physicalrpi5.Config) (laneguard.Hardware, error) {
	return physicalrpi5.New(config, physicalrpi5.Dependencies{})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-lane-guard: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("kaiba-provision-lane-guard", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stationID := flags.String("station-id", "development-station", "fixed station identity")
	laneID := flags.String("lane-id", "lane-1", "fixed lane identity")
	usbPath := flags.String("rpiboot-sysfs", "/sys/bus/usb/devices/1-1", "fixed RPIBOOT sysfs path")
	uartPath := flags.String("uart", "/dev/serial/by-id/kaiba-target-uart", "fixed target UART path")
	gpioChip := flags.String("gpio-chip", "/dev/gpiochip0", "fixed power-relay GPIO chip")
	gpioOffset := flags.Uint64("gpio-offset", 0, "fixed power-relay GPIO line offset")
	gpioActiveLow := flags.Bool("gpio-active-low", false, "treat the power-relay line as active-low")
	leaseMargin := flags.Duration("lease-safety-margin", 30*time.Second, "lease lifetime reserved after the worst-case operation duration")
	journalPath := flags.String("journal", "", "absolute durable execute-once journal path")
	planPath := flags.String("plan", "", "absolute approved plan JSON path")
	requestPath := flags.String("request", "", "absolute execute/reconcile request JSON path")
	mode := flags.String("mode", "execute", "one-shot operation: execute or reconcile")
	enableMutations := flags.Bool("enable-mutations", false, "enable the immutable physical RPIBOOT adapter")
	printReleaseBinding := flags.Bool("print-release-binding", false, "print the immutable public release binding as JSON and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *gpioOffset > math.MaxUint32 {
		return errors.New("GPIO offset exceeds uint32")
	}
	laneConfig := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     *stationID, LaneID: *laneID,
		RPIBootSysfsPath: *usbPath, UARTPath: *uartPath,
		PowerGPIO:         laneguard.GPIODescriptor{ChipPath: *gpioChip, Offset: uint32(*gpioOffset), ActiveLow: *gpioActiveLow},
		LeaseSafetyMargin: *leaseMargin,
	}
	if err := laneConfig.Validate(); err != nil {
		return err
	}
	if *printReleaseBinding {
		if *enableMutations {
			return errors.New("print-release-binding cannot be combined with enable-mutations")
		}
		compiledRelease, err := immutableReleaseBinding()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(compiledRelease)
	}
	if !*enableMutations {
		fmt.Fprintf(os.Stdout, "lane guard configuration valid; mutation disabled for %s/%s\n", laneConfig.StationID, laneConfig.LaneID)
		return nil
	}
	if effectiveUID() != 0 {
		return errors.New("physical lane operation requires root")
	}
	if *mode != "execute" && *mode != "reconcile" {
		return errors.New("mode must be execute or reconcile")
	}
	if *journalPath == "" || *planPath == "" || *requestPath == "" {
		return errors.New("enabled operation requires journal, plan, and request paths")
	}
	var plan laneguard.Plan
	if err := loadStrictJSON(*planPath, 1024*1024, &plan); err != nil {
		return fmt.Errorf("load approved plan: %w", err)
	}
	var request laneguard.ExecuteRequest
	if err := loadStrictJSON(*requestPath, 128*1024, &request); err != nil {
		return fmt.Errorf("load operation request: %w", err)
	}
	if err := laneguard.ValidatePlanRequest(laneConfig, plan, request); err != nil {
		return fmt.Errorf("validate approved plan and operation request: %w", err)
	}
	if *mode == "execute" && !time.Now().UTC().Before(plan.ApprovalExpiresAt) {
		return laneguard.ErrApprovalExpired
	}
	immutablePaths := physicalrpi5.ImmutablePaths{
		RPIBootBinary: rpibootBinary, GPIOSetBinary: gpioSetBinary,
		FreshReadbackBundle: freshReadbackBundle, FreshCommitBundle: freshCommitBundle,
		OwnedReadbackBundle: ownedReadbackBundle, OwnedRecoveryBundle: ownedRecoveryBundle,
		NegativeBootBundle: negativeBootBundle, RootIntegrityBundle: rootIntegrityBundle,
		RequireNixStorePaths: true,
	}
	if err := immutablePaths.Validate(); err != nil {
		return fmt.Errorf("validate immutable physical paths: %w", err)
	}
	compiledRelease, err := immutableReleaseBinding()
	if err != nil {
		return err
	}
	if plan.Release != compiledRelease {
		return fmt.Errorf("%w: approved release differs from the immutable lane-guard build", laneguard.ErrPlanMismatch)
	}
	initialMode := physicalrpi5.ModeFresh
	if *mode == "reconcile" {
		initialMode = physicalrpi5.ModeAuto
	} else if plan.Operations[request.Sequence-1].ExpectedPrestate.CustomerKeyHash != zeroHash {
		initialMode = physicalrpi5.ModeOwned
	}
	physicalConfig := physicalrpi5.Config{
		Paths:       immutablePaths,
		InitialMode: initialMode, ExpectedCustomerKeyHash: expectedCustomerKeyHash,
		ExpectedEEPROMHash: expectedEEPROMHash, ExpectedBootImageDigest: expectedBootImageDigest,
	}
	hardware, err := buildHardware(physicalConfig)
	if err != nil {
		return fmt.Errorf("construct immutable physical adapter: %w", err)
	}
	if closer, ok := hardware.(io.Closer); ok {
		defer func() {
			resultErr = errors.Join(resultErr, closer.Close())
		}()
	}
	store, err := laneguard.NewFileStore(*journalPath)
	if err != nil {
		return err
	}
	guard, err := laneguard.New(laneConfig, hardware, store)
	if err != nil {
		return err
	}
	if err := guard.LoadPlan(ctx, plan); err != nil {
		return fmt.Errorf("load approved plan into fixed lane: %w", err)
	}
	var attempt laneguard.Attempt
	if *mode == "reconcile" {
		attempt, err = guard.Reconcile(ctx, request)
	} else {
		attempt, err = guard.Execute(ctx, request)
	}
	if attempt.Key != "" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if encodeErr := encoder.Encode(attempt); encodeErr != nil {
			return errors.Join(err, fmt.Errorf("encode attempt result: %w", encodeErr))
		}
	}
	return err
}

func immutableReleaseBinding() (releasebinding.Binding, error) {
	compiledRelease := releasebinding.Binding{
		SignedReleaseManifestDigest: signedReleaseManifestDigest,
		LaneGuardPackageDigest:      laneGuardPackageDigest,
		CompiledArtifactSetDigest:   compiledArtifactSetDigest,
		ExpectedCustomerKeyHash:     canonicalExpectedDigest(expectedCustomerKeyHash),
		ExpectedEEPROMDigest:        canonicalExpectedDigest(expectedEEPROMHash),
		ExpectedBootImageDigest:     expectedBootImageDigest,
	}
	if err := compiledRelease.Validate(); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("validate immutable release binding: %w", err)
	}
	return compiledRelease, nil
}

func canonicalExpectedDigest(value string) string {
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + value
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func loadStrictJSON(path string, maximum int64, target any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("JSON path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open regular non-symlink JSON input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("JSON input must be a regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maximum {
		return fmt.Errorf("JSON input exceeds %d bytes", maximum)
	}
	if err := rejectDuplicateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input has a trailing value")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := rejectDuplicateToken(decoder, token, "$"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}

func rejectDuplicateToken(decoder *json.Decoder, token json.Token, path string) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key := keyToken.(string)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%s contains duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := rejectDuplicateToken(decoder, value, path+"."+key); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := rejectDuplicateToken(decoder, value, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
