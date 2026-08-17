package physicalrpi5

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const (
	broadcomVendorID   = "0a5c"
	bcm2712ProductID   = "2712"
	zeroCustomerKey    = "0000000000000000000000000000000000000000000000000000000000000000"
	signedBootMarker   = "KAIBA_SECURE_BOOT_EVIDENCE=pass"
	negativeBootProof  = "KAIBA_NEGATIVE_BOOT_REJECTED"
	rootIntegrityProof = "KAIBA_ROOT_INTEGRITY_REJECTED"
)

var (
	ErrNoRPIBootTarget  = errors.New("no BCM2712 RPIBOOT target is present")
	ErrAmbiguousTargets = errors.New("RPIBOOT target selection is ambiguous")
	ErrUnexpectedTarget = errors.New("RPIBOOT target is not on the fixed lane path")
	ErrMetadataMismatch = errors.New("authoritative RPIBOOT metadata does not match approved state")
	ErrBootEvidence     = errors.New("signed-boot UART evidence does not match the immutable target manifest")
	ErrUARTTestEvidence = errors.New("UART test evidence does not contain exactly one expected proof record")
)

type Dependencies struct {
	Runner  Runner
	FS      FileSystem
	GPIO    GPIO
	UART    UART
	Sleeper Sleeper
}

type Adapter struct {
	mu          sync.Mutex
	config      Config
	runner      Runner
	filesystem  FileSystem
	gpio        GPIO
	uart        UART
	sleeper     Sleeper
	lane        *laneguard.Config
	target      *rpi5.Observation
	directState laneguard.DirectState
	lastUART    []byte
	mode        string
	power       PowerLease
}

func New(config Config, dependencies Dependencies) (*Adapter, error) {
	config.applyDefaults()
	config.ExpectedCustomerKeyHash = normalizeDigest(config.ExpectedCustomerKeyHash)
	config.ExpectedEEPROMHash = normalizeDigest(config.ExpectedEEPROMHash)
	if err := config.Validate(); err != nil {
		return nil, err
	}
	runner := dependencies.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	filesystem := dependencies.FS
	if filesystem == nil {
		filesystem = OSFileSystem{}
	}
	gpio := dependencies.GPIO
	if gpio == nil {
		gpio = ExecGPIO{Binary: config.Paths.GPIOSetBinary}
	}
	uart := dependencies.UART
	if uart == nil {
		uart = FileUART{}
	}
	sleeper := dependencies.Sleeper
	if sleeper == nil {
		sleeper = TimerSleeper{}
	}
	return &Adapter{
		config: config, runner: runner, filesystem: filesystem,
		gpio: gpio, uart: uart, sleeper: sleeper, mode: config.InitialMode,
	}, nil
}

func (adapter *Adapter) Observe(ctx context.Context, lane laneguard.Config) (result laneguard.Observation, resultErr error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if err := adapter.bindLane(lane); err != nil {
		return laneguard.Observation{}, err
	}
	if err := adapter.ensurePower(ctx, lane.PowerGPIO); err != nil {
		return laneguard.Observation{}, err
	}
	defer func() {
		if adapter.power != nil {
			if err := adapter.releasePower(); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	if err := adapter.waitForExpectedTarget(ctx, lane.RPIBootSysfsPath); err != nil {
		return laneguard.Observation{}, err
	}
	candidates, err := adapter.eligibleTargets(ctx, lane.RPIBootSysfsPath)
	if err != nil {
		return laneguard.Observation{}, err
	}
	if len(candidates) != 1 {
		return laneguard.Observation{}, fmt.Errorf("%w: found %d eligible devices", ErrAmbiguousTargets, len(candidates))
	}
	if candidates[0] != lane.RPIBootSysfsPath {
		return laneguard.Observation{}, fmt.Errorf("%w: found %s", ErrUnexpectedTarget, candidates[0])
	}
	if adapter.mode == ModeAuto {
		_, ownedErr := adapter.readbackLocked(ctx, lane, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
		if ownedErr != nil {
			_, freshErr := adapter.readbackLocked(ctx, lane, adapter.config.Paths.FreshReadbackBundle, ModeFresh)
			if freshErr != nil {
				return laneguard.Observation{}, errors.Join(errors.New("auto-reconciliation could not establish fresh or owned state"), ownedErr, freshErr)
			}
		}
	} else {
		bundle := adapter.config.Paths.FreshReadbackBundle
		if adapter.mode == ModeOwned {
			bundle = adapter.config.Paths.OwnedReadbackBundle
		}
		if _, err := adapter.readbackLocked(ctx, lane, bundle, adapter.mode); err != nil {
			return laneguard.Observation{}, err
		}
	}
	if err := adapter.releasePowerAndConfirm(ctx, lane); err != nil {
		return laneguard.Observation{}, err
	}
	return adapter.cachedObservation(lane), nil
}

func (adapter *Adapter) Execute(ctx context.Context, lane laneguard.Config, operation laneguard.Operation) (result laneguard.OperationResult, resultErr error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if err := adapter.bindLane(lane); err != nil {
		return laneguard.OperationResult{}, err
	}
	defer func() {
		if adapter.power != nil {
			if err := adapter.releasePower(); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	switch operation {
	case laneguard.OperationProgramCustomerKeyAndEEPROM:
		result, resultErr = adapter.commitLocked(ctx, lane)
	case laneguard.OperationColdPowerCycle:
		result, resultErr = adapter.coldPowerCycleLocked(ctx, lane)
	case laneguard.OperationVerifySignedBoot:
		resultErr = errors.New("standalone signed-boot verification is unsupported; the bounded cold-power operation captures and verifies it")
	case laneguard.OperationOwnedReadback:
		result, resultErr = adapter.readbackLocked(ctx, lane, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
	case laneguard.OperationTestOwnedRecovery:
		result, resultErr = adapter.readbackLocked(ctx, lane, adapter.config.Paths.OwnedRecoveryBundle, ModeOwned)
	case laneguard.OperationPostRecoveryReadback:
		result, resultErr = adapter.readbackLocked(ctx, lane, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
	case laneguard.OperationTestNegativeBoot:
		result, resultErr = adapter.uartBundleTestLocked(ctx, lane, adapter.config.Paths.NegativeBootBundle, []byte(negativeBootProof), "negative_boot_rejected")
	case laneguard.OperationTestRootIntegrity:
		result, resultErr = adapter.uartBundleTestLocked(ctx, lane, adapter.config.Paths.RootIntegrityBundle, []byte(rootIntegrityProof), "root_integrity_rejected")
	default:
		resultErr = fmt.Errorf("unsupported physical operation %q", operation)
	}
	if resultErr != nil {
		return result, resultErr
	}
	if err := adapter.releasePowerAndConfirm(ctx, lane); err != nil {
		resultErr = errors.Join(resultErr, err)
		return result, resultErr
	}
	return result, nil
}

func (adapter *Adapter) commitLocked(ctx context.Context, lane laneguard.Config) (laneguard.OperationResult, error) {
	if adapter.mode != ModeFresh {
		return laneguard.OperationResult{}, errors.New("fresh ownership commit is forbidden for an owned target")
	}
	output, commandErr := adapter.runRPIBootLocked(ctx, lane, adapter.config.Paths.FreshCommitBundle)
	metadata, extractErr := rpi5.ExtractMetadataObject(output)
	if extractErr != nil {
		if commandErr != nil {
			return laneguard.OperationResult{}, errors.Join(errors.New("fresh commit outcome is ambiguous"), commandErr, extractErr)
		}
		return laneguard.OperationResult{}, fmt.Errorf("extract fresh commit metadata: %w", extractErr)
	}
	observation, err := rpi5.ParseMetadata(metadata)
	if err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("parse fresh commit metadata: %w", err)
	}
	if err := adapter.validateContinuity(observation); err != nil {
		return laneguard.OperationResult{}, err
	}
	if observation.CustomerKeyHash != adapter.config.ExpectedCustomerKeyHash ||
		observation.EEPROMHash != adapter.config.ExpectedEEPROMHash ||
		strings.ToLower(observation.UpstreamFields["EEPROM_UPDATE"]) != "success" ||
		strings.ToLower(observation.UpstreamFields["SECURE_BOOT_PROVISION"]) != "success" {
		return laneguard.OperationResult{}, fmt.Errorf("%w: commit key, EEPROM, or success fields differ", ErrMetadataMismatch)
	}
	adapter.target = &observation
	adapter.mode = ModeOwned
	adapter.directState = directState(observation, "rpiboot")
	detail := "fresh commit metadata and direct postcondition verified"
	if commandErr != nil {
		detail = "fresh commit command reported an error, but complete authoritative metadata verified the postcondition"
	}
	return laneguard.OperationResult{OutputDigest: digestBytes(output), Detail: detail}, nil
}

func (adapter *Adapter) readbackLocked(ctx context.Context, lane laneguard.Config, bundle, mode string) (laneguard.OperationResult, error) {
	output, commandErr := adapter.runRPIBootLocked(ctx, lane, bundle)
	if commandErr != nil {
		return laneguard.OperationResult{}, commandErr
	}
	metadata, err := rpi5.ExtractMetadataObject(output)
	if err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("extract RPIBOOT readback metadata: %w", err)
	}
	observation, err := rpi5.ParseMetadata(metadata)
	if err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("parse RPIBOOT readback metadata: %w", err)
	}
	if err := adapter.validateContinuity(observation); err != nil {
		return laneguard.OperationResult{}, err
	}
	switch mode {
	case ModeFresh:
		if observation.CustomerKeyHash != zeroCustomerKey {
			return laneguard.OperationResult{}, fmt.Errorf("%w: fresh readback has a programmed customer key", ErrMetadataMismatch)
		}
	case ModeOwned:
		if observation.CustomerKeyHash != adapter.config.ExpectedCustomerKeyHash || observation.EEPROMHash != adapter.config.ExpectedEEPROMHash {
			return laneguard.OperationResult{}, fmt.Errorf("%w: owned key or EEPROM digest differs", ErrMetadataMismatch)
		}
	default:
		return laneguard.OperationResult{}, errors.New("invalid readback mode")
	}
	adapter.target = &observation
	adapter.mode = mode
	adapter.directState = directState(observation, "rpiboot")
	return laneguard.OperationResult{OutputDigest: digestBytes(output), Detail: mode + " RPIBOOT readback verified"}, nil
}

func (adapter *Adapter) coldPowerCycleLocked(ctx context.Context, lane laneguard.Config) (laneguard.OperationResult, error) {
	if adapter.target == nil || adapter.mode != ModeOwned {
		return laneguard.OperationResult{}, errors.New("cold power cycle requires an authoritative owned-target readback")
	}
	if err := adapter.releasePower(); err != nil {
		return laneguard.OperationResult{}, err
	}
	if err := adapter.waitForDisappearance(ctx, lane.RPIBootSysfsPath); err != nil {
		return laneguard.OperationResult{}, err
	}
	if err := adapter.sleeper.Sleep(ctx, adapter.config.MinimumColdInterval); err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("maintain minimum cold interval: %w", err)
	}
	marker := []byte(signedBootMarker)
	uartCtx, cancel := context.WithTimeout(ctx, adapter.config.UARTTimeout)
	defer cancel()
	evidence, err := adapter.uart.Capture(uartCtx, lane.UARTPath, marker, adapter.config.MaximumOutputBytes, func() error {
		return adapter.ensurePower(ctx, lane.PowerGPIO)
	})
	if err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("capture signed cold-boot UART evidence: %w", err)
	}
	if err := validateSignedBootEvidence(evidence, adapter.config.ExpectedBootImageDigest); err != nil {
		return laneguard.OperationResult{}, err
	}
	adapter.lastUART = append(adapter.lastUART[:0], evidence...)
	adapter.directState.PowerState = "signed_os"
	return laneguard.OperationResult{OutputDigest: digestBytes(evidence), Detail: "minimum cold interval and signed boot UART evidence verified"}, nil
}

func (adapter *Adapter) uartBundleTestLocked(ctx context.Context, lane laneguard.Config, bundle string, marker []byte, powerState string) (laneguard.OperationResult, error) {
	uartCtx, cancel := context.WithTimeout(ctx, adapter.config.UARTTimeout)
	defer cancel()
	evidence, err := adapter.uart.Capture(uartCtx, lane.UARTPath, marker, adapter.config.MaximumOutputBytes, func() error {
		_, runErr := adapter.runRPIBootLocked(ctx, lane, bundle)
		return runErr
	})
	if err != nil {
		return laneguard.OperationResult{}, fmt.Errorf("capture bounded UART test evidence: %w", err)
	}
	if err := validateExactMarkerEvidence(evidence, string(marker)); err != nil {
		return laneguard.OperationResult{}, err
	}
	adapter.lastUART = append(adapter.lastUART[:0], evidence...)
	adapter.directState.PowerState = powerState
	return laneguard.OperationResult{OutputDigest: digestBytes(evidence), Detail: "UART rejection evidence verified"}, nil
}

func (adapter *Adapter) runRPIBootLocked(ctx context.Context, lane laneguard.Config, bundle string) ([]byte, error) {
	if err := adapter.ensurePower(ctx, lane.PowerGPIO); err != nil {
		return nil, err
	}
	if err := adapter.waitForExpectedTarget(ctx, lane.RPIBootSysfsPath); err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, adapter.config.CommandTimeout)
	defer cancel()
	stdout := &boundedBuffer{maximum: adapter.config.MaximumOutputBytes}
	stderr := &boundedBuffer{maximum: adapter.config.MaximumOutputBytes}
	usbPath := filepath.Base(lane.RPIBootSysfsPath)
	err := adapter.runner.Run(commandCtx, adapter.config.Paths.RPIBootBinary, []string{"-p", usbPath, "-d", bundle}, stdout, stderr)
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("rpiboot output exceeds %d bytes", adapter.config.MaximumOutputBytes)
	}
	if err != nil {
		return append([]byte(nil), stdout.bytes...), fmt.Errorf("rpiboot operation failed: %w", err)
	}
	return append([]byte(nil), stdout.bytes...), nil
}

func (adapter *Adapter) waitForExpectedTarget(ctx context.Context, expectedPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, adapter.config.USBReappearTimeout)
	defer cancel()
	for {
		candidates, err := adapter.eligibleTargets(waitCtx, expectedPath)
		if err != nil {
			return err
		}
		switch {
		case len(candidates) == 1 && candidates[0] == expectedPath:
			return nil
		case len(candidates) == 0:
			if err := adapter.sleeper.Sleep(waitCtx, adapter.config.USBPollInterval); err != nil {
				return errors.Join(ErrNoRPIBootTarget, fmt.Errorf("wait for fixed RPIBOOT target reappearance: %w", err))
			}
		case len(candidates) > 1:
			return fmt.Errorf("%w: found %d eligible devices", ErrAmbiguousTargets, len(candidates))
		default:
			return fmt.Errorf("%w: found %s", ErrUnexpectedTarget, candidates[0])
		}
	}
}

func (adapter *Adapter) waitForDisappearance(ctx context.Context, expectedPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, adapter.config.USBDisappearTimeout)
	defer cancel()
	for {
		candidates, err := adapter.eligibleTargets(waitCtx, expectedPath)
		if err != nil {
			return fmt.Errorf("wait for RPIBOOT target disappearance: %w", err)
		}
		if len(candidates) == 0 {
			return nil
		}
		if len(candidates) != 1 || candidates[0] != expectedPath {
			return ErrUnexpectedTarget
		}
		if err := adapter.sleeper.Sleep(waitCtx, adapter.config.USBPollInterval); err != nil {
			return fmt.Errorf("wait for RPIBOOT target disappearance: %w", err)
		}
	}
}

func (adapter *Adapter) ensurePower(ctx context.Context, descriptor laneguard.GPIODescriptor) error {
	if adapter.power != nil {
		return nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, adapter.config.CommandTimeout)
	defer cancel()
	lease, err := adapter.gpio.AcquirePower(commandCtx, descriptor)
	if err != nil {
		return err
	}
	adapter.power = lease
	return nil
}

func (adapter *Adapter) releasePower() error {
	if adapter.power == nil {
		return nil
	}
	lease := adapter.power
	adapter.power = nil
	if err := lease.Release(); err != nil {
		return fmt.Errorf("release normally-off power relay: %w", err)
	}
	return nil
}

func (adapter *Adapter) releasePowerAndConfirm(ctx context.Context, lane laneguard.Config) error {
	if err := adapter.releasePower(); err != nil {
		return err
	}
	if err := adapter.waitForDisappearance(ctx, lane.RPIBootSysfsPath); err != nil {
		return fmt.Errorf("confirm target disappearance after power release: %w", err)
	}
	if adapter.target != nil {
		adapter.directState.PowerState = "powered_off"
	}
	return nil
}

func (adapter *Adapter) eligibleTargets(ctx context.Context, expectedPath string) ([]string, error) {
	root := filepath.Dir(expectedPath)
	entries, err := adapter.filesystem.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read USB sysfs: %w", err)
	}
	candidates := make([]string, 0, 1)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		base := filepath.Join(root, entry.Name())
		vendor, vendorErr := adapter.filesystem.ReadFile(filepath.Join(base, "idVendor"))
		product, productErr := adapter.filesystem.ReadFile(filepath.Join(base, "idProduct"))
		if vendorErr != nil || productErr != nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(string(vendor))) == broadcomVendorID && strings.ToLower(strings.TrimSpace(string(product))) == bcm2712ProductID {
			candidates = append(candidates, base)
		}
	}
	sort.Strings(candidates)
	return candidates, nil
}

func (adapter *Adapter) bindLane(lane laneguard.Config) error {
	if err := lane.Validate(); err != nil {
		return err
	}
	if adapter.lane == nil {
		copy := lane
		adapter.lane = &copy
		return nil
	}
	if *adapter.lane != lane {
		return errors.New("physical adapter lane configuration changed")
	}
	return nil
}

func (adapter *Adapter) validateContinuity(observation rpi5.Observation) error {
	if adapter.target != nil && adapter.target.TargetFingerprint != observation.TargetFingerprint {
		return fmt.Errorf("%w: metadata fingerprint changed", laneguard.ErrTargetContinuity)
	}
	return nil
}

func (adapter *Adapter) cachedObservation(lane laneguard.Config) laneguard.Observation {
	return laneguard.Observation{
		EligibleTargets: 1, RPIBootSysfsPath: lane.RPIBootSysfsPath,
		TargetFingerprint: adapter.target.TargetFingerprint, State: adapter.directState,
	}
}

func directState(observation rpi5.Observation, powerState string) laneguard.DirectState {
	securityState := "owned"
	if observation.CustomerKeyHash == zeroCustomerKey {
		securityState = "fresh"
	}
	return laneguard.DirectState{
		CustomerKeyHash: "sha256:" + observation.CustomerKeyHash, EEPROMHash: "sha256:" + observation.EEPROMHash,
		SecurityState: securityState, PowerState: powerState,
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateSignedBootEvidence(evidence []byte, expectedDigest string) error {
	var record string
	for _, line := range strings.Split(string(evidence), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, signedBootMarker) {
			continue
		}
		if record != "" {
			return fmt.Errorf("%w: multiple pass records", ErrBootEvidence)
		}
		record = line
	}
	if record == "" {
		return fmt.Errorf("%w: pass record is absent", ErrBootEvidence)
	}
	fields := strings.Fields(record)
	if len(fields) != 6 || fields[0] != signedBootMarker {
		return fmt.Errorf("%w: pass record has an unexpected shape", ErrBootEvidence)
	}
	values := make(map[string]string, 5)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" {
			return fmt.Errorf("%w: malformed pass field", ErrBootEvidence)
		}
		if _, duplicate := values[key]; duplicate {
			return fmt.Errorf("%w: duplicate %s field", ErrBootEvidence, key)
		}
		values[key] = value
	}
	if len(values) != 5 || values["boot_img_sha256"] != expectedDigest ||
		values["root"] != "/dev/mapper/root" || values["rollback"] != "unimplemented" ||
		values["enrollment_ready"] != "false" {
		return fmt.Errorf("%w: digest, root, or policy field differs", ErrBootEvidence)
	}
	signed := values["signed"]
	if len(signed) != 8 || strings.ToLower(signed) != signed {
		return fmt.Errorf("%w: signed field is not canonical 32-bit hexadecimal", ErrBootEvidence)
	}
	signedValue, err := strconv.ParseUint(signed, 16, 32)
	if err != nil || signedValue&8 != 8 {
		return fmt.Errorf("%w: customer-key OTP bit is not set", ErrBootEvidence)
	}
	return nil
}

func validateExactMarkerEvidence(evidence []byte, expected string) error {
	matches := 0
	for _, line := range strings.Split(string(evidence), "\n") {
		if strings.TrimSuffix(line, "\r") == expected {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("%w: found %d exact records", ErrUARTTestEvidence, matches)
	}
	return nil
}

// Close de-energizes the normally-off lane relay. The command also configures
// gpioset with a parent-death signal so an ungraceful process exit fails off.
func (adapter *Adapter) Close() error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.releasePower()
}

type boundedBuffer struct {
	bytes    []byte
	maximum  int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if len(buffer.bytes)+len(value) > buffer.maximum {
		remaining := buffer.maximum - len(buffer.bytes)
		if remaining > 0 {
			buffer.bytes = append(buffer.bytes, value[:remaining]...)
		}
		buffer.overflow = true
		return len(value), io.ErrShortWrite
	}
	buffer.bytes = append(buffer.bytes, value...)
	return len(value), nil
}

var _ laneguard.Hardware = (*Adapter)(nil)
