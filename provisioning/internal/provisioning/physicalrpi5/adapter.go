package physicalrpi5

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const (
	broadcomVendorID   = "0a5c"
	bcm2712ProductID   = "2712"
	zeroCustomerKey    = "0000000000000000000000000000000000000000000000000000000000000000"
	signedBootMarker   = "KAIBA_SECURE_BOOT_EVIDENCE=pass"
	negativeBootProof  = "KAIBA_NEGATIVE_BOOT_REJECTED"
	rootIntegrityProof = "KAIBA_ROOT_INTEGRITY_REJECTED"

	holdBOOTSELInstructions      = "Hold BOOTSEL before target power is applied and keep holding it until a separate release prompt appears."
	releaseBOOTSELInstructions   = "Release BOOTSEL now; do not disconnect target power or the lane USB connection."
	normalBootInstructions       = "Leave BOOTSEL untouched while target power is applied."
	manualDisconnectInstructions = "Disconnect every target power source, including the lane USB cable and the normal Raspberry Pi power supply. Confirm the target power LED is off, then acknowledge."
	manualRPIBootInstructions    = "Keep the normal Raspberry Pi power supply disconnected. Hold BOOTSEL, connect the pre-qualified intact power-capable lane USB path as the target's sole power and data connection, keep BOOTSEL held, then acknowledge. A VBUS-cut data-only cable is not valid for this step."
	manualNormalBootInstructions = "Confirm the lane USB cable is disconnected. Leave BOOTSEL untouched, connect the normal Raspberry Pi power supply, then acknowledge."
)

var (
	ErrNoRPIBootTarget  = errors.New("no BCM2712 RPIBOOT target is present")
	ErrAmbiguousTargets = errors.New("RPIBOOT target selection is ambiguous")
	ErrUnexpectedTarget = errors.New("RPIBOOT target is not on the fixed lane path")
	ErrWrongBootMode    = errors.New("observed boot mode differs from the authorized mode")
	ErrMetadataMismatch = errors.New("authoritative RPIBOOT metadata does not match approved state")
	ErrBootEvidence     = errors.New("signed-boot UART evidence does not match the immutable target manifest")
	ErrUARTTestEvidence = errors.New("UART test evidence does not contain exactly one expected proof record")
	ErrRestartRecovered = errors.New("an interrupted boot transition was recovered before new hardware I/O")
)

// Prompter is the only operator-channel surface the privileged adapter needs.
// operatorprompt.Server satisfies this interface with its Present method.
type Prompter interface {
	Present(context.Context, operatorprompt.Prompt) (operatorprompt.Acknowledgement, error)
}

type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type Dependencies struct {
	Runner   Runner
	FS       FileSystem
	GPIO     GPIO
	UART     UART
	Sleeper  Sleeper
	Journal  laneguard.Journal
	Prompter Prompter
	Clock    Clock
}

type Adapter struct {
	mu          sync.Mutex
	config      Config
	runner      Runner
	filesystem  FileSystem
	gpio        GPIO
	uart        UART
	sleeper     Sleeper
	journal     laneguard.Journal
	prompter    Prompter
	clock       Clock
	lane        *laneguard.Config
	target      *rpi5.Observation
	directState laneguard.DirectState
	lastUART    []byte
	mode        string
	power       PowerLease
	usbPin      USBInstancePin
}

type safeOffProof struct {
	powerOffAt  time.Time
	usbAbsentAt time.Time
	operator    laneguard.OperatorPowerProof
}

func New(config Config, dependencies Dependencies) (*Adapter, error) {
	config.applyDefaults()
	config.ExpectedCustomerKeyHash = normalizeDigest(config.ExpectedCustomerKeyHash)
	config.ExpectedEEPROMHash = normalizeDigest(config.ExpectedEEPROMHash)
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if dependencies.Journal == nil {
		return nil, errors.New("durable lane journal is required")
	}
	if dependencies.Prompter == nil {
		return nil, errors.New("authenticated operator prompter is required")
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
	clock := dependencies.Clock
	if clock == nil {
		clock = wallClock{}
	}
	return &Adapter{
		config: config, runner: runner, filesystem: filesystem, gpio: gpio, uart: uart,
		sleeper: sleeper, journal: dependencies.Journal, prompter: dependencies.Prompter,
		clock: clock, mode: config.InitialMode,
	}, nil
}

func (adapter *Adapter) Observe(ctx context.Context, lane laneguard.Config, action laneguard.HardwareAction) (result laneguard.Observation, resultErr error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if err := adapter.prepareLane(ctx, lane); err != nil {
		return laneguard.Observation{}, err
	}
	if err := adapter.validateAction(lane, action, false); err != nil {
		return laneguard.Observation{}, err
	}
	payload := func(payloadCtx context.Context) (laneguard.OperationResult, error) {
		if adapter.mode == ModeAuto {
			owned, ownedErr := adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
			if ownedErr == nil {
				return owned, nil
			}
			fresh, freshErr := adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, adapter.config.Paths.FreshReadbackBundle, ModeFresh)
			if freshErr != nil {
				return laneguard.OperationResult{}, errors.Join(errors.New("auto-reconciliation could not establish fresh or owned state"), ownedErr, freshErr)
			}
			return fresh, nil
		}
		bundle := adapter.config.Paths.FreshReadbackBundle
		if adapter.mode == ModeOwned {
			bundle = adapter.config.Paths.OwnedReadbackBundle
		}
		return adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, bundle, adapter.mode)
	}
	_, outcome, err := adapter.runBootTransition(ctx, lane, action, payload)
	result.BootTransition = outcome
	if err != nil {
		return result, err
	}
	result = adapter.cachedObservation(lane)
	result.BootTransition = outcome
	return result, nil
}

func (adapter *Adapter) Execute(ctx context.Context, lane laneguard.Config, action laneguard.HardwareAction) (result laneguard.OperationResult, resultErr error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if err := adapter.prepareLane(ctx, lane); err != nil {
		return laneguard.OperationResult{}, err
	}
	if err := adapter.validateAction(lane, action, true); err != nil {
		return laneguard.OperationResult{}, err
	}
	payload := func(payloadCtx context.Context) (laneguard.OperationResult, error) {
		switch action.Operation {
		case laneguard.OperationProgramCustomerKeyAndEEPROM:
			return adapter.commitLocked(payloadCtx, lane, action.TargetFingerprint)
		case laneguard.OperationColdPowerCycle:
			return laneguard.OperationResult{}, errors.New("normal cold-power evidence must be captured by the boot-transition state machine")
		case laneguard.OperationVerifySignedBoot:
			return laneguard.OperationResult{}, errors.New("standalone signed-boot verification is unsupported; the bounded cold-power operation captures and verifies it")
		case laneguard.OperationOwnedReadback:
			return adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
		case laneguard.OperationTestOwnedRecovery:
			return adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, adapter.config.Paths.OwnedRecoveryBundle, ModeOwned)
		case laneguard.OperationPostRecoveryReadback:
			return adapter.readbackLocked(payloadCtx, lane, action.TargetFingerprint, adapter.config.Paths.OwnedReadbackBundle, ModeOwned)
		case laneguard.OperationTestNegativeBoot:
			return adapter.uartBundleTestLocked(payloadCtx, lane, adapter.config.Paths.NegativeBootBundle, []byte(negativeBootProof), "negative_boot_rejected")
		case laneguard.OperationTestRootIntegrity:
			return adapter.uartBundleTestLocked(payloadCtx, lane, adapter.config.Paths.RootIntegrityBundle, []byte(rootIntegrityProof), "root_integrity_rejected")
		default:
			return laneguard.OperationResult{}, fmt.Errorf("unsupported physical operation %q", action.Operation)
		}
	}
	result, outcome, err := adapter.runBootTransition(ctx, lane, action, payload)
	result.BootTransition = outcome
	return result, err
}

func (adapter *Adapter) prepareLane(ctx context.Context, lane laneguard.Config) error {
	if err := adapter.bindLane(lane); err != nil {
		return err
	}
	if err := adapter.recoverIncompleteTransitions(ctx, lane); err != nil {
		return err
	}
	quarantined, err := adapter.journal.HasQuarantinedBootTransition()
	if err != nil {
		return fmt.Errorf("read durable boot-transition quarantine: %w", err)
	}
	if quarantined {
		return laneguard.ErrQuarantined
	}
	return nil
}

func (adapter *Adapter) validateAction(lane laneguard.Config, action laneguard.HardwareAction, execute bool) error {
	if err := action.Validate(); err != nil {
		return err
	}
	if action.StationID != lane.StationID || action.LaneID != lane.LaneID {
		return errors.New("hardware action does not belong to the fixed lane")
	}
	if action.PowerControlMode != lane.PowerControlMode ||
		action.PowerControlMode != laneguard.PowerControlMode(adapter.config.PowerControl) {
		return errors.New("hardware action power control does not match the authorized physical lane")
	}
	if execute {
		if action.Phase != laneguard.HardwarePhaseExecute {
			return errors.New("Execute requires an execute-phase hardware action")
		}
	} else {
		switch action.Phase {
		case laneguard.HardwarePhasePreObservation, laneguard.HardwarePhasePostObservation, laneguard.HardwarePhaseReconciliation:
		default:
			return errors.New("Observe requires an observation-phase hardware action")
		}
	}
	return nil
}

func (adapter *Adapter) runBootTransition(
	ctx context.Context,
	lane laneguard.Config,
	action laneguard.HardwareAction,
	payload func(context.Context) (laneguard.OperationResult, error),
) (laneguard.OperationResult, laneguard.BootTransitionOutcome, error) {
	startedAt := adapter.now()
	initialSafeOff, err := adapter.establishInitialSafeOff(ctx, lane, action)
	if err != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, fmt.Errorf("establish initial safe-off state: %w", err)
	}
	coldEndsAt := initialSafeOff.usbAbsentAt.Add(adapter.config.MinimumColdInterval)
	kind := operatorprompt.KindHoldBOOTSEL
	instructions := holdBOOTSELInstructions
	if action.RequestedBootMode == laneguard.BootModeNormal {
		kind = operatorprompt.KindNormalNoAction
		instructions = normalBootInstructions
	}
	if adapter.config.PowerControl == PowerControlManual {
		kind = operatorprompt.KindConnectRPIBootPower
		instructions = manualRPIBootInstructions
		if action.RequestedBootMode == laneguard.BootModeNormal {
			kind = operatorprompt.KindConnectNormalPower
			instructions = manualNormalBootInstructions
		}
	}
	prompt, err := adapter.newPrompt(action, kind, instructions, coldEndsAt.Add(adapter.config.OperatorPromptTimeout))
	if err != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, err
	}
	transition, err := adapter.journal.BeginBootTransition(laneguard.BeginBootTransitionRequest{
		PowerControlMode: laneguard.PowerControlMode(adapter.config.PowerControl), InitialPowerOffProof: initialSafeOff.operator,
		Action: action, StartedAt: startedAt, RecordedAt: adapter.atLeast(initialSafeOff.usbAbsentAt),
		PowerOffObservedAt: initialSafeOff.powerOffAt, USBAbsentObservedAt: initialSafeOff.usbAbsentAt, ColdIntervalEndsAt: coldEndsAt,
		PromptID: prompt.ID, PromptDigest: prompt.Digest, PromptExpiresAt: prompt.ExpiresAt,
	})
	if err != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, fmt.Errorf("durably begin boot transition: %w", err)
	}
	if err := adapter.sleeper.Sleep(ctx, adapter.config.MinimumColdInterval); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureInterrupted, fmt.Errorf("maintain minimum cold interval: %w", err))
	}
	transition.Status = laneguard.BootTransitionAwaitingOperator
	transition.UpdatedAt = adapter.atLeast(transition.ColdIntervalEndsAt)
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist operator-ready transition: %w", err))
	}
	// In manual normal-boot mode the UART and wrong-mode watcher must be armed
	// before the operator connects the normal power supply. The transition
	// therefore remains durably awaiting the already-bound prompt until the
	// capture trigger presents it.
	if adapter.config.PowerControl == PowerControlManual && action.RequestedBootMode == laneguard.BootModeNormal {
		return adapter.runNormalTransition(ctx, lane, transition, prompt)
	}
	acknowledged, failure, promptErr := adapter.acknowledgePowerPrompt(ctx, transition, prompt)
	if promptErr != nil {
		return adapter.failTransition(ctx, lane, acknowledged, failure, promptErr)
	}
	transition = acknowledged
	if action.RequestedBootMode == laneguard.BootModeNormal {
		return adapter.runNormalTransition(ctx, lane, transition, prompt)
	}
	return adapter.runRPIBootTransition(ctx, lane, transition, payload)
}

func (adapter *Adapter) acknowledgePowerPrompt(
	ctx context.Context,
	transition laneguard.BootTransition,
	prompt operatorprompt.Prompt,
) (laneguard.BootTransition, laneguard.BootTransitionFailure, error) {
	acknowledgement, err := adapter.prompter.Present(ctx, prompt)
	if err != nil {
		failure := laneguard.BootTransitionFailureOperatorRejected
		if errors.Is(err, operatorprompt.ErrPromptExpired) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			failure = laneguard.BootTransitionFailureOperatorTimeout
		}
		if ctx.Err() != nil {
			failure = laneguard.BootTransitionFailureInterrupted
		}
		return transition, failure, fmt.Errorf("obtain operator power acknowledgement: %w", err)
	}
	if err := validatePromptAcknowledgement(prompt, acknowledgement, transition.ColdIntervalEndsAt); err != nil {
		return transition, laneguard.BootTransitionFailureOperatorRejected, err
	}
	transition.Status = laneguard.BootTransitionOperatorAcknowledged
	transition.Operator = acknowledgement.Peer
	transition.OperatorAcknowledgedAt = acknowledgement.AcknowledgedAt.UTC()
	transition.UpdatedAt = adapter.atLeast(transition.OperatorAcknowledgedAt)
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist operator power acknowledgement: %w", err)
	}
	return transition, laneguard.BootTransitionFailureNone, nil
}

func (adapter *Adapter) runRPIBootTransition(
	ctx context.Context,
	lane laneguard.Config,
	transition laneguard.BootTransition,
	payload func(context.Context) (laneguard.OperationResult, error),
) (laneguard.OperationResult, laneguard.BootTransitionOutcome, error) {
	if adapter.config.PowerControl == PowerControlRelay {
		if err := adapter.ensurePower(ctx, lane.PowerGPIO); err != nil {
			return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("apply target power: %w", err))
		}
	}
	transition.Status = laneguard.BootTransitionPowerEstablished
	transition.PowerEstablishedAt = adapter.powerEstablishedAt(transition)
	transition.UpdatedAt = adapter.atLeast(transition.UpdatedAt, transition.PowerEstablishedAt)
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist power application: %w", err))
	}
	if err := adapter.waitForExpectedTarget(ctx, lane.RPIBootSysfsPath); err != nil {
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(err, ErrNoRPIBootTarget) {
			failure = laneguard.BootTransitionFailureWrongMode
		} else if errors.Is(err, ErrUnexpectedTarget) || errors.Is(err, ErrAmbiguousTargets) {
			failure = laneguard.BootTransitionFailureTargetContinuity
		}
		if ctx.Err() != nil {
			failure = laneguard.BootTransitionFailureInterrupted
		}
		return adapter.failTransition(ctx, lane, transition, failure, err)
	}
	modeObservedAt := adapter.atLeast(transition.PowerEstablishedAt)
	releasePrompt, err := adapter.newPrompt(transition.Action, operatorprompt.KindReleaseBOOTSEL, releaseBOOTSELInstructions, modeObservedAt.Add(adapter.config.OperatorPromptTimeout))
	if err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, err)
	}
	transition.Status = laneguard.BootTransitionModeObserved
	transition.ModeObservedAt = modeObservedAt
	transition.ObservedMode = laneguard.BootModeRPIBoot
	transition.RPIBootSysfsPath = lane.RPIBootSysfsPath
	transition.RPIBootEligibleTargets = 1
	transition.RPIBootObservationMethod = laneguard.RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = adapter.config.USBPollInterval
	transition.ReleasePromptID = releasePrompt.ID
	transition.ReleasePromptDigest = releasePrompt.Digest
	transition.ReleasePromptExpiresAt = releasePrompt.ExpiresAt
	transition.UpdatedAt = modeObservedAt
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist observed RPIBOOT mode and release prompt: %w", err))
	}
	releaseAcknowledgement, err := adapter.prompter.Present(ctx, releasePrompt)
	if err != nil {
		failure := laneguard.BootTransitionFailureOperatorRejected
		if errors.Is(err, operatorprompt.ErrPromptExpired) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			failure = laneguard.BootTransitionFailureOperatorTimeout
		}
		if ctx.Err() != nil {
			failure = laneguard.BootTransitionFailureInterrupted
		}
		return adapter.failTransition(ctx, lane, transition, failure, fmt.Errorf("obtain BOOTSEL release acknowledgement: %w", err))
	}
	if err := validatePromptAcknowledgement(releasePrompt, releaseAcknowledgement, transition.ModeObservedAt); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureOperatorRejected, err)
	}
	transition.Status = laneguard.BootTransitionOperatorReleased
	transition.ReleaseOperator = releaseAcknowledgement.Peer
	transition.OperatorReleasedAt = releaseAcknowledgement.AcknowledgedAt.UTC()
	transition.UpdatedAt = adapter.atLeast(transition.OperatorReleasedAt)
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist BOOTSEL release acknowledgement: %w", err))
	}
	if err := adapter.requireExactTarget(ctx, lane.RPIBootSysfsPath); err != nil {
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(err, ErrNoRPIBootTarget) || errors.Is(err, ErrUnexpectedTarget) || errors.Is(err, ErrAmbiguousTargets) {
			failure = laneguard.BootTransitionFailureTargetContinuity
		}
		return adapter.failTransition(ctx, lane, transition, failure, fmt.Errorf("recheck fixed RPIBOOT target after release: %w", err))
	}
	if transition.Action.Phase == laneguard.HardwarePhaseExecute {
		pin, err := adapter.pinRPIBootInstance(lane.RPIBootSysfsPath)
		if err != nil {
			return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureTargetContinuity, err)
		}
		adapter.usbPin = pin
		defer func() {
			adapter.usbPin = nil
			_ = pin.Close()
		}()
		if err := adapter.preflightRPIBootIdentityLocked(ctx, lane, transition.Action.TargetFingerprint); err != nil {
			failure := laneguard.BootTransitionFailureHardware
			if errors.Is(err, laneguard.ErrTargetContinuity) || errors.Is(err, ErrNoRPIBootTarget) ||
				errors.Is(err, ErrUnexpectedTarget) || errors.Is(err, ErrAmbiguousTargets) {
				failure = laneguard.BootTransitionFailureTargetContinuity
			}
			if ctx.Err() != nil {
				failure = laneguard.BootTransitionFailureInterrupted
			}
			return adapter.failTransition(ctx, lane, transition, failure, err)
		}
	}
	result, err := payload(ctx)
	if err != nil {
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(err, laneguard.ErrTargetContinuity) || errors.Is(err, ErrNoRPIBootTarget) || errors.Is(err, ErrUnexpectedTarget) || errors.Is(err, ErrAmbiguousTargets) {
			failure = laneguard.BootTransitionFailureTargetContinuity
		}
		if ctx.Err() != nil {
			failure = laneguard.BootTransitionFailureInterrupted
		}
		return adapter.failTransition(ctx, lane, transition, failure, err)
	}
	outcome, err := adapter.completeTransition(ctx, lane, transition)
	if err != nil {
		return result, outcome, err
	}
	result.BootTransition = outcome
	return result, outcome, nil
}

func (adapter *Adapter) runNormalTransition(
	ctx context.Context,
	lane laneguard.Config,
	transition laneguard.BootTransition,
	prompt operatorprompt.Prompt,
) (laneguard.OperationResult, laneguard.BootTransitionOutcome, error) {
	if adapter.target == nil || adapter.mode != ModeOwned {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, errors.New("normal cold-power boot requires an authoritative owned-target readback"))
	}
	uartCtx, cancelUART := context.WithCancel(ctx)
	defer cancelUART()
	var watcher *normalModeWatcher
	var powerPromptErr error
	powerPromptFailure := laneguard.BootTransitionFailureNone
	evidence, captureErr := adapter.uart.Capture(uartCtx, lane.UARTPath, []byte(signedBootMarker), adapter.config.MaximumOutputBytes, adapter.config.UARTTimeout, func() error {
		var err error
		watcher, err = adapter.startNormalModeWatcher(uartCtx, lane.RPIBootSysfsPath, cancelUART)
		if err != nil {
			return err
		}
		if adapter.config.PowerControl == PowerControlManual {
			transition, powerPromptFailure, powerPromptErr = adapter.acknowledgePowerPrompt(uartCtx, transition, prompt)
			if powerPromptErr != nil {
				return powerPromptErr
			}
		} else if err := adapter.ensurePower(uartCtx, lane.PowerGPIO); err != nil {
			return fmt.Errorf("apply target power: %w", err)
		}
		transition.Status = laneguard.BootTransitionPowerEstablished
		transition.PowerEstablishedAt = adapter.powerEstablishedAt(transition)
		transition.UpdatedAt = adapter.atLeast(transition.UpdatedAt, transition.PowerEstablishedAt)
		if err := adapter.journal.PutBootTransition(transition); err != nil {
			return fmt.Errorf("persist power application: %w", err)
		}
		return nil
	})
	if watcher == nil {
		if powerPromptErr != nil {
			return adapter.failTransition(ctx, lane, transition, powerPromptFailure, powerPromptErr)
		}
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(captureErr, ErrWrongBootMode) {
			failure = laneguard.BootTransitionFailureWrongMode
		}
		return adapter.failTransition(ctx, lane, transition, failure, fmt.Errorf("arm normal-boot UART and RPIBOOT watcher: %w", captureErr))
	}
	if captureErr == nil {
		captureErr = validateSignedBootEvidence(evidence, adapter.config.ExpectedBootImageDigest)
	}
	notObservedThrough, watcherErr := watcher.stopAndRecheck(ctx)
	if watcherErr != nil {
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(watcherErr, ErrWrongBootMode) {
			failure = laneguard.BootTransitionFailureWrongMode
		}
		return adapter.failTransition(ctx, lane, transition, failure, errors.Join(watcherErr, captureErr))
	}
	if powerPromptErr != nil {
		return adapter.failTransition(ctx, lane, transition, powerPromptFailure, powerPromptErr)
	}
	if captureErr != nil {
		failure := laneguard.BootTransitionFailureHardware
		if errors.Is(captureErr, context.DeadlineExceeded) && ctx.Err() == nil {
			failure = laneguard.BootTransitionFailureModeTimeout
		}
		if ctx.Err() != nil {
			failure = laneguard.BootTransitionFailureInterrupted
		}
		return adapter.failTransition(ctx, lane, transition, failure, fmt.Errorf("capture signed cold-boot UART evidence: %w", captureErr))
	}
	modeObservedAt := notObservedThrough
	if modeObservedAt.Before(transition.PowerEstablishedAt) {
		modeObservedAt = transition.PowerEstablishedAt
		notObservedThrough = modeObservedAt
	}
	transition.Status = laneguard.BootTransitionModeObserved
	transition.ModeObservedAt = modeObservedAt
	transition.ObservedMode = laneguard.BootModeNormal
	transition.RPIBootSysfsPath = lane.RPIBootSysfsPath
	transition.RPIBootEligibleTargets = 0
	transition.UARTPath = lane.UARTPath
	transition.UARTOutputDigest = digestBytes(evidence)
	transition.RPIBootObservationMethod = laneguard.RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = adapter.config.USBPollInterval
	transition.RPIBootNotObservedThrough = notObservedThrough
	transition.UpdatedAt = modeObservedAt
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		return adapter.failTransition(ctx, lane, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist normal-boot mode evidence: %w", err))
	}
	adapter.lastUART = append(adapter.lastUART[:0], evidence...)
	adapter.directState.PowerState = "signed_os"
	result := laneguard.OperationResult{OutputDigest: digestBytes(evidence), Detail: "minimum cold interval and signed boot UART evidence verified"}
	outcome, err := adapter.completeTransition(ctx, lane, transition)
	if err != nil {
		return result, outcome, err
	}
	result.BootTransition = outcome
	return result, outcome, nil
}

type normalModeWatcher struct {
	adapter      *Adapter
	expectedPath string
	cancel       context.CancelFunc
	done         chan struct{}

	mu      sync.Mutex
	err     error
	through time.Time
}

func (adapter *Adapter) startNormalModeWatcher(ctx context.Context, expectedPath string, cancelUART context.CancelFunc) (*normalModeWatcher, error) {
	if err := adapter.requireNoTargets(ctx, expectedPath); err != nil {
		return nil, errors.Join(ErrWrongBootMode, err)
	}
	watchCtx, cancel := context.WithCancel(ctx)
	watcher := &normalModeWatcher{
		adapter: adapter, expectedPath: expectedPath, cancel: cancel, done: make(chan struct{}),
		through: adapter.now(),
	}
	armed := make(chan struct{})
	go func() {
		defer close(watcher.done)
		close(armed)
		for {
			if err := adapter.sleeper.Sleep(watchCtx, adapter.config.USBPollInterval); err != nil {
				return
			}
			if err := adapter.requireNoTargets(watchCtx, expectedPath); err != nil {
				watcher.mu.Lock()
				if watcher.err == nil {
					watcher.err = err
				}
				watcher.mu.Unlock()
				cancelUART()
				return
			}
			watcher.mu.Lock()
			watcher.through = adapter.now()
			watcher.mu.Unlock()
		}
	}()
	<-armed
	return watcher, nil
}

func (watcher *normalModeWatcher) stopAndRecheck(ctx context.Context) (time.Time, error) {
	checkCtx, checkCancel := context.WithTimeout(context.WithoutCancel(ctx), watcher.adapter.config.CleanupTimeout)
	defer checkCancel()
	checkErr := watcher.adapter.requireNoTargets(checkCtx, watcher.expectedPath)
	checkedAt := watcher.adapter.now()
	watcher.cancel()
	<-watcher.done
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	if checkErr != nil && watcher.err == nil {
		watcher.err = checkErr
	}
	if watcher.err == nil && checkedAt.After(watcher.through) {
		watcher.through = checkedAt
	}
	return watcher.through, watcher.err
}

func (adapter *Adapter) recoverIncompleteTransitions(ctx context.Context, lane laneguard.Config) error {
	incomplete, err := adapter.journal.IncompleteBootTransitions()
	if err != nil {
		return fmt.Errorf("read incomplete boot transitions: %w", err)
	}
	if len(incomplete) == 0 {
		return nil
	}
	for _, transition := range incomplete {
		configuredMode := laneguard.PowerControlMode(adapter.config.PowerControl)
		if transition.PowerControlMode != configuredMode {
			terminal := transition
			terminal.Status = laneguard.BootTransitionQuarantined
			terminal.Failure = laneguard.BootTransitionFailureSafeOffUnproven
			terminal.FinalSafeOffProof = laneguard.OperatorPowerProof{}
			terminal.SafeOffObservedAt = time.Time{}
			terminal.UpdatedAt = adapter.atLeast(transition.UpdatedAt)
			mismatchErr := fmt.Errorf(
				"interrupted transition power-control mode %q differs from configured mode %q; no recovery actuator was used",
				transition.PowerControlMode, configuredMode,
			)
			if err := adapter.journal.PutBootTransition(terminal); err != nil {
				return errors.Join(ErrRestartRecovered, mismatchErr, fmt.Errorf("quarantine mismatched interrupted transition %q: %w", transition.Key, err))
			}
			return errors.Join(ErrRestartRecovered, mismatchErr)
		}
		proof, safeErr := adapter.proveSafeOff(ctx, lane, transition.Action, transition.PowerControlMode)
		terminal := transition
		terminal.FinalSafeOffProof = proof.operator
		terminal.UpdatedAt = adapter.atLeast(transition.UpdatedAt, proof.usbAbsentAt)
		if safeErr != nil {
			terminal.Status = laneguard.BootTransitionQuarantined
			terminal.Failure = laneguard.BootTransitionFailureSafeOffUnproven
			terminal.SafeOffObservedAt = time.Time{}
		} else {
			terminal.Status = laneguard.BootTransitionInterruptedSafeOff
			terminal.Failure = laneguard.BootTransitionFailureInterrupted
			terminal.SafeOffObservedAt = terminal.UpdatedAt
		}
		if err := adapter.journal.PutBootTransition(terminal); err != nil {
			return errors.Join(ErrRestartRecovered, safeErr, fmt.Errorf("terminalize interrupted transition %q: %w", transition.Key, err))
		}
		if safeErr != nil {
			return errors.Join(ErrRestartRecovered, errors.New("restart recovery quarantined the lane because safe-off was not proven"), safeErr)
		}
	}
	return nil
}

func (adapter *Adapter) failTransition(
	ctx context.Context,
	lane laneguard.Config,
	transition laneguard.BootTransition,
	failure laneguard.BootTransitionFailure,
	cause error,
) (laneguard.OperationResult, laneguard.BootTransitionOutcome, error) {
	proof, safeErr := adapter.proveSafeOff(ctx, lane, transition.Action, transition.PowerControlMode)
	transition.FinalSafeOffProof = proof.operator
	return adapter.terminalizeTransition(ctx, transition, failure, cause, proof.usbAbsentAt, safeErr)
}

func (adapter *Adapter) terminalizeTransition(
	ctx context.Context,
	transition laneguard.BootTransition,
	failure laneguard.BootTransitionFailure,
	cause error,
	safeOffAt time.Time,
	safeErr error,
) (laneguard.OperationResult, laneguard.BootTransitionOutcome, error) {
	stored, exists, readErr := adapter.journal.GetBootTransition(transition.Key)
	if readErr != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(cause, safeErr, fmt.Errorf("reload durable boot transition for terminalization: %w", readErr))
	}
	if !exists {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(cause, safeErr, errors.New("durable boot transition disappeared before terminalization"))
	}
	if stored.IsTerminal() {
		outcome, outcomeErr := stored.Outcome()
		if outcomeErr != nil {
			return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(
				cause, safeErr, fmt.Errorf("derive outcome from already-persisted terminal boot transition: %w", outcomeErr),
			)
		}
		return laneguard.OperationResult{BootTransition: outcome}, outcome, errors.Join(cause, safeErr)
	}
	progress, mergeErr := laneguard.MergeBootTransitionProgress(stored, transition)
	if mergeErr != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(
			cause, safeErr, fmt.Errorf("merge locally observed boot-transition progress; durable record remains incomplete for restart recovery: %w", mergeErr),
		)
	}
	terminal := progress
	terminal.FinalSafeOffProof = transition.FinalSafeOffProof
	terminal.UpdatedAt = adapter.atLeast(stored.UpdatedAt, progress.UpdatedAt, safeOffAt)
	if safeErr != nil {
		terminal.Status = laneguard.BootTransitionQuarantined
		terminal.Failure = laneguard.BootTransitionFailureSafeOffUnproven
		terminal.SafeOffObservedAt = time.Time{}
	} else {
		terminal.SafeOffObservedAt = terminal.UpdatedAt
		if failure == laneguard.BootTransitionFailureInterrupted || ctx.Err() != nil {
			terminal.Status = laneguard.BootTransitionInterruptedSafeOff
			terminal.Failure = laneguard.BootTransitionFailureInterrupted
		} else {
			terminal.Status = laneguard.BootTransitionAbortedSafeOff
			terminal.Failure = failure
		}
	}
	if err := adapter.journal.PutBootTransition(terminal); err != nil {
		persistErr := fmt.Errorf("persist terminal boot transition: %w", err)
		outcome, reloadErr := adapter.reloadDurableOutcome(terminal.Key)
		if reloadErr == nil {
			return laneguard.OperationResult{BootTransition: outcome}, outcome, errors.Join(cause, safeErr, persistErr)
		}
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(
			cause, safeErr, persistErr,
			fmt.Errorf("durable record remains incomplete for restart recovery: %w", reloadErr),
		)
	}
	outcome, err := adapter.reloadDurableOutcome(terminal.Key)
	if err != nil {
		return laneguard.OperationResult{}, laneguard.BootTransitionOutcome{}, errors.Join(cause, safeErr, err)
	}
	return laneguard.OperationResult{BootTransition: outcome}, outcome, errors.Join(cause, safeErr)
}

func (adapter *Adapter) completeTransition(ctx context.Context, lane laneguard.Config, transition laneguard.BootTransition) (laneguard.BootTransitionOutcome, error) {
	proof, safeErr := adapter.proveSafeOff(ctx, lane, transition.Action, transition.PowerControlMode)
	transition.FinalSafeOffProof = proof.operator
	if safeErr != nil {
		_, outcome, err := adapter.terminalizeTransition(ctx, transition, laneguard.BootTransitionFailureHardware, errors.New("prove final safe-off state"), proof.usbAbsentAt, safeErr)
		return outcome, err
	}
	transition.Status = laneguard.BootTransitionCompleted
	transition.SafeOffObservedAt = adapter.atLeast(transition.UpdatedAt, proof.usbAbsentAt)
	transition.CompletedAt = adapter.atLeast(transition.SafeOffObservedAt)
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		_, outcome, terminalErr := adapter.terminalizeTransition(ctx, transition, laneguard.BootTransitionFailureHardware, err, transition.SafeOffObservedAt, nil)
		return outcome, terminalErr
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		_, outcome, terminalErr := adapter.terminalizeTransition(ctx, transition, laneguard.BootTransitionFailureHardware, err, transition.SafeOffObservedAt, nil)
		return outcome, terminalErr
	}
	if err := adapter.journal.PutBootTransition(transition); err != nil {
		_, outcome, terminalErr := adapter.terminalizeTransition(ctx, transition, laneguard.BootTransitionFailureHardware, fmt.Errorf("persist completed boot transition: %w", err), transition.SafeOffObservedAt, nil)
		return outcome, terminalErr
	}
	outcome, err := adapter.reloadDurableOutcome(transition.Key)
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	return outcome, nil
}

func (adapter *Adapter) establishInitialSafeOff(
	ctx context.Context,
	lane laneguard.Config,
	action laneguard.HardwareAction,
) (safeOffProof, error) {
	if adapter.config.PowerControl == PowerControlManual {
		return adapter.manualSafeOff(ctx, lane, action)
	}
	return adapter.relaySafeOff(ctx, lane)
}

func (adapter *Adapter) proveSafeOff(
	ctx context.Context,
	lane laneguard.Config,
	action laneguard.HardwareAction,
	mode laneguard.PowerControlMode,
) (safeOffProof, error) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), adapter.config.CleanupTimeout)
	defer cancel()
	if mode == laneguard.PowerControlManual {
		return adapter.manualSafeOff(cleanupCtx, lane, action)
	}
	if mode != laneguard.PowerControlRelay {
		return safeOffProof{}, errors.New("cannot establish safe-off for an unknown power-control mode")
	}
	return adapter.relaySafeOff(cleanupCtx, lane)
}

func (adapter *Adapter) relaySafeOff(ctx context.Context, lane laneguard.Config) (safeOffProof, error) {
	releaseErr := adapter.releasePower()
	powerOffAt := adapter.now()
	disappearanceErr := adapter.waitForDisappearance(ctx, lane.RPIBootSysfsPath)
	if disappearanceErr != nil {
		disappearanceErr = fmt.Errorf("confirm USB absence after relay release: %w", disappearanceErr)
	}
	usbAbsentAt := adapter.atLeast(powerOffAt)
	if releaseErr == nil && disappearanceErr == nil && adapter.target != nil {
		adapter.directState.PowerState = "powered_off"
	}
	return safeOffProof{powerOffAt: powerOffAt, usbAbsentAt: usbAbsentAt}, errors.Join(releaseErr, disappearanceErr)
}

func (adapter *Adapter) manualSafeOff(
	ctx context.Context,
	lane laneguard.Config,
	action laneguard.HardwareAction,
) (safeOffProof, error) {
	promptStartedAt := adapter.now()
	promptExpiresAt := promptStartedAt.Add(adapter.config.OperatorPromptTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(promptExpiresAt) {
		promptExpiresAt = deadline.UTC()
	}
	if !promptExpiresAt.After(promptStartedAt) {
		return safeOffProof{}, context.DeadlineExceeded
	}
	prompt, err := adapter.newPrompt(
		action,
		operatorprompt.KindDisconnectPower,
		manualDisconnectInstructions,
		promptExpiresAt,
	)
	if err != nil {
		return safeOffProof{}, err
	}
	acknowledgement, err := adapter.prompter.Present(ctx, prompt)
	if err != nil {
		return safeOffProof{}, fmt.Errorf("obtain operator power-disconnection acknowledgement: %w", err)
	}
	if err := validatePromptAcknowledgement(prompt, acknowledgement, promptStartedAt); err != nil {
		return safeOffProof{}, err
	}
	proof := safeOffProof{
		powerOffAt: acknowledgement.AcknowledgedAt.UTC(),
		operator: laneguard.OperatorPowerProof{
			PromptID: prompt.ID, PromptDigest: prompt.Digest, PromptExpiresAt: prompt.ExpiresAt,
			Operator: acknowledgement.Peer, AcknowledgedAt: acknowledgement.AcknowledgedAt.UTC(),
		},
	}
	if err := adapter.waitForDisappearance(ctx, lane.RPIBootSysfsPath); err != nil {
		return proof, fmt.Errorf("confirm RPIBOOT USB absence after manual power-off acknowledgement: %w", err)
	}
	proof.usbAbsentAt = adapter.atLeast(proof.powerOffAt)
	if adapter.target != nil {
		adapter.directState.PowerState = "powered_off"
	}
	return proof, nil
}

func (adapter *Adapter) reloadDurableOutcome(key string) (laneguard.BootTransitionOutcome, error) {
	durable, exists, err := adapter.journal.GetBootTransition(key)
	if err != nil {
		return laneguard.BootTransitionOutcome{}, fmt.Errorf("reload terminal boot transition: %w", err)
	}
	if !exists || durable.Key != key {
		return laneguard.BootTransitionOutcome{}, errors.New("terminal boot transition was not durably readable by its exact key")
	}
	outcome, err := durable.Outcome()
	if err != nil {
		return laneguard.BootTransitionOutcome{}, fmt.Errorf("derive outcome from reloaded terminal boot transition: %w", err)
	}
	return outcome, nil
}

func (adapter *Adapter) commitLocked(ctx context.Context, lane laneguard.Config, expectedFingerprint string) (laneguard.OperationResult, error) {
	if adapter.mode != ModeFresh {
		return laneguard.OperationResult{}, errors.New("fresh ownership commit is forbidden for an owned target")
	}
	output, commandErr := adapter.runRPIBootPayloadLocked(ctx, lane, adapter.config.Paths.FreshCommitBundle)
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
	if err := adapter.validateContinuity(observation, expectedFingerprint); err != nil {
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
	attestation := laneguard.CommitAttestation{
		SchemaVersion:             laneguard.CommitAttestationSchemaVersion,
		TargetFingerprint:         observation.TargetFingerprint,
		CustomerKeyHash:           "sha256:" + observation.CustomerKeyHash,
		EEPROMHash:                "sha256:" + observation.EEPROMHash,
		EEPROMUpdateResult:        strings.ToLower(observation.UpstreamFields["EEPROM_UPDATE"]),
		SecureBootProvisionResult: strings.ToLower(observation.UpstreamFields["SECURE_BOOT_PROVISION"]),
	}
	detail := "fresh commit metadata and direct postcondition verified"
	if commandErr != nil {
		detail = "fresh commit command reported an error, but complete authoritative metadata verified the postcondition"
	}
	return laneguard.OperationResult{OutputDigest: digestBytes(output), Detail: detail, CommitAttestation: attestation}, nil
}

func (adapter *Adapter) readbackLocked(ctx context.Context, lane laneguard.Config, expectedFingerprint, bundle, mode string) (laneguard.OperationResult, error) {
	output, commandErr := adapter.runRPIBootPayloadLocked(ctx, lane, bundle)
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
	if err := adapter.validateContinuity(observation, expectedFingerprint); err != nil {
		return laneguard.OperationResult{}, err
	}
	switch mode {
	case ModeFresh:
		if observation.CustomerKeyHash != zeroCustomerKey {
			return laneguard.OperationResult{}, fmt.Errorf("%w: fresh readback has a programmed customer key", ErrMetadataMismatch)
		}
	case ModeOwned:
		if observation.CustomerKeyHash != adapter.config.ExpectedCustomerKeyHash ||
			(observation.EEPROMHash != "" && observation.EEPROMHash != adapter.config.ExpectedEEPROMHash) {
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

// preflightRPIBootIdentityLocked performs an immutable read-only readback
// immediately before an execute payload. It intentionally validates into a
// local value and never updates adapter mode, cached target, or direct state,
// so a mismatch cannot be hidden by adopting the replacement as current.
func (adapter *Adapter) preflightRPIBootIdentityLocked(ctx context.Context, lane laneguard.Config, expectedFingerprint string) error {
	bundle := adapter.config.Paths.FreshReadbackBundle
	mode := ModeFresh
	if adapter.mode == ModeOwned {
		bundle = adapter.config.Paths.OwnedReadbackBundle
		mode = ModeOwned
	} else if adapter.mode != ModeFresh {
		return errors.New("RPIBOOT identity preflight has no valid adapter mode")
	}
	output, err := adapter.runRPIBootPayloadLocked(ctx, lane, bundle)
	if err != nil {
		return fmt.Errorf("run bounded %s identity preflight: %w", mode, err)
	}
	metadata, err := rpi5.ExtractMetadataObject(output)
	if err != nil {
		return fmt.Errorf("extract %s identity preflight metadata: %w", mode, err)
	}
	observation, err := rpi5.ParseMetadata(metadata)
	if err != nil {
		return fmt.Errorf("parse %s identity preflight metadata: %w", mode, err)
	}
	if err := adapter.validateContinuity(observation, expectedFingerprint); err != nil {
		return fmt.Errorf("%s identity preflight: %w", mode, err)
	}
	if mode == ModeFresh && observation.CustomerKeyHash != zeroCustomerKey {
		return fmt.Errorf("%w: fresh identity preflight observed a programmed customer key", laneguard.ErrTargetContinuity)
	}
	if mode == ModeOwned && (observation.CustomerKeyHash != adapter.config.ExpectedCustomerKeyHash ||
		(observation.EEPROMHash != "" && observation.EEPROMHash != adapter.config.ExpectedEEPROMHash)) {
		return fmt.Errorf("%w: owned identity preflight key or EEPROM digest differs", laneguard.ErrTargetContinuity)
	}
	return nil
}

func (adapter *Adapter) uartBundleTestLocked(ctx context.Context, lane laneguard.Config, bundle string, marker []byte, powerState string) (laneguard.OperationResult, error) {
	evidence, err := adapter.uart.Capture(ctx, lane.UARTPath, marker, adapter.config.MaximumOutputBytes, adapter.config.UARTTimeout, func() error {
		_, runErr := adapter.runRPIBootPayloadLocked(ctx, lane, bundle)
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

// runRPIBootPayloadLocked performs no power or boot-mode selection. The
// durable transition has already proved exact target selection and BOOTSEL
// release before any payload helper is reached.
func (adapter *Adapter) runRPIBootPayloadLocked(ctx context.Context, lane laneguard.Config, bundle string) ([]byte, error) {
	switch adapter.config.PowerControl {
	case PowerControlRelay:
		if adapter.power == nil {
			return nil, errors.New("relay-backed RPIBOOT payload requires an active transition-owned power lease")
		}
	case PowerControlManual:
		if adapter.power != nil {
			return nil, errors.New("manual-power RPIBOOT payload must not hold a GPIO power lease")
		}
	default:
		return nil, errors.New("RPIBOOT payload has an invalid power-control mode")
	}
	if err := adapter.requireExactTarget(ctx, lane.RPIBootSysfsPath); err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, adapter.config.CommandTimeout)
	defer cancel()
	stdout := &boundedBuffer{maximum: adapter.config.MaximumOutputBytes}
	stderr := &boundedBuffer{maximum: adapter.config.MaximumOutputBytes}
	usbPath := filepath.Base(lane.RPIBootSysfsPath)
	arguments := []string{"-p", usbPath, "-d", bundle}
	var err error
	if adapter.usbPin != nil {
		guarded, ok := adapter.runner.(GuardedRunner)
		if !ok {
			return nil, errors.New("RPIBOOT execute runner lacks the required process-start identity guard")
		}
		err = guarded.RunGuarded(commandCtx, adapter.config.Paths.RPIBootBinary, arguments, func() error {
			if err := adapter.requireExactTarget(commandCtx, lane.RPIBootSysfsPath); err != nil {
				return err
			}
			if err := adapter.usbPin.Verify(); err != nil {
				return errors.Join(laneguard.ErrTargetContinuity, fmt.Errorf("pinned USB instance changed before runner start: %w", err))
			}
			return nil
		}, stdout, stderr)
	} else {
		err = adapter.runner.Run(commandCtx, adapter.config.Paths.RPIBootBinary, arguments, stdout, stderr)
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("rpiboot output exceeds %d bytes", adapter.config.MaximumOutputBytes)
	}
	if err != nil {
		return append([]byte(nil), stdout.bytes...), fmt.Errorf("rpiboot operation failed: %w", err)
	}
	return append([]byte(nil), stdout.bytes...), nil
}

func (adapter *Adapter) pinRPIBootInstance(expectedPath string) (USBInstancePin, error) {
	pinner, ok := adapter.filesystem.(USBInstancePinner)
	if !ok {
		return nil, errors.New("physical filesystem cannot pin a USB sysfs device instance")
	}
	pin, err := pinner.PinUSBInstance(expectedPath)
	if err != nil {
		return nil, errors.Join(laneguard.ErrTargetContinuity, fmt.Errorf("pin fixed RPIBOOT USB instance: %w", err))
	}
	if err := pin.Verify(); err != nil {
		_ = pin.Close()
		return nil, errors.Join(laneguard.ErrTargetContinuity, fmt.Errorf("verify pinned RPIBOOT USB instance: %w", err))
	}
	return pin, nil
}

func (adapter *Adapter) waitForExpectedTarget(ctx context.Context, expectedPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, adapter.config.USBReappearTimeout)
	defer cancel()
	for {
		topology, err := adapter.inspectUSBTopology(waitCtx, expectedPath, true)
		if err != nil {
			return err
		}
		switch {
		case topology.expectedPresent && len(topology.eligible) == 1 && topology.eligible[0] == expectedPath:
			return nil
		case !topology.expectedPresent && len(topology.eligible) == 0:
			if err := adapter.sleeper.Sleep(waitCtx, adapter.config.USBPollInterval); err != nil {
				return errors.Join(ErrNoRPIBootTarget, fmt.Errorf("wait for fixed RPIBOOT target reappearance: %w", err))
			}
		case len(topology.eligible) > 1:
			return fmt.Errorf("%w: found %d eligible devices", ErrAmbiguousTargets, len(topology.eligible))
		case topology.expectedPresent:
			return fmt.Errorf("%w: fixed sysfs node changed USB identity", ErrUnexpectedTarget)
		default:
			return fmt.Errorf("%w: found %s", ErrUnexpectedTarget, topology.eligible[0])
		}
	}
}

func (adapter *Adapter) waitForDisappearance(ctx context.Context, expectedPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, adapter.config.USBDisappearTimeout)
	defer cancel()
	for {
		topology, err := adapter.inspectUSBTopology(waitCtx, expectedPath, true)
		if err != nil {
			return fmt.Errorf("wait for RPIBOOT target disappearance: %w", err)
		}
		if !topology.expectedPresent && len(topology.eligible) == 0 {
			return nil
		}
		if !topology.expectedPresent || len(topology.eligible) != 1 || topology.eligible[0] != expectedPath {
			return ErrUnexpectedTarget
		}
		if err := adapter.sleeper.Sleep(waitCtx, adapter.config.USBPollInterval); err != nil {
			return fmt.Errorf("wait for RPIBOOT target disappearance: %w", err)
		}
	}
}

func (adapter *Adapter) requireExactTarget(ctx context.Context, expectedPath string) error {
	topology, err := adapter.inspectUSBTopology(ctx, expectedPath, true)
	if err != nil {
		return err
	}
	if !topology.expectedPresent && len(topology.eligible) == 0 {
		return ErrNoRPIBootTarget
	}
	if len(topology.eligible) > 1 {
		return ErrAmbiguousTargets
	}
	if !topology.expectedPresent || len(topology.eligible) != 1 || topology.eligible[0] != expectedPath {
		return ErrUnexpectedTarget
	}
	return nil
}

func (adapter *Adapter) requireNoTargets(ctx context.Context, expectedPath string) error {
	topology, err := adapter.inspectUSBTopology(ctx, expectedPath, false)
	if err != nil {
		return err
	}
	if len(topology.eligible) != 0 {
		return fmt.Errorf("%w: observed %d BCM2712 target(s)", ErrWrongBootMode, len(topology.eligible))
	}
	return nil
}

func (adapter *Adapter) ensurePower(ctx context.Context, descriptor laneguard.GPIODescriptor) error {
	if adapter.power != nil {
		return errors.New("target power is already held outside a fresh transition")
	}
	commandCtx, cancel := context.WithTimeout(ctx, adapter.config.CommandTimeout)
	defer cancel()
	lease, err := adapter.gpio.AcquirePower(commandCtx, descriptor)
	if lease != nil {
		// A lease returned with an acquisition error owns cleanup that is still
		// pending. Retain it so failTransition or Close can retry inactive.
		adapter.power = lease
	}
	if err != nil {
		return err
	}
	if lease == nil {
		return errors.New("GPIO acquisition succeeded without a power lease")
	}
	return nil
}

func (adapter *Adapter) releasePower() error {
	if adapter.power == nil {
		return nil
	}
	if err := adapter.power.Release(); err != nil {
		return fmt.Errorf("release normally-off power relay: %w", err)
	}
	adapter.power = nil
	return nil
}

type usbTopology struct {
	expectedPresent bool
	eligible        []string
}

func (adapter *Adapter) inspectUSBTopology(ctx context.Context, expectedPath string, strictExpectedAttributes bool) (usbTopology, error) {
	root := filepath.Dir(expectedPath)
	entries, err := adapter.filesystem.ReadDir(root)
	if err != nil {
		return usbTopology{}, fmt.Errorf("read USB sysfs: %w", err)
	}
	result := usbTopology{eligible: make([]string, 0, 1)}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return usbTopology{}, err
		}
		base := filepath.Join(root, entry.Name())
		expected := base == expectedPath
		if expected {
			result.expectedPresent = true
		}
		vendor, vendorErr := adapter.filesystem.ReadFile(filepath.Join(base, "idVendor"))
		product, productErr := adapter.filesystem.ReadFile(filepath.Join(base, "idProduct"))
		if vendorErr != nil || productErr != nil {
			if expected && strictExpectedAttributes {
				return usbTopology{}, errors.Join(
					fmt.Errorf("read fixed USB sysfs node attributes at %s", expectedPath), vendorErr, productErr,
				)
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(vendor)), broadcomVendorID) && strings.EqualFold(strings.TrimSpace(string(product)), bcm2712ProductID) {
			result.eligible = append(result.eligible, base)
		}
	}
	sort.Strings(result.eligible)
	return result, nil
}

func (adapter *Adapter) bindLane(lane laneguard.Config) error {
	if err := lane.Validate(); err != nil {
		return err
	}
	if lane.PowerControlMode != laneguard.PowerControlMode(adapter.config.PowerControl) {
		return errors.New("physical adapter power control differs from the authorized lane mode")
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

func (adapter *Adapter) validateContinuity(observation rpi5.Observation, expectedFingerprint string) error {
	if observation.TargetFingerprint != expectedFingerprint {
		return fmt.Errorf("%w: metadata fingerprint does not match the authority-bound target", laneguard.ErrTargetContinuity)
	}
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

func (adapter *Adapter) newPrompt(action laneguard.HardwareAction, kind operatorprompt.Kind, instructions string, expiresAt time.Time) (operatorprompt.Prompt, error) {
	material, err := json.Marshal(struct {
		Action    laneguard.HardwareAction `json:"action"`
		Kind      operatorprompt.Kind      `json:"kind"`
		ExpiresAt time.Time                `json:"expires_at"`
	}{Action: action, Kind: kind, ExpiresAt: expiresAt.UTC()})
	if err != nil {
		return operatorprompt.Prompt{}, err
	}
	digest := sha256.Sum256(material)
	id := "boot-" + string(kind) + "-" + hex.EncodeToString(digest[:8])
	return operatorprompt.New(action, kind, id, instructions, expiresAt)
}

func validatePromptAcknowledgement(prompt operatorprompt.Prompt, acknowledgement operatorprompt.Acknowledgement, notBefore time.Time) error {
	if acknowledgement.SchemaVersion != operatorprompt.AcknowledgementSchemaVersion ||
		acknowledgement.PromptID != prompt.ID || acknowledgement.PromptDigest != prompt.Digest || acknowledgement.Peer.PID <= 0 ||
		acknowledgement.AcknowledgedAt.Before(notBefore) || !acknowledgement.AcknowledgedAt.Before(prompt.ExpiresAt) {
		return errors.New("operator acknowledgement does not match the durable prompt, timing, or peer")
	}
	return nil
}

func (adapter *Adapter) now() time.Time { return adapter.clock.Now().UTC() }

func (adapter *Adapter) powerEstablishedAt(transition laneguard.BootTransition) time.Time {
	if transition.PowerControlMode == laneguard.PowerControlManual {
		// The daemon cannot observe the physical edge. In manual mode this field
		// deliberately records the authenticated acknowledgement/attestation.
		return transition.OperatorAcknowledgedAt
	}
	return adapter.atLeast(transition.OperatorAcknowledgedAt)
}

func (adapter *Adapter) atLeast(values ...time.Time) time.Time {
	result := adapter.now()
	for _, value := range values {
		if value.After(result) {
			result = value.UTC()
		}
	}
	return result
}

func directState(observation rpi5.Observation, powerState string) laneguard.DirectState {
	securityState := "owned"
	if observation.CustomerKeyHash == zeroCustomerKey {
		securityState = "fresh"
	}
	state := laneguard.DirectState{
		CustomerKeyHash:  "sha256:" + observation.CustomerKeyHash,
		EEPROMHashStatus: laneguard.EEPROMHashUnavailable,
		SecurityState:    securityState, PowerState: powerState,
	}
	if observation.EEPROMHash != "" {
		state.EEPROMHashStatus = laneguard.EEPROMHashObserved
		state.EEPROMHash = "sha256:" + observation.EEPROMHash
	}
	return state
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

// Close releases any relay lease still owned by the adapter. Manual mode has
// no electrical actuator; its terminal and restart paths require a separate
// authenticated disconnect acknowledgement instead.
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
