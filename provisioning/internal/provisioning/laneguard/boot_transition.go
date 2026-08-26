package laneguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	BootTransitionActionSchemaVersion    = "provisioning.kaiba.network/boot-transition-action/v1alpha1"
	BootTransitionSchemaVersion          = "provisioning.kaiba.network/boot-transition/v1alpha1"
	BootTransitionEvidenceSchemaVersion  = "provisioning.kaiba.network/boot-transition-evidence/v1alpha1"
	BootTransitionReferenceSchemaVersion = "provisioning.kaiba.network/boot-transition-reference/v1alpha1"

	bootTransitionEvidenceDigestDomain = "kaiba.provisioning.boot-transition-evidence.v1alpha1"
)

var (
	ErrBootTransitionOpen     = errors.New("an incomplete boot transition already exists for this action phase")
	ErrBootTransitionNotBegun = errors.New("boot transition was not durably created by BeginBootTransition")
)

// HardwarePhase identifies one target-facing boundary in an approved
// operation. Only execution inherits the operation's digest-bound boot mode;
// direct precondition, postcondition, and reconciliation observations use the
// fixed RPIBOOT observation path.
type HardwarePhase string

const (
	HardwarePhasePreObservation  HardwarePhase = "pre_observation"
	HardwarePhaseExecute         HardwarePhase = "execute"
	HardwarePhasePostObservation HardwarePhase = "post_observation"
	HardwarePhaseReconciliation  HardwarePhase = "reconciliation"
)

// HardwareAction is the immutable authority and intent binding carried into a
// future target-facing boot transition. It deliberately contains no physical
// path, payload selector, executable, prompt text, or caller-selected mode.
type HardwareAction struct {
	SchemaVersion             string        `json:"schema_version"`
	StationID                 string        `json:"station_id"`
	LaneID                    string        `json:"lane_id"`
	TransactionID             string        `json:"transaction_id"`
	PlanDigest                string        `json:"plan_digest"`
	TargetFingerprint         string        `json:"target_fingerprint"`
	FenceEpoch                uint64        `json:"fence_epoch"`
	ApprovalID                string        `json:"approval_id"`
	IntentReceipt             string        `json:"intent_receipt"`
	IntentSequence            uint32        `json:"intent_sequence"`
	Sequence                  uint32        `json:"sequence"`
	Operation                 Operation     `json:"operation"`
	OperationDigest           string        `json:"operation_digest"`
	AuthorizationID           string        `json:"authorization_id"`
	Phase                     HardwarePhase `json:"phase"`
	OperationRequiredBootMode BootMode      `json:"operation_required_boot_mode"`
	RequestedBootMode         BootMode      `json:"requested_boot_mode"`
	ReconciliationClaimID     string        `json:"reconciliation_claim_id,omitempty"`
	ReconciliationFenceEpoch  uint64        `json:"reconciliation_fence_epoch,omitempty"`
}

func (action HardwareAction) Validate() error {
	if action.SchemaVersion != BootTransitionActionSchemaVersion {
		return fmt.Errorf("unsupported boot-transition action schema %q", action.SchemaVersion)
	}
	if !identifierPattern.MatchString(action.StationID) || !identifierPattern.MatchString(action.LaneID) ||
		!identifierPattern.MatchString(action.TransactionID) || !identifierPattern.MatchString(action.TargetFingerprint) {
		return errors.New("boot-transition action contains an invalid identity")
	}
	if !digestPattern.MatchString(action.PlanDigest) || !digestPattern.MatchString(action.OperationDigest) {
		return errors.New("boot-transition action requires canonical plan and operation digests")
	}
	if action.FenceEpoch == 0 || action.ApprovalID == "" || action.IntentReceipt == "" ||
		action.IntentSequence == 0 || action.Sequence == 0 || action.IntentSequence != action.Sequence || action.AuthorizationID == "" {
		return errors.New("boot-transition action is missing immutable authority or intent bindings")
	}
	required, allowed := RequiredBootModeForOperation(action.Operation)
	if !allowed || action.OperationRequiredBootMode != required {
		return errors.New("boot-transition action operation or required boot mode is outside the closed policy")
	}
	switch action.Phase {
	case HardwarePhaseExecute:
		if action.RequestedBootMode != required {
			return errors.New("execute transition must request the operation's required boot mode")
		}
	case HardwarePhasePreObservation, HardwarePhasePostObservation:
		if action.RequestedBootMode != BootModeRPIBoot {
			return errors.New("direct execution observation must request RPIBOOT")
		}
	case HardwarePhaseReconciliation:
		if action.RequestedBootMode != BootModeRPIBoot {
			return errors.New("reconciliation observation must request RPIBOOT")
		}
		if !identifierPattern.MatchString(action.ReconciliationClaimID) || action.ReconciliationFenceEpoch <= action.FenceEpoch {
			return errors.New("reconciliation transition requires a fresh claim and fence")
		}
	default:
		return errors.New("boot-transition action has an invalid phase")
	}
	if action.Phase != HardwarePhaseReconciliation && (action.ReconciliationClaimID != "" || action.ReconciliationFenceEpoch != 0) {
		return errors.New("execution transition must not carry reconciliation authority")
	}
	return nil
}

// BootTransitionStatus is a closed, forward-only state machine. The three
// failure outcomes are terminal: safe abort, safe restart interruption, and
// quarantine when fail-off cannot be established.
type BootTransitionStatus string

const (
	BootTransitionRequested            BootTransitionStatus = "requested"
	BootTransitionAwaitingOperator     BootTransitionStatus = "awaiting_operator"
	BootTransitionOperatorAcknowledged BootTransitionStatus = "operator_acknowledged"
	BootTransitionPowerApplied         BootTransitionStatus = "power_applied"
	BootTransitionModeObserved         BootTransitionStatus = "mode_observed"
	BootTransitionOperatorReleased     BootTransitionStatus = "operator_released"
	BootTransitionCompleted            BootTransitionStatus = "completed"
	BootTransitionAbortedSafeOff       BootTransitionStatus = "aborted_safe_off"
	BootTransitionInterruptedSafeOff   BootTransitionStatus = "interrupted_safe_off"
	BootTransitionQuarantined          BootTransitionStatus = "quarantined"
)

type BootTransitionFailure string

const (
	BootTransitionFailureNone             BootTransitionFailure = ""
	BootTransitionFailureOperatorTimeout  BootTransitionFailure = "operator_timeout"
	BootTransitionFailureOperatorRejected BootTransitionFailure = "operator_rejected"
	BootTransitionFailureModeTimeout      BootTransitionFailure = "mode_timeout"
	BootTransitionFailureWrongMode        BootTransitionFailure = "wrong_mode"
	BootTransitionFailureTargetContinuity BootTransitionFailure = "target_continuity"
	BootTransitionFailureHardware         BootTransitionFailure = "hardware_error"
	BootTransitionFailureInterrupted      BootTransitionFailure = "interrupted"
	BootTransitionFailureSafeOffUnproven  BootTransitionFailure = "safe_off_unproven"
)

type OperatorPeer struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	PID int32  `json:"pid"`
}

type RPIBootObservationMethod string

const RPIBootObservationSysfsPoll RPIBootObservationMethod = "sysfs_poll"

// BeginBootTransitionRequest contains the power-off proof and the initial
// operator prompt which must be persisted atomically before it becomes
// actionable. Generation and key are allocated by the store.
type BeginBootTransitionRequest struct {
	Action              HardwareAction `json:"action"`
	StartedAt           time.Time      `json:"started_at"`
	RecordedAt          time.Time      `json:"recorded_at"`
	PowerOffObservedAt  time.Time      `json:"power_off_observed_at"`
	USBAbsentObservedAt time.Time      `json:"usb_absent_observed_at"`
	ColdIntervalEndsAt  time.Time      `json:"cold_interval_ends_at"`
	PromptID            string         `json:"prompt_id"`
	PromptDigest        string         `json:"prompt_digest"`
	PromptExpiresAt     time.Time      `json:"prompt_expires_at"`
}

func (request BeginBootTransitionRequest) transition(generation uint64) (BootTransition, error) {
	transition := BootTransition{
		SchemaVersion: BootTransitionSchemaVersion,
		Generation:    generation, Action: request.Action, Status: BootTransitionRequested,
		StartedAt: request.StartedAt, UpdatedAt: request.RecordedAt,
		PowerOffObservedAt: request.PowerOffObservedAt, USBAbsentObservedAt: request.USBAbsentObservedAt,
		ColdIntervalEndsAt: request.ColdIntervalEndsAt, PromptID: request.PromptID,
		PromptDigest: request.PromptDigest, PromptExpiresAt: request.PromptExpiresAt,
	}
	transition.Key = BootTransitionKey(request.Action, generation)
	if err := transition.Validate(); err != nil {
		return BootTransition{}, err
	}
	return transition, nil
}

// BootTransition is the durable mutable state for one physical mode-selection
// generation. Prompt contents are represented only by a bounded identifier and
// digest; an operator cannot supply action identity, phase, or boot mode.
type BootTransition struct {
	SchemaVersion             string                   `json:"schema_version"`
	Key                       string                   `json:"key"`
	Generation                uint64                   `json:"generation"`
	Action                    HardwareAction           `json:"action"`
	Status                    BootTransitionStatus     `json:"status"`
	StartedAt                 time.Time                `json:"started_at"`
	UpdatedAt                 time.Time                `json:"updated_at"`
	PowerOffObservedAt        time.Time                `json:"power_off_observed_at"`
	USBAbsentObservedAt       time.Time                `json:"usb_absent_observed_at"`
	ColdIntervalEndsAt        time.Time                `json:"cold_interval_ends_at"`
	PromptID                  string                   `json:"prompt_id"`
	PromptDigest              string                   `json:"prompt_digest"`
	PromptExpiresAt           time.Time                `json:"prompt_expires_at"`
	Operator                  OperatorPeer             `json:"operator"`
	OperatorAcknowledgedAt    time.Time                `json:"operator_acknowledged_at"`
	PowerAppliedAt            time.Time                `json:"power_applied_at"`
	ModeObservedAt            time.Time                `json:"mode_observed_at"`
	ObservedMode              BootMode                 `json:"observed_mode"`
	RPIBootSysfsPath          string                   `json:"rpiboot_sysfs_path"`
	RPIBootEligibleTargets    int                      `json:"rpiboot_eligible_targets"`
	UARTPath                  string                   `json:"uart_path"`
	UARTOutputDigest          string                   `json:"uart_output_digest"`
	RPIBootObservationMethod  RPIBootObservationMethod `json:"rpiboot_observation_method"`
	RPIBootPollInterval       time.Duration            `json:"rpiboot_poll_interval"`
	RPIBootNotObservedThrough time.Time                `json:"rpiboot_not_observed_through"`
	ReleasePromptID           string                   `json:"release_prompt_id"`
	ReleasePromptDigest       string                   `json:"release_prompt_digest"`
	ReleasePromptExpiresAt    time.Time                `json:"release_prompt_expires_at"`
	ReleaseOperator           OperatorPeer             `json:"release_operator"`
	OperatorReleasedAt        time.Time                `json:"operator_released_at"`
	SafeOffObservedAt         time.Time                `json:"safe_off_observed_at"`
	CompletedAt               time.Time                `json:"completed_at"`
	Failure                   BootTransitionFailure    `json:"failure"`
	EvidenceDigest            string                   `json:"evidence_digest"`
}

func BootTransitionKey(action HardwareAction, generation uint64) string {
	return fmt.Sprintf("%s/%s/%d/%d/%s/%d", action.TransactionID, action.PlanDigest, action.FenceEpoch, action.Sequence, action.Phase, generation)
}

func (transition BootTransition) IsTerminal() bool {
	switch transition.Status {
	case BootTransitionCompleted, BootTransitionAbortedSafeOff, BootTransitionInterruptedSafeOff, BootTransitionQuarantined:
		return true
	default:
		return false
	}
}

// BootTransitionReference is the small comparable outcome carried across an
// error boundary. The complete record remains in the durable journal; a
// completed outcome additionally binds its immutable evidence digest.
type BootTransitionReference struct {
	SchemaVersion  string                `json:"schema_version"`
	TransitionKey  string                `json:"transition_key"`
	Status         BootTransitionStatus  `json:"status"`
	Failure        BootTransitionFailure `json:"failure"`
	EvidenceDigest string                `json:"evidence_digest"`
}

func (transition BootTransition) Reference() (BootTransitionReference, error) {
	if err := transition.Validate(); err != nil {
		return BootTransitionReference{}, err
	}
	if !transition.IsTerminal() {
		return BootTransitionReference{}, errors.New("boot-transition reference requires a terminal record")
	}
	reference := BootTransitionReference{
		SchemaVersion: BootTransitionReferenceSchemaVersion, TransitionKey: transition.Key,
		Status: transition.Status, Failure: transition.Failure, EvidenceDigest: transition.EvidenceDigest,
	}
	return reference, reference.Validate()
}

func (reference BootTransitionReference) Validate() error {
	if reference.SchemaVersion != BootTransitionReferenceSchemaVersion || reference.TransitionKey == "" {
		return errors.New("boot-transition reference is missing its schema or key")
	}
	switch reference.Status {
	case BootTransitionCompleted:
		if reference.Failure != BootTransitionFailureNone || !digestPattern.MatchString(reference.EvidenceDigest) {
			return errors.New("completed boot-transition reference requires only a canonical evidence digest")
		}
	case BootTransitionAbortedSafeOff, BootTransitionInterruptedSafeOff, BootTransitionQuarantined:
		if !knownBootTransitionFailure(reference.Failure) || reference.Failure == BootTransitionFailureNone || reference.EvidenceDigest != "" {
			return errors.New("failed boot-transition reference requires only a known failure")
		}
	default:
		return errors.New("boot-transition reference requires a terminal status")
	}
	return nil
}

func (transition BootTransition) Validate() error {
	if transition.SchemaVersion != BootTransitionSchemaVersion || transition.Generation == 0 || transition.Key == "" {
		return errors.New("boot transition is missing its schema, key, or generation")
	}
	if err := transition.Action.Validate(); err != nil {
		return fmt.Errorf("boot transition action: %w", err)
	}
	if transition.Key != BootTransitionKey(transition.Action, transition.Generation) {
		return errors.New("boot transition key does not match its immutable action and generation")
	}
	if transition.StartedAt.IsZero() || transition.UpdatedAt.Before(transition.USBAbsentObservedAt) ||
		transition.PowerOffObservedAt.Before(transition.StartedAt) || transition.USBAbsentObservedAt.Before(transition.PowerOffObservedAt) ||
		transition.ColdIntervalEndsAt.Before(transition.USBAbsentObservedAt) || !transition.PromptExpiresAt.After(transition.ColdIntervalEndsAt) {
		return errors.New("boot transition has missing or unordered initial timestamps")
	}
	if !identifierPattern.MatchString(transition.PromptID) || !digestPattern.MatchString(transition.PromptDigest) {
		return errors.New("boot transition requires a bounded prompt ID and canonical prompt digest")
	}
	if err := validateBootTransitionProgress(transition); err != nil {
		return err
	}
	return nil
}

func validateBootTransitionProgress(transition BootTransition) error {
	statusRank, active := bootTransitionRank(transition.Status)
	if !active && !transition.IsTerminal() {
		return errors.New("boot transition has an invalid status")
	}
	acknowledged := !transition.OperatorAcknowledgedAt.IsZero()
	powered := !transition.PowerAppliedAt.IsZero()
	observed := !transition.ModeObservedAt.IsZero()
	released := !transition.OperatorReleasedAt.IsZero()
	safeOff := !transition.SafeOffObservedAt.IsZero()
	completed := !transition.CompletedAt.IsZero()
	if acknowledged && (transition.Operator.PID <= 0 || transition.OperatorAcknowledgedAt.Before(transition.ColdIntervalEndsAt)) {
		return errors.New("boot transition has invalid operator acknowledgment evidence")
	}
	if acknowledged && transition.OperatorAcknowledgedAt.After(transition.PromptExpiresAt) {
		return errors.New("boot transition accepted an expired operator prompt")
	}
	if powered && (!acknowledged || transition.PowerAppliedAt.Before(transition.OperatorAcknowledgedAt)) {
		return errors.New("boot transition applied power before durable operator acknowledgment")
	}
	if observed && (!powered || transition.ModeObservedAt.Before(transition.PowerAppliedAt)) {
		return errors.New("boot transition observed a mode before power was applied")
	}
	if released && (!observed || transition.ReleaseOperator.PID <= 0 || transition.OperatorReleasedAt.Before(transition.ModeObservedAt)) {
		return errors.New("boot transition has invalid BOOTSEL release acknowledgment evidence")
	}
	if released && transition.OperatorReleasedAt.After(transition.ReleasePromptExpiresAt) {
		return errors.New("boot transition accepted an expired BOOTSEL release prompt")
	}
	safeOffLowerBound := transition.USBAbsentObservedAt
	if powered {
		safeOffLowerBound = transition.PowerAppliedAt
	}
	if observed {
		safeOffLowerBound = transition.ModeObservedAt
	}
	if released {
		safeOffLowerBound = transition.OperatorReleasedAt
	}
	if safeOff && transition.SafeOffObservedAt.Before(safeOffLowerBound) {
		return errors.New("boot transition safe-off evidence is invalid")
	}
	if completed && (!safeOff || transition.CompletedAt.Before(transition.SafeOffObservedAt)) {
		return errors.New("boot transition completion precedes safe-off evidence")
	}
	if (acknowledged && transition.UpdatedAt.Before(transition.OperatorAcknowledgedAt)) ||
		(powered && transition.UpdatedAt.Before(transition.PowerAppliedAt)) ||
		(observed && transition.UpdatedAt.Before(transition.ModeObservedAt)) ||
		(released && transition.UpdatedAt.Before(transition.OperatorReleasedAt)) ||
		(safeOff && transition.UpdatedAt.Before(transition.SafeOffObservedAt)) ||
		(completed && transition.UpdatedAt.Before(transition.CompletedAt)) {
		return errors.New("boot transition update time precedes a recorded event")
	}
	if active {
		if transition.Failure != BootTransitionFailureNone || transition.EvidenceDigest != "" || completed || safeOff {
			return errors.New("active boot transition contains terminal outcome fields")
		}
		if statusRank >= 2 && !acknowledged || statusRank < 2 && acknowledged {
			return errors.New("boot transition acknowledgment fields do not match its status")
		}
		if statusRank >= 3 && !powered || statusRank < 3 && powered {
			return errors.New("boot transition power fields do not match its status")
		}
		if statusRank >= 4 && !observed || statusRank < 4 && observed {
			return errors.New("boot transition observation fields do not match its status")
		}
		if statusRank >= 5 && !released || statusRank < 5 && released {
			return errors.New("boot transition release fields do not match its status")
		}
		if observed {
			if err := validateObservedBootMode(transition); err != nil {
				return err
			}
			if transition.ObservedMode == BootModeNormal && released {
				return errors.New("normal boot transition must not contain a BOOTSEL release acknowledgment")
			}
			return nil
		}
		if statusRank >= 1 && transition.UpdatedAt.Before(transition.ColdIntervalEndsAt) {
			return errors.New("boot transition cannot await operator action before the cold interval ends")
		}
		if transition.ObservedMode != "" || transition.RPIBootSysfsPath != "" || transition.RPIBootEligibleTargets != 0 ||
			transition.UARTPath != "" || transition.UARTOutputDigest != "" || transition.RPIBootObservationMethod != "" ||
			transition.RPIBootPollInterval != 0 || !transition.RPIBootNotObservedThrough.IsZero() {
			return errors.New("boot transition contains observation data before mode observation")
		}
		return nil
	}

	if transition.Status == BootTransitionCompleted {
		if transition.Failure != BootTransitionFailureNone || !acknowledged || !powered || !observed || !safeOff || !completed {
			return errors.New("completed boot transition is missing required evidence")
		}
		if err := validateObservedBootMode(transition); err != nil {
			return err
		}
		if transition.ObservedMode == BootModeRPIBoot && !released {
			return errors.New("completed RPIBOOT transition requires a post-detection release acknowledgment")
		}
		if transition.ObservedMode == BootModeNormal && released {
			return errors.New("completed normal transition must not contain a BOOTSEL release acknowledgment")
		}
		evidence, err := transition.Evidence()
		if err != nil {
			return err
		}
		digest, err := evidence.Digest()
		if err != nil {
			return err
		}
		if transition.EvidenceDigest != digest {
			return errors.New("completed boot transition evidence digest does not match its record")
		}
		return nil
	}

	if !knownBootTransitionFailure(transition.Failure) || transition.Failure == BootTransitionFailureNone || transition.EvidenceDigest != "" || completed {
		return errors.New("failed boot transition has an invalid terminal outcome")
	}
	if transition.Status == BootTransitionQuarantined {
		if safeOff || transition.Failure != BootTransitionFailureSafeOffUnproven {
			return errors.New("quarantined boot transition must record unproven safe-off")
		}
		return nil
	}
	if !safeOff || transition.Failure == BootTransitionFailureSafeOffUnproven {
		return errors.New("safe terminal boot transition requires direct safe-off evidence")
	}
	if transition.Status == BootTransitionInterruptedSafeOff && transition.Failure != BootTransitionFailureInterrupted {
		return errors.New("interrupted boot transition requires the interrupted failure code")
	}
	return nil
}

func bootTransitionRank(status BootTransitionStatus) (int, bool) {
	switch status {
	case BootTransitionRequested:
		return 0, true
	case BootTransitionAwaitingOperator:
		return 1, true
	case BootTransitionOperatorAcknowledged:
		return 2, true
	case BootTransitionPowerApplied:
		return 3, true
	case BootTransitionModeObserved:
		return 4, true
	case BootTransitionOperatorReleased:
		return 5, true
	default:
		return 0, false
	}
}

func knownBootTransitionFailure(failure BootTransitionFailure) bool {
	switch failure {
	case BootTransitionFailureOperatorTimeout, BootTransitionFailureOperatorRejected,
		BootTransitionFailureModeTimeout, BootTransitionFailureWrongMode,
		BootTransitionFailureTargetContinuity, BootTransitionFailureHardware,
		BootTransitionFailureInterrupted, BootTransitionFailureSafeOffUnproven:
		return true
	default:
		return false
	}
}

func validateObservedBootMode(transition BootTransition) error {
	if transition.ObservedMode != transition.Action.RequestedBootMode {
		return errors.New("observed boot mode does not match the requested mode")
	}
	if !fixedChild(transition.RPIBootSysfsPath, "/sys/bus/usb/devices/") {
		return errors.New("boot-transition evidence requires the fixed monitored RPIBOOT path")
	}
	if transition.RPIBootObservationMethod != RPIBootObservationSysfsPoll || transition.RPIBootPollInterval <= 0 || transition.RPIBootPollInterval > time.Minute {
		return errors.New("boot-transition evidence requires a bounded RPIBOOT observation method and poll interval")
	}
	switch transition.ObservedMode {
	case BootModeRPIBoot:
		if transition.RPIBootEligibleTargets != 1 || transition.UARTPath != "" || transition.UARTOutputDigest != "" || !transition.RPIBootNotObservedThrough.IsZero() ||
			!identifierPattern.MatchString(transition.ReleasePromptID) || !digestPattern.MatchString(transition.ReleasePromptDigest) ||
			!transition.ReleasePromptExpiresAt.After(transition.ModeObservedAt) {
			return errors.New("RPIBOOT transition requires exactly one fixed USB target and no normal-boot evidence")
		}
	case BootModeNormal:
		if transition.RPIBootEligibleTargets != 0 || !fixedChild(transition.UARTPath, "/dev/serial/by-id/") ||
			!digestPattern.MatchString(transition.UARTOutputDigest) || transition.RPIBootNotObservedThrough.Before(transition.ModeObservedAt) ||
			transition.ReleasePromptID != "" || transition.ReleasePromptDigest != "" || !transition.ReleasePromptExpiresAt.IsZero() {
			return errors.New("normal transition requires UART evidence and RPIBOOT not observed through mode evidence")
		}
	default:
		return errors.New("boot transition observed an invalid mode")
	}
	return nil
}

// BootTransitionEvidence is the immutable, self-contained subset emitted only
// by a completed transition. Digest excludes no security-relevant field.
type BootTransitionEvidence struct {
	SchemaVersion             string                   `json:"schema_version"`
	TransitionKey             string                   `json:"transition_key"`
	Generation                uint64                   `json:"generation"`
	Action                    HardwareAction           `json:"action"`
	StartedAt                 time.Time                `json:"started_at"`
	PromptID                  string                   `json:"prompt_id"`
	PromptDigest              string                   `json:"prompt_digest"`
	PromptExpiresAt           time.Time                `json:"prompt_expires_at"`
	Operator                  OperatorPeer             `json:"operator"`
	PowerOffObservedAt        time.Time                `json:"power_off_observed_at"`
	USBAbsentObservedAt       time.Time                `json:"usb_absent_observed_at"`
	ColdIntervalEndsAt        time.Time                `json:"cold_interval_ends_at"`
	OperatorAcknowledgedAt    time.Time                `json:"operator_acknowledged_at"`
	PowerAppliedAt            time.Time                `json:"power_applied_at"`
	ModeObservedAt            time.Time                `json:"mode_observed_at"`
	ObservedMode              BootMode                 `json:"observed_mode"`
	RPIBootSysfsPath          string                   `json:"rpiboot_sysfs_path"`
	RPIBootEligibleTargets    int                      `json:"rpiboot_eligible_targets"`
	UARTPath                  string                   `json:"uart_path"`
	UARTOutputDigest          string                   `json:"uart_output_digest"`
	RPIBootObservationMethod  RPIBootObservationMethod `json:"rpiboot_observation_method"`
	RPIBootPollInterval       time.Duration            `json:"rpiboot_poll_interval"`
	RPIBootNotObservedThrough time.Time                `json:"rpiboot_not_observed_through"`
	ReleasePromptID           string                   `json:"release_prompt_id"`
	ReleasePromptDigest       string                   `json:"release_prompt_digest"`
	ReleasePromptExpiresAt    time.Time                `json:"release_prompt_expires_at"`
	ReleaseOperator           OperatorPeer             `json:"release_operator"`
	OperatorReleasedAt        time.Time                `json:"operator_released_at"`
	SafeOffObservedAt         time.Time                `json:"safe_off_observed_at"`
	CompletedAt               time.Time                `json:"completed_at"`
}

func (transition BootTransition) Evidence() (BootTransitionEvidence, error) {
	if transition.Status != BootTransitionCompleted {
		return BootTransitionEvidence{}, errors.New("boot-transition evidence is available only after completion")
	}
	evidence := BootTransitionEvidence{
		SchemaVersion: BootTransitionEvidenceSchemaVersion, TransitionKey: transition.Key, Generation: transition.Generation,
		Action: transition.Action, StartedAt: transition.StartedAt, PromptID: transition.PromptID,
		PromptDigest: transition.PromptDigest, PromptExpiresAt: transition.PromptExpiresAt, Operator: transition.Operator,
		PowerOffObservedAt: transition.PowerOffObservedAt, USBAbsentObservedAt: transition.USBAbsentObservedAt,
		ColdIntervalEndsAt: transition.ColdIntervalEndsAt, OperatorAcknowledgedAt: transition.OperatorAcknowledgedAt,
		PowerAppliedAt: transition.PowerAppliedAt, ModeObservedAt: transition.ModeObservedAt, ObservedMode: transition.ObservedMode,
		RPIBootSysfsPath: transition.RPIBootSysfsPath, RPIBootEligibleTargets: transition.RPIBootEligibleTargets,
		UARTPath: transition.UARTPath, UARTOutputDigest: transition.UARTOutputDigest,
		RPIBootObservationMethod: transition.RPIBootObservationMethod, RPIBootPollInterval: transition.RPIBootPollInterval,
		RPIBootNotObservedThrough: transition.RPIBootNotObservedThrough, ReleasePromptID: transition.ReleasePromptID,
		ReleasePromptDigest: transition.ReleasePromptDigest, ReleasePromptExpiresAt: transition.ReleasePromptExpiresAt,
		ReleaseOperator:    transition.ReleaseOperator,
		OperatorReleasedAt: transition.OperatorReleasedAt, SafeOffObservedAt: transition.SafeOffObservedAt,
		CompletedAt: transition.CompletedAt,
	}
	return evidence, nil
}

func (evidence BootTransitionEvidence) Validate() error {
	if evidence.SchemaVersion != BootTransitionEvidenceSchemaVersion || evidence.TransitionKey == "" || evidence.Generation == 0 {
		return errors.New("boot-transition evidence is missing its schema, key, or generation")
	}
	if err := evidence.Action.Validate(); err != nil {
		return fmt.Errorf("boot-transition evidence action: %w", err)
	}
	transition := BootTransition{
		SchemaVersion: BootTransitionSchemaVersion, Key: evidence.TransitionKey, Generation: evidence.Generation,
		Action: evidence.Action, Status: BootTransitionCompleted, StartedAt: evidence.StartedAt,
		UpdatedAt: evidence.CompletedAt, PowerOffObservedAt: evidence.PowerOffObservedAt,
		USBAbsentObservedAt: evidence.USBAbsentObservedAt, ColdIntervalEndsAt: evidence.ColdIntervalEndsAt,
		PromptID: evidence.PromptID, PromptDigest: evidence.PromptDigest, PromptExpiresAt: evidence.PromptExpiresAt,
		Operator: evidence.Operator, OperatorAcknowledgedAt: evidence.OperatorAcknowledgedAt, PowerAppliedAt: evidence.PowerAppliedAt,
		ModeObservedAt: evidence.ModeObservedAt, ObservedMode: evidence.ObservedMode, RPIBootSysfsPath: evidence.RPIBootSysfsPath,
		RPIBootEligibleTargets: evidence.RPIBootEligibleTargets, UARTPath: evidence.UARTPath,
		UARTOutputDigest: evidence.UARTOutputDigest, RPIBootObservationMethod: evidence.RPIBootObservationMethod,
		RPIBootPollInterval: evidence.RPIBootPollInterval, RPIBootNotObservedThrough: evidence.RPIBootNotObservedThrough,
		ReleasePromptID: evidence.ReleasePromptID, ReleasePromptDigest: evidence.ReleasePromptDigest,
		ReleasePromptExpiresAt: evidence.ReleasePromptExpiresAt,
		ReleaseOperator:        evidence.ReleaseOperator, OperatorReleasedAt: evidence.OperatorReleasedAt,
		SafeOffObservedAt: evidence.SafeOffObservedAt, CompletedAt: evidence.CompletedAt,
	}
	if transition.Key != BootTransitionKey(transition.Action, transition.Generation) {
		return errors.New("boot-transition evidence key does not match its action")
	}
	if transition.StartedAt.IsZero() || transition.PowerOffObservedAt.Before(transition.StartedAt) ||
		transition.USBAbsentObservedAt.Before(transition.PowerOffObservedAt) ||
		transition.ColdIntervalEndsAt.Before(transition.USBAbsentObservedAt) || transition.OperatorAcknowledgedAt.Before(transition.ColdIntervalEndsAt) ||
		transition.OperatorAcknowledgedAt.After(transition.PromptExpiresAt) ||
		transition.PowerAppliedAt.Before(transition.OperatorAcknowledgedAt) || transition.ModeObservedAt.Before(transition.PowerAppliedAt) ||
		transition.SafeOffObservedAt.Before(transition.ModeObservedAt) || transition.CompletedAt.Before(transition.SafeOffObservedAt) {
		return errors.New("boot-transition evidence timestamps are missing or unordered")
	}
	if !identifierPattern.MatchString(evidence.PromptID) || !digestPattern.MatchString(evidence.PromptDigest) || evidence.Operator.PID <= 0 {
		return errors.New("boot-transition evidence has invalid prompt or operator evidence")
	}
	if err := validateObservedBootMode(transition); err != nil {
		return err
	}
	if evidence.ObservedMode == BootModeRPIBoot {
		if evidence.ReleaseOperator.PID <= 0 || evidence.OperatorReleasedAt.Before(evidence.ModeObservedAt) ||
			evidence.OperatorReleasedAt.After(evidence.ReleasePromptExpiresAt) || evidence.SafeOffObservedAt.Before(evidence.OperatorReleasedAt) {
			return errors.New("RPIBOOT evidence requires a post-detection release acknowledgment")
		}
	} else if evidence.ReleaseOperator != (OperatorPeer{}) || !evidence.OperatorReleasedAt.IsZero() {
		return errors.New("normal-boot evidence must not contain a BOOTSEL release acknowledgment")
	}
	return nil
}

func (evidence BootTransitionEvidence) Digest() (string, error) {
	if err := evidence.Validate(); err != nil {
		return "", err
	}
	material, err := canonicalBootTransitionEvidence(evidence)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(bootTransitionEvidenceDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(material)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

type bootTransitionEvidenceDigestMaterial struct {
	SchemaVersion             string                   `json:"schema_version"`
	TransitionKey             string                   `json:"transition_key"`
	Generation                uint64                   `json:"generation"`
	Action                    HardwareAction           `json:"action"`
	StartedAt                 string                   `json:"started_at"`
	PromptID                  string                   `json:"prompt_id"`
	PromptDigest              string                   `json:"prompt_digest"`
	PromptExpiresAt           string                   `json:"prompt_expires_at"`
	Operator                  OperatorPeer             `json:"operator"`
	PowerOffObservedAt        string                   `json:"power_off_observed_at"`
	USBAbsentObservedAt       string                   `json:"usb_absent_observed_at"`
	ColdIntervalEndsAt        string                   `json:"cold_interval_ends_at"`
	OperatorAcknowledgedAt    string                   `json:"operator_acknowledged_at"`
	PowerAppliedAt            string                   `json:"power_applied_at"`
	ModeObservedAt            string                   `json:"mode_observed_at"`
	ObservedMode              BootMode                 `json:"observed_mode"`
	RPIBootSysfsPath          string                   `json:"rpiboot_sysfs_path"`
	RPIBootEligibleTargets    int                      `json:"rpiboot_eligible_targets"`
	UARTPath                  string                   `json:"uart_path"`
	UARTOutputDigest          string                   `json:"uart_output_digest"`
	RPIBootObservationMethod  RPIBootObservationMethod `json:"rpiboot_observation_method"`
	RPIBootPollIntervalNanos  int64                    `json:"rpiboot_poll_interval_nanoseconds"`
	RPIBootNotObservedThrough string                   `json:"rpiboot_not_observed_through"`
	ReleasePromptID           string                   `json:"release_prompt_id"`
	ReleasePromptDigest       string                   `json:"release_prompt_digest"`
	ReleasePromptExpiresAt    string                   `json:"release_prompt_expires_at"`
	ReleaseOperator           OperatorPeer             `json:"release_operator"`
	OperatorReleasedAt        string                   `json:"operator_released_at"`
	SafeOffObservedAt         string                   `json:"safe_off_observed_at"`
	CompletedAt               string                   `json:"completed_at"`
}

func canonicalBootTransitionEvidence(evidence BootTransitionEvidence) ([]byte, error) {
	return json.Marshal(bootTransitionEvidenceDigestMaterial{
		SchemaVersion: evidence.SchemaVersion, TransitionKey: evidence.TransitionKey, Generation: evidence.Generation,
		Action: evidence.Action, StartedAt: canonicalBootTransitionTime(evidence.StartedAt), PromptID: evidence.PromptID,
		PromptDigest: evidence.PromptDigest, PromptExpiresAt: canonicalBootTransitionTime(evidence.PromptExpiresAt), Operator: evidence.Operator,
		PowerOffObservedAt:     canonicalBootTransitionTime(evidence.PowerOffObservedAt),
		USBAbsentObservedAt:    canonicalBootTransitionTime(evidence.USBAbsentObservedAt),
		ColdIntervalEndsAt:     canonicalBootTransitionTime(evidence.ColdIntervalEndsAt),
		OperatorAcknowledgedAt: canonicalBootTransitionTime(evidence.OperatorAcknowledgedAt),
		PowerAppliedAt:         canonicalBootTransitionTime(evidence.PowerAppliedAt), ModeObservedAt: canonicalBootTransitionTime(evidence.ModeObservedAt),
		ObservedMode: evidence.ObservedMode, RPIBootSysfsPath: evidence.RPIBootSysfsPath,
		RPIBootEligibleTargets: evidence.RPIBootEligibleTargets, UARTPath: evidence.UARTPath,
		UARTOutputDigest: evidence.UARTOutputDigest, RPIBootObservationMethod: evidence.RPIBootObservationMethod,
		RPIBootPollIntervalNanos:  evidence.RPIBootPollInterval.Nanoseconds(),
		RPIBootNotObservedThrough: canonicalBootTransitionTime(evidence.RPIBootNotObservedThrough),
		ReleasePromptID:           evidence.ReleasePromptID, ReleasePromptDigest: evidence.ReleasePromptDigest,
		ReleasePromptExpiresAt: canonicalBootTransitionTime(evidence.ReleasePromptExpiresAt),
		ReleaseOperator:        evidence.ReleaseOperator, OperatorReleasedAt: canonicalBootTransitionTime(evidence.OperatorReleasedAt),
		SafeOffObservedAt: canonicalBootTransitionTime(evidence.SafeOffObservedAt), CompletedAt: canonicalBootTransitionTime(evidence.CompletedAt),
	})
}

func canonicalBootTransitionTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func validBootTransitionUpdate(existing, next BootTransition) error {
	if err := existing.Validate(); err != nil {
		return fmt.Errorf("existing boot transition: %w", err)
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if existing.SchemaVersion != next.SchemaVersion || existing.Key != next.Key || existing.Generation != next.Generation ||
		existing.Action != next.Action || !existing.StartedAt.Equal(next.StartedAt) ||
		!existing.PowerOffObservedAt.Equal(next.PowerOffObservedAt) || !existing.USBAbsentObservedAt.Equal(next.USBAbsentObservedAt) ||
		!existing.ColdIntervalEndsAt.Equal(next.ColdIntervalEndsAt) || existing.PromptID != next.PromptID ||
		existing.PromptDigest != next.PromptDigest || !existing.PromptExpiresAt.Equal(next.PromptExpiresAt) {
		return errors.New("boot transition immutable bindings cannot change")
	}
	if !bootTransitionProgressIsPrefix(existing, next) {
		return errors.New("boot transition recorded progress cannot change")
	}
	if existing.IsTerminal() {
		if existing != next {
			return errors.New("terminal boot transition cannot change")
		}
		return nil
	}
	if next.UpdatedAt.Before(existing.UpdatedAt) {
		return errors.New("boot transition update time cannot move backwards")
	}
	if next.IsTerminal() {
		if next.Status == BootTransitionCompleted {
			if next.Action.RequestedBootMode == BootModeRPIBoot && existing.Status != BootTransitionOperatorReleased {
				return errors.New("RPIBOOT transition cannot complete before post-detection release acknowledgment")
			}
			if next.Action.RequestedBootMode == BootModeNormal && existing.Status != BootTransitionModeObserved {
				return errors.New("normal transition cannot complete before direct mode observation")
			}
		}
		return nil
	}
	existingRank, _ := bootTransitionRank(existing.Status)
	nextRank, _ := bootTransitionRank(next.Status)
	if nextRank < existingRank || nextRank > existingRank+1 {
		return errors.New("boot transition status must advance one state at a time")
	}
	if nextRank == existingRank && existing != next {
		return errors.New("boot transition cannot mutate without advancing its status")
	}
	return nil
}

func bootTransitionProgressIsPrefix(existing, next BootTransition) bool {
	if !existing.OperatorAcknowledgedAt.IsZero() &&
		(existing.Operator != next.Operator || !existing.OperatorAcknowledgedAt.Equal(next.OperatorAcknowledgedAt)) {
		return false
	}
	if !existing.PowerAppliedAt.IsZero() && !existing.PowerAppliedAt.Equal(next.PowerAppliedAt) {
		return false
	}
	if !existing.ModeObservedAt.IsZero() &&
		(!existing.ModeObservedAt.Equal(next.ModeObservedAt) || existing.ObservedMode != next.ObservedMode ||
			existing.RPIBootSysfsPath != next.RPIBootSysfsPath || existing.RPIBootEligibleTargets != next.RPIBootEligibleTargets ||
			existing.UARTPath != next.UARTPath || existing.UARTOutputDigest != next.UARTOutputDigest ||
			existing.RPIBootObservationMethod != next.RPIBootObservationMethod || existing.RPIBootPollInterval != next.RPIBootPollInterval ||
			!existing.RPIBootNotObservedThrough.Equal(next.RPIBootNotObservedThrough) || existing.ReleasePromptID != next.ReleasePromptID ||
			existing.ReleasePromptDigest != next.ReleasePromptDigest || !existing.ReleasePromptExpiresAt.Equal(next.ReleasePromptExpiresAt)) {
		return false
	}
	if !existing.OperatorReleasedAt.IsZero() &&
		(existing.ReleaseOperator != next.ReleaseOperator || !existing.OperatorReleasedAt.Equal(next.OperatorReleasedAt)) {
		return false
	}
	if !existing.SafeOffObservedAt.IsZero() && !existing.SafeOffObservedAt.Equal(next.SafeOffObservedAt) {
		return false
	}
	if !existing.CompletedAt.IsZero() && !existing.CompletedAt.Equal(next.CompletedAt) {
		return false
	}
	if existing.Failure != BootTransitionFailureNone && existing.Failure != next.Failure {
		return false
	}
	if existing.EvidenceDigest != "" && existing.EvidenceDigest != next.EvidenceDigest {
		return false
	}
	return true
}
