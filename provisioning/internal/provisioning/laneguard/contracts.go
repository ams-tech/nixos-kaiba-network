// Package laneguard defines the narrow privileged boundary that owns one
// physical Raspberry Pi provisioning lane. Requests identify approved typed
// operations; they never contain executable names, payload paths, device
// selectors, or GPIO paths.
package laneguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const ContractSchemaVersion = "provisioning.kaiba.network/lane-guard/v1alpha1"

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	ErrNoPlan                 = errors.New("no approved plan is loaded")
	ErrPlanMismatch           = errors.New("request does not match the approved plan")
	ErrPlanLocked             = errors.New("the approved plan is locked")
	ErrTargetContinuity       = errors.New("target continuity check failed")
	ErrPrestateMismatch       = errors.New("direct target prestate does not match the approved plan")
	ErrPoststateMismatch      = errors.New("direct target poststate does not match the approved plan")
	ErrOutOfOrder             = errors.New("operation is out of order")
	ErrLeaseInvalid           = errors.New("claim lease has insufficient remaining lifetime")
	ErrReconciliationRequired = errors.New("operation outcome requires direct reconciliation")
	ErrQuarantined            = errors.New("operation or target is quarantined")
)

// Operation is a closed allowlist. The hardware adapter maps these values to
// build-time-pinned artifacts and implementations.
type Operation string

const (
	OperationProgramCustomerKeyAndEEPROM Operation = "program_customer_key_and_eeprom"
	OperationColdPowerCycle              Operation = "cold_power_cycle"
	// OperationVerifySignedBoot is retained as a deprecated wire identifier so
	// old inputs fail with an explicit unsupported-operation error. It is not
	// part of the accepted plan vocabulary; cold_power_cycle captures and
	// validates the signed-boot evidence atomically.
	OperationVerifySignedBoot     Operation = "verify_signed_boot"
	OperationOwnedReadback        Operation = "owned_readback"
	OperationTestOwnedRecovery    Operation = "test_owned_recovery"
	OperationPostRecoveryReadback Operation = "post_recovery_readback"
	OperationTestNegativeBoot     Operation = "test_negative_boot"
	OperationTestRootIntegrity    Operation = "test_root_integrity"
)

type OperationClass string

const (
	ClassReadOnly     OperationClass = "read_only"
	ClassReversible   OperationClass = "reversible"
	ClassIrreversible OperationClass = "irreversible"
)

var operationOrder = map[Operation]int{
	OperationProgramCustomerKeyAndEEPROM: 10,
	OperationColdPowerCycle:              20,
	OperationOwnedReadback:               40,
	OperationTestOwnedRecovery:           50,
	OperationPostRecoveryReadback:        60,
	OperationTestNegativeBoot:            70,
	OperationTestRootIntegrity:           80,
}

func operationClass(operation Operation) (OperationClass, bool) {
	switch operation {
	case OperationProgramCustomerKeyAndEEPROM:
		return ClassIrreversible, true
	case OperationColdPowerCycle, OperationTestOwnedRecovery, OperationTestNegativeBoot, OperationTestRootIntegrity:
		return ClassReversible, true
	case OperationOwnedReadback, OperationPostRecoveryReadback:
		return ClassReadOnly, true
	default:
		return "", false
	}
}

// GPIODescriptor identifies the one configured power-relay line. It is part
// of daemon configuration and deliberately absent from ExecuteRequest.
type GPIODescriptor struct {
	ChipPath  string `json:"chip_path"`
	Offset    uint32 `json:"offset"`
	ActiveLow bool   `json:"active_low"`
}

// Config fixes all physical resources owned by a guard instance.
type Config struct {
	SchemaVersion     string         `json:"schema_version"`
	StationID         string         `json:"station_id"`
	LaneID            string         `json:"lane_id"`
	RPIBootSysfsPath  string         `json:"rpiboot_sysfs_path"`
	UARTPath          string         `json:"uart_path"`
	PowerGPIO         GPIODescriptor `json:"power_gpio"`
	LeaseSafetyMargin time.Duration  `json:"lease_safety_margin"`
}

func (config Config) Validate() error {
	if config.SchemaVersion != "" && config.SchemaVersion != ContractSchemaVersion {
		return fmt.Errorf("unsupported schema version %q", config.SchemaVersion)
	}
	if !identifierPattern.MatchString(config.StationID) {
		return errors.New("station ID is invalid")
	}
	if !identifierPattern.MatchString(config.LaneID) {
		return errors.New("lane ID is invalid")
	}
	if !fixedChild(config.RPIBootSysfsPath, "/sys/bus/usb/devices/") {
		return errors.New("RPIBOOT path must identify one fixed child of /sys/bus/usb/devices")
	}
	if !fixedChild(config.UARTPath, "/dev/serial/by-id/") {
		return errors.New("UART path must identify one fixed /dev/serial/by-id device")
	}
	if !strings.HasPrefix(config.PowerGPIO.ChipPath, "/dev/gpiochip") || filepath.Clean(config.PowerGPIO.ChipPath) != config.PowerGPIO.ChipPath {
		return errors.New("GPIO chip must be a fixed /dev/gpiochip path")
	}
	if config.LeaseSafetyMargin < 0 {
		return errors.New("lease safety margin must not be negative")
	}
	return nil
}

func fixedChild(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || filepath.Clean(value) != value {
		return false
	}
	relative := strings.TrimPrefix(value, prefix)
	return relative != "" && relative != "." && !strings.Contains(relative, "/")
}

// DirectState contains only non-secret, directly observable security state.
// It is comparable so guards can require an exact approved pre/postcondition.
type DirectState struct {
	CustomerKeyHash string `json:"customer_key_hash"`
	EEPROMHash      string `json:"eeprom_hash"`
	SecurityState   string `json:"security_state"`
	PowerState      string `json:"power_state"`
}

type Observation struct {
	EligibleTargets   int         `json:"eligible_targets"`
	RPIBootSysfsPath  string      `json:"rpiboot_sysfs_path"`
	TargetFingerprint string      `json:"target_fingerprint"`
	State             DirectState `json:"state"`
}

type OperationSpec struct {
	Sequence          uint32         `json:"sequence"`
	Operation         Operation      `json:"operation"`
	Classification    OperationClass `json:"classification"`
	OperationDigest   string         `json:"operation_digest"`
	AuthorizationID   string         `json:"authorization_id"`
	ExpectedPrestate  DirectState    `json:"expected_prestate"`
	ExpectedPoststate DirectState    `json:"expected_poststate"`
	MaximumDuration   time.Duration  `json:"maximum_duration"`
}

// Plan is the complete approved operation sequence for one target and fence
// epoch. Approval and intent receipts are required before it can be loaded.
type Plan struct {
	SchemaVersion     string          `json:"schema_version"`
	StationID         string          `json:"station_id"`
	LaneID            string          `json:"lane_id"`
	TransactionID     string          `json:"transaction_id"`
	PlanDigest        string          `json:"plan_digest"`
	TargetFingerprint string          `json:"target_fingerprint"`
	FenceEpoch        uint64          `json:"fence_epoch"`
	ApprovalID        string          `json:"approval_id"`
	IntentReceipt     string          `json:"intent_receipt"`
	Operations        []OperationSpec `json:"operations"`
}

func (plan Plan) Validate(config Config) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("lane config: %w", err)
	}
	if plan.SchemaVersion != ContractSchemaVersion {
		return fmt.Errorf("unsupported plan schema version %q", plan.SchemaVersion)
	}
	if plan.StationID != config.StationID || plan.LaneID != config.LaneID {
		return fmt.Errorf("%w: station or lane identity", ErrPlanMismatch)
	}
	if !identifierPattern.MatchString(plan.TransactionID) || !identifierPattern.MatchString(plan.TargetFingerprint) {
		return errors.New("plan transaction or target identity is invalid")
	}
	if !digestPattern.MatchString(plan.PlanDigest) {
		return errors.New("plan digest must be a canonical sha256 digest")
	}
	if plan.FenceEpoch == 0 || plan.ApprovalID == "" || plan.IntentReceipt == "" {
		return errors.New("plan requires a fence epoch, approval, and durable intent receipt")
	}
	if len(plan.Operations) == 0 || len(plan.Operations) > len(operationOrder) {
		return errors.New("plan has an invalid operation count")
	}
	previousRank := 0
	var previousPoststate DirectState
	for index, operation := range plan.Operations {
		if operation.Sequence != uint32(index+1) {
			return errors.New("plan operation sequences must be contiguous and one-based")
		}
		class, allowed := operationClass(operation.Operation)
		rank := operationOrder[operation.Operation]
		if !allowed || rank <= previousRank {
			return errors.New("plan contains an unknown, duplicate, or out-of-order operation")
		}
		if operation.Classification != class {
			return errors.New("operation classification does not match the closed allowlist")
		}
		if !digestPattern.MatchString(operation.OperationDigest) || operation.AuthorizationID == "" {
			return errors.New("every operation requires a canonical digest and authorization")
		}
		if operation.MaximumDuration <= 0 {
			return errors.New("every operation requires a positive maximum duration")
		}
		if index > 0 && operation.ExpectedPrestate != previousPoststate {
			return errors.New("an operation prestate does not match the preceding postcondition")
		}
		previousRank = rank
		previousPoststate = operation.ExpectedPoststate
	}
	if plan.Operations[0].Operation != OperationProgramCustomerKeyAndEEPROM {
		return errors.New("the initial secure-boot plan must begin with the ownership commit")
	}
	return nil
}

// ExecuteRequest repeats every security-relevant binding. Physical paths and
// payload selectors are intentionally not request fields.
type ExecuteRequest struct {
	SchemaVersion     string      `json:"schema_version"`
	StationID         string      `json:"station_id"`
	LaneID            string      `json:"lane_id"`
	TransactionID     string      `json:"transaction_id"`
	PlanDigest        string      `json:"plan_digest"`
	TargetFingerprint string      `json:"target_fingerprint"`
	FenceEpoch        uint64      `json:"fence_epoch"`
	ApprovalID        string      `json:"approval_id"`
	IntentReceipt     string      `json:"intent_receipt"`
	Sequence          uint32      `json:"sequence"`
	OperationDigest   string      `json:"operation_digest"`
	AuthorizationID   string      `json:"authorization_id"`
	ExpectedPrestate  DirectState `json:"expected_prestate"`
	ClaimExpiresAt    time.Time   `json:"claim_expires_at"`
}

type OperationResult struct {
	OutputDigest  string `json:"output_digest"`
	BindingDigest string `json:"binding_digest"`
	Detail        string `json:"detail"`
}
