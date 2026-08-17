// Package rehearsal implements a software-only, non-authoritative secure-boot
// campaign rehearsal. It cannot access physical lane adapters and its terminal
// outcomes are deliberately distinct from production provisioning outcomes.
package rehearsal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const (
	ContractSchemaVersion = "kaiba.secure_boot.software_rehearsal.v1alpha1"
	OperationCount        = 7
	evidenceDigestDomain  = "kaiba.secure_boot.software_rehearsal.evidence.v1"
)

var (
	ErrInvalidContract = errors.New("invalid software rehearsal contract")
	ErrInvalidReport   = errors.New("invalid software rehearsal report")

	rehearsalIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// SafetyMode makes the absence of hardware authority part of the wire
// contract rather than an out-of-band convention.
type SafetyMode string

const SafetyModeSoftwareOnlyNoOTP SafetyMode = "software_only_no_otp"

// Authority identifies whether evidence may affect a production asset. The
// rehearsal package defines no production-authoritative value.
type Authority string

const AuthorityRehearsalOnly Authority = "rehearsal_only_non_authoritative"

// Operation is a rehearsal-local identifier. These values mirror the intended
// seven-step campaign while remaining independent of the production lane
// guard's types and implementation.
type Operation string

const (
	OperationProgramCustomerKeyAndEEPROM Operation = "program_customer_key_and_eeprom"
	OperationColdPowerCycle              Operation = "cold_power_cycle"
	OperationOwnedReadback               Operation = "owned_readback"
	OperationTestOwnedRecovery           Operation = "test_owned_recovery"
	OperationPostRecoveryReadback        Operation = "post_recovery_readback"
	OperationTestNegativeBoot            Operation = "test_negative_boot"
	OperationTestRootIntegrity           Operation = "test_root_integrity"
)

var canonicalOperations = [OperationCount]Operation{
	OperationProgramCustomerKeyAndEEPROM,
	OperationColdPowerCycle,
	OperationOwnedReadback,
	OperationTestOwnedRecovery,
	OperationPostRecoveryReadback,
	OperationTestNegativeBoot,
	OperationTestRootIntegrity,
}

// CanonicalOperations returns an independently owned copy of the complete
// rehearsal campaign.
func CanonicalOperations() []Operation {
	operations := make([]Operation, len(canonicalOperations))
	copy(operations, canonicalOperations[:])
	return operations
}

// Contract is the complete input accepted by the software rehearsal runner.
// It intentionally has no artifact paths, hardware identifiers, approvals, or
// production transaction identifiers.
type Contract struct {
	SchemaVersion string      `json:"schema_version"`
	RehearsalID   string      `json:"rehearsal_id"`
	SafetyMode    SafetyMode  `json:"safety_mode"`
	Authority     Authority   `json:"authority"`
	Operations    []Operation `json:"operations"`
}

// NewContract returns the one supported seven-operation rehearsal contract.
func NewContract(rehearsalID string) Contract {
	return Contract{
		SchemaVersion: ContractSchemaVersion,
		RehearsalID:   rehearsalID,
		SafetyMode:    SafetyModeSoftwareOnlyNoOTP,
		Authority:     AuthorityRehearsalOnly,
		Operations:    CanonicalOperations(),
	}
}

// Validate rejects contracts that weaken the software-only boundary or alter
// the exact campaign.
func (contract Contract) Validate() error {
	if contract.SchemaVersion != ContractSchemaVersion {
		return fmt.Errorf("%w: schema_version is %q", ErrInvalidContract, contract.SchemaVersion)
	}
	if !rehearsalIDPattern.MatchString(contract.RehearsalID) {
		return fmt.Errorf("%w: rehearsal_id must be a canonical lower-case identifier", ErrInvalidContract)
	}
	if contract.SafetyMode != SafetyModeSoftwareOnlyNoOTP {
		return fmt.Errorf("%w: unsupported safety_mode %q", ErrInvalidContract, contract.SafetyMode)
	}
	if contract.Authority != AuthorityRehearsalOnly {
		return fmt.Errorf("%w: unsupported authority %q", ErrInvalidContract, contract.Authority)
	}
	if len(contract.Operations) != OperationCount {
		return fmt.Errorf("%w: operation count is %d, want %d", ErrInvalidContract, len(contract.Operations), OperationCount)
	}
	for index, expected := range canonicalOperations {
		if contract.Operations[index] != expected {
			return fmt.Errorf("%w: operation %d is %q, want %q", ErrInvalidContract, index+1, contract.Operations[index], expected)
		}
	}
	return nil
}

// Phase is rehearsal-local state. Every terminal phase is visibly a rehearsal
// result and cannot be confused with a production lifecycle state.
type Phase string

const (
	PhaseReady              Phase = "rehearsal_ready"
	PhaseRunning            Phase = "rehearsal_running"
	PhaseRehearsalPassed    Phase = "rehearsal_passed"
	PhaseRehearsalFailed    Phase = "rehearsal_failed"
	PhaseRehearsalUncertain Phase = "rehearsal_uncertain"
)

// Outcome is the terminal disposition of a rehearsal campaign.
type Outcome string

const (
	OutcomeRehearsalPassed    Outcome = "rehearsal_passed"
	OutcomeRehearsalFailed    Outcome = "rehearsal_failed"
	OutcomeRehearsalUncertain Outcome = "rehearsal_uncertain"
)

// ModelState records only synthetic model progress. It does not claim that a
// device, EEPROM, OTP bank, boot medium, or power rail changed.
type ModelState string

const (
	ModelStateUnfusedFixtureReady            ModelState = "model_unfused_fixture_ready"
	ModelStateCommitPathObserved             ModelState = "model_commit_path_observed"
	ModelStateColdBootObserved               ModelState = "model_cold_boot_observed"
	ModelStateOwnedReadbackObserved          ModelState = "model_owned_readback_observed"
	ModelStateRecoveryObserved               ModelState = "model_recovery_observed"
	ModelStatePostRecoveryReadbackObserved   ModelState = "model_post_recovery_readback_observed"
	ModelStateNegativeBootRejectionObserved  ModelState = "model_negative_boot_rejection_observed"
	ModelStateRootIntegrityRejectionObserved ModelState = "model_root_integrity_rejection_observed"
)

var modelStates = [OperationCount + 1]ModelState{
	ModelStateUnfusedFixtureReady,
	ModelStateCommitPathObserved,
	ModelStateColdBootObserved,
	ModelStateOwnedReadbackObserved,
	ModelStateRecoveryObserved,
	ModelStatePostRecoveryReadbackObserved,
	ModelStateNegativeBootRejectionObserved,
	ModelStateRootIntegrityRejectionObserved,
}

// State carries explicit negative safety assertions so serialized reports can
// be rejected if a future change ever claims a physical or OTP action.
type State struct {
	Phase                     Phase      `json:"phase"`
	ModelState                ModelState `json:"model_state"`
	CompletedOperations       int        `json:"completed_operations"`
	NextSequence              int        `json:"next_sequence"`
	PhysicalMutationPerformed bool       `json:"physical_mutation_performed"`
	OTPWriteCount             int        `json:"otp_write_count"`
}

// StepDisposition describes one synthetic operation attempt.
type StepDisposition string

const (
	StepSucceeded StepDisposition = "rehearsal_step_succeeded"
	StepFailed    StepDisposition = "rehearsal_step_failed"
	StepUncertain StepDisposition = "rehearsal_step_uncertain"
)

// Evidence is deterministic synthetic model output. The safety booleans must
// remain false and are covered by Digest.
type Evidence struct {
	Kind                    string          `json:"kind"`
	Sequence                int             `json:"sequence"`
	Operation               Operation       `json:"operation"`
	Disposition             StepDisposition `json:"disposition"`
	Before                  ModelState      `json:"before"`
	After                   ModelState      `json:"after"`
	Observation             string          `json:"observation"`
	Detail                  string          `json:"detail"`
	PhysicalActionAttempted bool            `json:"physical_action_attempted"`
	OTPWriteAttempted       bool            `json:"otp_write_attempted"`
	Digest                  string          `json:"digest"`
}

const EvidenceKindSyntheticModel = "synthetic_rehearsal_model_observation"

// Report is the only serialized campaign result produced by this package.
type Report struct {
	SchemaVersion string     `json:"schema_version"`
	RehearsalID   string     `json:"rehearsal_id"`
	SafetyMode    SafetyMode `json:"safety_mode"`
	Authority     Authority  `json:"authority"`
	Outcome       Outcome    `json:"outcome"`
	State         State      `json:"state"`
	Evidence      []Evidence `json:"evidence"`
	Detail        string     `json:"detail"`
}

func (report Report) Validate() error {
	if report.SchemaVersion != ContractSchemaVersion {
		return fmt.Errorf("%w: schema_version is %q", ErrInvalidReport, report.SchemaVersion)
	}
	if !rehearsalIDPattern.MatchString(report.RehearsalID) {
		return fmt.Errorf("%w: invalid rehearsal_id", ErrInvalidReport)
	}
	if report.SafetyMode != SafetyModeSoftwareOnlyNoOTP || report.Authority != AuthorityRehearsalOnly {
		return fmt.Errorf("%w: report crossed the rehearsal authority boundary", ErrInvalidReport)
	}
	if report.State.PhysicalMutationPerformed || report.State.OTPWriteCount != 0 {
		return fmt.Errorf("%w: report claims a physical or OTP mutation", ErrInvalidReport)
	}
	completed := report.State.CompletedOperations
	if completed < 0 || completed > OperationCount || report.State.NextSequence != completed+1 {
		return fmt.Errorf("%w: invalid operation progress", ErrInvalidReport)
	}
	if report.State.ModelState != modelStates[completed] {
		return fmt.Errorf("%w: model state does not match operation progress", ErrInvalidReport)
	}

	expectedEvidence := completed
	terminalDisposition := StepSucceeded
	switch report.Outcome {
	case OutcomeRehearsalPassed:
		if report.State.Phase != PhaseRehearsalPassed || completed != OperationCount {
			return fmt.Errorf("%w: passed outcome is not complete", ErrInvalidReport)
		}
	case OutcomeRehearsalFailed:
		if report.State.Phase != PhaseRehearsalFailed || completed >= OperationCount {
			return fmt.Errorf("%w: failed outcome has invalid state", ErrInvalidReport)
		}
		expectedEvidence++
		terminalDisposition = StepFailed
	case OutcomeRehearsalUncertain:
		if report.State.Phase != PhaseRehearsalUncertain || completed >= OperationCount {
			return fmt.Errorf("%w: uncertain outcome has invalid state", ErrInvalidReport)
		}
		expectedEvidence++
		terminalDisposition = StepUncertain
	default:
		return fmt.Errorf("%w: unsupported outcome %q", ErrInvalidReport, report.Outcome)
	}
	if len(report.Evidence) != expectedEvidence {
		return fmt.Errorf("%w: evidence count is %d, want %d", ErrInvalidReport, len(report.Evidence), expectedEvidence)
	}
	for index, evidence := range report.Evidence {
		if evidence.Kind != EvidenceKindSyntheticModel || evidence.Sequence != index+1 || evidence.Operation != canonicalOperations[index] {
			return fmt.Errorf("%w: evidence %d does not match the canonical campaign", ErrInvalidReport, index+1)
		}
		if evidence.PhysicalActionAttempted || evidence.OTPWriteAttempted {
			return fmt.Errorf("%w: evidence %d claims a physical or OTP action", ErrInvalidReport, index+1)
		}
		if evidence.Before != modelStates[index] {
			return fmt.Errorf("%w: evidence %d has the wrong prestate", ErrInvalidReport, index+1)
		}
		wantDisposition := StepSucceeded
		wantAfter := modelStates[index+1]
		if index == len(report.Evidence)-1 && terminalDisposition != StepSucceeded {
			wantDisposition = terminalDisposition
			wantAfter = modelStates[index]
		}
		if evidence.Disposition != wantDisposition || evidence.After != wantAfter {
			return fmt.Errorf("%w: evidence %d has an invalid disposition or poststate", ErrInvalidReport, index+1)
		}
		if evidence.Observation == "" || evidence.Detail == "" {
			return fmt.Errorf("%w: evidence %d is incomplete", ErrInvalidReport, index+1)
		}
		if evidence.Digest != evidenceDigest(evidence) {
			return fmt.Errorf("%w: evidence %d digest mismatch", ErrInvalidReport, index+1)
		}
	}
	if report.Detail == "" {
		return fmt.Errorf("%w: detail is required", ErrInvalidReport)
	}
	return nil
}

type evidenceDigestMaterial struct {
	Kind                    string          `json:"kind"`
	Sequence                int             `json:"sequence"`
	Operation               Operation       `json:"operation"`
	Disposition             StepDisposition `json:"disposition"`
	Before                  ModelState      `json:"before"`
	After                   ModelState      `json:"after"`
	Observation             string          `json:"observation"`
	Detail                  string          `json:"detail"`
	PhysicalActionAttempted bool            `json:"physical_action_attempted"`
	OTPWriteAttempted       bool            `json:"otp_write_attempted"`
}

func evidenceDigest(evidence Evidence) string {
	material, err := json.Marshal(evidenceDigestMaterial{
		Kind: evidence.Kind, Sequence: evidence.Sequence, Operation: evidence.Operation,
		Disposition: evidence.Disposition, Before: evidence.Before, After: evidence.After,
		Observation: evidence.Observation, Detail: evidence.Detail,
		PhysicalActionAttempted: evidence.PhysicalActionAttempted,
		OTPWriteAttempted:       evidence.OTPWriteAttempted,
	})
	if err != nil {
		panic(fmt.Sprintf("marshal fixed rehearsal evidence: %v", err))
	}
	domainSeparated := make([]byte, 0, len(evidenceDigestDomain)+1+len(material))
	domainSeparated = append(domainSeparated, evidenceDigestDomain...)
	domainSeparated = append(domainSeparated, 0)
	domainSeparated = append(domainSeparated, material...)
	digest := sha256.Sum256(domainSeparated)
	return "sha256:" + hex.EncodeToString(digest[:])
}
