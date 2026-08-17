// Package plancompiler constructs the closed Raspberry Pi 5 secure-boot lane
// plan and binds it to independently persisted control and audit authority.
// It does not expose hardware paths, device selectors, or executable payloads.
package plancompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

var (
	ErrInvalidDraft = errors.New("invalid lane plan draft")
	identifier      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	prestateDigestDomain = "kaiba.provisioning.plan-compiler.prestate.v1alpha1"
	ZeroCustomerKeyHash  = controlplane.UnownedCustomerKeyHash
)

// DraftInput contains only values that are known before approval. Operation
// names, classifications, sequence numbers, and prestate chaining are fixed by
// BuildDraft rather than supplied by a caller.
type DraftInput struct {
	StationID         string
	LaneID            string
	TransactionID     string
	Release           releasebinding.Binding
	TargetFingerprint string
	FenceEpoch        uint64
	ApprovalExpiresAt time.Time
	InitialState      laneguard.DirectState
	AuthorizationIDs  [7]string
	MaximumDurations  [7]time.Duration
}

// Draft is an immutable, non-executable plan snapshot. ApprovalID and
// IntentReceipt remain empty until Bind authenticates both authorities.
type Draft struct {
	plan laneguard.Plan
}

var operations = [7]struct {
	operation      laneguard.Operation
	classification laneguard.OperationClass
}{
	{laneguard.OperationProgramCustomerKeyAndEEPROM, laneguard.ClassIrreversible},
	{laneguard.OperationColdPowerCycle, laneguard.ClassReversible},
	{laneguard.OperationOwnedReadback, laneguard.ClassReadOnly},
	{laneguard.OperationTestOwnedRecovery, laneguard.ClassReversible},
	{laneguard.OperationPostRecoveryReadback, laneguard.ClassReadOnly},
	{laneguard.OperationTestNegativeBoot, laneguard.ClassReversible},
	{laneguard.OperationTestRootIntegrity, laneguard.ClassReversible},
}

// BuildDraft constructs and hashes the exact seven-operation plan. It never
// accepts a caller-selected operation list or classification.
func BuildDraft(input DraftInput) (Draft, error) {
	if !identifier.MatchString(input.StationID) || !identifier.MatchString(input.LaneID) || !identifier.MatchString(input.TransactionID) {
		return Draft{}, fmt.Errorf("%w: station, lane, or transaction identity is invalid", ErrInvalidDraft)
	}
	if !validDigest(input.TargetFingerprint) || input.FenceEpoch == 0 {
		return Draft{}, fmt.Errorf("%w: target fingerprint or fence epoch is invalid", ErrInvalidDraft)
	}
	if err := input.Release.Validate(); err != nil {
		return Draft{}, fmt.Errorf("%w: release binding: %v", ErrInvalidDraft, err)
	}
	if input.Release.ExpectedCustomerKeyHash == ZeroCustomerKeyHash {
		return Draft{}, fmt.Errorf("%w: release expected customer key must be nonzero", ErrInvalidDraft)
	}
	if input.ApprovalExpiresAt.IsZero() {
		return Draft{}, fmt.Errorf("%w: approval expiry is required", ErrInvalidDraft)
	}
	if err := validateState(input.InitialState); err != nil {
		return Draft{}, err
	}
	if input.InitialState.CustomerKeyHash != ZeroCustomerKeyHash || input.InitialState.SecurityState != "fresh" || input.InitialState.PowerState != "powered_off" {
		return Draft{}, fmt.Errorf("%w: initial state must be a fresh, completely powered-off target", ErrInvalidDraft)
	}
	expectedOwnedState := laneguard.DirectState{
		CustomerKeyHash: input.Release.ExpectedCustomerKeyHash,
		EEPROMHash:      input.Release.ExpectedEEPROMDigest,
		SecurityState:   "owned",
		PowerState:      "powered_off",
	}

	plan := laneguard.Plan{
		SchemaVersion:     laneguard.ContractSchemaVersion,
		StationID:         input.StationID,
		LaneID:            input.LaneID,
		TransactionID:     input.TransactionID,
		Release:           input.Release,
		TargetFingerprint: input.TargetFingerprint,
		FenceEpoch:        input.FenceEpoch,
		ApprovalExpiresAt: input.ApprovalExpiresAt.UTC(),
		Operations:        make([]laneguard.OperationSpec, len(operations)),
	}
	prestate := input.InitialState
	for index, policy := range operations {
		if !identifier.MatchString(input.AuthorizationIDs[index]) {
			return Draft{}, fmt.Errorf("%w: authorization %d is invalid", ErrInvalidDraft, index+1)
		}
		if input.MaximumDurations[index] <= 0 {
			return Draft{}, fmt.Errorf("%w: operation %d duration must be positive", ErrInvalidDraft, index+1)
		}
		// The physical adapter's observation boundary always removes power
		// before returning. Operation-specific boot and recovery evidence is
		// carried in the operation result, not in this direct state chain.
		plan.Operations[index] = laneguard.OperationSpec{
			Sequence:          uint32(index + 1),
			Operation:         policy.operation,
			Classification:    policy.classification,
			AuthorizationID:   input.AuthorizationIDs[index],
			ExpectedPrestate:  prestate,
			ExpectedPoststate: expectedOwnedState,
			MaximumDuration:   input.MaximumDurations[index],
		}
		prestate = expectedOwnedState
	}
	derived, err := plan.WithDerivedDigests()
	if err != nil {
		return Draft{}, fmt.Errorf("%w: derive lane digests: %v", ErrInvalidDraft, err)
	}
	return Draft{plan: derived}, nil
}

func validateState(state laneguard.DirectState) error {
	if !validDigest(state.CustomerKeyHash) || !validDigest(state.EEPROMHash) {
		return fmt.Errorf("%w: direct-state key and EEPROM hashes must be canonical digests", ErrInvalidDraft)
	}
	if state.SecurityState == "" || state.PowerState == "" {
		return fmt.Errorf("%w: direct-state security and power fields must not be empty", ErrInvalidDraft)
	}
	return nil
}

// PlanDigest is the value that must be independently approved and placed in
// the durable audit intent.
func (draft Draft) PlanDigest() string { return draft.plan.PlanDigest }

// InitialPrestateDigest is the canonical digest used by the control intent.
func (draft Draft) InitialPrestateDigest() string {
	if len(draft.plan.Operations) == 0 {
		return ""
	}
	return prestateDigest(draft.plan.Operations[0].ExpectedPrestate)
}

func prestateDigest(state laneguard.DirectState) string {
	material, err := json.Marshal(state)
	if err != nil {
		panic(fmt.Sprintf("marshal fixed lane prestate: %v", err))
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(prestateDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(material)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// Snapshot returns a defensive copy for approval review. It is deliberately
// not a valid executable Plan until Bind supplies authenticated envelope data.
func (draft Draft) Snapshot() laneguard.Plan { return clonePlan(draft.plan) }

func validateDraft(draft Draft) error {
	plan := draft.plan
	if plan.ApprovalID != "" || plan.IntentReceipt != "" || plan.IntentSequence != 0 || len(plan.Operations) != len(operations) {
		return fmt.Errorf("%w: draft contains authority or the wrong operation count", ErrInvalidDraft)
	}
	for index, policy := range operations {
		operation := plan.Operations[index]
		if operation.Sequence != uint32(index+1) || operation.Operation != policy.operation || operation.Classification != policy.classification {
			return fmt.Errorf("%w: operation %d differs from policy", ErrInvalidDraft, index+1)
		}
		if index > 0 && operation.ExpectedPrestate != plan.Operations[index-1].ExpectedPoststate {
			return fmt.Errorf("%w: operation %d prestate is not chained", ErrInvalidDraft, index+1)
		}
	}
	derived, err := plan.WithDerivedDigests()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDraft, err)
	}
	if derived.PlanDigest != plan.PlanDigest {
		return fmt.Errorf("%w: plan digest mismatch", ErrInvalidDraft)
	}
	for index := range plan.Operations {
		if derived.Operations[index].OperationDigest != plan.Operations[index].OperationDigest {
			return fmt.Errorf("%w: operation %d digest mismatch", ErrInvalidDraft, index+1)
		}
	}
	return nil
}

func clonePlan(plan laneguard.Plan) laneguard.Plan {
	plan.Operations = append([]laneguard.OperationSpec(nil), plan.Operations...)
	return plan
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size
}
