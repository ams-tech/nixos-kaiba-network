package plancompiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

var (
	ErrAuthorityMismatch  = errors.New("lane plan authority mismatch")
	ErrApprovalExpired    = errors.New("lane plan approval expired")
	ErrStaleClaim         = errors.New("lane plan claim is stale")
	ErrInvalidAuditIntent = errors.New("invalid durable lane plan audit intent")
)

// Authority is one control/audit snapshot read immediately before lane-plan
// installation. Bind validates its internal bindings; the caller remains
// responsible for authenticating the services and obtaining Now from a trusted
// clock.
type Authority struct {
	Transaction       controlplane.Transaction
	ApprovalReceipt   auditlog.Receipt
	ApprovalRecord    auditlog.Record
	IntentReceipt     auditlog.Receipt
	IntentRecord      auditlog.Record
	Now               time.Time
	LeaseSafetyMargin time.Duration
}

// BoundPlan is immutable authority for one currently pending operation. A
// caller must fetch and Bind fresh authority after every successful operation,
// claim change, or approval change.
type BoundPlan struct {
	plan           laneguard.Plan
	claimExpiresAt time.Time
	operationIndex int
}

// RehearsalAuthoritySummary proves that the software-only rehearsal exercised
// the expected control/audit bindings without exposing an executable plan or
// request.
type RehearsalAuthoritySummary struct {
	TransactionID          string
	ResourceVersion        uint64
	FenceEpoch             uint64
	PlanDigest             string
	ApprovalID             string
	IntentReceipt          string
	PlanOperationCount     int
	ValidatedIntentCount   int
	ExecutableRequestCount int
	PendingSequence        uint32
	InitialCustomerKeyHash string
	OwnedCustomerKeyHash   string
}

type actorPolicy struct {
	approvalRole string
	intentRole   string
}

var (
	productionActors = actorPolicy{approvalRole: "approver", intentRole: "provisioning_station"}
	rehearsalActors  = actorPolicy{approvalRole: "software_rehearsal_approver", intentRole: "software_rehearsal"}
)

// Bind authenticates the draft's previously approved digest and the separate
// durable audit intent for exactly one currently pending operation.
func Bind(draft Draft, authority Authority) (BoundPlan, error) {
	return bindWithActorPolicy(draft, authority, productionActors)
}

// VerifySoftwareRehearsalAuthority validates the deliberately synthetic actor
// provenance used by the software-only rehearsal. It returns scalar evidence
// only, so rehearsal authority cannot be passed to the lane guard.
func VerifySoftwareRehearsalAuthority(draft Draft, authority Authority) (RehearsalAuthoritySummary, error) {
	bound, err := bindWithActorPolicy(draft, authority, rehearsalActors)
	if err != nil {
		return RehearsalAuthoritySummary{}, err
	}
	plan := bound.plan
	return RehearsalAuthoritySummary{
		TransactionID: authority.Transaction.ID, ResourceVersion: authority.Transaction.ResourceVersion,
		FenceEpoch: plan.FenceEpoch, PlanDigest: plan.PlanDigest,
		ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt,
		PlanOperationCount: len(plan.Operations), ValidatedIntentCount: 1, ExecutableRequestCount: 0,
		PendingSequence:        plan.Operations[bound.operationIndex].Sequence,
		InitialCustomerKeyHash: plan.Operations[0].ExpectedPrestate.CustomerKeyHash,
		OwnedCustomerKeyHash:   plan.Operations[0].ExpectedPoststate.CustomerKeyHash,
	}, nil
}

func bindWithActorPolicy(draft Draft, authority Authority, actors actorPolicy) (BoundPlan, error) {
	if err := validateDraft(draft); err != nil {
		return BoundPlan{}, err
	}
	if authority.Now.IsZero() || authority.LeaseSafetyMargin < 0 {
		return BoundPlan{}, fmt.Errorf("%w: current time or lease margin is invalid", ErrAuthorityMismatch)
	}
	now := authority.Now.UTC()
	transaction := authority.Transaction
	plan := draft.plan

	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ResourceVersion == 0 ||
		transaction.ID != plan.TransactionID || transaction.Status != controlplane.StatusMutationInProgress ||
		transaction.Quarantine != nil || transaction.SecurityApplied != nil || transaction.Abort != nil {
		return BoundPlan{}, fmt.Errorf("%w: transaction identity or status", ErrAuthorityMismatch)
	}
	if transaction.TransactionDigest != transactionDigest(transaction) {
		return BoundPlan{}, fmt.Errorf("%w: transaction digest", ErrAuthorityMismatch)
	}
	if transaction.BundleDigest != plan.Release.SignedReleaseManifestDigest ||
		transaction.ExpectedCustomerKeyHash != plan.Release.ExpectedCustomerKeyHash {
		return BoundPlan{}, fmt.Errorf("%w: transaction release", ErrAuthorityMismatch)
	}

	claim := transaction.ActiveClaim
	if claim == nil || claim.ID == "" || claim.Status != controlplane.ClaimActive || claim.Mode != controlplane.ClaimModeMutation ||
		claim.ClosedAt != nil || claim.StationID != plan.StationID || claim.LaneID != plan.LaneID ||
		claim.AssetID != transaction.AssetID || claim.FenceEpoch != plan.FenceEpoch || transaction.FenceEpoch != plan.FenceEpoch ||
		claim.AcquiredAt.IsZero() || claim.AcquiredAt.After(now) || !claim.ExpiresAt.After(claim.AcquiredAt) {
		return BoundPlan{}, ErrStaleClaim
	}
	if !containsExactCampaign(claim.AllowedStages) {
		return BoundPlan{}, fmt.Errorf("%w: claim does not authorize the complete campaign", ErrStaleClaim)
	}
	target := transaction.Target
	if target == nil || target.Fingerprint != plan.TargetFingerprint || target.FenceEpoch != plan.FenceEpoch ||
		target.CustomerKeyHash != transaction.ExpectedPrestateCustomerKeyHash ||
		target.CustomerKeyHash != plan.Operations[0].ExpectedPrestate.CustomerKeyHash || !validDigest(target.ObservationDigest) ||
		target.BoundAt.IsZero() || target.BoundAt.After(now) {
		return BoundPlan{}, fmt.Errorf("%w: target binding", ErrAuthorityMismatch)
	}

	approval := transaction.Approval
	if approval == nil || approval.ID == "" || approval.ApproverID == "" ||
		approval.TransactionDigest != transaction.TransactionDigest || approval.PlanDigest != plan.PlanDigest ||
		approval.StationID != plan.StationID || approval.LaneID != plan.LaneID || approval.FenceEpoch != plan.FenceEpoch ||
		approval.TargetFingerprint != plan.TargetFingerprint || approval.Release != plan.Release ||
		!containsExactCampaign(approval.AllowedOperations) || !validDigest(approval.AuditReceiptID) ||
		approval.ApprovedAt.IsZero() || approval.ApprovedAt.After(now) || !approval.ExpiresAt.Equal(plan.ApprovalExpiresAt) ||
		!approval.ExpiresAt.After(approval.ApprovedAt) || approval.ExpiresAt.Sub(approval.ApprovedAt) > 24*time.Hour {
		return BoundPlan{}, fmt.Errorf("%w: approval binding", ErrAuthorityMismatch)
	}
	if !now.Before(approval.ExpiresAt) {
		return BoundPlan{}, ErrApprovalExpired
	}
	if err := validateAuditApproval(plan, approval, authority.ApprovalReceipt, authority.ApprovalRecord, now, actors.approvalRole); err != nil {
		return BoundPlan{}, err
	}

	operationIndex, intent, err := validateControlOperations(plan, transaction.Operations, now)
	if err != nil {
		return BoundPlan{}, err
	}
	operation := plan.Operations[operationIndex]
	if !laneguard.LeaseCoversOperation(now, claim.ExpiresAt, operation.MaximumDuration, authority.LeaseSafetyMargin) {
		return BoundPlan{}, ErrStaleClaim
	}
	if err := validateAuditIntent(plan, operation, intent, authority.IntentReceipt, authority.IntentRecord, now, actors.intentRole); err != nil {
		return BoundPlan{}, err
	}
	if authority.ApprovalRecord.Sequence >= authority.IntentRecord.Sequence ||
		approval.ApprovedAt.After(authority.IntentRecord.RecordedAt) {
		return BoundPlan{}, fmt.Errorf("%w: approval and intent record ordering", ErrInvalidAuditIntent)
	}

	bound := clonePlan(plan)
	bound.ApprovalID = approval.ID
	bound.IntentReceipt = authority.IntentReceipt.ReceiptID
	bound.IntentSequence = operation.Sequence
	return BoundPlan{plan: bound, claimExpiresAt: claim.ExpiresAt.UTC(), operationIndex: operationIndex}, nil
}

// Load installs the opaque, authority-bound plan directly into a lane guard.
// Callers receive only the current ExecuteRequest, not a mutable plan envelope.
func (bound BoundPlan) Load(ctx context.Context, guard *laneguard.Guard) error {
	if guard == nil {
		return errors.New("lane guard is required")
	}
	return guard.LoadPlan(ctx, clonePlan(bound.plan))
}

// ExecuteRequest returns the one request whose durable control/audit intent is
// currently pending. A successful operation must be recorded and a new intent
// bound before the next sequence can be emitted.
func (bound BoundPlan) ExecuteRequest() (laneguard.ExecuteRequest, error) {
	if bound.operationIndex < 0 || bound.operationIndex >= len(bound.plan.Operations) {
		return laneguard.ExecuteRequest{}, fmt.Errorf("%w: bound plan has no current operation", ErrAuthorityMismatch)
	}
	operation := bound.plan.Operations[bound.operationIndex]
	return laneguard.ExecuteRequest{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     bound.plan.StationID, LaneID: bound.plan.LaneID,
		TransactionID: bound.plan.TransactionID, PlanDigest: bound.plan.PlanDigest,
		Release: bound.plan.Release, TargetFingerprint: bound.plan.TargetFingerprint,
		FenceEpoch: bound.plan.FenceEpoch, ApprovalID: bound.plan.ApprovalID,
		ApprovalExpiresAt: bound.plan.ApprovalExpiresAt, IntentReceipt: bound.plan.IntentReceipt,
		Sequence: operation.Sequence, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, ExpectedPrestate: operation.ExpectedPrestate,
		ClaimExpiresAt: bound.claimExpiresAt,
	}, nil
}

func validateControlOperations(plan laneguard.Plan, records []controlplane.OperationRecord, now time.Time) (int, controlplane.OperationRecord, error) {
	if len(records) == 0 || len(records) > len(plan.Operations) {
		return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: expected one pending operation after a successful plan prefix", ErrAuthorityMismatch)
	}
	seenIDs := make(map[string]struct{}, len(records))
	for index, record := range records {
		operation := plan.Operations[index]
		if record.ID == "" || record.Operation != string(operation.Operation) ||
			record.PlanDigest != plan.PlanDigest || record.Release != plan.Release ||
			!record.ApprovalExpiresAt.Equal(plan.ApprovalExpiresAt) || record.InputDigest != plan.PlanDigest ||
			record.PrestateDigest != prestateDigest(operation.ExpectedPrestate) || !validDigest(record.IntentAuditReceiptID) ||
			record.IntentFenceEpoch != plan.FenceEpoch || record.IntentAt.IsZero() || record.IntentAt.After(now) {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: control operation %d binding", ErrAuthorityMismatch, index+1)
		}
		if _, duplicate := seenIDs[record.ID]; duplicate {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: duplicate control operation ID", ErrAuthorityMismatch)
		}
		seenIDs[record.ID] = struct{}{}
		if index == len(records)-1 {
			if record.Status != controlplane.OperationIntentRecorded || record.OutputDigest != "" || record.ObservationDigest != "" ||
				record.EvidenceAuditReceiptID != "" || record.EvidenceAt != nil || record.ReconciliationAuditReceiptID != "" {
				return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: final control operation is not one clean pending intent", ErrAuthorityMismatch)
			}
			return index, record, nil
		}
		if record.Status != controlplane.OperationSucceeded && record.Status != controlplane.OperationConfirmedApplied {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: prior control operation %d is not successfully closed", ErrAuthorityMismatch, index+1)
		}
		if !validDigest(record.OutputDigest) || !validDigest(record.ObservationDigest) || record.EvidenceAt == nil ||
			record.EvidenceAt.Before(record.IntentAt) || record.EvidenceAt.After(now) {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: prior control operation %d evidence", ErrAuthorityMismatch, index+1)
		}
		if record.Status == controlplane.OperationSucceeded && !validDigest(record.EvidenceAuditReceiptID) {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: prior control operation %d evidence receipt", ErrAuthorityMismatch, index+1)
		}
		if record.Status == controlplane.OperationConfirmedApplied && !validDigest(record.ReconciliationAuditReceiptID) {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: prior control operation %d reconciliation receipt", ErrAuthorityMismatch, index+1)
		}
		if records[index+1].IntentAt.Before(*record.EvidenceAt) {
			return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: control operation %d ordering", ErrAuthorityMismatch, index+1)
		}
	}
	return 0, controlplane.OperationRecord{}, fmt.Errorf("%w: no pending control operation", ErrAuthorityMismatch)
}

func validateAuditApproval(plan laneguard.Plan, approval *controlplane.Approval, receipt auditlog.Receipt, record auditlog.Record, now time.Time, expectedRole string) error {
	if err := validateAuditReceipt(receipt, record, approval.AuditReceiptID, now); err != nil {
		return fmt.Errorf("%w: approval %v", ErrInvalidAuditIntent, err)
	}
	if approval.ApprovedAt.Before(record.RecordedAt) {
		return fmt.Errorf("%w: approval control record predates its audit record", ErrInvalidAuditIntent)
	}
	event := record.Event
	if event.SchemaVersion != auditlog.EventSchemaVersion || event.PolicyVersion != auditlog.DefaultPolicyVersion ||
		event.EventID != approval.ID || event.TransactionID != plan.TransactionID ||
		event.StationID != plan.StationID || event.LaneID != plan.LaneID ||
		event.Stage != "plan_approval" || event.FenceEpoch != plan.FenceEpoch ||
		event.InputDigest != plan.PlanDigest || event.OutputDigest != "" || event.Result != auditlog.ResultIntentRecorded ||
		len(event.Actors) != 1 || event.Actors[0].ID != approval.ApproverID || event.Actors[0].Role != expectedRole {
		return fmt.Errorf("%w: approval event does not bind the plan and approver", ErrInvalidAuditIntent)
	}
	return nil
}

func validateAuditIntent(plan laneguard.Plan, operation laneguard.OperationSpec, intent controlplane.OperationRecord, receipt auditlog.Receipt, record auditlog.Record, now time.Time, expectedRole string) error {
	if err := validateAuditReceipt(receipt, record, intent.IntentAuditReceiptID, now); err != nil {
		return fmt.Errorf("%w: intent %v", ErrInvalidAuditIntent, err)
	}
	if intent.IntentAt.Before(record.RecordedAt) {
		return fmt.Errorf("%w: intent record ordering", ErrInvalidAuditIntent)
	}
	event := record.Event
	if event.SchemaVersion != auditlog.EventSchemaVersion || event.PolicyVersion != auditlog.DefaultPolicyVersion || event.EventID != intent.ID ||
		event.TransactionID != plan.TransactionID || event.StationID != plan.StationID || event.LaneID != plan.LaneID ||
		event.Stage != string(operation.Operation) || event.FenceEpoch != plan.FenceEpoch ||
		event.InputDigest != plan.PlanDigest || event.OutputDigest != "" || event.Result != auditlog.ResultIntentRecorded ||
		len(event.Actors) != 1 || event.Actors[0].ID != plan.StationID || event.Actors[0].Role != expectedRole {
		return fmt.Errorf("%w: event does not bind the current plan intent and actor", ErrInvalidAuditIntent)
	}
	return nil
}

func validateAuditReceipt(receipt auditlog.Receipt, record auditlog.Record, expectedReceiptID string, now time.Time) error {
	if receipt.SchemaVersion != auditlog.ReceiptSchemaVersion || receipt.Sequence == 0 ||
		receipt.Sequence != record.Sequence || receipt.PreviousEventHash != record.PreviousEventHash ||
		receipt.EventHash != record.EventHash || !receipt.RecordedAt.Equal(record.RecordedAt) ||
		receipt.ReceiptID != auditReceiptID(record.EventHash) || receipt.ReceiptID != expectedReceiptID {
		return errors.New("receipt does not match the durable record")
	}
	if !validDigest(record.RequestDigest) || !validDigest(record.EventHash) ||
		record.EventHash != auditEventHash(record) || record.RecordedAt.IsZero() || record.RecordedAt.After(now) {
		return errors.New("record hash or ordering is invalid")
	}
	return nil
}

func containsExactCampaign(values []string) bool {
	operations := campaign.DevelopmentOperations()
	if len(values) != len(operations) {
		return false
	}
	for index, operation := range operations {
		if values[index] != string(operation) {
			return false
		}
	}
	return true
}

type transactionDigestMaterial struct {
	ID                              string `json:"id"`
	AssetID                         string `json:"asset_id"`
	IntendedLogicalID               string `json:"intended_logical_id"`
	ProfileID                       string `json:"profile_id"`
	BundleDigest                    string `json:"bundle_digest"`
	PolicyDigest                    string `json:"policy_digest"`
	ExpectedPrestateCustomerKeyHash string `json:"expected_prestate_customer_key_hash"`
	ExpectedCustomerKeyHash         string `json:"expected_customer_key_hash"`
}

func transactionDigest(transaction controlplane.Transaction) string {
	return digestJSON(transactionDigestMaterial{
		ID: transaction.ID, AssetID: transaction.AssetID,
		IntendedLogicalID: transaction.IntendedLogicalID, ProfileID: transaction.ProfileID,
		BundleDigest: transaction.BundleDigest, PolicyDigest: transaction.PolicyDigest,
		ExpectedPrestateCustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
		ExpectedCustomerKeyHash:         transaction.ExpectedCustomerKeyHash,
	})
}

type auditHashMaterial struct {
	Sequence          uint64         `json:"sequence"`
	PreviousEventHash string         `json:"previous_event_hash,omitempty"`
	RequestDigest     string         `json:"request_digest"`
	RecordedAt        time.Time      `json:"recorded_at"`
	Event             auditlog.Event `json:"event"`
}

func auditEventHash(record auditlog.Record) string {
	return digestJSON(auditHashMaterial{
		Sequence: record.Sequence, PreviousEventHash: record.PreviousEventHash,
		RequestDigest: record.RequestDigest, RecordedAt: record.RecordedAt, Event: record.Event,
	})
}

func auditReceiptID(eventHash string) string {
	digest := sha256.Sum256([]byte("kaiba-audit-receipt\x00" + eventHash))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal fixed plan authority material: %v", err))
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
