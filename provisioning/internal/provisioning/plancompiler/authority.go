package plancompiler

import (
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

// Authority is one authenticated snapshot read from the control and audit
// services immediately before lane-plan installation.
type Authority struct {
	Transaction       controlplane.Transaction
	ApprovalReceipt   auditlog.Receipt
	ApprovalRecord    auditlog.Record
	IntentReceipt     auditlog.Receipt
	IntentRecord      auditlog.Record
	Now               time.Time
	LeaseSafetyMargin time.Duration
}

// BoundPlan is immutable authority plus ordered request templates. A caller
// must fetch and Bind fresh authority again after a claim or approval change.
type BoundPlan struct {
	plan           laneguard.Plan
	claimExpiresAt time.Time
}

// Bind authenticates the draft's previously approved digest and the separate
// durable audit intent. The initial control operation intent must still be
// pending; completed, failed, uncertain, or additional operations are rejected.
func Bind(draft Draft, authority Authority) (BoundPlan, error) {
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
	maximumDuration := time.Duration(0)
	for _, operation := range plan.Operations {
		if operation.MaximumDuration > maximumDuration {
			maximumDuration = operation.MaximumDuration
		}
	}
	if claim.ExpiresAt.Sub(now) < maximumDuration+authority.LeaseSafetyMargin {
		return BoundPlan{}, ErrStaleClaim
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
	if err := validateAuditApproval(plan, approval, authority.ApprovalReceipt, authority.ApprovalRecord, now); err != nil {
		return BoundPlan{}, err
	}

	if len(transaction.Operations) != 1 {
		return BoundPlan{}, fmt.Errorf("%w: expected exactly one initial pending intent", ErrAuthorityMismatch)
	}
	intent := transaction.Operations[0]
	first := plan.Operations[0]
	if intent.ID == "" || intent.Operation != string(first.Operation) || intent.Status != controlplane.OperationIntentRecorded ||
		intent.PlanDigest != plan.PlanDigest || intent.Release != plan.Release || !intent.ApprovalExpiresAt.Equal(plan.ApprovalExpiresAt) ||
		intent.InputDigest != plan.PlanDigest || intent.PrestateDigest != draft.InitialPrestateDigest() ||
		intent.IntentFenceEpoch != plan.FenceEpoch || intent.IntentAt.IsZero() || intent.IntentAt.After(now) {
		return BoundPlan{}, fmt.Errorf("%w: initial control intent", ErrAuthorityMismatch)
	}
	if err := validateAuditIntent(plan, intent, authority.IntentReceipt, authority.IntentRecord, now); err != nil {
		return BoundPlan{}, err
	}

	bound := clonePlan(plan)
	bound.ApprovalID = approval.ID
	bound.IntentReceipt = authority.IntentReceipt.ReceiptID
	return BoundPlan{plan: bound, claimExpiresAt: claim.ExpiresAt.UTC()}, nil
}

// Plan returns a defensive copy of the fully bound lane plan.
func (bound BoundPlan) Plan() laneguard.Plan { return clonePlan(bound.plan) }

// ExecuteRequests returns exact request envelopes in canonical operation order.
func (bound BoundPlan) ExecuteRequests() []laneguard.ExecuteRequest {
	requests := make([]laneguard.ExecuteRequest, len(bound.plan.Operations))
	for index, operation := range bound.plan.Operations {
		requests[index] = laneguard.ExecuteRequest{
			SchemaVersion: laneguard.ContractSchemaVersion,
			StationID:     bound.plan.StationID, LaneID: bound.plan.LaneID,
			TransactionID: bound.plan.TransactionID, PlanDigest: bound.plan.PlanDigest,
			Release: bound.plan.Release, TargetFingerprint: bound.plan.TargetFingerprint,
			FenceEpoch: bound.plan.FenceEpoch, ApprovalID: bound.plan.ApprovalID,
			ApprovalExpiresAt: bound.plan.ApprovalExpiresAt, IntentReceipt: bound.plan.IntentReceipt,
			Sequence: operation.Sequence, OperationDigest: operation.OperationDigest,
			AuthorizationID: operation.AuthorizationID, ExpectedPrestate: operation.ExpectedPrestate,
			ClaimExpiresAt: bound.claimExpiresAt,
		}
	}
	return requests
}

func validateAuditApproval(plan laneguard.Plan, approval *controlplane.Approval, receipt auditlog.Receipt, record auditlog.Record, now time.Time) error {
	if err := validateAuditReceipt(receipt, record, approval.AuditReceiptID, now); err != nil {
		return fmt.Errorf("%w: approval %v", ErrInvalidAuditIntent, err)
	}
	event := record.Event
	if event.SchemaVersion != auditlog.EventSchemaVersion || event.PolicyVersion != auditlog.DefaultPolicyVersion ||
		event.EventID != approval.ID || event.TransactionID != plan.TransactionID ||
		event.StationID != plan.StationID || event.LaneID != plan.LaneID ||
		event.Stage != "plan_approval" || event.FenceEpoch != plan.FenceEpoch ||
		event.InputDigest != plan.PlanDigest || event.OutputDigest != "" || event.Result != auditlog.ResultIntentRecorded ||
		len(event.Actors) != 1 || event.Actors[0].ID != approval.ApproverID || event.Actors[0].Role != "approver" {
		return fmt.Errorf("%w: approval event does not bind the plan and approver", ErrInvalidAuditIntent)
	}
	return nil
}

func validateAuditIntent(plan laneguard.Plan, intent controlplane.OperationRecord, receipt auditlog.Receipt, record auditlog.Record, now time.Time) error {
	if err := validateAuditReceipt(receipt, record, intent.IntentAuditReceiptID, now); err != nil {
		return fmt.Errorf("%w: intent %v", ErrInvalidAuditIntent, err)
	}
	if intent.IntentAt.Before(record.RecordedAt) {
		return fmt.Errorf("%w: intent record ordering", ErrInvalidAuditIntent)
	}
	event := record.Event
	if event.SchemaVersion != auditlog.EventSchemaVersion || event.PolicyVersion != auditlog.DefaultPolicyVersion || event.EventID != intent.ID ||
		event.TransactionID != plan.TransactionID || event.StationID != plan.StationID || event.LaneID != plan.LaneID ||
		event.Stage != string(plan.Operations[0].Operation) || event.FenceEpoch != plan.FenceEpoch ||
		event.InputDigest != plan.PlanDigest || event.OutputDigest != "" || event.Result != auditlog.ResultIntentRecorded {
		return fmt.Errorf("%w: event does not bind the initial plan intent", ErrInvalidAuditIntent)
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
