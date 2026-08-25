package plancompiler

import (
	"errors"
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

var ErrInvalidReconciliationAuthority = errors.New("invalid authenticated reconciliation authority")

// BoundReconciliation retains the original, journal-bound plan while carrying
// a separate current claim that authorizes observation only. It intentionally
// has no ExecuteRequest or Load method.
type BoundReconciliation struct {
	plan    laneguard.Plan
	request laneguard.ReconcileRequest
}

// BindReconciliation reconstructs the original audited execution identity from
// durable control and audit records, then binds it to the current active
// reconciliation claim. The original approval may be expired and is not
// required to remain the transaction's current forward-mutation approval.
func BindReconciliation(draft Draft, authority Authority) (BoundReconciliation, error) {
	if err := validateDraft(draft); err != nil {
		return BoundReconciliation{}, err
	}
	if authority.Now.IsZero() || authority.LeaseSafetyMargin < 0 {
		return BoundReconciliation{}, reconciliationError("current time or lease margin is invalid")
	}
	now := authority.Now.UTC()
	transaction := authority.Transaction
	plan := draft.plan

	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ResourceVersion == 0 ||
		transaction.ID != plan.TransactionID || transaction.Status != controlplane.StatusReconciliationRequired ||
		transaction.Approval != nil || transaction.Quarantine != nil || transaction.SecurityApplied != nil || transaction.Abort != nil {
		return BoundReconciliation{}, reconciliationError("transaction identity, status, or terminal state")
	}
	if transaction.TransactionDigest != transactionDigest(transaction) {
		return BoundReconciliation{}, reconciliationError("transaction digest")
	}
	if transaction.BundleDigest != plan.Release.SignedReleaseManifestDigest ||
		transaction.ExpectedCustomerKeyHash != plan.Release.ExpectedCustomerKeyHash {
		return BoundReconciliation{}, reconciliationError("transaction release")
	}

	claim := transaction.ActiveClaim
	if claim == nil || claim.ID == "" || claim.Status != controlplane.ClaimActive ||
		claim.Mode != controlplane.ClaimModeReconciliation || claim.ClosedAt != nil ||
		claim.AssetID != transaction.AssetID || claim.FenceEpoch != transaction.FenceEpoch ||
		claim.FenceEpoch <= plan.FenceEpoch || claim.AcquiredAt.IsZero() || claim.AcquiredAt.After(now) ||
		!claim.ExpiresAt.After(claim.AcquiredAt) || !claim.ExpiresAt.After(now) ||
		len(claim.AllowedStages) != 1 || claim.AllowedStages[0] != "reconciliation" {
		return BoundReconciliation{}, reconciliationError("current reconciliation claim")
	}

	target := transaction.Target
	if target == nil || target.Fingerprint != plan.TargetFingerprint || target.FenceEpoch != plan.FenceEpoch ||
		target.CustomerKeyHash != transaction.ExpectedPrestateCustomerKeyHash ||
		target.CustomerKeyHash != plan.Operations[0].ExpectedPrestate.CustomerKeyHash ||
		!validDigest(target.ObservationDigest) || target.BoundAt.IsZero() || target.BoundAt.After(now) {
		return BoundReconciliation{}, reconciliationError("original target binding")
	}

	operationIndex, intent, err := validateReconciliationOperations(plan, transaction.Operations, now)
	if err != nil {
		return BoundReconciliation{}, err
	}
	operation := plan.Operations[operationIndex]
	approval := intent.Approval
	if err := validateReconciliationApproval(plan, transaction, intent, approval, now); err != nil {
		return BoundReconciliation{}, err
	}
	if !laneguard.LeaseCoversOperation(now, claim.ExpiresAt, laneguard.ReconciliationObservationBudget, authority.LeaseSafetyMargin) {
		return BoundReconciliation{}, reconciliationError("current reconciliation claim lease")
	}
	originalClaim, err := originalMutationClaim(transaction, plan, intent, *claim)
	if err != nil {
		return BoundReconciliation{}, err
	}
	if err := validateAuditApproval(plan, &approval, authority.ApprovalReceipt, authority.ApprovalRecord, now, productionActors.approvalRole); err != nil {
		return BoundReconciliation{}, err
	}
	if err := validateAuditIntent(plan, operation, intent, authority.IntentReceipt, authority.IntentRecord, now, productionActors.intentRole); err != nil {
		return BoundReconciliation{}, err
	}
	if authority.ApprovalRecord.Sequence >= authority.IntentRecord.Sequence || approval.ApprovedAt.After(authority.IntentRecord.RecordedAt) {
		return BoundReconciliation{}, fmt.Errorf("%w: approval and intent record ordering", ErrInvalidAuditIntent)
	}

	boundPlan := clonePlan(plan)
	boundPlan.ApprovalID = approval.ID
	boundPlan.IntentReceipt = authority.IntentReceipt.ReceiptID
	boundPlan.IntentSequence = operation.Sequence
	originalRequest := laneguard.ExecuteRequest{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     boundPlan.StationID, LaneID: boundPlan.LaneID,
		TransactionID: boundPlan.TransactionID, PlanDigest: boundPlan.PlanDigest,
		Release: boundPlan.Release, TargetFingerprint: boundPlan.TargetFingerprint,
		FenceEpoch: boundPlan.FenceEpoch, ApprovalID: boundPlan.ApprovalID,
		ApprovalExpiresAt: boundPlan.ApprovalExpiresAt, IntentReceipt: boundPlan.IntentReceipt,
		Sequence: operation.Sequence, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, ExpectedPrestate: operation.ExpectedPrestate,
		ClaimExpiresAt: originalClaim.ExpiresAt.UTC(),
	}
	request := laneguard.ReconcileRequest{
		SchemaVersion:   laneguard.ReconcileRequestSchemaVersion,
		OriginalRequest: originalRequest,
		Claim: laneguard.ReconciliationClaim{
			StationID: claim.StationID, LaneID: claim.LaneID,
			TransactionID: transaction.ID, TargetFingerprint: plan.TargetFingerprint,
			ClaimID: claim.ID, FenceEpoch: claim.FenceEpoch, ExpiresAt: claim.ExpiresAt.UTC(),
		},
	}
	return BoundReconciliation{plan: boundPlan, request: request}, nil
}

// Reconciliation returns a defensive pair for the authenticated bridge. The
// first value is the original attempt plan; the second carries only current
// observation authority and cannot be passed to Guard.Execute.
func (bound BoundReconciliation) Reconciliation() (laneguard.Plan, laneguard.ReconcileRequest, error) {
	if bound.request.SchemaVersion != laneguard.ReconcileRequestSchemaVersion || bound.plan.PlanDigest == "" {
		return laneguard.Plan{}, laneguard.ReconcileRequest{}, reconciliationError("bound reconciliation is empty")
	}
	return clonePlan(bound.plan), bound.request, nil
}

func validateReconciliationOperations(plan laneguard.Plan, records []controlplane.OperationRecord, now time.Time) (int, controlplane.OperationRecord, error) {
	if len(records) == 0 || len(records) > len(plan.Operations) {
		return 0, controlplane.OperationRecord{}, reconciliationError("expected one unresolved operation after a successful plan prefix")
	}
	seenIDs := make(map[string]struct{}, len(records))
	for index, record := range records {
		operation := plan.Operations[index]
		if record.ID == "" || record.Operation != string(operation.Operation) ||
			record.PlanDigest != plan.PlanDigest || record.Release != plan.Release ||
			!record.ApprovalExpiresAt.Equal(plan.ApprovalExpiresAt) || record.InputDigest != plan.PlanDigest ||
			record.PrestateDigest != prestateDigest(operation.ExpectedPrestate) || !validDigest(record.IntentAuditReceiptID) ||
			record.IntentFenceEpoch != plan.FenceEpoch || record.IntentAt.IsZero() || record.IntentAt.After(now) {
			return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("control operation %d binding", index+1))
		}
		if _, duplicate := seenIDs[record.ID]; duplicate {
			return 0, controlplane.OperationRecord{}, reconciliationError("duplicate control operation ID")
		}
		seenIDs[record.ID] = struct{}{}
		if index == len(records)-1 {
			switch record.Status {
			case controlplane.OperationIntentRecorded:
				if record.OutputDigest != "" || record.ObservationDigest != "" || record.EvidenceAuditReceiptID != "" ||
					record.EvidenceAt != nil || record.ReconciliationAuditReceiptID != "" {
					return 0, controlplane.OperationRecord{}, reconciliationError("final intent-recorded operation contains evidence")
				}
			case controlplane.OperationUncertain:
				if !validDigest(record.OutputDigest) || !validDigest(record.ObservationDigest) ||
					!validDigest(record.EvidenceAuditReceiptID) || record.EvidenceAt == nil ||
					record.EvidenceAt.Before(record.IntentAt) || record.EvidenceAt.After(now) ||
					record.ReconciliationAuditReceiptID != "" {
					return 0, controlplane.OperationRecord{}, reconciliationError("final uncertain operation evidence is incomplete")
				}
			default:
				return 0, controlplane.OperationRecord{}, reconciliationError("final control operation is not unresolved")
			}
			return index, record, nil
		}
		if record.Status != controlplane.OperationSucceeded && record.Status != controlplane.OperationConfirmedApplied {
			return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("prior control operation %d is not successfully closed", index+1))
		}
		if !validDigest(record.OutputDigest) || !validDigest(record.ObservationDigest) || record.EvidenceAt == nil ||
			record.EvidenceAt.Before(record.IntentAt) || record.EvidenceAt.After(now) {
			return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("prior control operation %d evidence", index+1))
		}
		switch record.Status {
		case controlplane.OperationSucceeded:
			if !validDigest(record.EvidenceAuditReceiptID) || record.ReconciliationAuditReceiptID != "" {
				return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("prior control operation %d evidence receipt", index+1))
			}
		case controlplane.OperationConfirmedApplied:
			if !validDigest(record.ReconciliationAuditReceiptID) ||
				(record.EvidenceAuditReceiptID != "" && !validDigest(record.EvidenceAuditReceiptID)) {
				return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("prior control operation %d reconciliation receipt", index+1))
			}
		}
		if records[index+1].IntentAt.Before(*record.EvidenceAt) {
			return 0, controlplane.OperationRecord{}, reconciliationError(fmt.Sprintf("control operation %d ordering", index+1))
		}
	}
	return 0, controlplane.OperationRecord{}, reconciliationError("no unresolved control operation")
}

func validateReconciliationApproval(plan laneguard.Plan, transaction controlplane.Transaction, intent controlplane.OperationRecord, approval controlplane.Approval, now time.Time) error {
	if approval.ID == "" || approval.ApproverID == "" || approval.TransactionDigest != transaction.TransactionDigest ||
		approval.PlanDigest != plan.PlanDigest || approval.StationID != plan.StationID || approval.LaneID != plan.LaneID ||
		approval.FenceEpoch != plan.FenceEpoch || approval.TargetFingerprint != plan.TargetFingerprint ||
		approval.Release != plan.Release || !containsExactCampaign(approval.AllowedOperations) ||
		!validDigest(approval.AuditReceiptID) || approval.ApprovedAt.IsZero() || approval.ApprovedAt.After(now) ||
		!approval.ExpiresAt.Equal(plan.ApprovalExpiresAt) || !approval.ExpiresAt.After(approval.ApprovedAt) ||
		approval.ExpiresAt.Sub(approval.ApprovedAt) > 24*time.Hour || intent.IntentAt.Before(approval.ApprovedAt) ||
		!intent.ApprovalExpiresAt.Equal(approval.ExpiresAt) {
		return reconciliationError("original approval snapshot")
	}
	return nil
}

func originalMutationClaim(transaction controlplane.Transaction, plan laneguard.Plan, intent controlplane.OperationRecord, currentClaim controlplane.Claim) (controlplane.Claim, error) {
	var selected controlplane.Claim
	matches := 0
	for _, claim := range transaction.ClaimHistory {
		if claim.FenceEpoch != plan.FenceEpoch {
			continue
		}
		selected = claim
		matches++
	}
	if matches != 1 || selected.ID == "" ||
		(selected.Status != controlplane.ClaimTransferred && selected.Status != controlplane.ClaimExpired) ||
		selected.ClosedAt == nil || selected.ClosedAt.Before(selected.AcquiredAt) ||
		selected.ClosedAt.Before(intent.IntentAt) || selected.ClosedAt.After(currentClaim.AcquiredAt) ||
		selected.Mode != controlplane.ClaimModeMutation ||
		selected.StationID != plan.StationID || selected.LaneID != plan.LaneID ||
		selected.AssetID != transaction.AssetID || selected.AcquiredAt.IsZero() ||
		!selected.ExpiresAt.After(selected.AcquiredAt) || intent.IntentAt.Before(selected.AcquiredAt) ||
		!selected.ExpiresAt.After(intent.IntentAt) || !containsExactCampaign(selected.AllowedStages) {
		return controlplane.Claim{}, reconciliationError("original mutation claim")
	}
	return selected, nil
}

func reconciliationError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidReconciliationAuthority, detail)
}
