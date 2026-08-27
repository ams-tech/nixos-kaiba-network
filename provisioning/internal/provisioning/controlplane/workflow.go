package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

func (s *Service) BindTarget(_ context.Context, request BindTargetRequest) (Transaction, error) {
	if err := validateBindTargetRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("bind_target", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		switch transaction.Status {
		case StatusClaimed, StatusTargetBound, StatusReconciled:
		default:
			return fmt.Errorf("%w: cannot bind a target in status %q", ErrIllegalTransition, transaction.Status)
		}
		if request.CustomerKeyHash != transaction.ExpectedPrestateCustomerKeyHash {
			return fmt.Errorf("%w: observed customer key hash differs from the approved transaction prestate", ErrConflict)
		}
		if transaction.Target != nil && (transaction.Target.Fingerprint != request.TargetFingerprint || transaction.Target.CustomerKeyHash != request.CustomerKeyHash) {
			return fmt.Errorf("%w: target replacement or changed customer key hash", ErrConflict)
		}
		transaction.Target = &TargetBinding{
			Fingerprint: request.TargetFingerprint, ObservationDigest: request.ObservationDigest,
			CustomerKeyHash: request.CustomerKeyHash, BoundAt: now, FenceEpoch: claim.FenceEpoch,
		}
		transaction.Approval = nil
		transaction.Status = StatusTargetBound
		return nil
	})
}

// PreflightApproval validates a complete approver-authenticated proposal
// against the current target-bound transaction without changing durable state.
// It also accepts the exact already-committed control approval so a lost
// response can be retried without station credentials. The audit service's
// idempotency record independently binds the proposal approval-event time.
func (s *Service) PreflightApproval(_ context.Context, request ApprovalPreflightRequest) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateApprovalPreflightRequest(request); err != nil {
		return Transaction{}, err
	}
	transaction, exists := s.state.Transactions[request.TransactionID]
	if !exists {
		return Transaction{}, ErrNotFound
	}
	if err := matchApprovalPreflight(&transaction, request, s.clock().UTC()); err != nil {
		return Transaction{}, err
	}
	return cloneTransaction(transaction)
}

func matchApprovalPreflight(transaction *Transaction, request ApprovalPreflightRequest, now time.Time) error {
	if transaction.ID != request.TransactionID || transaction.TransactionDigest != request.TransactionDigest {
		return fmt.Errorf("%w: approval transaction identity or digest changed", ErrConflict)
	}

	var claim *Claim
	switch transaction.Status {
	case StatusTargetBound:
		if err := validateCurrentApprovalPreflightTimes(request.ApprovedAt, request.ExpiresAt, now); err != nil {
			return err
		}
		current, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		claim = current
		if transaction.ResourceVersion != request.ExpectedResourceVersion {
			return ErrVersionConflict
		}
		if transaction.Approval != nil || len(transaction.Operations) != 0 {
			return fmt.Errorf("%w: target-bound transaction contains approval state", ErrConflict)
		}
	case StatusCommitApproved:
		// This is the read-only half of a lost-response replay. Match the
		// immutable committed approval and its original claim snapshot before
		// consulting any current lease or approval window: both are allowed to
		// have expired since the successful commit.
		if transaction.ResourceVersion <= request.ExpectedResourceVersion || len(transaction.Operations) != 0 {
			return fmt.Errorf("%w: transaction is not an exact initial approval replay", ErrConflict)
		}
		current, err := requireApprovalReplayClaim(transaction, request.ClaimID, request.FenceEpoch)
		if err != nil {
			return err
		}
		claim = current
		approval := transaction.Approval
		if approval == nil || approval.ID != request.ApprovalID || approval.ApproverID != request.ApproverID ||
			approval.TransactionDigest != request.TransactionDigest || approval.PlanDigest != request.PlanDigest ||
			approval.StationID != request.StationID || approval.LaneID != request.LaneID ||
			approval.FenceEpoch != request.FenceEpoch || approval.TargetFingerprint != request.TargetFingerprint ||
			approval.Release != request.Release || !equalOrderedStrings(approval.AllowedOperations, request.AllowedOperations) ||
			!approval.ExpiresAt.Equal(request.ExpiresAt) {
			return fmt.Errorf("%w: committed approval differs from the preflight proposal", ErrConflict)
		}
	default:
		return fmt.Errorf("%w: approval preflight requires target_bound or its exact committed replay", ErrIllegalTransition)
	}

	if claim.StationID != request.StationID || claim.LaneID != request.LaneID ||
		!equalOrderedStrings(claim.AllowedStages, request.AllowedOperations) {
		return fmt.Errorf("%w: approval claim ownership or ordered operations changed", ErrConflict)
	}
	if transaction.Target == nil || transaction.Target.FenceEpoch != request.FenceEpoch ||
		transaction.Target.Fingerprint != request.TargetFingerprint {
		return fmt.Errorf("%w: approval target binding changed", ErrConflict)
	}
	if request.ApprovedAt.Before(transaction.Target.BoundAt) || !claim.ExpiresAt.After(request.ApprovedAt) {
		return fmt.Errorf("%w: approval time is outside the target-bound claim", ErrConflict)
	}
	if request.Release.SignedReleaseManifestDigest != transaction.BundleDigest ||
		request.Release.ExpectedCustomerKeyHash != transaction.ExpectedCustomerKeyHash {
		return fmt.Errorf("%w: approval release binding changed", ErrConflict)
	}

	return nil
}

func requireApprovalReplayClaim(transaction *Transaction, claimID string, fenceEpoch uint64) (*Claim, error) {
	claim := transaction.ActiveClaim
	if claim == nil || claim.Status != ClaimActive || claim.ID != claimID ||
		claim.FenceEpoch != fenceEpoch || transaction.FenceEpoch != fenceEpoch {
		return nil, ErrStaleFence
	}
	if claim.Mode != ClaimModeMutation {
		return nil, fmt.Errorf("%w: claim mode %q does not authorize %q", ErrIllegalTransition, claim.Mode, ClaimModeMutation)
	}
	return claim, nil
}

func equalOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (s *Service) RecordApproval(_ context.Context, request RecordApprovalRequest) (Transaction, error) {
	if err := validateRecordApprovalRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("record_approval", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		if err := validateCurrentApprovalExpiry(request.ExpiresAt, now); err != nil {
			return err
		}
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		if transaction.Status != StatusTargetBound && transaction.Status != StatusCommitApproved {
			return fmt.Errorf("%w: approval requires target_bound status", ErrIllegalTransition)
		}
		if transaction.Target == nil || transaction.Target.FenceEpoch != claim.FenceEpoch {
			return fmt.Errorf("%w: target must be directly reidentified in the current fence epoch", ErrStaleFence)
		}
		if request.TransactionDigest != transaction.TransactionDigest || request.TargetFingerprint != transaction.Target.Fingerprint ||
			request.Release.SignedReleaseManifestDigest != transaction.BundleDigest ||
			request.Release.ExpectedCustomerKeyHash != transaction.ExpectedCustomerKeyHash {
			return fmt.Errorf("%w: approval binding does not match the transaction and target", ErrConflict)
		}
		if previous := transaction.Approval; previous != nil && request.PlanDigest == previous.PlanDigest &&
			(request.Release != previous.Release || !request.ExpiresAt.Equal(previous.ExpiresAt)) {
			return fmt.Errorf("%w: reapproval changed release binding or expiry without changing the plan digest", ErrConflict)
		}
		for _, operation := range request.AllowedOperations {
			if !contains(claim.AllowedStages, operation) {
				return fmt.Errorf("%w: claim does not authorize approved operation %q", ErrIllegalTransition, operation)
			}
		}
		if err := validatePriorOperationsAgainstPlan(
			transaction.Operations,
			request.PlanDigest,
			request.Release,
			request.ExpiresAt,
			request.AllowedOperations,
		); err != nil {
			return err
		}
		transaction.Approval = &Approval{
			ID: request.ApprovalID, ApproverID: request.ApproverID,
			TransactionDigest: request.TransactionDigest, PlanDigest: request.PlanDigest,
			StationID: claim.StationID, LaneID: claim.LaneID, FenceEpoch: claim.FenceEpoch,
			TargetFingerprint: request.TargetFingerprint,
			Release:           request.Release,
			AllowedOperations: append([]string(nil), request.AllowedOperations...),
			AuditReceiptID:    request.AuditReceiptID, ApprovedAt: now, ExpiresAt: request.ExpiresAt.UTC(),
		}
		transaction.Status = StatusCommitApproved
		return nil
	})
}

func (s *Service) RecordStageIntent(ctx context.Context, request RecordIntentRequest) (Transaction, error) {
	return s.RecordIntent(ctx, request)
}

func (s *Service) RecordIntent(_ context.Context, request RecordIntentRequest) (Transaction, error) {
	if err := validateRecordIntentRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("record_intent", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		if transaction.Status != StatusCommitApproved {
			return fmt.Errorf("%w: intent requires commit_approved status", ErrIllegalTransition)
		}
		approval, err := requireCurrentApproval(transaction, claim, request.ApprovalID, request.PlanDigest, now)
		if err != nil {
			return err
		}
		for _, operation := range transaction.Operations {
			if operation.ID == request.OperationID {
				return fmt.Errorf("%w: operation_id already exists", ErrConflict)
			}
			if operation.Status == OperationConfirmedNotApplied {
				return fmt.Errorf("%w: confirmed-not-applied operations cannot be retried under the current protocol", ErrIllegalTransition)
			}
			if operation.Status == OperationIntentRecorded || operation.Status == OperationUncertain {
				return fmt.Errorf("%w: previous operation requires reconciliation", ErrIllegalTransition)
			}
		}
		next := completedApprovedOperations(transaction.Operations)
		if next >= len(approval.AllowedOperations) || approval.AllowedOperations[next] != request.Operation {
			return fmt.Errorf("%w: operation is out of the approved order", ErrIllegalTransition)
		}
		if !contains(claim.AllowedStages, request.Operation) {
			return fmt.Errorf("%w: claim does not authorize operation", ErrIllegalTransition)
		}
		transaction.Operations = append(transaction.Operations, OperationRecord{
			ID: request.OperationID, Operation: request.Operation, Status: OperationIntentRecorded,
			PlanDigest: request.PlanDigest, Release: approval.Release, ApprovalExpiresAt: approval.ExpiresAt,
			Approval:       cloneApproval(*approval),
			InputDigest:    request.InputDigest,
			PrestateDigest: request.PrestateDigest, IntentAuditReceiptID: request.AuditReceiptID,
			IntentAt: now, IntentFenceEpoch: claim.FenceEpoch,
		})
		transaction.Status = StatusMutationInProgress
		return nil
	})
}

func cloneApproval(approval Approval) Approval {
	approval.AllowedOperations = append([]string(nil), approval.AllowedOperations...)
	return approval
}

func (s *Service) RecordStageEvidence(ctx context.Context, request RecordEvidenceRequest) (Transaction, error) {
	return s.RecordEvidence(ctx, request)
}

func (s *Service) RecordEvidence(_ context.Context, request RecordEvidenceRequest) (Transaction, error) {
	if err := validateRecordEvidenceRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("record_evidence", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		_, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		if transaction.Status != StatusMutationInProgress || len(transaction.Operations) == 0 {
			return fmt.Errorf("%w: no mutation is awaiting evidence", ErrIllegalTransition)
		}
		operation := &transaction.Operations[len(transaction.Operations)-1]
		if operation.ID != request.OperationID || operation.Status != OperationIntentRecorded {
			return fmt.Errorf("%w: evidence does not match the pending operation", ErrConflict)
		}
		observedAt := now
		operation.OutputDigest = request.OutputDigest
		operation.ObservationDigest = request.ObservationDigest
		operation.EvidenceAuditReceiptID = request.AuditReceiptID
		operation.EvidenceAt = &observedAt
		switch request.Result {
		case EvidenceSucceeded:
			operation.Status = OperationSucceeded
			transaction.Status = StatusCommitApproved
		case EvidenceFailed:
			operation.Status = OperationFailed
			transaction.Status = StatusQuarantined
			transaction.Approval = nil
			transaction.Quarantine = &QuarantineRecord{
				ReasonCode: "operation_failed", ObservationDigest: request.ObservationDigest,
				AuditReceiptID: request.AuditReceiptID, FenceEpoch: request.FenceEpoch, RecordedAt: now,
			}
		case EvidenceUncertain:
			operation.Status = OperationUncertain
			transaction.Status = StatusReconciliationRequired
			transaction.Approval = nil
		}
		return nil
	})
}

func (s *Service) RecordReconciliation(_ context.Context, request RecordReconciliationRequest) (Transaction, error) {
	if err := validateRecordReconciliationRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("record_reconciliation", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		_, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeReconciliation)
		if err != nil {
			return err
		}
		if transaction.Status != StatusReconciliationRequired && transaction.Status != StatusQuarantined {
			return fmt.Errorf("%w: transaction is not awaiting reconciliation", ErrIllegalTransition)
		}
		operation := findOperation(transaction.Operations, request.OperationID)
		if operation == nil || (operation.Status != OperationIntentRecorded && operation.Status != OperationUncertain && operation.Status != OperationFailed) {
			return fmt.Errorf("%w: operation cannot be reconciled", ErrIllegalTransition)
		}
		observedAt := now
		operation.OutputDigest = request.OutputDigest
		operation.ObservationDigest = request.ObservationDigest
		operation.ReconciliationAuditReceiptID = request.AuditReceiptID
		operation.EvidenceAt = &observedAt
		transaction.Approval = nil
		switch request.Resolution {
		case ResolutionConfirmedApplied:
			operation.Status = OperationConfirmedApplied
			if transaction.Status != StatusQuarantined {
				transaction.Status = StatusReconciled
			}
		case ResolutionConfirmedNotApplied:
			operation.Status = OperationConfirmedNotApplied
			if transaction.Status != StatusQuarantined {
				transaction.Status = StatusReconciled
			}
		case ResolutionUnknown:
			operation.Status = OperationUncertain
			transaction.Status = StatusQuarantined
			transaction.Quarantine = &QuarantineRecord{
				ReasonCode: "reconciliation_unknown", ObservationDigest: request.ObservationDigest,
				AuditReceiptID: request.AuditReceiptID, FenceEpoch: request.FenceEpoch, RecordedAt: now,
			}
		}
		return nil
	})
}

func (s *Service) QuarantineDevice(_ context.Context, request QuarantineRequest) (Transaction, error) {
	if err := validateQuarantineRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("quarantine_device", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		_, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, "")
		if err != nil {
			return err
		}
		if transaction.Status == StatusSecurityApplied || transaction.Status == StatusAborted || transaction.Status == StatusQuarantined {
			return fmt.Errorf("%w: transaction is already terminal", ErrIllegalTransition)
		}
		transaction.Approval = nil
		transaction.Status = StatusQuarantined
		transaction.Quarantine = &QuarantineRecord{
			ReasonCode: request.ReasonCode, ObservationDigest: request.ObservationDigest,
			AuditReceiptID: request.AuditReceiptID, FenceEpoch: request.FenceEpoch, RecordedAt: now,
		}
		return nil
	})
}

func (s *Service) AbortTransaction(_ context.Context, request AbortRequest) (Transaction, error) {
	if err := validateAbortRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("abort_transaction", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		_, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		if len(transaction.Operations) != 0 || transaction.Status == StatusSecurityApplied || transaction.Status == StatusQuarantined {
			return fmt.Errorf("%w: abort is allowed only before the first irreversible intent", ErrIllegalTransition)
		}
		transaction.Approval = nil
		transaction.Status = StatusAborted
		transaction.Abort = &AbortRecord{
			ReusableBaselineDigest: request.ReusableBaselineDigest,
			AuditReceiptID:         request.AuditReceiptID, RecordedAt: now,
		}
		return nil
	})
}

// MarkSecurityApplied is the intentionally limited initial terminal transition.
// There is no enrollment-ready transition while anti-rollback is unimplemented.
func (s *Service) MarkSecurityApplied(_ context.Context, request SecurityAppliedRequest) (Transaction, error) {
	if err := validateSecurityAppliedRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("mark_security_applied", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, ClaimModeMutation)
		if err != nil {
			return err
		}
		if transaction.Status != StatusCommitApproved || transaction.Approval == nil {
			return fmt.Errorf("%w: finalization requires an active approval", ErrIllegalTransition)
		}
		approval, err := requireCurrentApproval(transaction, claim, transaction.Approval.ID, request.PlanDigest, now)
		if err != nil {
			return err
		}
		if err := validateCompletedDevelopmentCampaign(transaction.Operations, approval); err != nil {
			return err
		}
		transaction.Status = StatusSecurityApplied
		transaction.SecurityApplied = &SecurityAppliedRecord{
			EvidenceDigest: request.EvidenceDigest, AuditReceiptID: request.AuditReceiptID,
			RollbackStatus:        request.RollbackStatus,
			ReleaseClassification: request.ReleaseClassification, RecordedAt: now,
		}
		return nil
	})
}

func requireCurrentApproval(transaction *Transaction, claim *Claim, approvalID, planDigest string, now time.Time) (*Approval, error) {
	approval := transaction.Approval
	if approval == nil || approval.ID != approvalID || approval.PlanDigest != planDigest ||
		approval.TransactionDigest != transaction.TransactionDigest || approval.FenceEpoch != claim.FenceEpoch ||
		approval.StationID != claim.StationID || approval.LaneID != claim.LaneID ||
		transaction.Target == nil || approval.TargetFingerprint != transaction.Target.Fingerprint ||
		approval.Release.SignedReleaseManifestDigest != transaction.BundleDigest ||
		approval.Release.ExpectedCustomerKeyHash != transaction.ExpectedCustomerKeyHash {
		return nil, fmt.Errorf("%w: approval does not match current transaction, target, claim, and plan", ErrConflict)
	}
	if !approval.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: approval expired", ErrIllegalTransition)
	}
	return approval, nil
}

func completedApprovedOperations(operations []OperationRecord) int {
	completed := 0
	for _, operation := range operations {
		if operation.Status == OperationSucceeded || operation.Status == OperationConfirmedApplied {
			completed++
		}
	}
	return completed
}

func validateCompletedDevelopmentCampaign(operations []OperationRecord, approval *Approval) error {
	if approval == nil {
		return fmt.Errorf("%w: finalization requires a campaign approval", ErrIllegalTransition)
	}
	if err := validateDevelopmentOperationNames(approval.AllowedOperations); err != nil {
		return fmt.Errorf("%w: approval is not the complete development secure-boot campaign: %v", ErrIllegalTransition, err)
	}

	next := 0
	for index, operation := range operations {
		if next >= len(approval.AllowedOperations) {
			return fmt.Errorf("%w: operation record %d follows the completed campaign", ErrIllegalTransition, index+1)
		}
		if operation.PlanDigest != approval.PlanDigest {
			return fmt.Errorf("%w: operation record %d has a different plan digest", ErrIllegalTransition, index+1)
		}
		if operation.Release != approval.Release || !operation.ApprovalExpiresAt.Equal(approval.ExpiresAt) {
			return fmt.Errorf("%w: operation record %d has a different release binding or approval expiry", ErrIllegalTransition, index+1)
		}
		if operation.Operation != approval.AllowedOperations[next] {
			return fmt.Errorf("%w: operation record %d is out of campaign order", ErrIllegalTransition, index+1)
		}
		switch operation.Status {
		case OperationSucceeded, OperationConfirmedApplied:
			next++
		case OperationConfirmedNotApplied:
			// A conclusive no-op does not satisfy this campaign step and cannot
			// be retried under the current protocol.
		default:
			return fmt.Errorf("%w: operation record %d lacks authoritative terminal evidence", ErrIllegalTransition, index+1)
		}
	}
	if next != len(approval.AllowedOperations) {
		return fmt.Errorf("%w: campaign completed %d of %d required operations", ErrIllegalTransition, next, len(approval.AllowedOperations))
	}
	return nil
}

func findOperation(operations []OperationRecord, id string) *OperationRecord {
	for index := range operations {
		if operations[index].ID == id {
			return &operations[index]
		}
	}
	return nil
}

func validatePriorOperationsAgainstPlan(
	operations []OperationRecord,
	planDigest string,
	release releasebinding.Binding,
	approvalExpiresAt time.Time,
	approved []string,
) error {
	next := 0
	for _, operation := range operations {
		if operation.PlanDigest != planDigest {
			return fmt.Errorf("%w: fresh approval changed the plan digest after an intent was recorded", ErrConflict)
		}
		if operation.Release != release || !operation.ApprovalExpiresAt.Equal(approvalExpiresAt) {
			return fmt.Errorf("%w: fresh approval changed the release binding or expiry after an intent was recorded", ErrConflict)
		}
		if next >= len(approved) || approved[next] != operation.Operation {
			return fmt.Errorf("%w: prior operations do not match the newly approved ordered plan", ErrConflict)
		}
		if operation.Status == OperationSucceeded || operation.Status == OperationConfirmedApplied {
			next++
		}
	}
	return nil
}
