package controlplane

import "fmt"

func validatePersistedState(state persistedState) error {
	if state.SchemaVersion != StoreSchemaVersion {
		return corrupt("unsupported store schema_version")
	}
	if state.Transactions == nil || state.FenceEpochs == nil || state.Idempotency == nil {
		return corrupt("required store maps are missing")
	}
	for id, transaction := range state.Transactions {
		if id != transaction.ID {
			return corrupt("transaction map key does not match transaction ID")
		}
		if err := validateTransaction(transaction, state.FenceEpochs); err != nil {
			return err
		}
	}
	for key, record := range state.Idempotency {
		if !validIdentifier(key) || !validIdentifier(record.Operation) || !validDigest(record.RequestDigest) || !validIdentifier(record.TransactionID) {
			return corrupt("invalid idempotency index entry")
		}
		if _, exists := state.Transactions[record.TransactionID]; !exists {
			return corrupt("idempotency index references a missing transaction")
		}
	}
	return nil
}

func validateTransaction(transaction Transaction, fenceEpochs map[string]uint64) error {
	if transaction.SchemaVersion != TransactionSchemaVersion || !validIdentifier(transaction.ID) ||
		!validIdentifier(transaction.AssetID) || !validIdentifier(transaction.IntendedLogicalID) || !validIdentifier(transaction.ProfileID) {
		return corrupt("invalid transaction identity or schema")
	}
	if transaction.ResourceVersion == 0 || transaction.CreatedAt.IsZero() || transaction.UpdatedAt.Before(transaction.CreatedAt) {
		return corrupt("invalid transaction version or timestamps")
	}
	if !validDigest(transaction.BundleDigest) || !validDigest(transaction.PolicyDigest) ||
		!validDigest(transaction.ExpectedPrestateCustomerKeyHash) ||
		!validDigest(transaction.ExpectedCustomerKeyHash) || !validDigest(transaction.TransactionDigest) {
		return corrupt("invalid transaction digest")
	}
	wantDigest, err := transactionDigest(transaction)
	if err != nil || wantDigest != transaction.TransactionDigest {
		return corrupt("transaction digest does not match immutable fields")
	}
	switch transaction.Status {
	case StatusCreated, StatusClaimed, StatusTargetBound, StatusCommitApproved, StatusMutationInProgress,
		StatusReconciliationRequired, StatusReconciled, StatusSecurityApplied, StatusAborted, StatusQuarantined:
	default:
		return corrupt("unsupported transaction status")
	}
	if transaction.FenceEpoch > fenceEpochs[transaction.AssetID] {
		return corrupt("transaction fence epoch exceeds asset epoch")
	}
	if transaction.ActiveClaim != nil {
		if err := validateClaim(*transaction.ActiveClaim, transaction, true); err != nil {
			return err
		}
	}
	for _, claim := range transaction.ClaimHistory {
		if err := validateClaim(claim, transaction, false); err != nil {
			return err
		}
	}
	if transaction.Target != nil {
		if !validDigest(transaction.Target.Fingerprint) || !validDigest(transaction.Target.ObservationDigest) ||
			transaction.Target.CustomerKeyHash != transaction.ExpectedPrestateCustomerKeyHash || transaction.Target.BoundAt.IsZero() ||
			transaction.Target.FenceEpoch == 0 || transaction.Target.FenceEpoch > transaction.FenceEpoch {
			return corrupt("invalid target binding")
		}
	}
	if transaction.Approval != nil {
		if err := validateStoredApproval(*transaction.Approval, transaction); err != nil {
			return err
		}
	}
	operationIDs := make(map[string]struct{}, len(transaction.Operations))
	for index, operation := range transaction.Operations {
		if _, duplicate := operationIDs[operation.ID]; duplicate {
			return corrupt("duplicate operation ID")
		}
		operationIDs[operation.ID] = struct{}{}
		if err := validateStoredOperation(operation, transaction); err != nil {
			return err
		}
		if index > 0 {
			first := transaction.Operations[0]
			if operation.PlanDigest != first.PlanDigest || operation.Release != first.Release ||
				!operation.ApprovalExpiresAt.Equal(first.ApprovalExpiresAt) {
				return corrupt("operation plan bindings are inconsistent")
			}
		}
	}
	if (transaction.Status == StatusQuarantined) != (transaction.Quarantine != nil) {
		return corrupt("quarantine terminal record does not match status")
	}
	if transaction.Quarantine != nil && (!validIdentifier(transaction.Quarantine.ReasonCode) ||
		!validDigest(transaction.Quarantine.ObservationDigest) || !validDigest(transaction.Quarantine.AuditReceiptID) ||
		transaction.Quarantine.RecordedAt.IsZero() || transaction.Quarantine.FenceEpoch == 0) {
		return corrupt("invalid quarantine record")
	}
	if (transaction.Status == StatusSecurityApplied) != (transaction.SecurityApplied != nil) {
		return corrupt("security-applied terminal record does not match status")
	}
	if transaction.SecurityApplied != nil && (!validDigest(transaction.SecurityApplied.EvidenceDigest) ||
		!validDigest(transaction.SecurityApplied.AuditReceiptID) || transaction.SecurityApplied.RollbackStatus != "rollback_unimplemented" ||
		transaction.SecurityApplied.ReleaseClassification != "development_asset" || transaction.SecurityApplied.RecordedAt.IsZero()) {
		return corrupt("invalid security-applied record")
	}
	if transaction.Status == StatusSecurityApplied {
		if transaction.Approval == nil {
			return corrupt("security-applied transaction has no campaign approval")
		}
		if err := validateCompletedDevelopmentCampaign(transaction.Operations, transaction.Approval); err != nil {
			return corrupt("security-applied transaction does not contain complete campaign evidence")
		}
	}
	if (transaction.Status == StatusAborted) != (transaction.Abort != nil) {
		return corrupt("abort terminal record does not match status")
	}
	if transaction.Abort != nil && (!validDigest(transaction.Abort.ReusableBaselineDigest) ||
		!validDigest(transaction.Abort.AuditReceiptID) || transaction.Abort.RecordedAt.IsZero()) {
		return corrupt("invalid abort record")
	}
	return nil
}

func validateClaim(claim Claim, transaction Transaction, active bool) error {
	if !validIdentifier(claim.ID) || !validIdentifier(claim.StationID) || !validIdentifier(claim.LaneID) ||
		claim.AssetID != transaction.AssetID || claim.FenceEpoch == 0 || claim.FenceEpoch > transaction.FenceEpoch ||
		claim.AcquiredAt.IsZero() || !claim.ExpiresAt.After(claim.AcquiredAt) {
		return corrupt("invalid claim")
	}
	if claim.Mode != ClaimModeMutation && claim.Mode != ClaimModeReconciliation {
		return corrupt("unsupported claim mode")
	}
	if err := validateStringSet("allowed_stages", claim.AllowedStages, 1, 32); err != nil {
		return corrupt("invalid claim allowed stages")
	}
	if active {
		if claim.Status != ClaimActive || claim.ClosedAt != nil || claim.FenceEpoch != transaction.FenceEpoch {
			return corrupt("invalid active claim")
		}
	} else {
		if claim.Status != ClaimReleased && claim.Status != ClaimTransferred && claim.Status != ClaimExpired {
			return corrupt("invalid historical claim status")
		}
		if claim.ClosedAt == nil || claim.ClosedAt.Before(claim.AcquiredAt) {
			return corrupt("invalid historical claim close time")
		}
	}
	return nil
}

func validateStoredApproval(approval Approval, transaction Transaction) error {
	if !validIdentifier(approval.ID) || !validIdentifier(approval.ApproverID) || approval.TransactionDigest != transaction.TransactionDigest ||
		!validDigest(approval.PlanDigest) || !validIdentifier(approval.StationID) || !validIdentifier(approval.LaneID) ||
		approval.FenceEpoch != transaction.FenceEpoch || transaction.Target == nil ||
		approval.TargetFingerprint != transaction.Target.Fingerprint ||
		approval.Release.SignedReleaseManifestDigest != transaction.BundleDigest ||
		approval.Release.ExpectedCustomerKeyHash != transaction.ExpectedCustomerKeyHash ||
		!validDigest(approval.AuditReceiptID) || approval.ApprovedAt.IsZero() || !approval.ExpiresAt.After(approval.ApprovedAt) ||
		approval.ExpiresAt.After(approval.ApprovedAt.Add(maximumApprovalLifetime)) {
		return corrupt("invalid approval")
	}
	if err := approval.Release.Validate(); err != nil {
		return corrupt("invalid approval release binding")
	}
	if err := validateStringSet("allowed_operations", approval.AllowedOperations, 1, 32); err != nil {
		return corrupt("invalid approval operations")
	}
	if err := validateDevelopmentOperationNames(approval.AllowedOperations); err != nil {
		return corrupt("approval does not contain the complete development secure-boot campaign")
	}
	return nil
}

func validateStoredOperation(operation OperationRecord, transaction Transaction) error {
	if !validIdentifier(operation.ID) || !validIdentifier(operation.Operation) || !validDigest(operation.PlanDigest) ||
		!validDigest(operation.InputDigest) || !validDigest(operation.PrestateDigest) || !validDigest(operation.IntentAuditReceiptID) ||
		operation.IntentAt.IsZero() || operation.IntentFenceEpoch == 0 || operation.IntentFenceEpoch > transaction.FenceEpoch ||
		!operation.ApprovalExpiresAt.After(operation.IntentAt) ||
		operation.ApprovalExpiresAt.After(operation.IntentAt.Add(maximumApprovalLifetime)) ||
		operation.Release.SignedReleaseManifestDigest != transaction.BundleDigest ||
		operation.Release.ExpectedCustomerKeyHash != transaction.ExpectedCustomerKeyHash {
		return corrupt("invalid operation intent")
	}
	if err := operation.Release.Validate(); err != nil {
		return corrupt("invalid operation release binding")
	}
	switch operation.Status {
	case OperationIntentRecorded:
		if operation.OutputDigest != "" || operation.ObservationDigest != "" || operation.EvidenceAuditReceiptID != "" || operation.EvidenceAt != nil || operation.ReconciliationAuditReceiptID != "" {
			return corrupt("intent-only operation unexpectedly contains evidence")
		}
	case OperationSucceeded, OperationFailed:
		if !validDigest(operation.OutputDigest) || !validDigest(operation.ObservationDigest) || !validDigest(operation.EvidenceAuditReceiptID) || operation.EvidenceAt == nil {
			return corrupt("operation evidence is incomplete")
		}
	case OperationUncertain:
		if operation.EvidenceAuditReceiptID != "" {
			if !validDigest(operation.OutputDigest) || !validDigest(operation.ObservationDigest) || !validDigest(operation.EvidenceAuditReceiptID) || operation.EvidenceAt == nil {
				return corrupt("uncertain operation evidence is incomplete")
			}
		} else if !validDigest(operation.ObservationDigest) || !validDigest(operation.ReconciliationAuditReceiptID) || operation.EvidenceAt == nil ||
			(operation.OutputDigest != "" && !validDigest(operation.OutputDigest)) {
			return corrupt("unknown reconciliation evidence is incomplete")
		}
	case OperationConfirmedApplied:
		if !validDigest(operation.OutputDigest) || !validDigest(operation.ObservationDigest) || !validDigest(operation.ReconciliationAuditReceiptID) || operation.EvidenceAt == nil {
			return corrupt("confirmed-applied reconciliation is incomplete")
		}
	case OperationConfirmedNotApplied:
		if operation.OutputDigest != "" && !validDigest(operation.OutputDigest) {
			return corrupt("confirmed-not-applied output digest is invalid")
		}
		if !validDigest(operation.ObservationDigest) || !validDigest(operation.ReconciliationAuditReceiptID) || operation.EvidenceAt == nil {
			return corrupt("confirmed-not-applied reconciliation is incomplete")
		}
	default:
		return corrupt("unsupported operation status")
	}
	return nil
}

func corrupt(message string) error {
	return fmt.Errorf("%w: %s", ErrCorruptStore, message)
}
