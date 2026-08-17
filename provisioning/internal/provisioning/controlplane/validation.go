package controlplane

import (
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
)

func validateCreateRequest(request CreateTransactionRequest) error {
	if err := validateEnvelope(request.SchemaVersion, CreateTransactionRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"transaction_id": request.TransactionID, "asset_id": request.AssetID,
		"intended_logical_id": request.IntendedLogicalID, "profile_id": request.ProfileID,
	} {
		if !validIdentifier(value) {
			return invalid(name + " is invalid")
		}
	}
	for name, value := range map[string]string{
		"bundle_digest": request.BundleDigest, "policy_digest": request.PolicyDigest,
		"expected_prestate_customer_key_hash": request.ExpectedPrestateCustomerKeyHash,
		"expected_customer_key_hash":          request.ExpectedCustomerKeyHash,
	} {
		if !validDigest(value) {
			return invalid(name + " must be a lowercase sha256 digest")
		}
	}
	return nil
}

func validateAcquireClaimRequest(request AcquireClaimRequest) error {
	if err := validateEnvelope(request.SchemaVersion, AcquireClaimRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if !validIdentifier(request.TransactionID) || !validIdentifier(request.StationID) || !validIdentifier(request.LaneID) {
		return invalid("transaction_id, station_id, or lane_id is invalid")
	}
	if request.ExpectedResourceVersion == 0 {
		return invalid("expected_resource_version must be non-zero")
	}
	if request.Mode != ClaimModeMutation && request.Mode != ClaimModeReconciliation {
		return invalid("claim mode is unsupported")
	}
	if err := validateStringSet("allowed_stages", request.AllowedStages, 1, 32); err != nil {
		return err
	}
	return validateLease(request.LeaseDurationSeconds)
}

func validateRenewClaimRequest(request RenewClaimRequest) error {
	if err := validateEnvelope(request.SchemaVersion, RenewClaimRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(MutationContext{
		TransactionID: request.TransactionID, ExpectedResourceVersion: request.ExpectedResourceVersion,
		ClaimID: request.ClaimID, FenceEpoch: request.FenceEpoch,
	}); err != nil {
		return err
	}
	return validateLease(request.LeaseDurationSeconds)
}

func validateTransferClaimRequest(request TransferClaimRequest) error {
	if err := validateEnvelope(request.SchemaVersion, TransferClaimRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(MutationContext{
		TransactionID: request.TransactionID, ExpectedResourceVersion: request.ExpectedResourceVersion,
		ClaimID: request.ClaimID, FenceEpoch: request.FenceEpoch,
	}); err != nil {
		return err
	}
	if !validIdentifier(request.NewStationID) || !validIdentifier(request.NewLaneID) {
		return invalid("new station_id or lane_id is invalid")
	}
	if request.Mode != ClaimModeMutation && request.Mode != ClaimModeReconciliation {
		return invalid("claim mode is unsupported")
	}
	if err := validateStringSet("allowed_stages", request.AllowedStages, 1, 32); err != nil {
		return err
	}
	return validateLease(request.LeaseDurationSeconds)
}

func validateReleaseClaimRequest(request ReleaseClaimRequest) error {
	if err := validateEnvelope(request.SchemaVersion, ReleaseClaimRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	return validateMutationContext(MutationContext{
		TransactionID: request.TransactionID, ExpectedResourceVersion: request.ExpectedResourceVersion,
		ClaimID: request.ClaimID, FenceEpoch: request.FenceEpoch,
	})
}

func validateBindTargetRequest(request BindTargetRequest) error {
	if err := validateEnvelope(request.SchemaVersion, BindTargetRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validDigest(request.TargetFingerprint) || !validDigest(request.ObservationDigest) || !validDigest(request.CustomerKeyHash) {
		return invalid("target fingerprint, observation digest, and customer key hash must be lowercase sha256 digests")
	}
	return nil
}

func validateRecordApprovalRequest(request RecordApprovalRequest, now time.Time) error {
	if err := validateEnvelope(request.SchemaVersion, RecordApprovalRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validIdentifier(request.ApprovalID) || !validIdentifier(request.ApproverID) {
		return invalid("approval_id or approver_id is invalid")
	}
	for _, digest := range []string{request.TransactionDigest, request.PlanDigest, request.TargetFingerprint, request.AuditReceiptID} {
		if !validDigest(digest) {
			return invalid("approval digest or audit receipt is invalid")
		}
	}
	if err := request.Release.Validate(); err != nil {
		return invalid("release binding is invalid: " + err.Error())
	}
	if err := validateStringSet("allowed_operations", request.AllowedOperations, 1, 32); err != nil {
		return err
	}
	if err := validateDevelopmentOperationNames(request.AllowedOperations); err != nil {
		return invalid("allowed_operations: " + err.Error())
	}
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maximumApprovalLifetime)) {
		return invalid("approval expiry must be in the future and no more than 24 hours away")
	}
	return nil
}

func validateRecordIntentRequest(request RecordIntentRequest) error {
	if err := validateEnvelope(request.SchemaVersion, RecordIntentRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validIdentifier(request.ApprovalID) || !validIdentifier(request.OperationID) || !validIdentifier(request.Operation) {
		return invalid("approval_id, operation_id, or operation is invalid")
	}
	for _, digest := range []string{request.PlanDigest, request.InputDigest, request.PrestateDigest, request.AuditReceiptID} {
		if !validDigest(digest) {
			return invalid("intent digest or audit receipt is invalid")
		}
	}
	return nil
}

func validateRecordEvidenceRequest(request RecordEvidenceRequest) error {
	if err := validateEnvelope(request.SchemaVersion, RecordEvidenceRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validIdentifier(request.OperationID) {
		return invalid("operation_id is invalid")
	}
	if request.Result != EvidenceSucceeded && request.Result != EvidenceFailed && request.Result != EvidenceUncertain {
		return invalid("evidence result is unsupported")
	}
	for _, digest := range []string{request.OutputDigest, request.ObservationDigest, request.AuditReceiptID} {
		if !validDigest(digest) {
			return invalid("evidence digest or audit receipt is invalid")
		}
	}
	return nil
}

func validateRecordReconciliationRequest(request RecordReconciliationRequest) error {
	if err := validateEnvelope(request.SchemaVersion, RecordReconciliationRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validIdentifier(request.OperationID) {
		return invalid("operation_id is invalid")
	}
	switch request.Resolution {
	case ResolutionConfirmedApplied:
		if !validDigest(request.OutputDigest) {
			return invalid("confirmed_applied reconciliation requires output_digest")
		}
	case ResolutionConfirmedNotApplied, ResolutionUnknown:
		if request.OutputDigest != "" && !validDigest(request.OutputDigest) {
			return invalid("optional reconciliation output_digest is invalid")
		}
	default:
		return invalid("reconciliation resolution is unsupported")
	}
	if !validDigest(request.ObservationDigest) || !validDigest(request.AuditReceiptID) {
		return invalid("reconciliation observation digest or audit receipt is invalid")
	}
	return nil
}

func validateQuarantineRequest(request QuarantineRequest) error {
	if err := validateEnvelope(request.SchemaVersion, QuarantineRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validIdentifier(request.ReasonCode) || !validDigest(request.ObservationDigest) || !validDigest(request.AuditReceiptID) {
		return invalid("quarantine reason, observation digest, or audit receipt is invalid")
	}
	return nil
}

func validateAbortRequest(request AbortRequest) error {
	if err := validateEnvelope(request.SchemaVersion, AbortRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	if !validDigest(request.ReusableBaselineDigest) || !validDigest(request.AuditReceiptID) {
		return invalid("abort baseline digest or audit receipt is invalid")
	}
	return nil
}

func validateSecurityAppliedRequest(request SecurityAppliedRequest) error {
	if err := validateEnvelope(request.SchemaVersion, SecurityAppliedRequestSchemaVersion, request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateMutationContext(request.MutationContext); err != nil {
		return err
	}
	for _, digest := range []string{request.PlanDigest, request.EvidenceDigest, request.AuditReceiptID} {
		if !validDigest(digest) {
			return invalid("security-applied digest or audit receipt is invalid")
		}
	}
	if request.RollbackStatus != "rollback_unimplemented" {
		return invalid("initial implementation requires rollback_status rollback_unimplemented")
	}
	if request.ReleaseClassification != "development_asset" {
		return invalid("initial implementation permits only development_asset release classification")
	}
	return nil
}

func validateEnvelope(got, want, idempotencyKey string) error {
	if got != want {
		return invalid("unsupported schema_version")
	}
	if !validIdentifier(idempotencyKey) {
		return invalid("idempotency_key is invalid")
	}
	return nil
}

func validateMutationContext(context MutationContext) error {
	if !validIdentifier(context.TransactionID) || !validIdentifier(context.ClaimID) {
		return invalid("transaction_id or claim_id is invalid")
	}
	if context.ExpectedResourceVersion == 0 || context.FenceEpoch == 0 {
		return invalid("expected_resource_version and fence_epoch must be non-zero")
	}
	return nil
}

func validateLease(seconds uint32) error {
	duration := time.Duration(seconds) * time.Second
	if duration < minimumLease || duration > maximumLease {
		return invalid("lease_duration_seconds must be between 30 and 3600")
	}
	return nil
}

func validateStringSet(name string, values []string, minimum, maximum int) error {
	if len(values) < minimum || len(values) > maximum {
		return invalid(fmt.Sprintf("%s must contain between %d and %d entries", name, minimum, maximum))
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value) {
			return invalid(name + " contains an invalid entry")
		}
		if _, duplicate := seen[value]; duplicate {
			return invalid(name + " contains a duplicate entry")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateDevelopmentOperationNames(values []string) error {
	operations := make([]campaign.Operation, len(values))
	for index, value := range values {
		operations[index] = campaign.Operation(value)
	}
	return campaign.ValidateDevelopmentOperations(operations)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
