// Package controlplane implements the reference provisioning coordinator and
// inventory state machine. It is platform-neutral: physical execution remains
// the responsibility of the station lane guard and target adapter.
package controlplane

import (
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	TransactionSchemaVersion = "provisioning.kaiba.network/control-transaction/v1alpha2"
	StoreSchemaVersion       = "provisioning.kaiba.network/control-store/v1alpha2"
	CommandSchemaVersion     = "provisioning.kaiba.network/control-command/v1alpha1"

	CreateTransactionRequestSchemaVersion    = "provisioning.kaiba.network/create-transaction-request/v1alpha2"
	AcquireClaimRequestSchemaVersion         = "provisioning.kaiba.network/acquire-claim-request/v1alpha1"
	RenewClaimRequestSchemaVersion           = "provisioning.kaiba.network/renew-claim-request/v1alpha1"
	TransferClaimRequestSchemaVersion        = "provisioning.kaiba.network/transfer-claim-request/v1alpha1"
	ReleaseClaimRequestSchemaVersion         = "provisioning.kaiba.network/release-claim-request/v1alpha1"
	BindTargetRequestSchemaVersion           = "provisioning.kaiba.network/bind-target-request/v1alpha1"
	RecordApprovalRequestSchemaVersion       = "provisioning.kaiba.network/record-approval-request/v1alpha2"
	RecordIntentRequestSchemaVersion         = "provisioning.kaiba.network/record-intent-request/v1alpha1"
	RecordEvidenceRequestSchemaVersion       = "provisioning.kaiba.network/record-evidence-request/v1alpha1"
	RecordReconciliationRequestSchemaVersion = "provisioning.kaiba.network/record-reconciliation-request/v1alpha1"
	QuarantineRequestSchemaVersion           = "provisioning.kaiba.network/quarantine-request/v1alpha1"
	AbortRequestSchemaVersion                = "provisioning.kaiba.network/abort-request/v1alpha1"
	SecurityAppliedRequestSchemaVersion      = "provisioning.kaiba.network/security-applied-request/v1alpha1"
)

type TransactionStatus string

const (
	StatusCreated                TransactionStatus = "created"
	StatusClaimed                TransactionStatus = "claimed"
	StatusTargetBound            TransactionStatus = "target_bound"
	StatusCommitApproved         TransactionStatus = "commit_approved"
	StatusMutationInProgress     TransactionStatus = "mutation_in_progress"
	StatusReconciliationRequired TransactionStatus = "reconciliation_required"
	StatusReconciled             TransactionStatus = "reconciled"
	StatusSecurityApplied        TransactionStatus = "security_applied"
	StatusAborted                TransactionStatus = "aborted"
	StatusQuarantined            TransactionStatus = "quarantined"
)

type ClaimMode string

const (
	ClaimModeMutation       ClaimMode = "mutation"
	ClaimModeReconciliation ClaimMode = "reconciliation"
)

type ClaimStatus string

const (
	ClaimActive      ClaimStatus = "active"
	ClaimReleased    ClaimStatus = "released"
	ClaimTransferred ClaimStatus = "transferred"
	ClaimExpired     ClaimStatus = "expired"
)

type OperationStatus string

const (
	OperationIntentRecorded      OperationStatus = "intent_recorded"
	OperationSucceeded           OperationStatus = "succeeded"
	OperationFailed              OperationStatus = "failed"
	OperationUncertain           OperationStatus = "uncertain"
	OperationConfirmedApplied    OperationStatus = "confirmed_applied"
	OperationConfirmedNotApplied OperationStatus = "confirmed_not_applied"
)

type EvidenceResult string

const (
	EvidenceSucceeded EvidenceResult = "succeeded"
	EvidenceFailed    EvidenceResult = "failed"
	EvidenceUncertain EvidenceResult = "uncertain"
)

type ReconciliationResolution string

const (
	ResolutionConfirmedApplied    ReconciliationResolution = "confirmed_applied"
	ResolutionConfirmedNotApplied ReconciliationResolution = "confirmed_not_applied"
	ResolutionUnknown             ReconciliationResolution = "unknown"
)

type TargetBinding struct {
	Fingerprint       string    `json:"fingerprint"`
	ObservationDigest string    `json:"observation_digest"`
	CustomerKeyHash   string    `json:"customer_key_hash"`
	BoundAt           time.Time `json:"bound_at"`
	FenceEpoch        uint64    `json:"fence_epoch"`
}

type Claim struct {
	ID            string      `json:"id"`
	Mode          ClaimMode   `json:"mode"`
	Status        ClaimStatus `json:"status"`
	StationID     string      `json:"station_id"`
	LaneID        string      `json:"lane_id"`
	AssetID       string      `json:"asset_id"`
	FenceEpoch    uint64      `json:"fence_epoch"`
	AllowedStages []string    `json:"allowed_stages"`
	AcquiredAt    time.Time   `json:"acquired_at"`
	ExpiresAt     time.Time   `json:"expires_at"`
	ClosedAt      *time.Time  `json:"closed_at,omitempty"`
}

type Approval struct {
	ID                string                 `json:"id"`
	ApproverID        string                 `json:"approver_id"`
	TransactionDigest string                 `json:"transaction_digest"`
	PlanDigest        string                 `json:"plan_digest"`
	StationID         string                 `json:"station_id"`
	LaneID            string                 `json:"lane_id"`
	FenceEpoch        uint64                 `json:"fence_epoch"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	Release           releasebinding.Binding `json:"release"`
	AllowedOperations []string               `json:"allowed_operations"`
	AuditReceiptID    string                 `json:"audit_receipt_id"`
	ApprovedAt        time.Time              `json:"approved_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
}

type OperationRecord struct {
	ID                           string                 `json:"id"`
	Operation                    string                 `json:"operation"`
	Status                       OperationStatus        `json:"status"`
	PlanDigest                   string                 `json:"plan_digest"`
	Release                      releasebinding.Binding `json:"release"`
	ApprovalExpiresAt            time.Time              `json:"approval_expires_at"`
	InputDigest                  string                 `json:"input_digest"`
	PrestateDigest               string                 `json:"prestate_digest"`
	IntentAuditReceiptID         string                 `json:"intent_audit_receipt_id"`
	IntentAt                     time.Time              `json:"intent_at"`
	IntentFenceEpoch             uint64                 `json:"intent_fence_epoch"`
	OutputDigest                 string                 `json:"output_digest,omitempty"`
	ObservationDigest            string                 `json:"observation_digest,omitempty"`
	EvidenceAuditReceiptID       string                 `json:"evidence_audit_receipt_id,omitempty"`
	EvidenceAt                   *time.Time             `json:"evidence_at,omitempty"`
	ReconciliationAuditReceiptID string                 `json:"reconciliation_audit_receipt_id,omitempty"`
}

type QuarantineRecord struct {
	ReasonCode        string    `json:"reason_code"`
	ObservationDigest string    `json:"observation_digest"`
	AuditReceiptID    string    `json:"audit_receipt_id"`
	FenceEpoch        uint64    `json:"fence_epoch"`
	RecordedAt        time.Time `json:"recorded_at"`
}

type SecurityAppliedRecord struct {
	EvidenceDigest        string    `json:"evidence_digest"`
	AuditReceiptID        string    `json:"audit_receipt_id"`
	RollbackStatus        string    `json:"rollback_status"`
	ReleaseClassification string    `json:"release_classification"`
	RecordedAt            time.Time `json:"recorded_at"`
}

type AbortRecord struct {
	ReusableBaselineDigest string    `json:"reusable_baseline_digest"`
	AuditReceiptID         string    `json:"audit_receipt_id"`
	RecordedAt             time.Time `json:"recorded_at"`
}

type Transaction struct {
	SchemaVersion                   string                 `json:"schema_version"`
	ID                              string                 `json:"id"`
	ResourceVersion                 uint64                 `json:"resource_version"`
	Status                          TransactionStatus      `json:"status"`
	AssetID                         string                 `json:"asset_id"`
	IntendedLogicalID               string                 `json:"intended_logical_id"`
	ProfileID                       string                 `json:"profile_id"`
	BundleDigest                    string                 `json:"bundle_digest"`
	PolicyDigest                    string                 `json:"policy_digest"`
	ExpectedPrestateCustomerKeyHash string                 `json:"expected_prestate_customer_key_hash"`
	ExpectedCustomerKeyHash         string                 `json:"expected_customer_key_hash"`
	TransactionDigest               string                 `json:"transaction_digest"`
	FenceEpoch                      uint64                 `json:"fence_epoch"`
	ActiveClaim                     *Claim                 `json:"active_claim,omitempty"`
	ClaimHistory                    []Claim                `json:"claim_history"`
	Target                          *TargetBinding         `json:"target,omitempty"`
	Approval                        *Approval              `json:"approval,omitempty"`
	Operations                      []OperationRecord      `json:"operations"`
	Quarantine                      *QuarantineRecord      `json:"quarantine,omitempty"`
	SecurityApplied                 *SecurityAppliedRecord `json:"security_applied,omitempty"`
	Abort                           *AbortRecord           `json:"abort,omitempty"`
	CreatedAt                       time.Time              `json:"created_at"`
	UpdatedAt                       time.Time              `json:"updated_at"`
}

type CreateTransactionRequest struct {
	SchemaVersion                   string `json:"schema_version"`
	IdempotencyKey                  string `json:"idempotency_key"`
	TransactionID                   string `json:"transaction_id"`
	AssetID                         string `json:"asset_id"`
	IntendedLogicalID               string `json:"intended_logical_id"`
	ProfileID                       string `json:"profile_id"`
	BundleDigest                    string `json:"bundle_digest"`
	PolicyDigest                    string `json:"policy_digest"`
	ExpectedPrestateCustomerKeyHash string `json:"expected_prestate_customer_key_hash"`
	ExpectedCustomerKeyHash         string `json:"expected_customer_key_hash"`
}

type AcquireClaimRequest struct {
	SchemaVersion           string    `json:"schema_version"`
	IdempotencyKey          string    `json:"idempotency_key"`
	TransactionID           string    `json:"transaction_id"`
	ExpectedResourceVersion uint64    `json:"expected_resource_version"`
	StationID               string    `json:"station_id"`
	LaneID                  string    `json:"lane_id"`
	Mode                    ClaimMode `json:"mode"`
	AllowedStages           []string  `json:"allowed_stages"`
	LeaseDurationSeconds    uint32    `json:"lease_duration_seconds"`
}

type RenewClaimRequest struct {
	SchemaVersion           string `json:"schema_version"`
	IdempotencyKey          string `json:"idempotency_key"`
	TransactionID           string `json:"transaction_id"`
	ExpectedResourceVersion uint64 `json:"expected_resource_version"`
	ClaimID                 string `json:"claim_id"`
	FenceEpoch              uint64 `json:"fence_epoch"`
	LeaseDurationSeconds    uint32 `json:"lease_duration_seconds"`
}

type TransferClaimRequest struct {
	SchemaVersion           string    `json:"schema_version"`
	IdempotencyKey          string    `json:"idempotency_key"`
	TransactionID           string    `json:"transaction_id"`
	ExpectedResourceVersion uint64    `json:"expected_resource_version"`
	ClaimID                 string    `json:"claim_id"`
	FenceEpoch              uint64    `json:"fence_epoch"`
	NewStationID            string    `json:"new_station_id"`
	NewLaneID               string    `json:"new_lane_id"`
	Mode                    ClaimMode `json:"mode"`
	AllowedStages           []string  `json:"allowed_stages"`
	LeaseDurationSeconds    uint32    `json:"lease_duration_seconds"`
}

type ReleaseClaimRequest struct {
	SchemaVersion           string `json:"schema_version"`
	IdempotencyKey          string `json:"idempotency_key"`
	TransactionID           string `json:"transaction_id"`
	ExpectedResourceVersion uint64 `json:"expected_resource_version"`
	ClaimID                 string `json:"claim_id"`
	FenceEpoch              uint64 `json:"fence_epoch"`
}

type MutationContext struct {
	TransactionID           string `json:"transaction_id"`
	ExpectedResourceVersion uint64 `json:"expected_resource_version"`
	ClaimID                 string `json:"claim_id"`
	FenceEpoch              uint64 `json:"fence_epoch"`
}

type BindTargetRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	TargetFingerprint string `json:"target_fingerprint"`
	ObservationDigest string `json:"observation_digest"`
	CustomerKeyHash   string `json:"customer_key_hash"`
}

type RecordApprovalRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	ApprovalID        string                 `json:"approval_id"`
	ApproverID        string                 `json:"approver_id"`
	TransactionDigest string                 `json:"transaction_digest"`
	PlanDigest        string                 `json:"plan_digest"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	Release           releasebinding.Binding `json:"release"`
	AllowedOperations []string               `json:"allowed_operations"`
	AuditReceiptID    string                 `json:"audit_receipt_id"`
	ExpiresAt         time.Time              `json:"expires_at"`
}

type RecordIntentRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	ApprovalID     string `json:"approval_id"`
	OperationID    string `json:"operation_id"`
	Operation      string `json:"operation"`
	PlanDigest     string `json:"plan_digest"`
	InputDigest    string `json:"input_digest"`
	PrestateDigest string `json:"prestate_digest"`
	AuditReceiptID string `json:"audit_receipt_id"`
}

type RecordEvidenceRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	OperationID       string         `json:"operation_id"`
	Result            EvidenceResult `json:"result"`
	OutputDigest      string         `json:"output_digest"`
	ObservationDigest string         `json:"observation_digest"`
	AuditReceiptID    string         `json:"audit_receipt_id"`
}

type RecordReconciliationRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	OperationID       string                   `json:"operation_id"`
	Resolution        ReconciliationResolution `json:"resolution"`
	OutputDigest      string                   `json:"output_digest,omitempty"`
	ObservationDigest string                   `json:"observation_digest"`
	AuditReceiptID    string                   `json:"audit_receipt_id"`
}

type QuarantineRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	ReasonCode        string `json:"reason_code"`
	ObservationDigest string `json:"observation_digest"`
	AuditReceiptID    string `json:"audit_receipt_id"`
}

type AbortRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	ReusableBaselineDigest string `json:"reusable_baseline_digest"`
	AuditReceiptID         string `json:"audit_receipt_id"`
}

type SecurityAppliedRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	MutationContext
	PlanDigest            string `json:"plan_digest"`
	EvidenceDigest        string `json:"evidence_digest"`
	AuditReceiptID        string `json:"audit_receipt_id"`
	RollbackStatus        string `json:"rollback_status"`
	ReleaseClassification string `json:"release_classification"`
}
