// Package livestation provides the versioned, authoritative state/action
// contract for a hardware-backed provisioning station. It is deliberately
// separate from stationui, whose graph remains an explicit simulation.
package livestation

import "time"

const (
	StateSchemaVersion  = "provisioning.kaiba.network/station-live-state/v1alpha1"
	ExportSchemaVersion = "provisioning.kaiba.network/station-live-export/v1alpha1"
	RollbackStatus      = "rollback_unimplemented"
)

type Phase string

const (
	PhaseStationAdmission             Phase = "station_admission"
	PhaseTransactionCreation          Phase = "transaction_creation"
	PhaseReady                        Phase = "ready"
	PhaseTargetBound                  Phase = "target_bound"
	PhaseQualifiedFreshCandidate      Phase = "qualified_fresh_candidate"
	PhasePrepared                     Phase = "prepared"
	PhaseCommitApproved               Phase = "commit_approved"
	PhaseCommitIntentRecorded         Phase = "commit_intent_recorded"
	PhaseReconciliationRequired       Phase = "reconciliation_required"
	PhaseCommitReadbackVerified       Phase = "commit_readback_verified"
	PhaseSignedBootVerified           Phase = "signed_boot_verified"
	PhaseOwnedReadbackVerified        Phase = "owned_readback_verified"
	PhaseRecoveryVerified             Phase = "recovery_verified"
	PhasePostRecoveryReadbackVerified Phase = "post_recovery_readback_verified"
	PhaseNegativeBootVerified         Phase = "negative_boot_verified"
	PhaseRootIntegrityVerified        Phase = "root_integrity_verified"
	PhaseAuditReconciled              Phase = "audit_reconciled"
	PhaseSecurityApplied              Phase = "security_applied"
	PhaseStopped                      Phase = "stopped"
	PhaseQuarantined                  Phase = "quarantined"
)

type Action string

const (
	ActionRunStationAdmission   Action = "run_station_admission"
	ActionCreateTransaction     Action = "create_transaction"
	ActionAttachTarget          Action = "attach_target"
	ActionRunFreshQualification Action = "run_fresh_qualification"
	ActionPrepareTransaction    Action = "prepare_transaction"
	ActionRequestCommitApproval Action = "request_commit_approval"
	ActionRecordCommitIntent    Action = "record_commit_intent"
	ActionExecuteCommit         Action = "execute_commit"
	ActionReconcileCommit       Action = "reconcile_commit"
	ActionConfirmSignedBoot     Action = "confirm_signed_boot"
	ActionRunOwnedReadback      Action = "run_owned_readback"
	ActionTestOwnedRecovery     Action = "test_owned_recovery"
	ActionRerunOwnedReadback    Action = "rerun_owned_readback"
	ActionTestNegativeBoot      Action = "test_negative_boot"
	ActionTestRootIntegrity     Action = "test_root_integrity"
	ActionReconcileAudit        Action = "reconcile_audit"
	ActionMarkSecurityApplied   Action = "mark_security_applied"
	ActionExportRedacted        Action = "export_redacted"
	ActionReset                 Action = "reset"

	// ActionMarkEnrollmentReady is reserved so callers receive a deterministic
	// rejection. It is never present in AllowedActions in this milestone.
	ActionMarkEnrollmentReady Action = "mark_enrollment_ready"
)

type ActionClassification string

const (
	ActionAdministrative         ActionClassification = "administrative"
	ActionReadOnly               ActionClassification = "read_only"
	ActionReversible             ActionClassification = "reversible"
	ActionAuthorizationAffecting ActionClassification = "authorization_affecting"
	ActionIrreversible           ActionClassification = "irreversible"
)

type ActionRequest struct {
	Action           Action `json:"action"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type ActionPresentation struct {
	Action               Action               `json:"action"`
	Label                string               `json:"label"`
	Description          string               `json:"description"`
	Classification       ActionClassification `json:"classification"`
	RequiresConfirmation bool                 `json:"requires_confirmation"`
	PointOfNoReturn      bool                 `json:"point_of_no_return"`
}

type DeviceLifecycle string

const (
	LifecycleUnregistered            DeviceLifecycle = "unregistered"
	LifecycleQualifiedFreshCandidate DeviceLifecycle = "qualified_fresh_candidate"
	LifecyclePrepared                DeviceLifecycle = "prepared"
	LifecycleCommitInProgress        DeviceLifecycle = "commit_in_progress"
	LifecycleSecurityApplied         DeviceLifecycle = "security_applied"
	LifecycleOwnedQuarantined        DeviceLifecycle = "owned_quarantined"
)

type TransactionStatus string

const (
	TransactionCreated         TransactionStatus = "created"
	TransactionTargetBound     TransactionStatus = "target_bound"
	TransactionPreflightPassed TransactionStatus = "preflight_passed"
	TransactionCommitApproved  TransactionStatus = "commit_approved"
	TransactionSecurityApplied TransactionStatus = "security_applied"
	TransactionAborted         TransactionStatus = "aborted"
	TransactionQuarantined     TransactionStatus = "quarantined"
)

type StationState struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type LaneState struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	USBPath  string `json:"usb_path"`
	UARTPath string `json:"uart_path"`
}

type WorkflowStage struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

type TransactionSummary struct {
	ID                          string            `json:"id"`
	Status                      TransactionStatus `json:"status"`
	ClaimID                     string            `json:"claim_id"`
	FenceEpoch                  uint64            `json:"fence_epoch"`
	TargetFingerprint           string            `json:"target_fingerprint"`
	PlanDigest                  string            `json:"plan_digest"`
	ApprovalID                  string            `json:"approval_id"`
	IntentReceipt               string            `json:"intent_receipt"`
	CommitExecutions            int               `json:"commit_executions"`
	IrreversibleBoundaryCrossed bool              `json:"irreversible_boundary_crossed"`
}

type ManifestSummary struct {
	ID                        string `json:"id"`
	Digest                    string `json:"digest"`
	PlanDigest                string `json:"plan_digest"`
	ExpectedCustomerKeyHash   string `json:"expected_customer_key_hash"`
	EEPROMImageDigest         string `json:"eeprom_image_digest"`
	BootImageDigest           string `json:"boot_image_digest"`
	FreshCommitBundleDigest   string `json:"fresh_commit_bundle_digest"`
	OwnedRecoveryBundleDigest string `json:"owned_recovery_bundle_digest"`
	VerificationStatus        string `json:"verification_status"`
	RollbackPolicy            string `json:"rollback_policy"`
}

type TargetSummary struct {
	Model               string `json:"model"`
	ProfileID           string `json:"profile_id"`
	TargetFingerprint   string `json:"target_fingerprint"`
	CustomerKeyHash     string `json:"customer_key_hash"`
	EEPROMHash          string `json:"eeprom_hash"`
	SecureBootState     string `json:"secure_boot_state"`
	VideoCoreJTAGLocked bool   `json:"videocore_jtag_locked"`
}

type Finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Evidence struct {
	ID         string    `json:"id"`
	Stage      string    `json:"stage"`
	Status     string    `json:"status"`
	Digest     string    `json:"digest"`
	Detail     string    `json:"detail"`
	ReceiptID  string    `json:"receipt_id"`
	RecordedAt time.Time `json:"recorded_at"`
}

type Outcome struct {
	Status  string `json:"status"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

type SafetyState struct {
	Simulation                   bool   `json:"simulation"`
	SecretFree                   bool   `json:"secret_free"`
	AuthoritativeEvidence        bool   `json:"authoritative_evidence"`
	LiveMutationCapable          bool   `json:"live_mutation_capable"`
	IrreversibleBoundaryCrossed  bool   `json:"irreversible_boundary_crossed"`
	RollbackStatus               string `json:"rollback_status"`
	EnrollmentCapable            bool   `json:"enrollment_capable"`
	DebugControlsLocked          bool   `json:"debug_controls_locked"`
	EEPROMWriteProtectionApplied bool   `json:"eeprom_write_protection_applied"`
}

type RedactedExport struct {
	SchemaVersion string             `json:"schema_version"`
	Simulation    bool               `json:"simulation"`
	SecretFree    bool               `json:"secret_free"`
	StationID     string             `json:"station_id"`
	LaneID        string             `json:"lane_id"`
	Lifecycle     DeviceLifecycle    `json:"lifecycle"`
	Transaction   TransactionSummary `json:"transaction"`
	Manifest      ManifestSummary    `json:"manifest"`
	Target        TargetSummary      `json:"target"`
	Evidence      []Evidence         `json:"evidence"`
	Outcome       Outcome            `json:"outcome"`
	Safety        SafetyState        `json:"safety"`
}

// State intentionally has no scenario or scenarios fields. Live state is
// derived only from the orchestrator and authoritative evidence.
type State struct {
	SchemaVersion       string               `json:"schema_version"`
	Revision            uint64               `json:"revision"`
	Simulation          bool                 `json:"simulation"`
	SecretFree          bool                 `json:"secret_free"`
	Station             StationState         `json:"station"`
	Lane                LaneState            `json:"lane"`
	Phase               Phase                `json:"phase"`
	Lifecycle           DeviceLifecycle      `json:"lifecycle"`
	WorkflowStages      []WorkflowStage      `json:"workflow_stages"`
	Instruction         string               `json:"instruction"`
	AllowedActions      []Action             `json:"allowed_actions"`
	ActionPresentations []ActionPresentation `json:"action_presentations"`
	Transaction         *TransactionSummary  `json:"transaction,omitempty"`
	Manifest            *ManifestSummary     `json:"manifest,omitempty"`
	Target              *TargetSummary       `json:"target,omitempty"`
	Findings            []Finding            `json:"findings"`
	Evidence            []Evidence           `json:"evidence"`
	Outcome             *Outcome             `json:"outcome,omitempty"`
	Safety              SafetyState          `json:"safety"`
	ExportRecord        *RedactedExport      `json:"export_record,omitempty"`
}
