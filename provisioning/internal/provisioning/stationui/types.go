// Package stationui provides the explicitly simulated provisioning-station
// workflow used by the kiosk demonstration. It has no hardware backend and
// cannot authorize or perform persistent device mutations.
package stationui

const (
	StateSchemaVersion  = "provisioning.kaiba.network/station-demo-state/v1alpha2"
	ExportSchemaVersion = "provisioning.kaiba.network/station-demo-export/v1alpha2"

	AssessmentDisclaimer = "This synthetic workflow is not device authentication or attestation, does not establish a live target's unprovisioned state, and cannot authorize or perform irreversible provisioning."
)

type ScenarioID string

const (
	ScenarioHappyPath                    ScenarioID = "happy-path"
	ScenarioClassMismatch                ScenarioID = "class-mismatch"
	ScenarioBaselineFailure              ScenarioID = "baseline-failure"
	ScenarioMultipleTargets              ScenarioID = "multiple-targets"
	ScenarioAcquisitionError             ScenarioID = "acquisition-error"
	ScenarioTargetReplaced               ScenarioID = "target-replaced"
	ScenarioMutationSafetyViolation      ScenarioID = "mutation-safety-violation"
	ScenarioBootFailure                  ScenarioID = "boot-failure"
	ScenarioPreparationFailure           ScenarioID = "preparation-failure"
	ScenarioApprovalFailure              ScenarioID = "approval-failure"
	ScenarioTrustFailure                 ScenarioID = "trust-failure"
	ScenarioCommitUncertain              ScenarioID = "commit-uncertain"
	ScenarioCommitReadbackMismatch       ScenarioID = "commit-readback-mismatch"
	ScenarioSignedBootFailure            ScenarioID = "signed-boot-failure"
	ScenarioOwnedReadbackMismatch        ScenarioID = "owned-readback-mismatch"
	ScenarioRecoveryFailure              ScenarioID = "recovery-failure"
	ScenarioNegativeBootFailure          ScenarioID = "negative-boot-failure"
	ScenarioRootIntegrityFailure         ScenarioID = "root-integrity-failure"
	ScenarioRollbackFailure              ScenarioID = "rollback-failure"
	ScenarioFinalizationFailure          ScenarioID = "finalization-failure"
	ScenarioFinalRetestFailure           ScenarioID = "final-retest-failure"
	ScenarioAuditFailure                 ScenarioID = "audit-failure"
	ScenarioDeferredBaselineFailure      ScenarioID = "deferred-baseline-failure"
	ScenarioPrecommitTargetReplaced      ScenarioID = "precommit-target-replaced"
	ScenarioPostRecoveryReadbackMismatch ScenarioID = "post-recovery-readback-mismatch"
)

type Phase string

const (
	PhaseStationAdmission               Phase = "station_admission"
	PhaseTransactionCreation            Phase = "transaction_creation"
	PhaseReady                          Phase = "ready"
	PhaseTargetDetected                 Phase = "target_detected"
	PhasePowerCycleRequired             Phase = "power_cycle_required"
	PhaseAwaitingReconnect              Phase = "awaiting_reconnect"
	PhaseSecondProbeReady               Phase = "second_probe_ready"
	PhaseAwaitingNormalBootConfirmation Phase = "awaiting_normal_boot_confirmation"
	PhaseQualifiedFreshCandidate        Phase = "qualified_fresh_candidate"
	PhaseBaselineClosed                 Phase = "baseline_closed"
	PhasePrepared                       Phase = "prepared"
	PhaseCommitApproved                 Phase = "commit_approved"
	PhaseTrustEstablished               Phase = "trust_established"
	PhaseCommitTargetReidentified       Phase = "commit_target_reidentified"
	PhaseCommitIntentRecorded           Phase = "commit_intent_recorded"
	PhaseCommitInProgress               Phase = "commit_in_progress"
	PhaseCommitReadbackVerified         Phase = "commit_readback_verified"
	PhaseAwaitingOwnedColdBoot          Phase = "awaiting_owned_cold_boot"
	PhaseSignedBootVerified             Phase = "signed_boot_verified"
	PhaseOwnedReadbackVerified          Phase = "owned_readback_verified"
	PhaseRecoveryVerified               Phase = "recovery_verified"
	PhasePostRecoveryReadbackVerified   Phase = "post_recovery_readback_verified"
	PhaseNegativeBootVerified           Phase = "negative_boot_verified"
	PhaseRootIntegrityVerified          Phase = "root_integrity_verified"
	PhaseRollbackVerified               Phase = "rollback_verified"
	PhaseFinalizationApproved           Phase = "finalization_approved"
	PhaseFinalizationIntentRecorded     Phase = "finalization_intent_recorded"
	PhaseFinalControlsApplied           Phase = "final_controls_applied"
	PhaseFinalColdRestartObserved       Phase = "final_cold_restart_observed"
	PhaseFinalControlsReadbackVerified  Phase = "final_controls_readback_verified"
	PhaseFinalRetestVerified            Phase = "final_retest_verified"
	PhaseAuditReconciled                Phase = "audit_reconciled"
	PhaseEnrollmentReady                Phase = "enrollment_ready"
	PhaseStopped                        Phase = "stopped"
	PhaseQuarantined                    Phase = "quarantined"
)

type Action string

const (
	ActionRunStationAdmission          Action = "run_station_admission"
	ActionCreateTransaction            Action = "create_transaction"
	ActionAttachTarget                 Action = "attach_target"
	ActionRunFirstProbe                Action = "run_first_probe"
	ActionDisconnectTarget             Action = "disconnect_target"
	ActionReconnectTarget              Action = "reconnect_target"
	ActionRunSecondProbe               Action = "run_second_probe"
	ActionConfirmBootOK                Action = "confirm_boot_ok"
	ActionConfirmBootFailed            Action = "confirm_boot_failed"
	ActionCloseDeferredBaseline        Action = "close_deferred_baseline"
	ActionPrepareTransaction           Action = "prepare_transaction"
	ActionRequestCommitApproval        Action = "request_commit_approval"
	ActionEstablishInitialTrust        Action = "establish_initial_trust"
	ActionReidentifyCommitTarget       Action = "reidentify_commit_target"
	ActionRecordCommitIntent           Action = "record_commit_intent"
	ActionExecuteCommit                Action = "execute_commit"
	ActionObserveCommitReadback        Action = "observe_commit_readback"
	ActionPowerOffOwnedTarget          Action = "power_off_owned_target"
	ActionConfirmSignedBoot            Action = "confirm_signed_boot"
	ActionRunOwnedReadback             Action = "run_owned_readback"
	ActionTestOwnedRecovery            Action = "test_owned_recovery"
	ActionRerunOwnedReadback           Action = "rerun_owned_readback"
	ActionTestNegativeBoot             Action = "test_negative_boot"
	ActionTestRootIntegrity            Action = "test_root_integrity"
	ActionTestRollback                 Action = "test_rollback"
	ActionRequestFinalizationApproval  Action = "request_finalization_approval"
	ActionRecordFinalizationIntent     Action = "record_finalization_intent"
	ActionApplyFinalControls           Action = "apply_final_controls"
	ActionColdRestartFinalizedTarget   Action = "cold_restart_finalized_target"
	ActionObserveFinalControlsReadback Action = "observe_final_controls_readback"
	ActionRunFinalRetest               Action = "run_final_retest"
	ActionReconcileAudit               Action = "reconcile_audit"
	ActionMarkEnrollmentReady          Action = "mark_enrollment_ready"
	ActionExportRedacted               Action = "export_redacted"
	ActionReset                        Action = "reset"
)

type WorkflowStageID string

const (
	WorkflowStageAdmission         WorkflowStageID = "admission"
	WorkflowStageTransaction       WorkflowStageID = "transaction"
	WorkflowStageQualification     WorkflowStageID = "qualification"
	WorkflowStagePreparation       WorkflowStageID = "preparation"
	WorkflowStageApproval          WorkflowStageID = "approval"
	WorkflowStageInitialTrust      WorkflowStageID = "initial_trust"
	WorkflowStageOwnershipCommit   WorkflowStageID = "ownership_commit"
	WorkflowStageOwnedVerification WorkflowStageID = "owned_verification"
	WorkflowStageFinalization      WorkflowStageID = "finalization"
	WorkflowStageAudit             WorkflowStageID = "audit_reconciliation"
)

type WorkflowStageStatus string

const (
	WorkflowStagePending  WorkflowStageStatus = "pending"
	WorkflowStageCurrent  WorkflowStageStatus = "current"
	WorkflowStageComplete WorkflowStageStatus = "complete"
	WorkflowStageFailed   WorkflowStageStatus = "failed"
)

type ActionClassification string

const (
	ActionAdministrative         ActionClassification = "administrative"
	ActionReadOnly               ActionClassification = "read_only"
	ActionReversible             ActionClassification = "reversible"
	ActionAuthorizationAffecting ActionClassification = "authorization_affecting"
	ActionIrreversible           ActionClassification = "irreversible"
)

type TransactionStatus string

const (
	TransactionCreated          TransactionStatus = "created"
	TransactionTargetBound      TransactionStatus = "target_bound"
	TransactionPreflightPassed  TransactionStatus = "preflight_passed"
	TransactionCommitApproved   TransactionStatus = "commit_approved"
	TransactionTrustEstablished TransactionStatus = "trust_established"
	TransactionSecurityApplied  TransactionStatus = "security_applied"
	TransactionAborted          TransactionStatus = "aborted"
	TransactionQuarantined      TransactionStatus = "quarantined"
)

type DeviceLifecycle string

const (
	LifecycleUnregistered            DeviceLifecycle = "unregistered"
	LifecycleQualifiedFreshCandidate DeviceLifecycle = "qualified_fresh_candidate"
	LifecyclePrepared                DeviceLifecycle = "prepared"
	LifecycleCommitInProgress        DeviceLifecycle = "commit_in_progress"
	LifecycleSecurityApplied         DeviceLifecycle = "security_applied"
	LifecycleEnrollmentReady         DeviceLifecycle = "enrollment_ready"
	LifecycleOwnedQuarantined        DeviceLifecycle = "owned_quarantined"
)

type EvidenceStatus string

const (
	EvidencePending  EvidenceStatus = "pending"
	EvidencePassed   EvidenceStatus = "passed"
	EvidenceFailed   EvidenceStatus = "failed"
	EvidenceRecorded EvidenceStatus = "recorded"
)

type ActionRequest struct {
	Action           Action `json:"action"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type ScenarioOption struct {
	ID     ScenarioID `json:"id"`
	Label  string     `json:"label"`
	Action Action     `json:"action"`
}

type WorkflowStage struct {
	ID     WorkflowStageID     `json:"id"`
	Label  string              `json:"label"`
	Status WorkflowStageStatus `json:"status"`
}

type ActionPresentation struct {
	Action               Action               `json:"action"`
	Label                string               `json:"label"`
	Description          string               `json:"description"`
	Classification       ActionClassification `json:"classification"`
	RequiresConfirmation bool                 `json:"requires_confirmation"`
	PointOfNoReturn      bool                 `json:"point_of_no_return"`
}

type StationState struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type LaneState struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	USBPath string `json:"usb_path"`
}

type TargetSummary struct {
	Synthetic           bool   `json:"synthetic"`
	Model               string `json:"model"`
	ProfileID           string `json:"profile_id"`
	ProfileStatus       string `json:"profile_status"`
	Adapter             string `json:"adapter"`
	Fingerprint         string `json:"target_fingerprint"`
	UserSerial          string `json:"user_serial"`
	FactoryUUID         string `json:"factory_uuid"`
	BoardRevision       string `json:"board_revision"`
	Processor           string `json:"processor"`
	ModelCode           string `json:"model_code"`
	BootROM             string `json:"boot_rom"`
	EEPROMHash          string `json:"eeprom_hash"`
	CustomerKeyHash     string `json:"customer_key_hash"`
	CustomerKeyState    string `json:"customer_key_state"`
	VideoCoreJTAGState  string `json:"videocore_jtag_state"`
	VideoCoreJTAGLocked bool   `json:"videocore_jtag_locked"`
}

type Finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ProbeSummary struct {
	Sequence                           int               `json:"sequence"`
	Status                             string            `json:"status"`
	DeviceClassStatus                  string            `json:"device_class_status"`
	ObservableBaselineStatus           string            `json:"observable_baseline_status"`
	EligibleForReversibleQualification bool              `json:"eligible_for_reversible_qualification"`
	EvidenceDigest                     string            `json:"evidence_digest,omitempty"`
	Observation                        *TargetSummary    `json:"observation,omitempty"`
	Assessment                         AssessmentSummary `json:"assessment"`
	Findings                           []Finding         `json:"findings"`
}

type AssessmentStatus struct {
	Status string `json:"status"`
}

type AssessmentSummary struct {
	DeviceClass                        AssessmentStatus `json:"device_class"`
	ObservableBaseline                 AssessmentStatus `json:"observable_baseline"`
	EligibleForReversibleQualification bool             `json:"eligible_for_reversible_qualification"`
	MutationEligible                   bool             `json:"mutation_eligible"`
	FullUnprovisionedState             string           `json:"full_unprovisioned_state"`
	Disclaimer                         string           `json:"disclaimer"`
}

type Comparison struct {
	Field  string `json:"field"`
	Label  string `json:"label"`
	First  string `json:"first"`
	Second string `json:"second"`
	Status string `json:"status"`
}

type Outcome struct {
	Status  string `json:"status"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

type TransactionSummary struct {
	ID                          string            `json:"id"`
	Status                      TransactionStatus `json:"status"`
	AssetID                     string            `json:"asset_id"`
	IntendedLogicalID           string            `json:"intended_logical_id"`
	ClaimID                     string            `json:"claim_id"`
	FenceEpoch                  uint64            `json:"fence_epoch"`
	OperatorID                  string            `json:"operator_id"`
	ApproverID                  string            `json:"approver_id"`
	TargetFingerprint           string            `json:"target_fingerprint"`
	Digest                      string            `json:"digest"`
	PlanDigest                  string            `json:"plan_digest"`
	ApprovalID                  string            `json:"approval_id"`
	IntentReceipt               string            `json:"intent_receipt"`
	FinalizationApprovalID      string            `json:"finalization_approval_id"`
	FinalizationIntentReceipt   string            `json:"finalization_intent_receipt"`
	IrreversibleBoundaryCrossed bool              `json:"irreversible_boundary_crossed"`
	CommitExecutions            int               `json:"commit_executions"`
	FinalControlExecutions      int               `json:"final_control_executions"`
}

type ManifestSummary struct {
	ID                          string `json:"id"`
	Digest                      string `json:"digest"`
	ProfileID                   string `json:"profile_id"`
	ProfileDigest               string `json:"profile_digest"`
	AdapterID                   string `json:"adapter_id"`
	AdapterDigest               string `json:"adapter_digest"`
	ExpectedCustomerKeyHash     string `json:"expected_customer_key_hash"`
	EEPROMImageDigest           string `json:"eeprom_image_digest"`
	BootImageDigest             string `json:"boot_image_digest"`
	BootSignatureDigest         string `json:"boot_signature_digest"`
	RootIntegrityDigest         string `json:"root_integrity_digest"`
	FreshCommitBundleDigest     string `json:"fresh_commit_bundle_digest"`
	OwnedRecoveryBundleDigest   string `json:"owned_recovery_bundle_digest"`
	BootOrder                   string `json:"boot_order"`
	RollbackPolicy              string `json:"rollback_policy"`
	DebugPolicy                 string `json:"debug_policy"`
	EEPROMWriteProtectionPolicy string `json:"eeprom_write_protection_policy"`
	SignerID                    string `json:"signer_id"`
	SigningToolVersion          string `json:"signing_tool_version"`
	VerificationStatus          string `json:"verification_status"`
}

type EvidenceSummary struct {
	ID     string          `json:"id"`
	Label  string          `json:"label"`
	Stage  WorkflowStageID `json:"stage"`
	Status EvidenceStatus  `json:"status"`
	Digest string          `json:"digest"`
	Detail string          `json:"detail"`
}

type SafetyState struct {
	Simulation             bool   `json:"simulation"`
	MutationEligible       bool   `json:"mutation_eligible"`
	FullUnprovisionedState string `json:"full_unprovisioned_state"`
	LiveTargetAccess       bool   `json:"live_target_access"`
	LiveMutationCapable    bool   `json:"live_mutation_capable"`
	AuthoritativeEvidence  bool   `json:"authoritative_evidence"`
	SecretsPresent         bool   `json:"secrets_present"`
	ApprovalAuthority      bool   `json:"approval_authority"`
	SigningCapable         bool   `json:"signing_capable"`
	EnrollmentCapable      bool   `json:"enrollment_capable"`
	Disclaimer             string `json:"disclaimer"`
}

type RedactedExport struct {
	SchemaVersion string             `json:"schema_version"`
	Simulation    bool               `json:"simulation"`
	SecretFree    bool               `json:"secret_free"`
	Scenario      ScenarioID         `json:"scenario"`
	StationID     string             `json:"station_id"`
	LaneID        string             `json:"lane_id"`
	Lifecycle     DeviceLifecycle    `json:"lifecycle"`
	Transaction   TransactionSummary `json:"transaction"`
	Manifest      ManifestSummary    `json:"manifest"`
	Evidence      []EvidenceSummary  `json:"evidence"`
	Outcome       Outcome            `json:"outcome"`
	Safety        SafetyState        `json:"safety"`
}

type State struct {
	SchemaVersion       string               `json:"schema_version"`
	Revision            uint64               `json:"revision"`
	Simulation          bool                 `json:"simulation"`
	Scenario            ScenarioID           `json:"scenario"`
	Scenarios           []ScenarioOption     `json:"scenarios"`
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
	Probes              []ProbeSummary       `json:"probes"`
	Comparison          []Comparison         `json:"comparison"`
	Findings            []Finding            `json:"findings"`
	Evidence            []EvidenceSummary    `json:"evidence"`
	Outcome             *Outcome             `json:"outcome,omitempty"`
	Safety              SafetyState          `json:"safety"`
	ExportRecord        *RedactedExport      `json:"export_record,omitempty"`
}
