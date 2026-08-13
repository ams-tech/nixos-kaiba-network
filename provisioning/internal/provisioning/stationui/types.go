// Package stationui provides the explicitly simulated provisioning-station
// workflow used by the kiosk demonstration. It has no hardware backend and
// cannot authorize or perform persistent device mutations.
package stationui

const (
	StateSchemaVersion  = "provisioning.kaiba.network/station-demo-state/v1alpha1"
	ExportSchemaVersion = "provisioning.kaiba.network/station-demo-export/v1alpha1"

	AssessmentDisclaimer = "This observation is correlation and partial preflight evidence; it is not device authentication or attestation and does not authorize irreversible provisioning."
)

type ScenarioID string

const (
	ScenarioHappyPath               ScenarioID = "happy-path"
	ScenarioClassMismatch           ScenarioID = "class-mismatch"
	ScenarioBaselineFailure         ScenarioID = "baseline-failure"
	ScenarioMultipleTargets         ScenarioID = "multiple-targets"
	ScenarioAcquisitionError        ScenarioID = "acquisition-error"
	ScenarioTargetReplaced          ScenarioID = "target-replaced"
	ScenarioMutationSafetyViolation ScenarioID = "mutation-safety-violation"
	ScenarioBootFailure             ScenarioID = "boot-failure"
)

type Phase string

const (
	PhaseReady                          Phase = "ready"
	PhaseTargetDetected                 Phase = "target_detected"
	PhasePowerCycleRequired             Phase = "power_cycle_required"
	PhaseAwaitingReconnect              Phase = "awaiting_reconnect"
	PhaseSecondProbeReady               Phase = "second_probe_ready"
	PhaseAwaitingNormalBootConfirmation Phase = "awaiting_normal_boot_confirmation"
	PhaseComplete                       Phase = "complete"
	PhaseStopped                        Phase = "stopped"
	PhaseQuarantined                    Phase = "quarantined"
)

type Action string

const (
	ActionAttachTarget      Action = "attach_target"
	ActionRunFirstProbe     Action = "run_first_probe"
	ActionDisconnectTarget  Action = "disconnect_target"
	ActionReconnectTarget   Action = "reconnect_target"
	ActionRunSecondProbe    Action = "run_second_probe"
	ActionConfirmBootOK     Action = "confirm_boot_ok"
	ActionConfirmBootFailed Action = "confirm_boot_failed"
	ActionExportRedacted    Action = "export_redacted"
	ActionReset             Action = "reset"
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

type SafetyState struct {
	Simulation             bool   `json:"simulation"`
	MutationEligible       bool   `json:"mutation_eligible"`
	FullUnprovisionedState string `json:"full_unprovisioned_state"`
	Disclaimer             string `json:"disclaimer"`
}

type RedactedExport struct {
	SchemaVersion           string     `json:"schema_version"`
	Simulation              bool       `json:"simulation"`
	Scenario                ScenarioID `json:"scenario"`
	StationID               string     `json:"station_id"`
	LaneID                  string     `json:"lane_id"`
	ProfileID               string     `json:"profile_id"`
	ProbeCount              int        `json:"probe_count"`
	StableObservationsMatch bool       `json:"stable_observations_match"`
	NormalBootConfirmation  string     `json:"normal_boot_confirmation"`
	OutcomeStatus           string     `json:"outcome_status"`
	MutationEligible        bool       `json:"mutation_eligible"`
	FullUnprovisionedState  string     `json:"full_unprovisioned_state"`
}

type State struct {
	SchemaVersion  string           `json:"schema_version"`
	Revision       uint64           `json:"revision"`
	Simulation     bool             `json:"simulation"`
	Scenario       ScenarioID       `json:"scenario"`
	Scenarios      []ScenarioOption `json:"scenarios"`
	Station        StationState     `json:"station"`
	Lane           LaneState        `json:"lane"`
	Phase          Phase            `json:"phase"`
	Instruction    string           `json:"instruction"`
	AllowedActions []Action         `json:"allowed_actions"`
	Target         *TargetSummary   `json:"target,omitempty"`
	Probes         []ProbeSummary   `json:"probes"`
	Comparison     []Comparison     `json:"comparison"`
	Findings       []Finding        `json:"findings"`
	Outcome        *Outcome         `json:"outcome,omitempty"`
	Safety         SafetyState      `json:"safety"`
	ExportRecord   *RedactedExport  `json:"export_record,omitempty"`
}
