package stationui

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrStaleRevision    = errors.New("state revision does not match")
	ErrActionNotAllowed = errors.New("action is not allowed in the current phase")
)

type Machine struct {
	mu    sync.Mutex
	state State
}

func NewMockMachine(scenario ScenarioID) (*Machine, error) {
	if !validScenario(scenario) {
		return nil, fmt.Errorf("unsupported mock scenario %q", scenario)
	}
	return &Machine{state: initialState(scenario, 1)}, nil
}

func ScenarioIDs() []ScenarioID {
	return []ScenarioID{
		ScenarioHappyPath,
		ScenarioClassMismatch,
		ScenarioBaselineFailure,
		ScenarioMultipleTargets,
		ScenarioAcquisitionError,
		ScenarioTargetReplaced,
		ScenarioMutationSafetyViolation,
		ScenarioBootFailure,
	}
}

func (m *Machine) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneState(m.state)
}

func (m *Machine) Apply(request ActionRequest) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if request.ExpectedRevision != m.state.Revision {
		return cloneState(m.state), ErrStaleRevision
	}
	if scenario, ok := scenarioFromAction(request.Action); ok {
		if !validScenario(scenario) {
			return cloneState(m.state), ErrActionNotAllowed
		}
		m.state = initialState(scenario, m.state.Revision+1)
		return cloneState(m.state), nil
	}
	if !actionAllowed(m.state.AllowedActions, request.Action) {
		return cloneState(m.state), ErrActionNotAllowed
	}

	next := cloneState(m.state)
	switch request.Action {
	case ActionAttachTarget:
		attachTarget(&next)
	case ActionRunFirstProbe:
		runFirstProbe(&next)
	case ActionDisconnectTarget:
		disconnectTarget(&next)
	case ActionReconnectTarget:
		reconnectTarget(&next)
	case ActionRunSecondProbe:
		runSecondProbe(&next)
	case ActionConfirmBootOK:
		confirmBoot(&next, true)
	case ActionConfirmBootFailed:
		confirmBoot(&next, false)
	case ActionExportRedacted:
		exportRedacted(&next)
	case ActionReset:
		next = initialState(next.Scenario, next.Revision)
	default:
		return cloneState(m.state), ErrActionNotAllowed
	}
	next.AllowedActions = withScenarioActions(next.AllowedActions)
	next.Revision++
	m.state = next
	return cloneState(m.state), nil
}

func initialState(scenario ScenarioID, revision uint64) State {
	return State{
		SchemaVersion:  StateSchemaVersion,
		Revision:       revision,
		Simulation:     true,
		Scenario:       scenario,
		Scenarios:      scenarioOptions(),
		Station:        StationState{ID: "kaiba-station-01", Status: "ready"},
		Lane:           LaneState{ID: "lane-1", Status: "empty", USBPath: "1-2.3"},
		Phase:          PhaseReady,
		Instruction:    "Connect exactly one simulated target to lane-1, then review it before probing.",
		AllowedActions: withScenarioActions([]Action{ActionAttachTarget}),
		Probes:         []ProbeSummary{},
		Comparison:     []Comparison{},
		Findings:       []Finding{},
		Safety: SafetyState{
			Simulation:             true,
			MutationEligible:       false,
			FullUnprovisionedState: "not_established",
			Disclaimer:             AssessmentDisclaimer,
		},
	}
}

func attachTarget(state *State) {
	if state.Scenario == ScenarioMultipleTargets {
		state.Phase = PhaseStopped
		state.Lane.Status = "blocked"
		state.Station.Status = "attention_required"
		state.Instruction = "Disconnect targets until exactly one expected RPIBOOT device remains."
		state.Findings = []Finding{{Code: "multiple_targets", Message: "The mock lane observed more than one eligible target and refused target selection."}}
		state.Outcome = &Outcome{Status: "stopped", Title: "Probe stopped", Message: "Target selection was ambiguous; no probe ran."}
		state.AllowedActions = []Action{ActionExportRedacted, ActionReset}
		return
	}
	state.Phase = PhaseTargetDetected
	state.Lane.Status = "target_detected"
	state.Target = syntheticTarget()
	state.Instruction = "Review the synthetic target and explicitly start metadata probe 1."
	state.AllowedActions = []Action{ActionRunFirstProbe, ActionReset}
}

func runFirstProbe(state *State) {
	switch state.Scenario {
	case ScenarioAcquisitionError:
		state.Probes = append(state.Probes, failedProbe(1, "acquisition_error", "The simulated rpiboot acquisition did not complete."))
		stop(state, "Probe acquisition failed", "No parsed observation was accepted.")
	case ScenarioMutationSafetyViolation:
		state.Probes = append(state.Probes, failedProbe(1, "mutation_success_reported", "The simulated evidence reported an unexpected persistent mutation result."))
		quarantine(state, "Probe safety violation", "A mutation-success indication was observed during a metadata-only probe.")
	case ScenarioClassMismatch:
		observation := syntheticTarget()
		observation.Model = "Raspberry Pi 500"
		observation.BoardRevision = "c041a0"
		observation.ModelCode = "0x1a"
		state.Target = observation
		state.Probes = append(state.Probes, assessedProbe(1, observation, "fail", "indeterminate", false,
			Finding{Code: "device_class_mismatch", Message: "Decoded model code does not identify a Raspberry Pi 5 Model B."}))
		stop(state, "Incompatible device class", "The target is outside the experimental Pi 5 Model B profile.")
	case ScenarioBaselineFailure:
		observation := syntheticTarget()
		observation.CustomerKeyState = "set"
		state.Target = observation
		state.Probes = append(state.Probes, assessedProbe(1, observation, "pass", "fail", false,
			Finding{Code: "customer_key_already_set", Message: "The customer-key hash is nonzero."}))
		stop(state, "Observable baseline failed", "The target does not match the allowed unprovisioned baseline.")
	default:
		observation := syntheticTarget()
		state.Probes = append(state.Probes, assessedProbe(1, observation, "pass", "pass", true))
		state.Phase = PhasePowerCycleRequired
		state.Lane.Status = "power_cycle_required"
		state.Instruction = "Remove every source of power from the target. The mock requires observing disconnection before reconnecting."
		state.AllowedActions = []Action{ActionDisconnectTarget, ActionReset}
	}
}

func disconnectTarget(state *State) {
	state.Phase = PhaseAwaitingReconnect
	state.Lane.Status = "disconnected"
	state.Instruction = "The target is fully disconnected. Reconnect it in RPIBOOT mode on the same lane."
	state.AllowedActions = []Action{ActionReconnectTarget, ActionReset}
}

func reconnectTarget(state *State) {
	state.Phase = PhaseSecondProbeReady
	state.Lane.Status = "target_detected"
	state.Instruction = "A target is present again on lane-1. Explicitly start metadata probe 2."
	state.AllowedActions = []Action{ActionRunSecondProbe, ActionReset}
	if state.Scenario == ScenarioTargetReplaced {
		replacement := replacementTarget()
		state.Target = replacement
	}
}

func runSecondProbe(state *State) {
	observation := syntheticTarget()
	if state.Scenario == ScenarioTargetReplaced {
		observation = replacementTarget()
	}
	state.Probes = append(state.Probes, assessedProbe(2, observation, "pass", "pass", true))
	state.Target = observation
	state.Comparison = compareObservations(state.Probes[0].Observation, observation)
	if hasChangedComparison(state.Comparison) {
		quarantine(state, "Target changed after power removal", "Stable target observations did not match the first probe.")
		return
	}
	state.Phase = PhaseAwaitingNormalBootConfirmation
	state.Lane.Status = "awaiting_normal_boot_confirmation"
	state.Instruction = "Boot the target normally and record the observed result. This confirmation is operator-supplied evidence."
	if state.Scenario == ScenarioBootFailure {
		state.AllowedActions = []Action{ActionConfirmBootFailed, ActionReset}
	} else {
		state.AllowedActions = []Action{ActionConfirmBootOK, ActionConfirmBootFailed, ActionReset}
	}
}

func confirmBoot(state *State, ok bool) {
	if !ok {
		quarantine(state, "Normal boot failed", "The operator reported that the target did not boot normally after the probes.")
		return
	}
	state.Phase = PhaseComplete
	state.Lane.Status = "qualification_complete"
	state.Instruction = "Export the simulated redacted qualification record or reset the demo."
	state.Outcome = &Outcome{
		Status:  "hardware_qualification_passed",
		Title:   "Hardware qualification passed",
		Message: "Two consistent non-persistent probe observations and an operator-supplied normal-boot confirmation were recorded.",
	}
	state.AllowedActions = []Action{ActionExportRedacted, ActionReset}
}

func stop(state *State, title, message string) {
	state.Phase = PhaseStopped
	state.Lane.Status = "stopped"
	state.Station.Status = "attention_required"
	state.Instruction = "Review the simulated evidence. Persistent provisioning remains unavailable."
	state.Outcome = &Outcome{Status: "stopped", Title: title, Message: message}
	state.AllowedActions = []Action{ActionExportRedacted, ActionReset}
}

func quarantine(state *State, title, message string) {
	state.Phase = PhaseQuarantined
	state.Lane.Status = "quarantined"
	state.Station.Status = "attention_required"
	state.Instruction = "Keep the target isolated and export the simulated evidence. Do not retry provisioning."
	state.Outcome = &Outcome{Status: "quarantined", Title: title, Message: message}
	state.AllowedActions = []Action{ActionExportRedacted, ActionReset}
}

func exportRedacted(state *State) {
	outcomeStatus := "stopped"
	if state.Outcome != nil {
		outcomeStatus = state.Outcome.Status
	}
	boot := "not_observed"
	if state.Phase == PhaseComplete {
		boot = "operator_confirmed_normal"
	} else if state.Outcome != nil && state.Outcome.Title == "Normal boot failed" {
		boot = "operator_confirmed_failed"
	}
	state.ExportRecord = &RedactedExport{
		SchemaVersion:           ExportSchemaVersion,
		Simulation:              true,
		Scenario:                state.Scenario,
		StationID:               state.Station.ID,
		LaneID:                  state.Lane.ID,
		ProfileID:               "raspberry-pi-5-model-b-v1alpha1",
		ProbeCount:              len(state.Probes),
		StableObservationsMatch: len(state.Comparison) > 0 && !hasChangedComparison(state.Comparison),
		NormalBootConfirmation:  boot,
		OutcomeStatus:           outcomeStatus,
		MutationEligible:        false,
		FullUnprovisionedState:  "not_established",
	}
	state.Instruction = "The redacted simulation record is ready in this response."
	state.AllowedActions = []Action{ActionReset}
}

func syntheticTarget() *TargetSummary {
	return &TargetSummary{
		Synthetic:           true,
		Model:               "Raspberry Pi 5 Model B",
		ProfileID:           "raspberry-pi-5-model-b-v1alpha1",
		ProfileStatus:       "experimental",
		Adapter:             "raspberrypi.rpi5.otp-metadata/v1alpha1",
		Fingerprint:         "sha256:78600d0f50dc838dfb97414d04e8c08efe7771837a620f8503ec465b8628b6c1",
		UserSerial:          "a7eb274c",
		FactoryUUID:         "001000911006186073",
		BoardRevision:       "b04170",
		Processor:           "4 — BCM2712",
		ModelCode:           "0x17",
		BootROM:             "0000000a",
		EEPROMHash:          "",
		CustomerKeyState:    "unset — zero hash",
		VideoCoreJTAGState:  "unlocked",
		VideoCoreJTAGLocked: false,
	}
}

func replacementTarget() *TargetSummary {
	target := *syntheticTarget()
	target.Fingerprint = "sha256:a73b7f1649cce641901f1e12f11460d54bd0ac8feaaeb87fdf5f87c265104b04"
	target.UserSerial = "b8fc385d"
	target.FactoryUUID = "003000922007297184"
	return &target
}

func assessedProbe(sequence int, observation *TargetSummary, classStatus, baselineStatus string, eligible bool, findings ...Finding) ProbeSummary {
	copyOfObservation := *observation
	digest := "sha256:1bf5b56d68ea49c27ff142f001b1b36374da9c110c8bc3ea2e8dbe19e37f381a"
	if sequence == 2 {
		digest = "sha256:262c95177f7498f265c3d7c40a70ab7a8df4e932e666165b7415f20dcc16040d"
	}
	return ProbeSummary{
		Sequence: sequence, Status: "observed", DeviceClassStatus: classStatus,
		ObservableBaselineStatus: baselineStatus, EligibleForReversibleQualification: eligible,
		EvidenceDigest: digest, Observation: &copyOfObservation,
		Assessment: assessmentSummary(classStatus, baselineStatus, eligible),
		Findings:   append([]Finding(nil), findings...),
	}
}

func failedProbe(sequence int, code, message string) ProbeSummary {
	return ProbeSummary{
		Sequence: sequence, Status: "failed", DeviceClassStatus: "indeterminate",
		ObservableBaselineStatus: "indeterminate", EligibleForReversibleQualification: false,
		Assessment: assessmentSummary("indeterminate", "indeterminate", false),
		Findings:   []Finding{{Code: code, Message: message}},
	}
}

func assessmentSummary(classStatus, baselineStatus string, eligible bool) AssessmentSummary {
	return AssessmentSummary{
		DeviceClass:                        AssessmentStatus{Status: classStatus},
		ObservableBaseline:                 AssessmentStatus{Status: baselineStatus},
		EligibleForReversibleQualification: eligible,
		MutationEligible:                   false,
		FullUnprovisionedState:             "not_established",
		Disclaimer:                         AssessmentDisclaimer,
	}
}

func compareObservations(first, second *TargetSummary) []Comparison {
	if first == nil || second == nil {
		return []Comparison{}
	}
	fields := []struct{ key, label, first, second string }{
		{"target_fingerprint", "Target fingerprint", first.Fingerprint, second.Fingerprint},
		{"user_serial", "User serial", first.UserSerial, second.UserSerial},
		{"factory_uuid", "Factory UUID", first.FactoryUUID, second.FactoryUUID},
		{"board_revision", "Board revision", first.BoardRevision, second.BoardRevision},
		{"boot_rom", "Boot ROM", first.BootROM, second.BootROM},
		{"eeprom_hash", "EEPROM hash", first.EEPROMHash, second.EEPROMHash},
		{"customer_key_state", "Customer key state", first.CustomerKeyState, second.CustomerKeyState},
		{"videocore_jtag_state", "VideoCore JTAG", first.VideoCoreJTAGState, second.VideoCoreJTAGState},
	}
	result := make([]Comparison, 0, len(fields))
	for _, field := range fields {
		status := "match"
		if field.first == "" && field.second == "" {
			status = "not_observed"
		} else if field.first == "" || field.second == "" {
			status = "changed"
		} else if field.first != field.second {
			status = "changed"
		}
		result = append(result, Comparison{Field: field.key, Label: field.label, First: field.first, Second: field.second, Status: status})
	}
	return result
}

func hasChangedComparison(comparison []Comparison) bool {
	for _, field := range comparison {
		if field.Status == "match" || (field.Field == "eeprom_hash" && field.Status == "not_observed") {
			continue
		}
		return true
	}
	return false
}

func actionAllowed(allowed []Action, action Action) bool {
	for _, candidate := range allowed {
		if action == candidate {
			return true
		}
	}
	return false
}

func validScenario(scenario ScenarioID) bool {
	for _, candidate := range ScenarioIDs() {
		if scenario == candidate {
			return true
		}
	}
	return false
}

func scenarioOptions() []ScenarioOption {
	labels := map[ScenarioID]string{
		ScenarioHappyPath: "Happy path", ScenarioClassMismatch: "Device-class mismatch",
		ScenarioBaselineFailure: "Observable baseline failure", ScenarioMultipleTargets: "Multiple targets",
		ScenarioAcquisitionError: "Probe acquisition error", ScenarioTargetReplaced: "Target replaced",
		ScenarioMutationSafetyViolation: "Mutation safety violation", ScenarioBootFailure: "Normal boot failure",
	}
	result := make([]ScenarioOption, 0, len(ScenarioIDs()))
	for _, id := range ScenarioIDs() {
		result = append(result, ScenarioOption{ID: id, Label: labels[id], Action: Action("select_scenario:" + string(id))})
	}
	return result
}

func withScenarioActions(actions []Action) []Action {
	result := append([]Action(nil), actions...)
	for _, scenario := range ScenarioIDs() {
		action := Action("select_scenario:" + string(scenario))
		if !actionAllowed(result, action) {
			result = append(result, action)
		}
	}
	return result
}

func scenarioFromAction(action Action) (ScenarioID, bool) {
	const prefix = "select_scenario:"
	value := string(action)
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	return ScenarioID(strings.TrimPrefix(value, prefix)), true
}

func cloneState(state State) State {
	encoded, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	var clone State
	if err := json.Unmarshal(encoded, &clone); err != nil {
		panic(err)
	}
	return clone
}
