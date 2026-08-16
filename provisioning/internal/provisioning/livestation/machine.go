package livestation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

var liveIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Config struct {
	StationID       string
	LaneID          string
	USBPath         string
	UARTPath        string
	MutationCapable bool
}

type Machine struct {
	mu      sync.Mutex
	config  Config
	backend Backend
	state   State
}

type transition struct {
	from           Phase
	to             Phase
	classification ActionClassification
	irreversible   bool
	instruction    string
}

var transitions = map[Action]transition{
	ActionRunStationAdmission:   {PhaseStationAdmission, PhaseTransactionCreation, ActionReadOnly, false, "Create a centrally tracked transaction for this admitted station and lane."},
	ActionCreateTransaction:     {PhaseTransactionCreation, PhaseReady, ActionAdministrative, false, "Attach exactly one target through the fixed lane guard."},
	ActionAttachTarget:          {PhaseReady, PhaseTargetBound, ActionReadOnly, false, "Run the authoritative two-pass fresh-board qualification."},
	ActionRunFreshQualification: {PhaseTargetBound, PhaseQualifiedFreshCandidate, ActionReversible, false, "Resolve and verify the immutable secure-boot artifact plan."},
	ActionPrepareTransaction:    {PhaseQualifiedFreshCandidate, PhasePrepared, ActionAdministrative, false, "Request approval for the exact target, epoch, prestate, and operation plan."},
	ActionRequestCommitApproval: {PhasePrepared, PhaseCommitApproved, ActionAuthorizationAffecting, false, "Record the approved one-shot commit intent and remote audit receipt."},
	ActionRecordCommitIntent:    {PhaseCommitApproved, PhaseCommitIntentRecorded, ActionAuthorizationAffecting, false, "Execute the approved ownership commit once through the lane guard."},
	ActionExecuteCommit:         {PhaseCommitIntentRecorded, PhaseCommitReadbackVerified, ActionIrreversible, true, "Cold-power the owned target and verify the approved signed boot."},
	ActionReconcileCommit:       {PhaseReconciliationRequired, PhaseCommitReadbackVerified, ActionReadOnly, false, "Cold-power the reconciled owned target and verify the approved signed boot."},
	ActionConfirmSignedBoot:     {PhaseCommitReadbackVerified, PhaseSignedBootVerified, ActionReadOnly, false, "Run the customer-authorized owned-device readback."},
	ActionRunOwnedReadback:      {PhaseSignedBootVerified, PhaseOwnedReadbackVerified, ActionReadOnly, false, "Test the customer-counter-signed recovery path."},
	ActionTestOwnedRecovery:     {PhaseOwnedReadbackVerified, PhaseRecoveryVerified, ActionReversible, false, "Re-run authoritative owned-device readback after recovery."},
	ActionRerunOwnedReadback:    {PhaseRecoveryVerified, PhasePostRecoveryReadbackVerified, ActionReadOnly, false, "Test unsigned, altered, wrong-key, alternate-media, and stock-recovery rejection."},
	ActionTestNegativeBoot:      {PhasePostRecoveryReadbackVerified, PhaseNegativeBootVerified, ActionReversible, false, "Verify dm-verity rejects persistent-system tampering before runtime services."},
	ActionTestRootIntegrity:     {PhaseNegativeBootVerified, PhaseRootIntegrityVerified, ActionReversible, false, "Reconcile the complete secret-free audit record with inventory."},
	ActionReconcileAudit:        {PhaseRootIntegrityVerified, PhaseAuditReconciled, ActionAdministrative, false, "Record security_applied with rollback explicitly unimplemented."},
	ActionMarkSecurityApplied:   {PhaseAuditReconciled, PhaseSecurityApplied, ActionAdministrative, false, "Export the secret-free development-device record."},
}

func NewMachine(config Config, backend Backend) (*Machine, error) {
	if !liveIDPattern.MatchString(config.StationID) || !liveIDPattern.MatchString(config.LaneID) {
		return nil, errors.New("station and lane IDs must be fixed non-empty identifiers")
	}
	if config.USBPath == "" || config.UARTPath == "" {
		return nil, errors.New("fixed USB and UART paths are required")
	}
	if backend == nil {
		return nil, errors.New("orchestration backend is required")
	}
	machine := &Machine{config: config, backend: backend}
	machine.state = initialState(config, 1)
	return machine, nil
}

func (machine *Machine) Snapshot() State {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	return cloneState(machine.state)
}

func (machine *Machine) Current(context.Context) (State, error) {
	return machine.Snapshot(), nil
}

func (machine *Machine) Apply(ctx context.Context, request ActionRequest) (State, error) {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if request.ExpectedRevision != machine.state.Revision {
		return cloneState(machine.state), ErrStaleRevision
	}
	if request.Action == ActionMarkEnrollmentReady || !actionAllowed(machine.state.AllowedActions, request.Action) {
		return cloneState(machine.state), ErrActionNotAllowed
	}
	if request.Action == ActionExportRedacted {
		machine.export()
		machine.state.Revision++
		machine.refresh()
		return cloneState(machine.state), nil
	}
	if request.Action == ActionReset {
		result, err := machine.backend.Perform(ctx, BackendRequest{Action: request.Action, Classification: ActionAdministrative, State: cloneState(machine.state)})
		if err != nil {
			return cloneState(machine.state), err
		}
		if result.Disposition != DispositionSucceeded {
			return cloneState(machine.state), ErrInvalidBackendResult
		}
		machine.state = initialState(machine.config, machine.state.Revision+1)
		return cloneState(machine.state), nil
	}
	definition, ok := transitions[request.Action]
	if !ok || definition.from != machine.state.Phase {
		return cloneState(machine.state), ErrActionNotAllowed
	}
	result, err := machine.backend.Perform(ctx, BackendRequest{
		Action: request.Action, Classification: definition.classification,
		Irreversible: definition.irreversible, State: cloneState(machine.state),
	})
	if err != nil {
		return machine.backendError(request.Action, err)
	}
	if err := validateDisposition(result.Disposition); err != nil {
		return cloneState(machine.state), err
	}
	if result.Disposition != DispositionSucceeded {
		return machine.nonSuccess(request.Action, result)
	}
	beforeMerge := cloneState(machine.state)
	if err := machine.mergeAndValidate(request.Action, result); err != nil {
		if definition.irreversible || beforeMerge.Safety.IrreversibleBoundaryCrossed {
			if definition.irreversible {
				machine.crossBoundary()
			}
			machine.quarantine("invalid_backend_result", err.Error())
			return cloneState(machine.state), errors.Join(ErrQuarantined, err)
		}
		machine.state = beforeMerge
		return cloneState(machine.state), err
	}
	machine.state.Phase = definition.to
	machine.state.Instruction = definition.instruction
	if definition.irreversible {
		machine.crossBoundary()
	}
	machine.applyStatus(request.Action)
	machine.state.Revision++
	machine.refresh()
	return cloneState(machine.state), nil
}

func (machine *Machine) backendError(action Action, backendErr error) (State, error) {
	if errors.Is(backendErr, ErrBackendUnavailable) {
		return cloneState(machine.state), backendErr
	}
	if action == ActionExecuteCommit {
		machine.crossBoundary()
		machine.state.Phase = PhaseReconciliationRequired
		machine.state.Instruction = "Do not repeat the commit. Reconcile its direct postcondition through the lane guard."
		machine.state.Revision++
		machine.refresh()
		return cloneState(machine.state), errors.Join(ErrReconciliationRequired, backendErr)
	}
	if machine.state.Safety.IrreversibleBoundaryCrossed {
		machine.quarantine("backend_error_after_commit", backendErr.Error())
		return cloneState(machine.state), errors.Join(ErrQuarantined, backendErr)
	}
	return cloneState(machine.state), backendErr
}

func (machine *Machine) nonSuccess(action Action, result BackendResult) (State, error) {
	machine.state.Findings = append(machine.state.Findings, result.Findings...)
	machine.state.Evidence = append(machine.state.Evidence, result.Evidence...)
	if action == ActionExecuteCommit {
		machine.crossBoundary()
		if result.Disposition == DispositionUncertain {
			machine.state.Phase = PhaseReconciliationRequired
			machine.state.Instruction = "Do not repeat the commit. Directly reconcile the one-shot outcome."
			machine.state.Revision++
			machine.refresh()
			return cloneState(machine.state), ErrReconciliationRequired
		}
	}
	if action == ActionReconcileCommit && result.Disposition == DispositionUncertain {
		machine.state.Revision++
		machine.refresh()
		return cloneState(machine.state), ErrReconciliationRequired
	}
	if machine.state.Safety.IrreversibleBoundaryCrossed {
		machine.quarantine("post_commit_failure", result.Detail)
		return cloneState(machine.state), ErrQuarantined
	}
	machine.state.Phase = PhaseStopped
	machine.state.Instruction = "Resolve the failed pre-commit gate or reset through the orchestrator."
	machine.state.Outcome = &Outcome{Status: "aborted", Title: "Provisioning stopped", Message: result.Detail}
	if machine.state.Transaction != nil {
		machine.state.Transaction.Status = TransactionAborted
	}
	machine.state.Revision++
	machine.refresh()
	return cloneState(machine.state), errors.New("authoritative gate failed")
}

func (machine *Machine) mergeAndValidate(action Action, result BackendResult) error {
	if len(result.Evidence) == 0 {
		return fmt.Errorf("%w: successful action has no authoritative evidence", ErrInvalidBackendResult)
	}
	for _, evidence := range result.Evidence {
		if evidence.ID == "" || evidence.Stage == "" || evidence.Status == "" || evidence.Digest == "" || evidence.ReceiptID == "" || evidence.RecordedAt.IsZero() {
			return fmt.Errorf("%w: authoritative evidence is missing a binding, digest, receipt, or timestamp", ErrInvalidBackendResult)
		}
	}
	if result.Transaction != nil {
		if machine.state.Transaction != nil && machine.state.Transaction.ID != result.Transaction.ID {
			return fmt.Errorf("%w: transaction identity changed", ErrInvalidBackendResult)
		}
		transaction := *result.Transaction
		if machine.state.Transaction != nil && machine.state.Transaction.IrreversibleBoundaryCrossed {
			transaction.IrreversibleBoundaryCrossed = true
			transaction.CommitExecutions = machine.state.Transaction.CommitExecutions
		}
		machine.state.Transaction = &transaction
	}
	if result.Manifest != nil {
		manifest := *result.Manifest
		machine.state.Manifest = &manifest
	}
	if result.Target != nil {
		if machine.state.Target != nil && machine.state.Target.TargetFingerprint != result.Target.TargetFingerprint {
			return fmt.Errorf("%w: target identity changed", ErrInvalidBackendResult)
		}
		target := *result.Target
		machine.state.Target = &target
	}
	machine.state.Evidence = append(machine.state.Evidence, result.Evidence...)
	machine.state.Findings = append(machine.state.Findings, result.Findings...)
	switch action {
	case ActionCreateTransaction:
		if machine.state.Transaction == nil || machine.state.Transaction.ID == "" || machine.state.Transaction.ClaimID == "" || machine.state.Transaction.FenceEpoch == 0 {
			return fmt.Errorf("%w: transaction, claim, and fence epoch are required", ErrInvalidBackendResult)
		}
	case ActionAttachTarget:
		if machine.state.Target == nil || machine.state.Target.TargetFingerprint == "" || machine.state.Transaction == nil {
			return fmt.Errorf("%w: target binding is required", ErrInvalidBackendResult)
		}
		if machine.state.Transaction.TargetFingerprint != machine.state.Target.TargetFingerprint {
			return fmt.Errorf("%w: transaction target binding differs from observation", ErrInvalidBackendResult)
		}
	case ActionPrepareTransaction:
		if machine.state.Manifest == nil || machine.state.Manifest.Digest == "" || machine.state.Manifest.PlanDigest == "" || machine.state.Manifest.RollbackPolicy != RollbackStatus {
			return fmt.Errorf("%w: verified manifest with explicit rollback status is required", ErrInvalidBackendResult)
		}
		if machine.state.Transaction == nil || machine.state.Transaction.PlanDigest != machine.state.Manifest.PlanDigest {
			return fmt.Errorf("%w: manifest and transaction plan digests differ", ErrInvalidBackendResult)
		}
	case ActionRequestCommitApproval:
		if machine.state.Transaction == nil || machine.state.Transaction.ApprovalID == "" {
			return fmt.Errorf("%w: commit approval is required", ErrInvalidBackendResult)
		}
	case ActionRecordCommitIntent:
		if machine.state.Transaction == nil || machine.state.Transaction.IntentReceipt == "" {
			return fmt.Errorf("%w: remote intent receipt is required", ErrInvalidBackendResult)
		}
	}
	return nil
}

func (machine *Machine) crossBoundary() {
	machine.state.Safety.IrreversibleBoundaryCrossed = true
	machine.state.Lifecycle = LifecycleCommitInProgress
	if machine.state.Transaction != nil {
		machine.state.Transaction.IrreversibleBoundaryCrossed = true
		machine.state.Transaction.CommitExecutions = 1
	}
}

func (machine *Machine) applyStatus(action Action) {
	if machine.state.Transaction == nil {
		return
	}
	switch action {
	case ActionCreateTransaction:
		machine.state.Transaction.Status = TransactionCreated
	case ActionAttachTarget:
		machine.state.Transaction.Status = TransactionTargetBound
	case ActionRunFreshQualification:
		machine.state.Transaction.Status = TransactionPreflightPassed
		machine.state.Lifecycle = LifecycleQualifiedFreshCandidate
	case ActionPrepareTransaction:
		machine.state.Lifecycle = LifecyclePrepared
	case ActionRequestCommitApproval:
		machine.state.Transaction.Status = TransactionCommitApproved
	case ActionMarkSecurityApplied:
		machine.state.Transaction.Status = TransactionSecurityApplied
		machine.state.Lifecycle = LifecycleSecurityApplied
		machine.state.Outcome = &Outcome{
			Status: "security_applied", Title: "Development secure boot applied",
			Message: "The owned development board passed the implemented gates. Enrollment remains blocked because rollback protection is unimplemented.",
		}
	}
}

func (machine *Machine) quarantine(code, detail string) {
	machine.state.Phase = PhaseQuarantined
	machine.state.Lifecycle = LifecycleOwnedQuarantined
	machine.state.Findings = append(machine.state.Findings, Finding{Code: code, Message: detail})
	machine.state.Outcome = &Outcome{Status: "owned_quarantined", Title: "Owned target quarantined", Message: detail}
	if machine.state.Transaction != nil {
		machine.state.Transaction.Status = TransactionQuarantined
	}
	machine.state.Revision++
	machine.refresh()
}

func (machine *Machine) export() {
	if machine.state.Transaction == nil || machine.state.Manifest == nil || machine.state.Target == nil || machine.state.Outcome == nil {
		return
	}
	machine.state.ExportRecord = &RedactedExport{
		SchemaVersion: ExportSchemaVersion, Simulation: false, SecretFree: true,
		StationID: machine.state.Station.ID, LaneID: machine.state.Lane.ID,
		Lifecycle: machine.state.Lifecycle, Transaction: *machine.state.Transaction,
		Manifest: *machine.state.Manifest, Target: *machine.state.Target,
		Evidence: append([]Evidence(nil), machine.state.Evidence...), Outcome: *machine.state.Outcome,
		Safety: machine.state.Safety,
	}
}

func initialState(config Config, revision uint64) State {
	state := State{
		SchemaVersion: StateSchemaVersion, Revision: revision, Simulation: false, SecretFree: true,
		Station: StationState{ID: config.StationID, Status: "admission_required"},
		Lane:    LaneState{ID: config.LaneID, Status: "fixed", USBPath: config.USBPath, UARTPath: config.UARTPath},
		Phase:   PhaseStationAdmission, Lifecycle: LifecycleUnregistered,
		Instruction: "Run station, lane, control-service, identity, time, journal, and audit admission checks.",
		Findings:    []Finding{}, Evidence: []Evidence{},
		Safety: SafetyState{
			Simulation: false, SecretFree: true, AuthoritativeEvidence: true,
			LiveMutationCapable: config.MutationCapable, RollbackStatus: RollbackStatus, EnrollmentCapable: false,
			DebugControlsLocked: false, EEPROMWriteProtectionApplied: false,
		},
	}
	refreshState(&state)
	return state
}

func (machine *Machine) refresh() { refreshState(&machine.state) }

func refreshState(state *State) {
	state.Simulation = false
	state.SecretFree = true
	state.SchemaVersion = StateSchemaVersion
	state.Safety.Simulation = false
	state.Safety.SecretFree = true
	state.Safety.RollbackStatus = RollbackStatus
	state.Safety.EnrollmentCapable = false
	if state.Transaction != nil {
		state.Safety.IrreversibleBoundaryCrossed = state.Transaction.IrreversibleBoundaryCrossed
	}
	state.AllowedActions = allowedActions(*state)
	state.ActionPresentations = make([]ActionPresentation, 0, len(state.AllowedActions))
	for _, action := range state.AllowedActions {
		state.ActionPresentations = append(state.ActionPresentations, presentation(action))
	}
	state.WorkflowStages = workflowStages(state.Phase)
}

func allowedActions(state State) []Action {
	if state.Phase == PhaseSecurityApplied && state.ExportRecord == nil {
		return []Action{ActionExportRedacted}
	}
	if state.Phase == PhaseStopped && !state.Safety.IrreversibleBoundaryCrossed {
		return []Action{ActionReset}
	}
	if state.Phase == PhaseQuarantined || state.Phase == PhaseSecurityApplied {
		return []Action{}
	}
	for action, definition := range transitions {
		if definition.from == state.Phase {
			actions := []Action{action}
			if state.Phase != PhaseStationAdmission && !state.Safety.IrreversibleBoundaryCrossed {
				actions = append(actions, ActionReset)
			}
			return actions
		}
	}
	return []Action{}
}

func actionAllowed(actions []Action, candidate Action) bool {
	for _, action := range actions {
		if action == candidate {
			return true
		}
	}
	return false
}

func validateDisposition(disposition Disposition) error {
	switch disposition {
	case DispositionSucceeded, DispositionFailed, DispositionUncertain:
		return nil
	default:
		return fmt.Errorf("%w: invalid disposition %q", ErrInvalidBackendResult, disposition)
	}
}

func presentation(action Action) ActionPresentation {
	if action == ActionReset {
		return ActionPresentation{Action: action, Label: "Abort and reset", Description: "Centrally abort the still-reversible transaction and return the lane to admission.", Classification: ActionAdministrative, RequiresConfirmation: true}
	}
	if action == ActionExportRedacted {
		return ActionPresentation{Action: action, Label: "Export redacted record", Description: "Create a secret-free development-device record.", Classification: ActionReadOnly}
	}
	definition := transitions[action]
	return ActionPresentation{
		Action: action, Label: string(action), Description: definition.instruction,
		Classification:       definition.classification,
		RequiresConfirmation: definition.classification == ActionAuthorizationAffecting || definition.irreversible,
		PointOfNoReturn:      definition.irreversible,
	}
}

func workflowStages(phase Phase) []WorkflowStage {
	definitions := []struct {
		id, label string
		last      Phase
	}{
		{"admission", "Station admission", PhaseStationAdmission},
		{"transaction", "Transaction and target binding", PhaseTargetBound},
		{"qualification", "Fresh qualification", PhaseQualifiedFreshCandidate},
		{"preparation", "Artifact preparation", PhasePrepared},
		{"approval", "Commit approval and intent", PhaseCommitIntentRecorded},
		{"ownership_commit", "One-shot ownership commit", PhaseCommitReadbackVerified},
		{"owned_verification", "Owned-device verification", PhaseRootIntegrityVerified},
		{"audit_reconciliation", "Audit reconciliation", PhaseSecurityApplied},
	}
	rank := phaseRank(phase)
	stages := make([]WorkflowStage, 0, len(definitions))
	previousLast := -1
	for _, definition := range definitions {
		last := phaseRank(definition.last)
		status := "pending"
		if rank > last {
			status = "complete"
		} else if rank > previousLast {
			status = "current"
		}
		if phase == PhaseStopped || phase == PhaseQuarantined {
			if status == "current" {
				status = "failed"
			}
		}
		stages = append(stages, WorkflowStage{ID: definition.id, Label: definition.label, Status: status})
		previousLast = last
	}
	return stages
}

func phaseRank(phase Phase) int {
	order := []Phase{
		PhaseStationAdmission, PhaseTransactionCreation, PhaseReady, PhaseTargetBound,
		PhaseQualifiedFreshCandidate, PhasePrepared, PhaseCommitApproved, PhaseCommitIntentRecorded,
		PhaseReconciliationRequired, PhaseCommitReadbackVerified, PhaseSignedBootVerified,
		PhaseOwnedReadbackVerified, PhaseRecoveryVerified, PhasePostRecoveryReadbackVerified,
		PhaseNegativeBootVerified, PhaseRootIntegrityVerified, PhaseAuditReconciled, PhaseSecurityApplied,
	}
	for index, candidate := range order {
		if phase == candidate {
			return index
		}
	}
	return -1
}

func cloneState(state State) State {
	copy := state
	copy.WorkflowStages = append([]WorkflowStage(nil), state.WorkflowStages...)
	copy.AllowedActions = append([]Action(nil), state.AllowedActions...)
	copy.ActionPresentations = append([]ActionPresentation(nil), state.ActionPresentations...)
	copy.Findings = append([]Finding(nil), state.Findings...)
	copy.Evidence = append([]Evidence(nil), state.Evidence...)
	if state.Transaction != nil {
		value := *state.Transaction
		copy.Transaction = &value
	}
	if state.Manifest != nil {
		value := *state.Manifest
		copy.Manifest = &value
	}
	if state.Target != nil {
		value := *state.Target
		copy.Target = &value
	}
	if state.Outcome != nil {
		value := *state.Outcome
		copy.Outcome = &value
	}
	if state.ExportRecord != nil {
		value := *state.ExportRecord
		value.Evidence = append([]Evidence(nil), state.ExportRecord.Evidence...)
		copy.ExportRecord = &value
	}
	return copy
}
