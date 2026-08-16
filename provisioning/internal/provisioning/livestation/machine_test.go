package livestation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	calls        []Action
	dispositions map[Action]Disposition
	errors       map[Action]error
	omitEvidence map[Action]bool
	replaceAt    Action
}

func (backend *fakeBackend) Perform(_ context.Context, request BackendRequest) (BackendResult, error) {
	backend.calls = append(backend.calls, request.Action)
	if err := backend.errors[request.Action]; err != nil {
		return BackendResult{}, err
	}
	disposition := backend.dispositions[request.Action]
	if disposition == "" {
		disposition = DispositionSucceeded
	}
	result := BackendResult{Disposition: disposition, Detail: "fake authoritative result"}
	if !backend.omitEvidence[request.Action] {
		result.Evidence = []Evidence{{
			ID: "evidence-" + string(request.Action), Stage: string(request.State.Phase), Status: "passed",
			Digest: "sha256:" + strings.Repeat("a", 64), ReceiptID: "receipt-" + string(request.Action),
			RecordedAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		}}
	}
	switch request.Action {
	case ActionCreateTransaction:
		result.Transaction = &TransactionSummary{ID: "transaction-1", ClaimID: "claim-1", FenceEpoch: 7}
	case ActionAttachTarget:
		transaction := *request.State.Transaction
		transaction.TargetFingerprint = "target-1"
		result.Transaction = &transaction
		result.Target = &TargetSummary{Model: "Raspberry Pi 5 Model B", ProfileID: "rpi5", TargetFingerprint: "target-1", CustomerKeyHash: strings.Repeat("0", 64), SecureBootState: "fresh"}
	case ActionPrepareTransaction:
		transaction := *request.State.Transaction
		transaction.PlanDigest = "sha256:" + strings.Repeat("b", 64)
		result.Transaction = &transaction
		result.Manifest = &ManifestSummary{ID: "manifest-1", Digest: "sha256:" + strings.Repeat("c", 64), PlanDigest: transaction.PlanDigest, RollbackPolicy: RollbackStatus, VerificationStatus: "verified"}
	case ActionRequestCommitApproval:
		transaction := *request.State.Transaction
		transaction.ApprovalID = "approval-1"
		result.Transaction = &transaction
	case ActionRecordCommitIntent:
		transaction := *request.State.Transaction
		transaction.IntentReceipt = "intent-receipt-1"
		result.Transaction = &transaction
	}
	if backend.replaceAt == request.Action {
		result.Target = &TargetSummary{TargetFingerprint: "replacement-target"}
	}
	return result, nil
}

func TestSuccessfulDevelopmentWorkflowStopsAtSecurityApplied(t *testing.T) {
	machine, backend := newTestMachine(t)
	state := runToPhase(t, machine, PhaseSecurityApplied)
	if state.Lifecycle != LifecycleSecurityApplied || state.Transaction.Status != TransactionSecurityApplied {
		t.Fatalf("terminal lifecycle = %q, transaction = %#v", state.Lifecycle, state.Transaction)
	}
	if state.Transaction.CommitExecutions != 1 || !state.Transaction.IrreversibleBoundaryCrossed {
		t.Fatalf("commit accounting = %#v", state.Transaction)
	}
	if state.Safety.RollbackStatus != RollbackStatus || state.Safety.EnrollmentCapable || state.Safety.DebugControlsLocked || state.Safety.EEPROMWriteProtectionApplied {
		t.Fatalf("terminal safety = %#v", state.Safety)
	}
	if len(state.AllowedActions) != 1 || state.AllowedActions[0] != ActionExportRedacted {
		t.Fatalf("terminal actions before export = %v", state.AllowedActions)
	}
	if _, err := machine.Apply(context.Background(), ActionRequest{Action: ActionMarkEnrollmentReady, ExpectedRevision: state.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("enrollment action error = %v", err)
	}
	if len(backend.calls) != 16 {
		t.Fatalf("backend calls changed after rejected enrollment: %d", len(backend.calls))
	}

	state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionExportRedacted, ExpectedRevision: state.Revision})
	if err != nil || state.ExportRecord == nil || !state.ExportRecord.SecretFree || state.ExportRecord.Lifecycle != LifecycleSecurityApplied {
		t.Fatalf("export state = %#v, %v", state.ExportRecord, err)
	}
	if len(state.AllowedActions) != 0 {
		t.Fatalf("post-export actions = %v", state.AllowedActions)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"scenario"`) || strings.Contains(string(encoded), "enrollment_ready") {
		t.Fatalf("live state leaked simulation/enrollment shape: %s", encoded)
	}
}

func TestResetExistsOnlyBeforeIrreversibleBoundary(t *testing.T) {
	machine, _ := newTestMachine(t)
	state := runToPhase(t, machine, PhasePrepared)
	if !containsAction(state.AllowedActions, ActionReset) {
		t.Fatalf("pre-commit reset absent: %v", state.AllowedActions)
	}
	state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionReset, ExpectedRevision: state.Revision})
	if err != nil || state.Phase != PhaseStationAdmission || state.Transaction != nil {
		t.Fatalf("reset state = %#v, %v", state, err)
	}

	machine, _ = newTestMachine(t)
	state = runToPhase(t, machine, PhaseCommitReadbackVerified)
	if containsAction(state.AllowedActions, ActionReset) {
		t.Fatalf("post-boundary reset exposed: %v", state.AllowedActions)
	}
	if _, err := machine.Apply(context.Background(), ActionRequest{Action: ActionReset, ExpectedRevision: state.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("post-boundary reset error = %v", err)
	}
}

func TestUncertainCommitCanOnlyReconcileAndNeverRepeats(t *testing.T) {
	machine, backend := newTestMachine(t)
	state := runToPhase(t, machine, PhaseCommitIntentRecorded)
	backend.dispositions[ActionExecuteCommit] = DispositionUncertain
	state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionExecuteCommit, ExpectedRevision: state.Revision})
	if !errors.Is(err, ErrReconciliationRequired) || state.Phase != PhaseReconciliationRequired || !state.Safety.IrreversibleBoundaryCrossed {
		t.Fatalf("uncertain state = %#v, %v", state, err)
	}
	if len(state.AllowedActions) != 1 || state.AllowedActions[0] != ActionReconcileCommit {
		t.Fatalf("uncertain actions = %v", state.AllowedActions)
	}
	if _, err := machine.Apply(context.Background(), ActionRequest{Action: ActionExecuteCommit, ExpectedRevision: state.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("repeat commit error = %v", err)
	}
	backend.dispositions[ActionExecuteCommit] = DispositionSucceeded
	state, err = machine.Apply(context.Background(), ActionRequest{Action: ActionReconcileCommit, ExpectedRevision: state.Revision})
	if err != nil || state.Phase != PhaseCommitReadbackVerified || state.Transaction.CommitExecutions != 1 {
		t.Fatalf("reconciled state = %#v, %v", state, err)
	}
}

func TestPostCommitFailureAndTargetReplacementQuarantine(t *testing.T) {
	t.Run("verification failure", func(t *testing.T) {
		machine, backend := newTestMachine(t)
		state := runToPhase(t, machine, PhaseCommitReadbackVerified)
		backend.dispositions[ActionConfirmSignedBoot] = DispositionFailed
		state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionConfirmSignedBoot, ExpectedRevision: state.Revision})
		if !errors.Is(err, ErrQuarantined) || state.Phase != PhaseQuarantined || state.Lifecycle != LifecycleOwnedQuarantined || len(state.AllowedActions) != 0 {
			t.Fatalf("quarantine state = %#v, %v", state, err)
		}
	})
	t.Run("replacement observation", func(t *testing.T) {
		machine, backend := newTestMachine(t)
		state := runToPhase(t, machine, PhaseSignedBootVerified)
		backend.replaceAt = ActionRunOwnedReadback
		state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionRunOwnedReadback, ExpectedRevision: state.Revision})
		if !errors.Is(err, ErrQuarantined) || state.Phase != PhaseQuarantined {
			t.Fatalf("replacement state = %#v, %v", state, err)
		}
	})
}

func TestBackendUnavailableCannotCrossBoundary(t *testing.T) {
	machine, backend := newTestMachine(t)
	state := runToPhase(t, machine, PhaseCommitIntentRecorded)
	backend.errors[ActionExecuteCommit] = ErrBackendUnavailable
	before := state
	state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionExecuteCommit, ExpectedRevision: state.Revision})
	if !errors.Is(err, ErrBackendUnavailable) || state.Revision != before.Revision || state.Safety.IrreversibleBoundaryCrossed || state.Phase != before.Phase {
		t.Fatalf("disabled backend state = %#v, %v", state, err)
	}
}

func TestStaleRevisionAndInvalidEvidenceDoNotMutateState(t *testing.T) {
	machine, backend := newTestMachine(t)
	initial := machine.Snapshot()
	if _, err := machine.Apply(context.Background(), ActionRequest{Action: ActionRunStationAdmission, ExpectedRevision: initial.Revision + 1}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale error = %v", err)
	}
	if len(backend.calls) != 0 {
		t.Fatal("stale request reached backend")
	}
	backend.omitEvidence[ActionRunStationAdmission] = true
	state, err := machine.Apply(context.Background(), ActionRequest{Action: ActionRunStationAdmission, ExpectedRevision: initial.Revision})
	if !errors.Is(err, ErrInvalidBackendResult) || state.Revision != initial.Revision || state.Phase != initial.Phase || len(state.Evidence) != 0 {
		t.Fatalf("invalid backend result mutated state = %#v, %v", state, err)
	}
}

func newTestMachine(t *testing.T) (*Machine, *fakeBackend) {
	t.Helper()
	backend := &fakeBackend{dispositions: make(map[Action]Disposition), errors: make(map[Action]error), omitEvidence: make(map[Action]bool)}
	machine, err := NewMachine(Config{StationID: "station-1", LaneID: "lane-1", USBPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/kaiba-uart", MutationCapable: true}, backend)
	if err != nil {
		t.Fatal(err)
	}
	return machine, backend
}

func runToPhase(t *testing.T, machine *Machine, wanted Phase) State {
	t.Helper()
	state := machine.Snapshot()
	for steps := 0; state.Phase != wanted && steps < 32; steps++ {
		if len(state.AllowedActions) == 0 {
			t.Fatalf("no action from phase %q toward %q", state.Phase, wanted)
		}
		action := state.AllowedActions[0]
		var err error
		state, err = machine.Apply(context.Background(), ActionRequest{Action: action, ExpectedRevision: state.Revision})
		if err != nil {
			t.Fatalf("apply %q: %v", action, err)
		}
	}
	if state.Phase != wanted {
		t.Fatalf("ended at %q, want %q", state.Phase, wanted)
	}
	return state
}

func containsAction(actions []Action, wanted Action) bool {
	for _, action := range actions {
		if action == wanted {
			return true
		}
	}
	return false
}
