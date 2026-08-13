package stationui

import (
	"errors"
	"sync"
	"testing"
)

func TestHappyPathRequiresPowerCycleAndBootConfirmation(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	steps := []struct {
		action Action
		phase  Phase
	}{
		{ActionAttachTarget, PhaseTargetDetected},
		{ActionRunFirstProbe, PhasePowerCycleRequired},
		{ActionDisconnectTarget, PhaseAwaitingReconnect},
		{ActionReconnectTarget, PhaseSecondProbeReady},
		{ActionRunSecondProbe, PhaseAwaitingNormalBootConfirmation},
		{ActionConfirmBootOK, PhaseComplete},
		{ActionExportRedacted, PhaseComplete},
	}
	for _, step := range steps {
		before := machine.Snapshot()
		state, err := machine.Apply(ActionRequest{Action: step.action, ExpectedRevision: before.Revision})
		if err != nil {
			t.Fatalf("apply %q: %v", step.action, err)
		}
		if state.Phase != step.phase {
			t.Fatalf("after %q phase = %q, want %q", step.action, state.Phase, step.phase)
		}
		assertSafetyInvariants(t, state)
	}
	state := machine.Snapshot()
	if len(state.Probes) != 2 || len(state.Comparison) != 8 {
		t.Fatalf("observations: probes=%d comparison=%d", len(state.Probes), len(state.Comparison))
	}
	for _, comparison := range state.Comparison {
		if comparison.Status != "match" {
			t.Fatalf("comparison %q = %q", comparison.Field, comparison.Status)
		}
	}
	if state.Outcome == nil || state.Outcome.Status != "hardware_qualification_passed" {
		t.Fatalf("outcome = %#v", state.Outcome)
	}
	if state.ExportRecord == nil || !state.ExportRecord.Simulation || state.ExportRecord.MutationEligible {
		t.Fatalf("export = %#v", state.ExportRecord)
	}
	if state.ExportRecord.NormalBootConfirmation != "operator_confirmed_normal" {
		t.Fatalf("boot confirmation = %q", state.ExportRecord.NormalBootConfirmation)
	}
}

func TestFailureScenariosStopOrQuarantine(t *testing.T) {
	tests := []struct {
		scenario ScenarioID
		actions  []Action
		phase    Phase
	}{
		{ScenarioMultipleTargets, []Action{ActionAttachTarget}, PhaseStopped},
		{ScenarioClassMismatch, []Action{ActionAttachTarget, ActionRunFirstProbe}, PhaseStopped},
		{ScenarioBaselineFailure, []Action{ActionAttachTarget, ActionRunFirstProbe}, PhaseStopped},
		{ScenarioAcquisitionError, []Action{ActionAttachTarget, ActionRunFirstProbe}, PhaseStopped},
		{ScenarioMutationSafetyViolation, []Action{ActionAttachTarget, ActionRunFirstProbe}, PhaseQuarantined},
		{ScenarioTargetReplaced, []Action{ActionAttachTarget, ActionRunFirstProbe, ActionDisconnectTarget, ActionReconnectTarget, ActionRunSecondProbe}, PhaseQuarantined},
		{ScenarioBootFailure, []Action{ActionAttachTarget, ActionRunFirstProbe, ActionDisconnectTarget, ActionReconnectTarget, ActionRunSecondProbe, ActionConfirmBootFailed}, PhaseQuarantined},
	}
	for _, test := range tests {
		t.Run(string(test.scenario), func(t *testing.T) {
			machine := newTestMachine(t, test.scenario)
			for _, action := range test.actions {
				state := machine.Snapshot()
				if _, err := machine.Apply(ActionRequest{Action: action, ExpectedRevision: state.Revision}); err != nil {
					t.Fatalf("apply %q: %v", action, err)
				}
			}
			state := machine.Snapshot()
			if state.Phase != test.phase || state.Outcome == nil {
				t.Fatalf("state = phase %q, outcome %#v", state.Phase, state.Outcome)
			}
			assertSafetyInvariants(t, state)
		})
	}
}

func TestInvalidAndStaleActionsDoNotChangeState(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	before := machine.Snapshot()
	if _, err := machine.Apply(ActionRequest{Action: ActionRunFirstProbe, ExpectedRevision: before.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("illegal action error = %v", err)
	}
	if got := machine.Snapshot(); got.Revision != before.Revision || got.Phase != before.Phase {
		t.Fatalf("illegal action changed state: %#v", got)
	}
	if _, err := machine.Apply(ActionRequest{Action: ActionAttachTarget, ExpectedRevision: before.Revision + 1}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale action error = %v", err)
	}
	if got := machine.Snapshot(); got.Revision != before.Revision || got.Phase != before.Phase {
		t.Fatalf("stale action changed state: %#v", got)
	}
}

func TestConcurrentDoubleActionAllowsExactlyOneTransition(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	revision := machine.Snapshot().Revision
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := machine.Apply(ActionRequest{Action: ActionAttachTarget, ExpectedRevision: revision})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrStaleRevision):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	if state := machine.Snapshot(); state.Revision != revision+1 || state.Phase != PhaseTargetDetected {
		t.Fatalf("state after double action = %#v", state)
	}
}

func TestSnapshotIsDeepCopyAndResetPreservesScenario(t *testing.T) {
	machine := newTestMachine(t, ScenarioBaselineFailure)
	snapshot := machine.Snapshot()
	snapshot.AllowedActions[0] = ActionRunSecondProbe
	snapshot.Scenarios[0].Label = "changed"
	actual := machine.Snapshot()
	if actual.AllowedActions[0] != ActionAttachTarget || actual.Scenarios[0].Label == "changed" {
		t.Fatal("snapshot mutation affected authoritative state")
	}
	state, err := machine.Apply(ActionRequest{Action: ActionAttachTarget, ExpectedRevision: actual.Revision})
	if err != nil {
		t.Fatal(err)
	}
	state, err = machine.Apply(ActionRequest{Action: ActionReset, ExpectedRevision: state.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if state.Scenario != ScenarioBaselineFailure || state.Phase != PhaseReady || state.Target != nil {
		t.Fatalf("reset state = %#v", state)
	}
}

func TestScenarioSelectionIsRevisioned(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	before := machine.Snapshot()
	state, err := machine.Apply(ActionRequest{
		Action: Action("select_scenario:" + string(ScenarioTargetReplaced)), ExpectedRevision: before.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Scenario != ScenarioTargetReplaced || state.Phase != PhaseReady || state.Revision != before.Revision+1 {
		t.Fatalf("selected state = %#v", state)
	}
	if _, err := machine.Apply(ActionRequest{Action: "select_scenario:not-real", ExpectedRevision: state.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("unknown scenario error = %v", err)
	}
}

func newTestMachine(t *testing.T, scenario ScenarioID) *Machine {
	t.Helper()
	machine, err := NewMockMachine(scenario)
	if err != nil {
		t.Fatal(err)
	}
	return machine
}

func assertSafetyInvariants(t *testing.T, state State) {
	t.Helper()
	if !state.Simulation || !state.Safety.Simulation || state.Safety.MutationEligible {
		t.Fatalf("unsafe simulation state: %#v", state.Safety)
	}
	if state.Safety.FullUnprovisionedState != "not_established" || state.Safety.Disclaimer != AssessmentDisclaimer {
		t.Fatalf("safety contract = %#v", state.Safety)
	}
	for _, probe := range state.Probes {
		if probe.EligibleForReversibleQualification && state.Safety.MutationEligible {
			t.Fatal("reversible qualification implied mutation eligibility")
		}
		if probe.Assessment.MutationEligible || probe.Assessment.FullUnprovisionedState != "not_established" || probe.Assessment.Disclaimer != AssessmentDisclaimer {
			t.Fatalf("unsafe probe assessment: %#v", probe.Assessment)
		}
	}
	if state.ExportRecord != nil {
		if !state.ExportRecord.Simulation || state.ExportRecord.MutationEligible || state.ExportRecord.FullUnprovisionedState != "not_established" {
			t.Fatalf("unsafe export record: %#v", state.ExportRecord)
		}
	}
}
