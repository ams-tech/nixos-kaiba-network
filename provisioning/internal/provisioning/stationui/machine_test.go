package stationui

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

type expectedStep struct {
	action           Action
	phase            Phase
	lifecycle        DeviceLifecycle
	transaction      TransactionStatus
	boundary         bool
	commitExecutions int
	finalExecutions  int
}

var happyPath = []expectedStep{
	{ActionRunStationAdmission, PhaseTransactionCreation, LifecycleUnregistered, "", false, 0, 0},
	{ActionCreateTransaction, PhaseReady, LifecycleUnregistered, TransactionCreated, false, 0, 0},
	{ActionAttachTarget, PhaseTargetDetected, LifecycleUnregistered, TransactionTargetBound, false, 0, 0},
	{ActionRunFirstProbe, PhasePowerCycleRequired, LifecycleUnregistered, TransactionTargetBound, false, 0, 0},
	{ActionDisconnectTarget, PhaseAwaitingReconnect, LifecycleUnregistered, TransactionTargetBound, false, 0, 0},
	{ActionReconnectTarget, PhaseSecondProbeReady, LifecycleUnregistered, TransactionTargetBound, false, 0, 0},
	{ActionRunSecondProbe, PhaseAwaitingNormalBootConfirmation, LifecycleUnregistered, TransactionTargetBound, false, 0, 0},
	{ActionConfirmBootOK, PhaseQualifiedFreshCandidate, LifecycleQualifiedFreshCandidate, TransactionTargetBound, false, 0, 0},
	{ActionCloseDeferredBaseline, PhaseBaselineClosed, LifecycleQualifiedFreshCandidate, TransactionPreflightPassed, false, 0, 0},
	{ActionPrepareTransaction, PhasePrepared, LifecyclePrepared, TransactionPreflightPassed, false, 0, 0},
	{ActionRequestCommitApproval, PhaseCommitApproved, LifecyclePrepared, TransactionCommitApproved, false, 0, 0},
	{ActionEstablishInitialTrust, PhaseTrustEstablished, LifecyclePrepared, TransactionTrustEstablished, false, 0, 0},
	{ActionReidentifyCommitTarget, PhaseCommitTargetReidentified, LifecyclePrepared, TransactionTrustEstablished, false, 0, 0},
	{ActionRecordCommitIntent, PhaseCommitIntentRecorded, LifecycleCommitInProgress, TransactionTrustEstablished, false, 0, 0},
	{ActionExecuteCommit, PhaseCommitInProgress, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionObserveCommitReadback, PhaseCommitReadbackVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionPowerOffOwnedTarget, PhaseAwaitingOwnedColdBoot, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionConfirmSignedBoot, PhaseSignedBootVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionRunOwnedReadback, PhaseOwnedReadbackVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionTestOwnedRecovery, PhaseRecoveryVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionRerunOwnedReadback, PhasePostRecoveryReadbackVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionTestNegativeBoot, PhaseNegativeBootVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionTestRootIntegrity, PhaseRootIntegrityVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionTestRollback, PhaseRollbackVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionRequestFinalizationApproval, PhaseFinalizationApproved, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionRecordFinalizationIntent, PhaseFinalizationIntentRecorded, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 0},
	{ActionApplyFinalControls, PhaseFinalControlsApplied, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 1},
	{ActionColdRestartFinalizedTarget, PhaseFinalColdRestartObserved, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 1},
	{ActionObserveFinalControlsReadback, PhaseFinalControlsReadbackVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 1},
	{ActionRunFinalRetest, PhaseFinalRetestVerified, LifecycleCommitInProgress, TransactionTrustEstablished, true, 1, 1},
	{ActionReconcileAudit, PhaseAuditReconciled, LifecycleSecurityApplied, TransactionSecurityApplied, true, 1, 1},
	{ActionMarkEnrollmentReady, PhaseEnrollmentReady, LifecycleEnrollmentReady, TransactionSecurityApplied, true, 1, 1},
	{ActionExportRedacted, PhaseEnrollmentReady, LifecycleEnrollmentReady, TransactionSecurityApplied, true, 1, 1},
}

func TestHappyPathModelsCompleteSecureBootTransaction(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	initial := machine.Snapshot()
	if initial.Phase != PhaseStationAdmission || initial.Transaction != nil || initial.Lifecycle != LifecycleUnregistered {
		t.Fatalf("initial state = %#v", initial)
	}
	assertSafetyInvariants(t, initial)

	for _, step := range happyPath {
		state := applyAction(t, machine, step.action)
		if state.Phase != step.phase || state.Lifecycle != step.lifecycle {
			t.Fatalf("after %q phase/lifecycle = %q/%q, want %q/%q", step.action, state.Phase, state.Lifecycle, step.phase, step.lifecycle)
		}
		if step.transaction == "" {
			if state.Transaction != nil {
				t.Fatalf("after %q transaction = %#v, want nil", step.action, state.Transaction)
			}
		} else if state.Transaction == nil || state.Transaction.Status != step.transaction ||
			state.Transaction.IrreversibleBoundaryCrossed != step.boundary ||
			state.Transaction.CommitExecutions != step.commitExecutions ||
			state.Transaction.FinalControlExecutions != step.finalExecutions {
			t.Fatalf("after %q transaction = %#v", step.action, state.Transaction)
		}
		assertSafetyInvariants(t, state)
	}

	state := machine.Snapshot()
	if len(state.Probes) != 2 || len(state.Comparison) != 9 {
		t.Fatalf("observations: probes=%d comparison=%d", len(state.Probes), len(state.Comparison))
	}
	for _, comparison := range state.Comparison {
		want := "match"
		if comparison.Field == "eeprom_hash" {
			want = "not_observed"
		}
		if comparison.Status != want {
			t.Fatalf("comparison %q = %q, want %q", comparison.Field, comparison.Status, want)
		}
	}
	if state.Manifest == nil || state.Manifest.VerificationStatus != "verified" || state.Manifest.ExpectedCustomerKeyHash != state.Target.CustomerKeyHash {
		t.Fatalf("manifest/target = %#v / %#v", state.Manifest, state.Target)
	}
	if state.Transaction.IntentReceipt == "" || state.Transaction.ApprovalID == "" || state.Transaction.ApproverID == "" ||
		state.Transaction.FinalizationApprovalID == "" || state.Transaction.FinalizationIntentReceipt == "" {
		t.Fatalf("transaction omitted approval or intent = %#v", state.Transaction)
	}
	for _, id := range []string{
		"station-admission", "transaction-created", "target-bound", "fresh-probe-1", "fresh-probe-2",
		"qualification-boot", "baseline-otp-key-rows", "baseline-eeprom-posture", "baseline-storage",
		"baseline-inventory", "baseline-firmware-authenticity", "baseline-debug-paths",
		"manifest-verification", "commit-approval", "initial-trust", "precommit-target-reidentification", "commit-intent",
		"ownership-commit", "commit-readback", "signed-cold-boot", "owned-readback", "owned-recovery",
		"post-recovery-readback", "negative-boot", "root-integrity", "rollback", "finalization-approval",
		"finalization-intent", "final-controls-execution", "final-cold-restart", "final-controls-readback", "final-retest",
		"audit-reconciliation", "enrollment-ready",
	} {
		assertEvidence(t, state, id, EvidenceFailed, false)
	}
	if state.Outcome == nil || state.Outcome.Status != "enrollment_ready" {
		t.Fatalf("outcome = %#v", state.Outcome)
	}
	if state.ExportRecord == nil || !state.ExportRecord.SecretFree || state.ExportRecord.Lifecycle != LifecycleEnrollmentReady {
		t.Fatalf("export = %#v", state.ExportRecord)
	}
	if state.ExportRecord.Transaction.CommitExecutions != 1 || state.ExportRecord.Transaction.FinalControlExecutions != 1 ||
		!state.ExportRecord.Transaction.IrreversibleBoundaryCrossed ||
		len(state.ExportRecord.Evidence) != len(state.Evidence) || state.ExportRecord.Outcome.Status != "enrollment_ready" {
		t.Fatalf("export record did not retain the full result: %#v", state.ExportRecord)
	}
	if len(state.AllowedActions) != 0 {
		t.Fatalf("owned exported terminal state still allows actions: %v", state.AllowedActions)
	}
}

func TestCommitCannotBeSkippedOrRepeated(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	initial := machine.Snapshot()
	assertRejectedWithoutChange(t, machine, ActionCreateTransaction, initial)

	applyHappyPrefix(t, machine, ActionEstablishInitialTrust)
	beforeReidentification := machine.Snapshot()
	assertRejectedWithoutChange(t, machine, ActionRecordCommitIntent, beforeReidentification)
	assertRejectedWithoutChange(t, machine, ActionExecuteCommit, beforeReidentification)

	beforeIntent := applyAction(t, machine, ActionReidentifyCommitTarget)
	assertRejectedWithoutChange(t, machine, ActionExecuteCommit, beforeIntent)

	applyAction(t, machine, ActionRecordCommitIntent)
	intent := machine.Snapshot()
	if intent.Transaction.IntentReceipt == "" || intent.Transaction.IrreversibleBoundaryCrossed || intent.Transaction.CommitExecutions != 0 {
		t.Fatalf("intent state = %#v", intent.Transaction)
	}
	assertRejectedWithoutChange(t, machine, ActionObserveCommitReadback, intent)

	executed := applyAction(t, machine, ActionExecuteCommit)
	if executed.Transaction.CommitExecutions != 1 || !executed.Transaction.IrreversibleBoundaryCrossed {
		t.Fatalf("executed state = %#v", executed.Transaction)
	}
	assertRejectedWithoutChange(t, machine, ActionExecuteCommit, executed)
	if state := machine.Snapshot(); state.Transaction.CommitExecutions != 1 {
		t.Fatalf("repeat changed execution count to %d", state.Transaction.CommitExecutions)
	}
}

func TestFinalControlsRequireSeparateApprovalIntentAndExecuteOnce(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	rollback := applyHappyPrefix(t, machine, ActionTestRollback)
	assertRejectedWithoutChange(t, machine, ActionApplyFinalControls, rollback)

	approved := applyAction(t, machine, ActionRequestFinalizationApproval)
	if approved.Transaction.FinalizationApprovalID == "" || approved.Transaction.FinalControlExecutions != 0 {
		t.Fatalf("finalization approval state = %#v", approved.Transaction)
	}
	assertRejectedWithoutChange(t, machine, ActionApplyFinalControls, approved)

	intent := applyAction(t, machine, ActionRecordFinalizationIntent)
	if intent.Transaction.FinalizationIntentReceipt == "" || intent.Transaction.FinalControlExecutions != 0 {
		t.Fatalf("finalization intent state = %#v", intent.Transaction)
	}
	assertRejectedWithoutChange(t, machine, ActionObserveFinalControlsReadback, intent)

	executed := applyAction(t, machine, ActionApplyFinalControls)
	if executed.Transaction.FinalControlExecutions != 1 || !executed.Transaction.IrreversibleBoundaryCrossed {
		t.Fatalf("final-controls execution state = %#v", executed.Transaction)
	}
	assertRejectedWithoutChange(t, machine, ActionApplyFinalControls, executed)
	if state := machine.Snapshot(); state.Transaction.FinalControlExecutions != 1 {
		t.Fatalf("repeat changed final-control execution count to %d", state.Transaction.FinalControlExecutions)
	}
	assertRejectedWithoutChange(t, machine, ActionObserveFinalControlsReadback, executed)
	restarted := applyAction(t, machine, ActionColdRestartFinalizedTarget)
	assertRejectedWithoutChange(t, machine, ActionColdRestartFinalizedTarget, restarted)
	applyAction(t, machine, ActionObserveFinalControlsReadback)
}

func TestPreCommitFailuresAbortWithoutCrossingOTP(t *testing.T) {
	tests := []struct {
		scenario ScenarioID
		trigger  Action
	}{
		{ScenarioMultipleTargets, ActionAttachTarget},
		{ScenarioClassMismatch, ActionRunFirstProbe},
		{ScenarioAcquisitionError, ActionRunFirstProbe},
		{ScenarioTargetReplaced, ActionRunSecondProbe},
		{ScenarioBootFailure, ActionConfirmBootFailed},
		{ScenarioDeferredBaselineFailure, ActionCloseDeferredBaseline},
		{ScenarioPreparationFailure, ActionPrepareTransaction},
		{ScenarioApprovalFailure, ActionRequestCommitApproval},
		{ScenarioTrustFailure, ActionEstablishInitialTrust},
		{ScenarioPrecommitTargetReplaced, ActionReidentifyCommitTarget},
	}
	for _, test := range tests {
		t.Run(string(test.scenario), func(t *testing.T) {
			machine := newTestMachine(t, test.scenario)
			applyScenarioThrough(t, machine, test.trigger)
			state := machine.Snapshot()
			if state.Phase != PhaseStopped || state.Outcome == nil || state.Outcome.Status != "aborted" {
				t.Fatalf("terminal state = %#v", state)
			}
			if state.Transaction == nil || state.Transaction.Status != TransactionAborted ||
				state.Transaction.IrreversibleBoundaryCrossed || state.Transaction.CommitExecutions != 0 {
				t.Fatalf("aborted transaction = %#v", state.Transaction)
			}
			if state.Lifecycle == LifecycleOwnedQuarantined {
				t.Fatalf("pre-commit failure claimed owned lifecycle: %q", state.Lifecycle)
			}
			assertSafetyInvariants(t, state)
		})
	}
}

func TestTerminalWorkflowStageUsesActualFailureEvidence(t *testing.T) {
	machine := newTestMachine(t, ScenarioAuditFailure)
	applyHappyPrefix(t, machine, ActionRunSecondProbe)
	state := applyAction(t, machine, ActionConfirmBootFailed)
	if state.Phase != PhaseStopped {
		t.Fatalf("phase = %q, want %q", state.Phase, PhaseStopped)
	}
	terminalEvidence := state.Evidence[len(state.Evidence)-1]
	if terminalEvidence.ID != "terminal-abort" || terminalEvidence.Stage != WorkflowStageQualification {
		t.Fatalf("terminal evidence = %#v", terminalEvidence)
	}
	for _, stage := range state.WorkflowStages {
		want := WorkflowStagePending
		switch stage.ID {
		case WorkflowStageAdmission, WorkflowStageTransaction:
			want = WorkflowStageComplete
		case WorkflowStageQualification:
			want = WorkflowStageFailed
		}
		if stage.Status != want {
			t.Fatalf("stage %q = %q, want %q", stage.ID, stage.Status, want)
		}
	}
}

func TestForeignOrUnexpectedMutationIsOwnedQuarantined(t *testing.T) {
	for _, scenario := range []ScenarioID{ScenarioBaselineFailure, ScenarioMutationSafetyViolation} {
		t.Run(string(scenario), func(t *testing.T) {
			machine := newTestMachine(t, scenario)
			applyScenarioThrough(t, machine, ActionRunFirstProbe)
			state := machine.Snapshot()
			if state.Phase != PhaseQuarantined || state.Lifecycle != LifecycleOwnedQuarantined ||
				state.Transaction.Status != TransactionQuarantined || state.Outcome.Status != "owned_quarantined" {
				t.Fatalf("foreign/uncertain state = %#v", state)
			}
			if scenario == ScenarioBaselineFailure {
				if state.Transaction.IrreversibleBoundaryCrossed || state.Target.CustomerKeyHash == expectedCustomerKeyHash() || state.Target.CustomerKeyHash == syntheticZeroCustomerKeyHash() {
					t.Fatalf("foreign ownership evidence = %#v / %#v", state.Transaction, state.Target)
				}
			} else if !state.Transaction.IrreversibleBoundaryCrossed || state.Transaction.CommitExecutions != 0 {
				t.Fatalf("unexpected-mutation boundary = %#v", state.Transaction)
			}
		})
	}
}

func TestPostOTPFailuresAreOwnedQuarantined(t *testing.T) {
	tests := []struct {
		scenario ScenarioID
		trigger  Action
	}{
		{ScenarioCommitUncertain, ActionExecuteCommit},
		{ScenarioCommitReadbackMismatch, ActionObserveCommitReadback},
		{ScenarioSignedBootFailure, ActionConfirmSignedBoot},
		{ScenarioOwnedReadbackMismatch, ActionRunOwnedReadback},
		{ScenarioRecoveryFailure, ActionTestOwnedRecovery},
		{ScenarioPostRecoveryReadbackMismatch, ActionRerunOwnedReadback},
		{ScenarioNegativeBootFailure, ActionTestNegativeBoot},
		{ScenarioRootIntegrityFailure, ActionTestRootIntegrity},
		{ScenarioRollbackFailure, ActionTestRollback},
		{ScenarioFinalizationFailure, ActionObserveFinalControlsReadback},
		{ScenarioFinalRetestFailure, ActionRunFinalRetest},
		{ScenarioAuditFailure, ActionReconcileAudit},
	}
	for _, test := range tests {
		t.Run(string(test.scenario), func(t *testing.T) {
			machine := newTestMachine(t, test.scenario)
			applyScenarioThrough(t, machine, test.trigger)
			state := machine.Snapshot()
			if state.Phase != PhaseQuarantined || state.Lifecycle != LifecycleOwnedQuarantined ||
				state.Outcome == nil || state.Outcome.Status != "owned_quarantined" {
				t.Fatalf("terminal state = %#v", state)
			}
			if state.Transaction.Status != TransactionQuarantined || !state.Transaction.IrreversibleBoundaryCrossed || state.Transaction.CommitExecutions != 1 {
				t.Fatalf("quarantined transaction = %#v", state.Transaction)
			}
			assertRejectedWithoutChange(t, machine, ActionExecuteCommit, state)
			assertSafetyInvariants(t, state)
		})
	}
}

func TestOwnedTerminalStatesHaveNoFreshPathReset(t *testing.T) {
	precommit := newTestMachine(t, ScenarioClassMismatch)
	applyScenarioThrough(t, precommit, ActionRunFirstProbe)
	stopped := precommit.Snapshot()
	if !actionAllowed(stopped.AllowedActions, ActionReset) {
		t.Fatalf("pre-ownership abort omitted reusable-fixture reset: %v", stopped.AllowedActions)
	}
	reset := applyAction(t, precommit, ActionReset)
	if reset.Phase != PhaseStationAdmission || reset.Transaction != nil || reset.Lifecycle != LifecycleUnregistered {
		t.Fatalf("pre-ownership reset state = %#v", reset)
	}

	tests := []struct {
		name     string
		scenario ScenarioID
		trigger  Action
	}{
		{name: "foreign ownership", scenario: ScenarioBaselineFailure, trigger: ActionRunFirstProbe},
		{name: "post-OTP quarantine", scenario: ScenarioCommitUncertain, trigger: ActionExecuteCommit},
		{name: "enrollment ready", scenario: ScenarioHappyPath, trigger: ActionMarkEnrollmentReady},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newTestMachine(t, test.scenario)
			applyScenarioThrough(t, machine, test.trigger)
			terminal := machine.Snapshot()
			if actionAllowed(terminal.AllowedActions, ActionReset) || !actionAllowed(terminal.AllowedActions, ActionExportRedacted) {
				t.Fatalf("owned terminal actions = %v", terminal.AllowedActions)
			}
			assertRejectedWithoutChange(t, machine, ActionReset, terminal)
			exported := applyAction(t, machine, ActionExportRedacted)
			if len(exported.AllowedActions) != 0 {
				t.Fatalf("exported owned terminal actions = %v", exported.AllowedActions)
			}
			assertRejectedWithoutChange(t, machine, ActionReset, exported)
		})
	}
}

func TestEveryEnrollmentGateIsOrderedAndRequired(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	for _, step := range happyPath[:len(happyPath)-1] {
		before := machine.Snapshot()
		if step.action != ActionMarkEnrollmentReady {
			assertRejectedWithoutChange(t, machine, ActionMarkEnrollmentReady, before)
		}
		state := applyAction(t, machine, step.action)
		if state.Phase != PhaseAuditReconciled && state.Phase != PhaseEnrollmentReady &&
			state.Transaction != nil && state.Transaction.Status == TransactionSecurityApplied {
			t.Fatalf("security_applied appeared at phase %q", state.Phase)
		}
	}
	state := machine.Snapshot()
	if state.Phase != PhaseEnrollmentReady || state.Lifecycle != LifecycleEnrollmentReady {
		t.Fatalf("final gate state = %#v", state)
	}
	for _, stage := range state.WorkflowStages {
		if stage.Status != WorkflowStageComplete {
			t.Fatalf("stage %q = %q", stage.ID, stage.Status)
		}
	}
}

func TestComparisonOnlyDefersAnUnobservedEEPROMHash(t *testing.T) {
	tests := []struct {
		name       string
		comparison []Comparison
		changed    bool
	}{
		{name: "all observed", comparison: []Comparison{{Field: "target_fingerprint", Status: "match"}}},
		{name: "EEPROM unavailable", comparison: []Comparison{{Field: "eeprom_hash", Status: "not_observed"}}},
		{name: "other field unavailable", comparison: []Comparison{{Field: "boot_rom", Status: "not_observed"}}, changed: true},
		{name: "unknown status", comparison: []Comparison{{Field: "eeprom_hash", Status: "unknown"}}, changed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasChangedComparison(tt.comparison); got != tt.changed {
				t.Fatalf("hasChangedComparison() = %t, want %t", got, tt.changed)
			}
		})
	}
}

func TestComparisonTreatsMixedEEPROMPresenceAsChanged(t *testing.T) {
	absent := syntheticTarget()
	present := *absent
	present.EEPROMHash = syntheticDigest("observed-eeprom")
	for _, pair := range []struct {
		name          string
		first, second *TargetSummary
	}{
		{name: "present then absent", first: &present, second: absent},
		{name: "absent then present", first: absent, second: &present},
	} {
		t.Run(pair.name, func(t *testing.T) {
			for _, comparison := range compareObservations(pair.first, pair.second) {
				if comparison.Field == "eeprom_hash" {
					if comparison.Status != "changed" {
						t.Fatalf("EEPROM comparison = %#v", comparison)
					}
					return
				}
			}
			t.Fatal("EEPROM comparison was not emitted")
		})
	}
}

func TestInvalidStaleAndConcurrentActionsDoNotForkState(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	before := machine.Snapshot()
	assertRejectedWithoutChange(t, machine, ActionAttachTarget, before)
	if _, err := machine.Apply(ActionRequest{Action: ActionRunStationAdmission, ExpectedRevision: before.Revision + 1}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale action error = %v", err)
	}

	revision := before.Revision
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := machine.Apply(ActionRequest{Action: ActionRunStationAdmission, ExpectedRevision: revision})
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
}

func TestSnapshotIsDeepCopyAndScenarioSelectionIsRevisioned(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	snapshot := machine.Snapshot()
	snapshot.AllowedActions[0] = ActionExecuteCommit
	snapshot.Scenarios[0].Label = "changed"
	snapshot.WorkflowStages[0].Label = "changed"
	snapshot.ActionPresentations[0].Label = "changed"
	snapshot.Evidence = append(snapshot.Evidence, EvidenceSummary{ID: "changed"})
	actual := machine.Snapshot()
	if actual.AllowedActions[0] != ActionRunStationAdmission || actual.Scenarios[0].Label == "changed" ||
		actual.WorkflowStages[0].Label == "changed" || actual.ActionPresentations[0].Label == "changed" || len(actual.Evidence) != 0 {
		t.Fatal("snapshot mutation affected authoritative state")
	}

	state, err := machine.Apply(ActionRequest{Action: Action("select_scenario:" + string(ScenarioAuditFailure)), ExpectedRevision: actual.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if state.Scenario != ScenarioAuditFailure || state.Phase != PhaseStationAdmission || state.Revision != actual.Revision+1 {
		t.Fatalf("selected state = %#v", state)
	}
	if _, err := machine.Apply(ActionRequest{Action: "select_scenario:not-real", ExpectedRevision: state.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("unknown scenario error = %v", err)
	}
}

func applyHappyPrefix(t *testing.T, machine *Machine, through Action) State {
	t.Helper()
	for _, step := range happyPath {
		state := applyAction(t, machine, step.action)
		if step.action == through {
			return state
		}
	}
	t.Fatalf("happy path does not contain %q", through)
	return State{}
}

func applyScenarioThrough(t *testing.T, machine *Machine, trigger Action) State {
	t.Helper()
	for _, step := range happyPath {
		action := step.action
		if machine.Snapshot().Scenario == ScenarioBootFailure && action == ActionConfirmBootOK {
			action = ActionConfirmBootFailed
		}
		state := applyAction(t, machine, action)
		if action == trigger {
			return state
		}
	}
	t.Fatalf("scenario path does not contain %q", trigger)
	return State{}
}

func applyAction(t *testing.T, machine *Machine, action Action) State {
	t.Helper()
	before := machine.Snapshot()
	state, err := machine.Apply(ActionRequest{Action: action, ExpectedRevision: before.Revision})
	if err != nil {
		t.Fatalf("apply %q at %q: %v", action, before.Phase, err)
	}
	return state
}

func assertRejectedWithoutChange(t *testing.T, machine *Machine, action Action, before State) {
	t.Helper()
	if _, err := machine.Apply(ActionRequest{Action: action, ExpectedRevision: before.Revision}); !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("illegal action %q error = %v", action, err)
	}
	after := machine.Snapshot()
	if after.Revision != before.Revision || after.Phase != before.Phase ||
		(after.Transaction != nil && before.Transaction != nil &&
			(after.Transaction.CommitExecutions != before.Transaction.CommitExecutions ||
				after.Transaction.FinalControlExecutions != before.Transaction.FinalControlExecutions)) {
		t.Fatalf("illegal action %q changed state: %#v", action, after)
	}
}

func assertEvidence(t *testing.T, state State, id string, status EvidenceStatus, equal bool) {
	t.Helper()
	for _, evidence := range state.Evidence {
		if evidence.ID != id {
			continue
		}
		if equal && evidence.Status != status {
			t.Fatalf("evidence %q status = %q, want %q", id, evidence.Status, status)
		}
		if !equal && evidence.Status == status {
			t.Fatalf("evidence %q unexpectedly has status %q", id, status)
		}
		if !strings.HasPrefix(evidence.Digest, "sha256:") || evidence.Detail == "" || evidence.Label == "" {
			t.Fatalf("incomplete evidence %q: %#v", id, evidence)
		}
		return
	}
	t.Fatalf("evidence %q not found", id)
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
	safety := state.Safety
	if !state.Simulation || !safety.Simulation || safety.MutationEligible || safety.LiveTargetAccess ||
		safety.LiveMutationCapable || safety.AuthoritativeEvidence || safety.SecretsPresent ||
		safety.ApprovalAuthority || safety.SigningCapable || safety.EnrollmentCapable {
		t.Fatalf("unsafe simulation state: %#v", safety)
	}
	if safety.FullUnprovisionedState != "not_established" || safety.Disclaimer != AssessmentDisclaimer {
		t.Fatalf("safety contract = %#v", safety)
	}
	for _, probe := range state.Probes {
		if probe.Assessment.MutationEligible || probe.Assessment.FullUnprovisionedState != "not_established" || probe.Assessment.Disclaimer != AssessmentDisclaimer {
			t.Fatalf("unsafe probe assessment: %#v", probe.Assessment)
		}
	}
	normalActions := 0
	for _, action := range state.AllowedActions {
		if _, scenarioAction := scenarioFromAction(action); !scenarioAction {
			normalActions++
		}
	}
	if len(state.ActionPresentations) != normalActions {
		t.Fatalf("presentations=%d normal actions=%d", len(state.ActionPresentations), normalActions)
	}
	for _, presentation := range state.ActionPresentations {
		if presentation.Action == "" || presentation.Label == "" || presentation.Description == "" || presentation.Classification == "" {
			t.Fatalf("incomplete action presentation: %#v", presentation)
		}
		if presentation.PointOfNoReturn != (presentation.Action == ActionExecuteCommit) {
			t.Fatalf("action %q point_of_no_return=%t", presentation.Action, presentation.PointOfNoReturn)
		}
	}
	if state.Transaction != nil {
		if state.Transaction.CommitExecutions < 0 || state.Transaction.CommitExecutions > 1 {
			t.Fatalf("commit execution count = %d", state.Transaction.CommitExecutions)
		}
		if state.Transaction.FinalControlExecutions < 0 || state.Transaction.FinalControlExecutions > 1 {
			t.Fatalf("final-control execution count = %d", state.Transaction.FinalControlExecutions)
		}
		if state.Transaction.CommitExecutions == 1 && !state.Transaction.IrreversibleBoundaryCrossed {
			t.Fatal("commit executed without crossing irreversible boundary")
		}
		if state.Transaction.FinalControlExecutions == 1 && (state.Transaction.CommitExecutions != 1 ||
			!state.Transaction.IrreversibleBoundaryCrossed || state.Transaction.FinalizationApprovalID == "" ||
			state.Transaction.FinalizationIntentReceipt == "") {
			t.Fatalf("final controls executed without required ownership, approval, or intent: %#v", state.Transaction)
		}
	}
	if state.Phase == PhaseEnrollmentReady && (state.Lifecycle != LifecycleEnrollmentReady || state.Transaction == nil || state.Transaction.Status != TransactionSecurityApplied) {
		t.Fatalf("invalid enrollment-ready state: %#v", state)
	}
	if state.Phase == PhaseQuarantined && (state.Lifecycle != LifecycleOwnedQuarantined || state.Transaction == nil || state.Transaction.Status != TransactionQuarantined) {
		t.Fatalf("invalid quarantine state: %#v", state)
	}
	if (state.Phase == PhaseQuarantined || state.Phase == PhaseEnrollmentReady) && actionAllowed(state.AllowedActions, ActionReset) {
		t.Fatalf("owned terminal state exposes reset: %#v", state.AllowedActions)
	}
	if state.ExportRecord != nil {
		exportSafety := state.ExportRecord.Safety
		if !state.ExportRecord.Simulation || !state.ExportRecord.SecretFree || exportSafety.LiveTargetAccess ||
			exportSafety.LiveMutationCapable || exportSafety.AuthoritativeEvidence || exportSafety.SecretsPresent ||
			exportSafety.ApprovalAuthority || exportSafety.SigningCapable || exportSafety.EnrollmentCapable {
			t.Fatalf("unsafe export record: %#v", state.ExportRecord)
		}
	}
}
