package stationui

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTransitionGraphCoversAuthoritativeSecureBootMachine(t *testing.T) {
	graph, err := GenerateTransitionGraph()
	if err != nil {
		t.Fatal(err)
	}
	if graph.SchemaVersion != TransitionGraphSchemaVersion || graph.StateSchemaVersion != StateSchemaVersion {
		t.Fatalf("graph versions = %q, %q", graph.SchemaVersion, graph.StateSchemaVersion)
	}
	if len(graph.Nodes) == 0 || len(graph.Nodes) > 512 {
		t.Fatalf("transition graph node count = %d", len(graph.Nodes))
	}
	root, ok := graph.Nodes[graph.DefaultNode]
	if !ok || root.State.Scenario != ScenarioHappyPath || root.State.Phase != PhaseStationAdmission {
		t.Fatalf("default node = %#v", root.State)
	}

	seenScenarios := make(map[ScenarioID]bool)
	seenPhases := make(map[Phase]bool)
	seenActions := make(map[Action]bool)
	seenEnrollmentReady := false
	seenOwnedQuarantine := false
	for id, node := range graph.Nodes {
		actualID, err := graphStateID(node.State)
		if err != nil {
			t.Fatal(err)
		}
		if actualID != id {
			t.Fatalf("node id = %s, content id = %s", id, actualID)
		}
		if node.State.Revision != 0 {
			t.Fatalf("node %s has runtime revision %d", id, node.State.Revision)
		}
		assertSafetyInvariants(t, node.State)
		seenScenarios[node.State.Scenario] = true
		seenPhases[node.State.Phase] = true
		seenEnrollmentReady = seenEnrollmentReady || node.State.Phase == PhaseEnrollmentReady
		seenOwnedQuarantine = seenOwnedQuarantine || node.State.Phase == PhaseQuarantined
		if len(node.Transitions) != len(node.State.AllowedActions) {
			t.Fatalf("node %s has %d transitions for %d allowed actions", id, len(node.Transitions), len(node.State.AllowedActions))
		}
		for _, action := range node.State.AllowedActions {
			seenActions[action] = true
			targetID, exists := node.Transitions[action]
			if !exists {
				t.Fatalf("node %s omits allowed action %q", id, action)
			}
			if _, exists := graph.Nodes[targetID]; !exists {
				t.Fatalf("node %s action %q references missing node %s", id, action, targetID)
			}
		}
	}

	seenNodes := map[string]bool{graph.DefaultNode: true}
	queue := []string{graph.DefaultNode}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, target := range graph.Nodes[current].Transitions {
			if !seenNodes[target] {
				seenNodes[target] = true
				queue = append(queue, target)
			}
		}
	}
	if len(seenNodes) != len(graph.Nodes) {
		t.Fatalf("reachable nodes = %d, graph nodes = %d", len(seenNodes), len(graph.Nodes))
	}
	for _, scenario := range ScenarioIDs() {
		if !seenScenarios[scenario] {
			t.Errorf("scenario %q is absent", scenario)
		}
	}
	for _, phase := range []Phase{
		PhaseStationAdmission,
		PhaseTransactionCreation,
		PhaseReady,
		PhaseTargetDetected,
		PhasePowerCycleRequired,
		PhaseAwaitingReconnect,
		PhaseSecondProbeReady,
		PhaseAwaitingNormalBootConfirmation,
		PhaseQualifiedFreshCandidate,
		PhaseBaselineClosed,
		PhasePrepared,
		PhaseCommitApproved,
		PhaseTrustEstablished,
		PhaseCommitTargetReidentified,
		PhaseCommitIntentRecorded,
		PhaseCommitInProgress,
		PhaseCommitReadbackVerified,
		PhaseAwaitingOwnedColdBoot,
		PhaseSignedBootVerified,
		PhaseOwnedReadbackVerified,
		PhaseRecoveryVerified,
		PhasePostRecoveryReadbackVerified,
		PhaseNegativeBootVerified,
		PhaseRootIntegrityVerified,
		PhaseRollbackVerified,
		PhaseFinalizationApproved,
		PhaseFinalizationIntentRecorded,
		PhaseFinalControlsApplied,
		PhaseFinalColdRestartObserved,
		PhaseFinalControlsReadbackVerified,
		PhaseFinalRetestVerified,
		PhaseAuditReconciled,
		PhaseEnrollmentReady,
		PhaseStopped,
		PhaseQuarantined,
	} {
		if !seenPhases[phase] {
			t.Errorf("phase %q is absent", phase)
		}
	}
	for _, action := range []Action{
		ActionRunStationAdmission,
		ActionCreateTransaction,
		ActionAttachTarget,
		ActionRunFirstProbe,
		ActionDisconnectTarget,
		ActionReconnectTarget,
		ActionRunSecondProbe,
		ActionConfirmBootOK,
		ActionConfirmBootFailed,
		ActionCloseDeferredBaseline,
		ActionPrepareTransaction,
		ActionRequestCommitApproval,
		ActionEstablishInitialTrust,
		ActionReidentifyCommitTarget,
		ActionRecordCommitIntent,
		ActionExecuteCommit,
		ActionObserveCommitReadback,
		ActionPowerOffOwnedTarget,
		ActionConfirmSignedBoot,
		ActionRunOwnedReadback,
		ActionTestOwnedRecovery,
		ActionRerunOwnedReadback,
		ActionTestNegativeBoot,
		ActionTestRootIntegrity,
		ActionTestRollback,
		ActionRequestFinalizationApproval,
		ActionRecordFinalizationIntent,
		ActionApplyFinalControls,
		ActionColdRestartFinalizedTarget,
		ActionObserveFinalControlsReadback,
		ActionRunFinalRetest,
		ActionReconcileAudit,
		ActionMarkEnrollmentReady,
		ActionExportRedacted,
		ActionReset,
	} {
		if !seenActions[action] {
			t.Errorf("action %q is absent", action)
		}
	}
	if !seenEnrollmentReady || !seenOwnedQuarantine {
		t.Fatalf("terminal coverage: enrollment_ready=%t owned_quarantine=%t", seenEnrollmentReady, seenOwnedQuarantine)
	}
}

func TestTransitionGraphEncodingIsDeterministic(t *testing.T) {
	first, err := GenerateTransitionGraph()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateTransitionGraph()
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("transition graph encoding changed between identical generations")
	}
}
