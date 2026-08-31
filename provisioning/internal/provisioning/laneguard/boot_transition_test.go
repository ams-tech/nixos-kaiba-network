package laneguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHardwareActionEnforcesClosedPhaseBootModePolicy(t *testing.T) {
	rpiboot := testHardwareAction(HardwarePhaseExecute, OperationProgramCustomerKeyAndEEPROM)
	normal := testHardwareAction(HardwarePhaseExecute, OperationColdPowerCycle)
	for _, action := range []HardwareAction{
		rpiboot,
		normal,
		testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle),
		testHardwareAction(HardwarePhasePostObservation, OperationColdPowerCycle),
		testHardwareAction(HardwarePhaseReconciliation, OperationColdPowerCycle),
	} {
		if err := action.Validate(); err != nil {
			t.Fatalf("valid %s/%s action rejected: %v", action.Phase, action.RequestedBootMode, err)
		}
	}

	tests := []struct {
		name   string
		mutate func(*HardwareAction)
	}{
		{"execute mode", func(value *HardwareAction) { value.RequestedBootMode = BootModeNormal }},
		{"operation policy", func(value *HardwareAction) { value.OperationRequiredBootMode = BootModeNormal }},
		{"observation mode", func(value *HardwareAction) {
			*value = testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)
			value.RequestedBootMode = BootModeNormal
		}},
		{"reconciliation claim", func(value *HardwareAction) {
			*value = testHardwareAction(HardwarePhaseReconciliation, OperationColdPowerCycle)
			value.ReconciliationClaimID = ""
		}},
		{"reconciliation authority on execute", func(value *HardwareAction) { value.ReconciliationClaimID = "claim" }},
		{"phase", func(value *HardwareAction) { value.Phase = "invented" }},
		{"power control", func(value *HardwareAction) { value.PowerControlMode = "invented" }},
		{"digest", func(value *HardwareAction) { value.OperationDigest = "not-a-digest" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := rpiboot
			test.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid hardware action was accepted")
			}
		})
	}
}

func TestBootTransitionForwardOnlyCompletionRequiresReleaseAndBindsEvidence(t *testing.T) {
	store := NewMemoryStore()
	request := testBeginBootTransitionRequest(testHardwareAction(HardwarePhaseExecute, OperationProgramCustomerKeyAndEEPROM))
	transition, err := store.BeginBootTransition(request)
	if err != nil || transition.Generation != 1 || transition.Status != BootTransitionRequested {
		t.Fatalf("begin transition = %#v, %v", transition, err)
	}
	missing := transition
	missing.Key = BootTransitionKey(missing.Action, missing.Generation+1)
	missing.Generation++
	if err := store.PutBootTransition(missing); !errors.Is(err, ErrBootTransitionNotBegun) {
		t.Fatalf("put without begin error = %v", err)
	}

	transition.Status = BootTransitionAwaitingOperator
	transition.UpdatedAt = transition.ColdIntervalEndsAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("await operator: %v", err)
	}

	transition.Status = BootTransitionOperatorAcknowledged
	transition.Operator = OperatorPeer{UID: 1000, GID: 1000, PID: 2000}
	transition.OperatorAcknowledgedAt = transition.ColdIntervalEndsAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorAcknowledgedAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("record operator acknowledgment: %v", err)
	}

	changed := transition
	changed.Status = BootTransitionPowerEstablished
	changed.Operator.UID++
	changed.PowerEstablishedAt = changed.OperatorAcknowledgedAt.Add(time.Second)
	changed.UpdatedAt = changed.PowerEstablishedAt
	if err := store.PutBootTransition(changed); err == nil || !strings.Contains(err.Error(), "progress") {
		t.Fatalf("changed acknowledged peer error = %v", err)
	}
	changed = transition
	changed.Status = BootTransitionPowerEstablished
	changed.PowerEstablishedAt = changed.OperatorAcknowledgedAt.Add(time.Second)
	changed.UpdatedAt = changed.OperatorAcknowledgedAt
	if err := store.PutBootTransition(changed); err == nil || !strings.Contains(err.Error(), "update time") {
		t.Fatalf("update before recorded event error = %v", err)
	}

	transition.Status = BootTransitionPowerEstablished
	transition.PowerEstablishedAt = transition.OperatorAcknowledgedAt.Add(time.Second)
	transition.UpdatedAt = transition.PowerEstablishedAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("record power applied: %v", err)
	}

	transition.Status = BootTransitionModeObserved
	transition.ModeObservedAt = transition.PowerEstablishedAt.Add(time.Second)
	transition.ObservedMode = BootModeRPIBoot
	transition.RPIBootSysfsPath = "/sys/bus/usb/devices/1-1"
	transition.RPIBootEligibleTargets = 1
	transition.RPIBootObservationMethod = RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = 50 * time.Millisecond
	transition.ReleasePromptID = "release_prompt_1"
	transition.ReleasePromptDigest = digest("d")
	transition.ReleasePromptExpiresAt = transition.ModeObservedAt.Add(time.Minute)
	transition.UpdatedAt = transition.ModeObservedAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("record RPIBOOT observation: %v", err)
	}

	withoutRelease := transition
	withoutRelease.Status = BootTransitionCompleted
	withoutRelease.SafeOffObservedAt = withoutRelease.ModeObservedAt.Add(time.Second)
	withoutRelease.CompletedAt = withoutRelease.SafeOffObservedAt
	withoutRelease.UpdatedAt = withoutRelease.CompletedAt
	if err := withoutRelease.Validate(); err == nil || !strings.Contains(err.Error(), "release acknowledgment") {
		t.Fatalf("completion without release error = %v", err)
	}

	transition.Status = BootTransitionOperatorReleased
	transition.ReleaseOperator = transition.Operator
	transition.OperatorReleasedAt = transition.ModeObservedAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorReleasedAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("record BOOTSEL release: %v", err)
	}

	transition.Status = BootTransitionCompleted
	transition.SafeOffObservedAt = transition.OperatorReleasedAt.Add(time.Second)
	transition.CompletedAt = transition.SafeOffObservedAt
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		t.Fatalf("derive completed evidence: %v", err)
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		t.Fatalf("digest completed evidence: %v", err)
	}
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("complete transition: %v", err)
	}
	reference, err := transition.Reference()
	if err != nil || reference.Status != BootTransitionCompleted || reference.EvidenceDigest != transition.EvidenceDigest {
		t.Fatalf("completed reference = %#v, %v", reference, err)
	}
	outcome, err := transition.Outcome()
	if err != nil || outcome.Action != transition.Action || outcome.Reference != reference || outcome.Evidence != evidence {
		t.Fatalf("completed outcome = %#v, %v", outcome, err)
	}

	mutatedEvidence := evidence
	mutatedEvidence.ReleasePromptDigest = digest("e")
	mutatedDigest, err := mutatedEvidence.Digest()
	if err != nil || mutatedDigest == transition.EvidenceDigest {
		t.Fatalf("release prompt was not evidence-bound: digest=%q err=%v", mutatedDigest, err)
	}
	expiredEvidence := evidence
	expiredEvidence.OperatorReleasedAt = expiredEvidence.ReleasePromptExpiresAt.Add(time.Nanosecond)
	if _, err := expiredEvidence.Digest(); err == nil || !strings.Contains(err.Error(), "release acknowledgment") {
		t.Fatalf("expired release acknowledgment error = %v", err)
	}
	outOfOrderEvidence := evidence
	outOfOrderEvidence.SafeOffObservedAt = outOfOrderEvidence.ModeObservedAt
	if _, err := outOfOrderEvidence.Digest(); err == nil || !strings.Contains(err.Error(), "release acknowledgment") {
		t.Fatalf("safe-off before release acknowledgment error = %v", err)
	}
	invalidActionEvidence := evidence
	invalidActionEvidence.Action.AuthorizationID = ""
	if _, err := invalidActionEvidence.Digest(); err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("invalid evidence action error = %v", err)
	}
	changed = transition
	changed.CompletedAt = changed.CompletedAt.Add(time.Second)
	changed.UpdatedAt = changed.CompletedAt
	if err := store.PutBootTransition(changed); err == nil {
		t.Fatalf("terminal rewrite error = %v", err)
	}
}

func TestManualPowerTransitionRequiresAndBindsInitialAndFinalSafeOffProof(t *testing.T) {
	request := testBeginBootTransitionRequest(testHardwareAction(HardwarePhaseExecute, OperationProgramCustomerKeyAndEEPROM))
	request.PowerControlMode = PowerControlManual
	request.Action.PowerControlMode = PowerControlManual
	request.InitialPowerOffProof = testOperatorPowerProof(
		"initial_power_off", request.StartedAt.Add(500*time.Millisecond), request.StartedAt.Add(time.Minute),
	)
	transition, err := request.transition(1)
	if err != nil {
		t.Fatalf("begin manual transition: %v", err)
	}
	transition.Status = BootTransitionCompleted
	transition.Operator = OperatorPeer{UID: 1000, GID: 1000, PID: 2000}
	transition.OperatorAcknowledgedAt = transition.ColdIntervalEndsAt.Add(time.Second)
	transition.PowerEstablishedAt = transition.OperatorAcknowledgedAt
	transition.ModeObservedAt = transition.PowerEstablishedAt.Add(time.Second)
	transition.ObservedMode = BootModeRPIBoot
	transition.RPIBootSysfsPath = "/sys/bus/usb/devices/1-1"
	transition.RPIBootEligibleTargets = 1
	transition.RPIBootObservationMethod = RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = 50 * time.Millisecond
	transition.ReleasePromptID = "release_prompt_manual"
	transition.ReleasePromptDigest = digest("d")
	transition.ReleasePromptExpiresAt = transition.ModeObservedAt.Add(time.Minute)
	transition.ReleaseOperator = transition.Operator
	transition.OperatorReleasedAt = transition.ModeObservedAt.Add(time.Second)
	transition.FinalSafeOffProof = testOperatorPowerProof(
		"final_power_off", transition.OperatorReleasedAt.Add(time.Second), transition.OperatorReleasedAt.Add(time.Minute),
	)
	transition.SafeOffObservedAt = transition.FinalSafeOffProof.AcknowledgedAt.Add(time.Second)
	transition.CompletedAt = transition.SafeOffObservedAt
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		t.Fatalf("manual evidence: %v", err)
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		t.Fatalf("manual evidence digest: %v", err)
	}
	if err := transition.Validate(); err != nil {
		t.Fatalf("valid completed manual transition rejected: %v", err)
	}
	reference, err := transition.Reference()
	if err != nil || reference.PowerControlMode != PowerControlManual ||
		reference.PowerEstablishmentBasis != PowerEstablishmentOperatorAttestation ||
		reference.SafeOffBasis != SafeOffOperatorDisconnectAndUSBAbsence ||
		reference.InitialPowerOffProof != transition.InitialPowerOffProof ||
		reference.FinalSafeOffProof != transition.FinalSafeOffProof ||
		!reference.SafeOffObservedAt.Equal(transition.SafeOffObservedAt) {
		t.Fatalf("manual terminal attribution = %#v, %v", reference, err)
	}
	zeroTimestampReference := reference
	zeroTimestampReference.InitialPowerOffProof.AcknowledgedAt = time.Time{}
	if err := zeroTimestampReference.Validate(); err == nil {
		t.Fatal("manual reference accepted a zero acknowledgement timestamp")
	}

	tests := []struct {
		name   string
		mutate func(*BootTransition)
	}{
		{"missing initial proof", func(value *BootTransition) { value.InitialPowerOffProof = OperatorPowerProof{} }},
		{"missing final proof", func(value *BootTransition) { value.FinalSafeOffProof = OperatorPowerProof{} }},
		{"final proof before release", func(value *BootTransition) {
			value.FinalSafeOffProof.AcknowledgedAt = value.OperatorReleasedAt.Add(-time.Nanosecond)
		}},
		{"relay with manual proof", func(value *BootTransition) { value.PowerControlMode = PowerControlRelay }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := transition
			test.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid manual power evidence was accepted")
			}
		})
	}

	changedEvidence := evidence
	changedEvidence.FinalSafeOffProof.Operator.PID++
	changedDigest, err := changedEvidence.Digest()
	if err != nil || changedDigest == transition.EvidenceDigest {
		t.Fatalf("manual final safe-off proof was not evidence-bound: digest=%q err=%v", changedDigest, err)
	}
	falseEdgeTime := evidence
	falseEdgeTime.PowerEstablishedAt = falseEdgeTime.PowerEstablishedAt.Add(time.Nanosecond)
	if _, err := falseEdgeTime.Digest(); err == nil || !strings.Contains(err.Error(), "attestation time") {
		t.Fatalf("manual evidence with a fictional sensed power edge was accepted: %v", err)
	}

	quarantined, err := request.transition(2)
	if err != nil {
		t.Fatal(err)
	}
	quarantined.Status = BootTransitionQuarantined
	quarantined.Failure = BootTransitionFailureSafeOffUnproven
	quarantined.UpdatedAt = quarantined.UpdatedAt.Add(time.Second)
	if err := quarantined.Validate(); err != nil {
		t.Fatalf("manual quarantine without a false final proof rejected: %v", err)
	}
	quarantinedReference, err := quarantined.Reference()
	if err != nil || quarantinedReference.SafeOffBasis != SafeOffUnproven ||
		!quarantinedReference.SafeOffObservedAt.IsZero() {
		t.Fatalf("manual quarantine attribution = %#v, %v", quarantinedReference, err)
	}
}

func TestBootTransitionBeginAllocatesGenerationAndBlocksOpenPhase(t *testing.T) {
	store := NewMemoryStore()
	request := testBeginBootTransitionRequest(testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle))

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.BeginBootTransition(request)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded := 0
	blocked := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrBootTransitionOpen):
			blocked++
		default:
			t.Fatalf("unexpected concurrent begin error: %v", err)
		}
	}
	if succeeded != 1 || blocked != callers-1 {
		t.Fatalf("concurrent begins: succeeded=%d blocked=%d", succeeded, blocked)
	}

	incomplete, err := store.IncompleteBootTransitions()
	if err != nil || len(incomplete) != 1 || incomplete[0].Generation != 1 {
		t.Fatalf("incomplete generation 1 = %#v, %v", incomplete, err)
	}
	interrupted := incomplete[0]
	interrupted.Status = BootTransitionInterruptedSafeOff
	interrupted.Failure = BootTransitionFailureInterrupted
	interrupted.SafeOffObservedAt = interrupted.UpdatedAt.Add(time.Second)
	interrupted.UpdatedAt = interrupted.SafeOffObservedAt
	if err := store.PutBootTransition(interrupted); err != nil {
		t.Fatalf("terminalize interrupted transition: %v", err)
	}
	reference, err := interrupted.Reference()
	if err != nil || reference.Status != BootTransitionInterruptedSafeOff || reference.Failure != BootTransitionFailureInterrupted {
		t.Fatalf("interrupted reference = %#v, %v", reference, err)
	}
	outcome, err := interrupted.Outcome()
	if err != nil || outcome.Reference != reference || outcome.Evidence != (BootTransitionEvidence{}) {
		t.Fatalf("interrupted outcome = %#v, %v", outcome, err)
	}
	wrongModeOutcome := outcome
	wrongModeOutcome.Action.PowerControlMode = PowerControlManual
	if err := wrongModeOutcome.ValidateForAction(wrongModeOutcome.Action); err == nil || !strings.Contains(err.Error(), "authority-bound action") {
		t.Fatalf("failed outcome with a different power mode was accepted: %v", err)
	}

	secondRequest := request
	secondRequest.StartedAt = secondRequest.StartedAt.Add(time.Minute)
	secondRequest.RecordedAt = secondRequest.RecordedAt.Add(time.Minute)
	secondRequest.PowerOffObservedAt = secondRequest.PowerOffObservedAt.Add(time.Minute)
	secondRequest.USBAbsentObservedAt = secondRequest.USBAbsentObservedAt.Add(time.Minute)
	secondRequest.ColdIntervalEndsAt = secondRequest.ColdIntervalEndsAt.Add(time.Minute)
	secondRequest.PromptID = "hold_prompt_2"
	secondRequest.PromptDigest = digest("f")
	secondRequest.PromptExpiresAt = secondRequest.PromptExpiresAt.Add(time.Minute)
	second, err := store.BeginBootTransition(secondRequest)
	if err != nil || second.Generation != 2 {
		t.Fatalf("begin generation 2 = %#v, %v", second, err)
	}
}

func TestMergeBootTransitionProgressPreservesOnlyValidForwardLocalPrefix(t *testing.T) {
	store := NewMemoryStore()
	transition, err := store.BeginBootTransition(testBeginBootTransitionRequest(testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)))
	if err != nil {
		t.Fatal(err)
	}
	transition.Status = BootTransitionAwaitingOperator
	transition.UpdatedAt = transition.ColdIntervalEndsAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatal(err)
	}
	transition.Status = BootTransitionOperatorAcknowledged
	transition.Operator = OperatorPeer{UID: 1000, GID: 1000, PID: 2000}
	transition.OperatorAcknowledgedAt = transition.UpdatedAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorAcknowledgedAt
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatal(err)
	}

	local := transition
	local.Status = BootTransitionPowerEstablished
	local.PowerEstablishedAt = local.UpdatedAt.Add(time.Second)
	local.UpdatedAt = local.PowerEstablishedAt
	merged, err := MergeBootTransitionProgress(transition, local)
	if err != nil || merged != local {
		t.Fatalf("merged forward power prefix = %#v, %v", merged, err)
	}

	changed := local
	changed.Action.TargetFingerprint = "replacement-target"
	changed.Key = BootTransitionKey(changed.Action, changed.Generation)
	if _, err := MergeBootTransitionProgress(transition, changed); err == nil {
		t.Fatal("changed immutable action was accepted as local progress")
	}

	completed := local
	completed.Status = BootTransitionCompleted
	completed.SafeOffObservedAt = completed.UpdatedAt.Add(time.Second)
	completed.CompletedAt = completed.SafeOffObservedAt
	completed.UpdatedAt = completed.CompletedAt
	// Completion without a mode observation is invalid and must not be
	// projected into an apparently valid active prefix.
	if _, err := MergeBootTransitionProgress(transition, completed); err == nil {
		t.Fatal("invalid terminal local state was accepted as progress")
	}
}

func TestMemoryStoreReportsTerminalBootTransitionQuarantine(t *testing.T) {
	store := NewMemoryStore()
	quarantined, err := store.HasQuarantinedBootTransition()
	if err != nil || quarantined {
		t.Fatalf("empty quarantine state = %t, %v", quarantined, err)
	}
	transition, err := store.BeginBootTransition(testBeginBootTransitionRequest(testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)))
	if err != nil {
		t.Fatal(err)
	}
	transition.Status = BootTransitionQuarantined
	transition.Failure = BootTransitionFailureSafeOffUnproven
	transition.UpdatedAt = transition.UpdatedAt.Add(time.Second)
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("persist quarantine: %v", err)
	}
	quarantined, err = store.HasQuarantinedBootTransition()
	if err != nil || !quarantined {
		t.Fatalf("terminal quarantine state = %t, %v", quarantined, err)
	}
}

func TestFileStoreReportsBootTransitionQuarantineAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := store.BeginBootTransition(testBeginBootTransitionRequest(testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)))
	if err != nil {
		t.Fatal(err)
	}
	transition.Status = BootTransitionQuarantined
	transition.Failure = BootTransitionFailureSafeOffUnproven
	transition.UpdatedAt = transition.UpdatedAt.Add(time.Second)
	if err := store.PutBootTransition(transition); err != nil {
		t.Fatalf("persist quarantine: %v", err)
	}
	if quarantined, err := store.HasQuarantinedBootTransition(); err != nil || !quarantined {
		t.Fatalf("live file quarantine state = %t, %v", quarantined, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if quarantined, err := reopened.HasQuarantinedBootTransition(); err != nil || !quarantined {
		t.Fatalf("reopened file quarantine state = %t, %v", quarantined, err)
	}
}

func TestFileStoreOwnsStableProcessLockAndReopensAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("concurrent journal owner error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first owner: %v", err)
	}
	if _, _, err := first.Get("missing"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed journal read error = %v", err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen after lock release: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened journal: %v", err)
	}
}

func TestFileStorePersistsUnifiedJournalAndRejectsAmbiguousFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "journal.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	request := testBeginBootTransitionRequest(testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle))
	unbegun, err := request.transition(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutBootTransition(unbegun); !errors.Is(err, ErrBootTransitionNotBegun) {
		t.Fatalf("file-store put without begin error = %v", err)
	}
	transition, err := store.BeginBootTransition(request)
	if err != nil {
		t.Fatalf("persist requested transition: %v", err)
	}
	attemptAction := testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)
	attemptAction.TransactionID = "attempt-transaction"
	preObservation, err := recordFakeBootTransition(store, testConfig(), attemptAction, 100, false)
	if err != nil {
		t.Fatalf("persist attempt pre-observation: %v", err)
	}
	now := transition.StartedAt
	attempt := Attempt{
		SchemaVersion: AttemptSchemaVersion,
		Key:           fmt.Sprintf("%s/%s/%d/%d", attemptAction.TransactionID, attemptAction.PlanDigest, attemptAction.FenceEpoch, attemptAction.Sequence),
		TransactionID: attemptAction.TransactionID, PlanDigest: attemptAction.PlanDigest,
		TargetFingerprint: attemptAction.TargetFingerprint, FenceEpoch: attemptAction.FenceEpoch,
		ApprovalID: attemptAction.ApprovalID, IntentReceipt: attemptAction.IntentReceipt,
		IntentSequence: attemptAction.IntentSequence, Sequence: attemptAction.Sequence, Operation: attemptAction.Operation,
		OperationDigest: attemptAction.OperationDigest, Status: AttemptStarted, StartedAt: now, UpdatedAt: now,
		PreObservationTransition: preObservation,
	}
	if err := store.Put(attempt); err != nil {
		t.Fatalf("persist attempt beside transition: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual, ok, err := reopened.Get(attempt.Key); err != nil || !ok || actual != attempt {
		t.Fatalf("reopened attempt = %#v, %t, %v", actual, ok, err)
	}
	if actual, ok, err := reopened.GetBootTransition(transition.Key); err != nil || !ok || actual != transition {
		t.Fatalf("reopened transition = %#v, %t, %v", actual, ok, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	duplicatePath := filepath.Join(directory, "duplicate.json")
	duplicate := `{"schema_version":"` + AttemptStoreSchemaVersion + `","attempts":{},"attempts":{},"boot_transitions":{}}`
	if err := os.WriteFile(duplicatePath, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	duplicateStore, err := NewFileStore(duplicatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicateStore.Close()
	if _, _, err := duplicateStore.Get("missing"); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate journal error = %v", err)
	}

	target := filepath.Join(directory, "target.json")
	validEmpty := `{"schema_version":"` + AttemptStoreSchemaVersion + `","attempts":{},"boot_transitions":{}}`
	if err := os.WriteFile(target, []byte(validEmpty), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(target, symlinkPath); err != nil {
		t.Fatal(err)
	}
	symlinkStore, err := NewFileStore(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer symlinkStore.Close()
	if _, _, err := symlinkStore.Get("missing"); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink journal error = %v", err)
	}
}

func testHardwareAction(phase HardwarePhase, operation Operation) HardwareAction {
	required, _ := RequiredBootModeForOperation(operation)
	requested := required
	if phase != HardwarePhaseExecute {
		requested = BootModeRPIBoot
	}
	action := HardwareAction{
		SchemaVersion: BootTransitionActionSchemaVersion, StationID: "station", LaneID: "lane",
		PowerControlMode: PowerControlRelay,
		TransactionID:    "transaction", PlanDigest: digest("a"), TargetFingerprint: "target", FenceEpoch: 1,
		ApprovalID: "approval", IntentReceipt: "intent", IntentSequence: 1, Sequence: 1,
		Operation: operation, OperationDigest: digest("b"), AuthorizationID: "authorization",
		Phase: phase, OperationRequiredBootMode: required, RequestedBootMode: requested,
	}
	if phase == HardwarePhaseReconciliation {
		action.ReconciliationClaimID = "reconciliation-claim"
		action.ReconciliationFenceEpoch = 2
	}
	return action
}

func testBeginBootTransitionRequest(action HardwareAction) BeginBootTransitionRequest {
	started := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return BeginBootTransitionRequest{
		Action: action, PowerControlMode: PowerControlRelay,
		StartedAt: started, PowerOffObservedAt: started.Add(time.Second),
		USBAbsentObservedAt: started.Add(2 * time.Second), ColdIntervalEndsAt: started.Add(4 * time.Second),
		RecordedAt: started.Add(2 * time.Second), PromptID: "hold_prompt_1", PromptDigest: digest("c"),
		PromptExpiresAt: started.Add(2 * time.Minute),
	}
}

func testOperatorPowerProof(id string, acknowledgedAt, expiresAt time.Time) OperatorPowerProof {
	return OperatorPowerProof{
		PromptID: id, PromptDigest: digest("e"), PromptExpiresAt: expiresAt,
		Operator: OperatorPeer{UID: 1000, GID: 1000, PID: 2001}, AcknowledgedAt: acknowledgedAt,
	}
}
