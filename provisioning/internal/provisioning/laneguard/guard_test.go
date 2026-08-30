package laneguard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

type fakeClock struct{ now time.Time }

func (clock fakeClock) Now() time.Time { return clock.now }

type countingStore struct {
	Journal
	gets int
	puts int
}

func (store *countingStore) Get(string) (Attempt, bool, error) {
	store.gets++
	return Attempt{}, false, nil
}

func (store *countingStore) Put(Attempt) error {
	store.puts++
	return nil
}

type hookStore struct {
	Journal
	afterFirstGet func()
	once          sync.Once
}

func (store *hookStore) Get(key string) (Attempt, bool, error) {
	attempt, found, err := store.Journal.Get(key)
	store.once.Do(store.afterFirstGet)
	return attempt, found, err
}

type mutableClock struct{ now time.Time }

func (clock *mutableClock) Now() time.Time { return clock.now }

type recordingDispatchAuthority struct {
	executeCalls        int
	reconciliationCalls int
	execute             func(context.Context, Plan, ExecuteRequest) error
	reconciliation      func(context.Context, Plan, ReconcileRequest) error
}

func (authority *recordingDispatchAuthority) RecheckExecute(ctx context.Context, plan Plan, request ExecuteRequest) error {
	authority.executeCalls++
	if authority.execute != nil {
		return authority.execute(ctx, plan, request)
	}
	return nil
}

func (authority *recordingDispatchAuthority) RecheckReconciliation(ctx context.Context, plan Plan, request ReconcileRequest) error {
	authority.reconciliationCalls++
	if authority.reconciliation != nil {
		return authority.reconciliation(ctx, plan, request)
	}
	return nil
}

type fakeHardware struct {
	mu              sync.Mutex
	journal         Journal
	observation     Observation
	observeErr      error
	observeErrAt    map[int]error
	executeErr      error
	executeCount    int
	observeCount    int
	transitionCount int
	actions         []HardwareAction
	after           map[Operation]DirectState
	beforeObserve   func()
	beforeExecute   func(Operation)
	waitObserve     bool
	waitExecute     bool
	mutateOutcome   func(HardwareAction, *BootTransitionOutcome)
	replaceTarget   bool
}

func (hardware *fakeHardware) Observe(ctx context.Context, config Config, action HardwareAction) (Observation, error) {
	hardware.mu.Lock()
	hardware.observeCount++
	observeCount := hardware.observeCount
	hardware.transitionCount++
	ordinal := hardware.transitionCount
	hardware.actions = append(hardware.actions, action)
	if hardware.beforeObserve != nil {
		hardware.beforeObserve()
	}
	observation := hardware.observation
	hardwareErr := hardware.observeErr
	if scheduledErr, ok := hardware.observeErrAt[observeCount]; ok {
		hardwareErr = scheduledErr
	}
	mutate := hardware.mutateOutcome
	wait := hardware.waitObserve
	hardware.mu.Unlock()
	if wait {
		<-ctx.Done()
		return Observation{}, ctx.Err()
	}
	outcome, transitionErr := recordFakeBootTransition(hardware.journal, config, action, ordinal, hardwareErr != nil)
	if mutate != nil {
		mutate(action, &outcome)
	}
	observation.BootTransition = outcome
	return observation, errors.Join(hardwareErr, transitionErr)
}

func (hardware *fakeHardware) Execute(ctx context.Context, config Config, action HardwareAction) (OperationResult, error) {
	hardware.mu.Lock()
	hardware.executeCount++
	hardware.transitionCount++
	ordinal := hardware.transitionCount
	hardware.actions = append(hardware.actions, action)
	callback := hardware.beforeExecute
	if state, ok := hardware.after[action.Operation]; ok {
		hardware.observation.State = state
	}
	if hardware.replaceTarget {
		hardware.observation.TargetFingerprint = "replacement-target"
	}
	err := hardware.executeErr
	mutate := hardware.mutateOutcome
	wait := hardware.waitExecute
	hardware.mu.Unlock()
	if callback != nil {
		callback(action.Operation)
	}
	if wait {
		<-ctx.Done()
		return OperationResult{}, ctx.Err()
	}
	outcome, transitionErr := recordFakeBootTransition(hardware.journal, config, action, ordinal, err != nil)
	if mutate != nil {
		mutate(action, &outcome)
	}
	result := OperationResult{OutputDigest: digest("f"), Detail: "fake result", BootTransition: outcome}
	if action.Operation == OperationProgramCustomerKeyAndEEPROM && err == nil && transitionErr == nil {
		result.CommitAttestation = CommitAttestation{
			SchemaVersion: CommitAttestationSchemaVersion, TargetFingerprint: action.TargetFingerprint,
			CustomerKeyHash: digest("4"), EEPROMHash: digest("5"),
			EEPROMUpdateResult: "success", SecureBootProvisionResult: "success",
		}
	}
	return result, errors.Join(err, transitionErr)
}

func recordFakeBootTransition(journal Journal, config Config, action HardwareAction, ordinal int, failed bool) (BootTransitionOutcome, error) {
	if journal == nil {
		return BootTransitionOutcome{}, errors.New("fake hardware has no shared journal")
	}
	started := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Add(time.Duration(ordinal) * time.Minute)
	request := BeginBootTransitionRequest{
		Action: action, PowerControlMode: PowerControlRelay,
		StartedAt: started, RecordedAt: started.Add(2 * time.Second),
		PowerOffObservedAt: started.Add(time.Second), USBAbsentObservedAt: started.Add(2 * time.Second),
		ColdIntervalEndsAt: started.Add(4 * time.Second), PromptID: "hold_prompt",
		PromptDigest: digest("a"), PromptExpiresAt: started.Add(2 * time.Minute),
	}
	transition, err := journal.BeginBootTransition(request)
	if err != nil {
		return BootTransitionOutcome{}, err
	}
	if failed {
		transition.Status = BootTransitionAbortedSafeOff
		transition.Failure = BootTransitionFailureHardware
		transition.SafeOffObservedAt = started.Add(3 * time.Second)
		transition.UpdatedAt = transition.SafeOffObservedAt
		if err := journal.PutBootTransition(transition); err != nil {
			return BootTransitionOutcome{}, err
		}
		return transition.Outcome()
	}
	transition.Status = BootTransitionAwaitingOperator
	transition.UpdatedAt = transition.ColdIntervalEndsAt
	if err := journal.PutBootTransition(transition); err != nil {
		return BootTransitionOutcome{}, err
	}
	transition.Status = BootTransitionOperatorAcknowledged
	transition.Operator = OperatorPeer{UID: 1000, GID: 1000, PID: int32(2000 + ordinal)}
	transition.OperatorAcknowledgedAt = transition.ColdIntervalEndsAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorAcknowledgedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return BootTransitionOutcome{}, err
	}
	transition.Status = BootTransitionPowerEstablished
	transition.PowerEstablishedAt = transition.OperatorAcknowledgedAt.Add(time.Second)
	transition.UpdatedAt = transition.PowerEstablishedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return BootTransitionOutcome{}, err
	}
	transition.Status = BootTransitionModeObserved
	transition.ModeObservedAt = transition.PowerEstablishedAt.Add(time.Second)
	transition.ObservedMode = action.RequestedBootMode
	transition.RPIBootSysfsPath = config.RPIBootSysfsPath
	transition.RPIBootObservationMethod = RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = 50 * time.Millisecond
	if action.RequestedBootMode == BootModeRPIBoot {
		transition.RPIBootEligibleTargets = 1
		transition.ReleasePromptID = "release_prompt"
		transition.ReleasePromptDigest = digest("b")
		transition.ReleasePromptExpiresAt = transition.ModeObservedAt.Add(time.Minute)
	} else {
		transition.UARTPath = config.UARTPath
		transition.UARTOutputDigest = digest("c")
		transition.RPIBootNotObservedThrough = transition.ModeObservedAt
	}
	transition.UpdatedAt = transition.ModeObservedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return BootTransitionOutcome{}, err
	}
	if action.RequestedBootMode == BootModeRPIBoot {
		transition.Status = BootTransitionOperatorReleased
		transition.ReleaseOperator = transition.Operator
		transition.OperatorReleasedAt = transition.ModeObservedAt.Add(time.Second)
		transition.UpdatedAt = transition.OperatorReleasedAt
		if err := journal.PutBootTransition(transition); err != nil {
			return BootTransitionOutcome{}, err
		}
	}
	transition.Status = BootTransitionCompleted
	transition.SafeOffObservedAt = transition.ModeObservedAt.Add(2 * time.Second)
	if !transition.OperatorReleasedAt.IsZero() {
		transition.SafeOffObservedAt = transition.OperatorReleasedAt.Add(time.Second)
	}
	transition.CompletedAt = transition.SafeOffObservedAt
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		return BootTransitionOutcome{}, err
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		return BootTransitionOutcome{}, err
	}
	if err := journal.PutBootTransition(transition); err != nil {
		return BootTransitionOutcome{}, err
	}
	return transition.Outcome()
}

func TestGuardExecutesApprovedOperationsOnceAndInOrder(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	attempt, err := guard.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("execute commit: %v", err)
	}
	if attempt.Status != AttemptVerified || attempt.ObservedState != plan.Operations[0].ExpectedPoststate {
		t.Fatalf("commit attempt = %#v", attempt)
	}
	if !strings.HasPrefix(attempt.Result.BindingDigest, "sha256:") || len(attempt.Result.BindingDigest) != 71 {
		t.Fatalf("transaction-bound result = %#v", attempt.Result)
	}
	if attempt.PreObservationTransition == (BootTransitionOutcome{}) ||
		attempt.ExecutionTransition == (BootTransitionOutcome{}) ||
		attempt.PostObservationTransition == (BootTransitionOutcome{}) ||
		attempt.Result.BootTransition != attempt.ExecutionTransition {
		t.Fatalf("attempt did not persist all execution-path transitions: %#v", attempt)
	}
	for index, phase := range []HardwarePhase{HardwarePhasePreObservation, HardwarePhaseExecute, HardwarePhasePostObservation} {
		expected, actionErr := makeHardwareAction(plan, plan.Operations[0], phase, nil)
		if actionErr != nil || len(hardware.actions) <= index || hardware.actions[index] != expected {
			t.Fatalf("hardware action %d = %#v, want %#v (derive error %v)", index, hardware.actions, expected, actionErr)
		}
	}
	changedEvidence := attempt.Result
	changedEvidence.BindingDigest = ""
	changedEvidence.BootTransition.Reference.EvidenceDigest = digest("0")
	if rebound := bindOperationResult(plan, plan.Operations[0], changedEvidence); rebound.BindingDigest == attempt.Result.BindingDigest {
		t.Fatal("operation binding digest did not bind execution transition evidence")
	}
	if hardware.executeCount != 1 {
		t.Fatalf("hardware executions = %d, want 1", hardware.executeCount)
	}

	// An identical delivery is idempotent and returns the durable result. It
	// never invokes hardware a second time.
	replayed, err := guard.Execute(context.Background(), request)
	if err != nil || replayed.Status != AttemptVerified {
		t.Fatalf("replay = %#v, %v", replayed, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("hardware executions after replay = %d, want 1", hardware.executeCount)
	}

	secondGuard, secondPlan := loadTestIntent(t, testConfig(), hardware, store, plan, 2, now)
	second := requestFor(secondPlan, 2, now.Add(10*time.Minute))
	if _, err := secondGuard.Execute(context.Background(), second); err != nil {
		t.Fatalf("execute ordered second operation: %v", err)
	}
	if hardware.executeCount != 2 {
		t.Fatalf("hardware executions = %d, want 2", hardware.executeCount)
	}
}

func TestOperationResultBindingChangesWithApprovedTransaction(t *testing.T) {
	plan := testPlan()
	result := OperationResult{OutputDigest: digest("f"), Detail: "same device evidence"}
	first := bindOperationResult(plan, plan.Operations[0], result)
	plan.TransactionID = "transaction-2"
	plan = deriveTestPlan(plan)
	second := bindOperationResult(plan, plan.Operations[0], result)
	if first.OutputDigest != second.OutputDigest || first.BindingDigest == second.BindingDigest {
		t.Fatalf("bindings do not isolate transactions: first=%#v second=%#v", first, second)
	}
}

func TestGuardRecordsIntentBeforeCallingHardware(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.beforeExecute = func(Operation) {
		record, ok, err := store.Get(attemptKey(plan, 1))
		if err != nil || !ok || record.Status != AttemptStarted {
			t.Errorf("journal at hardware boundary = %#v, %t, %v", record, ok, err)
		}
	}
	if _, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute))); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestDispatchAuthorityDenialAfterPreObservationLeavesNoStartedAttempt(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	hardware := &fakeHardware{
		journal: store,
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		after: map[Operation]DirectState{plan.Operations[0].Operation: plan.Operations[0].ExpectedPoststate},
	}
	denied := errors.New("server dispatch authority expired")
	authority := &recordingDispatchAuthority{}
	authority.execute = func(_ context.Context, gotPlan Plan, gotRequest ExecuteRequest) error {
		if !samePlan(gotPlan, plan) || gotRequest != requestFor(plan, 1, now.Add(10*time.Minute)) {
			t.Fatalf("dispatch authority input = %#v / %#v", gotPlan, gotRequest)
		}
		if hardware.observeCount != 1 || hardware.executeCount != 0 {
			t.Fatalf("dispatch recheck order = observations:%d executions:%d", hardware.observeCount, hardware.executeCount)
		}
		if attempt, found, err := store.Get(attemptKey(plan, 1)); err != nil || found || attempt != (Attempt{}) {
			t.Fatalf("attempt existed before dispatch authority: %#v, %t, %v", attempt, found, err)
		}
		return denied
	}
	guard, err := NewWithClockAndDispatchAuthority(config, hardware, store, fakeClock{now}, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, denied) {
		t.Fatalf("dispatch denial error = %v", err)
	}
	if authority.executeCalls != 1 || authority.reconciliationCalls != 0 || hardware.executeCount != 0 {
		t.Fatalf("denied dispatch calls = authority:%d/%d hardware:%d", authority.executeCalls, authority.reconciliationCalls, hardware.executeCount)
	}
	if attempt, found, err := store.Get(attemptKey(plan, 1)); err != nil || found || attempt != (Attempt{}) {
		t.Fatalf("denied dispatch persisted AttemptStarted: %#v, %t, %v", attempt, found, err)
	}
}

func TestReconciliationDispatchAuthorityDenialPreventsTargetObservation(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("execution response lost")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	uncertain, err := guard.Execute(context.Background(), request)
	if !errors.Is(err, ErrReconciliationRequired) || uncertain.Status != AttemptUncertain {
		t.Fatalf("uncertain execution = %#v, %v", uncertain, err)
	}

	restartedHardware := &fakeHardware{
		journal: store,
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPoststate,
		},
	}
	denied := errors.New("server reconciliation authority expired")
	authority := &recordingDispatchAuthority{}
	authority.reconciliation = func(_ context.Context, gotPlan Plan, gotRequest ReconcileRequest) error {
		if !samePlan(gotPlan, plan) || gotRequest != reconcileRequest(plan, request, now.Add(10*time.Minute)) {
			t.Fatalf("reconciliation dispatch authority input = %#v / %#v", gotPlan, gotRequest)
		}
		if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
			t.Fatalf("reconciliation reached hardware before authority: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
		}
		persisted, found, getErr := store.Get(attemptKey(plan, 1))
		if getErr != nil || !found || persisted != uncertain {
			t.Fatalf("journal changed before reconciliation authority: %#v, %t, %v", persisted, found, getErr)
		}
		return denied
	}
	restarted, err := NewWithClockAndDispatchAuthority(testConfig(), restartedHardware, store, fakeClock{now}, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute))); !errors.Is(err, denied) {
		t.Fatalf("reconciliation dispatch denial error = %v", err)
	}
	if authority.reconciliationCalls != 1 || authority.executeCalls != 0 || restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
		t.Fatalf("denied reconciliation calls = authority:%d/%d hardware:%d/%d", authority.executeCalls, authority.reconciliationCalls, restartedHardware.observeCount, restartedHardware.executeCount)
	}
	persisted, found, err := store.Get(attemptKey(plan, 1))
	if err != nil || !found || persisted != uncertain {
		t.Fatalf("reconciliation denial changed the attempt: %#v, %t, %v", persisted, found, err)
	}
}

func TestDurableTerminalReplaySkipsDispatchAuthority(t *testing.T) {
	guard, _, store, plan, now := newTestGuard(t)
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	verified, err := guard.Execute(context.Background(), request)
	if err != nil || verified.Status != AttemptVerified {
		t.Fatalf("initial execution = %#v, %v", verified, err)
	}
	restartedHardware := &fakeHardware{journal: store}
	authority := &recordingDispatchAuthority{
		execute: func(context.Context, Plan, ExecuteRequest) error {
			t.Fatal("terminal execute replay reached dispatch authority")
			return nil
		},
		reconciliation: func(context.Context, Plan, ReconcileRequest) error {
			t.Fatal("terminal reconciliation replay reached dispatch authority")
			return nil
		},
	}
	restarted, err := NewWithClockAndDispatchAuthority(testConfig(), restartedHardware, store, fakeClock{now}, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if replayed, err := restarted.Execute(context.Background(), request); err != nil || replayed != verified {
		t.Fatalf("terminal execute replay = %#v, %v", replayed, err)
	}
	if replayed, err := restarted.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute))); err != nil || replayed != verified {
		t.Fatalf("terminal reconciliation replay = %#v, %v", replayed, err)
	}
	if authority.executeCalls != 0 || authority.reconciliationCalls != 0 || restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
		t.Fatalf("terminal replay calls = authority:%d/%d hardware:%d/%d", authority.executeCalls, authority.reconciliationCalls, restartedHardware.observeCount, restartedHardware.executeCount)
	}
}

func TestGuardNeverRepeatsUncertainIrreversibleOperation(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("USB response lost")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	attempt, err := guard.Execute(context.Background(), request)
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain {
		t.Fatalf("uncertain execute = %#v, %v", attempt, err)
	}
	if attempt.ExecutionTransition.Reference.Status != BootTransitionAbortedSafeOff ||
		attempt.ExecutionTransition.Reference.Failure != BootTransitionFailureHardware {
		t.Fatalf("hardware error transition was not preserved: %#v", attempt.ExecutionTransition)
	}
	if transition, found, getErr := store.GetBootTransition(attempt.ExecutionTransition.Reference.TransitionKey); getErr != nil || !found {
		t.Fatalf("hardware error transition is not durable: %#v, %t, %v", transition, found, getErr)
	}
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("second execute error = %v", err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("uncertain operation executed %d times", hardware.executeCount)
	}

	// The fake changed to the approved EEPROM and key before losing its response,
	// but those bytes cannot recreate the commit response's success fields.
	hardware.executeErr = nil
	hardware.observation.State.EEPROMHashStatus = EEPROMHashObserved
	reconciled, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || reconciled.Status != AttemptUncertain ||
		reconciled.Result.CommitAttestation != (CommitAttestation{}) {
		t.Fatalf("reconcile = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("reconciliation executed hardware; count = %d", hardware.executeCount)
	}
}

func TestGuardPersistsFailedReconciliationTransition(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("execution response lost")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("create uncertain attempt: %v", err)
	}
	hardware.executeErr = nil
	hardware.observeErr = errors.New("reconciliation observation failed")
	attempt, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain {
		t.Fatalf("failed reconciliation = %#v, %v", attempt, err)
	}
	if attempt.ReconciliationTransition.Reference.Status != BootTransitionAbortedSafeOff ||
		attempt.ReconciliationTransition.Reference.Failure != BootTransitionFailureHardware {
		t.Fatalf("failed reconciliation transition was not preserved: %#v", attempt.ReconciliationTransition)
	}
	persisted, found, getErr := store.Get(attempt.Key)
	if getErr != nil || !found || persisted.ReconciliationTransition != attempt.ReconciliationTransition {
		t.Fatalf("persisted reconciliation failure = %#v, %t, %v", persisted, found, getErr)
	}
}

func TestGuardRejectsTamperedBootTransitionOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		phase  HardwarePhase
		mutate func(*BootTransitionOutcome)
	}{
		{"phase", HardwarePhasePreObservation, func(outcome *BootTransitionOutcome) {
			outcome.Action.Phase = HardwarePhaseExecute
		}},
		{"mode", HardwarePhaseExecute, func(outcome *BootTransitionOutcome) {
			outcome.Action.RequestedBootMode = BootModeNormal
		}},
		{"action", HardwarePhasePostObservation, func(outcome *BootTransitionOutcome) {
			outcome.Action.AuthorizationID = "other-authorization"
		}},
		{"evidence", HardwarePhaseReconciliation, func(outcome *BootTransitionOutcome) {
			outcome.Evidence.ReleasePromptDigest = digest("9")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, hardware, store, plan, now := newTestGuard(t)
			hardware.mutateOutcome = func(action HardwareAction, outcome *BootTransitionOutcome) {
				if action.Phase == test.phase {
					test.mutate(outcome)
				}
			}
			request := requestFor(plan, 1, now.Add(10*time.Minute))
			var attempt Attempt
			var err error
			if test.phase == HardwarePhaseReconciliation {
				hardware.executeErr = errors.New("execution response lost")
				if _, executeErr := guard.Execute(context.Background(), request); !errors.Is(executeErr, ErrReconciliationRequired) {
					t.Fatalf("create uncertain attempt: %v", executeErr)
				}
				hardware.executeErr = nil
				attempt, err = guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
			} else {
				attempt, err = guard.Execute(context.Background(), request)
			}
			if !errors.Is(err, ErrBootTransitionOutcome) {
				t.Fatalf("tampered %s outcome error = %v", test.phase, err)
			}
			persisted, found, getErr := store.Get(attemptKey(plan, 1))
			if getErr != nil {
				t.Fatal(getErr)
			}
			if test.phase == HardwarePhasePreObservation {
				if found || attempt != (Attempt{}) {
					t.Fatalf("tampered pre-observation created an attempt: %#v, found=%t", attempt, found)
				}
				return
			}
			if !found || persisted.Status != AttemptUncertain {
				t.Fatalf("tampered outcome did not fail closed: %#v, found=%t", persisted, found)
			}
			switch test.phase {
			case HardwarePhaseExecute:
				if persisted.ExecutionTransition != (BootTransitionOutcome{}) {
					t.Fatal("fabricated execution outcome was persisted")
				}
			case HardwarePhasePostObservation:
				if persisted.PostObservationTransition != (BootTransitionOutcome{}) {
					t.Fatal("fabricated post-observation outcome was persisted")
				}
			case HardwarePhaseReconciliation:
				if persisted.ReconciliationTransition != (BootTransitionOutcome{}) {
					t.Fatal("fabricated reconciliation outcome was persisted")
				}
			}
		})
	}
}

func TestGuardRejectsOutcomeMissingFromItsJournal(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.journal = NewMemoryStore()
	attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrBootTransitionOutcome) || attempt != (Attempt{}) {
		t.Fatalf("non-durable outcome = %#v, %v", attempt, err)
	}
	if _, found, getErr := store.Get(attemptKey(plan, 1)); getErr != nil || found {
		t.Fatalf("non-durable pre-observation created attempt: found=%t err=%v", found, getErr)
	}
}

func TestReconcileConfirmsExactOriginalPrestateWithoutRedispatch(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.after[plan.Operations[0].Operation] = plan.Operations[0].ExpectedPrestate
	hardware.executeErr = errors.New("response lost before target commit")
	original := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("uncertain execute = %v", err)
	}
	reconcile := reconcileRequest(plan, original, now.Add(10*time.Minute))
	attempt, err := guard.Reconcile(context.Background(), reconcile)
	if err != nil || attempt.Status != AttemptConfirmedNotApplied || attempt.ObservedState != plan.Operations[0].ExpectedPrestate {
		t.Fatalf("confirmed-not-applied reconciliation = %#v, %v", attempt, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("reconciliation redispatched hardware %d times", hardware.executeCount)
	}
	persisted, found, err := store.Get(attempt.Key)
	if err != nil || !found || persisted != attempt {
		t.Fatalf("persisted confirmed-not-applied attempt = %#v, %t, %v", persisted, found, err)
	}
	if replayed, err := guard.Reconcile(context.Background(), reconcile); err != nil || replayed != attempt {
		t.Fatalf("idempotent reconciliation = %#v, %v", replayed, err)
	}
	if replayed, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrConfirmedNotApplied) || replayed != attempt {
		t.Fatalf("old execute request after confirmed no-op = %#v, %v", replayed, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("old execute request redispatched hardware %d times", hardware.executeCount)
	}
}

func TestReconcileKeepsUnavailableInitialEEPROMPrestateUncertain(t *testing.T) {
	config := testConfig()
	planBody := testPlanBody()
	planBody.Operations[0].ExpectedPrestate.EEPROMHash = ""
	planBody.Operations[0].ExpectedPrestate.EEPROMHashStatus = EEPROMHashUnavailable
	plan := deriveTestPlan(planBody)
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	hardware := &fakeHardware{
		journal: store,
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		after:      map[Operation]DirectState{plan.Operations[0].Operation: plan.Operations[0].ExpectedPrestate},
		executeErr: errors.New("response lost after EEPROM might have changed"),
	}
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	original := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("uncertain execute = %v", err)
	}
	attempt, err := guard.Reconcile(context.Background(), reconcileRequest(plan, original, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain || attempt.ObservedState != plan.Operations[0].ExpectedPrestate {
		t.Fatalf("unavailable-prestate reconciliation = %#v, %v", attempt, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("reconciliation redispatched hardware %d times", hardware.executeCount)
	}
	persisted, found, getErr := store.Get(attempt.Key)
	if getErr != nil || !found || persisted != attempt {
		t.Fatalf("persisted unavailable-prestate attempt = %#v, %t, %v", persisted, found, getErr)
	}
}

func TestCommitAttestationResolvesUnavailableReadbackAcrossOperationRestart(t *testing.T) {
	config := testConfig()
	planBody := testPlanBody()
	planBody.Operations[0].ExpectedPrestate.EEPROMHash = ""
	planBody.Operations[0].ExpectedPrestate.EEPROMHashStatus = EEPROMHashUnavailable
	plan := deriveTestPlan(planBody)
	ownedUnavailable := plan.Operations[0].ExpectedPoststate
	ownedUnavailable.EEPROMHash = ""
	ownedUnavailable.EEPROMHashStatus = EEPROMHashUnavailable
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	hardware := &fakeHardware{
		journal: store,
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		after: map[Operation]DirectState{
			OperationProgramCustomerKeyAndEEPROM: ownedUnavailable,
			OperationColdPowerCycle:              ownedUnavailable,
		},
	}
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	commit, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
	if err != nil || commit.Status != AttemptVerified || commit.ObservedState != plan.Operations[0].ExpectedPoststate ||
		commit.Result.CommitAttestation != expectedCommitAttestation(plan) {
		t.Fatalf("commit-attested operation 1 = %#v, %v", commit, err)
	}

	restarted, nextPlan := loadTestIntent(t, config, hardware, store, plan, 2, now)
	coldBoot, err := restarted.Execute(context.Background(), requestFor(nextPlan, 2, now.Add(10*time.Minute)))
	if err != nil || coldBoot.Status != AttemptVerified || coldBoot.ObservedState != nextPlan.Operations[1].ExpectedPoststate {
		t.Fatalf("restart operation 2 = %#v, %v", coldBoot, err)
	}
	if hardware.executeCount != 2 {
		t.Fatalf("hardware executions = %d, want one commit and one cold boot", hardware.executeCount)
	}
}

func TestResolveEEPROMProofNeverTrustsRawCommitAttestedStatus(t *testing.T) {
	plan := testPlan()
	expected := plan.Operations[0].ExpectedPoststate
	if resolved, matches, inconclusive := resolveEEPROMProof(expected, expected, CommitAttestation{}); matches || !inconclusive || resolved != expected {
		t.Fatalf("unattested raw commit claim = %#v, matches=%t inconclusive=%t", resolved, matches, inconclusive)
	}
	if resolved, matches, inconclusive := resolveEEPROMProof(expected, expected, expectedCommitAttestation(plan)); !matches || inconclusive || resolved != expected {
		t.Fatalf("exact attested commit claim = %#v, matches=%t inconclusive=%t", resolved, matches, inconclusive)
	}
	observed := expected
	observed.EEPROMHashStatus = EEPROMHashObserved
	if resolved, matches, inconclusive := resolveEEPROMProof(expected, observed, CommitAttestation{}); matches || !inconclusive || resolved != observed {
		t.Fatalf("unattested exact EEPROM observation = %#v, matches=%t inconclusive=%t", resolved, matches, inconclusive)
	}
	if resolved, matches, inconclusive := resolveEEPROMProof(expected, observed, expectedCommitAttestation(plan)); !matches || inconclusive || resolved != expected {
		t.Fatalf("attested exact EEPROM observation = %#v, matches=%t inconclusive=%t", resolved, matches, inconclusive)
	}
}

func TestOperationThreeReconciliationPrefersObservedPoststateOverAttestedPrestate(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	commit, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
	if err != nil || commit.Status != AttemptVerified || commit.Result.CommitAttestation.IsZero() {
		t.Fatalf("operation 1 = %#v, %v", commit, err)
	}

	guard, plan = loadTestIntent(t, testConfig(), hardware, store, plan, 2, now)
	coldBoot, err := guard.Execute(context.Background(), requestFor(plan, 2, now.Add(10*time.Minute)))
	if err != nil || coldBoot.Status != AttemptVerified {
		t.Fatalf("operation 2 = %#v, %v", coldBoot, err)
	}

	hardware.after[OperationOwnedReadback] = plan.Operations[2].ExpectedPoststate
	guard, plan = loadTestIntent(t, testConfig(), hardware, store, plan, 3, now)
	hardware.executeErr = errors.New("owned-readback response lost after observation")
	request := requestFor(plan, 3, now.Add(10*time.Minute))
	uncertain, err := guard.Execute(context.Background(), request)
	if !errors.Is(err, ErrReconciliationRequired) || uncertain.Status != AttemptUncertain {
		t.Fatalf("uncertain operation 3 = %#v, %v", uncertain, err)
	}

	hardware.executeErr = nil
	reconciled, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if err != nil || reconciled.Status != AttemptVerified || reconciled.ObservedState != plan.Operations[2].ExpectedPoststate {
		t.Fatalf("reconciled operation 3 = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 3 {
		t.Fatalf("operation 3 reconciliation redispatched hardware; executions=%d", hardware.executeCount)
	}
}

func TestOwnedUnavailableReconciliationWithoutCommitAttestationNeverRedispatches(t *testing.T) {
	config := testConfig()
	planBody := testPlanBody()
	planBody.Operations[0].ExpectedPrestate.EEPROMHash = ""
	planBody.Operations[0].ExpectedPrestate.EEPROMHashStatus = EEPROMHashUnavailable
	plan := deriveTestPlan(planBody)
	ownedUnavailable := plan.Operations[0].ExpectedPoststate
	ownedUnavailable.EEPROMHash = ""
	ownedUnavailable.EEPROMHashStatus = EEPROMHashUnavailable
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	hardware := &fakeHardware{
		journal: store,
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		after:      map[Operation]DirectState{OperationProgramCustomerKeyAndEEPROM: ownedUnavailable},
		executeErr: errors.New("fresh-commit response was lost"),
	}
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("ambiguous commit = %v", err)
	}
	attempt, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain ||
		attempt.Result.CommitAttestation != (CommitAttestation{}) || attempt.ObservedState != ownedUnavailable {
		t.Fatalf("owned unavailable reconciliation = %#v, %v", attempt, err)
	}
	if replay, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) || replay != attempt {
		t.Fatalf("ambiguous execute replay = %#v, %v", replay, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("ambiguous commit was redispatched %d times", hardware.executeCount)
	}
}

func TestGuardRejectsExpiredApprovalBeforeObservationHardwareOrJournal(t *testing.T) {
	guard, hardware, _, plan, _ := newTestGuard(t)
	journal := &countingStore{}
	guard.store = journal
	guard.clock = fakeClock{now: plan.ApprovalExpiresAt}
	observationsBefore := hardware.observeCount

	request := requestFor(plan, 1, plan.ApprovalExpiresAt.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expired execute error = %v, want approval expired", err)
	}
	if hardware.observeCount != observationsBefore || hardware.executeCount != 0 {
		t.Fatalf("expired approval reached hardware: observations %d -> %d, executions %d", observationsBefore, hardware.observeCount, hardware.executeCount)
	}
	if journal.gets != 0 || journal.puts != 0 {
		t.Fatalf("expired approval reached journal: gets=%d puts=%d", journal.gets, journal.puts)
	}
}

func TestGuardAllowsReconciliationAfterApprovalExpiry(t *testing.T) {
	guard, hardware, _, plan, now := newTestGuard(t)
	hardware.observeErrAt = map[int]error{2: errors.New("post-commit observation lost")}
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("uncertain execute error = %v", err)
	}
	hardware.observation.State.EEPROMHashStatus = EEPROMHashObserved

	guard.clock = fakeClock{now: plan.ApprovalExpiresAt.Add(time.Second)}
	reconciled, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, plan.ApprovalExpiresAt.Add(10*time.Minute)))
	if err != nil || reconciled.Status != AttemptVerified {
		t.Fatalf("expired reconciliation = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("expired reconciliation executed hardware; count = %d", hardware.executeCount)
	}
}

func TestReconcileNeverConfirmsFreshCommitNotAppliedAfterAttestedResponse(t *testing.T) {
	guard, hardware, _, plan, now := newTestGuard(t)
	hardware.observeErrAt = map[int]error{2: errors.New("post-commit observation lost")}
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	uncertain, err := guard.Execute(context.Background(), request)
	if !errors.Is(err, ErrReconciliationRequired) || uncertain.Status != AttemptUncertain || uncertain.Result.CommitAttestation.IsZero() {
		t.Fatalf("attested uncertain execute = %#v, %v", uncertain, err)
	}

	hardware.observation.State = plan.Operations[0].ExpectedPrestate
	reconciled, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || reconciled.Status != AttemptUncertain ||
		reconciled.Result.CommitAttestation != uncertain.Result.CommitAttestation {
		t.Fatalf("conflicting prestate reconciliation = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("conflicting reconciliation redispatched hardware; count = %d", hardware.executeCount)
	}
}

func TestRestartLoadsUncertainAttemptForObservationOnly(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.observeErrAt = map[int]error{2: errors.New("post-commit observation lost")}
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("first execute = %v", err)
	}

	observedPoststate := plan.Operations[0].ExpectedPoststate
	observedPoststate.EEPROMHashStatus = EEPROMHashObserved
	restartedHardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: observedPoststate,
	}}
	restartedHardware.journal = store
	restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadPlan(context.Background(), plan); err != nil {
		t.Fatalf("reload uncertain plan: %v", err)
	}
	if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
		t.Fatalf("LoadPlan reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
	}
	if _, err := restarted.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("restart execute error = %v", err)
	}
	if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
		t.Fatalf("restart execute replay reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
	}
	attempt, err := restarted.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if err != nil || attempt.Status != AttemptVerified {
		t.Fatalf("restart reconcile = %#v, %v", attempt, err)
	}
	if restartedHardware.observeCount != 1 || restartedHardware.executeCount != 0 {
		t.Fatalf("restart reconciliation calls: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
	}
}

func TestReconcileRequiresFreshBoundClaimBeforeObservation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ReconcileRequest, Plan, time.Time)
		want   error
	}{
		{"previous schema", func(request *ReconcileRequest, _ Plan, _ time.Time) {
			request.SchemaVersion = "provisioning.kaiba.network/lane-guard-reconcile-request/v1alpha1"
		}, ErrReconciliationAuthority},
		{"unknown schema", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.SchemaVersion = "other" }, ErrReconciliationAuthority},
		{"station", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.Claim.StationID = "other-station" }, ErrReconciliationAuthority},
		{"lane", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.Claim.LaneID = "other-lane" }, ErrReconciliationAuthority},
		{"transaction", func(request *ReconcileRequest, _ Plan, _ time.Time) {
			request.Claim.TransactionID = "other-transaction"
		}, ErrReconciliationAuthority},
		{"target", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.Claim.TargetFingerprint = "other-target" }, ErrReconciliationAuthority},
		{"claim", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.Claim.ClaimID = "" }, ErrReconciliationAuthority},
		{"stale fence", func(request *ReconcileRequest, plan Plan, _ time.Time) { request.Claim.FenceEpoch = plan.FenceEpoch }, ErrReconciliationAuthority},
		{"missing expiry", func(request *ReconcileRequest, _ Plan, _ time.Time) { request.Claim.ExpiresAt = time.Time{} }, ErrReconciliationAuthority},
		{"short lease", func(request *ReconcileRequest, _ Plan, now time.Time) {
			request.Claim.ExpiresAt = now.Add(ReconciliationObservationBudget + testConfig().LeaseSafetyMargin - time.Nanosecond)
		}, ErrLeaseInvalid},
		{"changed original intent", func(request *ReconcileRequest, _ Plan, _ time.Time) {
			request.OriginalRequest.IntentReceipt = "other-intent"
		}, ErrPlanMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, hardware, store, plan, now := newTestGuard(t)
			hardware.executeErr = errors.New("response lost")
			original := requestFor(plan, 1, now.Add(10*time.Minute))
			if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationRequired) {
				t.Fatal(err)
			}
			key := attemptKey(plan, 1)
			before, ok, err := store.Get(key)
			if err != nil || !ok {
				t.Fatalf("stored attempt = %#v, %t, %v", before, ok, err)
			}
			observations := hardware.observeCount
			request := reconcileRequest(plan, original, now.Add(10*time.Minute))
			test.change(&request, plan, now)
			if _, err := guard.Reconcile(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("Reconcile() error = %v, want %v", err, test.want)
			}
			if hardware.observeCount != observations || hardware.executeCount != 1 {
				t.Fatalf("invalid claim reached hardware: observations %d -> %d; executions %d", observations, hardware.observeCount, hardware.executeCount)
			}
			after, ok, err := store.Get(key)
			if err != nil || !ok || after != before {
				t.Fatalf("invalid claim changed attempt: before=%#v after=%#v found=%t err=%v", before, after, ok, err)
			}
		})
	}
}

func TestRestartReconcilesOriginalPlanAfterClaimTransfersLanes(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.observeErrAt = map[int]error{2: errors.New("post-commit observation lost")}
	original := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatal(err)
	}

	currentConfig := testConfig()
	currentConfig.StationID = "station-2"
	currentConfig.LaneID = "lane-2"
	observedPoststate := plan.Operations[0].ExpectedPoststate
	observedPoststate.EEPROMHashStatus = EEPROMHashObserved
	restartedHardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: currentConfig.RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: observedPoststate,
	}}
	restartedHardware.journal = store
	restarted, err := NewWithClock(currentConfig, restartedHardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadPlan(context.Background(), plan); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("execution load after transfer = %v, want plan mismatch", err)
	}
	reconcile := reconcileRequest(plan, original, now.Add(10*time.Minute))
	reconcile.Claim.StationID = currentConfig.StationID
	reconcile.Claim.LaneID = currentConfig.LaneID
	if err := ValidateReconcileRequest(currentConfig, plan, reconcile); err != nil {
		t.Fatalf("validate transferred claim: %v", err)
	}
	attempt, err := restarted.ReconcilePlan(context.Background(), plan, reconcile)
	if err != nil || attempt.Status != AttemptVerified {
		t.Fatalf("transferred reconciliation = %#v, %v", attempt, err)
	}
	expectedAction, actionErr := makeHardwareAction(plan, plan.Operations[0], HardwarePhaseReconciliation, &reconcile.Claim)
	if actionErr != nil || attempt.ReconciliationTransition.Reference.Status != BootTransitionCompleted ||
		attempt.ReconciliationTransition.Action != expectedAction ||
		attempt.ReconciliationTransition.Evidence.Action != expectedAction {
		t.Fatalf("reconciliation transition evidence = %#v, expected action %#v, derive error %v", attempt.ReconciliationTransition, expectedAction, actionErr)
	}
	if durable, found, getErr := store.GetBootTransition(attempt.ReconciliationTransition.Reference.TransitionKey); getErr != nil || !found {
		t.Fatalf("reconciliation transition is not durable: %#v, %t, %v", durable, found, getErr)
	}
	if restartedHardware.observeCount != 1 {
		t.Fatalf("reconciliation observed target %d times, want exactly once", restartedHardware.observeCount)
	}
	if restartedHardware.executeCount != 0 || hardware.executeCount != 1 {
		t.Fatalf("reconciliation redispatched hardware: original=%d restarted=%d", hardware.executeCount, restartedHardware.executeCount)
	}
}

func TestRestartReconciliationRechecksClaimAfterJournalRecovery(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("response lost after command")
	original := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatal(err)
	}

	clock := &mutableClock{now: now}
	expiresAt := now.Add(ReconciliationObservationBudget + testConfig().LeaseSafetyMargin)
	restartedStore := &hookStore{Journal: store}
	restartedStore.afterFirstGet = func() { clock.now = clock.now.Add(time.Nanosecond) }
	restartedHardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPoststate,
	}}
	restartedHardware.journal = restartedStore
	restarted, err := NewWithClock(testConfig(), restartedHardware, restartedStore, clock)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := reconcileRequest(plan, original, expiresAt)
	if _, err := restarted.ReconcilePlan(context.Background(), plan, reconcile); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("claim expiring during journal recovery = %v, want lease invalid", err)
	}
	if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
		t.Fatalf("expired restart authority reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
	}
}

func TestReconciliationPlanWithMissingJournalPermanentlyDisarmsExecute(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	hardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
	}}
	store := NewMemoryStore()
	hardware.journal = store
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	original := requestFor(plan, 1, now.Add(10*time.Minute))
	reconcile := reconcileRequest(plan, original, now.Add(10*time.Minute))
	if _, err := guard.ReconcilePlan(context.Background(), plan, reconcile); err == nil || !strings.Contains(err.Error(), "no operation attempt") {
		t.Fatalf("missing-journal reconciliation = %v", err)
	}
	if _, err := guard.Execute(context.Background(), original); !errors.Is(err, ErrReconciliationAuthority) {
		t.Fatalf("execute after reconciliation-only load = %v", err)
	}
	if hardware.observeCount != 0 || hardware.executeCount != 0 {
		t.Fatalf("missing journal reached hardware: observations=%d executions=%d", hardware.observeCount, hardware.executeCount)
	}
}

func TestRestartRejectsAuthorityRolledBackBehindVerifiedJournal(t *testing.T) {
	firstGuard, hardware, store, firstPlan, now := newTestGuard(t)
	if _, err := firstGuard.Execute(context.Background(), requestFor(firstPlan, 1, now.Add(10*time.Minute))); err != nil {
		t.Fatalf("execute first operation: %v", err)
	}
	secondGuard, secondPlan := loadTestIntent(t, testConfig(), hardware, store, firstPlan, 2, now)
	if _, err := secondGuard.Execute(context.Background(), requestFor(secondPlan, 2, now.Add(10*time.Minute))); err != nil {
		t.Fatalf("execute second operation: %v", err)
	}

	staleGuard, err := NewWithClock(testConfig(), hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	observationsBefore := hardware.observeCount
	if err := staleGuard.LoadPlan(context.Background(), firstPlan); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("rolled-back authority load error = %v", err)
	}
	if hardware.observeCount != observationsBefore {
		t.Fatal("rolled-back authority reached target observation")
	}
}

func TestReconcileKeepsIndistinguishableOperationUncertain(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	hardware := &fakeHardware{
		observation: Observation{EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate},
		after: map[Operation]DirectState{
			plan.Operations[0].Operation: plan.Operations[0].ExpectedPoststate,
			plan.Operations[1].Operation: plan.Operations[1].ExpectedPoststate,
		},
	}
	store := NewMemoryStore()
	hardware.journal = store
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute))); err != nil {
		t.Fatalf("execute prerequisite: %v", err)
	}
	hardware.executeErr = errors.New("response lost")
	guard, plan = loadTestIntent(t, config, hardware, store, plan, 2, now)
	request := requestFor(plan, 2, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("execute indistinguishable operation: %v", err)
	}
	attempt, err := guard.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute)))
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain || !strings.Contains(attempt.Detail, "cannot distinguish") {
		t.Fatalf("indistinguishable reconcile = %#v, %v", attempt, err)
	}
	if hardware.executeCount != 2 {
		t.Fatalf("reconciliation replayed hardware; count = %d", hardware.executeCount)
	}
}

func TestRestartFailsClosedForUnknownOrQuarantinedState(t *testing.T) {
	t.Run("unknown uncertain state", func(t *testing.T) {
		guard, hardware, store, plan, now := newTestGuard(t)
		hardware.executeErr = errors.New("response lost")
		if _, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute))); !errors.Is(err, ErrReconciliationRequired) {
			t.Fatal(err)
		}
		unknown := plan.Operations[0].ExpectedPoststate
		unknown.SecurityState = "unknown"
		restartedHardware := &fakeHardware{observation: Observation{EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint, State: unknown}}
		restartedHardware.journal = store
		restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.LoadPlan(context.Background(), plan); err != nil {
			t.Fatalf("load uncertain restart: %v", err)
		}
		if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
			t.Fatalf("LoadPlan reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
		}
		attempt, err := restarted.Reconcile(context.Background(), reconcileRequest(plan, requestFor(plan, 1, now.Add(10*time.Minute)), now.Add(10*time.Minute)))
		if !errors.Is(err, ErrQuarantined) || !errors.Is(err, ErrPoststateMismatch) || attempt.Status != AttemptQuarantined {
			t.Fatalf("unknown state reconciliation = %#v, %v", attempt, err)
		}
		if restartedHardware.observeCount != 1 || restartedHardware.executeCount != 0 {
			t.Fatalf("reconciliation hardware calls: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
		}
	})

	t.Run("quarantine remains terminal", func(t *testing.T) {
		guard, hardware, store, plan, now := newTestGuard(t)
		bad := plan.Operations[0].ExpectedPoststate
		bad.SecurityState = "mismatch"
		hardware.after[OperationProgramCustomerKeyAndEEPROM] = bad
		request := requestFor(plan, 1, now.Add(10*time.Minute))
		if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrQuarantined) {
			t.Fatal(err)
		}
		restartedHardware := &fakeHardware{observation: Observation{EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint, State: bad}}
		restartedHardware.journal = store
		restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.LoadPlan(context.Background(), plan); err != nil {
			t.Fatalf("reload quarantine: %v", err)
		}
		if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
			t.Fatalf("LoadPlan reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
		}
		if _, err := restarted.Execute(context.Background(), request); !errors.Is(err, ErrQuarantined) {
			t.Fatalf("execute after quarantine = %v", err)
		}
		if _, err := restarted.Reconcile(context.Background(), reconcileRequest(plan, request, now.Add(10*time.Minute))); !errors.Is(err, ErrQuarantined) {
			t.Fatalf("reconcile after quarantine = %v", err)
		}
		if restartedHardware.observeCount != 0 || restartedHardware.executeCount != 0 {
			t.Fatalf("quarantined journal reached hardware: observations=%d executions=%d", restartedHardware.observeCount, restartedHardware.executeCount)
		}
	})
}

func TestGuardQuarantinesConclusiveBadPoststateAndReplacement(t *testing.T) {
	t.Run("bad poststate", func(t *testing.T) {
		guard, hardware, _, plan, now := newTestGuard(t)
		hardware.after[OperationProgramCustomerKeyAndEEPROM] = DirectState{CustomerKeyHash: "unexpected", SecurityState: "unknown", PowerState: "rpiboot"}
		attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
		if !errors.Is(err, ErrQuarantined) || !errors.Is(err, ErrPoststateMismatch) || attempt.Status != AttemptQuarantined {
			t.Fatalf("bad poststate = %#v, %v", attempt, err)
		}
	})
	t.Run("replacement", func(t *testing.T) {
		guard, hardware, _, plan, now := newTestGuard(t)
		hardware.replaceTarget = true
		attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
		if !errors.Is(err, ErrQuarantined) || !errors.Is(err, ErrTargetContinuity) || attempt.Status != AttemptQuarantined {
			t.Fatalf("replacement = %#v, %v", attempt, err)
		}
	})
}

func TestGuardRejectsStaleBindingsBeforeHardware(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ExecuteRequest)
	}{
		{"station", func(request *ExecuteRequest) { request.StationID = "other-station" }},
		{"lane", func(request *ExecuteRequest) { request.LaneID = "other-lane" }},
		{"transaction", func(request *ExecuteRequest) { request.TransactionID = "other-transaction" }},
		{"plan", func(request *ExecuteRequest) { request.PlanDigest = digest("9") }},
		{"signed release manifest", func(request *ExecuteRequest) { request.Release.SignedReleaseManifestDigest = digest("9") }},
		{"lane guard package", func(request *ExecuteRequest) { request.Release.LaneGuardPackageDigest = digest("9") }},
		{"compiled artifact set", func(request *ExecuteRequest) { request.Release.CompiledArtifactSetDigest = digest("9") }},
		{"expected customer key", func(request *ExecuteRequest) { request.Release.ExpectedCustomerKeyHash = digest("9") }},
		{"expected EEPROM", func(request *ExecuteRequest) { request.Release.ExpectedEEPROMDigest = digest("9") }},
		{"expected boot image", func(request *ExecuteRequest) { request.Release.ExpectedBootImageDigest = digest("9") }},
		{"target", func(request *ExecuteRequest) { request.TargetFingerprint = "other-target" }},
		{"initial observation", func(request *ExecuteRequest) { request.InitialObservationDigest = digest("9") }},
		{"fence", func(request *ExecuteRequest) { request.FenceEpoch++ }},
		{"approval", func(request *ExecuteRequest) { request.ApprovalID = "other-approval" }},
		{"approval expiry", func(request *ExecuteRequest) { request.ApprovalExpiresAt = request.ApprovalExpiresAt.Add(time.Second) }},
		{"intent", func(request *ExecuteRequest) { request.IntentReceipt = "other-receipt" }},
		{"sequence", func(request *ExecuteRequest) { request.Sequence = 2 }},
		{"operation", func(request *ExecuteRequest) { request.OperationDigest = digest("8") }},
		{"authorization", func(request *ExecuteRequest) { request.AuthorizationID = "other-authorization" }},
		{"required boot mode", func(request *ExecuteRequest) { request.RequiredBootMode = BootModeNormal }},
		{"prestate", func(request *ExecuteRequest) { request.ExpectedPrestate.SecurityState = "changed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, hardware, _, plan, now := newTestGuard(t)
			request := requestFor(plan, 1, now.Add(10*time.Minute))
			test.change(&request)
			observationsBefore := hardware.observeCount
			if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrPlanMismatch) {
				t.Fatalf("error = %v, want plan mismatch", err)
			}
			if hardware.observeCount != observationsBefore || hardware.executeCount != 0 {
				t.Fatalf("stale request reached hardware: observations %d -> %d, executions %d", observationsBefore, hardware.observeCount, hardware.executeCount)
			}
		})
	}
}

func TestSamePlanIncludesReleaseAndApprovalExpiry(t *testing.T) {
	plan := testPlan()
	equivalent := clonePlan(plan)
	equivalent.ApprovalExpiresAt = equivalent.ApprovalExpiresAt.In(time.FixedZone("equivalent-offset", -7*60*60))
	if !samePlan(plan, equivalent) {
		t.Fatal("plans with the same canonical approval-expiry instant compare different")
	}
	for _, test := range []struct {
		name   string
		mutate func(*Plan)
	}{
		{"release", func(value *Plan) { value.Release.ExpectedEEPROMDigest = digest("9") }},
		{"power control mode", func(value *Plan) { value.PowerControlMode = PowerControlManual }},
		{"approval expiry", func(value *Plan) { value.ApprovalExpiresAt = value.ApprovalExpiresAt.Add(time.Second) }},
		{"intent sequence", func(value *Plan) { value.IntentSequence++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := clonePlan(plan)
			test.mutate(&changed)
			if samePlan(plan, changed) {
				t.Fatalf("plans compare equal after mutating %s", test.name)
			}
		})
	}
}

func TestValidateAttemptForPlanBindsPublishedTransitionPowerMode(t *testing.T) {
	guard, _, _, plan, now := newTestGuard(t)
	attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	tampered := attempt
	tampered.PreObservationTransition.Action.PowerControlMode = PowerControlManual
	tampered.PreObservationTransition.Reference.PowerControlMode = PowerControlManual
	if err := ValidateAttemptForPlan(plan, tampered); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("wrong-mode published transition error = %v, want plan mismatch", err)
	}
}

func TestGuardRejectsOutOfOrderAndShortLease(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	outOfOrderGuard, outOfOrderPlan := loadTestIntent(t, testConfig(), hardware, store, plan, 2, now)
	if _, err := outOfOrderGuard.Execute(context.Background(), requestFor(outOfOrderPlan, 2, now.Add(10*time.Minute))); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("out-of-order error = %v", err)
	}
	if _, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(89*time.Second))); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("short-lease error = %v", err)
	}
	if hardware.executeCount != 0 {
		t.Fatalf("rejected work reached hardware")
	}

	exactGuard, _, _, exactPlan, exactNow := newTestGuard(t)
	if _, err := exactGuard.Execute(context.Background(), requestFor(exactPlan, 1, exactNow.Add(90*time.Second))); err != nil {
		t.Fatalf("exact lease boundary error = %v", err)
	}
}

func TestGuardRechecksAuthorityAfterDirectPrestateObservation(t *testing.T) {
	initial := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		after      time.Time
		want       error
		claimUntil time.Time
	}{
		{
			name:       "approval expired",
			after:      testPlan().ApprovalExpiresAt,
			want:       ErrApprovalExpired,
			claimUntil: initial.Add(10 * time.Minute),
		},
		{
			name:       "claim no longer covers operation",
			after:      initial.Add(8*time.Minute + 31*time.Second),
			want:       ErrLeaseInvalid,
			claimUntil: initial.Add(10 * time.Minute),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			plan := testPlan()
			clock := &mutableClock{now: initial}
			hardware := &fakeHardware{
				observation: Observation{
					EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
					TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
				},
			}
			hardware.beforeObserve = func() { clock.now = test.after }
			store := NewMemoryStore()
			hardware.journal = store
			guard, err := NewWithClock(config, hardware, store, clock)
			if err != nil {
				t.Fatal(err)
			}
			if err := guard.LoadPlan(context.Background(), plan); err != nil {
				t.Fatal(err)
			}

			if _, err := guard.Execute(context.Background(), requestFor(plan, 1, test.claimUntil)); !errors.Is(err, test.want) {
				t.Fatalf("execute error = %v, want %v", err, test.want)
			}
			if hardware.observeCount != 1 || hardware.executeCount != 0 {
				t.Fatalf("hardware calls: observations=%d executions=%d", hardware.observeCount, hardware.executeCount)
			}
			if _, found, err := store.Get(attemptKey(plan, 1)); err != nil || found {
				t.Fatalf("expired authority recorded intent: found=%t err=%v", found, err)
			}
		})
	}
}

func TestGuardEnforcesReviewedOperationDeadline(t *testing.T) {
	newDeadlineGuard := func(t *testing.T, waitObserve, waitExecute bool) (*Guard, *fakeHardware, *MemoryStore, Plan, time.Time) {
		t.Helper()
		config := testConfig()
		plan := testPlanBody()
		plan.Operations[0].MaximumDuration = 20 * time.Millisecond
		plan = deriveTestPlan(plan)
		now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
		store := NewMemoryStore()
		hardware := &fakeHardware{
			journal: store, waitObserve: waitObserve, waitExecute: waitExecute,
			observation: Observation{
				EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
				TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
			},
		}
		guard, err := NewWithClock(config, hardware, store, fakeClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.LoadPlan(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		return guard, hardware, store, plan, now
	}

	t.Run("pre-observation", func(t *testing.T) {
		guard, hardware, store, plan, now := newDeadlineGuard(t, true, false)
		attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(time.Minute)))
		if !errors.Is(err, ErrOperationDeadline) || attempt != (Attempt{}) {
			t.Fatalf("deadline result = %#v, %v", attempt, err)
		}
		if hardware.executeCount != 0 {
			t.Fatalf("deadline-crossing pre-observation reached execution %d times", hardware.executeCount)
		}
		if _, found, getErr := store.Get(attemptKey(plan, 1)); getErr != nil || found {
			t.Fatalf("pre-execution deadline created an attempt: found=%t err=%v", found, getErr)
		}
	})

	t.Run("execution", func(t *testing.T) {
		guard, hardware, store, plan, now := newDeadlineGuard(t, false, true)
		attempt, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(time.Minute)))
		if !errors.Is(err, ErrOperationDeadline) || !errors.Is(err, ErrReconciliationRequired) ||
			attempt.Status != AttemptUncertain {
			t.Fatalf("deadline result = %#v, %v", attempt, err)
		}
		if hardware.executeCount != 1 {
			t.Fatalf("execution count = %d", hardware.executeCount)
		}
		durable, found, getErr := store.Get(attemptKey(plan, 1))
		if getErr != nil || !found || durable.Status != AttemptUncertain {
			t.Fatalf("durable deadline result = %#v, found=%t err=%v", durable, found, getErr)
		}
	})
}

func TestGuardRejectsExpiredClaimWhenDurationArithmeticWouldOverflow(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	for name, expiry := range map[string]time.Time{
		"future but insufficient": now.Add(time.Hour),
		"expired":                 now.Add(-time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			plan := testPlanBody()
			plan.Operations[0].MaximumDuration = time.Duration(1<<63 - 1)
			plan = deriveTestPlan(plan)
			hardware := &fakeHardware{
				observation: Observation{
					EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
					TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
				},
			}
			journal := &countingStore{Journal: NewMemoryStore()}
			hardware.journal = journal
			guard, err := NewWithClock(config, hardware, journal, fakeClock{now})
			if err != nil {
				t.Fatal(err)
			}
			if err := guard.LoadPlan(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			journal.gets = 0
			journal.puts = 0
			observationsBefore := hardware.observeCount

			if _, err := guard.Execute(context.Background(), requestFor(plan, 1, expiry)); !errors.Is(err, ErrLeaseInvalid) {
				t.Fatalf("overflowing lease error = %v", err)
			}
			if hardware.observeCount != observationsBefore || hardware.executeCount != 0 {
				t.Fatalf("invalid claim reached hardware: observations %d -> %d, executions %d", observationsBefore, hardware.observeCount, hardware.executeCount)
			}
			if journal.gets != 0 || journal.puts != 0 {
				t.Fatalf("invalid claim reached journal: gets=%d puts=%d", journal.gets, journal.puts)
			}
		})
	}
}

func TestLoadPlanPerformsNoTargetIO(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	for _, test := range []struct {
		name string
		obs  Observation
	}{
		{"no target", Observation{EligibleTargets: 0, RPIBootSysfsPath: config.RPIBootSysfsPath}},
		{"multiple targets", Observation{EligibleTargets: 2, RPIBootSysfsPath: config.RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint}},
		{"wrong path", Observation{EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-2", TargetFingerprint: plan.TargetFingerprint}},
		{"wrong target", Observation{EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath, TargetFingerprint: "replacement-target"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hardware := &fakeHardware{observation: test.obs, observeErr: errors.New("target I/O must not be attempted")}
			store := NewMemoryStore()
			hardware.journal = store
			guard, err := New(config, hardware, store)
			if err != nil {
				t.Fatal(err)
			}
			if err := guard.LoadPlan(context.Background(), plan); err != nil {
				t.Fatalf("load plan: %v", err)
			}
			if hardware.observeCount != 0 || hardware.executeCount != 0 {
				t.Fatalf("LoadPlan reached hardware: observations=%d executions=%d", hardware.observeCount, hardware.executeCount)
			}
		})
	}
}

func TestPlanRequiresCompleteDevelopmentCampaign(t *testing.T) {
	canonical := testPlan()
	if err := canonical.Validate(testConfig()); err != nil {
		t.Fatalf("canonical plan rejected: %v", err)
	}

	tests := []struct {
		name              string
		mutate            func(*Plan)
		wantCampaignError bool
	}{
		{
			name: "truncated",
			mutate: func(plan *Plan) {
				plan.Operations = plan.Operations[:len(plan.Operations)-1]
			},
			wantCampaignError: true,
		},
		{
			name: "reordered",
			mutate: func(plan *Plan) {
				plan.Operations[2], plan.Operations[3] = plan.Operations[3], plan.Operations[2]
			},
			wantCampaignError: true,
		},
		{
			name: "duplicated",
			mutate: func(plan *Plan) {
				plan.Operations[3].Operation = plan.Operations[2].Operation
			},
			wantCampaignError: true,
		},
		{
			name: "inserted",
			mutate: func(plan *Plan) {
				inserted := plan.Operations[len(plan.Operations)-1]
				inserted.Sequence++
				plan.Operations = append(plan.Operations, inserted)
			},
			wantCampaignError: true,
		},
		{
			name: "renamed",
			mutate: func(plan *Plan) {
				plan.Operations[4].Operation = "renamed_operation"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := canonical
			plan.Operations = append([]OperationSpec(nil), canonical.Operations...)
			test.mutate(&plan)
			err := plan.Validate(testConfig())
			if err == nil {
				t.Fatal("altered campaign was accepted")
			}
			if test.wantCampaignError && !errors.Is(err, campaign.ErrInvalidDevelopmentCampaign) {
				t.Fatalf("error = %v, want invalid development campaign", err)
			}
		})
	}
}

func TestPlanRequiresExactlyOneInRangeIntentSequence(t *testing.T) {
	for name, sequence := range map[string]uint32{
		"missing":      0,
		"out of range": uint32(len(testPlan().Operations) + 1),
	} {
		t.Run(name, func(t *testing.T) {
			plan := testPlan()
			plan.IntentSequence = sequence
			if err := plan.Validate(testConfig()); err == nil {
				t.Fatalf("plan with intent sequence %d was accepted", sequence)
			}
		})
	}
}

func TestPlanRejectsDeprecatedStandaloneSignedBootOperation(t *testing.T) {
	plan := testPlan()
	plan.Operations[1] = OperationSpec{
		Sequence: 2, Operation: OperationVerifySignedBoot, Classification: ClassReadOnly,
		OperationDigest: digest("c"), AuthorizationID: "authorization-2",
		ExpectedPrestate:  plan.Operations[0].ExpectedPoststate,
		ExpectedPoststate: plan.Operations[0].ExpectedPoststate, MaximumDuration: time.Minute,
	}
	if err := plan.Validate(testConfig()); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("deprecated standalone signed-boot operation was accepted: %v", err)
	}
}

func TestFileStorePersistsExecuteOnceTerminalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	action := testHardwareAction(HardwarePhasePreObservation, OperationColdPowerCycle)
	action.TransactionID = "transaction"
	action.PlanDigest = digest("a")
	action.TargetFingerprint = "target"
	action.OperationDigest = digest("b")
	preObservation, err := recordFakeBootTransition(store, testConfig(), action, 200, false)
	if err != nil {
		t.Fatalf("persist pre-observation transition: %v", err)
	}
	attempt := Attempt{
		SchemaVersion: AttemptSchemaVersion, Key: "transaction/" + digest("a") + "/1/1",
		TransactionID: "transaction", PlanDigest: digest("a"), TargetFingerprint: "target",
		FenceEpoch: 1, ApprovalID: "approval", IntentReceipt: "intent", IntentSequence: 1,
		Sequence: 1, Operation: OperationColdPowerCycle,
		OperationDigest: digest("b"), Status: AttemptStarted, StartedAt: now, UpdatedAt: now,
		ObservedState: DirectState{SecurityState: "fresh"}, PreObservationTransition: preObservation, Detail: "started",
	}
	if err := store.Put(attempt); err != nil {
		t.Fatalf("put started: %v", err)
	}
	attempt.Status = AttemptVerified
	attempt.ObservedState = DirectState{SecurityState: "owned"}
	attempt.Detail = "verified"
	if err := store.Put(attempt); err != nil {
		t.Fatalf("put verified: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close first journal owner: %v", err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	actual, ok, err := reopened.Get(attempt.Key)
	if err != nil || !ok || actual != attempt {
		t.Fatalf("reopened = %#v, %t, %v", actual, ok, err)
	}
	changed := attempt
	changed.Detail = "rewritten"
	if err := reopened.Put(changed); err == nil {
		t.Fatal("terminal record rewrite succeeded")
	}
}

func TestStoreRejectsIncoherentTerminalFreshCommitAttestations(t *testing.T) {
	guard, _, store, plan, now := newTestGuard(t)
	verified, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
	if err != nil || verified.Status != AttemptVerified || verified.Result.CommitAttestation.IsZero() {
		t.Fatalf("verified fresh commit = %#v, %v", verified, err)
	}

	tests := []struct {
		name   string
		mutate func(*Attempt)
		want   string
	}{
		{
			name: "verified without attestation",
			mutate: func(attempt *Attempt) {
				attempt.Result.CommitAttestation = CommitAttestation{}
			},
			want: "requires a commit attestation",
		},
		{
			name: "verified with another target",
			mutate: func(attempt *Attempt) {
				attempt.Result.CommitAttestation.TargetFingerprint = "another-target"
			},
			want: "target does not match",
		},
		{
			name: "confirmed not applied with attestation",
			mutate: func(attempt *Attempt) {
				attempt.Status = AttemptConfirmedNotApplied
			},
			want: "cannot carry a commit attestation",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := verified
			test.mutate(&changed)
			if err := store.Put(changed); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("store error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadPlanRejectsCurrentSchemaVerifiedCommitOutsideApprovedRelease(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CommitAttestation)
	}{
		{"customer key", func(attestation *CommitAttestation) { attestation.CustomerKeyHash = digest("9") }},
		{"EEPROM", func(attestation *CommitAttestation) { attestation.EEPROMHash = digest("8") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, hardware, store, plan, now := newTestGuard(t)
			verified, err := guard.Execute(context.Background(), requestFor(plan, 1, now.Add(10*time.Minute)))
			if err != nil || verified.Status != AttemptVerified {
				t.Fatalf("verified fresh commit = %#v, %v", verified, err)
			}
			test.mutate(&verified.Result.CommitAttestation)
			verified.Result = bindOperationResult(plan, plan.Operations[0], verified.Result)
			if err := validateAttempt(verified); err != nil {
				t.Fatalf("valid-shaped current-schema attempt = %v", err)
			}
			store.mu.Lock()
			store.attempts[verified.Key] = verified
			store.mu.Unlock()

			restarted, err := NewWithClock(testConfig(), hardware, store, fakeClock{now})
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.LoadPlan(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "fresh-commit attestation differs") {
				t.Fatalf("LoadPlan error = %v, want plan-mismatched commit attestation", err)
			}
			if hardware.observeCount != 2 || hardware.executeCount != 1 {
				t.Fatalf("LoadPlan reached hardware: observations=%d executions=%d", hardware.observeCount, hardware.executeCount)
			}
		})
	}
}

func TestFileStoreRejectsPreAttemptStoreSchema(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "attempts.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"provisioning.kaiba.network/lane-guard-attempt-store/v1alpha3","attempts":{},"boot_transitions":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Get("missing"); err == nil || !strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("old journal error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	oldAttemptPath := filepath.Join(directory, "old-attempt.json")
	oldAttempt := `{"schema_version":"` + AttemptStoreSchemaVersion + `","attempts":{"legacy":{"schema_version":"provisioning.kaiba.network/lane-guard-attempt/v1alpha2","key":"legacy"}},"boot_transitions":{}}`
	if err := os.WriteFile(oldAttemptPath, []byte(oldAttempt), 0o600); err != nil {
		t.Fatal(err)
	}
	oldAttemptStore, err := NewFileStore(oldAttemptPath)
	if err != nil {
		t.Fatal(err)
	}
	defer oldAttemptStore.Close()
	if _, _, err := oldAttemptStore.Get("legacy"); err == nil || !strings.Contains(err.Error(), "unsupported attempt schema") {
		t.Fatalf("old attempt error = %v", err)
	}
}

func newTestGuard(t *testing.T) (*Guard, *fakeHardware, *MemoryStore, Plan, time.Time) {
	t.Helper()
	config := testConfig()
	plan := testPlan()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	hardware := &fakeHardware{
		observation: Observation{EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate},
		after: map[Operation]DirectState{
			plan.Operations[0].Operation: plan.Operations[0].ExpectedPoststate,
			plan.Operations[1].Operation: plan.Operations[1].ExpectedPoststate,
		},
	}
	store := NewMemoryStore()
	hardware.journal = store
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return guard, hardware, store, plan, now
}

func loadTestIntent(t *testing.T, config Config, hardware Hardware, store Journal, plan Plan, sequence uint32, now time.Time) (*Guard, Plan) {
	t.Helper()
	plan.IntentSequence = sequence
	plan.IntentReceipt = fmt.Sprintf("receipt-%d", sequence)
	if fake, ok := hardware.(*fakeHardware); ok {
		fake.journal = store
	}
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return guard, plan
}

func reconcileRequest(plan Plan, original ExecuteRequest, expiresAt time.Time) ReconcileRequest {
	return ReconcileRequest{
		SchemaVersion:   ReconcileRequestSchemaVersion,
		OriginalRequest: original,
		Claim: ReconciliationClaim{
			StationID: plan.StationID, LaneID: plan.LaneID, TransactionID: plan.TransactionID,
			TargetFingerprint: plan.TargetFingerprint, ClaimID: "reconciliation-claim",
			FenceEpoch: plan.FenceEpoch + 1, ExpiresAt: expiresAt,
		},
	}
}

func testConfig() Config {
	return Config{
		SchemaVersion: ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
		PowerControlMode: PowerControlRelay,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/kaiba-uart-1",
		PowerGPIO: GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17}, LeaseSafetyMargin: 30 * time.Second,
	}
}

func testPlan() Plan {
	return deriveTestPlan(testPlanBody())
}

func deriveTestPlan(plan Plan) Plan {
	derived, err := plan.WithDerivedDigests()
	if err != nil {
		panic(err)
	}
	return derived
}

func testPlanBody() Plan {
	zero := DirectState{CustomerKeyHash: unownedCustomerKeyHash, EEPROMHash: digest("d"), EEPROMHashStatus: EEPROMHashObserved, SecurityState: "fresh", PowerState: "powered_off"}
	attested := DirectState{CustomerKeyHash: digest("4"), EEPROMHash: digest("5"), EEPROMHashStatus: EEPROMHashCommitAttested, SecurityState: "owned", PowerState: "powered_off"}
	observed := attested
	observed.EEPROMHashStatus = EEPROMHashObserved
	return Plan{
		SchemaVersion: ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
		PowerControlMode: PowerControlRelay,
		TransactionID:    "transaction-1", Release: testReleaseBinding(), TargetFingerprint: "target-1", InitialObservationDigest: digest("7"),
		FenceEpoch: 7, ApprovalID: "approval-1",
		ApprovalExpiresAt: time.Date(2026, 8, 16, 12, 0, 0, 123456789, time.UTC), IntentReceipt: "receipt-1", IntentSequence: 1,
		Operations: []OperationSpec{
			{Sequence: 1, Operation: OperationProgramCustomerKeyAndEEPROM, Classification: ClassIrreversible, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-1", ExpectedPrestate: zero, ExpectedPoststate: attested, MaximumDuration: time.Minute},
			{Sequence: 2, Operation: OperationColdPowerCycle, Classification: ClassReversible, RequiredBootMode: BootModeNormal, AuthorizationID: "authorization-2", ExpectedPrestate: attested, ExpectedPoststate: attested, MaximumDuration: time.Minute},
			{Sequence: 3, Operation: OperationOwnedReadback, Classification: ClassReadOnly, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-3", ExpectedPrestate: attested, ExpectedPoststate: observed, MaximumDuration: time.Minute},
			{Sequence: 4, Operation: OperationTestOwnedRecovery, Classification: ClassReversible, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-4", ExpectedPrestate: observed, ExpectedPoststate: observed, MaximumDuration: time.Minute},
			{Sequence: 5, Operation: OperationPostRecoveryReadback, Classification: ClassReadOnly, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-5", ExpectedPrestate: observed, ExpectedPoststate: observed, MaximumDuration: time.Minute},
			{Sequence: 6, Operation: OperationTestNegativeBoot, Classification: ClassReversible, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-6", ExpectedPrestate: observed, ExpectedPoststate: observed, MaximumDuration: time.Minute},
			{Sequence: 7, Operation: OperationTestRootIntegrity, Classification: ClassReversible, RequiredBootMode: BootModeRPIBoot, AuthorizationID: "authorization-7", ExpectedPrestate: observed, ExpectedPoststate: observed, MaximumDuration: time.Minute},
		},
	}
}

func requestFor(plan Plan, sequence uint32, expiry time.Time) ExecuteRequest {
	operation := plan.Operations[sequence-1]
	return ExecuteRequest{
		SchemaVersion: ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest,
		Release:           plan.Release,
		TargetFingerprint: plan.TargetFingerprint, InitialObservationDigest: plan.InitialObservationDigest, FenceEpoch: plan.FenceEpoch,
		ApprovalID: plan.ApprovalID, ApprovalExpiresAt: plan.ApprovalExpiresAt, IntentReceipt: plan.IntentReceipt,
		Sequence: sequence, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, RequiredBootMode: operation.RequiredBootMode,
		ExpectedPrestate: operation.ExpectedPrestate,
		ClaimExpiresAt:   expiry,
	}
}

func testReleaseBinding() releasebinding.Binding {
	return releasebinding.Binding{
		SignedReleaseManifestDigest: digest("1"),
		LaneGuardPackageDigest:      digest("2"),
		CompiledArtifactSetDigest:   digest("3"),
		ExpectedCustomerKeyHash:     digest("4"),
		ExpectedEEPROMDigest:        digest("5"),
		ExpectedBootImageDigest:     digest("6"),
	}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
