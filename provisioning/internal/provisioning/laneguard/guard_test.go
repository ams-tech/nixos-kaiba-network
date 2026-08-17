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

type fakeHardware struct {
	mu            sync.Mutex
	observation   Observation
	observeErr    error
	executeErr    error
	executeCount  int
	observeCount  int
	after         map[Operation]DirectState
	beforeObserve func()
	beforeExecute func(Operation)
	replaceTarget bool
}

func (hardware *fakeHardware) Observe(context.Context, Config) (Observation, error) {
	hardware.mu.Lock()
	defer hardware.mu.Unlock()
	hardware.observeCount++
	if hardware.beforeObserve != nil {
		hardware.beforeObserve()
	}
	return hardware.observation, hardware.observeErr
}

func (hardware *fakeHardware) Execute(_ context.Context, _ Config, operation Operation) (OperationResult, error) {
	hardware.mu.Lock()
	hardware.executeCount++
	callback := hardware.beforeExecute
	if state, ok := hardware.after[operation]; ok {
		hardware.observation.State = state
	}
	if hardware.replaceTarget {
		hardware.observation.TargetFingerprint = "replacement-target"
	}
	err := hardware.executeErr
	hardware.mu.Unlock()
	if callback != nil {
		callback(operation)
	}
	return OperationResult{OutputDigest: digest("f"), Detail: "fake result"}, err
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

func TestGuardNeverRepeatsUncertainIrreversibleOperation(t *testing.T) {
	guard, hardware, _, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("USB response lost")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	attempt, err := guard.Execute(context.Background(), request)
	if !errors.Is(err, ErrReconciliationRequired) || attempt.Status != AttemptUncertain {
		t.Fatalf("uncertain execute = %#v, %v", attempt, err)
	}
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("second execute error = %v", err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("uncertain operation executed %d times", hardware.executeCount)
	}

	// The fake changed to the approved poststate before losing its response;
	// direct reconciliation can therefore verify the attempt without replay.
	hardware.executeErr = nil
	reconciled, err := guard.Reconcile(context.Background(), request)
	if err != nil || reconciled.Status != AttemptVerified {
		t.Fatalf("reconcile = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("reconciliation executed hardware; count = %d", hardware.executeCount)
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
	hardware.executeErr = errors.New("response lost after command")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("uncertain execute error = %v", err)
	}

	guard.clock = fakeClock{now: plan.ApprovalExpiresAt.Add(time.Second)}
	reconciled, err := guard.Reconcile(context.Background(), request)
	if err != nil || reconciled.Status != AttemptVerified {
		t.Fatalf("expired reconciliation = %#v, %v", reconciled, err)
	}
	if hardware.executeCount != 1 {
		t.Fatalf("expired reconciliation executed hardware; count = %d", hardware.executeCount)
	}
}

func TestRestartLoadsUncertainAttemptForObservationOnly(t *testing.T) {
	guard, hardware, store, plan, now := newTestGuard(t)
	hardware.executeErr = errors.New("response lost after command")
	request := requestFor(plan, 1, now.Add(10*time.Minute))
	if _, err := guard.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("first execute = %v", err)
	}

	restartedHardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: testConfig().RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPoststate,
	}}
	restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadPlan(context.Background(), plan); err != nil {
		t.Fatalf("reload uncertain plan: %v", err)
	}
	if _, err := restarted.Execute(context.Background(), request); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("restart execute error = %v", err)
	}
	attempt, err := restarted.Reconcile(context.Background(), request)
	if err != nil || attempt.Status != AttemptVerified {
		t.Fatalf("restart reconcile = %#v, %v", attempt, err)
	}
	if restartedHardware.executeCount != 0 {
		t.Fatalf("restart replayed hardware %d times", restartedHardware.executeCount)
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
	plan.Operations[1].ExpectedPoststate = plan.Operations[1].ExpectedPrestate
	for index := 2; index < len(plan.Operations); index++ {
		plan.Operations[index].ExpectedPrestate = plan.Operations[1].ExpectedPoststate
		plan.Operations[index].ExpectedPoststate = plan.Operations[1].ExpectedPoststate
	}
	plan = deriveTestPlan(plan)
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	hardware := &fakeHardware{
		observation: Observation{EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath, TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate},
		after: map[Operation]DirectState{
			plan.Operations[0].Operation: plan.Operations[0].ExpectedPoststate,
			plan.Operations[1].Operation: plan.Operations[1].ExpectedPoststate,
		},
	}
	store := NewMemoryStore()
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
	attempt, err := guard.Reconcile(context.Background(), request)
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
		restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.LoadPlan(context.Background(), plan); !errors.Is(err, ErrPrestateMismatch) {
			t.Fatalf("unknown state load error = %v", err)
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
		restarted, err := NewWithClock(testConfig(), restartedHardware, store, fakeClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.LoadPlan(context.Background(), plan); err != nil {
			t.Fatalf("reload quarantine: %v", err)
		}
		if _, err := restarted.Execute(context.Background(), request); !errors.Is(err, ErrQuarantined) {
			t.Fatalf("execute after quarantine = %v", err)
		}
		if _, err := restarted.Reconcile(context.Background(), request); !errors.Is(err, ErrQuarantined) {
			t.Fatalf("reconcile after quarantine = %v", err)
		}
		if restartedHardware.executeCount != 0 {
			t.Fatal("quarantined journal reopened execution")
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
		{"fence", func(request *ExecuteRequest) { request.FenceEpoch++ }},
		{"approval", func(request *ExecuteRequest) { request.ApprovalID = "other-approval" }},
		{"approval expiry", func(request *ExecuteRequest) { request.ApprovalExpiresAt = request.ApprovalExpiresAt.Add(time.Second) }},
		{"intent", func(request *ExecuteRequest) { request.IntentReceipt = "other-receipt" }},
		{"sequence", func(request *ExecuteRequest) { request.Sequence = 2 }},
		{"operation", func(request *ExecuteRequest) { request.OperationDigest = digest("8") }},
		{"authorization", func(request *ExecuteRequest) { request.AuthorizationID = "other-authorization" }},
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
			journal := &countingStore{}
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

func TestLoadPlanRequiresExactLaneAndFreshTarget(t *testing.T) {
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
			hardware := &fakeHardware{observation: test.obs}
			guard, err := New(config, hardware, NewMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			if err := guard.LoadPlan(context.Background(), plan); !errors.Is(err, ErrTargetContinuity) {
				t.Fatalf("load error = %v", err)
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
	attempt := Attempt{
		SchemaVersion: ContractSchemaVersion, Key: "transaction/plan/1/1",
		TransactionID: "transaction", PlanDigest: digest("a"), TargetFingerprint: "target",
		FenceEpoch: 1, ApprovalID: "approval", IntentReceipt: "intent", IntentSequence: 1,
		Sequence: 1, Operation: OperationProgramCustomerKeyAndEEPROM,
		OperationDigest: digest("b"), Status: AttemptStarted, StartedAt: now, UpdatedAt: now,
		ObservedState: DirectState{SecurityState: "fresh"}, Detail: "started",
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
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
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

func TestFileStoreRejectsPreIntentBindingJournalSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"provisioning.kaiba.network/lane-guard/v1alpha2","attempts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get("missing"); err == nil || !strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("old journal error = %v", err)
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
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return guard, hardware, store, plan, now
}

func loadTestIntent(t *testing.T, config Config, hardware Hardware, store AttemptStore, plan Plan, sequence uint32, now time.Time) (*Guard, Plan) {
	t.Helper()
	plan.IntentSequence = sequence
	plan.IntentReceipt = fmt.Sprintf("receipt-%d", sequence)
	guard, err := NewWithClock(config, hardware, store, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return guard, plan
}

func testConfig() Config {
	return Config{
		SchemaVersion: ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
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
	zero := DirectState{CustomerKeyHash: strings.Repeat("0", 64), EEPROMHash: "sha256:factory", SecurityState: "fresh", PowerState: "rpiboot"}
	owned := DirectState{CustomerKeyHash: strings.Repeat("1", 64), EEPROMHash: digest("e"), SecurityState: "owned", PowerState: "rpiboot"}
	booted := owned
	booted.PowerState = "signed_os"
	return Plan{
		SchemaVersion: ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
		TransactionID: "transaction-1", Release: testReleaseBinding(), TargetFingerprint: "target-1",
		FenceEpoch: 7, ApprovalID: "approval-1",
		ApprovalExpiresAt: time.Date(2026, 8, 16, 12, 0, 0, 123456789, time.UTC), IntentReceipt: "receipt-1", IntentSequence: 1,
		Operations: []OperationSpec{
			{Sequence: 1, Operation: OperationProgramCustomerKeyAndEEPROM, Classification: ClassIrreversible, AuthorizationID: "authorization-1", ExpectedPrestate: zero, ExpectedPoststate: owned, MaximumDuration: time.Minute},
			{Sequence: 2, Operation: OperationColdPowerCycle, Classification: ClassReversible, AuthorizationID: "authorization-2", ExpectedPrestate: owned, ExpectedPoststate: booted, MaximumDuration: time.Minute},
			{Sequence: 3, Operation: OperationOwnedReadback, Classification: ClassReadOnly, AuthorizationID: "authorization-3", ExpectedPrestate: booted, ExpectedPoststate: booted, MaximumDuration: time.Minute},
			{Sequence: 4, Operation: OperationTestOwnedRecovery, Classification: ClassReversible, AuthorizationID: "authorization-4", ExpectedPrestate: booted, ExpectedPoststate: booted, MaximumDuration: time.Minute},
			{Sequence: 5, Operation: OperationPostRecoveryReadback, Classification: ClassReadOnly, AuthorizationID: "authorization-5", ExpectedPrestate: booted, ExpectedPoststate: booted, MaximumDuration: time.Minute},
			{Sequence: 6, Operation: OperationTestNegativeBoot, Classification: ClassReversible, AuthorizationID: "authorization-6", ExpectedPrestate: booted, ExpectedPoststate: booted, MaximumDuration: time.Minute},
			{Sequence: 7, Operation: OperationTestRootIntegrity, Classification: ClassReversible, AuthorizationID: "authorization-7", ExpectedPrestate: booted, ExpectedPoststate: booted, MaximumDuration: time.Minute},
		},
	}
}

func requestFor(plan Plan, sequence uint32, expiry time.Time) ExecuteRequest {
	operation := plan.Operations[sequence-1]
	return ExecuteRequest{
		SchemaVersion: ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest,
		Release:           plan.Release,
		TargetFingerprint: plan.TargetFingerprint, FenceEpoch: plan.FenceEpoch,
		ApprovalID: plan.ApprovalID, ApprovalExpiresAt: plan.ApprovalExpiresAt, IntentReceipt: plan.IntentReceipt,
		Sequence: sequence, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, ExpectedPrestate: operation.ExpectedPrestate,
		ClaimExpiresAt: expiry,
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
