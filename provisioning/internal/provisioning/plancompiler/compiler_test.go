package plancompiler

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

func TestHappyPathBuildsExactPlanAndBindsCurrentRequest(t *testing.T) {
	fixture := newFixture(t)
	bound, err := Bind(fixture.draft, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	plan := clonePlan(bound.plan)
	if plan.ApprovalID != fixture.authority.Transaction.Approval.ID || plan.IntentReceipt != fixture.authority.IntentReceipt.ReceiptID {
		t.Fatalf("authority envelope = %q/%q", plan.ApprovalID, plan.IntentReceipt)
	}
	wantCommitAttestedState := laneguard.DirectState{
		CustomerKeyHash:  plan.Release.ExpectedCustomerKeyHash,
		EEPROMHash:       plan.Release.ExpectedEEPROMDigest,
		EEPROMHashStatus: laneguard.EEPROMHashCommitAttested,
		SecurityState:    "owned",
		PowerState:       "powered_off",
	}
	wantObservedState := wantCommitAttestedState
	wantObservedState.EEPROMHashStatus = laneguard.EEPROMHashObserved
	if plan.InitialObservationDigest != fixture.authority.Transaction.Target.ObservationDigest {
		t.Fatalf("plan initial observation = %q, want control target observation %q", plan.InitialObservationDigest, fixture.authority.Transaction.Target.ObservationDigest)
	}
	request, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	wantOperations := campaign.DevelopmentOperations()
	if len(plan.Operations) != len(wantOperations) {
		t.Fatalf("plan operation count = %d", len(plan.Operations))
	}
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		PowerControlMode: plan.PowerControlMode,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-test",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
	}
	if request.Sequence != 1 || plan.Operations[0].Operation != wantOperations[0] {
		t.Fatal("current request is not the first approved operation")
	}
	if request.RequiredBootMode != laneguard.BootModeRPIBoot {
		t.Fatalf("current request boot mode = %q, want %q", request.RequiredBootMode, laneguard.BootModeRPIBoot)
	}
	if request.ClaimExpiresAt != fixture.authority.Transaction.ActiveClaim.ExpiresAt {
		t.Fatalf("request claim expiry = %s", request.ClaimExpiresAt)
	}
	if err := laneguard.ValidatePlanRequest(config, plan, request); err != nil {
		t.Fatalf("validate current request: %v", err)
	}
	for index := range plan.Operations {
		if plan.Operations[index].Operation != wantOperations[index] {
			t.Fatalf("plan operation %d is out of order", index+1)
		}
		wantPoststate := wantObservedState
		if index < 2 {
			wantPoststate = wantCommitAttestedState
		}
		if plan.Operations[index].ExpectedPoststate != wantPoststate {
			t.Fatalf("operation %d poststate = %#v, want %#v", index+1, plan.Operations[index].ExpectedPoststate, wantPoststate)
		}
		wantBootMode := laneguard.BootModeRPIBoot
		if plan.Operations[index].Operation == laneguard.OperationColdPowerCycle {
			wantBootMode = laneguard.BootModeNormal
		}
		if plan.Operations[index].RequiredBootMode != wantBootMode {
			t.Fatalf("operation %d boot mode = %q, want %q", index+1, plan.Operations[index].RequiredBootMode, wantBootMode)
		}
	}
	request.ApprovalID = "changed"
	plan.Operations[0].AuthorizationID = "changed"
	if rebound := clonePlan(bound.plan); rebound.ApprovalID == "changed" || rebound.Operations[0].AuthorizationID == "changed" {
		t.Fatal("bound plan exposed caller-owned mutable state")
	}
}

func TestBoundPlanEmitsOnlyTheCurrentlyDurableIntent(t *testing.T) {
	fixture := newFixture(t)
	bound, err := Bind(fixture.draft, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	request, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	if request.Sequence != 1 {
		t.Fatalf("executable request = %#v, want only sequence 1", request)
	}
}

func TestBoundPlanLoadsOpaquePlanAndExecutesCurrentRequestThroughPublicAPI(t *testing.T) {
	fixture := newFixture(t)
	bound, err := Bind(fixture.draft, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	request, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	draftSnapshot := fixture.draft.Snapshot()
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: request.StationID, LaneID: request.LaneID,
		PowerControlMode: draftSnapshot.PowerControlMode,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-public-api",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17}, LeaseSafetyMargin: 30 * time.Second,
	}
	journal := laneguard.NewMemoryStore()
	hardware := &boundPlanTestHardware{
		journal: journal,
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: request.TargetFingerprint, State: request.ExpectedPrestate,
		},
		poststate: draftSnapshot.Operations[0].ExpectedPoststate,
	}
	guard, err := laneguard.NewWithClock(config, hardware, journal, boundPlanTestClock{fixture.authority.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := bound.Load(context.Background(), guard); err != nil {
		t.Fatalf("load opaque bound plan: %v", err)
	}
	attempt, err := guard.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("execute current public request: %v", err)
	}
	if attempt.Status != laneguard.AttemptVerified || attempt.Sequence != request.Sequence {
		t.Fatalf("public API attempt = %#v", attempt)
	}
}

func TestGuardRejectsSynthesizedLaterSequenceWhenBoundEnvelopeIsPreserved(t *testing.T) {
	fixture := newFixture(t)
	bound, err := Bind(fixture.draft, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	plan := clonePlan(bound.plan)
	request, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	later := plan.Operations[1]
	request.Sequence = later.Sequence
	request.OperationDigest = later.OperationDigest
	request.AuthorizationID = later.AuthorizationID
	request.RequiredBootMode = later.RequiredBootMode
	request.ExpectedPrestate = later.ExpectedPrestate
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		PowerControlMode: plan.PowerControlMode,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-test",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
	}
	if err := laneguard.ValidatePlanRequest(config, plan, request); !errors.Is(err, laneguard.ErrPlanMismatch) {
		t.Fatalf("synthesized later request error = %v", err)
	}
}

func TestBindAdvancesOnlyAfterSuccessfulEvidenceAndANewIntent(t *testing.T) {
	fixture := newFixture(t)
	authority := advanceFixtureToSecondIntent(t, fixture)
	bound, err := Bind(fixture.draft, authority)
	if err != nil {
		t.Fatal(err)
	}
	request, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	if request.Sequence != 2 || request.IntentReceipt != authority.IntentReceipt.ReceiptID || request.RequiredBootMode != laneguard.BootModeNormal {
		t.Fatalf("second bound request = %#v", request)
	}
	for name, status := range map[string]controlplane.OperationStatus{
		"still pending":         controlplane.OperationIntentRecorded,
		"failed":                controlplane.OperationFailed,
		"uncertain":             controlplane.OperationUncertain,
		"confirmed not applied": controlplane.OperationConfirmedNotApplied,
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneAuthority(t, authority)
			changed.Transaction.Operations[0].Status = status
			if _, err := Bind(fixture.draft, changed); !errors.Is(err, ErrAuthorityMismatch) {
				t.Fatalf("prior status %q error = %v", status, err)
			}
		})
	}
}

func TestBindRejectsSemanticallyValidRehearsalActor(t *testing.T) {
	fixture := newFixture(t)
	authority := cloneAuthority(t, fixture.authority)
	authority.IntentRecord.Event.Actors = []auditlog.Actor{{ID: authority.Transaction.ActiveClaim.StationID, Role: "software_rehearsal"}}
	rehashIntentAuthority(&authority)
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
		t.Fatalf("rehearsal actor error = %v", err)
	}
}

func TestBindRejectsApprovalRecordedAfterControlApproval(t *testing.T) {
	fixture := newFixture(t)
	authority := cloneAuthority(t, fixture.authority)
	authority.Transaction.Approval.ApprovedAt = authority.ApprovalRecord.RecordedAt.Add(-time.Second)
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
		t.Fatalf("reversed approval ordering error = %v", err)
	}
}

func TestBindRejectsIntentControlTimeBeforeAuditRecord(t *testing.T) {
	fixture := newFixture(t)
	authority := cloneAuthority(t, fixture.authority)
	authority.Transaction.Operations[0].IntentAt = authority.IntentRecord.RecordedAt.Add(-time.Second)
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
		t.Fatalf("intent control-before-audit error = %v", err)
	}
}

func TestBindRejectsIntentAuditSequenceNotAfterApproval(t *testing.T) {
	fixture := newFixture(t)
	authority := cloneAuthority(t, fixture.authority)
	authority.IntentRecord.Sequence = authority.ApprovalRecord.Sequence
	authority.IntentReceipt.Sequence = authority.IntentRecord.Sequence
	rehashIntentAuthority(&authority)
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
		t.Fatalf("reversed audit sequence error = %v", err)
	}
}

func TestBindRejectsApprovalControlTimeAfterIntentAudit(t *testing.T) {
	fixture := newFixture(t)
	authority := cloneAuthority(t, fixture.authority)
	authority.Now = authority.Now.Add(2 * time.Second)
	authority.Transaction.Approval.ApprovedAt = authority.IntentRecord.RecordedAt.Add(time.Second)
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
		t.Fatalf("approval-after-intent-audit error = %v", err)
	}
}

func TestBindRejectsPriorEvidenceAfterNextIntent(t *testing.T) {
	fixture := newFixture(t)
	authority := advanceFixtureToSecondIntent(t, fixture)
	authority = cloneAuthority(t, authority)
	authority.Now = authority.Now.Add(2 * time.Second)
	evidenceAt := authority.Transaction.Operations[1].IntentAt.Add(time.Second)
	authority.Transaction.Operations[0].EvidenceAt = &evidenceAt
	if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatalf("evidence-after-next-intent error = %v", err)
	}
}

func TestBuildDraftRejectsMalformedInputs(t *testing.T) {
	base := testDraftInput(testNow())
	tests := map[string]func(*DraftInput){
		"identity":            func(value *DraftInput) { value.StationID = "bad id" },
		"power control mode":  func(value *DraftInput) { value.PowerControlMode = "" },
		"target":              func(value *DraftInput) { value.TargetFingerprint = "bad" },
		"initial observation": func(value *DraftInput) { value.InitialObservationDigest = "bad" },
		"fence":               func(value *DraftInput) { value.FenceEpoch = 0 },
		"release":             func(value *DraftInput) { value.Release.ExpectedEEPROMDigest = "bad" },
		"expiry":              func(value *DraftInput) { value.ApprovalExpiresAt = time.Time{} },
		"initial state":       func(value *DraftInput) { value.InitialState.PowerState = "" },
		"initial mode":        func(value *DraftInput) { value.InitialState.PowerState = "rpiboot" },
		"initial digest":      func(value *DraftInput) { value.InitialState.EEPROMHash = "not-a-digest" },
		"initial key":         func(value *DraftInput) { value.InitialState.CustomerKeyHash = digest("d") },
		"zero owned key":      func(value *DraftInput) { value.Release.ExpectedCustomerKeyHash = ZeroCustomerKeyHash },
		"authorization":       func(value *DraftInput) { value.AuthorizationIDs[3] = "bad id" },
		"duration":            func(value *DraftInput) { value.MaximumDurations[5] = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			if _, err := BuildDraft(input); !errors.Is(err, ErrInvalidDraft) {
				t.Fatalf("BuildDraft() error = %v", err)
			}
		})
	}
}

func TestBuildDraftBindsPowerControlModeIntoSnapshotAndPlanDigest(t *testing.T) {
	relayInput := testDraftInput(testNow())
	relay, err := BuildDraft(relayInput)
	if err != nil {
		t.Fatal(err)
	}
	manualInput := relayInput
	manualInput.PowerControlMode = laneguard.PowerControlManual
	manual, err := BuildDraft(manualInput)
	if err != nil {
		t.Fatal(err)
	}
	if relay.Snapshot().PowerControlMode != laneguard.PowerControlRelay || manual.Snapshot().PowerControlMode != laneguard.PowerControlManual {
		t.Fatalf("compiled power modes = relay:%q manual:%q", relay.Snapshot().PowerControlMode, manual.Snapshot().PowerControlMode)
	}
	if relay.PlanDigest() == manual.PlanDigest() {
		t.Fatal("changing relay to manual did not change the v1alpha6 plan digest")
	}
	restored, err := DraftFromSnapshot(manual.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot().PowerControlMode != laneguard.PowerControlManual {
		t.Fatalf("restored manual mode = %q", restored.Snapshot().PowerControlMode)
	}
}

func TestBuildDraftAcceptsObservedAndUnavailableFreshEEPROMPrestates(t *testing.T) {
	base := testDraftInput(testNow())
	tests := map[string]laneguard.DirectState{
		"observed": base.InitialState,
		"unavailable": {
			CustomerKeyHash:  ZeroCustomerKeyHash,
			EEPROMHashStatus: laneguard.EEPROMHashUnavailable,
			SecurityState:    "fresh",
			PowerState:       "powered_off",
		},
	}
	for name, initial := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			input.InitialState = initial
			draft, err := BuildDraft(input)
			if err != nil {
				t.Fatalf("BuildDraft() error = %v", err)
			}
			if got := draft.Snapshot().Operations[0].ExpectedPrestate; got != initial {
				t.Fatalf("initial prestate = %#v, want %#v", got, initial)
			}
			operations := draft.Snapshot().Operations
			if operations[0].ExpectedPoststate.EEPROMHashStatus != laneguard.EEPROMHashCommitAttested ||
				operations[1].ExpectedPrestate.EEPROMHashStatus != laneguard.EEPROMHashCommitAttested ||
				operations[1].ExpectedPoststate.EEPROMHashStatus != laneguard.EEPROMHashCommitAttested ||
				operations[2].ExpectedPrestate.EEPROMHashStatus != laneguard.EEPROMHashCommitAttested ||
				operations[2].ExpectedPoststate.EEPROMHashStatus != laneguard.EEPROMHashObserved {
				t.Fatalf("compiled EEPROM proof sequence = %#v", operations[:3])
			}
			for index := 3; index < len(operations); index++ {
				if operations[index].ExpectedPrestate.EEPROMHashStatus != laneguard.EEPROMHashObserved ||
					operations[index].ExpectedPoststate.EEPROMHashStatus != laneguard.EEPROMHashObserved {
					t.Fatalf("operation %d did not retain observed EEPROM proof: %#v", index+1, operations[index])
				}
			}
		})
	}
}

func TestBuildDraftRejectsInconsistentEEPROMAvailabilityAndNonFreshInitialState(t *testing.T) {
	base := testDraftInput(testNow())
	tests := map[string]laneguard.DirectState{
		"observed without hash": {
			CustomerKeyHash:  ZeroCustomerKeyHash,
			EEPROMHashStatus: laneguard.EEPROMHashObserved,
			SecurityState:    "fresh",
			PowerState:       "powered_off",
		},
		"unavailable with hash": {
			CustomerKeyHash:  ZeroCustomerKeyHash,
			EEPROMHash:       digest("6"),
			EEPROMHashStatus: laneguard.EEPROMHashUnavailable,
			SecurityState:    "fresh",
			PowerState:       "powered_off",
		},
		"unavailable owned": {
			CustomerKeyHash:  digest("d"),
			EEPROMHashStatus: laneguard.EEPROMHashUnavailable,
			SecurityState:    "owned",
			PowerState:       "powered_off",
		},
	}
	for name, initial := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			input.InitialState = initial
			if _, err := BuildDraft(input); !errors.Is(err, ErrInvalidDraft) {
				t.Fatalf("BuildDraft() error = %v", err)
			}
		})
	}
}

func TestInitialObservationDigestIsPlanDigestBound(t *testing.T) {
	base := testDraftInput(testNow())
	first, err := BuildDraft(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.InitialObservationDigest = digest("d")
	second, err := BuildDraft(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest() == second.PlanDigest() {
		t.Fatal("changing the initial observation did not change the plan digest")
	}

	tampered := first.Snapshot()
	tampered.InitialObservationDigest = changed.InitialObservationDigest
	if _, err := DraftFromSnapshot(tampered); !errors.Is(err, ErrInvalidDraft) {
		t.Fatalf("DraftFromSnapshot() accepted a tampered initial observation: %v", err)
	}
}

func TestDraftFromSnapshotReconstructsOnlyAuthorityFreePolicyPlan(t *testing.T) {
	draft, err := BuildDraft(testDraftInput(testNow()))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := draft.Snapshot()
	restored, err := DraftFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Snapshot(), snapshot) {
		t.Fatal("restored snapshot differs from reviewed snapshot")
	}

	tests := map[string]func(*laneguard.Plan){
		"approval": func(value *laneguard.Plan) { value.ApprovalID = "approval-forbidden" },
		"power control mode": func(value *laneguard.Plan) {
			value.PowerControlMode = laneguard.PowerControlManual
		},
		"intent receipt":  func(value *laneguard.Plan) { value.IntentReceipt = digest("f") },
		"intent sequence": func(value *laneguard.Plan) { value.IntentSequence = 1 },
		"initial observation": func(value *laneguard.Plan) {
			value.InitialObservationDigest = digest("d")
		},
		"operation":      func(value *laneguard.Plan) { value.Operations[2].Operation = laneguard.OperationColdPowerCycle },
		"classification": func(value *laneguard.Plan) { value.Operations[0].Classification = laneguard.ClassReadOnly },
		"required boot mode": func(value *laneguard.Plan) {
			value.Operations[0].RequiredBootMode = laneguard.BootModeNormal
		},
		"sequence": func(value *laneguard.Plan) { value.Operations[4].Sequence = 2 },
		"poststate": func(value *laneguard.Plan) {
			value.Operations[1].ExpectedPoststate.PowerState = "powered_on"
		},
		"operation digest": func(value *laneguard.Plan) { value.Operations[3].OperationDigest = digest("f") },
		"plan digest":      func(value *laneguard.Plan) { value.PlanDigest = digest("e") },
		"extra operation": func(value *laneguard.Plan) {
			value.Operations = append(value.Operations, value.Operations[len(value.Operations)-1])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := snapshot
			changed.Operations = append([]laneguard.OperationSpec(nil), snapshot.Operations...)
			mutate(&changed)
			if _, err := DraftFromSnapshot(changed); !errors.Is(err, ErrInvalidDraft) {
				t.Fatalf("DraftFromSnapshot() error = %v", err)
			}
		})
	}
}

func TestBindRejectsMutatedControlAuthorityFields(t *testing.T) {
	fixture := newFixture(t)
	tests := map[string]func(*Authority){
		"schema":               func(value *Authority) { value.Transaction.SchemaVersion = "other" },
		"transaction ID":       func(value *Authority) { value.Transaction.ID = "transaction-other" },
		"transaction status":   func(value *Authority) { value.Transaction.Status = controlplane.StatusCommitApproved },
		"transaction digest":   func(value *Authority) { value.Transaction.TransactionDigest = digest("f") },
		"transaction prestate": func(value *Authority) { value.Transaction.ExpectedPrestateCustomerKeyHash = digest("e") },
		"immutable asset":      func(value *Authority) { value.Transaction.AssetID = "asset-other" },
		"bundle":               func(value *Authority) { value.Transaction.BundleDigest = digest("f") },
		"fence":                func(value *Authority) { value.Transaction.FenceEpoch++ },
		"claim missing":        func(value *Authority) { value.Transaction.ActiveClaim = nil },
		"claim status":         func(value *Authority) { value.Transaction.ActiveClaim.Status = controlplane.ClaimExpired },
		"claim mode":           func(value *Authority) { value.Transaction.ActiveClaim.Mode = controlplane.ClaimModeReconciliation },
		"claim station":        func(value *Authority) { value.Transaction.ActiveClaim.StationID = "station-other" },
		"claim lane":           func(value *Authority) { value.Transaction.ActiveClaim.LaneID = "lane-other" },
		"claim asset":          func(value *Authority) { value.Transaction.ActiveClaim.AssetID = "asset-other" },
		"claim fence":          func(value *Authority) { value.Transaction.ActiveClaim.FenceEpoch++ },
		"claim stages":         func(value *Authority) { value.Transaction.ActiveClaim.AllowedStages[2] = "other" },
		"target missing":       func(value *Authority) { value.Transaction.Target = nil },
		"target fingerprint":   func(value *Authority) { value.Transaction.Target.Fingerprint = digest("f") },
		"target fence":         func(value *Authority) { value.Transaction.Target.FenceEpoch++ },
		"target key":           func(value *Authority) { value.Transaction.Target.CustomerKeyHash = digest("f") },
		"target observation":   func(value *Authority) { value.Transaction.Target.ObservationDigest = digest("f") },
		"approval missing":     func(value *Authority) { value.Transaction.Approval = nil },
		"approval transaction": func(value *Authority) { value.Transaction.Approval.TransactionDigest = digest("f") },
		"approval plan":        func(value *Authority) { value.Transaction.Approval.PlanDigest = digest("f") },
		"approval station":     func(value *Authority) { value.Transaction.Approval.StationID = "station-other" },
		"approval lane":        func(value *Authority) { value.Transaction.Approval.LaneID = "lane-other" },
		"approval fence":       func(value *Authority) { value.Transaction.Approval.FenceEpoch++ },
		"approval target":      func(value *Authority) { value.Transaction.Approval.TargetFingerprint = digest("f") },
		"approval release":     func(value *Authority) { value.Transaction.Approval.Release.ExpectedEEPROMDigest = digest("f") },
		"approval order": func(value *Authority) {
			value.Transaction.Approval.AllowedOperations[0], value.Transaction.Approval.AllowedOperations[1] = value.Transaction.Approval.AllowedOperations[1], value.Transaction.Approval.AllowedOperations[0]
		},
		"intent count":     func(value *Authority) { value.Transaction.Operations = nil },
		"intent operation": func(value *Authority) { value.Transaction.Operations[0].Operation = "other" },
		"intent status":    func(value *Authority) { value.Transaction.Operations[0].Status = controlplane.OperationSucceeded },
		"intent plan":      func(value *Authority) { value.Transaction.Operations[0].PlanDigest = digest("f") },
		"intent release":   func(value *Authority) { value.Transaction.Operations[0].Release.ExpectedEEPROMDigest = digest("f") },
		"intent input":     func(value *Authority) { value.Transaction.Operations[0].InputDigest = digest("f") },
		"intent prestate":  func(value *Authority) { value.Transaction.Operations[0].PrestateDigest = digest("f") },
		"intent receipt":   func(value *Authority) { value.Transaction.Operations[0].IntentAuditReceiptID = digest("f") },
		"intent fence":     func(value *Authority) { value.Transaction.Operations[0].IntentFenceEpoch++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authority := cloneAuthority(t, fixture.authority)
			mutate(&authority)
			if _, err := Bind(fixture.draft, authority); err == nil {
				t.Fatal("Bind() accepted mutated authority")
			}
		})
	}
}

func TestBindRejectsExpiryAndStaleClaim(t *testing.T) {
	fixture := newFixture(t)
	expired := cloneAuthority(t, fixture.authority)
	expired.Now = expired.Transaction.Approval.ExpiresAt
	if _, err := Bind(fixture.draft, expired); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expired approval error = %v", err)
	}

	stale := cloneAuthority(t, fixture.authority)
	stale.Transaction.ActiveClaim.ExpiresAt = stale.Now.Add(time.Minute)
	if _, err := Bind(fixture.draft, stale); !errors.Is(err, ErrStaleClaim) {
		t.Fatalf("stale claim error = %v", err)
	}

	exact := cloneAuthority(t, fixture.authority)
	exact.Transaction.ActiveClaim.ExpiresAt = exact.Now.Add(90 * time.Second)
	if _, err := Bind(fixture.draft, exact); err != nil {
		t.Fatalf("exact lease boundary error = %v", err)
	}
}

func TestBindRejectsExpiredClaimWhenDurationArithmeticWouldOverflow(t *testing.T) {
	now := testNow()
	input := testDraftInput(now)
	input.ApprovalExpiresAt = now.Add(23 * time.Hour)
	input.MaximumDurations[0] = time.Duration(1<<63 - 1)
	fixture := newFixtureWithDraftInput(t, input)
	for name, current := range map[string]time.Time{
		"future but insufficient": now,
		"expired":                 now.Add(2 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			authority := cloneAuthority(t, fixture.authority)
			authority.Now = current
			if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrStaleClaim) {
				t.Fatalf("overflowing claim error = %v", err)
			}
		})
	}
}

func TestBindRejectsAlteredReceiptAndAuditRecord(t *testing.T) {
	fixture := newFixture(t)
	tests := map[string]func(*Authority){
		"approval receipt ID": func(value *Authority) { value.ApprovalReceipt.ReceiptID = digest("e") },
		"approval event ID":   func(value *Authority) { value.ApprovalRecord.Event.EventID = "other" },
		"approval actor":      func(value *Authority) { value.ApprovalRecord.Event.Actors[0].ID = "other" },
		"approval event hash": func(value *Authority) { value.ApprovalRecord.EventHash = digest("e") },
		"receipt ID":          func(value *Authority) { value.IntentReceipt.ReceiptID = digest("f") },
		"receipt sequence":    func(value *Authority) { value.IntentReceipt.Sequence++ },
		"receipt event hash":  func(value *Authority) { value.IntentReceipt.EventHash = digest("f") },
		"receipt time": func(value *Authority) {
			value.IntentReceipt.RecordedAt = value.IntentReceipt.RecordedAt.Add(time.Second)
		},
		"record event":        func(value *Authority) { value.IntentRecord.Event.Stage = "other" },
		"record transaction":  func(value *Authority) { value.IntentRecord.Event.TransactionID = "transaction-other" },
		"record input":        func(value *Authority) { value.IntentRecord.Event.InputDigest = digest("f") },
		"record result":       func(value *Authority) { value.IntentRecord.Event.Result = auditlog.ResultSucceeded },
		"record request hash": func(value *Authority) { value.IntentRecord.RequestDigest = digest("f") },
		"record event hash":   func(value *Authority) { value.IntentRecord.EventHash = digest("f") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authority := cloneAuthority(t, fixture.authority)
			mutate(&authority)
			if _, err := Bind(fixture.draft, authority); !errors.Is(err, ErrInvalidAuditIntent) {
				t.Fatalf("Bind() error = %v", err)
			}
		})
	}
}

func TestBindReconciliationSeparatesOriginalAttemptFromCurrentClaim(t *testing.T) {
	fixture := newFixture(t)
	authority := transferFixtureToReconciliation(t, fixture, "station-recovery", "lane-recovery")
	// Forward approval expiry does not constrain observation-only reconciliation.
	authority.Now = fixture.authority.Transaction.Approval.ExpiresAt.Add(time.Minute)
	if !authority.Now.After(authority.Transaction.Operations[0].Approval.ExpiresAt) {
		t.Fatal("test did not exercise an expired original approval")
	}

	bound, err := BindReconciliation(fixture.draft, authority)
	if err != nil {
		t.Fatal(err)
	}
	plan, request, err := bound.Reconciliation()
	if err != nil {
		t.Fatal(err)
	}
	if authority.Transaction.Approval != nil {
		t.Fatal("reconciliation unexpectedly retained a current forward approval")
	}
	if plan.FenceEpoch != 1 || plan.StationID != "station-fixture" || plan.LaneID != "lane-fixture" ||
		plan.ApprovalID != "approval-fixture" || plan.IntentReceipt != fixture.authority.IntentReceipt.ReceiptID {
		t.Fatalf("reconstructed original plan = %#v", plan)
	}
	if request.OriginalRequest.FenceEpoch != plan.FenceEpoch ||
		request.OriginalRequest.ApprovalID != plan.ApprovalID ||
		request.OriginalRequest.IntentReceipt != plan.IntentReceipt ||
		request.OriginalRequest.RequiredBootMode != plan.Operations[0].RequiredBootMode ||
		request.Claim.StationID != "station-recovery" || request.Claim.LaneID != "lane-recovery" ||
		request.Claim.FenceEpoch != 2 || request.Claim.ClaimID != authority.Transaction.ActiveClaim.ID ||
		!request.Claim.ExpiresAt.Equal(authority.Transaction.ActiveClaim.ExpiresAt) {
		t.Fatalf("separate reconciliation request = %#v", request)
	}
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     request.Claim.StationID, LaneID: request.Claim.LaneID,
		PowerControlMode: plan.PowerControlMode,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/reconciliation-test",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
	}
	if err := laneguard.ValidateReconcileRequest(config, plan, request); err != nil {
		t.Fatalf("validate reconciliation request: %v", err)
	}
}

func TestBindReconciliationRejectsStaleOrIncompleteAuthority(t *testing.T) {
	fixture := newFixture(t)
	base := transferFixtureToReconciliation(t, fixture, "station-recovery", "lane-recovery")
	tests := map[string]func(*Authority){
		"current forward approval": func(value *Authority) {
			approval := value.Transaction.Operations[0].Approval
			value.Transaction.Approval = &approval
		},
		"mutation claim": func(value *Authority) {
			value.Transaction.ActiveClaim.Mode = controlplane.ClaimModeMutation
		},
		"stale current claim": func(value *Authority) {
			value.Transaction.ActiveClaim.ExpiresAt = value.Now
		},
		"old fence": func(value *Authority) {
			value.Transaction.ActiveClaim.FenceEpoch = 1
			value.Transaction.FenceEpoch = 1
		},
		"wrong claim stage": func(value *Authority) {
			value.Transaction.ActiveClaim.AllowedStages = []string{"program_customer_key_and_eeprom"}
		},
		"missing original claim": func(value *Authority) {
			value.Transaction.ClaimHistory = nil
		},
		"duplicate original claim": func(value *Authority) {
			value.Transaction.ClaimHistory = append(value.Transaction.ClaimHistory, value.Transaction.ClaimHistory[0])
		},
		"original claim released without transfer": func(value *Authority) {
			value.Transaction.ClaimHistory[0].Status = controlplane.ClaimReleased
		},
		"original claim missing close": func(value *Authority) {
			value.Transaction.ClaimHistory[0].ClosedAt = nil
		},
		"original claim closed before intent": func(value *Authority) {
			at := value.Transaction.Operations[0].IntentAt.Add(-time.Nanosecond)
			value.Transaction.ClaimHistory[0].ClosedAt = &at
		},
		"original claim overlaps current claim": func(value *Authority) {
			at := value.Transaction.ActiveClaim.AcquiredAt.Add(time.Nanosecond)
			value.Transaction.ClaimHistory[0].ClosedAt = &at
		},
		"original claim ended before intent": func(value *Authority) {
			value.Transaction.ClaimHistory[0].ExpiresAt = value.Transaction.Operations[0].IntentAt
		},
		"changed target fingerprint": func(value *Authority) {
			value.Transaction.Target.Fingerprint = digest("e")
		},
		"changed target prestate": func(value *Authority) {
			value.Transaction.Target.CustomerKeyHash = digest("e")
		},
		"missing approval snapshot": func(value *Authority) {
			value.Transaction.Operations[0].Approval = controlplane.Approval{}
		},
		"changed approval campaign": func(value *Authority) {
			value.Transaction.Operations[0].Approval.AllowedOperations[0] = "other"
		},
		"changed approval release": func(value *Authority) {
			value.Transaction.Operations[0].Approval.Release.ExpectedEEPROMDigest = digest("e")
		},
		"changed approval receipt": func(value *Authority) {
			value.Transaction.Operations[0].Approval.AuditReceiptID = digest("e")
		},
		"changed approval audit record": func(value *Authority) {
			value.ApprovalRecord.Event.Stage = "other"
		},
		"changed intent receipt": func(value *Authority) {
			value.Transaction.Operations[0].IntentAuditReceiptID = digest("e")
		},
		"changed intent audit record": func(value *Authority) {
			value.IntentRecord.Event.Stage = "other"
		},
		"short current lease": func(value *Authority) {
			value.Now = value.Transaction.ActiveClaim.ExpiresAt.Add(-30 * time.Second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authority := cloneAuthority(t, base)
			mutate(&authority)
			if _, err := BindReconciliation(fixture.draft, authority); err == nil {
				t.Fatal("BindReconciliation accepted altered authority")
			}
		})
	}
}

func TestBindReconciliationValidatesFinalUnresolvedEvidenceShape(t *testing.T) {
	t.Run("intent recorded", func(t *testing.T) {
		fixture := newFixture(t)
		base := transferFixtureToReconciliation(t, fixture, "station-recovery", "lane-recovery")
		tests := map[string]func(*controlplane.OperationRecord){
			"output":                 func(value *controlplane.OperationRecord) { value.OutputDigest = digest("c") },
			"observation":            func(value *controlplane.OperationRecord) { value.ObservationDigest = digest("d") },
			"evidence receipt":       func(value *controlplane.OperationRecord) { value.EvidenceAuditReceiptID = digest("e") },
			"evidence time":          func(value *controlplane.OperationRecord) { at := base.Now; value.EvidenceAt = &at },
			"reconciliation receipt": func(value *controlplane.OperationRecord) { value.ReconciliationAuditReceiptID = digest("f") },
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				authority := cloneAuthority(t, base)
				mutate(&authority.Transaction.Operations[0])
				if _, err := BindReconciliation(fixture.draft, authority); err == nil {
					t.Fatal("BindReconciliation accepted evidence on a clean intent")
				}
			})
		}
	})

	t.Run("uncertain", func(t *testing.T) {
		fixture := newFixture(t)
		base := uncertainFixtureToReconciliation(t, fixture)
		if _, err := BindReconciliation(fixture.draft, base); err != nil {
			t.Fatalf("valid uncertain authority: %v", err)
		}
		tests := map[string]func(*Authority){
			"output missing": func(value *Authority) {
				value.Transaction.Operations[0].OutputDigest = ""
			},
			"observation missing": func(value *Authority) {
				value.Transaction.Operations[0].ObservationDigest = ""
			},
			"evidence receipt missing": func(value *Authority) {
				value.Transaction.Operations[0].EvidenceAuditReceiptID = ""
			},
			"evidence time missing": func(value *Authority) {
				value.Transaction.Operations[0].EvidenceAt = nil
			},
			"evidence before intent": func(value *Authority) {
				at := value.Transaction.Operations[0].IntentAt.Add(-time.Second)
				value.Transaction.Operations[0].EvidenceAt = &at
			},
			"evidence after now": func(value *Authority) {
				at := value.Now.Add(time.Second)
				value.Transaction.Operations[0].EvidenceAt = &at
			},
			"unexpected reconciliation receipt": func(value *Authority) {
				value.Transaction.Operations[0].ReconciliationAuditReceiptID = digest("f")
			},
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				authority := cloneAuthority(t, base)
				mutate(&authority)
				if _, err := BindReconciliation(fixture.draft, authority); err == nil {
					t.Fatal("BindReconciliation accepted incomplete uncertain evidence")
				}
			})
		}
	})
}

func TestBindReconciliationValidatesSuccessfulPrefix(t *testing.T) {
	fixture := newFixture(t)
	advanced := advanceFixtureToSecondIntent(t, fixture)
	base := transferAuthorityToReconciliation(t, fixture, advanced, "station-recovery", "lane-recovery")
	if _, err := BindReconciliation(fixture.draft, base); err != nil {
		t.Fatalf("valid succeeded prefix: %v", err)
	}

	confirmed := cloneAuthority(t, base)
	confirmed.Transaction.Operations[0].Status = controlplane.OperationConfirmedApplied
	confirmed.Transaction.Operations[0].ReconciliationAuditReceiptID = digest("e")
	if _, err := BindReconciliation(fixture.draft, confirmed); err != nil {
		t.Fatalf("valid confirmed-applied prefix: %v", err)
	}

	tests := map[string]func(*Authority){
		"prior status": func(value *Authority) {
			value.Transaction.Operations[0].Status = controlplane.OperationFailed
		},
		"output missing": func(value *Authority) {
			value.Transaction.Operations[0].OutputDigest = ""
		},
		"observation missing": func(value *Authority) {
			value.Transaction.Operations[0].ObservationDigest = ""
		},
		"evidence time missing": func(value *Authority) {
			value.Transaction.Operations[0].EvidenceAt = nil
		},
		"succeeded evidence receipt missing": func(value *Authority) {
			value.Transaction.Operations[0].EvidenceAuditReceiptID = ""
		},
		"succeeded has reconciliation receipt": func(value *Authority) {
			value.Transaction.Operations[0].ReconciliationAuditReceiptID = digest("e")
		},
		"confirmed-applied reconciliation receipt missing": func(value *Authority) {
			value.Transaction.Operations[0].Status = controlplane.OperationConfirmedApplied
			value.Transaction.Operations[0].ReconciliationAuditReceiptID = ""
		},
		"confirmed-applied malformed evidence receipt": func(value *Authority) {
			value.Transaction.Operations[0].Status = controlplane.OperationConfirmedApplied
			value.Transaction.Operations[0].ReconciliationAuditReceiptID = digest("e")
			value.Transaction.Operations[0].EvidenceAuditReceiptID = "bad"
		},
		"next intent predates evidence": func(value *Authority) {
			value.Now = value.Now.Add(time.Second)
			at := value.Transaction.Operations[1].IntentAt.Add(time.Millisecond)
			value.Transaction.Operations[0].EvidenceAt = &at
		},
		"duplicate operation ID": func(value *Authority) {
			value.Transaction.Operations[1].ID = value.Transaction.Operations[0].ID
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authority := cloneAuthority(t, base)
			mutate(&authority)
			if _, err := BindReconciliation(fixture.draft, authority); err == nil {
				t.Fatal("BindReconciliation accepted an invalid successful prefix")
			}
		})
	}
}

type fixture struct {
	draft     Draft
	authority Authority
	control   *controlplane.Service
	audit     *auditlog.Service
}

type boundPlanTestClock struct{ now time.Time }

func (clock boundPlanTestClock) Now() time.Time { return clock.now }

type boundPlanTestHardware struct {
	journal     laneguard.Journal
	observation laneguard.Observation
	poststate   laneguard.DirectState
	transitions int
}

func (hardware *boundPlanTestHardware) Observe(_ context.Context, config laneguard.Config, action laneguard.HardwareAction) (laneguard.Observation, error) {
	hardware.transitions++
	outcome, err := recordBoundPlanBootTransition(hardware.journal, config, action, hardware.transitions)
	observation := hardware.observation
	observation.BootTransition = outcome
	return observation, err
}

func (hardware *boundPlanTestHardware) Execute(_ context.Context, config laneguard.Config, action laneguard.HardwareAction) (laneguard.OperationResult, error) {
	hardware.transitions++
	outcome, err := recordBoundPlanBootTransition(hardware.journal, config, action, hardware.transitions)
	hardware.observation.State = hardware.poststate
	return laneguard.OperationResult{
		OutputDigest: digest("f"), Detail: "compiler public API test",
		CommitAttestation: laneguard.CommitAttestation{
			SchemaVersion: laneguard.CommitAttestationSchemaVersion, TargetFingerprint: action.TargetFingerprint,
			CustomerKeyHash: hardware.poststate.CustomerKeyHash, EEPROMHash: hardware.poststate.EEPROMHash,
			EEPROMUpdateResult: "success", SecureBootProvisionResult: "success",
		},
		BootTransition: outcome,
	}, err
}

func recordBoundPlanBootTransition(journal laneguard.Journal, config laneguard.Config, action laneguard.HardwareAction, ordinal int) (laneguard.BootTransitionOutcome, error) {
	started := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Add(time.Duration(ordinal) * time.Minute)
	transition, err := journal.BeginBootTransition(laneguard.BeginBootTransitionRequest{
		Action: action, PowerControlMode: laneguard.PowerControlRelay,
		StartedAt: started, RecordedAt: started.Add(2 * time.Second),
		PowerOffObservedAt: started.Add(time.Second), USBAbsentObservedAt: started.Add(2 * time.Second),
		ColdIntervalEndsAt: started.Add(4 * time.Second), PromptID: "hold_prompt",
		PromptDigest: digest("a"), PromptExpiresAt: started.Add(2 * time.Minute),
	})
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionAwaitingOperator
	transition.UpdatedAt = transition.ColdIntervalEndsAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionOperatorAcknowledged
	transition.Operator = laneguard.OperatorPeer{UID: 1000, GID: 1000, PID: int32(2000 + ordinal)}
	transition.OperatorAcknowledgedAt = transition.ColdIntervalEndsAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorAcknowledgedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionPowerEstablished
	transition.PowerEstablishedAt = transition.OperatorAcknowledgedAt.Add(time.Second)
	transition.UpdatedAt = transition.PowerEstablishedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionModeObserved
	transition.ModeObservedAt = transition.PowerEstablishedAt.Add(time.Second)
	transition.ObservedMode = action.RequestedBootMode
	transition.RPIBootSysfsPath = config.RPIBootSysfsPath
	transition.RPIBootObservationMethod = laneguard.RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = 50 * time.Millisecond
	if action.RequestedBootMode == laneguard.BootModeRPIBoot {
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
		return laneguard.BootTransitionOutcome{}, err
	}
	if action.RequestedBootMode == laneguard.BootModeRPIBoot {
		transition.Status = laneguard.BootTransitionOperatorReleased
		transition.ReleaseOperator = transition.Operator
		transition.OperatorReleasedAt = transition.ModeObservedAt.Add(time.Second)
		transition.UpdatedAt = transition.OperatorReleasedAt
		if err := journal.PutBootTransition(transition); err != nil {
			return laneguard.BootTransitionOutcome{}, err
		}
	}
	transition.Status = laneguard.BootTransitionCompleted
	transition.SafeOffObservedAt = transition.ModeObservedAt.Add(2 * time.Second)
	if !transition.OperatorReleasedAt.IsZero() {
		transition.SafeOffObservedAt = transition.OperatorReleasedAt.Add(time.Second)
	}
	transition.CompletedAt = transition.SafeOffObservedAt
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	return transition.Outcome()
}

func newFixture(t *testing.T) fixture {
	return newFixtureWithDraftInput(t, testDraftInput(testNow()))
}

func newFixtureWithDraftInput(t *testing.T, draftInput DraftInput) fixture {
	t.Helper()
	now := testNow()
	operations := campaign.DevelopmentOperations()
	operationNames := make([]string, len(operations))
	for index, operation := range operations {
		operationNames[index] = string(operation)
	}

	control, err := controlplane.NewService(&controlplane.MemoryStore{},
		controlplane.WithClock(func() time.Time { return now }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) { return prefix + "-fixture", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	transaction, err := control.CreateTransaction(ctx, controlplane.CreateTransactionRequest{
		SchemaVersion: controlplane.CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-fixture",
		TransactionID: "transaction-fixture", AssetID: "asset-fixture", IntendedLogicalID: "device-fixture",
		ProfileID: "rpi5-v1", BundleDigest: digest("1"), PolicyDigest: digest("2"),
		ExpectedPrestateCustomerKeyHash: digest("0"), ExpectedCustomerKeyHash: digest("3"),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
		SchemaVersion: controlplane.AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-fixture",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-fixture", LaneID: "lane-fixture", Mode: controlplane.ClaimModeMutation,
		AllowedStages: operationNames, LeaseDurationSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.BindTarget(ctx, controlplane.BindTargetRequest{
		SchemaVersion: controlplane.BindTargetRequestSchemaVersion, IdempotencyKey: "target-fixture",
		MutationContext: mutationContext(transaction), TargetFingerprint: digest("4"),
		ObservationDigest: digest("5"), CustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	draft, err := BuildDraft(draftInput)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := auditlog.NewService(&auditlog.MemoryStore{}, auditlog.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	approvalReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "approval-audit-fixture",
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: "approval-fixture", TransactionID: transaction.ID,
			StationID: transaction.ActiveClaim.StationID, LaneID: transaction.ActiveClaim.LaneID,
			Stage: "plan_approval", FenceEpoch: transaction.FenceEpoch,
			InputDigest: draft.PlanDigest(), Result: auditlog.ResultIntentRecorded,
			Actors:       []auditlog.Actor{{ID: "approver-fixture", Role: "approver"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	release := testRelease()
	transaction, err = control.RecordApproval(ctx, controlplane.RecordApprovalRequest{
		SchemaVersion: controlplane.RecordApprovalRequestSchemaVersion, IdempotencyKey: "approval-fixture",
		MutationContext: mutationContext(transaction), ApprovalID: "approval-fixture", ApproverID: "approver-fixture",
		TransactionDigest: transaction.TransactionDigest, PlanDigest: draft.PlanDigest(),
		TargetFingerprint: transaction.Target.Fingerprint, Release: release,
		AllowedOperations: operationNames, AuditReceiptID: approvalReceipt.ReceiptID,
		ExpiresAt: draft.Snapshot().ApprovalExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "intent-fixture",
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: "operation-fixture", TransactionID: transaction.ID,
			StationID: transaction.ActiveClaim.StationID, LaneID: transaction.ActiveClaim.LaneID,
			Stage: operationNames[0], FenceEpoch: transaction.FenceEpoch,
			InputDigest: draft.PlanDigest(), Result: auditlog.ResultIntentRecorded,
			Actors:       []auditlog.Actor{{ID: "station-fixture", Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records := audit.Records(transaction.ID)
	if len(records) != 2 {
		t.Fatalf("audit records = %d", len(records))
	}
	transaction, err = control.RecordIntent(ctx, controlplane.RecordIntentRequest{
		SchemaVersion: controlplane.RecordIntentRequestSchemaVersion, IdempotencyKey: "control-intent-fixture",
		MutationContext: mutationContext(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-fixture", Operation: operationNames[0], PlanDigest: draft.PlanDigest(),
		InputDigest: draft.PlanDigest(), PrestateDigest: draft.InitialPrestateDigest(), AuditReceiptID: receipt.ReceiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{draft: draft, control: control, audit: audit, authority: Authority{
		Transaction:     transaction,
		ApprovalReceipt: approvalReceipt, ApprovalRecord: records[0],
		IntentReceipt: receipt, IntentRecord: records[1],
		Now: now, LeaseSafetyMargin: 30 * time.Second,
	}}
}

func testDraftInput(now time.Time) DraftInput {
	release := testRelease()
	fresh := laneguard.DirectState{
		CustomerKeyHash: ZeroCustomerKeyHash, EEPROMHash: digest("6"), EEPROMHashStatus: laneguard.EEPROMHashObserved,
		SecurityState: "fresh", PowerState: "powered_off",
	}
	return DraftInput{
		StationID: "station-fixture", LaneID: "lane-fixture", TransactionID: "transaction-fixture",
		PowerControlMode: laneguard.PowerControlRelay,
		Release:          release, TargetFingerprint: digest("4"), InitialObservationDigest: digest("5"), FenceEpoch: 1,
		ApprovalExpiresAt: now.Add(30 * time.Minute), InitialState: fresh,
		AuthorizationIDs: [7]string{
			"authorization-1", "authorization-2", "authorization-3", "authorization-4",
			"authorization-5", "authorization-6", "authorization-7",
		},
		MaximumDurations: [7]time.Duration{
			time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute,
		},
	}
}

func testRelease() releasebinding.Binding {
	return releasebinding.Binding{
		SignedReleaseManifestDigest: digest("1"), LaneGuardPackageDigest: digest("7"),
		CompiledArtifactSetDigest: digest("8"), ExpectedCustomerKeyHash: digest("3"),
		ExpectedEEPROMDigest: digest("9"), ExpectedBootImageDigest: digest("b"),
	}
}

func mutationContext(transaction controlplane.Transaction) controlplane.MutationContext {
	return controlplane.MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func transferFixtureToReconciliation(t *testing.T, fixture fixture, stationID, laneID string) Authority {
	t.Helper()
	return transferAuthorityToReconciliation(t, fixture, fixture.authority, stationID, laneID)
}

func transferAuthorityToReconciliation(t *testing.T, fixture fixture, authority Authority, stationID, laneID string) Authority {
	t.Helper()
	transaction := authority.Transaction
	transferred, err := fixture.control.TransferClaim(context.Background(), controlplane.TransferClaimRequest{
		SchemaVersion:  controlplane.TransferClaimRequestSchemaVersion,
		IdempotencyKey: "transfer-to-reconciliation",
		TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
		NewStationID: stationID, NewLaneID: laneID, Mode: controlplane.ClaimModeReconciliation,
		AllowedStages: []string{"reconciliation"}, LeaseDurationSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority.Transaction = transferred
	return authority
}

func uncertainFixtureToReconciliation(t *testing.T, fixture fixture) Authority {
	t.Helper()
	transaction, err := fixture.control.RecordEvidence(context.Background(), controlplane.RecordEvidenceRequest{
		SchemaVersion:  controlplane.RecordEvidenceRequestSchemaVersion,
		IdempotencyKey: "uncertain-evidence-fixture", MutationContext: mutationContext(fixture.authority.Transaction),
		OperationID: fixture.authority.Transaction.Operations[0].ID,
		Result:      controlplane.EvidenceUncertain, OutputDigest: digest("c"), ObservationDigest: digest("d"),
		AuditReceiptID: digest("e"),
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := fixture.authority
	authority.Transaction = transaction
	return transferAuthorityToReconciliation(t, fixture, authority, "station-recovery", "lane-recovery")
}

func cloneAuthority(t *testing.T, authority Authority) Authority {
	t.Helper()
	encoded, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	var clone Authority
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(authority, clone) {
		t.Fatal("authority clone changed representation")
	}
	return clone
}

func rehashIntentAuthority(authority *Authority) {
	authority.IntentRecord.EventHash = auditEventHash(authority.IntentRecord)
	authority.IntentReceipt.EventHash = authority.IntentRecord.EventHash
	authority.IntentReceipt.ReceiptID = auditReceiptID(authority.IntentRecord.EventHash)
	authority.Transaction.Operations[len(authority.Transaction.Operations)-1].IntentAuditReceiptID = authority.IntentReceipt.ReceiptID
}

func advanceFixtureToSecondIntent(t *testing.T, fixture fixture) Authority {
	t.Helper()
	ctx := context.Background()
	transaction := fixture.authority.Transaction
	now := fixture.authority.Now
	first := fixture.draft.plan.Operations[0]
	evidenceReceipt, err := fixture.audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "evidence-audit-fixture",
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: "evidence-operation-fixture", TransactionID: transaction.ID,
			StationID: transaction.ActiveClaim.StationID, LaneID: transaction.ActiveClaim.LaneID,
			Stage: string(first.Operation), FenceEpoch: transaction.FenceEpoch,
			InputDigest: fixture.draft.PlanDigest(), OutputDigest: digest("c"), Result: auditlog.ResultSucceeded,
			Actors:       []auditlog.Actor{{ID: "station-fixture", Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = fixture.control.RecordEvidence(ctx, controlplane.RecordEvidenceRequest{
		SchemaVersion: controlplane.RecordEvidenceRequestSchemaVersion, IdempotencyKey: "evidence-fixture",
		MutationContext: mutationContext(transaction), OperationID: transaction.Operations[0].ID,
		Result: controlplane.EvidenceSucceeded, OutputDigest: digest("c"), ObservationDigest: digest("d"),
		AuditReceiptID: evidenceReceipt.ReceiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.draft.plan.Operations[1]
	intentReceipt, err := fixture.audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "intent-2-audit-fixture",
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: "operation-2-fixture", TransactionID: transaction.ID,
			StationID: transaction.ActiveClaim.StationID, LaneID: transaction.ActiveClaim.LaneID,
			Stage: string(second.Operation), FenceEpoch: transaction.FenceEpoch,
			InputDigest: fixture.draft.PlanDigest(), Result: auditlog.ResultIntentRecorded,
			Actors:       []auditlog.Actor{{ID: "station-fixture", Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = fixture.control.RecordIntent(ctx, controlplane.RecordIntentRequest{
		SchemaVersion: controlplane.RecordIntentRequestSchemaVersion, IdempotencyKey: "control-intent-2-fixture",
		MutationContext: mutationContext(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-2-fixture", Operation: string(second.Operation), PlanDigest: fixture.draft.PlanDigest(),
		InputDigest: fixture.draft.PlanDigest(), PrestateDigest: prestateDigest(second.ExpectedPrestate),
		AuditReceiptID: intentReceipt.ReceiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	records := fixture.audit.Records(transaction.ID)
	if len(records) != 4 {
		t.Fatalf("audit records after second intent = %d", len(records))
	}
	authority := fixture.authority
	authority.Transaction = transaction
	authority.IntentReceipt = intentReceipt
	authority.IntentRecord = records[3]
	return authority
}

func testNow() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
