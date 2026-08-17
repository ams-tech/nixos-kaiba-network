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
	wantOwnedState := laneguard.DirectState{
		CustomerKeyHash: plan.Release.ExpectedCustomerKeyHash,
		EEPROMHash:      plan.Release.ExpectedEEPROMDigest,
		SecurityState:   "owned",
		PowerState:      "powered_off",
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
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-test",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
	}
	if request.Sequence != 1 || plan.Operations[0].Operation != wantOperations[0] {
		t.Fatal("current request is not the first approved operation")
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
		if plan.Operations[index].ExpectedPoststate != wantOwnedState {
			t.Fatalf("operation %d poststate = %#v, want release-bound powered-off state", index+1, plan.Operations[index].ExpectedPoststate)
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
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-public-api",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17}, LeaseSafetyMargin: 30 * time.Second,
	}
	hardware := &boundPlanTestHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: request.TargetFingerprint, State: request.ExpectedPrestate,
		},
		poststate: draftSnapshot.Operations[0].ExpectedPoststate,
	}
	guard, err := laneguard.NewWithClock(config, hardware, laneguard.NewMemoryStore(), boundPlanTestClock{fixture.authority.Now})
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
	request.ExpectedPrestate = later.ExpectedPrestate
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
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
	if request.Sequence != 2 || request.IntentReceipt != authority.IntentReceipt.ReceiptID {
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
		"identity":       func(value *DraftInput) { value.StationID = "bad id" },
		"target":         func(value *DraftInput) { value.TargetFingerprint = "bad" },
		"fence":          func(value *DraftInput) { value.FenceEpoch = 0 },
		"release":        func(value *DraftInput) { value.Release.ExpectedEEPROMDigest = "bad" },
		"expiry":         func(value *DraftInput) { value.ApprovalExpiresAt = time.Time{} },
		"initial state":  func(value *DraftInput) { value.InitialState.PowerState = "" },
		"initial mode":   func(value *DraftInput) { value.InitialState.PowerState = "rpiboot" },
		"initial digest": func(value *DraftInput) { value.InitialState.EEPROMHash = "not-a-digest" },
		"initial key":    func(value *DraftInput) { value.InitialState.CustomerKeyHash = digest("d") },
		"zero owned key": func(value *DraftInput) { value.Release.ExpectedCustomerKeyHash = ZeroCustomerKeyHash },
		"authorization":  func(value *DraftInput) { value.AuthorizationIDs[3] = "bad id" },
		"duration":       func(value *DraftInput) { value.MaximumDurations[5] = 0 },
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

type fixture struct {
	draft     Draft
	authority Authority
	control   *controlplane.Service
	audit     *auditlog.Service
}

type boundPlanTestClock struct{ now time.Time }

func (clock boundPlanTestClock) Now() time.Time { return clock.now }

type boundPlanTestHardware struct {
	observation laneguard.Observation
	poststate   laneguard.DirectState
}

func (hardware *boundPlanTestHardware) Observe(context.Context, laneguard.Config) (laneguard.Observation, error) {
	return hardware.observation, nil
}

func (hardware *boundPlanTestHardware) Execute(_ context.Context, _ laneguard.Config, _ laneguard.Operation) (laneguard.OperationResult, error) {
	hardware.observation.State = hardware.poststate
	return laneguard.OperationResult{OutputDigest: digest("f"), Detail: "compiler public API test"}, nil
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
		CustomerKeyHash: digest("0"), EEPROMHash: digest("6"), SecurityState: "fresh", PowerState: "powered_off",
	}
	return DraftInput{
		StationID: "station-fixture", LaneID: "lane-fixture", TransactionID: "transaction-fixture",
		Release: release, TargetFingerprint: digest("4"), FenceEpoch: 1,
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
