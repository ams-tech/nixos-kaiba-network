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

func TestHappyPathBuildsAndBindsExactOrderedRequests(t *testing.T) {
	fixture := newFixture(t)
	bound, err := Bind(fixture.draft, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	plan := bound.Plan()
	if plan.ApprovalID != fixture.authority.Transaction.Approval.ID || plan.IntentReceipt != fixture.authority.IntentReceipt.ReceiptID {
		t.Fatalf("authority envelope = %q/%q", plan.ApprovalID, plan.IntentReceipt)
	}
	wantOwnedState := laneguard.DirectState{
		CustomerKeyHash: plan.Release.ExpectedCustomerKeyHash,
		EEPROMHash:      plan.Release.ExpectedEEPROMDigest,
		SecurityState:   "owned",
		PowerState:      "powered_off",
	}
	requests := bound.ExecuteRequests()
	wantOperations := campaign.DevelopmentOperations()
	if len(requests) != len(wantOperations) || len(plan.Operations) != len(wantOperations) {
		t.Fatalf("request/operation count = %d/%d", len(requests), len(plan.Operations))
	}
	config := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/compiler-test",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
	}
	for index, request := range requests {
		if request.Sequence != uint32(index+1) || plan.Operations[index].Operation != wantOperations[index] {
			t.Fatalf("request %d is out of order", index+1)
		}
		if request.ClaimExpiresAt != fixture.authority.Transaction.ActiveClaim.ExpiresAt {
			t.Fatalf("request %d claim expiry = %s", index+1, request.ClaimExpiresAt)
		}
		if err := laneguard.ValidatePlanRequest(config, plan, request); err != nil {
			t.Fatalf("request %d: %v", index+1, err)
		}
		if plan.Operations[index].ExpectedPoststate != wantOwnedState {
			t.Fatalf("operation %d poststate = %#v, want release-bound powered-off state", index+1, plan.Operations[index].ExpectedPoststate)
		}
	}
	requests[0].ApprovalID = "changed"
	plan.Operations[0].AuthorizationID = "changed"
	if rebound := bound.Plan(); rebound.ApprovalID == "changed" || rebound.Operations[0].AuthorizationID == "changed" {
		t.Fatal("bound plan exposed caller-owned mutable state")
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
}

func newFixture(t *testing.T) fixture {
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

	draft, err := BuildDraft(testDraftInput(now))
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
		AllowedOperations: operationNames, AuditReceiptID: approvalReceipt.ReceiptID, ExpiresAt: now.Add(30 * time.Minute),
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
	return fixture{draft: draft, authority: Authority{
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

func testNow() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
