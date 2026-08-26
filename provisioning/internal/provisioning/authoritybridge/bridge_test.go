package authoritybridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

type controlReaderFunc func(context.Context, string) (controlplane.Transaction, error)

func (function controlReaderFunc) GetTransaction(ctx context.Context, transactionID string) (controlplane.Transaction, error) {
	return function(ctx, transactionID)
}

type auditReaderFunc func(context.Context, string) ([]auditlog.Record, error)

func (function auditReaderFunc) GetRecordsByReceiptIDs(ctx context.Context, transactionID string, _ []string) ([]auditlog.Record, error) {
	return function(ctx, transactionID)
}

type bridgeFixture struct {
	now               time.Time
	request           BridgeRequest
	transaction       controlplane.Transaction
	records           []auditlog.Record
	approvalReceiptID string
	intentReceiptID   string
}

func TestBinderReturnsOnlyTheCurrentAuthenticatedExecution(t *testing.T) {
	fixture := newBridgeFixture(t)
	controlCalls := 0
	binder := Binder{
		Control: controlReaderFunc(func(_ context.Context, transactionID string) (controlplane.Transaction, error) {
			controlCalls++
			if transactionID != fixture.transaction.ID {
				t.Fatalf("control transaction = %q", transactionID)
			}
			return fixture.transaction, nil
		}),
		Audit: auditReaderFunc(func(_ context.Context, transactionID string) ([]auditlog.Record, error) {
			if transactionID != fixture.transaction.ID {
				t.Fatalf("audit transaction = %q", transactionID)
			}
			return fixture.records, nil
		}),
		Now: func() time.Time { return fixture.now }, LeaseSafetyMargin: 30 * time.Second,
	}
	execution, err := binder.Bind(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if controlCalls != 2 {
		t.Fatalf("control reads = %d, want 2", controlCalls)
	}
	if execution.ExecuteRequest == nil || execution.ReconcileRequest != nil || execution.ExecuteRequest.Sequence != 1 || execution.Plan.IntentSequence != 1 ||
		execution.Plan.IntentReceipt != fixture.intentReceiptID ||
		execution.Plan.ApprovalID != fixture.transaction.Approval.ID {
		t.Fatalf("bound execution = %#v / %#v", execution.Plan, execution.ExecuteRequest)
	}
	if execution.ExecuteRequest.ClaimExpiresAt != fixture.transaction.ActiveClaim.ExpiresAt {
		t.Fatalf("claim expiry = %s", execution.ExecuteRequest.ClaimExpiresAt)
	}
	if execution.ExecuteRequest.RequiredBootMode != laneguard.BootModeRPIBoot ||
		execution.ExecuteRequest.RequiredBootMode != execution.Plan.Operations[0].RequiredBootMode {
		t.Fatalf("bound boot mode = %q / %q", execution.ExecuteRequest.RequiredBootMode, execution.Plan.Operations[0].RequiredBootMode)
	}
	if execution.Plan.PlanDigest != fixture.request.DraftSnapshot.PlanDigest {
		t.Fatal("bridge changed the approved plan digest")
	}
}

func TestBinderRejectsTamperedOrAuthoritativeDraftSnapshot(t *testing.T) {
	fixture := newBridgeFixture(t)
	tests := map[string]func(*BridgeRequest){
		"operation body": func(request *BridgeRequest) {
			request.DraftSnapshot.Operations[0].MaximumDuration++
		},
		"required boot mode": func(request *BridgeRequest) {
			request.DraftSnapshot.Operations[0].RequiredBootMode = laneguard.BootModeNormal
		},
		"operation digest": func(request *BridgeRequest) {
			request.DraftSnapshot.Operations[0].OperationDigest = bridgeDigest("f")
		},
		"plan digest": func(request *BridgeRequest) {
			request.DraftSnapshot.PlanDigest = bridgeDigest("e")
		},
		"approval envelope": func(request *BridgeRequest) {
			request.DraftSnapshot.ApprovalID = "caller-approval"
		},
		"intent envelope": func(request *BridgeRequest) {
			request.DraftSnapshot.IntentReceipt = bridgeDigest("d")
			request.DraftSnapshot.IntentSequence = 1
		},
		"transaction mismatch": func(request *BridgeRequest) {
			request.TransactionID = "transaction-other"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneBridgeRequest(fixture.request)
			mutate(&request)
			binder := Binder{
				Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
					t.Fatal("invalid draft reached the authority source")
					return controlplane.Transaction{}, nil
				}),
				Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
					t.Fatal("invalid draft reached the authority source")
					return nil, nil
				}),
			}
			if _, err := binder.Bind(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Bind() error = %v", err)
			}
		})
	}
}

func TestBridgeSchemaVersionsTrackDigestBoundBootModeWireChange(t *testing.T) {
	if RequestSchemaVersion != "provisioning.kaiba.network/authority-bridge-request/v1alpha3" ||
		ResponseSchemaVersion != "provisioning.kaiba.network/authority-bridge-response/v1alpha3" {
		t.Fatalf("authority bridge schemas = %q / %q", RequestSchemaVersion, ResponseSchemaVersion)
	}

	fixture := newBridgeFixture(t)
	request := cloneBridgeRequest(fixture.request)
	request.SchemaVersion = "provisioning.kaiba.network/authority-bridge-request/v1alpha2"
	binder := Binder{
		Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
			t.Fatal("previous wire schema reached the authority source")
			return controlplane.Transaction{}, nil
		}),
		Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
			t.Fatal("previous wire schema reached the authority source")
			return nil, nil
		}),
	}
	if _, err := binder.Bind(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Bind() error = %v", err)
	}
}

func TestBinderRejectsControlSnapshotChangeAcrossAuditRead(t *testing.T) {
	fixture := newBridgeFixture(t)
	changed := fixture.transaction
	changed.UpdatedAt = changed.UpdatedAt.Add(time.Nanosecond)
	reads := 0
	binder := Binder{
		Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
			reads++
			if reads == 1 {
				return fixture.transaction, nil
			}
			return changed, nil
		}),
		Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
			return fixture.records, nil
		}),
		Now: func() time.Time { return fixture.now },
	}
	if _, err := binder.Bind(context.Background(), fixture.request); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("Bind() error = %v", err)
	}
	if reads != 2 {
		t.Fatalf("control reads = %d", reads)
	}
}

func TestBinderRejectsExpiredApprovalAndInsufficientClaimLease(t *testing.T) {
	fixture := newBridgeFixture(t)
	t.Run("expired approval", func(t *testing.T) {
		binder := fixedBinder(fixture, fixture.records)
		binder.Now = func() time.Time { return fixture.transaction.Approval.ExpiresAt }
		if _, err := binder.Bind(context.Background(), fixture.request); !errors.Is(err, ErrAuthorityRejected) || !errors.Is(err, plancompiler.ErrApprovalExpired) {
			t.Fatalf("Bind() error = %v", err)
		}
	})
	t.Run("insufficient claim lease", func(t *testing.T) {
		current := fixture
		current.transaction = cloneBridgeTransaction(t, fixture.transaction)
		current.transaction.ActiveClaim.ExpiresAt = current.now.Add(time.Minute)
		binder := fixedBinder(current, current.records)
		if _, err := binder.Bind(context.Background(), current.request); !errors.Is(err, ErrAuthorityRejected) || !errors.Is(err, plancompiler.ErrStaleClaim) {
			t.Fatalf("Bind() error = %v", err)
		}
	})
}

func TestBinderFreezesFirstSnapshotBeforeAuditReaderCanMutateSharedValues(t *testing.T) {
	fixture := newBridgeFixture(t)
	shared := fixture.transaction
	binder := Binder{
		Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
			return shared, nil
		}),
		Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
			shared.ActiveClaim.ExpiresAt = shared.ActiveClaim.ExpiresAt.Add(time.Second)
			return fixture.records, nil
		}),
		Now: func() time.Time { return fixture.now },
	}
	if _, err := binder.Bind(context.Background(), fixture.request); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("Bind() error = %v", err)
	}
}

func TestBinderRequiresUniqueApprovalAndCurrentIntentRecords(t *testing.T) {
	fixture := newBridgeFixture(t)
	find := func(receiptID string) auditlog.Record {
		t.Helper()
		for _, record := range fixture.records {
			if receiptFromRecord(record).ReceiptID == receiptID {
				return record
			}
		}
		t.Fatalf("fixture record %q not found", receiptID)
		return auditlog.Record{}
	}
	tests := []struct {
		name    string
		records []auditlog.Record
		want    error
	}{
		{name: "missing approval", records: []auditlog.Record{find(fixture.intentReceiptID)}, want: ErrAuthorityRecordMissing},
		{name: "missing intent", records: []auditlog.Record{find(fixture.approvalReceiptID)}, want: ErrAuthorityRecordMissing},
		{name: "duplicate approval", records: append(append([]auditlog.Record(nil), fixture.records...), find(fixture.approvalReceiptID)), want: ErrAuthorityRecordDuplicate},
		{name: "duplicate intent", records: append(append([]auditlog.Record(nil), fixture.records...), find(fixture.intentReceiptID)), want: ErrAuthorityRecordDuplicate},
		{name: "unexpected record", records: append(append([]auditlog.Record(nil), fixture.records...), auditlog.Record{}), want: ErrAuthorityRecordUnexpected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binder := fixedBinder(fixture, test.records)
			if _, err := binder.Bind(context.Background(), fixture.request); !errors.Is(err, test.want) {
				t.Fatalf("Bind() error = %v", err)
			}
		})
	}
}

func TestReceiptReconstructionMatchesDurableAuditReceipts(t *testing.T) {
	fixture := newBridgeFixture(t)
	seen := map[string]bool{
		fixture.approvalReceiptID: false,
		fixture.intentReceiptID:   false,
	}
	for _, record := range fixture.records {
		receipt := receiptFromRecord(record)
		if _, expected := seen[receipt.ReceiptID]; expected {
			seen[receipt.ReceiptID] = true
		}
	}
	for receiptID, found := range seen {
		if !found {
			t.Fatalf("reconstructed receipt %q was not found", receiptID)
		}
	}
}

func TestBinderPropagatesAuthoritySourceFailuresWithoutUsingPartialState(t *testing.T) {
	fixture := newBridgeFixture(t)
	sourceErr := errors.New("authenticated service unavailable")
	tests := map[string]Binder{
		"first control read": {
			Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
				return controlplane.Transaction{}, sourceErr
			}),
			Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) { return fixture.records, nil }),
		},
		"audit read": {
			Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) { return fixture.transaction, nil }),
			Audit:   auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) { return nil, sourceErr }),
		},
		"second control read": secondReadErrorBinder(fixture, sourceErr),
	}
	for name, binder := range tests {
		t.Run(name, func(t *testing.T) {
			binder.Now = func() time.Time { return fixture.now }
			if _, err := binder.Bind(context.Background(), fixture.request); !errors.Is(err, ErrAuthoritySource) || !errors.Is(err, sourceErr) {
				t.Fatalf("Bind() error = %v", err)
			}
		})
	}
}

func TestBinderRejectsReconciliationWithoutAReconciliationClaim(t *testing.T) {
	fixture := newBridgeFixture(t)
	request := fixture.request
	request.Mode = ModeReconcile
	binder := fixedBinder(fixture, fixture.records)
	if _, err := binder.Bind(context.Background(), request); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("Bind() error = %v", err)
	}
}

func TestBinderReconstructsExpiredAttemptUnderFreshReconciliationClaim(t *testing.T) {
	fixture := newReconciliationBridgeFixture(t, "station-reconcile", "lane-reconcile")
	binding, err := fixedBinder(fixture, fixture.records).Bind(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if binding.ExecuteRequest != nil || binding.ReconcileRequest == nil {
		t.Fatalf("binding is not a strict reconciliation union: %#v", binding)
	}
	reconcile := binding.ReconcileRequest
	if reconcile.OriginalRequest.FenceEpoch != fixture.request.DraftSnapshot.FenceEpoch ||
		reconcile.OriginalRequest.ApprovalID == "" || reconcile.OriginalRequest.IntentReceipt != fixture.intentReceiptID {
		t.Fatalf("original attempt authority changed: %#v", reconcile.OriginalRequest)
	}
	if reconcile.Claim.StationID != "station-reconcile" || reconcile.Claim.LaneID != "lane-reconcile" ||
		reconcile.Claim.FenceEpoch != fixture.transaction.FenceEpoch || reconcile.Claim.ClaimID != fixture.transaction.ActiveClaim.ID {
		t.Fatalf("current reconciliation authority = %#v", reconcile.Claim)
	}
	if !fixture.now.After(binding.Plan.ApprovalExpiresAt) {
		t.Fatal("fixture did not prove reconciliation after original approval expiry")
	}
}

func fixedBinder(fixture bridgeFixture, records []auditlog.Record) Binder {
	return Binder{
		Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
			return fixture.transaction, nil
		}),
		Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
			return records, nil
		}),
		Now: func() time.Time { return fixture.now }, LeaseSafetyMargin: 30 * time.Second,
	}
}

func secondReadErrorBinder(fixture bridgeFixture, sourceErr error) Binder {
	reads := 0
	return Binder{
		Control: controlReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
			reads++
			if reads == 1 {
				return fixture.transaction, nil
			}
			return controlplane.Transaction{}, sourceErr
		}),
		Audit: auditReaderFunc(func(context.Context, string) ([]auditlog.Record, error) {
			return fixture.records, nil
		}),
	}
}

func newBridgeFixture(t *testing.T) bridgeFixture {
	t.Helper()
	now := time.Date(2026, 8, 22, 16, 0, 0, 0, time.UTC)
	operations := campaign.DevelopmentOperations()
	operationNames := make([]string, len(operations))
	for index, operation := range operations {
		operationNames[index] = string(operation)
	}
	release := releasebinding.Binding{
		SignedReleaseManifestDigest: bridgeDigest("1"), LaneGuardPackageDigest: bridgeDigest("2"),
		CompiledArtifactSetDigest: bridgeDigest("3"), ExpectedCustomerKeyHash: bridgeDigest("4"),
		ExpectedEEPROMDigest: bridgeDigest("5"), ExpectedBootImageDigest: bridgeDigest("6"),
	}
	draft, err := plancompiler.BuildDraft(plancompiler.DraftInput{
		StationID: "station-bridge", LaneID: "lane-bridge", TransactionID: "transaction-bridge",
		Release: release, TargetFingerprint: bridgeDigest("7"), FenceEpoch: 1,
		ApprovalExpiresAt: now.Add(30 * time.Minute),
		InitialState: laneguard.DirectState{
			CustomerKeyHash: plancompiler.ZeroCustomerKeyHash, EEPROMHash: bridgeDigest("8"),
			SecurityState: "fresh", PowerState: "powered_off",
		},
		AuthorizationIDs: [7]string{"authorization-1", "authorization-2", "authorization-3", "authorization-4", "authorization-5", "authorization-6", "authorization-7"},
		MaximumDurations: [7]time.Duration{time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := controlplane.NewService(&controlplane.MemoryStore{},
		controlplane.WithClock(func() time.Time { return now }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) { return prefix + "-bridge", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	transaction, err := control.CreateTransaction(ctx, controlplane.CreateTransactionRequest{
		SchemaVersion: controlplane.CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-bridge",
		TransactionID: "transaction-bridge", AssetID: "asset-bridge", IntendedLogicalID: "logical-bridge", ProfileID: "rpi5-bridge",
		BundleDigest: release.SignedReleaseManifestDigest, PolicyDigest: bridgeDigest("9"),
		ExpectedPrestateCustomerKeyHash: plancompiler.ZeroCustomerKeyHash, ExpectedCustomerKeyHash: release.ExpectedCustomerKeyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
		SchemaVersion: controlplane.AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-bridge",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-bridge", LaneID: "lane-bridge", Mode: controlplane.ClaimModeMutation,
		AllowedStages: operationNames, LeaseDurationSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.BindTarget(ctx, controlplane.BindTargetRequest{
		SchemaVersion: controlplane.BindTargetRequestSchemaVersion, IdempotencyKey: "target-bridge",
		MutationContext: bridgeMutationContext(transaction), TargetFingerprint: bridgeDigest("7"),
		ObservationDigest: bridgeDigest("a"), CustomerKeyHash: plancompiler.ZeroCustomerKeyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := auditlog.NewService(&auditlog.MemoryStore{}, auditlog.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	approvalReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "approval-audit-bridge",
		Event: bridgeAuditEvent(draft, transaction, "approval-bridge", "plan_approval", auditlog.Actor{ID: "approver-bridge", Role: "approver"}, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.RecordApproval(ctx, controlplane.RecordApprovalRequest{
		SchemaVersion: controlplane.RecordApprovalRequestSchemaVersion, IdempotencyKey: "approval-control-bridge",
		MutationContext: bridgeMutationContext(transaction), ApprovalID: "approval-bridge", ApproverID: "approver-bridge",
		TransactionDigest: transaction.TransactionDigest, PlanDigest: draft.PlanDigest(), TargetFingerprint: bridgeDigest("7"),
		Release: release, AllowedOperations: operationNames, AuditReceiptID: approvalReceipt.ReceiptID,
		ExpiresAt: draft.Snapshot().ApprovalExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	intentReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "intent-audit-bridge",
		Event: bridgeAuditEvent(draft, transaction, "operation-bridge", operationNames[0], auditlog.Actor{ID: "station-bridge", Role: "provisioning_station"}, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.RecordIntent(ctx, controlplane.RecordIntentRequest{
		SchemaVersion: controlplane.RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-control-bridge",
		MutationContext: bridgeMutationContext(transaction), ApprovalID: "approval-bridge",
		OperationID: "operation-bridge", Operation: operationNames[0], PlanDigest: draft.PlanDigest(),
		InputDigest: draft.PlanDigest(), PrestateDigest: draft.InitialPrestateDigest(), AuditReceiptID: intentReceipt.ReceiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bridgeFixture{
		now: now, request: BridgeRequest{
			SchemaVersion: RequestSchemaVersion, Mode: ModeExecute,
			TransactionID: transaction.ID, DraftSnapshot: draft.Snapshot(),
		},
		transaction: transaction, records: audit.Records(transaction.ID),
		approvalReceiptID: approvalReceipt.ReceiptID, intentReceiptID: intentReceipt.ReceiptID,
	}
}

func newReconciliationBridgeFixture(t *testing.T, stationID, laneID string) bridgeFixture {
	t.Helper()
	fixture := newBridgeFixture(t)
	transaction := cloneBridgeTransaction(t, fixture.transaction)
	originalClaim := *transaction.ActiveClaim
	fixture.now = originalClaim.ExpiresAt.Add(time.Minute)
	closedAt := fixture.now
	originalClaim.Status = controlplane.ClaimExpired
	originalClaim.ClosedAt = &closedAt
	transaction.ClaimHistory = append(transaction.ClaimHistory, originalClaim)
	transaction.FenceEpoch++
	transaction.ResourceVersion++
	transaction.Status = controlplane.StatusReconciliationRequired
	transaction.Approval = nil
	transaction.ActiveClaim = &controlplane.Claim{
		ID: "claim-reconciliation", Mode: controlplane.ClaimModeReconciliation, Status: controlplane.ClaimActive,
		StationID: stationID, LaneID: laneID, AssetID: transaction.AssetID,
		FenceEpoch: transaction.FenceEpoch, AllowedStages: []string{"reconciliation"},
		AcquiredAt: fixture.now, ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
	transaction.UpdatedAt = fixture.now
	fixture.transaction = transaction
	fixture.request.Mode = ModeReconcile
	return fixture
}

func bridgeAuditEvent(draft plancompiler.Draft, transaction controlplane.Transaction, eventID, stage string, actor auditlog.Actor, now time.Time) auditlog.Event {
	return auditlog.Event{
		SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
		EventID: eventID, TransactionID: transaction.ID,
		StationID: "station-bridge", LaneID: "lane-bridge", Stage: stage, FenceEpoch: transaction.FenceEpoch,
		InputDigest: draft.PlanDigest(), Result: auditlog.ResultIntentRecorded, Actors: []auditlog.Actor{actor},
		TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
	}
}

func bridgeMutationContext(transaction controlplane.Transaction) controlplane.MutationContext {
	return controlplane.MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func cloneBridgeRequest(request BridgeRequest) BridgeRequest {
	request.DraftSnapshot.Operations = append([]laneguard.OperationSpec(nil), request.DraftSnapshot.Operations...)
	return request
}

func cloneBridgeTransaction(t *testing.T, transaction controlplane.Transaction) controlplane.Transaction {
	t.Helper()
	encoded, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	var clone controlplane.Transaction
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func bridgeDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
