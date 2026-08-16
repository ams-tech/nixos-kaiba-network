package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type testFixture struct {
	t       *testing.T
	service *Service
	now     time.Time
	ids     int
}

func newTestFixture(t *testing.T, store Store) *testFixture {
	t.Helper()
	fixture := &testFixture{t: t, now: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	service, err := NewService(store,
		WithClock(func() time.Time { return fixture.now }),
		WithIDGenerator(func(prefix string) (string, error) {
			fixture.ids++
			return prefix + "-test-" + number(fixture.ids), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	return fixture
}

func TestSecurityAppliedWorkflowIsDurableAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	fixture := newTestFixture(t, FileStore{Path: path})
	transaction := fixture.createClaimBindApprove([]string{"commit_security"})

	intentRequest := RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-1",
		MutationContext: contextFor(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-1", Operation: "commit_security", PlanDigest: transaction.Approval.PlanDigest,
		InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	}
	transaction = fixture.intent(intentRequest)
	if transaction.Status != StatusMutationInProgress {
		t.Fatalf("intent status = %q", transaction.Status)
	}
	evidenceRequest := RecordEvidenceRequest{
		SchemaVersion: RecordEvidenceRequestSchemaVersion, IdempotencyKey: "evidence-1",
		MutationContext: contextFor(transaction), OperationID: "operation-1", Result: EvidenceSucceeded,
		OutputDigest: digest("9"), ObservationDigest: digest("a"), AuditReceiptID: digest("b"),
	}
	transaction = fixture.evidence(evidenceRequest)
	replayed, err := fixture.service.RecordEvidence(context.Background(), evidenceRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ResourceVersion != transaction.ResourceVersion {
		t.Fatalf("idempotent replay changed version: %d != %d", replayed.ResourceVersion, transaction.ResourceVersion)
	}
	securityRequest := SecurityAppliedRequest{
		SchemaVersion: SecurityAppliedRequestSchemaVersion, IdempotencyKey: "security-applied-1",
		MutationContext: contextFor(transaction), PlanDigest: transaction.Approval.PlanDigest,
		EvidenceDigest: digest("c"), AuditReceiptID: digest("d"),
		RollbackStatus: "rollback_unimplemented", ReleaseClassification: "development_asset",
	}
	transaction, err = fixture.service.MarkSecurityApplied(context.Background(), securityRequest)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != StatusSecurityApplied || transaction.SecurityApplied == nil {
		t.Fatalf("terminal transaction = %#v", transaction)
	}
	release := ReleaseClaimRequest{
		SchemaVersion: ReleaseClaimRequestSchemaVersion, IdempotencyKey: "release-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
	transaction, err = fixture.service.ReleaseClaim(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.ActiveClaim != nil || len(transaction.ClaimHistory) != 1 || transaction.ClaimHistory[0].Status != ClaimReleased {
		t.Fatalf("released transaction = %#v", transaction)
	}

	reopened, err := NewService(FileStore{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != StatusSecurityApplied || persisted.ResourceVersion != transaction.ResourceVersion {
		t.Fatalf("persisted transaction = %#v", persisted)
	}
}

func TestTransferIncrementsFenceAndInvalidatesApproval(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.createClaimBindApprove([]string{"commit_security"})
	oldClaim := *transaction.ActiveClaim
	transfer := TransferClaimRequest{
		SchemaVersion: TransferClaimRequestSchemaVersion, IdempotencyKey: "transfer-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: oldClaim.ID, FenceEpoch: oldClaim.FenceEpoch,
		NewStationID: "station-2", NewLaneID: "lane-2", Mode: ClaimModeMutation,
		AllowedStages: []string{"commit_security"}, LeaseDurationSeconds: 300,
	}
	transaction, err := fixture.service.TransferClaim(context.Background(), transfer)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.FenceEpoch != oldClaim.FenceEpoch+1 || transaction.Approval != nil || transaction.Status != StatusTargetBound {
		t.Fatalf("transferred transaction = %#v", transaction)
	}
	stale := RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "stale-intent",
		MutationContext: MutationContext{TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion, ClaimID: oldClaim.ID, FenceEpoch: oldClaim.FenceEpoch},
		ApprovalID:      "approval-1", OperationID: "operation-1", Operation: "commit_security",
		PlanDigest: digest("5"), InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	}
	if _, err := fixture.service.RecordIntent(context.Background(), stale); !errors.Is(err, ErrStaleFence) && !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("stale intent error = %v", err)
	}

	approval := fixture.approvalRequest(transaction, []string{"commit_security"}, "approval-2")
	if _, err := fixture.service.RecordApproval(context.Background(), approval); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("approval without current-epoch reidentification error = %v", err)
	}
	rebind := BindTargetRequest{
		SchemaVersion: BindTargetRequestSchemaVersion, IdempotencyKey: "rebind-2",
		MutationContext: contextFor(transaction), TargetFingerprint: digest("3"),
		ObservationDigest: digest("e"), CustomerKeyHash: digest("2"),
	}
	transaction, err = fixture.service.BindTarget(context.Background(), rebind)
	if err != nil {
		t.Fatal(err)
	}
	changedTarget := rebind
	changedTarget.IdempotencyKey = "changed-target"
	changedTarget.ExpectedResourceVersion = transaction.ResourceVersion
	changedTarget.TargetFingerprint = digest("f")
	if _, err := fixture.service.BindTarget(context.Background(), changedTarget); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed target error = %v", err)
	}
}

func TestExpiredInFlightClaimEntersReadOnlyReconciliationAndUnknownQuarantines(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.createClaimBindApprove([]string{"commit_security"})
	transaction = fixture.intent(RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-1",
		MutationContext: contextFor(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-1", Operation: "commit_security", PlanDigest: transaction.Approval.PlanDigest,
		InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	})
	fixture.now = fixture.now.Add(10 * time.Minute)
	reconcileClaim := AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "reconcile-claim",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeReconciliation,
		AllowedStages: []string{"reconciliation"}, LeaseDurationSeconds: 300,
	}
	transaction, err := fixture.service.AcquireClaim(context.Background(), reconcileClaim)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != StatusReconciliationRequired || transaction.ActiveClaim.Mode != ClaimModeReconciliation || transaction.FenceEpoch != 2 {
		t.Fatalf("reconciliation claim = %#v", transaction)
	}
	reconcile := RecordReconciliationRequest{
		SchemaVersion: RecordReconciliationRequestSchemaVersion, IdempotencyKey: "reconcile-1",
		MutationContext: contextFor(transaction), OperationID: "operation-1", Resolution: ResolutionUnknown,
		ObservationDigest: digest("a"), AuditReceiptID: digest("b"),
	}
	transaction, err = fixture.service.RecordReconciliation(context.Background(), reconcile)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != StatusQuarantined || transaction.Quarantine == nil || transaction.Approval != nil {
		t.Fatalf("unknown reconciliation = %#v", transaction)
	}
	intent := RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "forbidden-retry",
		MutationContext: contextFor(transaction), ApprovalID: "approval-2", OperationID: "operation-2",
		Operation: "commit_security", PlanDigest: digest("5"), InputDigest: digest("6"),
		PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	}
	if _, err := fixture.service.RecordIntent(context.Background(), intent); err == nil {
		t.Fatal("quarantined transaction accepted a blind retry")
	}
}

func TestOptimisticVersionAndIdempotencyConflictsFailClosed(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.create()
	request := AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: []string{"commit_security"}, LeaseDurationSeconds: 300,
	}
	claimed, err := fixture.service.AcquireClaim(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	badVersion := request
	badVersion.IdempotencyKey = "claim-bad-version"
	if _, err := fixture.service.AcquireClaim(context.Background(), badVersion); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("version error = %v", err)
	}
	changedReplay := request
	changedReplay.ExpectedResourceVersion = claimed.ResourceVersion
	changedReplay.LaneID = "lane-2"
	if _, err := fixture.service.AcquireClaim(context.Background(), changedReplay); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency error = %v", err)
	}
}

func TestDecodeStrictRejectsUnknownSecretAndDuplicateFields(t *testing.T) {
	var request CreateTransactionRequest
	if err := DecodeStrict([]byte(`{"schema_version":"a","schema_version":"b"}`), &request); err == nil {
		t.Fatal("duplicate field was accepted")
	}
	if err := DecodeStrict([]byte(`{"schema_version":"x","private_key":"secret"}`), &request); err == nil {
		t.Fatal("unknown secret-bearing field was accepted")
	}
}

func (fixture *testFixture) create() Transaction {
	fixture.t.Helper()
	transaction, err := fixture.service.CreateTransaction(context.Background(), CreateTransactionRequest{
		SchemaVersion: CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-1",
		TransactionID: "transaction-1", AssetID: "asset-1", IntendedLogicalID: "device-1",
		ProfileID: "rpi5-v1", BundleDigest: digest("0"), PolicyDigest: digest("1"), ExpectedCustomerKeyHash: digest("2"),
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func (fixture *testFixture) createClaimBindApprove(operations []string) Transaction {
	fixture.t.Helper()
	transaction := fixture.create()
	var err error
	transaction, err = fixture.service.AcquireClaim(context.Background(), AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: operations, LeaseDurationSeconds: 300,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	transaction, err = fixture.service.BindTarget(context.Background(), BindTargetRequest{
		SchemaVersion: BindTargetRequestSchemaVersion, IdempotencyKey: "bind-1",
		MutationContext: contextFor(transaction), TargetFingerprint: digest("3"),
		ObservationDigest: digest("4"), CustomerKeyHash: digest("2"),
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	transaction, err = fixture.service.RecordApproval(context.Background(), fixture.approvalRequest(transaction, operations, "approval-1"))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func (fixture *testFixture) approvalRequest(transaction Transaction, operations []string, approvalID string) RecordApprovalRequest {
	return RecordApprovalRequest{
		SchemaVersion: RecordApprovalRequestSchemaVersion, IdempotencyKey: "record-" + approvalID,
		MutationContext: contextFor(transaction), ApprovalID: approvalID, ApproverID: "approver-1",
		TransactionDigest: transaction.TransactionDigest, PlanDigest: digest("5"),
		TargetFingerprint: transaction.Target.Fingerprint, ExpectedCustomerKeyHash: transaction.ExpectedCustomerKeyHash,
		AllowedOperations: operations, AuditReceiptID: digest("a"), ExpiresAt: fixture.now.Add(30 * time.Minute),
	}
}

func (fixture *testFixture) intent(request RecordIntentRequest) Transaction {
	fixture.t.Helper()
	transaction, err := fixture.service.RecordIntent(context.Background(), request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func (fixture *testFixture) evidence(request RecordEvidenceRequest) Transaction {
	fixture.t.Helper()
	transaction, err := fixture.service.RecordEvidence(context.Background(), request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func contextFor(transaction Transaction) MutationContext {
	return MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func digest(character string) string {
	value := "sha256:"
	for len(value) < len("sha256:")+64 {
		value += character
	}
	return value
}

func number(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return string(digits[value/10]) + string(digits[value%10])
}
