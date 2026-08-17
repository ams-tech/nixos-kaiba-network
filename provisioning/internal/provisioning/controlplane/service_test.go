package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
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
	operations := developmentCampaignNames()
	transaction := fixture.createClaimBindApprove(operations)
	wantRelease := approvalRelease(transaction)
	if transaction.Approval == nil || transaction.Approval.Release != wantRelease {
		t.Fatalf("persisted approval release = %#v, want %#v", transaction.Approval, wantRelease)
	}

	for index, operation := range operations {
		sequence := number(index + 1)
		intentRequest := RecordIntentRequest{
			SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-" + sequence,
			MutationContext: contextFor(transaction), ApprovalID: transaction.Approval.ID,
			OperationID: "operation-" + sequence, Operation: operation, PlanDigest: transaction.Approval.PlanDigest,
			InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
		}
		transaction = fixture.intent(intentRequest)
		if transaction.Status != StatusMutationInProgress {
			t.Fatalf("intent %d status = %q", index+1, transaction.Status)
		}
		evidenceRequest := RecordEvidenceRequest{
			SchemaVersion: RecordEvidenceRequestSchemaVersion, IdempotencyKey: "evidence-" + sequence,
			MutationContext: contextFor(transaction), OperationID: "operation-" + sequence, Result: EvidenceSucceeded,
			OutputDigest: digest("9"), ObservationDigest: digest("a"), AuditReceiptID: digest("b"),
		}
		transaction = fixture.evidence(evidenceRequest)
		if index == 0 {
			replayed, err := fixture.service.RecordEvidence(context.Background(), evidenceRequest)
			if err != nil {
				t.Fatal(err)
			}
			if replayed.ResourceVersion != transaction.ResourceVersion {
				t.Fatalf("idempotent replay changed version: %d != %d", replayed.ResourceVersion, transaction.ResourceVersion)
			}
		}
	}
	securityRequest := SecurityAppliedRequest{
		SchemaVersion: SecurityAppliedRequestSchemaVersion, IdempotencyKey: "security-applied-1",
		MutationContext: contextFor(transaction), PlanDigest: transaction.Approval.PlanDigest,
		EvidenceDigest: digest("c"), AuditReceiptID: digest("d"),
		RollbackStatus: "rollback_unimplemented", ReleaseClassification: "development_asset",
	}
	transaction, err := fixture.service.MarkSecurityApplied(context.Background(), securityRequest)
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
	if persisted.Status != StatusSecurityApplied || persisted.ResourceVersion != transaction.ResourceVersion ||
		persisted.Approval == nil || persisted.Approval.Release != wantRelease {
		t.Fatalf("persisted transaction = %#v", persisted)
	}
}

func TestFreshTargetPrestateIsDistinctFromApprovedPoststate(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.create()
	if transaction.ExpectedPrestateCustomerKeyHash == transaction.ExpectedCustomerKeyHash {
		t.Fatal("test transaction does not distinguish fresh and post-commit customer keys")
	}
	transaction, err := fixture.service.AcquireClaim(context.Background(), AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-distinct-key-state",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := BindTargetRequest{
		SchemaVersion: BindTargetRequestSchemaVersion, IdempotencyKey: "bind-poststate-as-fresh",
		MutationContext: contextFor(transaction), TargetFingerprint: digest("3"),
		ObservationDigest: digest("4"), CustomerKeyHash: transaction.ExpectedCustomerKeyHash,
	}
	if _, err := fixture.service.BindTarget(context.Background(), wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-commit key accepted as fresh prestate: %v", err)
	}
	right := wrong
	right.IdempotencyKey = "bind-actual-fresh-prestate"
	right.CustomerKeyHash = transaction.ExpectedPrestateCustomerKeyHash
	bound, err := fixture.service.BindTarget(context.Background(), right)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Target == nil || bound.Target.CustomerKeyHash != transaction.ExpectedPrestateCustomerKeyHash {
		t.Fatalf("fresh target binding = %#v", bound.Target)
	}
}

func TestRecordApprovalRequiresCompleteDevelopmentCampaign(t *testing.T) {
	canonical := developmentCampaignNames()
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "truncated",
			mutate: func(operations []string) []string {
				return operations[:len(operations)-1]
			},
		},
		{
			name: "reordered",
			mutate: func(operations []string) []string {
				operations[2], operations[3] = operations[3], operations[2]
				return operations
			},
		},
		{
			name: "duplicated",
			mutate: func(operations []string) []string {
				operations[3] = operations[2]
				return operations
			},
		},
		{
			name: "inserted",
			mutate: func(operations []string) []string {
				return append(operations, "inserted_operation")
			},
		},
		{
			name: "renamed",
			mutate: func(operations []string) []string {
				operations[4] = "renamed_operation"
				return operations
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			transaction := fixture.createClaimBind(canonical)
			operations := append([]string(nil), canonical...)
			request := fixture.approvalRequest(transaction, test.mutate(operations), "approval-invalid")
			if _, err := fixture.service.RecordApproval(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want invalid request", err)
			}
			persisted, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.ResourceVersion != transaction.ResourceVersion || persisted.Status != StatusTargetBound || persisted.Approval != nil {
				t.Fatalf("rejected approval changed transaction: %#v", persisted)
			}
		})
	}
}

func TestRecordApprovalRequiresCompleteReleaseBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*releasebinding.Binding)
	}{
		{
			name: "signed release manifest digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.SignedReleaseManifestDigest = ""
			},
		},
		{
			name: "lane guard package digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.LaneGuardPackageDigest = ""
			},
		},
		{
			name: "compiled artifact set digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.CompiledArtifactSetDigest = ""
			},
		},
		{
			name: "expected customer key hash",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedCustomerKeyHash = ""
			},
		},
		{
			name: "expected EEPROM digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedEEPROMDigest = ""
			},
		},
		{
			name: "expected boot image digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedBootImageDigest = ""
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			transaction := fixture.createClaimBind(developmentCampaignNames())
			request := fixture.approvalRequest(transaction, developmentCampaignNames(), "approval-invalid-release")
			test.mutate(&request.Release)

			if _, err := fixture.service.RecordApproval(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want invalid request", err)
			}
			persisted, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.ResourceVersion != transaction.ResourceVersion || persisted.Status != StatusTargetBound || persisted.Approval != nil {
				t.Fatalf("rejected release binding changed transaction: %#v", persisted)
			}
		})
	}
}

func TestRecordApprovalRequiresReleaseBindingToMatchTransaction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*releasebinding.Binding)
	}{
		{
			name: "signed release manifest",
			mutate: func(binding *releasebinding.Binding) {
				binding.SignedReleaseManifestDigest = digest("f")
			},
		},
		{
			name: "expected customer key",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedCustomerKeyHash = digest("f")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			transaction := fixture.createClaimBind(developmentCampaignNames())
			request := fixture.approvalRequest(transaction, developmentCampaignNames(), "approval-mismatched-release")
			test.mutate(&request.Release)

			if _, err := fixture.service.RecordApproval(context.Background(), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want conflict", err)
			}
			persisted, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.ResourceVersion != transaction.ResourceVersion || persisted.Status != StatusTargetBound || persisted.Approval != nil {
				t.Fatalf("mismatched release binding changed transaction: %#v", persisted)
			}
		})
	}
}

func TestReapprovalCannotRelabelStartedPlanReleaseOrExpiry(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecordApprovalRequest)
	}{
		{
			name: "release binding",
			mutate: func(request *RecordApprovalRequest) {
				request.Release.ExpectedBootImageDigest = digest("f")
			},
		},
		{
			name: "approval expiry",
			mutate: func(request *RecordApprovalRequest) {
				request.ExpiresAt = request.ExpiresAt.Add(time.Minute)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			operations := developmentCampaignNames()
			transaction := fixture.createClaimBindApprove(operations)
			transaction = fixture.recordSuccessfulOperation(transaction, operations[0], 1)
			request := fixture.approvalRequest(transaction, operations, "approval-replacement")
			request.PlanDigest = transaction.Approval.PlanDigest
			request.Release = transaction.Approval.Release
			request.ExpiresAt = transaction.Approval.ExpiresAt
			test.mutate(&request)

			if _, err := fixture.service.RecordApproval(context.Background(), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("reapproval error = %v, want conflict", err)
			}
			persisted, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.ResourceVersion != transaction.ResourceVersion || persisted.Approval.ID != transaction.Approval.ID ||
				persisted.Approval.Release != transaction.Approval.Release || !persisted.Approval.ExpiresAt.Equal(transaction.Approval.ExpiresAt) {
				t.Fatalf("rejected reapproval changed transaction: %#v", persisted)
			}
		})
	}
}

func TestReapprovalMayReplaceExcludedEnvelopeWithoutChangingStartedPlan(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	operations := developmentCampaignNames()
	transaction := fixture.createClaimBindApprove(operations)
	transaction = fixture.recordSuccessfulOperation(transaction, operations[0], 1)
	request := fixture.approvalRequest(transaction, operations, "approval-replacement")
	request.PlanDigest = transaction.Approval.PlanDigest
	request.Release = transaction.Approval.Release
	request.ExpiresAt = transaction.Approval.ExpiresAt

	reapproved, err := fixture.service.RecordApproval(context.Background(), request)
	if err != nil {
		t.Fatalf("same-plan reapproval: %v", err)
	}
	if reapproved.Approval.ID != request.ApprovalID || reapproved.Approval.Release != transaction.Approval.Release ||
		!reapproved.Approval.ExpiresAt.Equal(transaction.Approval.ExpiresAt) {
		t.Fatalf("reapproval = %#v", reapproved.Approval)
	}
}

func TestReapprovalAfterClaimTransferCannotRelabelStartedPlan(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecordApprovalRequest)
	}{
		{
			name: "release binding",
			mutate: func(request *RecordApprovalRequest) {
				request.Release.ExpectedEEPROMDigest = digest("f")
			},
		},
		{
			name: "approval expiry",
			mutate: func(request *RecordApprovalRequest) {
				request.ExpiresAt = request.ExpiresAt.Add(time.Minute)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			operations := developmentCampaignNames()
			transaction := fixture.createClaimBindApprove(operations)
			transaction = fixture.recordSuccessfulOperation(transaction, operations[0], 1)
			anchor := transaction.Operations[0]
			transaction, err := fixture.service.TransferClaim(context.Background(), TransferClaimRequest{
				SchemaVersion: TransferClaimRequestSchemaVersion, IdempotencyKey: "transfer-started-plan",
				TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
				ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
				NewStationID: "station-2", NewLaneID: "lane-2", Mode: ClaimModeMutation,
				AllowedStages: operations, LeaseDurationSeconds: 300,
			})
			if err != nil {
				t.Fatal(err)
			}
			transaction, err = fixture.service.BindTarget(context.Background(), BindTargetRequest{
				SchemaVersion: BindTargetRequestSchemaVersion, IdempotencyKey: "rebind-started-plan",
				MutationContext: contextFor(transaction), TargetFingerprint: transaction.Target.Fingerprint,
				ObservationDigest: digest("f"), CustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
			})
			if err != nil {
				t.Fatal(err)
			}
			if transaction.Approval != nil || len(transaction.Operations) != 1 {
				t.Fatalf("transferred transaction lost plan history: %#v", transaction)
			}
			request := fixture.approvalRequest(transaction, operations, "approval-after-transfer")
			request.PlanDigest = anchor.PlanDigest
			request.Release = anchor.Release
			request.ExpiresAt = anchor.ApprovalExpiresAt
			test.mutate(&request)

			if _, err := fixture.service.RecordApproval(context.Background(), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("reapproval error = %v, want conflict", err)
			}
		})
	}
}

func TestMarkSecurityAppliedRejectsPartialCampaign(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	operations := developmentCampaignNames()
	transaction := fixture.createClaimBindApprove(operations)
	transaction = fixture.recordSuccessfulOperation(transaction, operations[0], 1)
	request := fixture.securityAppliedRequest(transaction, "security-applied-partial")
	if _, err := fixture.service.MarkSecurityApplied(context.Background(), request); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("partial campaign finalization error = %v", err)
	}
	persisted, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ResourceVersion != transaction.ResourceVersion || persisted.Status != StatusCommitApproved || persisted.SecurityApplied != nil {
		t.Fatalf("partial finalization changed transaction: %#v", persisted)
	}
}

func TestPersistedTruncatedApprovalFailsClosed(t *testing.T) {
	store := &MemoryStore{}
	fixture := newTestFixture(t, store)
	transaction := fixture.createClaimBindApprove(developmentCampaignNames())
	data, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := DecodeStrict(data, &state); err != nil {
		t.Fatal(err)
	}
	stored := state.Transactions[transaction.ID]
	stored.Approval.AllowedOperations = stored.Approval.AllowedOperations[:len(stored.Approval.AllowedOperations)-1]
	state.Transactions[transaction.ID] = stored
	data, err = marshalState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(data); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(store); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("truncated persisted approval error = %v, want corrupt store", err)
	}
}

func TestPersistedApprovalReleaseBindingFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*releasebinding.Binding)
	}{
		{
			name: "missing signed release manifest digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.SignedReleaseManifestDigest = ""
			},
		},
		{
			name: "missing lane guard package digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.LaneGuardPackageDigest = ""
			},
		},
		{
			name: "missing compiled artifact set digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.CompiledArtifactSetDigest = ""
			},
		},
		{
			name: "missing expected customer key hash",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedCustomerKeyHash = ""
			},
		},
		{
			name: "missing expected EEPROM digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedEEPROMDigest = ""
			},
		},
		{
			name: "missing expected boot image digest",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedBootImageDigest = ""
			},
		},
		{
			name: "signed release manifest mismatches transaction",
			mutate: func(binding *releasebinding.Binding) {
				binding.SignedReleaseManifestDigest = digest("f")
			},
		},
		{
			name: "customer key mismatches transaction",
			mutate: func(binding *releasebinding.Binding) {
				binding.ExpectedCustomerKeyHash = digest("f")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &MemoryStore{}
			fixture := newTestFixture(t, store)
			transaction := fixture.createClaimBindApprove(developmentCampaignNames())
			data, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			var state persistedState
			if err := DecodeStrict(data, &state); err != nil {
				t.Fatal(err)
			}
			stored := state.Transactions[transaction.ID]
			test.mutate(&stored.Approval.Release)
			state.Transactions[transaction.ID] = stored
			data, err = marshalState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(data); err != nil {
				t.Fatal(err)
			}
			if _, err := NewService(store); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("corrupt persisted release binding error = %v, want corrupt store", err)
			}
		})
	}
}

func TestPersistedApprovalLifetimeFailsClosed(t *testing.T) {
	store := &MemoryStore{}
	fixture := newTestFixture(t, store)
	transaction := fixture.createClaimBindApprove(developmentCampaignNames())
	data, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := DecodeStrict(data, &state); err != nil {
		t.Fatal(err)
	}
	stored := state.Transactions[transaction.ID]
	stored.Approval.ExpiresAt = stored.Approval.ApprovedAt.Add(maximumApprovalLifetime + time.Nanosecond)
	state.Transactions[transaction.ID] = stored
	data, err = marshalState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(data); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(store); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("overlong persisted approval error = %v, want corrupt store", err)
	}
}

func TestMarkSecurityAppliedRevalidatesCampaignAndEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Transaction)
	}{
		{
			name: "truncated approval",
			mutate: func(transaction *Transaction) {
				transaction.Approval.AllowedOperations = transaction.Approval.AllowedOperations[:len(transaction.Approval.AllowedOperations)-1]
			},
		},
		{
			name: "reordered approval",
			mutate: func(transaction *Transaction) {
				operations := transaction.Approval.AllowedOperations
				operations[2], operations[3] = operations[3], operations[2]
			},
		},
		{
			name: "duplicated approval",
			mutate: func(transaction *Transaction) {
				transaction.Approval.AllowedOperations[3] = transaction.Approval.AllowedOperations[2]
			},
		},
		{
			name: "inserted approval",
			mutate: func(transaction *Transaction) {
				transaction.Approval.AllowedOperations = append(transaction.Approval.AllowedOperations, "inserted_operation")
			},
		},
		{
			name: "renamed approval",
			mutate: func(transaction *Transaction) {
				transaction.Approval.AllowedOperations[4] = "renamed_operation"
			},
		},
		{
			name: "truncated evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations = transaction.Operations[:len(transaction.Operations)-1]
			},
		},
		{
			name: "reordered evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations[2], transaction.Operations[3] = transaction.Operations[3], transaction.Operations[2]
			},
		},
		{
			name: "duplicated evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations[3].Operation = transaction.Operations[2].Operation
			},
		},
		{
			name: "inserted evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations = append(transaction.Operations, transaction.Operations[len(transaction.Operations)-1])
			},
		},
		{
			name: "renamed evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations[4].Operation = "renamed_operation"
			},
		},
		{
			name: "different plan evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations[4].PlanDigest = digest("e")
			},
		},
		{
			name: "nonterminal evidence",
			mutate: func(transaction *Transaction) {
				transaction.Operations[4].Status = OperationIntentRecorded
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			transaction := fixture.createClaimBindApprove(developmentCampaignNames())
			transaction = fixture.completeCampaign(transaction)
			stored, err := cloneTransaction(fixture.service.state.Transactions[transaction.ID])
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&stored)
			fixture.service.state.Transactions[transaction.ID] = stored

			request := fixture.securityAppliedRequest(transaction, "security-applied-invalid")
			if _, err := fixture.service.MarkSecurityApplied(context.Background(), request); !errors.Is(err, ErrIllegalTransition) {
				t.Fatalf("finalization error = %v, want illegal transition", err)
			}
		})
	}
}

func TestCompletedCampaignAllowsConclusiveReadbackNoOpBeforeRetry(t *testing.T) {
	operations := developmentCampaignNames()
	approval := &Approval{
		PlanDigest: digest("5"), Release: approvalRelease(Transaction{BundleDigest: digest("0"), ExpectedCustomerKeyHash: digest("2")}),
		AllowedOperations: operations, ExpiresAt: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC),
	}
	records := make([]OperationRecord, 0, len(operations)+1)
	for index, operation := range operations {
		if index == 2 {
			records = append(records, OperationRecord{
				Operation: operation, PlanDigest: approval.PlanDigest, Release: approval.Release,
				ApprovalExpiresAt: approval.ExpiresAt, Status: OperationConfirmedNotApplied,
			})
		}
		records = append(records, OperationRecord{
			Operation: operation, PlanDigest: approval.PlanDigest, Release: approval.Release,
			ApprovalExpiresAt: approval.ExpiresAt, Status: OperationSucceeded,
		})
	}
	if err := validateCompletedDevelopmentCampaign(records, approval); err != nil {
		t.Fatalf("conclusive readback no-op followed by retry was rejected: %v", err)
	}
}

func TestTransferIncrementsFenceAndInvalidatesApproval(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	operations := developmentCampaignNames()
	transaction := fixture.createClaimBindApprove(operations)
	oldClaim := *transaction.ActiveClaim
	transfer := TransferClaimRequest{
		SchemaVersion: TransferClaimRequestSchemaVersion, IdempotencyKey: "transfer-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: oldClaim.ID, FenceEpoch: oldClaim.FenceEpoch,
		NewStationID: "station-2", NewLaneID: "lane-2", Mode: ClaimModeMutation,
		AllowedStages: operations, LeaseDurationSeconds: 300,
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
		ApprovalID:      "approval-1", OperationID: "operation-1", Operation: operations[0],
		PlanDigest: digest("5"), InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	}
	if _, err := fixture.service.RecordIntent(context.Background(), stale); !errors.Is(err, ErrStaleFence) && !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("stale intent error = %v", err)
	}

	approval := fixture.approvalRequest(transaction, operations, "approval-2")
	if _, err := fixture.service.RecordApproval(context.Background(), approval); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("approval without current-epoch reidentification error = %v", err)
	}
	rebind := BindTargetRequest{
		SchemaVersion: BindTargetRequestSchemaVersion, IdempotencyKey: "rebind-2",
		MutationContext: contextFor(transaction), TargetFingerprint: digest("3"),
		ObservationDigest: digest("e"), CustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
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
	operations := developmentCampaignNames()
	transaction := fixture.createClaimBindApprove(operations)
	transaction = fixture.intent(RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-1",
		MutationContext: contextFor(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-1", Operation: operations[0], PlanDigest: transaction.Approval.PlanDigest,
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
		Operation: operations[0], PlanDigest: digest("5"), InputDigest: digest("6"),
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
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
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
	var approval RecordApprovalRequest
	if err := DecodeStrict([]byte(`{"expected_customer_key_hash":"sha256:legacy"}`), &approval); err == nil {
		t.Fatal("legacy top-level approval release field was accepted")
	}
}

func (fixture *testFixture) create() Transaction {
	fixture.t.Helper()
	transaction, err := fixture.service.CreateTransaction(context.Background(), CreateTransactionRequest{
		SchemaVersion: CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-1",
		TransactionID: "transaction-1", AssetID: "asset-1", IntendedLogicalID: "device-1",
		ProfileID: "rpi5-v1", BundleDigest: digest("0"), PolicyDigest: digest("1"),
		ExpectedPrestateCustomerKeyHash: digest("f"), ExpectedCustomerKeyHash: digest("2"),
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func (fixture *testFixture) createClaimBindApprove(operations []string) Transaction {
	fixture.t.Helper()
	transaction := fixture.createClaimBind(operations)
	transaction, err := fixture.service.RecordApproval(context.Background(), fixture.approvalRequest(transaction, operations, "approval-1"))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return transaction
}

func (fixture *testFixture) createClaimBind(operations []string) Transaction {
	fixture.t.Helper()
	transaction := fixture.create()
	transaction, err := fixture.service.AcquireClaim(context.Background(), AcquireClaimRequest{
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
		ObservationDigest: digest("4"), CustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
	})
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
		TargetFingerprint: transaction.Target.Fingerprint, Release: approvalRelease(transaction),
		AllowedOperations: operations, AuditReceiptID: digest("a"), ExpiresAt: fixture.now.Add(30 * time.Minute),
	}
}

func approvalRelease(transaction Transaction) releasebinding.Binding {
	return releasebinding.Binding{
		SignedReleaseManifestDigest: transaction.BundleDigest,
		LaneGuardPackageDigest:      digest("b"),
		CompiledArtifactSetDigest:   digest("c"),
		ExpectedCustomerKeyHash:     transaction.ExpectedCustomerKeyHash,
		ExpectedEEPROMDigest:        digest("d"),
		ExpectedBootImageDigest:     digest("e"),
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

func (fixture *testFixture) recordSuccessfulOperation(transaction Transaction, operation string, sequence int) Transaction {
	fixture.t.Helper()
	identifier := number(sequence)
	transaction = fixture.intent(RecordIntentRequest{
		SchemaVersion: RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-" + identifier,
		MutationContext: contextFor(transaction), ApprovalID: transaction.Approval.ID,
		OperationID: "operation-" + identifier, Operation: operation, PlanDigest: transaction.Approval.PlanDigest,
		InputDigest: digest("6"), PrestateDigest: digest("7"), AuditReceiptID: digest("8"),
	})
	return fixture.evidence(RecordEvidenceRequest{
		SchemaVersion: RecordEvidenceRequestSchemaVersion, IdempotencyKey: "evidence-" + identifier,
		MutationContext: contextFor(transaction), OperationID: "operation-" + identifier, Result: EvidenceSucceeded,
		OutputDigest: digest("9"), ObservationDigest: digest("a"), AuditReceiptID: digest("b"),
	})
}

func (fixture *testFixture) completeCampaign(transaction Transaction) Transaction {
	fixture.t.Helper()
	for index, operation := range developmentCampaignNames() {
		transaction = fixture.recordSuccessfulOperation(transaction, operation, index+1)
	}
	return transaction
}

func (fixture *testFixture) securityAppliedRequest(transaction Transaction, idempotencyKey string) SecurityAppliedRequest {
	fixture.t.Helper()
	return SecurityAppliedRequest{
		SchemaVersion: SecurityAppliedRequestSchemaVersion, IdempotencyKey: idempotencyKey,
		MutationContext: contextFor(transaction), PlanDigest: transaction.Approval.PlanDigest,
		EvidenceDigest: digest("c"), AuditReceiptID: digest("d"),
		RollbackStatus: "rollback_unimplemented", ReleaseClassification: "development_asset",
	}
}

func contextFor(transaction Transaction) MutationContext {
	return MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func developmentCampaignNames() []string {
	operations := campaign.DevelopmentOperations()
	names := make([]string, len(operations))
	for index, operation := range operations {
		names[index] = string(operation)
	}
	return names
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
