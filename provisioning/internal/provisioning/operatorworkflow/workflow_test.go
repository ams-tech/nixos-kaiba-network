package operatorworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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

type recordingAudit struct {
	service  *auditlog.Service
	receipts []auditlog.Receipt
}

func (audit *recordingAudit) Append(ctx context.Context, request auditlog.AppendRequest) (auditlog.Receipt, error) {
	receipt, err := audit.service.Append(ctx, request)
	if err == nil {
		audit.receipts = append(audit.receipts, receipt)
	}
	return receipt, err
}

type workflowFixture struct {
	now     time.Time
	clock   *time.Time
	input   DraftInput
	control *controlplane.Service
	audit   *recordingAudit
}

func newWorkflowFixture(t *testing.T) workflowFixture {
	t.Helper()
	now := time.Date(2026, time.August, 26, 15, 0, 0, 0, time.UTC)
	current := now
	control, err := controlplane.NewService(
		&controlplane.MemoryStore{},
		controlplane.WithClock(func() time.Time { return current }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) { return prefix + "-operator-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := auditlog.NewService(&auditlog.MemoryStore{}, auditlog.WithClock(func() time.Time { return current }))
	if err != nil {
		t.Fatal(err)
	}
	return workflowFixture{
		now: now, clock: &current, control: control, audit: &recordingAudit{service: auditService},
		input: DraftInput{
			SchemaVersion: DraftInputSchemaVersion,
			StationID:     "station-production-1", LaneID: "lane-1", TransactionID: "transaction-1",
			AssetID: "asset-1", IntendedLogicalID: "kaiba-1", ProfileID: "rpi5-production",
			PolicyDigest: testDigest("1"),
			Release: releasebinding.Binding{
				SignedReleaseManifestDigest: testDigest("2"), LaneGuardPackageDigest: testDigest("3"),
				CompiledArtifactSetDigest: testDigest("4"), ExpectedCustomerKeyHash: testDigest("5"),
				ExpectedEEPROMDigest: testDigest("6"), ExpectedBootImageDigest: testDigest("7"),
			},
			TargetFingerprint: testDigest("8"), ObservationDigest: testDigest("9"),
			InitialState: laneguard.DirectState{
				CustomerKeyHash:  controlplane.UnownedCustomerKeyHash,
				EEPROMHashStatus: laneguard.EEPROMHashObserved, EEPROMHash: testDigest("a"),
				SecurityState: "fresh", PowerState: "powered_off",
			},
			ApprovalExpiresAt: now.Add(30 * time.Minute),
			AuthorizationIDs: []string{
				"authorization-1", "authorization-2", "authorization-3", "authorization-4",
				"authorization-5", "authorization-6", "authorization-7",
			},
			MaximumSeconds: []uint32{60, 90, 60, 120, 60, 120, 120},
		},
	}
}

func TestWorkflowProducesBridgeCompatibleAuthorityAndAdvancesOnlyAfterEvidence(t *testing.T) {
	fixture := newWorkflowFixture(t)
	ctx := context.Background()

	snapshot, transaction, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ApprovalID != "" || snapshot.IntentReceipt != "" || snapshot.IntentSequence != 0 {
		t.Fatalf("draft leaked execution authority: %#v", snapshot)
	}
	if snapshot.InitialObservationDigest != fixture.input.ObservationDigest ||
		transaction.Target == nil || transaction.Target.ObservationDigest != snapshot.InitialObservationDigest {
		t.Fatalf("draft/control observation binding = %q / %#v", snapshot.InitialObservationDigest, transaction.Target)
	}
	wantOperations := campaign.DevelopmentOperations()
	if len(snapshot.Operations) != len(wantOperations) {
		t.Fatalf("operation count = %d, want %d", len(snapshot.Operations), len(wantOperations))
	}
	for index, operation := range snapshot.Operations {
		if operation.Operation != wantOperations[index] || operation.AuthorizationID != fixture.input.AuthorizationIDs[index] {
			t.Fatalf("operation %d = %#v", index+1, operation)
		}
		wantMode := laneguard.BootModeRPIBoot
		if operation.Operation == laneguard.OperationColdPowerCycle {
			wantMode = laneguard.BootModeNormal
		}
		if operation.RequiredBootMode != wantMode {
			t.Fatalf("operation %d boot mode = %q, want %q", index+1, operation.RequiredBootMode, wantMode)
		}
	}

	approval, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	// A byte-identical retry must not append another event or mutate control.
	approvalVersion := transaction.ResourceVersion
	transaction, err = ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("retry approval: %v", err)
	}
	if transaction.ResourceVersion != approvalVersion || len(fixture.audit.service.Records(transaction.ID)) != 1 {
		t.Fatal("approval replay was not idempotent")
	}

	intent, renewed, err := PrepareNextIntent(ctx, snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Sequence != 1 || intent.OperationID != snapshot.Operations[0].AuthorizationID {
		t.Fatalf("first intent = %#v", intent)
	}
	_, intentRequest, err := intent.requests(validPlaceholderDigest)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := plancompiler.DraftFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	wantPrestate, err := draft.PrestateDigest(1)
	if err != nil {
		t.Fatal(err)
	}
	if intentRequest.PrestateDigest != wantPrestate || intentRequest.Operation != string(wantOperations[0]) ||
		intentRequest.OperationID != snapshot.Operations[0].AuthorizationID {
		t.Fatalf("derived intent payload = %#v", intentRequest)
	}
	transaction, err = ApplyIntent(ctx, intent, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	intentVersion := transaction.ResourceVersion
	transaction, err = ApplyIntent(ctx, intent, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("retry intent: %v", err)
	}
	if transaction.ResourceVersion != intentVersion || len(fixture.audit.service.Records(transaction.ID)) != 2 {
		t.Fatal("intent replay was not idempotent")
	}

	records := fixture.audit.service.Records(transaction.ID)
	bound, err := plancompiler.Bind(draft, plancompiler.Authority{
		Transaction:     transaction,
		ApprovalReceipt: fixture.audit.receipts[0], ApprovalRecord: records[0],
		IntentReceipt: fixture.audit.receipts[2], IntentRecord: records[1],
		Now: fixture.now, LeaseSafetyMargin: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("bind generated control/audit payloads: %v", err)
	}
	execute, err := bound.ExecuteRequest()
	if err != nil {
		t.Fatal(err)
	}
	if execute.Sequence != 1 || execute.AuthorizationID != intent.OperationID ||
		execute.IntentReceipt != transaction.Operations[0].IntentAuditReceiptID ||
		execute.ClaimExpiresAt != renewed.ActiveClaim.ExpiresAt {
		t.Fatalf("bridge-compatible request = %#v", execute)
	}

	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	evidence, err := NewEvidenceProposal(snapshot, transaction, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyEvidence(ctx, evidence, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusCommitApproved || transaction.Operations[0].Status != controlplane.OperationSucceeded {
		t.Fatalf("recorded evidence transaction = %#v", transaction)
	}
	evidenceVersion := transaction.ResourceVersion
	transaction, err = ApplyEvidence(ctx, evidence, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("retry evidence: %v", err)
	}
	if transaction.ResourceVersion != evidenceVersion || len(fixture.audit.service.Records(transaction.ID)) != 3 {
		t.Fatal("evidence replay was not idempotent")
	}

	next, _, err := PrepareNextIntent(ctx, snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if next.Sequence != 2 || next.OperationID != snapshot.Operations[1].AuthorizationID ||
		snapshot.Operations[1].Operation != laneguard.OperationColdPowerCycle {
		t.Fatalf("second intent = %#v", next)
	}
}

func TestSecurityAppliedProposalAuditsThenTerminalizesExactCampaignIdempotently(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := completedCampaign(t, &fixture)
	proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.EvidenceDigest == "" || proposal.RollbackStatus != developmentRollbackStatus ||
		proposal.ReleaseClassification != developmentReleaseClassification ||
		proposal.ExpectedResourceVersion != transaction.ResourceVersion || proposal.ClaimID != transaction.ActiveClaim.ID {
		t.Fatalf("security-applied proposal = %#v", proposal)
	}

	transaction, err = ApplySecurityApplied(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusSecurityApplied || transaction.SecurityApplied == nil ||
		transaction.SecurityApplied.EvidenceDigest != proposal.EvidenceDigest ||
		transaction.SecurityApplied.RollbackStatus != developmentRollbackStatus ||
		transaction.SecurityApplied.ReleaseClassification != developmentReleaseClassification {
		t.Fatalf("security-applied transaction = %#v", transaction)
	}
	records := fixture.audit.service.Records(transaction.ID)
	terminalEvent := records[len(records)-1].Event
	if terminalEvent.Stage != "security_applied" || terminalEvent.Result != auditlog.ResultSucceeded ||
		terminalEvent.InputDigest != snapshot.PlanDigest || terminalEvent.OutputDigest != proposal.EvidenceDigest ||
		len(terminalEvent.ObservationReferences) != 1 ||
		terminalEvent.ObservationReferences[0].Digest != proposal.EvidenceDigest ||
		transaction.SecurityApplied.AuditReceiptID != fixture.audit.receipts[len(fixture.audit.receipts)-1].ReceiptID {
		t.Fatalf("security-applied audit/control binding = %#v / %#v", terminalEvent, transaction.SecurityApplied)
	}

	version := transaction.ResourceVersion
	recordCount := len(records)
	transaction, err = ApplySecurityApplied(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("replay security-applied proposal: %v", err)
	}
	if transaction.ResourceVersion != version || len(fixture.audit.service.Records(transaction.ID)) != recordCount {
		t.Fatal("security-applied replay was not idempotent")
	}
}

func TestReleaseTerminalClaimIsSelectorFreeAndIdempotent(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := completedCampaign(t, &fixture)
	proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplySecurityApplied(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	wantClaim := *transaction.ActiveClaim

	transaction, err = ReleaseTerminalClaim(context.Background(), snapshot, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusSecurityApplied || transaction.ActiveClaim != nil ||
		len(transaction.ClaimHistory) != 1 || transaction.ClaimHistory[0].Status != controlplane.ClaimReleased ||
		transaction.ClaimHistory[0].ClosedAt == nil || !sameClaimAuthority(transaction.ClaimHistory[0], wantClaim) {
		t.Fatalf("released terminal transaction = %#v", transaction)
	}

	version := transaction.ResourceVersion
	replayed, err := ReleaseTerminalClaim(context.Background(), snapshot, fixture.control)
	if err != nil {
		t.Fatalf("replay terminal claim release: %v", err)
	}
	if replayed.ResourceVersion != version || replayed.ActiveClaim != nil || len(replayed.ClaimHistory) != 1 {
		t.Fatalf("terminal claim release replay changed state: %#v", replayed)
	}
}

func TestReleaseTerminalClaimRejectsNonterminalCampaign(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := approvedEmptyCampaign(t, &fixture)
	if _, err := ReleaseTerminalClaim(context.Background(), snapshot, fixture.control); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("nonterminal release error = %v, want state mismatch", err)
	}
	current, err := fixture.control.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ResourceVersion != transaction.ResourceVersion || current.ActiveClaim == nil {
		t.Fatalf("rejected release changed control state: %#v", current)
	}
}

func TestReleaseTerminalClaimAllowsConclusiveReconciliation(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _ := uncertainFirstOperation(t, &fixture)
	transaction, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewReconciliationProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyReconciliation(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusReconciled || transaction.ActiveClaim == nil ||
		transaction.ActiveClaim.Mode != controlplane.ClaimModeReconciliation {
		t.Fatalf("conclusive reconciliation transaction = %#v", transaction)
	}
	transaction, err = ReleaseTerminalClaim(context.Background(), snapshot, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.ActiveClaim != nil || len(transaction.ClaimHistory) == 0 ||
		transaction.ClaimHistory[len(transaction.ClaimHistory)-1].Status != controlplane.ClaimReleased {
		t.Fatalf("released reconciliation claim = %#v", transaction)
	}
}

func TestReleaseTerminalClaimRejectsTamperedTerminalStateAndResponse(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := completedCampaign(t, &fixture)
	proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := ApplySecurityApplied(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}

	stateTests := map[string]func(*controlplane.Transaction){
		"approval plan":      func(value *controlplane.Transaction) { value.Approval.PlanDigest = testDigest("d") },
		"operation plan":     func(value *controlplane.Transaction) { value.Operations[0].PlanDigest = testDigest("d") },
		"authorization ID":   func(value *controlplane.Transaction) { value.Operations[0].ID = "authorization-other" },
		"terminal evidence":  func(value *controlplane.Transaction) { value.SecurityApplied.EvidenceDigest = testDigest("d") },
		"terminal receipt":   func(value *controlplane.Transaction) { value.SecurityApplied.AuditReceiptID = "invalid" },
		"target fingerprint": func(value *controlplane.Transaction) { value.Target.Fingerprint = testDigest("d") },
	}
	for name, mutate := range stateTests {
		t.Run("state "+name, func(t *testing.T) {
			changed := cloneControlTransaction(t, terminal)
			mutate(&changed)
			control := &recordingClaimReleaser{transaction: changed}
			if _, err := ReleaseTerminalClaim(context.Background(), snapshot, control); !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("tampered terminal state error = %v, want state mismatch", err)
			}
			if len(control.requests) != 0 {
				t.Fatal("tampered terminal state crossed the release boundary")
			}
		})
	}

	validResponse := exactTerminalReleaseResponse(terminal, fixture.now.Add(time.Second))
	responseTests := map[string]func(*controlplane.Transaction){
		"target":      func(value *controlplane.Transaction) { value.Target.Fingerprint = testDigest("d") },
		"operation":   func(value *controlplane.Transaction) { value.Operations[0].ID = "authorization-other" },
		"disposition": func(value *controlplane.Transaction) { value.SecurityApplied.EvidenceDigest = testDigest("d") },
		"prior history": func(value *controlplane.Transaction) {
			value.ClaimHistory = append([]controlplane.Claim{{ID: "claim-other"}}, value.ClaimHistory...)
		},
	}
	for name, mutate := range responseTests {
		t.Run("response "+name, func(t *testing.T) {
			changed := cloneControlTransaction(t, validResponse)
			mutate(&changed)
			control := &recordingClaimReleaser{transaction: terminal, released: changed}
			if _, err := ReleaseTerminalClaim(context.Background(), snapshot, control); !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("tampered release response error = %v, want state mismatch", err)
			}
			if len(control.requests) != 1 {
				t.Fatalf("release calls = %d, want 1", len(control.requests))
			}
		})
	}
}

func TestReleaseTerminalClaimRetryNeverRetargetsALaterQuarantineClaim(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	attempt.Status = laneguard.AttemptQuarantined
	proposal, err := NewEvidenceProposal(snapshot, transaction, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyEvidence(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusQuarantined {
		t.Fatalf("mutation quarantine transaction = %#v", transaction)
	}
	transaction, err = ReleaseTerminalClaim(context.Background(), snapshot, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = fixture.control.AcquireClaim(context.Background(), controlplane.AcquireClaimRequest{
		SchemaVersion: controlplane.AcquireClaimRequestSchemaVersion, IdempotencyKey: "later-reconciliation-claim",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: snapshot.StationID, LaneID: snapshot.LaneID,
		Mode: controlplane.ClaimModeReconciliation, AllowedStages: []string{"reconciliation"}, LeaseDurationSeconds: claimLeaseSeconds,
	})
	if err != nil {
		t.Fatal(err)
	}
	laterClaim := *transaction.ActiveClaim
	if _, err := ReleaseTerminalClaim(context.Background(), snapshot, fixture.control); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("delayed release retry error = %v, want state mismatch", err)
	}
	current, err := fixture.control.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ActiveClaim == nil || !sameClaimAuthority(*current.ActiveClaim, laterClaim) ||
		current.ResourceVersion != transaction.ResourceVersion {
		t.Fatalf("delayed retry retargeted the later claim: %#v", current)
	}
}

func TestReleaseTerminalClaimAllowsReconciliationQuarantine(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _ := uncertainFirstOperation(t, &fixture)
	transaction, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	attempt.Status = laneguard.AttemptUncertain
	proposal, err := NewReconciliationProposal(snapshot, transaction, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyReconciliation(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Status != controlplane.StatusQuarantined || transaction.ActiveClaim == nil ||
		transaction.ActiveClaim.Mode != controlplane.ClaimModeReconciliation {
		t.Fatalf("reconciliation quarantine transaction = %#v", transaction)
	}
	transaction, err = ReleaseTerminalClaim(context.Background(), snapshot, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.ActiveClaim != nil || transaction.ClaimHistory[len(transaction.ClaimHistory)-1].Status != controlplane.ClaimReleased {
		t.Fatalf("released reconciliation quarantine = %#v", transaction)
	}
}

func exactTerminalReleaseResponse(before controlplane.Transaction, updatedAt time.Time) controlplane.Transaction {
	after := before
	after.ResourceVersion++
	after.UpdatedAt = updatedAt.UTC()
	released := *before.ActiveClaim
	released.Status = controlplane.ClaimReleased
	closedAt := after.UpdatedAt
	released.ClosedAt = &closedAt
	after.ClaimHistory = append(append([]controlplane.Claim(nil), before.ClaimHistory...), released)
	after.ActiveClaim = nil
	return after
}

func TestSecurityAppliedRejectsProposalOrCompletedStateTamperingBeforeAudit(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := completedCampaign(t, &fixture)
	base, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	proposalTests := map[string]func(*SecurityAppliedProposal){
		"schema":          func(value *SecurityAppliedProposal) { value.SchemaVersion = "wrong" },
		"resource":        func(value *SecurityAppliedProposal) { value.ExpectedResourceVersion++ },
		"claim":           func(value *SecurityAppliedProposal) { value.ClaimID = "claim-other" },
		"fence":           func(value *SecurityAppliedProposal) { value.FenceEpoch++ },
		"evidence digest": func(value *SecurityAppliedProposal) { value.EvidenceDigest = testDigest("d") },
		"rollback":        func(value *SecurityAppliedProposal) { value.RollbackStatus = "implemented" },
		"classification":  func(value *SecurityAppliedProposal) { value.ReleaseClassification = "production" },
	}
	for name, mutate := range proposalTests {
		t.Run("proposal "+name, func(t *testing.T) {
			proposal := cloneSecurityAppliedProposal(t, base)
			mutate(&proposal)
			audit := &countingAudit{}
			control := &countingSecurityAppliedRecorder{transaction: transaction}
			if _, err := ApplySecurityApplied(context.Background(), proposal, staticReader{transaction}, audit, control); err == nil {
				t.Fatal("tampered security-applied proposal was accepted")
			}
			if audit.calls != 0 || control.calls != 0 {
				t.Fatalf("tampered proposal crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
			}
		})
	}

	stateTests := map[string]func(*controlplane.Transaction){
		"short campaign": func(value *controlplane.Transaction) {
			value.Operations = value.Operations[:len(value.Operations)-1]
		},
		"operation identity": func(value *controlplane.Transaction) { value.Operations[2].ID = "authorization-other" },
		"operation status":   func(value *controlplane.Transaction) { value.Operations[3].Status = controlplane.OperationUncertain },
		"evidence receipt":   func(value *controlplane.Transaction) { value.Operations[4].EvidenceAuditReceiptID = "" },
		"evidence output":    func(value *controlplane.Transaction) { value.Operations[5].OutputDigest = testDigest("e") },
		"target":             func(value *controlplane.Transaction) { value.Target.Fingerprint = testDigest("e") },
		"target observation": func(value *controlplane.Transaction) { value.Target.ObservationDigest = testDigest("e") },
	}
	for name, mutate := range stateTests {
		t.Run("state "+name, func(t *testing.T) {
			changed := cloneControlTransaction(t, transaction)
			mutate(&changed)
			audit := &countingAudit{}
			control := &countingSecurityAppliedRecorder{transaction: changed}
			if _, err := ApplySecurityApplied(context.Background(), base, staticReader{changed}, audit, control); err == nil {
				t.Fatal("tampered completed state was accepted")
			}
			if audit.calls != 0 || control.calls != 0 {
				t.Fatalf("tampered state crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
			}
		})
	}
}

func TestSecurityAppliedAuditFailureNeverCallsControl(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := completedCampaign(t, &fixture)
	proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	audit := &countingAudit{err: errors.New("audit unavailable")}
	control := &countingSecurityAppliedRecorder{transaction: transaction}
	if _, err := ApplySecurityApplied(context.Background(), proposal, staticReader{transaction}, audit, control); err == nil {
		t.Fatal("ApplySecurityApplied() succeeded with failed audit append")
	}
	if audit.calls != 1 || control.calls != 0 {
		t.Fatalf("calls after terminal audit failure: audit=%d control=%d", audit.calls, control.calls)
	}
}

func TestDraftPreparationAndClaimRenewalResumeWithoutIdempotencyConflict(t *testing.T) {
	fixture := newWorkflowFixture(t)
	ctx := context.Background()
	first, transaction, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	second, replayed, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatalf("resume completed draft preparation: %v", err)
	}
	if !reflect.DeepEqual(first, second) || transaction.ResourceVersion != replayed.ResourceVersion {
		t.Fatal("draft preparation replay changed the draft or transaction")
	}
	approval, err := NewApprovalProposal(first, replayed, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control); err != nil {
		t.Fatal(err)
	}
	firstIntent, firstRenewal, err := PrepareNextIntent(ctx, first, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	secondIntent, secondRenewal, err := PrepareNextIntent(ctx, first, fixture.now, fixture.control)
	if err != nil {
		t.Fatalf("renew after lost proposal publication: %v", err)
	}
	if firstIntent.Sequence != secondIntent.Sequence || firstIntent.OperationID != secondIntent.OperationID ||
		secondRenewal.ResourceVersion <= firstRenewal.ResourceVersion {
		t.Fatalf("renewal retries = %#v then %#v", firstIntent, secondIntent)
	}
}

func TestRenewPendingIntentRefreshesTheExactClaimBeforeExecutionAndEvidence(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	fixture.input.MaximumSeconds[1] = maximumOperationSeconds
	snapshot, pending := pendingSecondOperation(t, &fixture)
	reviewedAt := fixture.now.Add(20 * time.Minute)
	*fixture.clock = reviewedAt

	renewed, err := RenewPendingIntent(context.Background(), snapshot, reviewedAt, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ResourceVersion != pending.ResourceVersion+1 || renewed.ActiveClaim.ID != pending.ActiveClaim.ID ||
		!renewed.ActiveClaim.ExpiresAt.Equal(reviewedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
		len(renewed.Operations) != 2 || renewed.Operations[1].Status != controlplane.OperationIntentRecorded {
		t.Fatalf("renewed pending intent = %#v", renewed)
	}
	if !laneguard.LeaseCoversOperation(
		reviewedAt,
		renewed.ActiveClaim.ExpiresAt,
		snapshot.Operations[1].MaximumDuration,
		5*time.Minute,
	) {
		t.Fatal("renewed claim does not cover the maximum fixed operation and safety margin")
	}

	// A terminal lane receipt is local evidence, so control remains the same
	// exact pending intent until ApplyEvidence. Re-renewal must extend the lease
	// without inventing a different operation.
	afterReceipt := reviewedAt.Add(time.Second)
	*fixture.clock = afterReceipt
	again, err := RenewPendingIntent(context.Background(), snapshot, afterReceipt, fixture.control)
	if err != nil {
		t.Fatalf("renew pending intent again before evidence: %v", err)
	}
	if again.ResourceVersion != renewed.ResourceVersion+1 || again.ActiveClaim.ID != renewed.ActiveClaim.ID ||
		!again.ActiveClaim.ExpiresAt.Equal(afterReceipt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
		!reflect.DeepEqual(again.Operations, renewed.Operations) {
		t.Fatalf("repeated pending renewal changed authority: %#v", again)
	}
}

func TestRenewTargetBoundCampaignRefreshesOnlyTheUnapprovedCleanDraft(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	snapshot, before, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	reviewedAt := fixture.now.Add(15 * time.Minute)
	*fixture.clock = reviewedAt
	renewed, err := RenewTargetBoundCampaign(context.Background(), snapshot, reviewedAt, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ResourceVersion != before.ResourceVersion+1 || renewed.Status != controlplane.StatusTargetBound ||
		renewed.Approval != nil || len(renewed.Operations) != 0 || renewed.ActiveClaim.ID != before.ActiveClaim.ID ||
		!renewed.ActiveClaim.ExpiresAt.Equal(reviewedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) {
		t.Fatalf("renewed target-bound campaign = %#v", renewed)
	}
	repeatedAt := reviewedAt.Add(time.Second)
	*fixture.clock = repeatedAt
	again, err := RenewTargetBoundCampaign(context.Background(), snapshot, repeatedAt, fixture.control)
	if err != nil {
		t.Fatalf("repeat target-bound renewal: %v", err)
	}
	if again.ResourceVersion != renewed.ResourceVersion+1 ||
		!again.ActiveClaim.ExpiresAt.Equal(repeatedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) {
		t.Fatalf("repeated target-bound renewal = %#v", again)
	}
}

func TestRenewTargetBoundCampaignRejectsApprovalHistoryOrStateDrift(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	snapshot, base, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(10 * time.Minute)
	tests := map[string]func(*controlplane.Transaction){
		"approval appeared": func(value *controlplane.Transaction) {
			value.Approval = &controlplane.Approval{ID: "approval-other"}
		},
		"operation history appeared": func(value *controlplane.Transaction) {
			value.Operations = append(value.Operations, controlplane.OperationRecord{ID: "authorization-other"})
		},
		"claim history appeared": func(value *controlplane.Transaction) {
			value.ClaimHistory = append(value.ClaimHistory, *value.ActiveClaim)
		},
		"status advanced": func(value *controlplane.Transaction) { value.Status = controlplane.StatusCommitApproved },
		"target changed":  func(value *controlplane.Transaction) { value.Target.Fingerprint = testDigest("d") },
		"target removed":  func(value *controlplane.Transaction) { value.Target = nil },
		"claim lane changed": func(value *controlplane.Transaction) {
			value.ActiveClaim.LaneID = "lane-other"
		},
		"claim fence changed": func(value *controlplane.Transaction) { value.ActiveClaim.FenceEpoch++ },
		"claim expired":       func(value *controlplane.Transaction) { value.ActiveClaim.ExpiresAt = now },
		"quarantine appeared": func(value *controlplane.Transaction) {
			value.Quarantine = &controlplane.QuarantineRecord{ReasonCode: "tampered"}
		},
		"terminal disposition appeared": func(value *controlplane.Transaction) {
			value.SecurityApplied = &controlplane.SecurityAppliedRecord{EvidenceDigest: testDigest("e")}
		},
		"abort appeared": func(value *controlplane.Transaction) {
			value.Abort = &controlplane.AbortRecord{ReusableBaselineDigest: testDigest("f")}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneControlTransaction(t, base)
			mutate(&changed)
			control := &recordingClaimRenewer{transaction: changed}
			if _, err := RenewTargetBoundCampaign(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("drifted target-bound campaign was renewed")
			}
			if len(control.requests) != 0 {
				t.Fatal("drifted target-bound state crossed the renewal authority boundary")
			}
		})
	}
}

func TestRenewalRequestsCarryOnlyTheirPurposeSpecificServerGuard(t *testing.T) {
	t.Run("prepare next intent", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
		snapshot, transaction := approvedEmptyCampaign(t, &fixture)
		control := &recordingRenewClient{service: fixture.control}
		if _, _, err := PrepareNextIntent(context.Background(), snapshot, fixture.now, control); err != nil {
			t.Fatal(err)
		}
		assertApprovalBoundRenewalRequest(t, control.onlyRequest(t), transaction.Approval.ID, snapshot.PlanDigest)
	})

	t.Run("pending intent", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
		snapshot, transaction := pendingFirstOperation(t, &fixture)
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		control := &recordingRenewClient{service: fixture.control}
		if _, err := RenewPendingIntent(context.Background(), snapshot, renewedAt, control); err != nil {
			t.Fatal(err)
		}
		assertApprovalBoundRenewalRequest(t, control.onlyRequest(t), transaction.Approval.ID, snapshot.PlanDigest)
	})

	t.Run("ready campaign", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
		snapshot, transaction := approvedEmptyCampaign(t, &fixture)
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		control := &recordingRenewClient{service: fixture.control}
		if _, err := RenewReadyCampaign(context.Background(), snapshot, renewedAt, control); err != nil {
			t.Fatal(err)
		}
		assertApprovalBoundRenewalRequest(t, control.onlyRequest(t), transaction.Approval.ID, snapshot.PlanDigest)
	})

	t.Run("target-bound campaign", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
		snapshot, _, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		control := &recordingRenewClient{service: fixture.control}
		if _, err := RenewTargetBoundCampaign(context.Background(), snapshot, renewedAt, control); err != nil {
			t.Fatal(err)
		}
		request := control.onlyRequest(t)
		if request.ApprovalID != "" || request.PlanDigest != "" || request.TargetBoundAuthorizationExpiresAt == nil ||
			!request.TargetBoundAuthorizationExpiresAt.Equal(snapshot.ApprovalExpiresAt) {
			t.Fatalf("target-bound renewal guard = %#v", request)
		}
	})

	t.Run("pending evidence remains approval-free", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, transaction := pendingFirstOperation(t, &fixture)
		afterApproval := transaction.Approval.ExpiresAt.Add(time.Second)
		if !transaction.ActiveClaim.ExpiresAt.After(afterApproval) {
			t.Fatal("test claim did not outlive approval")
		}
		*fixture.clock = afterApproval
		control := &recordingRenewClient{service: fixture.control}
		if _, err := RenewPendingEvidence(context.Background(), snapshot, afterApproval, control); err != nil {
			t.Fatal(err)
		}
		assertApprovalFreeRenewalRequest(t, control.onlyRequest(t))
	})

	t.Run("reconciliation remains approval-free", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, _ := uncertainFirstOperation(t, &fixture)
		if _, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control); err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		control := &recordingRenewClient{service: fixture.control}
		if _, err := RenewReconciliationClaim(context.Background(), snapshot, renewedAt, control); err != nil {
			t.Fatal(err)
		}
		assertApprovalFreeRenewalRequest(t, control.onlyRequest(t))
	})
}

func assertApprovalBoundRenewalRequest(t *testing.T, request controlplane.RenewClaimRequest, approvalID, planDigest string) {
	t.Helper()
	if request.SchemaVersion != controlplane.RenewClaimRequestSchemaVersion || request.ApprovalID != approvalID ||
		request.PlanDigest != planDigest || request.TargetBoundAuthorizationExpiresAt != nil {
		t.Fatalf("approval-bound renewal guard = %#v", request)
	}
}

func assertApprovalFreeRenewalRequest(t *testing.T, request controlplane.RenewClaimRequest) {
	t.Helper()
	if request.SchemaVersion != controlplane.RenewClaimRequestSchemaVersion || request.ApprovalID != "" ||
		request.PlanDigest != "" || request.TargetBoundAuthorizationExpiresAt != nil {
		t.Fatalf("approval-free renewal guard = %#v", request)
	}
}

func TestRenewReadyCampaignAcceptsOnlyExactSuccessfulPrefixes(t *testing.T) {
	tests := map[string]struct {
		prefix uint32
		build  func(*testing.T, *workflowFixture) (laneguard.Plan, controlplane.Transaction)
	}{
		"approved empty prefix": {prefix: 0, build: approvedEmptyCampaign},
		"one successful operation": {
			prefix: 1,
			build:  successfulFirstOperation,
		},
		"completed campaign": {prefix: 7, build: completedCampaign},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
			snapshot, before := test.build(t, &fixture)
			reviewedAt := fixture.now.Add(15 * time.Minute)
			*fixture.clock = reviewedAt
			var evidenceBefore string
			if test.prefix == uint32(len(snapshot.Operations)) {
				var err error
				evidenceBefore, err = completedCampaignEvidence(snapshot, before, reviewedAt)
				if err != nil {
					t.Fatal(err)
				}
			}

			renewed, err := RenewReadyCampaign(context.Background(), snapshot, reviewedAt, fixture.control)
			if err != nil {
				t.Fatal(err)
			}
			prefix, err := readyCampaignPrefix(snapshot, renewed, renewed.UpdatedAt)
			if err != nil || prefix != test.prefix {
				t.Fatalf("renewed prefix = %d, %v; want %d", prefix, err, test.prefix)
			}
			if renewed.ResourceVersion != before.ResourceVersion+1 || renewed.ActiveClaim.ID != before.ActiveClaim.ID ||
				!renewed.ActiveClaim.ExpiresAt.Equal(reviewedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) {
				t.Fatalf("renewed ready campaign = %#v", renewed)
			}
			if evidenceBefore != "" {
				evidenceAfter, err := completedCampaignEvidence(snapshot, renewed, renewed.UpdatedAt)
				if err != nil || evidenceAfter != evidenceBefore {
					t.Fatalf("completed evidence changed across renewal: %q -> %q, %v", evidenceBefore, evidenceAfter, err)
				}
			}

			repeatedAt := reviewedAt.Add(time.Second)
			*fixture.clock = repeatedAt
			again, err := RenewReadyCampaign(context.Background(), snapshot, repeatedAt, fixture.control)
			if err != nil {
				t.Fatalf("repeat ready-campaign renewal: %v", err)
			}
			if again.ResourceVersion != renewed.ResourceVersion+1 ||
				!again.ActiveClaim.ExpiresAt.Equal(repeatedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
				!reflect.DeepEqual(again.Operations, renewed.Operations) {
				t.Fatalf("repeated ready renewal changed campaign history: %#v", again)
			}
		})
	}
}

func TestRenewPendingIntentRejectsStaleTamperedOrClosedState(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	snapshot, base := pendingSecondOperation(t, &fixture)
	now := fixture.now.Add(10 * time.Minute)
	tests := map[string]func(*controlplane.Transaction){
		"wrong transaction status": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusCommitApproved
		},
		"missing active claim": func(value *controlplane.Transaction) { value.ActiveClaim = nil },
		"expired claim":        func(value *controlplane.Transaction) { value.ActiveClaim.ExpiresAt = now },
		"closed claim": func(value *controlplane.Transaction) {
			closedAt := now
			value.ActiveClaim.Status = controlplane.ClaimReleased
			value.ActiveClaim.ClosedAt = &closedAt
		},
		"wrong claim lane":  func(value *controlplane.Transaction) { value.ActiveClaim.LaneID = "lane-other" },
		"stale claim fence": func(value *controlplane.Transaction) { value.ActiveClaim.FenceEpoch++ },
		"unexpected claim history": func(value *controlplane.Transaction) {
			value.ClaimHistory = append(value.ClaimHistory, *value.ActiveClaim)
		},
		"missing approval":     func(value *controlplane.Transaction) { value.Approval = nil },
		"expired approval":     func(value *controlplane.Transaction) { value.Approval.ExpiresAt = now },
		"replaced approval":    func(value *controlplane.Transaction) { value.Approval.ID = "approval-other" },
		"tampered prior order": func(value *controlplane.Transaction) { value.Operations[0].ID = "authorization-other" },
		"unresolved prior operation": func(value *controlplane.Transaction) {
			value.Operations[0].Status = controlplane.OperationUncertain
		},
		"reconciled prior operation": func(value *controlplane.Transaction) {
			value.Operations[0].Status = controlplane.OperationConfirmedApplied
			value.Operations[0].ReconciliationAuditReceiptID = testDigest("c")
		},
		"missing prior evidence": func(value *controlplane.Transaction) {
			value.Operations[0].EvidenceAuditReceiptID = ""
		},
		"pending result fields": func(value *controlplane.Transaction) {
			value.Operations[1].OutputDigest = testDigest("d")
		},
		"pending operation closed": func(value *controlplane.Transaction) {
			value.Operations[1].Status = controlplane.OperationSucceeded
		},
		"quarantine disposition": func(value *controlplane.Transaction) {
			value.Quarantine = &controlplane.QuarantineRecord{ReasonCode: "tampered"}
		},
		"security-applied disposition": func(value *controlplane.Transaction) {
			value.SecurityApplied = &controlplane.SecurityAppliedRecord{EvidenceDigest: testDigest("e")}
		},
		"abort disposition": func(value *controlplane.Transaction) {
			value.Abort = &controlplane.AbortRecord{ReusableBaselineDigest: testDigest("f")}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneControlTransaction(t, base)
			mutate(&changed)
			control := &recordingClaimRenewer{transaction: changed}
			if _, err := RenewPendingIntent(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("invalid pending state was renewed")
			}
			if len(control.requests) != 0 {
				t.Fatal("invalid pending state crossed the renewal authority boundary")
			}
		})
	}
}

func TestRenewReadyCampaignRejectsPendingReconciledAndTerminalStates(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	snapshot, base := successfulFirstOperation(t, &fixture)
	now := fixture.now.Add(10 * time.Minute)
	tests := map[string]func(*controlplane.Transaction){
		"pending": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusMutationInProgress
			value.Operations[0].Status = controlplane.OperationIntentRecorded
			value.Operations[0].OutputDigest = ""
			value.Operations[0].ObservationDigest = ""
			value.Operations[0].EvidenceAuditReceiptID = ""
			value.Operations[0].EvidenceAt = nil
		},
		"reconciled result": func(value *controlplane.Transaction) {
			value.Operations[0].Status = controlplane.OperationConfirmedApplied
			value.Operations[0].ReconciliationAuditReceiptID = testDigest("d")
		},
		"uncertain result": func(value *controlplane.Transaction) {
			value.Operations[0].Status = controlplane.OperationUncertain
		},
		"failed result": func(value *controlplane.Transaction) {
			value.Operations[0].Status = controlplane.OperationFailed
		},
		"quarantined transaction": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusQuarantined
			value.Quarantine = &controlplane.QuarantineRecord{ReasonCode: "operation_failed"}
		},
		"terminal transaction": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusSecurityApplied
			value.SecurityApplied = &controlplane.SecurityAppliedRecord{EvidenceDigest: testDigest("e")}
		},
		"expired approval": func(value *controlplane.Transaction) { value.Approval.ExpiresAt = now },
		"expired claim":    func(value *controlplane.Transaction) { value.ActiveClaim.ExpiresAt = now },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneControlTransaction(t, base)
			mutate(&changed)
			control := &recordingClaimRenewer{transaction: changed}
			if _, err := RenewReadyCampaign(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("invalid ready state was renewed")
			}
			if len(control.requests) != 0 {
				t.Fatal("invalid ready state crossed the renewal authority boundary")
			}
		})
	}
}

func TestRenewalRejectsAControlResponseThatChangesMoreThanTheLease(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.ApprovalExpiresAt = fixture.now.Add(3 * time.Hour)
	snapshot, base := pendingSecondOperation(t, &fixture)
	now := fixture.now.Add(10 * time.Minute)
	valid := cloneControlTransaction(t, base)
	valid.ResourceVersion++
	valid.UpdatedAt = now
	valid.ActiveClaim.ExpiresAt = now.Add(time.Duration(claimLeaseSeconds) * time.Second)
	tests := map[string]func(*controlplane.Transaction){
		"stale resource version": func(value *controlplane.Transaction) { value.ResourceVersion = base.ResourceVersion },
		"shortened lease":        func(value *controlplane.Transaction) { value.ActiveClaim.ExpiresAt = now.Add(time.Minute) },
		"replacement claim":      func(value *controlplane.Transaction) { value.ActiveClaim.ID = "claim-other" },
		"changed pending operation": func(value *controlplane.Transaction) {
			value.Operations[1].ID = "authorization-other"
		},
		"closed transaction": func(value *controlplane.Transaction) { value.Status = controlplane.StatusCommitApproved },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := cloneControlTransaction(t, valid)
			mutate(&response)
			control := &recordingClaimRenewer{transaction: base, renewed: response}
			if _, err := RenewPendingIntent(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("tampered renewal response was accepted")
			}
			if len(control.requests) != 1 {
				t.Fatalf("renew calls = %d, want 1", len(control.requests))
			}
		})
	}
}

func TestProposalResourceVersionsAreImmutableAcrossSameClaimRenewal(t *testing.T) {
	t.Run("intent", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, _ := approvedEmptyCampaign(t, &fixture)
		proposal, _, err := PrepareNextIntent(context.Background(), snapshot, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		if _, err := RenewReadyCampaign(context.Background(), snapshot, renewedAt, fixture.control); err != nil {
			t.Fatal(err)
		}
		audit := &countingAudit{}
		control := &countingIntentRecorder{}
		if _, err := ApplyIntent(context.Background(), proposal, fixture.control, audit, control); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("ApplyIntent() error after renewal = %v", err)
		}
		if audit.calls != 0 || control.calls != 0 {
			t.Fatalf("stale intent crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
		}
	})

	t.Run("evidence", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, transaction := pendingFirstOperation(t, &fixture)
		proposal, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		if _, err := RenewPendingIntent(context.Background(), snapshot, renewedAt, fixture.control); err != nil {
			t.Fatal(err)
		}
		audit := &countingAudit{}
		control := &countingEvidenceRecorder{}
		if _, err := ApplyEvidence(context.Background(), proposal, fixture.control, audit, control); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("ApplyEvidence() error after renewal = %v", err)
		}
		if audit.calls != 0 || control.calls != 0 {
			t.Fatalf("stale evidence crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
		}
	})

	t.Run("security applied", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, transaction := completedCampaign(t, &fixture)
		proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		if _, err := RenewReadyCampaign(context.Background(), snapshot, renewedAt, fixture.control); err != nil {
			t.Fatal(err)
		}
		audit := &countingAudit{}
		control := &countingSecurityAppliedRecorder{}
		if _, err := ApplySecurityApplied(context.Background(), proposal, fixture.control, audit, control); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("ApplySecurityApplied() error after renewal = %v", err)
		}
		if audit.calls != 0 || control.calls != 0 {
			t.Fatalf("stale terminal proposal crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
		}
	})

	t.Run("reconciliation", func(t *testing.T) {
		fixture := newWorkflowFixture(t)
		snapshot, _ := uncertainFirstOperation(t, &fixture)
		transaction, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		attempt := verifiedAttempt(snapshot, transaction, fixture.now)
		proposal, err := NewReconciliationProposal(snapshot, transaction, attempt, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		renewedAt := fixture.now.Add(time.Second)
		*fixture.clock = renewedAt
		if _, err := RenewReconciliationClaim(context.Background(), snapshot, renewedAt, fixture.control); err != nil {
			t.Fatal(err)
		}
		audit := &countingAudit{}
		control := &countingReconciliationRecorder{}
		if _, err := ApplyReconciliation(context.Background(), proposal, fixture.control, audit, control); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("ApplyReconciliation() error after renewal = %v", err)
		}
		if audit.calls != 0 || control.calls != 0 {
			t.Fatalf("stale reconciliation proposal crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
		}
	})
}

func TestApplyTransitionsRejectServerExpiredClaimsBeforeAuthorityWrites(t *testing.T) {
	for _, kind := range []string{"intent", "evidence", "security applied", "reconciliation"} {
		t.Run(kind, func(t *testing.T) {
			scenario := newApplyPreflightScenario(t, kind)
			if scenario.transaction.ActiveClaim == nil {
				t.Fatal("scenario has no active claim")
			}
			*scenario.fixture.clock = scenario.transaction.ActiveClaim.ExpiresAt
			audit := &countingAudit{}
			if _, err := scenario.applyCounting(scenario.fixture.control, audit); !errors.Is(err, controlplane.ErrLeaseExpired) {
				t.Fatalf("Apply() at server-time claim expiry error = %v, want ErrLeaseExpired", err)
			}
			if audit.calls != 0 || scenario.controlCalls() != 0 {
				t.Fatalf("expired claim crossed authority boundary: audit=%d control=%d", audit.calls, scenario.controlCalls())
			}
		})
	}
}

func TestApprovalBoundApplyTransitionsRejectServerExpiredApprovalBeforeAuthorityWrites(t *testing.T) {
	for _, kind := range []string{"intent", "security applied"} {
		t.Run(kind, func(t *testing.T) {
			scenario := newApplyPreflightScenario(t, kind)
			approval := scenario.transaction.Approval
			if approval == nil || scenario.transaction.ActiveClaim == nil ||
				!scenario.transaction.ActiveClaim.ExpiresAt.After(approval.ExpiresAt) {
				t.Fatal("scenario claim does not outlive its approval")
			}
			*scenario.fixture.clock = approval.ExpiresAt
			audit := &countingAudit{}
			if _, err := scenario.applyCounting(scenario.fixture.control, audit); !errors.Is(err, controlplane.ErrIllegalTransition) {
				t.Fatalf("Apply() at server-time approval expiry error = %v, want ErrIllegalTransition", err)
			}
			if audit.calls != 0 || scenario.controlCalls() != 0 {
				t.Fatalf("expired approval crossed authority boundary: audit=%d control=%d", audit.calls, scenario.controlCalls())
			}
		})
	}
}

func TestApplyTransitionsRejectDifferentSameVersionPreflightStateBeforeAuthorityWrites(t *testing.T) {
	for _, kind := range []string{"intent", "evidence", "security applied", "reconciliation"} {
		t.Run(kind, func(t *testing.T) {
			scenario := newApplyPreflightScenario(t, kind)
			changed := cloneControlTransaction(t, scenario.transaction)
			changed.UpdatedAt = changed.UpdatedAt.Add(time.Nanosecond)
			reader := &recordingCurrentClaimReader{
				transaction:          scenario.transaction,
				preflightTransaction: changed,
			}
			audit := &countingAudit{}
			if _, err := scenario.applyCounting(reader, audit); !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("Apply() with changed same-version preflight error = %v, want ErrStateMismatch", err)
			}
			if reader.preflightCalls != 1 || audit.calls != 0 || scenario.controlCalls() != 0 {
				t.Fatalf("changed preflight calls: preflight=%d audit=%d control=%d", reader.preflightCalls, audit.calls, scenario.controlCalls())
			}
		})
	}
}

func TestExactCommittedApplyReplaysSkipExpiredClaimPreflight(t *testing.T) {
	for _, kind := range []string{"intent", "evidence", "security applied", "reconciliation"} {
		t.Run(kind, func(t *testing.T) {
			scenario := newApplyPreflightScenario(t, kind)
			committed, err := scenario.applyReal(scenario.fixture.control, scenario.fixture.audit)
			if err != nil {
				t.Fatalf("commit proposal: %v", err)
			}
			if committed.ActiveClaim == nil {
				t.Fatal("committed transaction has no active claim")
			}
			version := committed.ResourceVersion
			records := len(scenario.fixture.audit.service.Records(committed.ID))
			*scenario.fixture.clock = committed.ActiveClaim.ExpiresAt
			reader := &recordingCurrentClaimReader{
				transaction:  committed,
				preflightErr: errors.New("expired preflight must be skipped for an exact replay"),
			}
			replayed, err := scenario.applyReal(reader, scenario.fixture.audit)
			if err != nil {
				t.Fatalf("replay after claim expiry: %v", err)
			}
			if reader.preflightCalls != 0 || replayed.ResourceVersion != version ||
				len(scenario.fixture.audit.service.Records(committed.ID)) != records {
				t.Fatalf("replay changed state: preflight=%d version=%d/%d audit records=%d/%d",
					reader.preflightCalls, replayed.ResourceVersion, version,
					len(scenario.fixture.audit.service.Records(committed.ID)), records)
			}
		})
	}
}

func TestDraftInputRejectsAmbiguousOrUnexecutableCampaignValues(t *testing.T) {
	tests := map[string]func(*DraftInput){
		"short authorization list": func(input *DraftInput) { input.AuthorizationIDs = input.AuthorizationIDs[:6] },
		"extra authorization":      func(input *DraftInput) { input.AuthorizationIDs = append(input.AuthorizationIDs, "authorization-8") },
		"short duration list":      func(input *DraftInput) { input.MaximumSeconds = input.MaximumSeconds[:6] },
		"extra duration":           func(input *DraftInput) { input.MaximumSeconds = append(input.MaximumSeconds, 60) },
		"duplicate authorization":  func(input *DraftInput) { input.AuthorizationIDs[6] = input.AuthorizationIDs[0] },
		"zero duration":            func(input *DraftInput) { input.MaximumSeconds[0] = 0 },
		"over executable maximum":  func(input *DraftInput) { input.MaximumSeconds[0] = maximumOperationSeconds + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			mutate(&fixture.input)
			if _, _, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("PrepareDraft() error = %v", err)
			}
		})
	}
}

func TestDraftInputAcceptsMaximumExecutableOperationBudget(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.MaximumSeconds[0] = maximumOperationSeconds
	if _, _, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control); err != nil {
		t.Fatalf("PrepareDraft() rejected maximum executable budget: %v", err)
	}
}

func TestDraftInputAcceptsExplicitlyUnavailableFreshEEPROMHash(t *testing.T) {
	fixture := newWorkflowFixture(t)
	fixture.input.InitialState.EEPROMHashStatus = laneguard.EEPROMHashUnavailable
	fixture.input.InitialState.EEPROMHash = ""
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatalf("PrepareDraft() rejected unavailable fresh EEPROM hash: %v", err)
	}
	got := snapshot.Operations[0].ExpectedPrestate
	if got.EEPROMHashStatus != laneguard.EEPROMHashUnavailable || got.EEPROMHash != "" ||
		snapshot.InitialObservationDigest != fixture.input.ObservationDigest || transaction.Target == nil ||
		transaction.Target.ObservationDigest != snapshot.InitialObservationDigest {
		t.Fatalf("unavailable prestate was not evidence-bound: state=%#v plan=%q target=%#v", got, snapshot.InitialObservationDigest, transaction.Target)
	}
}

func TestPrestateDigestIsPolicyDerivedForEveryOperation(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := plancompiler.DraftFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	first, err := draft.PrestateDigest(1)
	if err != nil {
		t.Fatal(err)
	}
	if first != draft.InitialPrestateDigest() || !digestPattern.MatchString(first) {
		t.Fatalf("initial prestate digest = %q", first)
	}
	commitAttested, err := draft.PrestateDigest(2)
	if err != nil {
		t.Fatal(err)
	}
	if commitAttested == first {
		t.Fatal("fresh and owned prestates have the same digest")
	}
	third, err := draft.PrestateDigest(3)
	if err != nil || third != commitAttested {
		t.Fatalf("sequence 3 prestate digest = %q, %v; want commit-attested digest %q", third, err, commitAttested)
	}
	observed, err := draft.PrestateDigest(4)
	if err != nil {
		t.Fatal(err)
	}
	if observed == commitAttested {
		t.Fatal("commit-attested and independently observed prestates have the same digest")
	}
	for sequence := uint32(5); sequence <= 7; sequence++ {
		got, err := draft.PrestateDigest(sequence)
		if err != nil || got != observed {
			t.Fatalf("sequence %d prestate digest = %q, %v; want observed digest %q", sequence, got, err, observed)
		}
	}
	for _, sequence := range []uint32{0, 8} {
		if _, err := draft.PrestateDigest(sequence); !errors.Is(err, plancompiler.ErrInvalidDraft) {
			t.Fatalf("sequence %d error = %v", sequence, err)
		}
	}
}

func TestEvidenceRejectsEveryMutableOrCrossTransactionAttemptBindingBeforeAudit(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	base, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*EvidenceProposal){
		"schema":             func(value *EvidenceProposal) { value.Attempt.SchemaVersion = "wrong" },
		"key":                func(value *EvidenceProposal) { value.Attempt.Key += "-other" },
		"transaction":        func(value *EvidenceProposal) { value.Attempt.TransactionID = "transaction-other" },
		"plan":               func(value *EvidenceProposal) { value.Attempt.PlanDigest = testDigest("b") },
		"target":             func(value *EvidenceProposal) { value.Attempt.TargetFingerprint = testDigest("c") },
		"fence":              func(value *EvidenceProposal) { value.Attempt.FenceEpoch++ },
		"approval":           func(value *EvidenceProposal) { value.Attempt.ApprovalID = "approval-other" },
		"intent receipt":     func(value *EvidenceProposal) { value.Attempt.IntentReceipt = testDigest("d") },
		"intent sequence":    func(value *EvidenceProposal) { value.Attempt.IntentSequence++ },
		"operation":          func(value *EvidenceProposal) { value.Attempt.Operation = laneguard.OperationColdPowerCycle },
		"operation digest":   func(value *EvidenceProposal) { value.Attempt.OperationDigest = testDigest("e") },
		"started time":       func(value *EvidenceProposal) { value.Attempt.StartedAt = time.Time{} },
		"updated ordering":   func(value *EvidenceProposal) { value.Attempt.UpdatedAt = value.Attempt.StartedAt.Add(-time.Second) },
		"event ordering":     func(value *EvidenceProposal) { value.EventTime = value.Attempt.UpdatedAt.Add(-time.Second) },
		"verified poststate": func(value *EvidenceProposal) { value.Attempt.ObservedState = snapshot.Operations[0].ExpectedPrestate },
		"verified post transition": func(value *EvidenceProposal) {
			value.Attempt.PostObservationTransition = laneguard.BootTransitionOutcome{}
		},
		"result binding":     func(value *EvidenceProposal) { value.Attempt.Result.BindingDigest = "bad" },
		"proposal claim":     func(value *EvidenceProposal) { value.ClaimID = "claim-other" },
		"proposal operation": func(value *EvidenceProposal) { value.OperationID = "authorization-other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			proposal := cloneEvidenceProposal(t, base)
			mutate(&proposal)
			audit := &countingAudit{}
			control := &countingEvidenceRecorder{transaction: transaction}
			_, err := ApplyEvidence(context.Background(), proposal, staticReader{transaction}, audit, control)
			if err == nil {
				t.Fatal("tampered evidence was accepted")
			}
			if audit.calls != 0 || control.calls != 0 {
				t.Fatalf("tampered evidence crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
			}
		})
	}
}

func TestEvidenceProposalRejectsMissingClaimWithoutPanic(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	transaction.ActiveClaim = nil
	if _, err := NewEvidenceProposal(snapshot, transaction, attempt, fixture.now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewEvidenceProposal() error = %v", err)
	}
}

func TestAuditFailureNeverCallsControlRecorder(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	proposal, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	audit := &countingAudit{err: errors.New("audit unavailable")}
	control := &countingEvidenceRecorder{transaction: transaction}
	if _, err := ApplyEvidence(context.Background(), proposal, staticReader{transaction}, audit, control); err == nil {
		t.Fatal("ApplyEvidence() succeeded with failed audit append")
	}
	if audit.calls != 1 || control.calls != 0 {
		t.Fatalf("calls after audit failure: audit=%d control=%d", audit.calls, control.calls)
	}
}

func TestApprovalRejectsStaleControlStateBeforeAudit(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*controlplane.Transaction){
		"resource version": func(value *controlplane.Transaction) { value.ResourceVersion++ },
		"claim replacement": func(value *controlplane.Transaction) {
			claim := *value.ActiveClaim
			claim.ID = "replacement-claim"
			value.ActiveClaim = &claim
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := transaction
			mutate(&changed)
			audit := &countingAudit{}
			preflight := &countingApprovalPreflighter{transaction: changed}
			control := &countingApprovalRecorder{transaction: changed}
			if _, err := ApplyApproval(context.Background(), proposal, preflight, audit, control); err == nil {
				t.Fatal("stale approval proposal was accepted")
			}
			if preflight.calls != 1 || audit.calls != 0 || control.calls != 0 {
				t.Fatalf("stale approval boundary calls: preflight=%d audit=%d control=%d", preflight.calls, audit.calls, control.calls)
			}
		})
	}
}

func TestApprovalPreflightBindsProposalAndAuditFailurePreventsControl(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	preflight := &countingApprovalPreflighter{transaction: transaction}
	audit := &countingAudit{err: errors.New("audit unavailable")}
	control := &countingApprovalRecorder{transaction: transaction}
	if _, err := ApplyApproval(context.Background(), proposal, preflight, audit, control); err == nil {
		t.Fatal("ApplyApproval() succeeded with failed audit append")
	}
	if preflight.calls != 1 || audit.calls != 1 || control.calls != 0 {
		t.Fatalf("approval boundary calls: preflight=%d audit=%d control=%d", preflight.calls, audit.calls, control.calls)
	}
	want := controlplane.ApprovalPreflightRequest{
		SchemaVersion: controlplane.ApprovalPreflightRequestSchemaVersion,
		MutationContext: controlplane.MutationContext{
			TransactionID:           proposal.DraftSnapshot.TransactionID,
			ExpectedResourceVersion: proposal.ExpectedResourceVersion,
			ClaimID:                 proposal.ClaimID, FenceEpoch: proposal.FenceEpoch,
		},
		ApprovalID: proposal.ApprovalID, ApproverID: proposal.ApproverID,
		TransactionDigest: proposal.TransactionDigest, PlanDigest: proposal.DraftSnapshot.PlanDigest,
		StationID: proposal.DraftSnapshot.StationID, LaneID: proposal.DraftSnapshot.LaneID,
		TargetFingerprint: proposal.DraftSnapshot.TargetFingerprint, Release: proposal.DraftSnapshot.Release,
		AllowedOperations: planOperations(proposal.DraftSnapshot),
		ApprovedAt:        proposal.EventTime, ExpiresAt: proposal.DraftSnapshot.ApprovalExpiresAt,
	}
	if !reflect.DeepEqual(preflight.request, want) {
		t.Fatalf("approval preflight = %#v, want %#v", preflight.request, want)
	}
}

func TestApprovalReplayCannotChangeAuditedProposalTime(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyApproval(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	wantVersion := transaction.ResourceVersion
	*fixture.clock = transaction.ActiveClaim.ExpiresAt.Add(time.Second)
	changed := proposal
	changed.EventTime = proposal.EventTime.Add(time.Second)
	if _, err := ApplyApproval(context.Background(), changed, fixture.control, fixture.audit, fixture.control); err == nil {
		t.Fatal("approval replay changed its audited event time")
	}
	persisted, err := fixture.control.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ResourceVersion != wantVersion || len(fixture.audit.service.Records(transaction.ID)) != 1 {
		t.Fatal("changed approval replay mutated control or appended another audit event")
	}
}

func TestExactCommittedApprovalReplaySurvivesClaimAndApprovalExpiry(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyApproval(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	wantVersion := transaction.ResourceVersion
	wantApproval := *transaction.Approval
	*fixture.clock = transaction.ActiveClaim.ExpiresAt.Add(time.Second)
	if !fixture.clock.After(transaction.Approval.ExpiresAt) {
		t.Fatal("test clock did not pass both claim and approval expiry")
	}

	replayed, err := ApplyApproval(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("exact committed approval replay after expiry: %v", err)
	}
	if replayed.ResourceVersion != wantVersion || replayed.Approval == nil ||
		!reflect.DeepEqual(*replayed.Approval, wantApproval) || len(fixture.audit.service.Records(transaction.ID)) != 1 {
		t.Fatalf("post-expiry approval replay changed durable state: %#v", replayed)
	}
}

func TestAuditOnlyApprovalCannotCommitAfterServerExpiry(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	auditRequest, _, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.audit.Append(context.Background(), auditRequest); err != nil {
		t.Fatal(err)
	}
	wantVersion := transaction.ResourceVersion
	*fixture.clock = snapshot.ApprovalExpiresAt
	if !transaction.ActiveClaim.ExpiresAt.After(*fixture.clock) {
		t.Fatal("test claim did not remain live at approval expiry")
	}

	if _, err := ApplyApproval(context.Background(), proposal, fixture.control, fixture.audit, fixture.control); err == nil {
		t.Fatal("audit-only approval committed after its server-time expiry")
	}
	persisted, err := fixture.control.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ResourceVersion != wantVersion || persisted.Status != controlplane.StatusTargetBound || persisted.Approval != nil ||
		len(fixture.audit.service.Records(transaction.ID)) != 1 || len(fixture.audit.receipts) != 1 {
		t.Fatalf("expired audit-only approval changed state: %#v", persisted)
	}
}

func TestReconciliationClaimAndTerminalResultsAreFixedIdempotentAndNonRetrying(t *testing.T) {
	tests := []struct {
		name              string
		status            laneguard.AttemptStatus
		state             func(laneguard.OperationSpec) laneguard.DirectState
		resolution        controlplane.ReconciliationResolution
		operationStatus   controlplane.OperationStatus
		transactionStatus controlplane.TransactionStatus
		auditResult       string
	}{
		{
			name: "confirmed applied", status: laneguard.AttemptVerified,
			state:      func(operation laneguard.OperationSpec) laneguard.DirectState { return operation.ExpectedPoststate },
			resolution: controlplane.ResolutionConfirmedApplied, operationStatus: controlplane.OperationConfirmedApplied,
			transactionStatus: controlplane.StatusReconciled, auditResult: auditlog.ResultReconciled,
		},
		{
			name: "confirmed not applied", status: laneguard.AttemptConfirmedNotApplied,
			state:      func(operation laneguard.OperationSpec) laneguard.DirectState { return operation.ExpectedPrestate },
			resolution: controlplane.ResolutionConfirmedNotApplied, operationStatus: controlplane.OperationConfirmedNotApplied,
			transactionStatus: controlplane.StatusReconciled, auditResult: auditlog.ResultReconciled,
		},
		{
			name: "still uncertain", status: laneguard.AttemptUncertain,
			state:      func(operation laneguard.OperationSpec) laneguard.DirectState { return operation.ExpectedPrestate },
			resolution: controlplane.ResolutionUnknown, operationStatus: controlplane.OperationUncertain,
			transactionStatus: controlplane.StatusQuarantined, auditResult: auditlog.ResultQuarantined,
		},
		{
			name: "reconciliation quarantined", status: laneguard.AttemptQuarantined,
			state:      func(laneguard.OperationSpec) laneguard.DirectState { return laneguard.DirectState{} },
			resolution: controlplane.ResolutionUnknown, operationStatus: controlplane.OperationUncertain,
			transactionStatus: controlplane.StatusQuarantined, auditResult: auditlog.ResultQuarantined,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			snapshot, transaction := uncertainFirstOperation(t, &fixture)
			originalFence := transaction.FenceEpoch
			transaction, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
			if err != nil {
				t.Fatal(err)
			}
			if transaction.Status != controlplane.StatusReconciliationRequired || transaction.ActiveClaim == nil ||
				transaction.ActiveClaim.Mode != controlplane.ClaimModeReconciliation ||
				!reflect.DeepEqual(transaction.ActiveClaim.AllowedStages, []string{"reconciliation"}) ||
				transaction.ActiveClaim.StationID != snapshot.StationID || transaction.ActiveClaim.LaneID != snapshot.LaneID ||
				transaction.FenceEpoch <= originalFence {
				t.Fatalf("prepared reconciliation claim = %#v", transaction)
			}

			attempt := verifiedAttempt(snapshot, transaction, fixture.now)
			attempt.Status = test.status
			attempt.ObservedState = test.state(snapshot.Operations[0])
			proposal, err := NewReconciliationProposal(snapshot, transaction, attempt, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if proposal.Resolution != test.resolution || proposal.OperationID != snapshot.Operations[0].AuthorizationID {
				t.Fatalf("proposal = %#v", proposal)
			}
			transaction, err = ApplyReconciliation(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
			if err != nil {
				t.Fatal(err)
			}
			if transaction.Status != test.transactionStatus || transaction.Operations[0].Status != test.operationStatus {
				t.Fatalf("reconciled transaction = %#v", transaction)
			}
			records := fixture.audit.service.Records(transaction.ID)
			last := records[len(records)-1].Event
			if last.Stage != "reconciliation" || last.FenceEpoch != proposal.FenceEpoch ||
				last.InputDigest != snapshot.PlanDigest || last.Result != test.auditResult || len(last.ObservationReferences) != 2 {
				t.Fatalf("reconciliation audit = %#v", last)
			}

			version := transaction.ResourceVersion
			recordCount := len(records)
			transaction, err = ApplyReconciliation(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
			if err != nil {
				t.Fatalf("replay reconciliation: %v", err)
			}
			if transaction.ResourceVersion != version || len(fixture.audit.service.Records(transaction.ID)) != recordCount {
				t.Fatal("reconciliation replay was not idempotent")
			}

			if test.resolution == controlplane.ResolutionConfirmedNotApplied {
				_, err := fixture.control.TransferClaim(context.Background(), controlplane.TransferClaimRequest{
					SchemaVersion: controlplane.TransferClaimRequestSchemaVersion, IdempotencyKey: "forbidden-retry",
					TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
					ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
					NewStationID: snapshot.StationID, NewLaneID: snapshot.LaneID,
					Mode: controlplane.ClaimModeMutation, AllowedStages: planOperations(snapshot), LeaseDurationSeconds: 300,
				})
				if !errors.Is(err, controlplane.ErrIllegalTransition) {
					t.Fatalf("confirmed-not-applied authorized mutation retry: %v", err)
				}
			}
		})
	}
}

func TestReconciliationClaimResumesAndAcquiresAfterExpiry(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := uncertainFirstOperation(t, &fixture)
	prepared, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatalf("resume reconciliation claim: %v", err)
	}
	if resumed.ActiveClaim.ID != prepared.ActiveClaim.ID || resumed.FenceEpoch != prepared.FenceEpoch ||
		resumed.ResourceVersion <= prepared.ResourceVersion {
		t.Fatalf("resumed claim = %#v, prepared = %#v", resumed.ActiveClaim, prepared.ActiveClaim)
	}

	// A separate transaction whose mutation lease expires takes the fixed
	// AcquireClaim path; it cannot reuse the expired mutation fence.
	expiredFixture := newWorkflowFixture(t)
	expiredSnapshot, expired := uncertainFirstOperation(t, &expiredFixture)
	oldFence := expired.FenceEpoch
	advanced := expired.ActiveClaim.ExpiresAt.Add(time.Second)
	*expiredFixture.clock = advanced
	acquired, err := PrepareReconciliationClaim(context.Background(), expiredSnapshot, advanced, expiredFixture.control)
	if err != nil {
		t.Fatalf("acquire reconciliation after expiry: %v", err)
	}
	if acquired.FenceEpoch <= oldFence || acquired.ActiveClaim.Mode != controlplane.ClaimModeReconciliation ||
		len(acquired.ClaimHistory) == 0 || acquired.ClaimHistory[len(acquired.ClaimHistory)-1].Status != controlplane.ClaimExpired {
		t.Fatalf("claim after expiry = %#v", acquired.ActiveClaim)
	}
	_ = transaction
}

func TestRenewReconciliationClaimRefreshesOnlyTheCurrentReadOnlyClaim(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _ := uncertainFirstOperation(t, &fixture)
	prepared, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	// A still-active claim with less than the five-minute observation budget
	// must be renewable; only the renewed claim must cover that budget.
	reviewedAt := prepared.ActiveClaim.ExpiresAt.Add(-2 * time.Minute)
	*fixture.clock = reviewedAt
	renewed, err := RenewReconciliationClaim(context.Background(), snapshot, reviewedAt, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ResourceVersion != prepared.ResourceVersion+1 || renewed.ActiveClaim.ID != prepared.ActiveClaim.ID ||
		renewed.FenceEpoch != prepared.FenceEpoch || renewed.ActiveClaim.Mode != controlplane.ClaimModeReconciliation ||
		!renewed.ActiveClaim.ExpiresAt.Equal(reviewedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
		!reflect.DeepEqual(renewed.Operations, prepared.Operations) {
		t.Fatalf("renewed reconciliation claim = %#v", renewed)
	}
	repeatedAt := reviewedAt.Add(time.Second)
	*fixture.clock = repeatedAt
	again, err := RenewReconciliationClaim(context.Background(), snapshot, repeatedAt, fixture.control)
	if err != nil {
		t.Fatalf("repeat reconciliation renewal: %v", err)
	}
	if again.ResourceVersion != renewed.ResourceVersion+1 || again.ActiveClaim.ID != renewed.ActiveClaim.ID ||
		!again.ActiveClaim.ExpiresAt.Equal(repeatedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
		!reflect.DeepEqual(again.Operations, renewed.Operations) {
		t.Fatalf("repeated reconciliation renewal = %#v", again)
	}
}

func TestRenewReconciliationClaimRejectsExpiredMutationOrResolvedState(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _ := uncertainFirstOperation(t, &fixture)
	base, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(10 * time.Minute)
	tests := map[string]func(*controlplane.Transaction){
		"mutation claim": func(value *controlplane.Transaction) {
			value.ActiveClaim.Mode = controlplane.ClaimModeMutation
			value.ActiveClaim.AllowedStages = planOperations(snapshot)
		},
		"expired claim": func(value *controlplane.Transaction) { value.ActiveClaim.ExpiresAt = now },
		"closed claim": func(value *controlplane.Transaction) {
			closedAt := now
			value.ActiveClaim.Status = controlplane.ClaimReleased
			value.ActiveClaim.ClosedAt = &closedAt
		},
		"wrong station": func(value *controlplane.Transaction) { value.ActiveClaim.StationID = "station-other" },
		"wrong lane":    func(value *controlplane.Transaction) { value.ActiveClaim.LaneID = "lane-other" },
		"stale fence":   func(value *controlplane.Transaction) { value.ActiveClaim.FenceEpoch++ },
		"approval restored": func(value *controlplane.Transaction) {
			approval := value.Operations[len(value.Operations)-1].Approval
			value.Approval = &approval
		},
		"operation resolved": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusReconciled
			last := &value.Operations[len(value.Operations)-1]
			last.Status = controlplane.OperationConfirmedApplied
			last.ReconciliationAuditReceiptID = testDigest("d")
		},
		"terminal quarantine": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusQuarantined
			value.Quarantine = &controlplane.QuarantineRecord{ReasonCode: "reconciliation_unknown"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneControlTransaction(t, base)
			mutate(&changed)
			control := &recordingClaimRenewer{transaction: changed}
			if _, err := RenewReconciliationClaim(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("invalid reconciliation state was renewed")
			}
			if len(control.requests) != 0 {
				t.Fatal("invalid reconciliation state crossed the renewal authority boundary")
			}
		})
	}

	valid := cloneControlTransaction(t, base)
	valid.ResourceVersion++
	valid.UpdatedAt = now
	valid.ActiveClaim.ExpiresAt = now.Add(time.Duration(claimLeaseSeconds) * time.Second)
	responseTests := map[string]func(*controlplane.Transaction){
		"changed claim": func(value *controlplane.Transaction) { value.ActiveClaim.ID = "claim-other" },
		"changed fence": func(value *controlplane.Transaction) { value.ActiveClaim.FenceEpoch++ },
		"resolved operation": func(value *controlplane.Transaction) {
			value.Status = controlplane.StatusReconciled
			value.Operations[len(value.Operations)-1].Status = controlplane.OperationConfirmedApplied
		},
	}
	for name, mutate := range responseTests {
		t.Run("response "+name, func(t *testing.T) {
			response := cloneControlTransaction(t, valid)
			mutate(&response)
			control := &recordingClaimRenewer{transaction: base, renewed: response}
			if _, err := RenewReconciliationClaim(context.Background(), snapshot, now, control); err == nil {
				t.Fatal("changed reconciliation renewal response was accepted")
			}
			if len(control.requests) != 1 {
				t.Fatalf("renew calls = %d, want 1", len(control.requests))
			}
		})
	}
}

func TestReconciliationRejectsStaleClaimAndTamperingBeforeAudit(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, _ := uncertainFirstOperation(t, &fixture)
	transaction, err := PrepareReconciliationClaim(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	base, err := NewReconciliationProposal(snapshot, transaction, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	withoutObservation := attempt
	withoutObservation.Status = laneguard.AttemptConfirmedNotApplied
	withoutObservation.ObservedState = snapshot.Operations[0].ExpectedPrestate
	withoutObservation.ReconciliationTransition = laneguard.BootTransitionOutcome{}
	if _, err := NewReconciliationProposal(snapshot, transaction, withoutObservation, fixture.now); err == nil {
		t.Fatal("confirmed-not-applied reconciliation without a current observation transition was accepted")
	}
	tests := map[string]func(*ReconciliationProposal){
		"resolution":      func(value *ReconciliationProposal) { value.Resolution = controlplane.ResolutionUnknown },
		"claim":           func(value *ReconciliationProposal) { value.ClaimID = "claim-other" },
		"claim fence":     func(value *ReconciliationProposal) { value.FenceEpoch++ },
		"operation":       func(value *ReconciliationProposal) { value.OperationID = "authorization-other" },
		"attempt fence":   func(value *ReconciliationProposal) { value.Attempt.FenceEpoch++ },
		"attempt plan":    func(value *ReconciliationProposal) { value.Attempt.PlanDigest = testDigest("d") },
		"attempt receipt": func(value *ReconciliationProposal) { value.Attempt.IntentReceipt = testDigest("e") },
		"attempt poststate": func(value *ReconciliationProposal) {
			value.Attempt.ObservedState = snapshot.Operations[0].ExpectedPrestate
		},
		"attempt status": func(value *ReconciliationProposal) { value.Attempt.Status = laneguard.AttemptStarted },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			proposal := cloneReconciliationProposal(t, base)
			mutate(&proposal)
			audit := &countingAudit{}
			control := &countingReconciliationRecorder{transaction: transaction}
			_, err := ApplyReconciliation(context.Background(), proposal, staticReader{transaction}, audit, control)
			if err == nil {
				t.Fatal("tampered reconciliation was accepted")
			}
			if audit.calls != 0 || control.calls != 0 {
				t.Fatalf("tampered reconciliation crossed authority boundary: audit=%d control=%d", audit.calls, control.calls)
			}
		})
	}

	stale := transaction
	claim := *stale.ActiveClaim
	claim.ID = "claim-replaced"
	stale.ActiveClaim = &claim
	audit := &countingAudit{}
	control := &countingReconciliationRecorder{transaction: stale}
	if _, err := ApplyReconciliation(context.Background(), base, staticReader{stale}, audit, control); err == nil {
		t.Fatal("stale reconciliation claim was accepted")
	}
	if audit.calls != 0 || control.calls != 0 {
		t.Fatal("stale claim reached an authority writer")
	}
}

func pendingFirstOperation(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	ctx := context.Background()
	snapshot, transaction, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control); err != nil {
		t.Fatal(err)
	}
	intent, _, err := PrepareNextIntent(ctx, snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyIntent(ctx, intent, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, transaction
}

func approvedEmptyCampaign(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	ctx := context.Background()
	snapshot, transaction, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, transaction
}

func successfulFirstOperation(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	snapshot, transaction := pendingFirstOperation(t, fixture)
	evidence, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyEvidence(context.Background(), evidence, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, transaction
}

func pendingSecondOperation(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	snapshot, _ := successfulFirstOperation(t, fixture)
	intent, _, err := PrepareNextIntent(context.Background(), snapshot, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := ApplyIntent(context.Background(), intent, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, transaction
}

func completedCampaign(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	ctx := context.Background()
	snapshot, transaction, err := PrepareDraft(ctx, fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalProposal(snapshot, transaction, "approver-1", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyApproval(ctx, approval, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	for range snapshot.Operations {
		intent, _, err := PrepareNextIntent(ctx, snapshot, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		transaction, err = ApplyIntent(ctx, intent, fixture.control, fixture.audit, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		transaction, err = ApplyEvidence(ctx, evidence, fixture.control, fixture.audit, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot, transaction
}

func uncertainFirstOperation(t *testing.T, fixture *workflowFixture) (laneguard.Plan, controlplane.Transaction) {
	t.Helper()
	snapshot, transaction := pendingFirstOperation(t, fixture)
	attempt := verifiedAttempt(snapshot, transaction, fixture.now)
	attempt.Status = laneguard.AttemptUncertain
	attempt.ObservedState = snapshot.Operations[0].ExpectedPrestate
	proposal, err := NewEvidenceProposal(snapshot, transaction, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = ApplyEvidence(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, transaction
}

func verifiedAttempt(snapshot laneguard.Plan, transaction controlplane.Transaction, now time.Time) laneguard.Attempt {
	record := transaction.Operations[len(transaction.Operations)-1]
	operation := snapshot.Operations[len(transaction.Operations)-1]
	base := laneguard.HardwareAction{
		SchemaVersion: laneguard.BootTransitionActionSchemaVersion,
		StationID:     snapshot.StationID, LaneID: snapshot.LaneID,
		TransactionID: snapshot.TransactionID, PlanDigest: snapshot.PlanDigest,
		TargetFingerprint: snapshot.TargetFingerprint, FenceEpoch: snapshot.FenceEpoch,
		ApprovalID: record.Approval.ID, IntentReceipt: record.IntentAuditReceiptID,
		IntentSequence: operation.Sequence, Sequence: operation.Sequence,
		Operation: operation.Operation, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, OperationRequiredBootMode: operation.RequiredBootMode,
	}
	preAction := base
	preAction.Phase = laneguard.HardwarePhasePreObservation
	preAction.RequestedBootMode = laneguard.BootModeRPIBoot
	executeAction := base
	executeAction.Phase = laneguard.HardwarePhaseExecute
	executeAction.RequestedBootMode = operation.RequiredBootMode
	postAction := base
	postAction.Phase = laneguard.HardwarePhasePostObservation
	postAction.RequestedBootMode = laneguard.BootModeRPIBoot
	pre := completedBootTransitionOutcome(preAction, now.Add(-30*time.Second))
	execution := completedBootTransitionOutcome(executeAction, now.Add(-20*time.Second))
	post := completedBootTransitionOutcome(postAction, now.Add(-10*time.Second))
	attempt := laneguard.Attempt{
		SchemaVersion: laneguard.AttemptSchemaVersion,
		Key:           fmt.Sprintf("%s/%s/%d/%d", snapshot.TransactionID, snapshot.PlanDigest, snapshot.FenceEpoch, operation.Sequence),
		TransactionID: snapshot.TransactionID, PlanDigest: snapshot.PlanDigest,
		TargetFingerprint: snapshot.TargetFingerprint, FenceEpoch: snapshot.FenceEpoch,
		ApprovalID: record.Approval.ID, IntentReceipt: record.IntentAuditReceiptID,
		IntentSequence: operation.Sequence, Sequence: operation.Sequence, Operation: operation.Operation,
		OperationDigest: operation.OperationDigest, Status: laneguard.AttemptVerified,
		StartedAt: now.Add(-time.Minute), UpdatedAt: now,
		Result: laneguard.OperationResult{
			OutputDigest: testDigest("f"), BindingDigest: testDigest("0"), Detail: "fixed result",
			BootTransition: execution,
		},
		ObservedState:            operation.ExpectedPoststate,
		PreObservationTransition: pre, ExecutionTransition: execution, PostObservationTransition: post,
		Detail: "direct postcondition verified",
	}
	if transaction.ActiveClaim != nil && transaction.ActiveClaim.Mode == controlplane.ClaimModeReconciliation {
		reconciliationAction := base
		reconciliationAction.Phase = laneguard.HardwarePhaseReconciliation
		reconciliationAction.RequestedBootMode = laneguard.BootModeRPIBoot
		reconciliationAction.ReconciliationClaimID = transaction.ActiveClaim.ID
		reconciliationAction.ReconciliationFenceEpoch = transaction.FenceEpoch
		attempt.ReconciliationTransition = completedBootTransitionOutcome(reconciliationAction, now.Add(-5*time.Second))
	}
	return attempt
}

func completedBootTransitionOutcome(action laneguard.HardwareAction, start time.Time) laneguard.BootTransitionOutcome {
	modeObserved := start.Add(5 * time.Second)
	evidence := laneguard.BootTransitionEvidence{
		SchemaVersion: laneguard.BootTransitionEvidenceSchemaVersion,
		TransitionKey: laneguard.BootTransitionKey(action, 1), Generation: 1, Action: action,
		StartedAt: start, PromptID: "prompt-test", PromptDigest: testDigest("1"),
		PromptExpiresAt: start.Add(20 * time.Second), Operator: laneguard.OperatorPeer{UID: 1000, GID: 1000, PID: 100},
		PowerOffObservedAt: start, USBAbsentObservedAt: start.Add(time.Second), ColdIntervalEndsAt: start.Add(2 * time.Second),
		OperatorAcknowledgedAt: start.Add(3 * time.Second), PowerAppliedAt: start.Add(4 * time.Second),
		ModeObservedAt: modeObserved, ObservedMode: action.RequestedBootMode,
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", RPIBootObservationMethod: laneguard.RPIBootObservationSysfsPoll,
		RPIBootPollInterval: 100 * time.Millisecond, SafeOffObservedAt: start.Add(7 * time.Second), CompletedAt: start.Add(8 * time.Second),
	}
	if action.RequestedBootMode == laneguard.BootModeRPIBoot {
		evidence.RPIBootEligibleTargets = 1
		evidence.ReleasePromptID = "release-test"
		evidence.ReleasePromptDigest = testDigest("2")
		evidence.ReleasePromptExpiresAt = start.Add(20 * time.Second)
		evidence.ReleaseOperator = laneguard.OperatorPeer{UID: 1000, GID: 1000, PID: 101}
		evidence.OperatorReleasedAt = start.Add(6 * time.Second)
	} else {
		evidence.UARTPath = "/dev/serial/by-id/operator-workflow-test"
		evidence.UARTOutputDigest = testDigest("3")
		evidence.RPIBootNotObservedThrough = modeObserved
	}
	digest, err := evidence.Digest()
	if err != nil {
		panic(fmt.Sprintf("construct test boot-transition evidence: %v", err))
	}
	outcome := laneguard.BootTransitionOutcome{
		SchemaVersion: laneguard.BootTransitionOutcomeSchemaVersion,
		Action:        action,
		Generation:    1,
		Reference: laneguard.BootTransitionReference{
			SchemaVersion: laneguard.BootTransitionReferenceSchemaVersion,
			TransitionKey: evidence.TransitionKey, Status: laneguard.BootTransitionCompleted, EvidenceDigest: digest,
		},
		Evidence: evidence,
	}
	if err := outcome.ValidateForAction(action); err != nil {
		panic(fmt.Sprintf("construct test boot-transition outcome: %v", err))
	}
	return outcome
}

func cloneEvidenceProposal(t *testing.T, proposal EvidenceProposal) EvidenceProposal {
	t.Helper()
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var clone EvidenceProposal
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func cloneReconciliationProposal(t *testing.T, proposal ReconciliationProposal) ReconciliationProposal {
	t.Helper()
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var clone ReconciliationProposal
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func cloneSecurityAppliedProposal(t *testing.T, proposal SecurityAppliedProposal) SecurityAppliedProposal {
	t.Helper()
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var clone SecurityAppliedProposal
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func cloneControlTransaction(t *testing.T, transaction controlplane.Transaction) controlplane.Transaction {
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

type applyPreflightScenario struct {
	fixture       *workflowFixture
	transaction   controlplane.Transaction
	applyCounting func(transactionReader, auditAppender) (controlplane.Transaction, error)
	applyReal     func(transactionReader, auditAppender) (controlplane.Transaction, error)
	controlCalls  func() int
}

func newApplyPreflightScenario(t *testing.T, kind string) applyPreflightScenario {
	t.Helper()
	fixture := newWorkflowFixture(t)
	ctx := context.Background()
	switch kind {
	case "intent":
		snapshot, _ := approvedEmptyCampaign(t, &fixture)
		proposal, transaction, err := PrepareNextIntent(ctx, snapshot, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		writer := &countingIntentRecorder{transaction: transaction}
		return applyPreflightScenario{
			fixture: &fixture, transaction: transaction,
			applyCounting: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyIntent(ctx, proposal, current, audit, writer)
			},
			applyReal: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyIntent(ctx, proposal, current, audit, fixture.control)
			},
			controlCalls: func() int { return writer.calls },
		}
	case "evidence":
		snapshot, transaction := pendingFirstOperation(t, &fixture)
		proposal, err := NewEvidenceProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		writer := &countingEvidenceRecorder{transaction: transaction}
		return applyPreflightScenario{
			fixture: &fixture, transaction: transaction,
			applyCounting: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyEvidence(ctx, proposal, current, audit, writer)
			},
			applyReal: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyEvidence(ctx, proposal, current, audit, fixture.control)
			},
			controlCalls: func() int { return writer.calls },
		}
	case "security applied":
		snapshot, transaction := completedCampaign(t, &fixture)
		proposal, err := NewSecurityAppliedProposal(snapshot, transaction, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		writer := &countingSecurityAppliedRecorder{transaction: transaction}
		return applyPreflightScenario{
			fixture: &fixture, transaction: transaction,
			applyCounting: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplySecurityApplied(ctx, proposal, current, audit, writer)
			},
			applyReal: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplySecurityApplied(ctx, proposal, current, audit, fixture.control)
			},
			controlCalls: func() int { return writer.calls },
		}
	case "reconciliation":
		snapshot, _ := uncertainFirstOperation(t, &fixture)
		transaction, err := PrepareReconciliationClaim(ctx, snapshot, fixture.now, fixture.control)
		if err != nil {
			t.Fatal(err)
		}
		proposal, err := NewReconciliationProposal(snapshot, transaction, verifiedAttempt(snapshot, transaction, fixture.now), fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		writer := &countingReconciliationRecorder{transaction: transaction}
		return applyPreflightScenario{
			fixture: &fixture, transaction: transaction,
			applyCounting: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyReconciliation(ctx, proposal, current, audit, writer)
			},
			applyReal: func(current transactionReader, audit auditAppender) (controlplane.Transaction, error) {
				return ApplyReconciliation(ctx, proposal, current, audit, fixture.control)
			},
			controlCalls: func() int { return writer.calls },
		}
	default:
		t.Fatalf("unknown apply preflight scenario %q", kind)
		return applyPreflightScenario{}
	}
}

type recordingCurrentClaimReader struct {
	transaction          controlplane.Transaction
	preflightTransaction controlplane.Transaction
	preflightErr         error
	preflightCalls       int
}

func (reader *recordingCurrentClaimReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return reader.transaction, nil
}

func (reader *recordingCurrentClaimReader) PreflightCurrentClaim(_ context.Context, _ controlplane.CurrentClaimPreflightRequest) (controlplane.Transaction, error) {
	reader.preflightCalls++
	return reader.preflightTransaction, reader.preflightErr
}

type staticReader struct{ transaction controlplane.Transaction }

func (reader staticReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return reader.transaction, nil
}

func (reader staticReader) PreflightCurrentClaim(_ context.Context, request controlplane.CurrentClaimPreflightRequest) (controlplane.Transaction, error) {
	if request.SchemaVersion != controlplane.CurrentClaimPreflightRequestSchemaVersion ||
		request.TransactionID != reader.transaction.ID ||
		request.ExpectedResourceVersion != reader.transaction.ResourceVersion || reader.transaction.ActiveClaim == nil ||
		request.ClaimID != reader.transaction.ActiveClaim.ID || request.FenceEpoch != reader.transaction.FenceEpoch {
		return controlplane.Transaction{}, ErrStateMismatch
	}
	return reader.transaction, nil
}

type recordingClaimRenewer struct {
	transaction controlplane.Transaction
	renewed     controlplane.Transaction
	requests    []controlplane.RenewClaimRequest
}

type recordingRenewClient struct {
	service  *controlplane.Service
	requests []controlplane.RenewClaimRequest
}

func (control *recordingRenewClient) GetTransaction(ctx context.Context, transactionID string) (controlplane.Transaction, error) {
	return control.service.GetTransaction(ctx, transactionID)
}

func (control *recordingRenewClient) RenewClaim(ctx context.Context, request controlplane.RenewClaimRequest) (controlplane.Transaction, error) {
	control.requests = append(control.requests, request)
	return control.service.RenewClaim(ctx, request)
}

func (control *recordingRenewClient) onlyRequest(t *testing.T) controlplane.RenewClaimRequest {
	t.Helper()
	if len(control.requests) != 1 {
		t.Fatalf("renew calls = %d, want 1", len(control.requests))
	}
	return control.requests[0]
}

type recordingClaimReleaser struct {
	transaction controlplane.Transaction
	released    controlplane.Transaction
	requests    []controlplane.ReleaseClaimRequest
	err         error
}

func (control *recordingClaimReleaser) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return control.transaction, nil
}

func (control *recordingClaimReleaser) ReleaseClaim(_ context.Context, request controlplane.ReleaseClaimRequest) (controlplane.Transaction, error) {
	control.requests = append(control.requests, request)
	return control.released, control.err
}

func (control *recordingClaimRenewer) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return control.transaction, nil
}

func (control *recordingClaimRenewer) RenewClaim(_ context.Context, request controlplane.RenewClaimRequest) (controlplane.Transaction, error) {
	control.requests = append(control.requests, request)
	return control.renewed, nil
}

type countingAudit struct {
	calls int
	err   error
}

func (audit *countingAudit) Append(context.Context, auditlog.AppendRequest) (auditlog.Receipt, error) {
	audit.calls++
	return auditlog.Receipt{SchemaVersion: auditlog.ReceiptSchemaVersion, ReceiptID: validPlaceholderDigest}, audit.err
}

type countingEvidenceRecorder struct {
	calls       int
	transaction controlplane.Transaction
}

type countingIntentRecorder struct {
	calls       int
	transaction controlplane.Transaction
}

type countingApprovalRecorder struct {
	calls       int
	transaction controlplane.Transaction
}

type countingApprovalPreflighter struct {
	calls       int
	request     controlplane.ApprovalPreflightRequest
	transaction controlplane.Transaction
	err         error
}

func (control *countingApprovalPreflighter) PreflightApproval(_ context.Context, request controlplane.ApprovalPreflightRequest) (controlplane.Transaction, error) {
	control.calls++
	control.request = request
	return control.transaction, control.err
}

func (control *countingApprovalRecorder) RecordApproval(context.Context, controlplane.RecordApprovalRequest) (controlplane.Transaction, error) {
	control.calls++
	return control.transaction, nil
}

func (control *countingIntentRecorder) RecordIntent(context.Context, controlplane.RecordIntentRequest) (controlplane.Transaction, error) {
	control.calls++
	return control.transaction, nil
}

func (control *countingEvidenceRecorder) RecordEvidence(context.Context, controlplane.RecordEvidenceRequest) (controlplane.Transaction, error) {
	control.calls++
	return control.transaction, nil
}

type countingReconciliationRecorder struct {
	calls       int
	transaction controlplane.Transaction
}

func (control *countingReconciliationRecorder) RecordReconciliation(context.Context, controlplane.RecordReconciliationRequest) (controlplane.Transaction, error) {
	control.calls++
	return control.transaction, nil
}

type countingSecurityAppliedRecorder struct {
	calls       int
	transaction controlplane.Transaction
}

func (control *countingSecurityAppliedRecorder) MarkSecurityApplied(context.Context, controlplane.SecurityAppliedRequest) (controlplane.Transaction, error) {
	control.calls++
	return control.transaction, nil
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
