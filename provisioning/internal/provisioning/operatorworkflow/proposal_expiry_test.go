package operatorworkflow

import (
	"context"
	"errors"
	"testing"
)

func TestApprovalProposalAndRenewalRejectReviewedWindowExpiry(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction, err := PrepareDraft(context.Background(), fixture.input, fixture.now, fixture.control)
	if err != nil {
		t.Fatal(err)
	}
	expiredAt := snapshot.ApprovalExpiresAt
	control := &recordingClaimRenewer{transaction: transaction}

	if _, err := RenewTargetBoundCampaign(context.Background(), snapshot, expiredAt, control); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("RenewTargetBoundCampaign() error = %v, want state mismatch", err)
	}
	if len(control.requests) != 0 {
		t.Fatalf("expired approval window issued %d renewal request(s)", len(control.requests))
	}
	if _, err := NewApprovalProposal(snapshot, transaction, "approver-1", expiredAt); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("NewApprovalProposal() error = %v, want state mismatch", err)
	}
}

func TestIntentProposalAndPreparationRejectApprovalExpiryBeforeRenewal(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := approvedEmptyCampaign(t, &fixture)
	expiredAt := snapshot.ApprovalExpiresAt
	control := &recordingClaimRenewer{transaction: transaction}

	if _, _, err := PrepareNextIntent(context.Background(), snapshot, expiredAt, control); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("PrepareNextIntent() error = %v, want state mismatch", err)
	}
	if len(control.requests) != 0 {
		t.Fatalf("expired approval issued %d intent renewal request(s)", len(control.requests))
	}
	if _, err := NewIntentProposal(snapshot, transaction, 1, expiredAt); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("NewIntentProposal() error = %v, want state mismatch", err)
	}
}

func TestEvidenceProposalRejectsExpiredClaim(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	expiredAt := transaction.ActiveClaim.ExpiresAt
	attempt := verifiedAttempt(snapshot, transaction, expiredAt)

	if _, err := NewEvidenceProposal(snapshot, transaction, attempt, expiredAt); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("NewEvidenceProposal() error = %v, want state mismatch", err)
	}
}

func TestEvidenceProposalAcceptsExpiredApprovalWhileExactClaimIsCurrent(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, transaction := pendingFirstOperation(t, &fixture)
	eventTime := snapshot.ApprovalExpiresAt
	if !transaction.ActiveClaim.ExpiresAt.After(eventTime) {
		t.Fatal("test setup did not retain the exact current claim")
	}
	attempt := verifiedAttempt(snapshot, transaction, eventTime)

	proposal, err := NewEvidenceProposal(snapshot, transaction, attempt, eventTime)
	if err != nil {
		t.Fatalf("NewEvidenceProposal() rejected terminal evidence at approval expiry: %v", err)
	}
	if proposal.ExpectedResourceVersion != transaction.ResourceVersion || proposal.ClaimID != transaction.ActiveClaim.ID ||
		proposal.OperationID != transaction.Operations[0].ID || string(proposal.Attempt.Status) != "verified" {
		t.Fatalf("evidence proposal = %#v", proposal)
	}
}
