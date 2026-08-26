package operatorworkflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

func TestPendingEvidenceRenewalPreservesAuthorizedTerminalResultAfterApprovalExpiry(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, pending := pendingFirstOperation(t, &fixture)

	// The operation began under its immutable approval and completed just after
	// that approval expired. The same mutation claim is still live.
	completedAt := fixture.input.ApprovalExpiresAt.Add(30 * time.Second)
	*fixture.clock = completedAt
	if !pending.ActiveClaim.ExpiresAt.After(completedAt) {
		t.Fatal("test setup did not leave the original mutation claim active")
	}
	if _, err := RenewPendingIntent(context.Background(), snapshot, completedAt, fixture.control); err == nil {
		t.Fatal("RenewPendingIntent() accepted an expired approval")
	}

	renewed, err := RenewPendingEvidence(context.Background(), snapshot, completedAt, fixture.control)
	if err != nil {
		t.Fatalf("RenewPendingEvidence() rejected terminal evidence: %v", err)
	}
	if renewed.ResourceVersion != pending.ResourceVersion+1 || renewed.ActiveClaim.ID != pending.ActiveClaim.ID ||
		!renewed.ActiveClaim.ExpiresAt.Equal(completedAt.Add(time.Duration(claimLeaseSeconds)*time.Second)) ||
		len(renewed.Operations) != 1 || renewed.Operations[0].Status != controlplane.OperationIntentRecorded {
		t.Fatalf("evidence-only renewal changed pending authority: %#v", renewed)
	}

	attempt := verifiedAttempt(snapshot, renewed, completedAt)
	if !attempt.StartedAt.Before(fixture.input.ApprovalExpiresAt) || attempt.UpdatedAt.Before(fixture.input.ApprovalExpiresAt) {
		t.Fatalf("test attempt does not cross approval expiry: %#v", attempt)
	}
	proposal, err := NewEvidenceProposal(snapshot, renewed, attempt, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := ApplyEvidence(context.Background(), proposal, fixture.control, fixture.audit, fixture.control)
	if err != nil {
		t.Fatalf("ApplyEvidence() rejected authorized terminal evidence after approval expiry: %v", err)
	}
	if recorded.Status != controlplane.StatusCommitApproved ||
		recorded.Operations[0].Status != controlplane.OperationSucceeded {
		t.Fatalf("recorded terminal evidence = %#v", recorded)
	}
}

func TestPendingEvidenceRenewalCannotReviveExpiredClaim(t *testing.T) {
	fixture := newWorkflowFixture(t)
	snapshot, pending := pendingFirstOperation(t, &fixture)
	expiredAt := pending.ActiveClaim.ExpiresAt
	*fixture.clock = expiredAt

	if _, err := RenewPendingEvidence(context.Background(), snapshot, expiredAt, fixture.control); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("RenewPendingEvidence() error = %v, want state mismatch", err)
	}
}

func TestPendingEvidenceRenewalRejectsAuthorityAndPendingStateDriftBeforeRenewal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*controlplane.Transaction)
	}{
		{
			name: "intent outside original approval window",
			mutate: func(transaction *controlplane.Transaction) {
				transaction.Operations[len(transaction.Operations)-1].IntentAt = transaction.Approval.ExpiresAt
			},
		},
		{
			name: "embedded approval changed",
			mutate: func(transaction *controlplane.Transaction) {
				transaction.Operations[len(transaction.Operations)-1].Approval.ApproverID = "approver-2"
			},
		},
		{
			name: "top-level approval changed",
			mutate: func(transaction *controlplane.Transaction) {
				transaction.Approval.ApproverID = "approver-2"
			},
		},
		{
			name: "pending result added",
			mutate: func(transaction *controlplane.Transaction) {
				transaction.Operations[len(transaction.Operations)-1].OutputDigest = testDigest("c")
			},
		},
		{
			name: "claim replaced at a new fence",
			mutate: func(transaction *controlplane.Transaction) {
				transaction.ActiveClaim.ID = "claim-replaced"
				transaction.ActiveClaim.FenceEpoch++
				transaction.FenceEpoch++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			snapshot, pending := pendingFirstOperation(t, &fixture)
			validationTime := fixture.input.ApprovalExpiresAt.Add(30 * time.Second)

			changed := pending
			claim := *pending.ActiveClaim
			changed.ActiveClaim = &claim
			approval := *pending.Approval
			changed.Approval = &approval
			changed.Operations = append([]controlplane.OperationRecord(nil), pending.Operations...)
			test.mutate(&changed)
			control := &recordingClaimRenewer{transaction: changed}

			if _, err := RenewPendingEvidence(context.Background(), snapshot, validationTime, control); !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("RenewPendingEvidence() error = %v, want state mismatch", err)
			}
			if len(control.requests) != 0 {
				t.Fatalf("invalid state issued %d renewal request(s)", len(control.requests))
			}
		})
	}
}
