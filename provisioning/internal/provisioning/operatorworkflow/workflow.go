// Package operatorworkflow assembles the fixed Raspberry Pi 5 development
// campaign and prepares its narrowly typed control/audit authority. It never
// accepts an operation list, operation selector, executable path, artifact
// path, hardware path, boot-mode selector, or generic control command.
package operatorworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	DraftInputSchemaVersion             = "provisioning.kaiba.network/operator-draft-input/v1alpha1"
	ApprovalProposalSchemaVersion       = "provisioning.kaiba.network/operator-approval-proposal/v1alpha1"
	IntentProposalSchemaVersion         = "provisioning.kaiba.network/operator-intent-proposal/v1alpha1"
	EvidenceProposalSchemaVersion       = "provisioning.kaiba.network/operator-evidence-proposal/v1alpha1"
	ReconciliationProposalSchemaVersion = "provisioning.kaiba.network/operator-reconciliation-proposal/v1alpha1"

	claimLeaseSeconds = uint32(3600)
	maximumApproval   = 24 * time.Hour
	digestDomain      = "kaiba.provisioning.operator-workflow.v1alpha1"
)

var (
	ErrInvalidInput   = errors.New("invalid operator workflow input")
	ErrStateMismatch  = errors.New("operator workflow state mismatch")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// DraftInput is the complete reviewed, authority-free input to the fixed
// seven-operation compiler. The operation vocabulary, ordering,
// classifications, boot modes, and claim stages are not input fields.
type DraftInput struct {
	SchemaVersion     string                 `json:"schema_version"`
	StationID         string                 `json:"station_id"`
	LaneID            string                 `json:"lane_id"`
	TransactionID     string                 `json:"transaction_id"`
	AssetID           string                 `json:"asset_id"`
	IntendedLogicalID string                 `json:"intended_logical_id"`
	ProfileID         string                 `json:"profile_id"`
	PolicyDigest      string                 `json:"policy_digest"`
	Release           releasebinding.Binding `json:"release"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	ObservationDigest string                 `json:"observation_digest"`
	InitialState      laneguard.DirectState  `json:"initial_state"`
	ApprovalExpiresAt time.Time              `json:"approval_expires_at"`
	AuthorizationIDs  []string               `json:"authorization_ids"`
	MaximumSeconds    []uint32               `json:"maximum_duration_seconds"`
}

// ApprovalProposal is durable, secret-free material handed to the independent
// approver. The requests emitted from it are reconstructed from the validated
// draft; the proposal cannot carry a caller-selected operation set.
type ApprovalProposal struct {
	SchemaVersion           string         `json:"schema_version"`
	DraftSnapshot           laneguard.Plan `json:"draft_snapshot"`
	ApprovalID              string         `json:"approval_id"`
	ApproverID              string         `json:"approver_id"`
	TransactionDigest       string         `json:"transaction_digest"`
	ExpectedResourceVersion uint64         `json:"expected_resource_version"`
	ClaimID                 string         `json:"claim_id"`
	FenceEpoch              uint64         `json:"fence_epoch"`
	EventTime               time.Time      `json:"event_time"`
}

// IntentProposal is one durable, retryable proposal for the compiler-derived
// next operation. It contains a sequence for review, but no operation selector;
// the operation and prestate are recovered from DraftSnapshot.
type IntentProposal struct {
	SchemaVersion           string         `json:"schema_version"`
	DraftSnapshot           laneguard.Plan `json:"draft_snapshot"`
	ExpectedResourceVersion uint64         `json:"expected_resource_version"`
	ClaimID                 string         `json:"claim_id"`
	FenceEpoch              uint64         `json:"fence_epoch"`
	ApprovalID              string         `json:"approval_id"`
	OperationID             string         `json:"operation_id"`
	Sequence                uint32         `json:"sequence"`
	EventTime               time.Time      `json:"event_time"`
}

// EvidenceProposal binds one terminal lane-guard attempt to the currently
// pending control operation. Attempt is secret-free and is retained verbatim
// so retries cannot silently change the reported result.
type EvidenceProposal struct {
	SchemaVersion           string            `json:"schema_version"`
	DraftSnapshot           laneguard.Plan    `json:"draft_snapshot"`
	ExpectedResourceVersion uint64            `json:"expected_resource_version"`
	ClaimID                 string            `json:"claim_id"`
	FenceEpoch              uint64            `json:"fence_epoch"`
	OperationID             string            `json:"operation_id"`
	Attempt                 laneguard.Attempt `json:"attempt"`
	EventTime               time.Time         `json:"event_time"`
}

// ReconciliationProposal binds a trusted terminal observation of the
// original execute-once attempt to a fresh read-only reconciliation claim.
// Resolution is reviewable but is always rederived from Attempt; it is not a
// caller-selected control transition.
type ReconciliationProposal struct {
	SchemaVersion           string                                `json:"schema_version"`
	DraftSnapshot           laneguard.Plan                        `json:"draft_snapshot"`
	ExpectedResourceVersion uint64                                `json:"expected_resource_version"`
	ClaimID                 string                                `json:"claim_id"`
	FenceEpoch              uint64                                `json:"fence_epoch"`
	OperationID             string                                `json:"operation_id"`
	Resolution              controlplane.ReconciliationResolution `json:"resolution"`
	Attempt                 laneguard.Attempt                     `json:"attempt"`
	EventTime               time.Time                             `json:"event_time"`
}

type transactionCreator interface {
	CreateTransaction(context.Context, controlplane.CreateTransactionRequest) (controlplane.Transaction, error)
	AcquireClaim(context.Context, controlplane.AcquireClaimRequest) (controlplane.Transaction, error)
	BindTarget(context.Context, controlplane.BindTargetRequest) (controlplane.Transaction, error)
}

type transactionReader interface {
	GetTransaction(context.Context, string) (controlplane.Transaction, error)
}

type claimRenewer interface {
	RenewClaim(context.Context, controlplane.RenewClaimRequest) (controlplane.Transaction, error)
}

type claimAcquirer interface {
	AcquireClaim(context.Context, controlplane.AcquireClaimRequest) (controlplane.Transaction, error)
}

type claimTransferer interface {
	TransferClaim(context.Context, controlplane.TransferClaimRequest) (controlplane.Transaction, error)
}

type approvalRecorder interface {
	RecordApproval(context.Context, controlplane.RecordApprovalRequest) (controlplane.Transaction, error)
}

type intentRecorder interface {
	RecordIntent(context.Context, controlplane.RecordIntentRequest) (controlplane.Transaction, error)
}

type evidenceRecorder interface {
	RecordEvidence(context.Context, controlplane.RecordEvidenceRequest) (controlplane.Transaction, error)
}

type reconciliationRecorder interface {
	RecordReconciliation(context.Context, controlplane.RecordReconciliationRequest) (controlplane.Transaction, error)
}

type auditAppender interface {
	Append(context.Context, auditlog.AppendRequest) (auditlog.Receipt, error)
}

// PrepareDraft creates/resumes the exact transaction, acquires its fixed
// mutation claim, binds the reviewed fresh observation, and only then compiles
// the authority-free draft using the returned fence epoch.
func PrepareDraft(ctx context.Context, input DraftInput, now time.Time, control transactionCreator) (laneguard.Plan, controlplane.Transaction, error) {
	if control == nil {
		return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("%w: control client is required", ErrInvalidInput)
	}
	if err := validateDraftInput(input, now); err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, err
	}
	operations := developmentOperationNames()
	transaction, err := control.CreateTransaction(ctx, controlplane.CreateTransactionRequest{
		SchemaVersion:  controlplane.CreateTransactionRequestSchemaVersion,
		IdempotencyKey: workflowID("create", input.TransactionID),
		TransactionID:  input.TransactionID, AssetID: input.AssetID,
		IntendedLogicalID: input.IntendedLogicalID, ProfileID: input.ProfileID,
		BundleDigest: input.Release.SignedReleaseManifestDigest, PolicyDigest: input.PolicyDigest,
		ExpectedPrestateCustomerKeyHash: input.InitialState.CustomerKeyHash,
		ExpectedCustomerKeyHash:         input.Release.ExpectedCustomerKeyHash,
	})
	if err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("create transaction: %w", err)
	}
	if err := matchCreatedTransaction(transaction, input); err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, err
	}
	switch transaction.Status {
	case controlplane.StatusCreated:
		transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
			SchemaVersion:  controlplane.AcquireClaimRequestSchemaVersion,
			IdempotencyKey: workflowID("claim", input.TransactionID, fmt.Sprint(transaction.ResourceVersion)),
			TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
			StationID: input.StationID, LaneID: input.LaneID, Mode: controlplane.ClaimModeMutation,
			AllowedStages: operations, LeaseDurationSeconds: claimLeaseSeconds,
		})
		if err != nil {
			return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("acquire fixed campaign claim: %w", err)
		}
	case controlplane.StatusClaimed, controlplane.StatusTargetBound:
		// A lost response can leave the preceding compare-and-set durably
		// committed. Resume only the exact same active campaign; never acquire
		// fresh authority from an old target observation.
	default:
		return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("%w: draft preparation cannot resume transaction status %q", ErrStateMismatch, transaction.Status)
	}
	if err := matchClaim(transaction, input.StationID, input.LaneID, operations); err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, err
	}
	if !transaction.ActiveClaim.ExpiresAt.After(now.UTC()) {
		return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("%w: fixed campaign claim is already expired", ErrStateMismatch)
	}
	if transaction.Status == controlplane.StatusClaimed {
		transaction, err = control.BindTarget(ctx, controlplane.BindTargetRequest{
			SchemaVersion:     controlplane.BindTargetRequestSchemaVersion,
			IdempotencyKey:    workflowID("bind-target", input.TransactionID, fmt.Sprint(transaction.ResourceVersion)),
			MutationContext:   mutationContext(transaction),
			TargetFingerprint: input.TargetFingerprint, ObservationDigest: input.ObservationDigest,
			CustomerKeyHash: input.InitialState.CustomerKeyHash,
		})
		if err != nil {
			return laneguard.Plan{}, controlplane.Transaction{}, fmt.Errorf("bind reviewed target observation: %w", err)
		}
	}
	if err := matchBoundTransaction(transaction, input); err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, err
	}
	draft, err := buildDraft(input, transaction.FenceEpoch)
	if err != nil {
		return laneguard.Plan{}, controlplane.Transaction{}, err
	}
	return draft.Snapshot(), transaction, nil
}

func validateDraftInput(input DraftInput, now time.Time) error {
	if input.SchemaVersion != DraftInputSchemaVersion || now.IsZero() {
		return fmt.Errorf("%w: schema version or current time", ErrInvalidInput)
	}
	if !identifierPattern.MatchString(input.AssetID) || !identifierPattern.MatchString(input.IntendedLogicalID) ||
		!identifierPattern.MatchString(input.ProfileID) || !digestPattern.MatchString(input.PolicyDigest) ||
		!digestPattern.MatchString(input.ObservationDigest) {
		return fmt.Errorf("%w: transaction metadata or observation digest", ErrInvalidInput)
	}
	if !input.ApprovalExpiresAt.After(now.UTC()) || input.ApprovalExpiresAt.After(now.UTC().Add(maximumApproval)) {
		return fmt.Errorf("%w: approval expiry must be within the next 24 hours", ErrInvalidInput)
	}
	if len(input.AuthorizationIDs) != len(campaign.DevelopmentOperations()) ||
		len(input.MaximumSeconds) != len(campaign.DevelopmentOperations()) {
		return fmt.Errorf("%w: exactly seven authorization IDs and duration budgets are required", ErrInvalidInput)
	}
	seenAuthorizations := make(map[string]struct{}, len(input.AuthorizationIDs))
	for index, authorizationID := range input.AuthorizationIDs {
		if _, exists := seenAuthorizations[authorizationID]; exists {
			return fmt.Errorf("%w: authorization %d duplicates an earlier operation ID", ErrInvalidInput, index+1)
		}
		seenAuthorizations[authorizationID] = struct{}{}
	}
	_, err := buildDraft(input, 1)
	return err
}

func buildDraft(input DraftInput, fenceEpoch uint64) (plancompiler.Draft, error) {
	var maximum [7]time.Duration
	var authorizationIDs [7]string
	if len(input.AuthorizationIDs) != len(authorizationIDs) || len(input.MaximumSeconds) != len(maximum) {
		return plancompiler.Draft{}, fmt.Errorf("%w: exactly seven authorization IDs and duration budgets are required", ErrInvalidInput)
	}
	for index, seconds := range input.MaximumSeconds {
		if seconds == 0 || seconds >= claimLeaseSeconds {
			return plancompiler.Draft{}, fmt.Errorf("%w: maximum duration %d must be between 1 and %d seconds", ErrInvalidInput, index+1, claimLeaseSeconds-1)
		}
		maximum[index] = time.Duration(seconds) * time.Second
		authorizationIDs[index] = input.AuthorizationIDs[index]
	}
	draft, err := plancompiler.BuildDraft(plancompiler.DraftInput{
		StationID: input.StationID, LaneID: input.LaneID, TransactionID: input.TransactionID,
		Release: input.Release, TargetFingerprint: input.TargetFingerprint, FenceEpoch: fenceEpoch,
		ApprovalExpiresAt: input.ApprovalExpiresAt, InitialState: input.InitialState,
		AuthorizationIDs: authorizationIDs, MaximumDurations: maximum,
	})
	if err != nil {
		return plancompiler.Draft{}, fmt.Errorf("%w: compile fixed campaign: %v", ErrInvalidInput, err)
	}
	return draft, nil
}

// NewApprovalProposal converts an authenticated target-bound transaction into
// immutable material for a separate approver session.
func NewApprovalProposal(snapshot laneguard.Plan, transaction controlplane.Transaction, approverID string, eventTime time.Time) (ApprovalProposal, error) {
	if !identifierPattern.MatchString(approverID) || eventTime.IsZero() {
		return ApprovalProposal{}, fmt.Errorf("%w: approver identity or event time", ErrInvalidInput)
	}
	if _, err := plancompiler.DraftFromSnapshot(snapshot); err != nil {
		return ApprovalProposal{}, fmt.Errorf("%w: draft: %v", ErrInvalidInput, err)
	}
	if err := matchDraftTransaction(snapshot, transaction, controlplane.StatusTargetBound); err != nil {
		return ApprovalProposal{}, err
	}
	if transaction.Approval != nil || len(transaction.Operations) != 0 {
		return ApprovalProposal{}, fmt.Errorf("%w: approval requires a clean target-bound transaction", ErrStateMismatch)
	}
	if eventTime.Before(transaction.Target.BoundAt) || !transaction.ActiveClaim.ExpiresAt.After(eventTime) {
		return ApprovalProposal{}, fmt.Errorf("%w: approval event is outside the current target-bound claim", ErrStateMismatch)
	}
	return ApprovalProposal{
		SchemaVersion: ApprovalProposalSchemaVersion, DraftSnapshot: clonePlan(snapshot),
		ApprovalID: workflowID("approval", snapshot.PlanDigest, approverID), ApproverID: approverID,
		TransactionDigest: transaction.TransactionDigest, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch, EventTime: eventTime.UTC(),
	}, nil
}

func (proposal ApprovalProposal) requests(receiptID string) (auditlog.AppendRequest, controlplane.RecordApprovalRequest, error) {
	draft, err := plancompiler.DraftFromSnapshot(proposal.DraftSnapshot)
	if err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordApprovalRequest{}, fmt.Errorf("%w: approval draft: %v", ErrInvalidInput, err)
	}
	if proposal.SchemaVersion != ApprovalProposalSchemaVersion || !identifierPattern.MatchString(proposal.ApprovalID) ||
		!identifierPattern.MatchString(proposal.ApproverID) || !digestPattern.MatchString(proposal.TransactionDigest) ||
		proposal.ExpectedResourceVersion == 0 || !identifierPattern.MatchString(proposal.ClaimID) ||
		proposal.FenceEpoch != proposal.DraftSnapshot.FenceEpoch || proposal.EventTime.IsZero() ||
		!proposal.EventTime.Before(proposal.DraftSnapshot.ApprovalExpiresAt) ||
		proposal.ApprovalID != workflowID("approval", proposal.DraftSnapshot.PlanDigest, proposal.ApproverID) {
		return auditlog.AppendRequest{}, controlplane.RecordApprovalRequest{}, fmt.Errorf("%w: approval proposal fields", ErrInvalidInput)
	}
	operations := planOperations(proposal.DraftSnapshot)
	auditRequest := auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: workflowID("audit-approval", proposal.ApprovalID),
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: proposal.ApprovalID, TransactionID: proposal.DraftSnapshot.TransactionID,
			StationID: proposal.DraftSnapshot.StationID, LaneID: proposal.DraftSnapshot.LaneID,
			Stage: "plan_approval", FenceEpoch: proposal.FenceEpoch,
			InputDigest: proposal.DraftSnapshot.PlanDigest, Result: auditlog.ResultIntentRecorded,
			Actors:       []auditlog.Actor{{ID: proposal.ApproverID, Role: "approver"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: proposal.EventTime.UTC(), ClockStatus: "synchronized"},
		},
	}
	controlRequest := controlplane.RecordApprovalRequest{
		SchemaVersion:  controlplane.RecordApprovalRequestSchemaVersion,
		IdempotencyKey: workflowID("control-approval", proposal.ApprovalID),
		MutationContext: controlplane.MutationContext{
			TransactionID:           proposal.DraftSnapshot.TransactionID,
			ExpectedResourceVersion: proposal.ExpectedResourceVersion,
			ClaimID:                 proposal.ClaimID, FenceEpoch: proposal.FenceEpoch,
		},
		ApprovalID: proposal.ApprovalID, ApproverID: proposal.ApproverID,
		TransactionDigest: proposal.TransactionDigest, PlanDigest: draft.PlanDigest(),
		TargetFingerprint: proposal.DraftSnapshot.TargetFingerprint, Release: proposal.DraftSnapshot.Release,
		AllowedOperations: operations, AuditReceiptID: receiptID,
		ExpiresAt: proposal.DraftSnapshot.ApprovalExpiresAt,
	}
	return auditRequest, controlRequest, nil
}

// ApplyApproval appends the approver-authenticated audit event before the
// compare-and-set control approval. Replaying the same proposal is idempotent.
func ApplyApproval(ctx context.Context, proposal ApprovalProposal, current transactionReader, audit auditAppender, control approvalRecorder) (controlplane.Transaction, error) {
	if current == nil || audit == nil || control == nil {
		return controlplane.Transaction{}, fmt.Errorf("%w: approval clients are required", ErrInvalidInput)
	}
	transaction, err := current.GetTransaction(ctx, proposal.DraftSnapshot.TransactionID)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read transaction before approval append: %w", err)
	}
	if err := proposalMatchesCurrentApproval(proposal, transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	auditRequest, _, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	receipt, err := audit.Append(ctx, auditRequest)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append plan-approval audit: %w", err)
	}
	if !digestPattern.MatchString(receipt.ReceiptID) {
		return controlplane.Transaction{}, fmt.Errorf("%w: audit returned an invalid receipt", ErrStateMismatch)
	}
	_, request, err := proposal.requests(receipt.ReceiptID)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	transaction, err = control.RecordApproval(ctx, request)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record control approval: %w", err)
	}
	return transaction, nil
}

func proposalMatchesCurrentApproval(proposal ApprovalProposal, transaction controlplane.Transaction) error {
	if _, _, err := proposal.requests(validPlaceholderDigest); err != nil {
		return err
	}
	if transaction.ID != proposal.DraftSnapshot.TransactionID ||
		transaction.TransactionDigest != proposal.TransactionDigest || transaction.ActiveClaim == nil ||
		transaction.ActiveClaim.ID != proposal.ClaimID || transaction.FenceEpoch != proposal.FenceEpoch ||
		transaction.ActiveClaim.FenceEpoch != proposal.FenceEpoch {
		return fmt.Errorf("%w: current transaction or claim differs from the approval proposal", ErrStateMismatch)
	}
	if transaction.ResourceVersion == proposal.ExpectedResourceVersion {
		if err := matchDraftTransaction(proposal.DraftSnapshot, transaction, controlplane.StatusTargetBound); err != nil {
			return err
		}
		if transaction.Approval != nil || len(transaction.Operations) != 0 {
			return fmt.Errorf("%w: transaction is no longer awaiting its initial approval", ErrStateMismatch)
		}
		return nil
	}
	if transaction.ResourceVersion < proposal.ExpectedResourceVersion {
		return fmt.Errorf("%w: transaction resource version moved backwards", ErrStateMismatch)
	}
	if err := matchDraftTransaction(proposal.DraftSnapshot, transaction, controlplane.StatusCommitApproved); err != nil {
		return err
	}
	approval := transaction.Approval
	if approval == nil || len(transaction.Operations) != 0 || approval.ID != proposal.ApprovalID ||
		approval.ApproverID != proposal.ApproverID || approval.TransactionDigest != proposal.TransactionDigest ||
		approval.PlanDigest != proposal.DraftSnapshot.PlanDigest || approval.StationID != proposal.DraftSnapshot.StationID ||
		approval.LaneID != proposal.DraftSnapshot.LaneID || approval.FenceEpoch != proposal.FenceEpoch ||
		approval.TargetFingerprint != proposal.DraftSnapshot.TargetFingerprint || approval.Release != proposal.DraftSnapshot.Release ||
		!equalStrings(approval.AllowedOperations, planOperations(proposal.DraftSnapshot)) ||
		!digestPattern.MatchString(approval.AuditReceiptID) || approval.ApprovedAt.IsZero() ||
		!approval.ExpiresAt.Equal(proposal.DraftSnapshot.ApprovalExpiresAt) {
		return fmt.Errorf("%w: recorded approval differs from the proposal", ErrStateMismatch)
	}
	return nil
}

// PrepareNextIntent renews the existing fixed claim, derives the sole next
// operation from successful control history, and returns a durable proposal.
func PrepareNextIntent(ctx context.Context, snapshot laneguard.Plan, now time.Time, control interface {
	transactionReader
	claimRenewer
}) (IntentProposal, controlplane.Transaction, error) {
	if control == nil || now.IsZero() {
		return IntentProposal{}, controlplane.Transaction{}, fmt.Errorf("%w: control client or current time", ErrInvalidInput)
	}
	if _, err := plancompiler.DraftFromSnapshot(snapshot); err != nil {
		return IntentProposal{}, controlplane.Transaction{}, fmt.Errorf("%w: draft: %v", ErrInvalidInput, err)
	}
	transaction, err := control.GetTransaction(ctx, snapshot.TransactionID)
	if err != nil {
		return IntentProposal{}, controlplane.Transaction{}, fmt.Errorf("read transaction before intent: %w", err)
	}
	sequence, err := nextSequence(snapshot, transaction)
	if err != nil {
		return IntentProposal{}, controlplane.Transaction{}, err
	}
	transaction, err = control.RenewClaim(ctx, controlplane.RenewClaimRequest{
		SchemaVersion:  controlplane.RenewClaimRequestSchemaVersion,
		IdempotencyKey: workflowID("renew", snapshot.PlanDigest, fmt.Sprint(sequence), fmt.Sprint(transaction.ResourceVersion)),
		TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
		LeaseDurationSeconds: claimLeaseSeconds,
	})
	if err != nil {
		return IntentProposal{}, controlplane.Transaction{}, fmt.Errorf("renew fixed campaign claim: %w", err)
	}
	proposal, err := NewIntentProposal(snapshot, transaction, sequence, now)
	return proposal, transaction, err
}

func NewIntentProposal(snapshot laneguard.Plan, transaction controlplane.Transaction, sequence uint32, eventTime time.Time) (IntentProposal, error) {
	if _, err := plancompiler.DraftFromSnapshot(snapshot); err != nil {
		return IntentProposal{}, fmt.Errorf("%w: draft: %v", ErrInvalidInput, err)
	}
	if eventTime.IsZero() || sequence == 0 || int(sequence) > len(snapshot.Operations) {
		return IntentProposal{}, fmt.Errorf("%w: intent sequence or event time", ErrInvalidInput)
	}
	wantSequence, err := nextSequence(snapshot, transaction)
	if err != nil {
		return IntentProposal{}, err
	}
	if sequence != wantSequence {
		return IntentProposal{}, fmt.Errorf("%w: intent is not the next operation", ErrStateMismatch)
	}
	if eventTime.Before(transaction.Approval.ApprovedAt) || !transaction.ActiveClaim.ExpiresAt.After(eventTime) {
		return IntentProposal{}, fmt.Errorf("%w: intent event is outside the current approval and claim", ErrStateMismatch)
	}
	operation := snapshot.Operations[sequence-1]
	return IntentProposal{
		SchemaVersion: IntentProposalSchemaVersion, DraftSnapshot: clonePlan(snapshot),
		ExpectedResourceVersion: transaction.ResourceVersion, ClaimID: transaction.ActiveClaim.ID,
		FenceEpoch: transaction.FenceEpoch, ApprovalID: transaction.Approval.ID,
		OperationID: operation.AuthorizationID, Sequence: sequence, EventTime: eventTime.UTC(),
	}, nil
}

func (proposal IntentProposal) requests(receiptID string) (auditlog.AppendRequest, controlplane.RecordIntentRequest, error) {
	draft, err := plancompiler.DraftFromSnapshot(proposal.DraftSnapshot)
	if err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordIntentRequest{}, fmt.Errorf("%w: intent draft: %v", ErrInvalidInput, err)
	}
	if proposal.SchemaVersion != IntentProposalSchemaVersion || proposal.Sequence == 0 ||
		int(proposal.Sequence) > len(proposal.DraftSnapshot.Operations) || proposal.ExpectedResourceVersion == 0 ||
		!identifierPattern.MatchString(proposal.ClaimID) || !identifierPattern.MatchString(proposal.ApprovalID) ||
		proposal.FenceEpoch != proposal.DraftSnapshot.FenceEpoch || proposal.EventTime.IsZero() ||
		!proposal.EventTime.Before(proposal.DraftSnapshot.ApprovalExpiresAt) {
		return auditlog.AppendRequest{}, controlplane.RecordIntentRequest{}, fmt.Errorf("%w: intent proposal fields", ErrInvalidInput)
	}
	operation := proposal.DraftSnapshot.Operations[proposal.Sequence-1]
	if proposal.OperationID != operation.AuthorizationID {
		return auditlog.AppendRequest{}, controlplane.RecordIntentRequest{}, fmt.Errorf("%w: operation ID is not compiler-bound", ErrInvalidInput)
	}
	prestateDigest, err := draft.PrestateDigest(proposal.Sequence)
	if err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordIntentRequest{}, err
	}
	auditRequest := auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: workflowID("audit-intent", proposal.DraftSnapshot.PlanDigest, fmt.Sprint(proposal.Sequence)),
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: proposal.OperationID, TransactionID: proposal.DraftSnapshot.TransactionID,
			StationID: proposal.DraftSnapshot.StationID, LaneID: proposal.DraftSnapshot.LaneID,
			Stage: string(operation.Operation), FenceEpoch: proposal.FenceEpoch,
			InputDigest: proposal.DraftSnapshot.PlanDigest, Result: auditlog.ResultIntentRecorded,
			Actors:       []auditlog.Actor{{ID: proposal.DraftSnapshot.StationID, Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: proposal.EventTime.UTC(), ClockStatus: "synchronized"},
		},
	}
	controlRequest := controlplane.RecordIntentRequest{
		SchemaVersion:  controlplane.RecordIntentRequestSchemaVersion,
		IdempotencyKey: workflowID("control-intent", proposal.DraftSnapshot.PlanDigest, fmt.Sprint(proposal.Sequence)),
		MutationContext: controlplane.MutationContext{
			TransactionID:           proposal.DraftSnapshot.TransactionID,
			ExpectedResourceVersion: proposal.ExpectedResourceVersion,
			ClaimID:                 proposal.ClaimID, FenceEpoch: proposal.FenceEpoch,
		},
		ApprovalID: proposal.ApprovalID, OperationID: proposal.OperationID,
		Operation: string(operation.Operation), PlanDigest: proposal.DraftSnapshot.PlanDigest,
		InputDigest: proposal.DraftSnapshot.PlanDigest, PrestateDigest: prestateDigest,
		AuditReceiptID: receiptID,
	}
	return auditRequest, controlRequest, nil
}

func ApplyIntent(ctx context.Context, proposal IntentProposal, current transactionReader, audit auditAppender, control intentRecorder) (controlplane.Transaction, error) {
	if current == nil || audit == nil || control == nil {
		return controlplane.Transaction{}, fmt.Errorf("%w: intent clients are required", ErrInvalidInput)
	}
	transaction, err := current.GetTransaction(ctx, proposal.DraftSnapshot.TransactionID)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read transaction before intent append: %w", err)
	}
	if err := proposalMatchesCurrentIntent(proposal, transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	auditRequest, _, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	receipt, err := audit.Append(ctx, auditRequest)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append operation intent audit: %w", err)
	}
	if !digestPattern.MatchString(receipt.ReceiptID) {
		return controlplane.Transaction{}, fmt.Errorf("%w: audit returned an invalid receipt", ErrStateMismatch)
	}
	_, request, err := proposal.requests(receipt.ReceiptID)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	transaction, err = control.RecordIntent(ctx, request)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record control intent: %w", err)
	}
	return transaction, nil
}

func NewEvidenceProposal(snapshot laneguard.Plan, transaction controlplane.Transaction, attempt laneguard.Attempt, eventTime time.Time) (EvidenceProposal, error) {
	if _, err := plancompiler.DraftFromSnapshot(snapshot); err != nil {
		return EvidenceProposal{}, fmt.Errorf("%w: draft: %v", ErrInvalidInput, err)
	}
	if eventTime.IsZero() || len(transaction.Operations) == 0 || transaction.ActiveClaim == nil {
		return EvidenceProposal{}, fmt.Errorf("%w: evidence event time or pending operation", ErrInvalidInput)
	}
	operation := transaction.Operations[len(transaction.Operations)-1]
	proposal := EvidenceProposal{
		SchemaVersion: EvidenceProposalSchemaVersion, DraftSnapshot: clonePlan(snapshot),
		ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID:                 transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
		OperationID: operation.ID, Attempt: attempt, EventTime: eventTime.UTC(),
	}
	if err := proposalMatchesCurrentEvidence(proposal, transaction); err != nil {
		return EvidenceProposal{}, err
	}
	return proposal, nil
}

func (proposal EvidenceProposal) requests(receiptID string) (auditlog.AppendRequest, controlplane.RecordEvidenceRequest, error) {
	if _, err := plancompiler.DraftFromSnapshot(proposal.DraftSnapshot); err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, fmt.Errorf("%w: evidence draft: %v", ErrInvalidInput, err)
	}
	if proposal.SchemaVersion != EvidenceProposalSchemaVersion || proposal.ExpectedResourceVersion == 0 ||
		!identifierPattern.MatchString(proposal.ClaimID) || !identifierPattern.MatchString(proposal.OperationID) ||
		proposal.FenceEpoch != proposal.DraftSnapshot.FenceEpoch || proposal.EventTime.IsZero() ||
		!digestPattern.MatchString(receiptID) {
		return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, fmt.Errorf("%w: evidence proposal fields", ErrInvalidInput)
	}
	if err := validateAttemptForDraft(proposal.DraftSnapshot, proposal.Attempt, proposal.EventTime); err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, err
	}
	attemptDigest := digestJSON("lane-guard-attempt", proposal.Attempt)
	observationDigest := digestJSON("direct-state", proposal.Attempt.ObservedState)
	outputDigest := attemptDigest
	auditResult := auditlog.ResultUncertain
	controlResult := controlplane.EvidenceUncertain
	switch proposal.Attempt.Status {
	case laneguard.AttemptVerified:
		if !digestPattern.MatchString(proposal.Attempt.Result.BindingDigest) {
			return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, fmt.Errorf("%w: verified attempt has no bound result", ErrInvalidInput)
		}
		outputDigest = proposal.Attempt.Result.BindingDigest
		auditResult = auditlog.ResultSucceeded
		controlResult = controlplane.EvidenceSucceeded
	case laneguard.AttemptUncertain:
	case laneguard.AttemptQuarantined:
		auditResult = auditlog.ResultQuarantined
		controlResult = controlplane.EvidenceFailed
	default:
		return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, fmt.Errorf("%w: attempt status is not recordable as operation evidence", ErrInvalidInput)
	}
	if proposal.Attempt.Sequence == 0 || int(proposal.Attempt.Sequence) > len(proposal.DraftSnapshot.Operations) {
		return auditlog.AppendRequest{}, controlplane.RecordEvidenceRequest{}, fmt.Errorf("%w: attempt sequence", ErrInvalidInput)
	}
	operation := proposal.DraftSnapshot.Operations[proposal.Attempt.Sequence-1]
	eventID := workflowID("evidence", proposal.Attempt.Key, string(proposal.Attempt.Status))
	auditRequest := auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: workflowID("audit-evidence", proposal.Attempt.Key, string(proposal.Attempt.Status)),
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: eventID, TransactionID: proposal.DraftSnapshot.TransactionID,
			StationID: proposal.DraftSnapshot.StationID, LaneID: proposal.DraftSnapshot.LaneID,
			Stage: string(operation.Operation), FenceEpoch: proposal.FenceEpoch,
			InputDigest: proposal.DraftSnapshot.PlanDigest, OutputDigest: outputDigest, Result: auditResult,
			Actors:       []auditlog.Actor{{ID: proposal.DraftSnapshot.StationID, Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: proposal.EventTime.UTC(), ClockStatus: "synchronized"},
			ObservationReferences: []auditlog.ObservationReference{
				{Kind: "lane_guard_attempt", Digest: attemptDigest},
				{Kind: "direct_state", Digest: observationDigest},
			},
		},
	}
	controlRequest := controlplane.RecordEvidenceRequest{
		SchemaVersion:  controlplane.RecordEvidenceRequestSchemaVersion,
		IdempotencyKey: workflowID("control-evidence", proposal.Attempt.Key, string(proposal.Attempt.Status)),
		MutationContext: controlplane.MutationContext{
			TransactionID:           proposal.DraftSnapshot.TransactionID,
			ExpectedResourceVersion: proposal.ExpectedResourceVersion,
			ClaimID:                 proposal.ClaimID, FenceEpoch: proposal.FenceEpoch,
		},
		OperationID: proposal.OperationID, Result: controlResult,
		OutputDigest: outputDigest, ObservationDigest: observationDigest, AuditReceiptID: receiptID,
	}
	return auditRequest, controlRequest, nil
}

func ApplyEvidence(ctx context.Context, proposal EvidenceProposal, current transactionReader, audit auditAppender, control evidenceRecorder) (controlplane.Transaction, error) {
	if current == nil || audit == nil || control == nil {
		return controlplane.Transaction{}, fmt.Errorf("%w: evidence clients are required", ErrInvalidInput)
	}
	transaction, err := current.GetTransaction(ctx, proposal.DraftSnapshot.TransactionID)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read transaction before evidence append: %w", err)
	}
	if err := proposalMatchesCurrentEvidence(proposal, transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	auditRequest, _, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	receipt, err := audit.Append(ctx, auditRequest)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append operation evidence audit: %w", err)
	}
	if !digestPattern.MatchString(receipt.ReceiptID) {
		return controlplane.Transaction{}, fmt.Errorf("%w: audit returned an invalid receipt", ErrStateMismatch)
	}
	_, request, err := proposal.requests(receipt.ReceiptID)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	transaction, err = control.RecordEvidence(ctx, request)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record control evidence: %w", err)
	}
	return transaction, nil
}

// PrepareReconciliationClaim converts the original lane's current claim into
// observation-only authority, or acquires that authority after the old claim
// expires. Station, lane, mode, stage, and lease are all policy-derived. It
// never creates fresh mutation authority and never rebinds the target.
func PrepareReconciliationClaim(ctx context.Context, snapshot laneguard.Plan, now time.Time, control interface {
	transactionReader
	claimAcquirer
	claimRenewer
	claimTransferer
}) (controlplane.Transaction, error) {
	if control == nil || now.IsZero() {
		return controlplane.Transaction{}, fmt.Errorf("%w: reconciliation control client or current time", ErrInvalidInput)
	}
	if _, err := plancompiler.DraftFromSnapshot(snapshot); err != nil {
		return controlplane.Transaction{}, fmt.Errorf("%w: reconciliation draft: %v", ErrInvalidInput, err)
	}
	transaction, err := control.GetTransaction(ctx, snapshot.TransactionID)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read transaction before reconciliation claim: %w", err)
	}
	if _, err := unresolvedSequence(snapshot, transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	claim := transaction.ActiveClaim
	switch {
	case claim != nil && claim.Status == controlplane.ClaimActive && claim.ExpiresAt.After(now.UTC()) && claim.Mode == controlplane.ClaimModeReconciliation:
		if err := matchReconciliationClaim(snapshot, transaction, now.UTC()); err != nil {
			return controlplane.Transaction{}, err
		}
		transaction, err = control.RenewClaim(ctx, controlplane.RenewClaimRequest{
			SchemaVersion:  controlplane.RenewClaimRequestSchemaVersion,
			IdempotencyKey: workflowID("renew-reconciliation", snapshot.PlanDigest, fmt.Sprint(transaction.ResourceVersion)),
			TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
			ClaimID: claim.ID, FenceEpoch: claim.FenceEpoch, LeaseDurationSeconds: claimLeaseSeconds,
		})
	case claim != nil && claim.Status == controlplane.ClaimActive && claim.ExpiresAt.After(now.UTC()) && claim.Mode == controlplane.ClaimModeMutation:
		if err := matchClaim(transaction, snapshot.StationID, snapshot.LaneID, planOperations(snapshot)); err != nil {
			return controlplane.Transaction{}, err
		}
		if transaction.FenceEpoch != snapshot.FenceEpoch {
			return controlplane.Transaction{}, fmt.Errorf("%w: mutation claim no longer has the original execution fence", ErrStateMismatch)
		}
		transaction, err = control.TransferClaim(ctx, controlplane.TransferClaimRequest{
			SchemaVersion:  controlplane.TransferClaimRequestSchemaVersion,
			IdempotencyKey: workflowID("transfer-reconciliation", snapshot.PlanDigest, fmt.Sprint(transaction.ResourceVersion)),
			TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
			ClaimID: claim.ID, FenceEpoch: claim.FenceEpoch,
			NewStationID: snapshot.StationID, NewLaneID: snapshot.LaneID,
			Mode: controlplane.ClaimModeReconciliation, AllowedStages: []string{"reconciliation"},
			LeaseDurationSeconds: claimLeaseSeconds,
		})
	default:
		transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
			SchemaVersion:  controlplane.AcquireClaimRequestSchemaVersion,
			IdempotencyKey: workflowID("acquire-reconciliation", snapshot.PlanDigest, fmt.Sprint(transaction.ResourceVersion)),
			TransactionID:  transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
			StationID: snapshot.StationID, LaneID: snapshot.LaneID,
			Mode: controlplane.ClaimModeReconciliation, AllowedStages: []string{"reconciliation"},
			LeaseDurationSeconds: claimLeaseSeconds,
		})
	}
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("prepare fixed reconciliation claim: %w", err)
	}
	if err := matchPreparedReconciliation(snapshot, transaction, now.UTC()); err != nil {
		return controlplane.Transaction{}, err
	}
	return transaction, nil
}

// NewReconciliationProposal maps the trusted terminal attempt through the
// closed recovery policy. The caller cannot choose a resolution.
func NewReconciliationProposal(snapshot laneguard.Plan, transaction controlplane.Transaction, attempt laneguard.Attempt, eventTime time.Time) (ReconciliationProposal, error) {
	if eventTime.IsZero() {
		return ReconciliationProposal{}, fmt.Errorf("%w: reconciliation event time", ErrInvalidInput)
	}
	if err := matchPreparedReconciliation(snapshot, transaction, eventTime.UTC()); err != nil {
		return ReconciliationProposal{}, err
	}
	sequence, err := unresolvedSequence(snapshot, transaction)
	if err != nil {
		return ReconciliationProposal{}, err
	}
	if attempt.Sequence != sequence {
		return ReconciliationProposal{}, fmt.Errorf("%w: reconciliation attempt is not the unresolved operation", ErrStateMismatch)
	}
	resolution, err := reconciliationResolution(snapshot, attempt, eventTime.UTC())
	if err != nil {
		return ReconciliationProposal{}, err
	}
	if err := matchReconciliationTransitionClaim(attempt, transaction.ActiveClaim.ID, transaction.FenceEpoch); err != nil {
		return ReconciliationProposal{}, err
	}
	record := transaction.Operations[sequence-1]
	if err := matchAttemptRecord(snapshot, attempt, record); err != nil {
		return ReconciliationProposal{}, err
	}
	return ReconciliationProposal{
		SchemaVersion: ReconciliationProposalSchemaVersion, DraftSnapshot: clonePlan(snapshot),
		ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID:                 transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
		OperationID: record.ID, Resolution: resolution, Attempt: attempt, EventTime: eventTime.UTC(),
	}, nil
}

func (proposal ReconciliationProposal) requests(receiptID string) (auditlog.AppendRequest, controlplane.RecordReconciliationRequest, error) {
	if _, err := plancompiler.DraftFromSnapshot(proposal.DraftSnapshot); err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordReconciliationRequest{}, fmt.Errorf("%w: reconciliation draft: %v", ErrInvalidInput, err)
	}
	if proposal.SchemaVersion != ReconciliationProposalSchemaVersion || proposal.ExpectedResourceVersion == 0 ||
		!identifierPattern.MatchString(proposal.ClaimID) || !identifierPattern.MatchString(proposal.OperationID) ||
		proposal.FenceEpoch <= proposal.DraftSnapshot.FenceEpoch || proposal.EventTime.IsZero() ||
		!digestPattern.MatchString(receiptID) {
		return auditlog.AppendRequest{}, controlplane.RecordReconciliationRequest{}, fmt.Errorf("%w: reconciliation proposal fields", ErrInvalidInput)
	}
	resolution, err := reconciliationResolution(proposal.DraftSnapshot, proposal.Attempt, proposal.EventTime)
	if err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordReconciliationRequest{}, err
	}
	if proposal.Resolution != resolution {
		return auditlog.AppendRequest{}, controlplane.RecordReconciliationRequest{}, fmt.Errorf("%w: reconciliation resolution is not attempt-derived", ErrInvalidInput)
	}
	if err := matchReconciliationTransitionClaim(proposal.Attempt, proposal.ClaimID, proposal.FenceEpoch); err != nil {
		return auditlog.AppendRequest{}, controlplane.RecordReconciliationRequest{}, err
	}
	attemptDigest := digestJSON("lane-guard-reconciliation-attempt", proposal.Attempt)
	observationDigest := digestJSON("direct-state", proposal.Attempt.ObservedState)
	auditResult := auditlog.ResultReconciled
	if resolution == controlplane.ResolutionUnknown {
		auditResult = auditlog.ResultQuarantined
	}
	eventID := workflowID("reconciliation", proposal.Attempt.Key, string(proposal.Attempt.Status), fmt.Sprint(proposal.FenceEpoch))
	auditRequest := auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: workflowID("audit-reconciliation", eventID),
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: eventID, TransactionID: proposal.DraftSnapshot.TransactionID,
			StationID: proposal.DraftSnapshot.StationID, LaneID: proposal.DraftSnapshot.LaneID,
			Stage: "reconciliation", FenceEpoch: proposal.FenceEpoch,
			InputDigest: proposal.DraftSnapshot.PlanDigest, OutputDigest: attemptDigest, Result: auditResult,
			Actors:       []auditlog.Actor{{ID: proposal.DraftSnapshot.StationID, Role: "provisioning_station"}},
			TimeEvidence: auditlog.TimeEvidence{StationTime: proposal.EventTime.UTC(), ClockStatus: "synchronized"},
			ObservationReferences: []auditlog.ObservationReference{
				{Kind: "lane_guard_reconciliation_attempt", Digest: attemptDigest},
				{Kind: "direct_state", Digest: observationDigest},
			},
		},
	}
	controlRequest := controlplane.RecordReconciliationRequest{
		SchemaVersion:  controlplane.RecordReconciliationRequestSchemaVersion,
		IdempotencyKey: workflowID("control-reconciliation", eventID),
		MutationContext: controlplane.MutationContext{
			TransactionID:           proposal.DraftSnapshot.TransactionID,
			ExpectedResourceVersion: proposal.ExpectedResourceVersion,
			ClaimID:                 proposal.ClaimID, FenceEpoch: proposal.FenceEpoch,
		},
		OperationID: proposal.OperationID, Resolution: resolution,
		OutputDigest: attemptDigest, ObservationDigest: observationDigest, AuditReceiptID: receiptID,
	}
	return auditRequest, controlRequest, nil
}

// ApplyReconciliation durably audits the observation before the control CAS.
// Exact proposal replay is accepted; no path in this workflow issues a new
// mutation claim or operation intent after reconciliation.
func ApplyReconciliation(ctx context.Context, proposal ReconciliationProposal, current transactionReader, audit auditAppender, control reconciliationRecorder) (controlplane.Transaction, error) {
	if current == nil || audit == nil || control == nil {
		return controlplane.Transaction{}, fmt.Errorf("%w: reconciliation clients are required", ErrInvalidInput)
	}
	transaction, err := current.GetTransaction(ctx, proposal.DraftSnapshot.TransactionID)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read transaction before reconciliation append: %w", err)
	}
	if err := proposalMatchesCurrentReconciliation(proposal, transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	auditRequest, _, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	receipt, err := audit.Append(ctx, auditRequest)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append reconciliation audit: %w", err)
	}
	if !digestPattern.MatchString(receipt.ReceiptID) {
		return controlplane.Transaction{}, fmt.Errorf("%w: audit returned an invalid receipt", ErrStateMismatch)
	}
	_, request, err := proposal.requests(receipt.ReceiptID)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	transaction, err = control.RecordReconciliation(ctx, request)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record control reconciliation: %w", err)
	}
	return transaction, nil
}

func unresolvedSequence(snapshot laneguard.Plan, transaction controlplane.Transaction) (uint32, error) {
	draft, err := plancompiler.DraftFromSnapshot(snapshot)
	if err != nil {
		return 0, fmt.Errorf("%w: reconciliation draft: %v", ErrInvalidInput, err)
	}
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ID != snapshot.TransactionID ||
		transaction.ResourceVersion == 0 ||
		(transaction.Status != controlplane.StatusMutationInProgress && transaction.Status != controlplane.StatusReconciliationRequired) ||
		transaction.BundleDigest != snapshot.Release.SignedReleaseManifestDigest ||
		transaction.ExpectedPrestateCustomerKeyHash != snapshot.Operations[0].ExpectedPrestate.CustomerKeyHash ||
		transaction.ExpectedCustomerKeyHash != snapshot.Release.ExpectedCustomerKeyHash ||
		!digestPattern.MatchString(transaction.TransactionDigest) || transaction.Target == nil ||
		transaction.Target.Fingerprint != snapshot.TargetFingerprint || transaction.Target.FenceEpoch != snapshot.FenceEpoch ||
		transaction.Target.CustomerKeyHash != snapshot.Operations[0].ExpectedPrestate.CustomerKeyHash ||
		!digestPattern.MatchString(transaction.Target.ObservationDigest) || transaction.Quarantine != nil ||
		transaction.SecurityApplied != nil || transaction.Abort != nil || len(transaction.Operations) == 0 ||
		len(transaction.Operations) > len(snapshot.Operations) {
		return 0, fmt.Errorf("%w: transaction is not one unresolved draft operation", ErrStateMismatch)
	}
	for index, record := range transaction.Operations {
		operation := snapshot.Operations[index]
		prestateDigest, err := draft.PrestateDigest(operation.Sequence)
		if err != nil {
			return 0, err
		}
		approval := record.Approval
		if record.ID != operation.AuthorizationID || record.Operation != string(operation.Operation) ||
			record.PlanDigest != snapshot.PlanDigest || record.Release != snapshot.Release ||
			!record.ApprovalExpiresAt.Equal(snapshot.ApprovalExpiresAt) || record.InputDigest != snapshot.PlanDigest ||
			record.PrestateDigest != prestateDigest || !digestPattern.MatchString(record.IntentAuditReceiptID) ||
			record.IntentFenceEpoch != snapshot.FenceEpoch || record.IntentAt.IsZero() ||
			!identifierPattern.MatchString(approval.ID) || !identifierPattern.MatchString(approval.ApproverID) ||
			approval.TransactionDigest != transaction.TransactionDigest || approval.PlanDigest != snapshot.PlanDigest ||
			approval.StationID != snapshot.StationID || approval.LaneID != snapshot.LaneID ||
			approval.FenceEpoch != snapshot.FenceEpoch || approval.TargetFingerprint != snapshot.TargetFingerprint ||
			approval.Release != snapshot.Release || !equalStrings(approval.AllowedOperations, planOperations(snapshot)) ||
			!digestPattern.MatchString(approval.AuditReceiptID) || approval.ApprovedAt.IsZero() ||
			!approval.ExpiresAt.Equal(snapshot.ApprovalExpiresAt) {
			return 0, fmt.Errorf("%w: reconciliation operation history differs at sequence %d", ErrStateMismatch, index+1)
		}
		if index < len(transaction.Operations)-1 {
			if record.Status != controlplane.OperationSucceeded && record.Status != controlplane.OperationConfirmedApplied {
				return 0, fmt.Errorf("%w: reconciliation prefix operation %d is not successfully closed", ErrStateMismatch, index+1)
			}
			if !digestPattern.MatchString(record.OutputDigest) || !digestPattern.MatchString(record.ObservationDigest) || record.EvidenceAt == nil {
				return 0, fmt.Errorf("%w: reconciliation prefix operation %d lacks evidence", ErrStateMismatch, index+1)
			}
			continue
		}
		switch record.Status {
		case controlplane.OperationIntentRecorded:
			if record.OutputDigest != "" || record.ObservationDigest != "" || record.EvidenceAuditReceiptID != "" ||
				record.EvidenceAt != nil || record.ReconciliationAuditReceiptID != "" {
				return 0, fmt.Errorf("%w: unresolved intent already contains evidence", ErrStateMismatch)
			}
		case controlplane.OperationUncertain:
			if !digestPattern.MatchString(record.OutputDigest) || !digestPattern.MatchString(record.ObservationDigest) ||
				!digestPattern.MatchString(record.EvidenceAuditReceiptID) || record.EvidenceAt == nil ||
				record.ReconciliationAuditReceiptID != "" {
				return 0, fmt.Errorf("%w: uncertain operation evidence is incomplete", ErrStateMismatch)
			}
		default:
			return 0, fmt.Errorf("%w: final operation is not unresolved", ErrStateMismatch)
		}
	}
	last := transaction.Operations[len(transaction.Operations)-1]
	if transaction.Status == controlplane.StatusMutationInProgress {
		if last.Status != controlplane.OperationIntentRecorded || transaction.Approval == nil ||
			transaction.Approval.ID != last.Approval.ID || transaction.FenceEpoch != snapshot.FenceEpoch {
			return 0, fmt.Errorf("%w: in-progress mutation authority differs from the unresolved intent", ErrStateMismatch)
		}
	} else if transaction.Approval != nil {
		return 0, fmt.Errorf("%w: reconciliation-required transaction retained mutation approval", ErrStateMismatch)
	}
	return uint32(len(transaction.Operations)), nil
}

func matchReconciliationClaim(snapshot laneguard.Plan, transaction controlplane.Transaction, now time.Time) error {
	claim := transaction.ActiveClaim
	if claim == nil || !identifierPattern.MatchString(claim.ID) || claim.Mode != controlplane.ClaimModeReconciliation ||
		claim.Status != controlplane.ClaimActive || claim.ClosedAt != nil || claim.StationID != snapshot.StationID ||
		claim.LaneID != snapshot.LaneID || claim.AssetID != transaction.AssetID || claim.FenceEpoch != transaction.FenceEpoch ||
		claim.FenceEpoch <= snapshot.FenceEpoch || !equalStrings(claim.AllowedStages, []string{"reconciliation"}) ||
		claim.AcquiredAt.IsZero() || !claim.ExpiresAt.After(claim.AcquiredAt) || !claim.ExpiresAt.After(now) {
		return fmt.Errorf("%w: current claim is not the fixed read-only reconciliation claim", ErrStateMismatch)
	}
	return nil
}

func matchPreparedReconciliation(snapshot laneguard.Plan, transaction controlplane.Transaction, now time.Time) error {
	if transaction.Status != controlplane.StatusReconciliationRequired || transaction.Approval != nil {
		return fmt.Errorf("%w: transaction is not awaiting read-only reconciliation", ErrStateMismatch)
	}
	if _, err := unresolvedSequence(snapshot, transaction); err != nil {
		return err
	}
	if err := matchReconciliationClaim(snapshot, transaction, now); err != nil {
		return err
	}
	if !laneguard.LeaseCoversOperation(now, transaction.ActiveClaim.ExpiresAt, laneguard.ReconciliationObservationBudget, 0) {
		return fmt.Errorf("%w: reconciliation claim cannot cover the fixed observation budget", ErrStateMismatch)
	}
	return nil
}

func reconciliationResolution(snapshot laneguard.Plan, attempt laneguard.Attempt, eventTime time.Time) (controlplane.ReconciliationResolution, error) {
	if err := validateAttemptForDraft(snapshot, attempt, eventTime); err != nil {
		return "", err
	}
	operation := snapshot.Operations[attempt.Sequence-1]
	switch attempt.Status {
	case laneguard.AttemptVerified:
		return controlplane.ResolutionConfirmedApplied, nil
	case laneguard.AttemptConfirmedNotApplied:
		if attempt.ObservedState != operation.ExpectedPrestate {
			return "", fmt.Errorf("%w: confirmed-not-applied attempt does not contain the approved prestate", ErrInvalidInput)
		}
		return controlplane.ResolutionConfirmedNotApplied, nil
	case laneguard.AttemptUncertain, laneguard.AttemptQuarantined:
		return controlplane.ResolutionUnknown, nil
	default:
		return "", fmt.Errorf("%w: attempt is not a terminal reconciliation result", ErrInvalidInput)
	}
}

func matchReconciliationTransitionClaim(attempt laneguard.Attempt, claimID string, fenceEpoch uint64) error {
	outcome := attempt.ReconciliationTransition
	if outcome == (laneguard.BootTransitionOutcome{}) {
		if attempt.Status == laneguard.AttemptConfirmedNotApplied ||
			attempt.Status == laneguard.AttemptUncertain || attempt.Status == laneguard.AttemptQuarantined {
			return fmt.Errorf("%w: reconciliation result lacks its current observation transition", ErrInvalidInput)
		}
		return nil
	}
	if outcome.Action.ReconciliationClaimID != claimID || outcome.Action.ReconciliationFenceEpoch != fenceEpoch {
		return fmt.Errorf("%w: reconciliation transition uses a different current claim", ErrStateMismatch)
	}
	return nil
}

func matchAttemptRecord(snapshot laneguard.Plan, attempt laneguard.Attempt, record controlplane.OperationRecord) error {
	if attempt.Sequence == 0 || int(attempt.Sequence) > len(snapshot.Operations) {
		return fmt.Errorf("%w: lane attempt sequence", ErrInvalidInput)
	}
	operation := snapshot.Operations[attempt.Sequence-1]
	if record.ID != operation.AuthorizationID || record.Operation != string(operation.Operation) ||
		record.PlanDigest != snapshot.PlanDigest || record.Release != snapshot.Release ||
		record.Approval.ID != attempt.ApprovalID || record.Approval.PlanDigest != snapshot.PlanDigest ||
		record.Approval.Release != snapshot.Release || !record.Approval.ExpiresAt.Equal(snapshot.ApprovalExpiresAt) ||
		record.IntentFenceEpoch != snapshot.FenceEpoch || record.IntentAuditReceiptID != attempt.IntentReceipt {
		return fmt.Errorf("%w: lane attempt differs from the unresolved control operation", ErrStateMismatch)
	}
	return nil
}

func proposalMatchesCurrentReconciliation(proposal ReconciliationProposal, transaction controlplane.Transaction) error {
	if _, _, err := proposal.requests(validPlaceholderDigest); err != nil {
		return err
	}
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ID != proposal.DraftSnapshot.TransactionID ||
		transaction.ActiveClaim == nil || transaction.ActiveClaim.ID != proposal.ClaimID ||
		transaction.ActiveClaim.Mode != controlplane.ClaimModeReconciliation || transaction.ActiveClaim.Status != controlplane.ClaimActive ||
		transaction.ActiveClaim.StationID != proposal.DraftSnapshot.StationID || transaction.ActiveClaim.LaneID != proposal.DraftSnapshot.LaneID ||
		transaction.FenceEpoch != proposal.FenceEpoch || transaction.ActiveClaim.FenceEpoch != proposal.FenceEpoch ||
		!equalStrings(transaction.ActiveClaim.AllowedStages, []string{"reconciliation"}) ||
		len(transaction.Operations) != int(proposal.Attempt.Sequence) {
		return fmt.Errorf("%w: current reconciliation claim or transaction differs from the proposal", ErrStateMismatch)
	}
	record := transaction.Operations[len(transaction.Operations)-1]
	if record.ID != proposal.OperationID {
		return fmt.Errorf("%w: current unresolved operation differs from the proposal", ErrStateMismatch)
	}
	if err := matchAttemptRecord(proposal.DraftSnapshot, proposal.Attempt, record); err != nil {
		return err
	}
	if transaction.ResourceVersion == proposal.ExpectedResourceVersion {
		if err := matchPreparedReconciliation(proposal.DraftSnapshot, transaction, proposal.EventTime); err != nil {
			return err
		}
		return nil
	}
	_, request, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return err
	}
	wantOperation := controlplane.OperationUncertain
	wantTransaction := controlplane.StatusQuarantined
	switch proposal.Resolution {
	case controlplane.ResolutionConfirmedApplied:
		wantOperation = controlplane.OperationConfirmedApplied
		wantTransaction = controlplane.StatusReconciled
	case controlplane.ResolutionConfirmedNotApplied:
		wantOperation = controlplane.OperationConfirmedNotApplied
		wantTransaction = controlplane.StatusReconciled
	}
	if transaction.Status != wantTransaction || record.Status != wantOperation ||
		record.OutputDigest != request.OutputDigest || record.ObservationDigest != request.ObservationDigest ||
		!digestPattern.MatchString(record.ReconciliationAuditReceiptID) {
		return fmt.Errorf("%w: recorded reconciliation differs from the proposal", ErrStateMismatch)
	}
	return nil
}

func nextSequence(snapshot laneguard.Plan, transaction controlplane.Transaction) (uint32, error) {
	if err := matchDraftTransaction(snapshot, transaction, controlplane.StatusCommitApproved); err != nil {
		return 0, err
	}
	if transaction.Approval == nil || transaction.Approval.PlanDigest != snapshot.PlanDigest ||
		transaction.Approval.Release != snapshot.Release || transaction.Approval.ID == "" ||
		!transaction.Approval.ExpiresAt.Equal(snapshot.ApprovalExpiresAt) {
		return 0, fmt.Errorf("%w: current approval does not bind the draft", ErrStateMismatch)
	}
	if len(transaction.Operations) >= len(snapshot.Operations) {
		return 0, fmt.Errorf("%w: campaign has no remaining operation", ErrStateMismatch)
	}
	for index, record := range transaction.Operations {
		operation := snapshot.Operations[index]
		if record.ID != operation.AuthorizationID || record.Operation != string(operation.Operation) ||
			record.PlanDigest != snapshot.PlanDigest || record.Release != snapshot.Release {
			return 0, fmt.Errorf("%w: operation history differs at sequence %d", ErrStateMismatch, index+1)
		}
		if record.Status != controlplane.OperationSucceeded && record.Status != controlplane.OperationConfirmedApplied {
			return 0, fmt.Errorf("%w: operation %d is not successfully closed", ErrStateMismatch, index+1)
		}
	}
	return uint32(len(transaction.Operations) + 1), nil
}

func proposalMatchesCurrentIntent(proposal IntentProposal, transaction controlplane.Transaction) error {
	if _, _, err := proposal.requests(validPlaceholderDigest); err != nil {
		return err
	}
	if transaction.ID != proposal.DraftSnapshot.TransactionID || transaction.FenceEpoch != proposal.FenceEpoch ||
		transaction.ActiveClaim == nil || transaction.ActiveClaim.ID != proposal.ClaimID ||
		transaction.Approval == nil || transaction.Approval.ID != proposal.ApprovalID {
		return fmt.Errorf("%w: current claim or approval differs from the intent proposal", ErrStateMismatch)
	}
	if transaction.ResourceVersion == proposal.ExpectedResourceVersion {
		sequence, err := nextSequence(proposal.DraftSnapshot, transaction)
		if err != nil {
			return err
		}
		if sequence != proposal.Sequence {
			return fmt.Errorf("%w: proposal sequence is no longer next", ErrStateMismatch)
		}
		return nil
	}
	// A byte-identical control replay is allowed after the intent already
	// committed. No other resource-version drift is accepted before the audit
	// append is replayed.
	if len(transaction.Operations) != int(proposal.Sequence) {
		return fmt.Errorf("%w: transaction changed after intent proposal", ErrStateMismatch)
	}
	last := transaction.Operations[len(transaction.Operations)-1]
	if last.ID != proposal.OperationID || last.Status != controlplane.OperationIntentRecorded ||
		last.PlanDigest != proposal.DraftSnapshot.PlanDigest || last.IntentFenceEpoch != proposal.FenceEpoch {
		return fmt.Errorf("%w: pending operation differs from intent proposal", ErrStateMismatch)
	}
	return nil
}

func proposalMatchesCurrentEvidence(proposal EvidenceProposal, transaction controlplane.Transaction) error {
	if _, _, err := proposal.requests(validPlaceholderDigest); err != nil {
		return err
	}
	if transaction.ID != proposal.DraftSnapshot.TransactionID || transaction.FenceEpoch != proposal.FenceEpoch ||
		transaction.ActiveClaim == nil || transaction.ActiveClaim.ID != proposal.ClaimID ||
		len(transaction.Operations) != int(proposal.Attempt.Sequence) {
		return fmt.Errorf("%w: current transaction differs from evidence proposal", ErrStateMismatch)
	}
	record := transaction.Operations[len(transaction.Operations)-1]
	operation := proposal.DraftSnapshot.Operations[proposal.Attempt.Sequence-1]
	draft, err := plancompiler.DraftFromSnapshot(proposal.DraftSnapshot)
	if err != nil {
		return fmt.Errorf("%w: evidence draft: %v", ErrInvalidInput, err)
	}
	prestateDigest, err := draft.PrestateDigest(proposal.Attempt.Sequence)
	if err != nil {
		return err
	}
	if record.ID != proposal.OperationID || record.Operation != string(proposal.Attempt.Operation) ||
		record.ID != operation.AuthorizationID || record.Operation != string(operation.Operation) ||
		record.PlanDigest != proposal.DraftSnapshot.PlanDigest || record.Release != proposal.DraftSnapshot.Release ||
		record.Approval.ID != proposal.Attempt.ApprovalID || record.Approval.PlanDigest != proposal.DraftSnapshot.PlanDigest ||
		record.Approval.Release != proposal.DraftSnapshot.Release || !record.Approval.ExpiresAt.Equal(proposal.DraftSnapshot.ApprovalExpiresAt) ||
		record.InputDigest != proposal.DraftSnapshot.PlanDigest || record.PrestateDigest != prestateDigest ||
		record.IntentFenceEpoch != proposal.FenceEpoch || record.IntentAuditReceiptID != proposal.Attempt.IntentReceipt {
		return fmt.Errorf("%w: pending operation differs from lane attempt", ErrStateMismatch)
	}
	if transaction.ResourceVersion == proposal.ExpectedResourceVersion {
		if transaction.Status != controlplane.StatusMutationInProgress || record.Status != controlplane.OperationIntentRecorded {
			return fmt.Errorf("%w: transaction is not awaiting attempt evidence", ErrStateMismatch)
		}
		return nil
	}
	// Permit only an idempotent replay after this exact operation has already
	// reached the control result represented by the proposal.
	want := controlplane.OperationUncertain
	switch proposal.Attempt.Status {
	case laneguard.AttemptVerified:
		want = controlplane.OperationSucceeded
	case laneguard.AttemptQuarantined:
		want = controlplane.OperationFailed
	}
	if record.Status != want {
		return fmt.Errorf("%w: transaction changed after evidence proposal", ErrStateMismatch)
	}
	_, request, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		return err
	}
	if record.OutputDigest != request.OutputDigest || record.ObservationDigest != request.ObservationDigest {
		return fmt.Errorf("%w: recorded evidence differs from the proposal", ErrStateMismatch)
	}
	return nil
}

func validateAttemptForDraft(snapshot laneguard.Plan, attempt laneguard.Attempt, eventTime time.Time) error {
	if attempt.SchemaVersion != laneguard.AttemptSchemaVersion || attempt.Sequence == 0 ||
		int(attempt.Sequence) > len(snapshot.Operations) || attempt.IntentSequence != attempt.Sequence ||
		attempt.TransactionID != snapshot.TransactionID || attempt.PlanDigest != snapshot.PlanDigest ||
		attempt.TargetFingerprint != snapshot.TargetFingerprint || attempt.FenceEpoch != snapshot.FenceEpoch ||
		!identifierPattern.MatchString(attempt.ApprovalID) || !digestPattern.MatchString(attempt.IntentReceipt) ||
		attempt.StartedAt.IsZero() || attempt.UpdatedAt.Before(attempt.StartedAt) || eventTime.Before(attempt.UpdatedAt) {
		return fmt.Errorf("%w: lane attempt has invalid immutable bindings or ordering", ErrInvalidInput)
	}
	operation := snapshot.Operations[attempt.Sequence-1]
	wantKey := fmt.Sprintf("%s/%s/%d/%d", snapshot.TransactionID, snapshot.PlanDigest, snapshot.FenceEpoch, attempt.Sequence)
	if attempt.Key != wantKey || attempt.Operation != operation.Operation || attempt.OperationDigest != operation.OperationDigest {
		return fmt.Errorf("%w: lane attempt is not compiler-bound", ErrInvalidInput)
	}
	for _, digest := range []string{attempt.Result.OutputDigest, attempt.Result.BindingDigest} {
		if digest != "" && !digestPattern.MatchString(digest) {
			return fmt.Errorf("%w: lane attempt result digest is invalid", ErrInvalidInput)
		}
	}
	if attempt.Status == laneguard.AttemptVerified && attempt.ObservedState != operation.ExpectedPoststate {
		return fmt.Errorf("%w: verified lane attempt does not contain the approved poststate", ErrInvalidInput)
	}
	if err := validateAttemptBootTransitions(snapshot, attempt); err != nil {
		return err
	}
	return nil
}

func validateAttemptBootTransitions(snapshot laneguard.Plan, attempt laneguard.Attempt) error {
	operation := snapshot.Operations[attempt.Sequence-1]
	base := laneguard.HardwareAction{
		SchemaVersion: laneguard.BootTransitionActionSchemaVersion,
		StationID:     snapshot.StationID, LaneID: snapshot.LaneID,
		TransactionID: snapshot.TransactionID, PlanDigest: snapshot.PlanDigest,
		TargetFingerprint: snapshot.TargetFingerprint, FenceEpoch: snapshot.FenceEpoch,
		ApprovalID: attempt.ApprovalID, IntentReceipt: attempt.IntentReceipt,
		IntentSequence: attempt.IntentSequence, Sequence: attempt.Sequence,
		Operation: attempt.Operation, OperationDigest: attempt.OperationDigest,
		AuthorizationID:           operation.AuthorizationID,
		OperationRequiredBootMode: operation.RequiredBootMode,
	}
	validate := func(name string, outcome laneguard.BootTransitionOutcome, phase laneguard.HardwarePhase, required bool) error {
		if outcome == (laneguard.BootTransitionOutcome{}) {
			if required {
				return fmt.Errorf("%w: attempt lacks its %s boot transition", ErrInvalidInput, name)
			}
			return nil
		}
		expected := base
		expected.Phase = phase
		expected.RequestedBootMode = laneguard.BootModeRPIBoot
		if phase == laneguard.HardwarePhaseExecute {
			expected.RequestedBootMode = operation.RequiredBootMode
		}
		if phase == laneguard.HardwarePhaseReconciliation {
			expected.ReconciliationClaimID = outcome.Action.ReconciliationClaimID
			expected.ReconciliationFenceEpoch = outcome.Action.ReconciliationFenceEpoch
		}
		if err := outcome.ValidateForAction(expected); err != nil {
			return fmt.Errorf("%w: attempt %s boot transition: %v", ErrInvalidInput, name, err)
		}
		return nil
	}
	if err := validate("pre-observation", attempt.PreObservationTransition, laneguard.HardwarePhasePreObservation, true); err != nil {
		return err
	}
	if attempt.PreObservationTransition.Reference.Status != laneguard.BootTransitionCompleted {
		return fmt.Errorf("%w: pre-observation boot transition did not complete", ErrInvalidInput)
	}
	if err := validate("execution", attempt.ExecutionTransition, laneguard.HardwarePhaseExecute, false); err != nil {
		return err
	}
	if err := validate("post-observation", attempt.PostObservationTransition, laneguard.HardwarePhasePostObservation, false); err != nil {
		return err
	}
	if err := validate("reconciliation", attempt.ReconciliationTransition, laneguard.HardwarePhaseReconciliation, false); err != nil {
		return err
	}
	if attempt.PostObservationTransition != (laneguard.BootTransitionOutcome{}) &&
		(attempt.ExecutionTransition == (laneguard.BootTransitionOutcome{}) || attempt.ExecutionTransition.Reference.Status != laneguard.BootTransitionCompleted) {
		return fmt.Errorf("%w: post-observation transition lacks completed execution", ErrInvalidInput)
	}
	if attempt.Result != (laneguard.OperationResult{}) {
		if attempt.ExecutionTransition.Reference.Status != laneguard.BootTransitionCompleted ||
			attempt.Result.BootTransition != attempt.ExecutionTransition {
			return fmt.Errorf("%w: operation result differs from its execution transition", ErrInvalidInput)
		}
	} else if attempt.ExecutionTransition.Reference.Status == laneguard.BootTransitionCompleted {
		return fmt.Errorf("%w: completed execution transition lacks its operation result", ErrInvalidInput)
	}
	executionCompleted := attempt.ExecutionTransition != (laneguard.BootTransitionOutcome{}) &&
		attempt.ExecutionTransition.Reference.Status == laneguard.BootTransitionCompleted
	postObservationCompleted := attempt.PostObservationTransition != (laneguard.BootTransitionOutcome{}) &&
		attempt.PostObservationTransition.Reference.Status == laneguard.BootTransitionCompleted
	reconciliationCompleted := attempt.ReconciliationTransition != (laneguard.BootTransitionOutcome{}) &&
		attempt.ReconciliationTransition.Reference.Status == laneguard.BootTransitionCompleted
	switch attempt.Status {
	case laneguard.AttemptVerified:
		if !(executionCompleted && postObservationCompleted) && !reconciliationCompleted {
			return fmt.Errorf("%w: verified attempt lacks a completed postcondition observation", ErrInvalidInput)
		}
	case laneguard.AttemptConfirmedNotApplied:
		if !reconciliationCompleted {
			return fmt.Errorf("%w: confirmed-not-applied attempt lacks completed reconciliation evidence", ErrInvalidInput)
		}
	}
	return nil
}

func matchCreatedTransaction(transaction controlplane.Transaction, input DraftInput) error {
	if transaction.ID != input.TransactionID || transaction.AssetID != input.AssetID ||
		transaction.IntendedLogicalID != input.IntendedLogicalID || transaction.ProfileID != input.ProfileID ||
		transaction.BundleDigest != input.Release.SignedReleaseManifestDigest || transaction.PolicyDigest != input.PolicyDigest ||
		transaction.ExpectedPrestateCustomerKeyHash != input.InitialState.CustomerKeyHash ||
		transaction.ExpectedCustomerKeyHash != input.Release.ExpectedCustomerKeyHash {
		return fmt.Errorf("%w: created transaction differs from reviewed input", ErrStateMismatch)
	}
	return nil
}

func matchClaim(transaction controlplane.Transaction, stationID, laneID string, operations []string) error {
	claim := transaction.ActiveClaim
	if claim == nil || !identifierPattern.MatchString(claim.ID) || claim.Mode != controlplane.ClaimModeMutation || claim.Status != controlplane.ClaimActive || claim.ClosedAt != nil ||
		claim.StationID != stationID || claim.LaneID != laneID || claim.FenceEpoch != transaction.FenceEpoch ||
		claim.AssetID != transaction.AssetID || claim.AcquiredAt.IsZero() || !claim.ExpiresAt.After(claim.AcquiredAt) ||
		!equalStrings(claim.AllowedStages, operations) {
		return fmt.Errorf("%w: acquired claim differs from fixed campaign", ErrStateMismatch)
	}
	return nil
}

func matchBoundTransaction(transaction controlplane.Transaction, input DraftInput) error {
	if err := matchCreatedTransaction(transaction, input); err != nil {
		return err
	}
	if err := matchClaim(transaction, input.StationID, input.LaneID, developmentOperationNames()); err != nil {
		return err
	}
	if transaction.Status != controlplane.StatusTargetBound || transaction.Target == nil ||
		transaction.Target.Fingerprint != input.TargetFingerprint || transaction.Target.ObservationDigest != input.ObservationDigest ||
		transaction.Target.CustomerKeyHash != input.InitialState.CustomerKeyHash || transaction.Target.FenceEpoch != transaction.FenceEpoch {
		return fmt.Errorf("%w: target binding differs from reviewed input", ErrStateMismatch)
	}
	return nil
}

func matchDraftTransaction(snapshot laneguard.Plan, transaction controlplane.Transaction, status controlplane.TransactionStatus) error {
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ID != snapshot.TransactionID ||
		transaction.ResourceVersion == 0 || transaction.Status != status || transaction.BundleDigest != snapshot.Release.SignedReleaseManifestDigest ||
		transaction.ExpectedPrestateCustomerKeyHash != snapshot.Operations[0].ExpectedPrestate.CustomerKeyHash ||
		transaction.ExpectedCustomerKeyHash != snapshot.Release.ExpectedCustomerKeyHash || !digestPattern.MatchString(transaction.TransactionDigest) ||
		transaction.FenceEpoch != snapshot.FenceEpoch ||
		transaction.ActiveClaim == nil || transaction.ActiveClaim.Mode != controlplane.ClaimModeMutation ||
		transaction.ActiveClaim.Status != controlplane.ClaimActive || transaction.ActiveClaim.ClosedAt != nil ||
		transaction.ActiveClaim.StationID != snapshot.StationID ||
		transaction.ActiveClaim.LaneID != snapshot.LaneID || transaction.ActiveClaim.FenceEpoch != snapshot.FenceEpoch ||
		!equalStrings(transaction.ActiveClaim.AllowedStages, planOperations(snapshot)) || transaction.Target == nil ||
		transaction.Target.Fingerprint != snapshot.TargetFingerprint || transaction.Target.FenceEpoch != snapshot.FenceEpoch ||
		transaction.Target.CustomerKeyHash != snapshot.Operations[0].ExpectedPrestate.CustomerKeyHash ||
		!digestPattern.MatchString(transaction.Target.ObservationDigest) {
		return fmt.Errorf("%w: control transaction does not match the authority-free draft", ErrStateMismatch)
	}
	return nil
}

func mutationContext(transaction controlplane.Transaction) controlplane.MutationContext {
	return controlplane.MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func developmentOperationNames() []string {
	operations := campaign.DevelopmentOperations()
	result := make([]string, len(operations))
	for index, operation := range operations {
		result[index] = string(operation)
	}
	return result
}

func planOperations(plan laneguard.Plan) []string {
	result := make([]string, len(plan.Operations))
	for index, operation := range plan.Operations {
		result[index] = string(operation.Operation)
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func clonePlan(plan laneguard.Plan) laneguard.Plan {
	plan.Operations = append([]laneguard.OperationSpec(nil), plan.Operations...)
	return plan
}

func workflowID(label string, values ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(digestDomain))
	for _, value := range append([]string{label}, values...) {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return label + "-" + hex.EncodeToString(hash.Sum(nil))[:32]
}

func digestJSON(label string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal fixed operator workflow value: %v", err))
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(digestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(label))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

const validPlaceholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
