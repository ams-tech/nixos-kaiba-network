package controlplane

import "context"

// Coordinator captures the platform-neutral control boundary used by a
// provisioning orchestrator. Deployments may replace the reference in-process
// Service with an authenticated remote client implementing this interface.
type Coordinator interface {
	CreateTransaction(context.Context, CreateTransactionRequest) (Transaction, error)
	AcquireClaim(context.Context, AcquireClaimRequest) (Transaction, error)
	RenewClaim(context.Context, RenewClaimRequest) (Transaction, error)
	TransferClaim(context.Context, TransferClaimRequest) (Transaction, error)
	ReleaseClaim(context.Context, ReleaseClaimRequest) (Transaction, error)
	BindTarget(context.Context, BindTargetRequest) (Transaction, error)
	PreflightApproval(context.Context, ApprovalPreflightRequest) (Transaction, error)
	RecordApproval(context.Context, RecordApprovalRequest) (Transaction, error)
	RecordStageIntent(context.Context, RecordIntentRequest) (Transaction, error)
	RecordStageEvidence(context.Context, RecordEvidenceRequest) (Transaction, error)
	RecordReconciliation(context.Context, RecordReconciliationRequest) (Transaction, error)
	QuarantineDevice(context.Context, QuarantineRequest) (Transaction, error)
	AbortTransaction(context.Context, AbortRequest) (Transaction, error)
	MarkSecurityApplied(context.Context, SecurityAppliedRequest) (Transaction, error)
	GetTransactionForReconciliation(context.Context, string) (Transaction, error)
}
