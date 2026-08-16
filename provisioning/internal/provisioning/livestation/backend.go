package livestation

import (
	"context"
	"errors"
)

var (
	ErrStaleRevision          = errors.New("state revision is stale")
	ErrActionNotAllowed       = errors.New("action is not allowed in the authoritative phase")
	ErrBackendUnavailable     = errors.New("orchestration backend is unavailable")
	ErrInvalidBackendResult   = errors.New("orchestration backend returned an invalid result")
	ErrReconciliationRequired = errors.New("irreversible outcome requires reconciliation")
	ErrQuarantined            = errors.New("owned target is quarantined")
)

type Disposition string

const (
	DispositionSucceeded Disposition = "succeeded"
	DispositionFailed    Disposition = "failed"
	DispositionUncertain Disposition = "uncertain"
)

type BackendRequest struct {
	Action         Action               `json:"action"`
	Classification ActionClassification `json:"classification"`
	Irreversible   bool                 `json:"irreversible"`
	State          State                `json:"state"`
}

type BackendResult struct {
	Disposition Disposition         `json:"disposition"`
	Transaction *TransactionSummary `json:"transaction,omitempty"`
	Manifest    *ManifestSummary    `json:"manifest,omitempty"`
	Target      *TargetSummary      `json:"target,omitempty"`
	Evidence    []Evidence          `json:"evidence"`
	Findings    []Finding           `json:"findings"`
	Detail      string              `json:"detail"`
}

// Backend performs all external orchestration. Machine owns transition
// authority; Backend supplies only evidence and externally assigned bindings.
type Backend interface {
	Perform(context.Context, BackendRequest) (BackendResult, error)
}

type BackendFunc func(context.Context, BackendRequest) (BackendResult, error)

func (function BackendFunc) Perform(ctx context.Context, request BackendRequest) (BackendResult, error) {
	return function(ctx, request)
}

// DisabledBackend is used by command defaults. It cannot advance the live
// workflow and, in particular, can never invoke a target mutation.
type DisabledBackend struct {
	Reason string
}

func (backend DisabledBackend) Perform(context.Context, BackendRequest) (BackendResult, error) {
	if backend.Reason == "" {
		return BackendResult{}, ErrBackendUnavailable
	}
	return BackendResult{Detail: backend.Reason}, ErrBackendUnavailable
}

// Orchestrator is the injectable boundary used by the loopback HTTP handler.
type Orchestrator interface {
	Current(context.Context) (State, error)
	Apply(context.Context, ActionRequest) (State, error)
}
