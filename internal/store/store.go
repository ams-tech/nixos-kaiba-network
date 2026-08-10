package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/model"
)

var (
	ErrNotFound             = errors.New("desired state not found")
	ErrIdempotencyConflict  = errors.New("idempotency key is already bound to a different request")
	ErrPreconditionRequired = errors.New("a desired-state write precondition is required")
	ErrPreconditionFailed   = errors.New("desired-state write precondition failed")
)

type IntentPrecondition struct {
	ExpectedGeneration int64
	RequireAbsent      bool
}

func MatchGeneration(generation int64) IntentPrecondition {
	return IntentPrecondition{ExpectedGeneration: generation}
}

func RequireAbsent() IntentPrecondition {
	return IntentPrecondition{RequireAbsent: true}
}

func (p IntentPrecondition) valid() bool {
	return (p.RequireAbsent && p.ExpectedGeneration == 0) || (!p.RequireAbsent && p.ExpectedGeneration > 0)
}

func (p IntentPrecondition) key() string {
	if p.RequireAbsent {
		return "if-none-match:*"
	}
	return fmt.Sprintf("if-match:g-%d", p.ExpectedGeneration)
}

type UpsertRequest struct {
	DeviceID          string
	Hostname          string
	Addresses         []netip.Addr
	IdempotencyKey    string
	Precondition      IntentPrecondition
	Now               time.Time
	LeaseDuration     time.Duration
	RenewAfterSeconds int64
}

type UpsertResult struct {
	Intent            model.Intent
	RenewAfterSeconds int64
	Replay            bool
}

// DesiredState is the controller/publisher storage boundary. DNS is only a
// projection of these durable records.
type DesiredState interface {
	UpsertIntent(context.Context, UpsertRequest) (UpsertResult, error)
	GetIntent(context.Context, string) (model.Intent, error)
	ExpireLeases(context.Context, time.Time) ([]model.Intent, error)
	ListOriginPending(context.Context, int) ([]model.Intent, error)
	ListObservationPending(context.Context, int) ([]model.Intent, error)
	MarkOriginApplied(context.Context, string, int64) error
	MarkPubliclyObserved(context.Context, string, int64) error
	MarkPublicationError(context.Context, string, int64, string) error
}
