package laneguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

var (
	ErrOperationDeadline      = errors.New("operation maximum duration exceeded")
	ErrReconciliationDeadline = errors.New("reconciliation observation budget exceeded")
)

// Hardware is the only component allowed to translate a typed operation into
// target-facing behavior. Implementations must use Config's fixed resources
// and build-time-pinned artifacts.
type Hardware interface {
	Observe(context.Context, Config, HardwareAction) (Observation, error)
	Execute(context.Context, Config, HardwareAction) (OperationResult, error)
}

// DispatchAuthority rechecks the exact immutable plan and request immediately
// before the guard creates a durable execution intent or observes a target for
// reconciliation. Production implementations must consult the authenticated
// authority source; the default implementation is intentionally local-only for
// package users that do not own that transport boundary.
type DispatchAuthority interface {
	RecheckExecute(context.Context, Plan, ExecuteRequest) error
	RecheckReconciliation(context.Context, Plan, ReconcileRequest) error
}

type localDispatchAuthority struct{}

func (localDispatchAuthority) RecheckExecute(context.Context, Plan, ExecuteRequest) error {
	return nil
}

func (localDispatchAuthority) RecheckReconciliation(context.Context, Plan, ReconcileRequest) error {
	return nil
}

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Guard struct {
	mu                 sync.Mutex
	config             Config
	hardware           Hardware
	store              Journal
	clock              Clock
	dispatchAuthority  DispatchAuthority
	plan               *Plan
	reconciliationOnly bool
	lockedOut          bool
}

func New(config Config, hardware Hardware, store Journal) (*Guard, error) {
	return newGuard(config, hardware, store, systemClock{}, localDispatchAuthority{})
}

func NewWithClock(config Config, hardware Hardware, store Journal, clock Clock) (*Guard, error) {
	return newGuard(config, hardware, store, clock, localDispatchAuthority{})
}

// NewWithDispatchAuthority constructs a guard whose final dispatch boundary is
// backed by an authenticated external authority source.
func NewWithDispatchAuthority(config Config, hardware Hardware, store Journal, authority DispatchAuthority) (*Guard, error) {
	return newGuard(config, hardware, store, systemClock{}, authority)
}

// NewWithClockAndDispatchAuthority is the testable form of
// NewWithDispatchAuthority.
func NewWithClockAndDispatchAuthority(config Config, hardware Hardware, store Journal, clock Clock, authority DispatchAuthority) (*Guard, error) {
	return newGuard(config, hardware, store, clock, authority)
}

func newGuard(config Config, hardware Hardware, store Journal, clock Clock, authority DispatchAuthority) (*Guard, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if hardware == nil {
		return nil, errors.New("hardware adapter is required")
	}
	if store == nil {
		return nil, errors.New("durable attempt store is required")
	}
	if clock == nil {
		return nil, errors.New("clock is required")
	}
	if authority == nil {
		return nil, errors.New("dispatch authority is required")
	}
	config.SchemaVersion = ContractSchemaVersion
	return &Guard{config: config, hardware: hardware, store: store, clock: clock, dispatchAuthority: authority}, nil
}

// LoadPlan validates and binds this guard instance to one approved plan, then
// restores its lockout state from the durable journal. It performs no
// target-facing I/O; Execute or Reconcile owns the first target observation.
// A different plan, target, transaction, or epoch requires a fresh guard after
// lane teardown.
func (guard *Guard) LoadPlan(_ context.Context, plan Plan) error {
	// Freeze caller-owned slice storage before validation so the body that is
	// checked is exactly the body retained after journal validation.
	plan = clonePlan(plan)
	if err := plan.Validate(guard.config); err != nil {
		return err
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.plan != nil {
		if samePlan(*guard.plan, plan) {
			return nil
		}
		return ErrPlanLocked
	}
	_, lockedOut, err := guard.restartStates(plan)
	if err != nil {
		return err
	}
	guard.plan = &plan
	guard.lockedOut = lockedOut
	return nil
}

// ReconcilePlan atomically loads the immutable original execution plan from
// its durable journal and reconciles its unresolved attempt under a fresh,
// read-only claim. Claim authority is checked before any target-facing I/O,
// and the target is observed exactly once. The method never calls
// Hardware.Execute.
func (guard *Guard) ReconcilePlan(ctx context.Context, plan Plan, request ReconcileRequest) (Attempt, error) {
	plan = clonePlan(plan)
	if err := ValidateReconcileRequest(guard.config, plan, request); err != nil {
		return Attempt{}, err
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if !LeaseCoversOperation(guard.clock.Now(), request.Claim.ExpiresAt, ReconciliationObservationBudget, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	if guard.plan != nil {
		if !samePlan(*guard.plan, plan) {
			return Attempt{}, ErrPlanLocked
		}
	} else {
		_, lockedOut, err := guard.restartStates(plan)
		if err != nil {
			return Attempt{}, err
		}
		guard.plan = &plan
		guard.lockedOut = lockedOut
	}
	// Once a guard accepts a current reconciliation claim, the original
	// execute envelope is attempt identity only. Permanently disarm mutation
	// even when journal recovery finds that the local started record is absent.
	guard.reconciliationOnly = true
	return guard.reconcileLocked(ctx, request)
}

func (guard *Guard) Execute(ctx context.Context, request ExecuteRequest) (Attempt, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	plan, operation, err := guard.matchRequest(request)
	if err != nil {
		return Attempt{}, err
	}
	current := guard.clock.Now()
	if !current.Before(plan.ApprovalExpiresAt) {
		return Attempt{}, ErrApprovalExpired
	}
	if !LeaseCoversOperation(current, request.ClaimExpiresAt, operation.MaximumDuration, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	operationCtx, cancelOperation := context.WithTimeoutCause(ctx, operation.MaximumDuration, ErrOperationDeadline)
	defer cancelOperation()
	key := attemptKey(plan, operation.Sequence)
	existing, found, err := guard.store.Get(key)
	if err != nil {
		return Attempt{}, fmt.Errorf("read execute-once journal: %w", err)
	}
	if found {
		if !attemptMatchesIntent(existing, plan, operation) {
			return Attempt{}, ErrPlanMismatch
		}
		switch existing.Status {
		case AttemptVerified:
			return existing, nil
		case AttemptConfirmedNotApplied:
			return existing, ErrConfirmedNotApplied
		case AttemptQuarantined:
			return existing, ErrQuarantined
		default:
			return existing, ErrReconciliationRequired
		}
	}
	if operation.Sequence > 1 {
		previous, found, err := guard.store.Get(attemptKey(plan, operation.Sequence-1))
		if err != nil {
			return Attempt{}, fmt.Errorf("read preceding operation journal: %w", err)
		}
		if !found || previous.Status != AttemptVerified || previous.ObservedState != operation.ExpectedPrestate {
			return Attempt{}, ErrOutOfOrder
		}
	}
	preAction, err := makeHardwareAction(plan, operation, HardwarePhasePreObservation, nil)
	if err != nil {
		return Attempt{}, err
	}
	observation, err := guard.observeBoundTarget(operationCtx, plan.TargetFingerprint, preAction)
	if err != nil {
		return Attempt{}, errors.Join(err, context.Cause(operationCtx))
	}
	if err := context.Cause(operationCtx); err != nil {
		return Attempt{}, err
	}
	// Direct observation may include bounded device waits and, once the manual
	// BOOTSEL selector is wired in, an operator acknowledgment. Revalidate both
	// authorities after that delay so the durable execute-once intent is never
	// recorded under an approval or claim that can no longer cover execution.
	current = guard.clock.Now()
	if !current.Before(plan.ApprovalExpiresAt) {
		return Attempt{}, ErrApprovalExpired
	}
	if !LeaseCoversOperation(current, request.ClaimExpiresAt, operation.MaximumDuration, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	if observation.State != operation.ExpectedPrestate {
		return Attempt{}, ErrPrestateMismatch
	}
	executionAction, err := makeHardwareAction(plan, operation, HardwarePhaseExecute, nil)
	if err != nil {
		return Attempt{}, err
	}
	if err := guard.dispatchAuthority.RecheckExecute(operationCtx, clonePlan(plan), request); err != nil {
		return Attempt{}, errors.Join(fmt.Errorf("recheck execution dispatch authority: %w", err), context.Cause(operationCtx))
	}
	if err := context.Cause(operationCtx); err != nil {
		return Attempt{}, err
	}
	current = guard.clock.Now()
	if !current.Before(plan.ApprovalExpiresAt) {
		return Attempt{}, ErrApprovalExpired
	}
	if !LeaseCoversOperation(current, request.ClaimExpiresAt, operation.MaximumDuration, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	now := current.UTC()
	attempt := Attempt{
		SchemaVersion: AttemptSchemaVersion, Key: key,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest,
		TargetFingerprint: plan.TargetFingerprint, FenceEpoch: plan.FenceEpoch,
		ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt, IntentSequence: plan.IntentSequence,
		Sequence: operation.Sequence, Operation: operation.Operation,
		OperationDigest: operation.OperationDigest, Status: AttemptStarted,
		StartedAt: now, UpdatedAt: now, ObservedState: observation.State,
		PreObservationTransition: observation.BootTransition,
		Detail:                   "durable intent recorded before hardware execution",
	}
	if err := guard.store.Put(attempt); err != nil {
		return Attempt{}, fmt.Errorf("record execute-once intent: %w", err)
	}
	result, executeErr := guard.hardware.Execute(operationCtx, guard.config, executionAction)
	transitionErr := guard.validateBootTransitionOutcome(executionAction, result.BootTransition, executeErr == nil)
	executeErr = errors.Join(executeErr, context.Cause(operationCtx))
	if executeErr != nil {
		if transitionErr == nil {
			attempt.ExecutionTransition = result.BootTransition
		}
		attempt.Status = AttemptUncertain
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "hardware call returned without an authoritative postcondition"
		if storeErr := guard.store.Put(attempt); storeErr != nil {
			return attempt, errors.Join(ErrReconciliationRequired, executeErr, transitionErr, fmt.Errorf("record uncertain outcome: %w", storeErr))
		}
		return attempt, errors.Join(ErrReconciliationRequired, executeErr, transitionErr)
	}
	if transitionErr != nil {
		attempt.Status = AttemptUncertain
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "hardware returned an invalid or non-durable boot-transition outcome"
		if storeErr := guard.store.Put(attempt); storeErr != nil {
			return attempt, errors.Join(ErrReconciliationRequired, transitionErr, fmt.Errorf("record uncertain outcome: %w", storeErr))
		}
		return attempt, errors.Join(ErrReconciliationRequired, transitionErr)
	}
	attempt.ExecutionTransition = result.BootTransition
	attempt.Result = bindOperationResult(plan, operation, result)
	postAction, err := makeHardwareAction(plan, operation, HardwarePhasePostObservation, nil)
	if err != nil {
		return attempt, err
	}
	postObservation, observeErr := guard.observeBoundTarget(operationCtx, plan.TargetFingerprint, postAction)
	observeErr = errors.Join(observeErr, context.Cause(operationCtx))
	if postObservation.BootTransition != (BootTransitionOutcome{}) {
		attempt.PostObservationTransition = postObservation.BootTransition
	}
	if observeErr != nil {
		if errors.Is(observeErr, ErrTargetContinuity) {
			attempt.Status = AttemptQuarantined
			attempt.UpdatedAt = guard.clock.Now().UTC()
			attempt.Detail = "target continuity changed after hardware execution"
			if storeErr := guard.store.Put(attempt); storeErr != nil {
				return attempt, errors.Join(ErrQuarantined, observeErr, fmt.Errorf("record quarantine: %w", storeErr))
			}
			return attempt, errors.Join(ErrQuarantined, observeErr)
		}
		attempt.Status = AttemptUncertain
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "hardware returned but direct postcondition observation failed"
		if storeErr := guard.store.Put(attempt); storeErr != nil {
			return attempt, errors.Join(ErrReconciliationRequired, observeErr, fmt.Errorf("record uncertain outcome: %w", storeErr))
		}
		return attempt, errors.Join(ErrReconciliationRequired, observeErr)
	}
	return guard.finishObserved(attempt, operation, postObservation)
}

// Reconcile directly observes an already-started operation. It never calls
// Hardware.Execute. A non-matching conclusive state is quarantined, while a
// temporarily unavailable observation remains uncertain.
func (guard *Guard) Reconcile(ctx context.Context, request ReconcileRequest) (Attempt, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.reconcileLocked(ctx, request)
}

func (guard *Guard) reconcileLocked(ctx context.Context, request ReconcileRequest) (Attempt, error) {
	plan, operation, err := guard.matchReconcileRequest(request)
	if err != nil {
		return Attempt{}, err
	}
	current := guard.clock.Now()
	if !LeaseCoversOperation(current, request.Claim.ExpiresAt, ReconciliationObservationBudget, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	reconciliationCtx, cancelReconciliation := context.WithTimeoutCause(
		ctx, ReconciliationObservationBudget, ErrReconciliationDeadline,
	)
	defer cancelReconciliation()
	key := attemptKey(plan, operation.Sequence)
	attempt, found, err := guard.store.Get(key)
	if err != nil {
		return Attempt{}, fmt.Errorf("read execute-once journal: %w", err)
	}
	if !found {
		return Attempt{}, errors.New("no operation attempt exists to reconcile")
	}
	if !attemptMatchesIntent(attempt, plan, operation) {
		return Attempt{}, ErrPlanMismatch
	}
	switch attempt.Status {
	case AttemptVerified:
		return attempt, nil
	case AttemptConfirmedNotApplied:
		return attempt, nil
	case AttemptQuarantined:
		return attempt, ErrQuarantined
	case AttemptStarted, AttemptUncertain:
	default:
		return Attempt{}, errors.New("attempt journal has an invalid status")
	}
	// Journal recovery may itself take time. Recheck immediately before the
	// sole target observation so the full bounded observation still fits in
	// the authenticated claim lease.
	if !LeaseCoversOperation(guard.clock.Now(), request.Claim.ExpiresAt, ReconciliationObservationBudget, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	reconciliationAction, err := makeHardwareAction(plan, operation, HardwarePhaseReconciliation, &request.Claim)
	if err != nil {
		return Attempt{}, err
	}
	if err := guard.dispatchAuthority.RecheckReconciliation(reconciliationCtx, clonePlan(plan), request); err != nil {
		return Attempt{}, errors.Join(fmt.Errorf("recheck reconciliation dispatch authority: %w", err), context.Cause(reconciliationCtx))
	}
	if err := context.Cause(reconciliationCtx); err != nil {
		return Attempt{}, err
	}
	if !LeaseCoversOperation(guard.clock.Now(), request.Claim.ExpiresAt, ReconciliationObservationBudget, guard.config.LeaseSafetyMargin) {
		return Attempt{}, ErrLeaseInvalid
	}
	observation, err := guard.observeBoundTarget(reconciliationCtx, plan.TargetFingerprint, reconciliationAction)
	err = errors.Join(err, context.Cause(reconciliationCtx))
	if observation.BootTransition != (BootTransitionOutcome{}) {
		attempt.ReconciliationTransition = observation.BootTransition
	}
	if err != nil {
		if errors.Is(err, ErrTargetContinuity) {
			attempt.Status = AttemptQuarantined
			attempt.UpdatedAt = guard.clock.Now().UTC()
			attempt.Detail = "target continuity changed during reconciliation"
			if storeErr := guard.store.Put(attempt); storeErr != nil {
				return attempt, errors.Join(ErrQuarantined, err, fmt.Errorf("record quarantine: %w", storeErr))
			}
			return attempt, errors.Join(ErrQuarantined, err)
		}
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "direct reconciliation observation failed"
		if storeErr := guard.store.Put(attempt); storeErr != nil {
			return attempt, errors.Join(ErrReconciliationRequired, err, fmt.Errorf("record reconciliation failure: %w", storeErr))
		}
		return attempt, errors.Join(ErrReconciliationRequired, err)
	}
	if operation.ExpectedPrestate == operation.ExpectedPoststate && observation.State == operation.ExpectedPoststate {
		attempt.Status = AttemptUncertain
		attempt.ObservedState = observation.State
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "direct state cannot distinguish whether the interrupted operation executed"
		if err := guard.store.Put(attempt); err != nil {
			return attempt, errors.Join(ErrReconciliationRequired, fmt.Errorf("record indistinguishable outcome: %w", err))
		}
		return attempt, ErrReconciliationRequired
	}
	if observation.State == operation.ExpectedPrestate {
		attempt.Status = AttemptConfirmedNotApplied
		attempt.ObservedState = observation.State
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "direct original prestate confirms that the interrupted operation did not apply"
		if err := guard.store.Put(attempt); err != nil {
			return attempt, fmt.Errorf("record confirmed-not-applied reconciliation: %w", err)
		}
		return attempt, nil
	}
	return guard.finishObserved(attempt, operation, observation)
}

// bindOperationResult makes otherwise repeatable device output unique to the
// exact approved execution. The raw output digest remains available for
// artifact correlation; BindingDigest is the value suitable for transaction
// evidence and audit records.
func bindOperationResult(plan Plan, operation OperationSpec, result OperationResult) OperationResult {
	digest := sha256.New()
	for _, value := range []string{
		ContractSchemaVersion,
		plan.StationID,
		plan.LaneID,
		plan.TransactionID,
		plan.PlanDigest,
		plan.TargetFingerprint,
		strconv.FormatUint(plan.FenceEpoch, 10),
		plan.ApprovalID,
		plan.IntentReceipt,
		strconv.FormatUint(uint64(operation.Sequence), 10),
		string(operation.Operation),
		operation.OperationDigest,
		operation.AuthorizationID,
		result.OutputDigest,
		result.BootTransition.Reference.TransitionKey,
		result.BootTransition.Reference.EvidenceDigest,
	} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	result.BindingDigest = "sha256:" + hex.EncodeToString(digest.Sum(nil))
	return result
}

func (guard *Guard) finishObserved(attempt Attempt, operation OperationSpec, observation Observation) (Attempt, error) {
	attempt.ObservedState = observation.State
	attempt.UpdatedAt = guard.clock.Now().UTC()
	if observation.State == operation.ExpectedPoststate {
		attempt.Status = AttemptVerified
		attempt.Detail = "direct postcondition verified"
		if err := guard.store.Put(attempt); err != nil {
			return attempt, fmt.Errorf("record verified postcondition: %w", err)
		}
		return attempt, nil
	}
	attempt.Status = AttemptQuarantined
	attempt.Detail = "direct postcondition did not match the approved plan"
	if err := guard.store.Put(attempt); err != nil {
		return attempt, errors.Join(ErrQuarantined, ErrPoststateMismatch, fmt.Errorf("record quarantine: %w", err))
	}
	return attempt, errors.Join(ErrQuarantined, ErrPoststateMismatch)
}

func (guard *Guard) matchRequest(request ExecuteRequest) (Plan, OperationSpec, error) {
	if guard.plan == nil {
		return Plan{}, OperationSpec{}, ErrNoPlan
	}
	if guard.reconciliationOnly {
		return Plan{}, OperationSpec{}, ErrReconciliationAuthority
	}
	if guard.lockedOut {
		return Plan{}, OperationSpec{}, ErrQuarantined
	}
	plan := *guard.plan
	operation, err := matchPlanRequest(plan, request)
	if err != nil {
		return Plan{}, OperationSpec{}, err
	}
	return plan, operation, nil
}

func (guard *Guard) matchReconcileRequest(request ReconcileRequest) (Plan, OperationSpec, error) {
	if guard.plan == nil {
		return Plan{}, OperationSpec{}, ErrNoPlan
	}
	if guard.lockedOut {
		return Plan{}, OperationSpec{}, ErrQuarantined
	}
	plan := *guard.plan
	operation, err := matchReconcileRequest(guard.config, plan, request)
	if err != nil {
		return Plan{}, OperationSpec{}, err
	}
	return plan, operation, nil
}

func matchPlanRequest(plan Plan, request ExecuteRequest) (OperationSpec, error) {
	if request.SchemaVersion != ContractSchemaVersion ||
		request.StationID != plan.StationID || request.LaneID != plan.LaneID ||
		request.TransactionID != plan.TransactionID || request.PlanDigest != plan.PlanDigest ||
		request.Release != plan.Release ||
		request.TargetFingerprint != plan.TargetFingerprint || request.FenceEpoch != plan.FenceEpoch ||
		request.ApprovalID != plan.ApprovalID || !request.ApprovalExpiresAt.Equal(plan.ApprovalExpiresAt) ||
		request.IntentReceipt != plan.IntentReceipt ||
		request.Sequence == 0 || request.Sequence != plan.IntentSequence || int(request.Sequence) > len(plan.Operations) {
		return OperationSpec{}, ErrPlanMismatch
	}
	operation := plan.Operations[request.Sequence-1]
	if request.OperationDigest != operation.OperationDigest || request.AuthorizationID != operation.AuthorizationID ||
		request.RequiredBootMode != operation.RequiredBootMode || request.ExpectedPrestate != operation.ExpectedPrestate {
		return OperationSpec{}, ErrPlanMismatch
	}
	return operation, nil
}

func matchReconcileRequest(config Config, plan Plan, request ReconcileRequest) (OperationSpec, error) {
	operation, err := matchPlanRequest(plan, request.OriginalRequest)
	if err != nil {
		return OperationSpec{}, err
	}
	claim := request.Claim
	if request.SchemaVersion != ReconcileRequestSchemaVersion ||
		claim.StationID != config.StationID || claim.LaneID != config.LaneID ||
		claim.TransactionID != plan.TransactionID || claim.TargetFingerprint != plan.TargetFingerprint ||
		!identifierPattern.MatchString(claim.ClaimID) || claim.FenceEpoch <= plan.FenceEpoch || claim.ExpiresAt.IsZero() {
		return OperationSpec{}, ErrReconciliationAuthority
	}
	if _, err := canonicalApprovalExpiry(claim.ExpiresAt); err != nil {
		return OperationSpec{}, ErrReconciliationAuthority
	}
	return operation, nil
}

func (guard *Guard) restartStates(plan Plan) ([]DirectState, bool, error) {
	expected := []DirectState{plan.Operations[0].ExpectedPrestate}
	foundAttempt := false
	closed := false
	for index, operation := range plan.Operations {
		attempt, found, err := guard.store.Get(attemptKey(plan, operation.Sequence))
		if err != nil {
			return nil, false, fmt.Errorf("read restart journal: %w", err)
		}
		if !found {
			if foundAttempt {
				expected = []DirectState{operation.ExpectedPrestate}
			}
			for later := index + 1; later < len(plan.Operations); later++ {
				if _, exists, err := guard.store.Get(attemptKey(plan, plan.Operations[later].Sequence)); err != nil {
					return nil, false, fmt.Errorf("read restart journal: %w", err)
				} else if exists {
					return nil, false, errors.New("execute-once journal contains an operation gap")
				}
			}
			break
		}
		foundAttempt = true
		if operation.Sequence > plan.IntentSequence {
			return nil, false, ErrPlanMismatch
		}
		if attempt.TransactionID != plan.TransactionID || attempt.PlanDigest != plan.PlanDigest ||
			attempt.TargetFingerprint != plan.TargetFingerprint || attempt.FenceEpoch != plan.FenceEpoch ||
			attempt.ApprovalID != plan.ApprovalID ||
			attempt.Sequence != operation.Sequence || attempt.Operation != operation.Operation ||
			attempt.OperationDigest != operation.OperationDigest {
			return nil, false, ErrPlanMismatch
		}
		if operation.Sequence == plan.IntentSequence && !attemptMatchesIntent(attempt, plan, operation) {
			return nil, false, ErrPlanMismatch
		}
		switch attempt.Status {
		case AttemptVerified:
			expected = []DirectState{operation.ExpectedPoststate}
		case AttemptConfirmedNotApplied:
			for later := index + 1; later < len(plan.Operations); later++ {
				if _, exists, err := guard.store.Get(attemptKey(plan, plan.Operations[later].Sequence)); err != nil {
					return nil, false, fmt.Errorf("read restart journal: %w", err)
				} else if exists {
					return nil, false, errors.New("journal continues after a confirmed-not-applied attempt")
				}
			}
			expected = []DirectState{operation.ExpectedPrestate}
			return expected, false, nil
		case AttemptStarted, AttemptUncertain:
			expected = []DirectState{operation.ExpectedPrestate, operation.ExpectedPoststate}
			closed = false
			if index+1 != len(plan.Operations) {
				for later := index + 1; later < len(plan.Operations); later++ {
					if _, exists, err := guard.store.Get(attemptKey(plan, plan.Operations[later].Sequence)); err != nil {
						return nil, false, fmt.Errorf("read restart journal: %w", err)
					} else if exists {
						return nil, false, errors.New("journal continues after a non-terminal attempt")
					}
				}
			}
			return expected, closed, nil
		case AttemptQuarantined:
			for later := index + 1; later < len(plan.Operations); later++ {
				if _, exists, err := guard.store.Get(attemptKey(plan, plan.Operations[later].Sequence)); err != nil {
					return nil, false, fmt.Errorf("read restart journal: %w", err)
				} else if exists {
					return nil, false, errors.New("journal continues after quarantine")
				}
			}
			expected = []DirectState{attempt.ObservedState}
			return expected, true, nil
		default:
			return nil, false, errors.New("execute-once journal contains an invalid status")
		}
	}
	return expected, closed, nil
}

func attemptMatchesIntent(attempt Attempt, plan Plan, operation OperationSpec) bool {
	return attempt.ApprovalID == plan.ApprovalID && attempt.IntentReceipt == plan.IntentReceipt &&
		attempt.IntentSequence == plan.IntentSequence && attempt.Sequence == operation.Sequence
}

func (guard *Guard) observeBoundTarget(ctx context.Context, fingerprint string, action HardwareAction) (Observation, error) {
	observation, hardwareErr := guard.hardware.Observe(ctx, guard.config, action)
	transitionErr := guard.validateBootTransitionOutcome(action, observation.BootTransition, hardwareErr == nil)
	if transitionErr != nil {
		return Observation{}, errors.Join(fmt.Errorf("observe lane target boot transition: %w", transitionErr), hardwareErr)
	}
	if hardwareErr != nil {
		return observation, fmt.Errorf("observe lane target: %w", hardwareErr)
	}
	if observation.EligibleTargets != 1 || observation.RPIBootSysfsPath != guard.config.RPIBootSysfsPath || observation.TargetFingerprint != fingerprint {
		return observation, ErrTargetContinuity
	}
	return observation, nil
}

func (guard *Guard) validateBootTransitionOutcome(action HardwareAction, outcome BootTransitionOutcome, completed bool) error {
	if err := outcome.ValidateForAction(action); err != nil {
		return fmt.Errorf("%w: %v", ErrBootTransitionOutcome, err)
	}
	if (outcome.Reference.Status == BootTransitionCompleted) != completed {
		return fmt.Errorf("%w: terminal status does not match the hardware return", ErrBootTransitionOutcome)
	}
	transition, found, err := guard.store.GetBootTransition(outcome.Reference.TransitionKey)
	if err != nil {
		return fmt.Errorf("%w: read durable transition: %v", ErrBootTransitionOutcome, err)
	}
	if !found {
		return fmt.Errorf("%w: referenced transition is not durable", ErrBootTransitionOutcome)
	}
	durable, err := transition.Outcome()
	if err != nil {
		return fmt.Errorf("%w: invalid durable transition: %v", ErrBootTransitionOutcome, err)
	}
	if durable != outcome {
		return fmt.Errorf("%w: returned outcome differs from the durable transition", ErrBootTransitionOutcome)
	}
	return nil
}

func makeHardwareAction(plan Plan, operation OperationSpec, phase HardwarePhase, claim *ReconciliationClaim) (HardwareAction, error) {
	action := HardwareAction{
		SchemaVersion: BootTransitionActionSchemaVersion,
		StationID:     plan.StationID, LaneID: plan.LaneID, TransactionID: plan.TransactionID,
		PlanDigest: plan.PlanDigest, TargetFingerprint: plan.TargetFingerprint, FenceEpoch: plan.FenceEpoch,
		ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt, IntentSequence: plan.IntentSequence,
		Sequence: operation.Sequence, Operation: operation.Operation, OperationDigest: operation.OperationDigest,
		AuthorizationID: operation.AuthorizationID, Phase: phase,
		OperationRequiredBootMode: operation.RequiredBootMode, RequestedBootMode: BootModeRPIBoot,
	}
	if phase == HardwarePhaseExecute {
		action.RequestedBootMode = operation.RequiredBootMode
	}
	if phase == HardwarePhaseReconciliation {
		if claim == nil {
			return HardwareAction{}, errors.New("reconciliation hardware action requires a current claim")
		}
		action.StationID = claim.StationID
		action.LaneID = claim.LaneID
		action.ReconciliationClaimID = claim.ClaimID
		action.ReconciliationFenceEpoch = claim.FenceEpoch
	} else if claim != nil {
		return HardwareAction{}, errors.New("non-reconciliation hardware action must not carry a claim")
	}
	if err := action.Validate(); err != nil {
		return HardwareAction{}, fmt.Errorf("derive hardware action: %w", err)
	}
	return action, nil
}

func attemptKey(plan Plan, sequence uint32) string {
	return AttemptJournalKey(plan, sequence)
}

// AttemptJournalKey is the single deterministic identity used by the guard's
// execute-once journal and by its immutable receipt publisher.
func AttemptJournalKey(plan Plan, sequence uint32) string {
	return fmt.Sprintf("%s/%s/%d/%d", plan.TransactionID, plan.PlanDigest, plan.FenceEpoch, sequence)
}

func clonePlan(plan Plan) Plan {
	copy := plan
	copy.Operations = append([]OperationSpec(nil), plan.Operations...)
	return copy
}

func samePlan(left, right Plan) bool {
	if left.SchemaVersion != right.SchemaVersion || left.StationID != right.StationID || left.LaneID != right.LaneID || left.TransactionID != right.TransactionID || left.PlanDigest != right.PlanDigest || left.Release != right.Release || left.TargetFingerprint != right.TargetFingerprint || left.FenceEpoch != right.FenceEpoch || left.ApprovalID != right.ApprovalID || !left.ApprovalExpiresAt.Equal(right.ApprovalExpiresAt) || left.IntentReceipt != right.IntentReceipt || left.IntentSequence != right.IntentSequence || len(left.Operations) != len(right.Operations) {
		return false
	}
	for index := range left.Operations {
		if left.Operations[index] != right.Operations[index] {
			return false
		}
	}
	return true
}
