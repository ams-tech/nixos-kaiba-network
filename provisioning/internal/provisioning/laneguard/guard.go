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

// Hardware is the only component allowed to translate a typed operation into
// target-facing behavior. Implementations must use Config's fixed resources
// and build-time-pinned artifacts.
type Hardware interface {
	Observe(context.Context, Config) (Observation, error)
	Execute(context.Context, Config, Operation) (OperationResult, error)
}

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Guard struct {
	mu        sync.Mutex
	config    Config
	hardware  Hardware
	store     AttemptStore
	clock     Clock
	plan      *Plan
	lockedOut bool
}

func New(config Config, hardware Hardware, store AttemptStore) (*Guard, error) {
	return NewWithClock(config, hardware, store, systemClock{})
}

func NewWithClock(config Config, hardware Hardware, store AttemptStore, clock Clock) (*Guard, error) {
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
	config.SchemaVersion = ContractSchemaVersion
	return &Guard{config: config, hardware: hardware, store: store, clock: clock}, nil
}

// LoadPlan binds this guard instance to one approved plan. A different plan,
// target, transaction, or epoch requires a fresh guard after lane teardown.
func (guard *Guard) LoadPlan(ctx context.Context, plan Plan) error {
	// Freeze caller-owned slice storage before validation so the body that is
	// checked is exactly the body retained after target observation.
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
	expectedStates, lockedOut, err := guard.restartStates(plan)
	if err != nil {
		return err
	}
	observation, err := guard.observeBoundTarget(ctx, plan.TargetFingerprint)
	if err != nil {
		return err
	}
	if !stateAllowed(observation.State, expectedStates) {
		return ErrPrestateMismatch
	}
	guard.plan = &plan
	guard.lockedOut = lockedOut
	return nil
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
	if remaining := request.ClaimExpiresAt.Sub(current); remaining < operation.MaximumDuration+guard.config.LeaseSafetyMargin {
		return Attempt{}, ErrLeaseInvalid
	}
	key := attemptKey(plan, operation.Sequence)
	existing, found, err := guard.store.Get(key)
	if err != nil {
		return Attempt{}, fmt.Errorf("read execute-once journal: %w", err)
	}
	if found {
		switch existing.Status {
		case AttemptVerified:
			return existing, nil
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
	observation, err := guard.observeBoundTarget(ctx, plan.TargetFingerprint)
	if err != nil {
		return Attempt{}, err
	}
	if observation.State != operation.ExpectedPrestate {
		return Attempt{}, ErrPrestateMismatch
	}
	now := guard.clock.Now().UTC()
	attempt := Attempt{
		SchemaVersion: ContractSchemaVersion, Key: key,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest,
		TargetFingerprint: plan.TargetFingerprint, FenceEpoch: plan.FenceEpoch,
		Sequence: operation.Sequence, Operation: operation.Operation,
		OperationDigest: operation.OperationDigest, Status: AttemptStarted,
		StartedAt: now, UpdatedAt: now, ObservedState: observation.State,
		Detail: "durable intent recorded before hardware execution",
	}
	if err := guard.store.Put(attempt); err != nil {
		return Attempt{}, fmt.Errorf("record execute-once intent: %w", err)
	}
	result, executeErr := guard.hardware.Execute(ctx, guard.config, operation.Operation)
	if executeErr != nil {
		attempt.Status = AttemptUncertain
		attempt.UpdatedAt = guard.clock.Now().UTC()
		attempt.Detail = "hardware call returned without an authoritative postcondition"
		if storeErr := guard.store.Put(attempt); storeErr != nil {
			return attempt, errors.Join(ErrReconciliationRequired, executeErr, fmt.Errorf("record uncertain outcome: %w", storeErr))
		}
		return attempt, errors.Join(ErrReconciliationRequired, executeErr)
	}
	attempt.Result = bindOperationResult(plan, operation, result)
	postObservation, observeErr := guard.observeBoundTarget(ctx, plan.TargetFingerprint)
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
func (guard *Guard) Reconcile(ctx context.Context, request ExecuteRequest) (Attempt, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	plan, operation, err := guard.matchRequest(request)
	if err != nil {
		return Attempt{}, err
	}
	key := attemptKey(plan, operation.Sequence)
	attempt, found, err := guard.store.Get(key)
	if err != nil {
		return Attempt{}, fmt.Errorf("read execute-once journal: %w", err)
	}
	if !found {
		return Attempt{}, errors.New("no operation attempt exists to reconcile")
	}
	switch attempt.Status {
	case AttemptVerified:
		return attempt, nil
	case AttemptQuarantined:
		return attempt, ErrQuarantined
	case AttemptStarted, AttemptUncertain:
	default:
		return Attempt{}, errors.New("attempt journal has an invalid status")
	}
	observation, err := guard.observeBoundTarget(ctx, plan.TargetFingerprint)
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

func matchPlanRequest(plan Plan, request ExecuteRequest) (OperationSpec, error) {
	if request.SchemaVersion != ContractSchemaVersion ||
		request.StationID != plan.StationID || request.LaneID != plan.LaneID ||
		request.TransactionID != plan.TransactionID || request.PlanDigest != plan.PlanDigest ||
		request.Release != plan.Release ||
		request.TargetFingerprint != plan.TargetFingerprint || request.FenceEpoch != plan.FenceEpoch ||
		request.ApprovalID != plan.ApprovalID || !request.ApprovalExpiresAt.Equal(plan.ApprovalExpiresAt) ||
		request.IntentReceipt != plan.IntentReceipt ||
		request.Sequence == 0 || int(request.Sequence) > len(plan.Operations) {
		return OperationSpec{}, ErrPlanMismatch
	}
	operation := plan.Operations[request.Sequence-1]
	if request.OperationDigest != operation.OperationDigest || request.AuthorizationID != operation.AuthorizationID || request.ExpectedPrestate != operation.ExpectedPrestate {
		return OperationSpec{}, ErrPlanMismatch
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
		if attempt.TransactionID != plan.TransactionID || attempt.PlanDigest != plan.PlanDigest ||
			attempt.TargetFingerprint != plan.TargetFingerprint || attempt.FenceEpoch != plan.FenceEpoch ||
			attempt.Sequence != operation.Sequence || attempt.Operation != operation.Operation ||
			attempt.OperationDigest != operation.OperationDigest {
			return nil, false, ErrPlanMismatch
		}
		switch attempt.Status {
		case AttemptVerified:
			expected = []DirectState{operation.ExpectedPoststate}
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

func stateAllowed(actual DirectState, expected []DirectState) bool {
	for _, candidate := range expected {
		if actual == candidate {
			return true
		}
	}
	return false
}

func (guard *Guard) observeBoundTarget(ctx context.Context, fingerprint string) (Observation, error) {
	observation, err := guard.hardware.Observe(ctx, guard.config)
	if err != nil {
		return Observation{}, fmt.Errorf("observe lane target: %w", err)
	}
	if observation.EligibleTargets != 1 || observation.RPIBootSysfsPath != guard.config.RPIBootSysfsPath || observation.TargetFingerprint != fingerprint {
		return Observation{}, ErrTargetContinuity
	}
	return observation, nil
}

func attemptKey(plan Plan, sequence uint32) string {
	return fmt.Sprintf("%s/%s/%d/%d", plan.TransactionID, plan.PlanDigest, plan.FenceEpoch, sequence)
}

func clonePlan(plan Plan) Plan {
	copy := plan
	copy.Operations = append([]OperationSpec(nil), plan.Operations...)
	return copy
}

func samePlan(left, right Plan) bool {
	if left.SchemaVersion != right.SchemaVersion || left.StationID != right.StationID || left.LaneID != right.LaneID || left.TransactionID != right.TransactionID || left.PlanDigest != right.PlanDigest || left.Release != right.Release || left.TargetFingerprint != right.TargetFingerprint || left.FenceEpoch != right.FenceEpoch || left.ApprovalID != right.ApprovalID || !left.ApprovalExpiresAt.Equal(right.ApprovalExpiresAt) || left.IntentReceipt != right.IntentReceipt || len(left.Operations) != len(right.Operations) {
		return false
	}
	for index := range left.Operations {
		if left.Operations[index] != right.Operations[index] {
			return false
		}
	}
	return true
}
