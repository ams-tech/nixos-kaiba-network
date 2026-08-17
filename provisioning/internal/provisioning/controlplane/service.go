package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid             = errors.New("invalid control-plane request")
	ErrNotFound            = errors.New("transaction not found")
	ErrConflict            = errors.New("control-plane resource conflict")
	ErrVersionConflict     = errors.New("unexpected resource version")
	ErrIdempotencyConflict = errors.New("idempotency key was reused with different input")
	ErrStaleFence          = errors.New("stale claim or fence epoch")
	ErrLeaseExpired        = errors.New("claim lease expired")
	ErrIllegalTransition   = errors.New("illegal transaction transition")
	ErrCorruptStore        = errors.New("control-plane store integrity check failed")
)

const (
	minimumLease            = 30 * time.Second
	maximumLease            = time.Hour
	maximumApprovalLifetime = 24 * time.Hour
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type Option func(*Service)

func WithClock(clock func() time.Time) Option {
	return func(service *Service) { service.clock = clock }
}

func WithIDGenerator(generator func(string) (string, error)) Option {
	return func(service *Service) { service.newID = generator }
}

type Service struct {
	mu    sync.Mutex
	store Store
	state persistedState
	clock func() time.Time
	newID func(string) (string, error)
}

func NewService(store Store, options ...Option) (*Service, error) {
	if store == nil {
		return nil, invalid("store is required")
	}
	service := &Service{
		store: store,
		state: persistedState{
			SchemaVersion: StoreSchemaVersion,
			Transactions:  make(map[string]Transaction),
			FenceEpochs:   make(map[string]uint64),
			Idempotency:   make(map[string]idempotencyRecord),
		},
		clock: time.Now,
		newID: randomID,
	}
	for _, option := range options {
		option(service)
	}
	if service.clock == nil || service.newID == nil {
		return nil, invalid("clock and ID generator are required")
	}
	data, err := store.Load()
	if errors.Is(err, ErrStoreNotFound) {
		return service, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedState
	if err := DecodeStrict(data, &state); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptStore, err)
	}
	if err := validatePersistedState(state); err != nil {
		return nil, err
	}
	service.state = state
	return service, nil
}

func (s *Service) GetTransaction(_ context.Context, transactionID string) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	transaction, exists := s.state.Transactions[transactionID]
	if !exists {
		return Transaction{}, ErrNotFound
	}
	return cloneTransaction(transaction)
}

// GetTransactionForReconciliation is deliberately read-only. Acquiring a
// reconciliation claim is a separate explicit operation and grants no mutation
// authority over the target.
func (s *Service) GetTransactionForReconciliation(ctx context.Context, transactionID string) (Transaction, error) {
	return s.GetTransaction(ctx, transactionID)
}

func (s *Service) CreateTransaction(_ context.Context, request CreateTransactionRequest) (Transaction, error) {
	if err := validateCreateRequest(request); err != nil {
		return Transaction{}, err
	}
	requestDigest, err := digestJSON(request)
	if err != nil {
		return Transaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if replay, err := s.replayLocked("create_transaction", request.IdempotencyKey, requestDigest); replay != nil || err != nil {
		if err != nil {
			return Transaction{}, err
		}
		return cloneTransaction(*replay)
	}
	if _, exists := s.state.Transactions[request.TransactionID]; exists {
		return Transaction{}, fmt.Errorf("%w: transaction_id already exists", ErrConflict)
	}
	for _, existing := range s.state.Transactions {
		if existing.AssetID == request.AssetID || existing.IntendedLogicalID == request.IntendedLogicalID {
			return Transaction{}, fmt.Errorf("%w: asset_id or intended_logical_id is already reserved", ErrConflict)
		}
	}
	now := s.clock().UTC()
	transaction := Transaction{
		SchemaVersion: TransactionSchemaVersion, ID: request.TransactionID,
		ResourceVersion: 1, Status: StatusCreated, AssetID: request.AssetID,
		IntendedLogicalID: request.IntendedLogicalID, ProfileID: request.ProfileID,
		BundleDigest: request.BundleDigest, PolicyDigest: request.PolicyDigest,
		ExpectedPrestateCustomerKeyHash: request.ExpectedPrestateCustomerKeyHash,
		ExpectedCustomerKeyHash:         request.ExpectedCustomerKeyHash,
		ClaimHistory:                    []Claim{}, Operations: []OperationRecord{}, CreatedAt: now, UpdatedAt: now,
	}
	transaction.TransactionDigest, err = transactionDigest(transaction)
	if err != nil {
		return Transaction{}, err
	}
	candidate, err := cloneState(s.state)
	if err != nil {
		return Transaction{}, err
	}
	candidate.Transactions[transaction.ID] = transaction
	candidate.Idempotency[request.IdempotencyKey] = idempotencyRecord{
		Operation: "create_transaction", RequestDigest: requestDigest, TransactionID: transaction.ID,
	}
	if err := s.commitLocked(candidate); err != nil {
		return Transaction{}, err
	}
	return cloneTransaction(transaction)
}

func (s *Service) AcquireClaim(_ context.Context, request AcquireClaimRequest) (Transaction, error) {
	if err := validateAcquireClaimRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("acquire_claim", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, state *persistedState, transaction *Transaction) error {
		if transaction.ActiveClaim != nil && transaction.ActiveClaim.Status == ClaimActive && transaction.ActiveClaim.ExpiresAt.After(now) {
			return fmt.Errorf("%w: transaction already has an active claim", ErrConflict)
		}
		if err := validateClaimModeForStatus(request.Mode, transaction.Status); err != nil {
			return err
		}
		if err := ensureClaimResourcesAvailable(*state, transaction.ID, request.StationID, request.LaneID, transaction.AssetID, now); err != nil {
			return err
		}
		if transaction.ActiveClaim != nil {
			closed := *transaction.ActiveClaim
			closed.Status = ClaimExpired
			closedAt := now
			closed.ClosedAt = &closedAt
			transaction.ClaimHistory = append(transaction.ClaimHistory, closed)
			transaction.ActiveClaim = nil
		}
		claimID, err := s.newID("claim")
		if err != nil {
			return fmt.Errorf("generate claim ID: %w", err)
		}
		epoch := state.FenceEpochs[transaction.AssetID] + 1
		state.FenceEpochs[transaction.AssetID] = epoch
		transaction.FenceEpoch = epoch
		transaction.ActiveClaim = &Claim{
			ID: claimID, Mode: request.Mode, Status: ClaimActive,
			StationID: request.StationID, LaneID: request.LaneID, AssetID: transaction.AssetID,
			FenceEpoch: epoch, AllowedStages: append([]string(nil), request.AllowedStages...),
			AcquiredAt: now, ExpiresAt: now.Add(time.Duration(request.LeaseDurationSeconds) * time.Second),
		}
		transaction.Approval = nil
		if request.Mode == ClaimModeReconciliation && transaction.Status == StatusMutationInProgress {
			transaction.Status = StatusReconciliationRequired
		} else if transaction.Status != StatusQuarantined && transaction.Status != StatusReconciliationRequired {
			if transaction.Target == nil {
				transaction.Status = StatusClaimed
			} else if request.Mode == ClaimModeMutation {
				transaction.Status = StatusTargetBound
			}
		}
		return nil
	})
}

func (s *Service) RenewClaim(_ context.Context, request RenewClaimRequest) (Transaction, error) {
	if err := validateRenewClaimRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("renew_claim", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, "")
		if err != nil {
			return err
		}
		claim.ExpiresAt = now.Add(time.Duration(request.LeaseDurationSeconds) * time.Second)
		return nil
	})
}

func (s *Service) TransferClaim(_ context.Context, request TransferClaimRequest) (Transaction, error) {
	if err := validateTransferClaimRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("transfer_claim", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, state *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, "")
		if err != nil {
			return err
		}
		if transaction.Status == StatusMutationInProgress && request.Mode != ClaimModeReconciliation {
			return fmt.Errorf("%w: an in-flight mutation must be reconciled before claim transfer", ErrIllegalTransition)
		}
		if err := validateClaimModeForStatus(request.Mode, transaction.Status); err != nil {
			return err
		}
		if err := ensureClaimResourcesAvailable(*state, transaction.ID, request.NewStationID, request.NewLaneID, transaction.AssetID, now); err != nil {
			return err
		}
		closed := *claim
		closed.Status = ClaimTransferred
		closedAt := now
		closed.ClosedAt = &closedAt
		transaction.ClaimHistory = append(transaction.ClaimHistory, closed)
		claimID, err := s.newID("claim")
		if err != nil {
			return fmt.Errorf("generate claim ID: %w", err)
		}
		epoch := state.FenceEpochs[transaction.AssetID] + 1
		state.FenceEpochs[transaction.AssetID] = epoch
		transaction.FenceEpoch = epoch
		transaction.ActiveClaim = &Claim{
			ID: claimID, Mode: request.Mode, Status: ClaimActive,
			StationID: request.NewStationID, LaneID: request.NewLaneID, AssetID: transaction.AssetID,
			FenceEpoch: epoch, AllowedStages: append([]string(nil), request.AllowedStages...),
			AcquiredAt: now, ExpiresAt: now.Add(time.Duration(request.LeaseDurationSeconds) * time.Second),
		}
		transaction.Approval = nil
		if request.Mode == ClaimModeReconciliation && transaction.Status == StatusMutationInProgress {
			transaction.Status = StatusReconciliationRequired
		} else if transaction.Status != StatusQuarantined && transaction.Status != StatusReconciliationRequired {
			if transaction.Target == nil {
				transaction.Status = StatusClaimed
			} else if request.Mode == ClaimModeMutation {
				transaction.Status = StatusTargetBound
			}
		}
		return nil
	})
}

func (s *Service) ReleaseClaim(_ context.Context, request ReleaseClaimRequest) (Transaction, error) {
	if err := validateReleaseClaimRequest(request); err != nil {
		return Transaction{}, err
	}
	return s.mutate("release_claim", request.IdempotencyKey, request.TransactionID, request.ExpectedResourceVersion, request, func(now time.Time, _ *persistedState, transaction *Transaction) error {
		claim, err := requireCurrentClaim(transaction, request.ClaimID, request.FenceEpoch, now, "")
		if err != nil {
			return err
		}
		switch transaction.Status {
		case StatusSecurityApplied, StatusQuarantined, StatusAborted:
		default:
			return fmt.Errorf("%w: claims may be released only after security_applied, quarantine, or proven clean abort", ErrIllegalTransition)
		}
		closed := *claim
		closed.Status = ClaimReleased
		closedAt := now
		closed.ClosedAt = &closedAt
		transaction.ClaimHistory = append(transaction.ClaimHistory, closed)
		transaction.ActiveClaim = nil
		return nil
	})
}

func (s *Service) replayLocked(operation, key, requestDigest string) (*Transaction, error) {
	record, exists := s.state.Idempotency[key]
	if !exists {
		return nil, nil
	}
	if record.Operation != operation || record.RequestDigest != requestDigest {
		return nil, ErrIdempotencyConflict
	}
	transaction, exists := s.state.Transactions[record.TransactionID]
	if !exists {
		return nil, fmt.Errorf("%w: idempotency index references a missing transaction", ErrCorruptStore)
	}
	return &transaction, nil
}

type mutateFunc func(time.Time, *persistedState, *Transaction) error

func (s *Service) mutate(operation, key, transactionID string, expectedVersion uint64, request any, apply mutateFunc) (Transaction, error) {
	requestDigest, err := digestJSON(request)
	if err != nil {
		return Transaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if replay, err := s.replayLocked(operation, key, requestDigest); replay != nil || err != nil {
		if err != nil {
			return Transaction{}, err
		}
		return cloneTransaction(*replay)
	}
	current, exists := s.state.Transactions[transactionID]
	if !exists {
		return Transaction{}, ErrNotFound
	}
	if expectedVersion == 0 || current.ResourceVersion != expectedVersion {
		return Transaction{}, fmt.Errorf("%w: got %d, want %d", ErrVersionConflict, expectedVersion, current.ResourceVersion)
	}
	candidate, err := cloneState(s.state)
	if err != nil {
		return Transaction{}, err
	}
	transaction := candidate.Transactions[transactionID]
	now := s.clock().UTC()
	if err := apply(now, &candidate, &transaction); err != nil {
		return Transaction{}, err
	}
	transaction.ResourceVersion++
	transaction.UpdatedAt = now
	candidate.Transactions[transactionID] = transaction
	candidate.Idempotency[key] = idempotencyRecord{Operation: operation, RequestDigest: requestDigest, TransactionID: transactionID}
	if err := s.commitLocked(candidate); err != nil {
		return Transaction{}, err
	}
	return cloneTransaction(transaction)
}

func (s *Service) commitLocked(candidate persistedState) error {
	if err := validatePersistedState(candidate); err != nil {
		return err
	}
	data, err := marshalState(candidate)
	if err != nil {
		return err
	}
	if err := s.store.Save(data); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func requireCurrentClaim(transaction *Transaction, claimID string, epoch uint64, now time.Time, mode ClaimMode) (*Claim, error) {
	claim := transaction.ActiveClaim
	if claim == nil || claim.Status != ClaimActive || claim.ID != claimID || claim.FenceEpoch != epoch || transaction.FenceEpoch != epoch {
		return nil, ErrStaleFence
	}
	if !claim.ExpiresAt.After(now) {
		return nil, ErrLeaseExpired
	}
	if mode != "" && claim.Mode != mode {
		return nil, fmt.Errorf("%w: claim mode %q does not authorize %q", ErrIllegalTransition, claim.Mode, mode)
	}
	return claim, nil
}

func ensureClaimResourcesAvailable(state persistedState, transactionID, stationID, laneID, assetID string, now time.Time) error {
	for id, transaction := range state.Transactions {
		if id == transactionID || transaction.ActiveClaim == nil || transaction.ActiveClaim.Status != ClaimActive || !transaction.ActiveClaim.ExpiresAt.After(now) {
			continue
		}
		claim := transaction.ActiveClaim
		if claim.AssetID == assetID || (claim.StationID == stationID && claim.LaneID == laneID) {
			return fmt.Errorf("%w: asset or station lane is already claimed", ErrConflict)
		}
	}
	return nil
}

func validateClaimModeForStatus(mode ClaimMode, status TransactionStatus) error {
	switch mode {
	case ClaimModeMutation:
		switch status {
		case StatusCreated, StatusClaimed, StatusTargetBound, StatusCommitApproved, StatusReconciled:
			return nil
		}
	case ClaimModeReconciliation:
		if status == StatusMutationInProgress || status == StatusReconciliationRequired || status == StatusQuarantined {
			return nil
		}
	}
	return fmt.Errorf("%w: claim mode %q is not allowed for status %q", ErrIllegalTransition, mode, status)
}

func randomID(prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(bytes), nil
}

type transactionDigestMaterial struct {
	ID                              string `json:"id"`
	AssetID                         string `json:"asset_id"`
	IntendedLogicalID               string `json:"intended_logical_id"`
	ProfileID                       string `json:"profile_id"`
	BundleDigest                    string `json:"bundle_digest"`
	PolicyDigest                    string `json:"policy_digest"`
	ExpectedPrestateCustomerKeyHash string `json:"expected_prestate_customer_key_hash"`
	ExpectedCustomerKeyHash         string `json:"expected_customer_key_hash"`
}

func transactionDigest(transaction Transaction) (string, error) {
	return digestJSON(transactionDigestMaterial{
		ID: transaction.ID, AssetID: transaction.AssetID,
		IntendedLogicalID: transaction.IntendedLogicalID, ProfileID: transaction.ProfileID,
		BundleDigest: transaction.BundleDigest, PolicyDigest: transaction.PolicyDigest,
		ExpectedPrestateCustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
		ExpectedCustomerKeyHash:         transaction.ExpectedCustomerKeyHash,
	})
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical control-plane value: %w", err)
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func invalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }
