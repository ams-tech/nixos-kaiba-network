package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

var ErrIdempotencyConflict = errors.New("signing request idempotency conflict")

// Signer is the approval-bound signing service interface exposed to artifact
// preparation. Implementations receive bytes, never caller-selected paths.
type Signer interface {
	Sign(context.Context, Request, []byte) (Result, error)
}

// Backend is the narrow private-key operation used only after Service has
// validated the request, artifact digest, idempotency key, and approval.
type Backend interface {
	Sign(context.Context, Algorithm, []byte) ([]byte, error)
}

// ApprovalVerifier authenticates the approval receipt and checks its current
// validity. A Service refuses to start without one.
type ApprovalVerifier interface {
	VerifyApproval(context.Context, ApprovalBinding) error
}

// StoredResult is the durable idempotency record. Production stores must make
// Save atomic and reject replacement of an existing request ID.
type StoredResult struct {
	RequestDigest bundle.Digest
	Result        Result
}

// ResultStore abstracts the durable signer receipt store.
type ResultStore interface {
	Lookup(context.Context, string) (StoredResult, bool, error)
	Save(context.Context, string, StoredResult) error
}

// Service validates and coordinates one approval-gated signing boundary. The
// mutex makes a single process race-free; the ResultStore remains responsible
// for cross-process atomicity in a production deployment.
type Service struct {
	policy   YubiKeyPolicy
	backend  Backend
	verifier ApprovalVerifier
	store    ResultStore
	mu       sync.Mutex
}

func NewService(policy YubiKeyPolicy, backend Backend, verifier ApprovalVerifier, store ResultStore) (*Service, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("signer policy: %w", err)
	}
	if backend == nil || verifier == nil || store == nil {
		return nil, errors.New("signing service requires a backend, approval verifier, and result store")
	}
	return &Service{policy: policy, backend: backend, verifier: verifier, store: store}, nil
}

func (s *Service) Sign(ctx context.Context, request Request, artifact []byte) (Result, error) {
	if err := request.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate signing request: %w", err)
	}
	if len(artifact) == 0 || len(artifact) > MaxArtifactBytes {
		return Result{}, fmt.Errorf("artifact size must be between 1 and %d bytes", MaxArtifactBytes)
	}
	if actual := bundle.Sum(artifact); actual != request.ArtifactDigest {
		return Result{}, fmt.Errorf("artifact digest %s does not match approved digest %s", actual, request.ArtifactDigest)
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return Result{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, found, err := s.store.Lookup(ctx, request.RequestID)
	if err != nil {
		return Result{}, fmt.Errorf("lookup signing receipt: %w", err)
	}
	if found {
		if stored.RequestDigest != requestDigest {
			return Result{}, ErrIdempotencyConflict
		}
		return stored.Result, nil
	}
	if err := s.verifier.VerifyApproval(ctx, request.Approval); err != nil {
		return Result{}, fmt.Errorf("verify signing approval: %w", err)
	}
	signature, err := s.backend.Sign(ctx, request.Algorithm, append([]byte(nil), artifact...))
	if err != nil {
		return Result{}, fmt.Errorf("sign approved artifact: %w", err)
	}
	if len(signature) != RSASignatureBytes {
		return Result{}, fmt.Errorf("signer returned %d signature bytes, want %d", len(signature), RSASignatureBytes)
	}
	policyDigest, err := s.policy.Digest()
	if err != nil {
		return Result{}, err
	}
	result := Result{
		SchemaVersion:       ResultSchemaV1Alpha2,
		RequestID:           request.RequestID,
		RequestDigest:       requestDigest,
		Role:                request.Role,
		ArtifactDigest:      request.ArtifactDigest,
		Algorithm:           request.Algorithm,
		SignatureHex:        hex.EncodeToString(signature),
		SignatureDigest:     bundle.Sum(signature),
		SignerPolicyDigest:  policyDigest,
		ReleaseIntentDigest: request.Approval.ReleaseIntentDigest,
	}
	stored = StoredResult{RequestDigest: requestDigest, Result: result}
	if err := s.store.Save(ctx, request.RequestID, stored); err != nil {
		return Result{}, fmt.Errorf("save signing receipt: %w", err)
	}
	return result, nil
}

// MemoryResultStore is deterministic test/development storage. It is not a
// substitute for the full-durability store required on the control host.
type MemoryResultStore struct {
	mu      sync.Mutex
	results map[string]StoredResult
}

func NewMemoryResultStore() *MemoryResultStore {
	return &MemoryResultStore{results: make(map[string]StoredResult)}
}

func (s *MemoryResultStore) Lookup(_ context.Context, requestID string) (StoredResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.results[requestID]
	return result, ok, nil
}

func (s *MemoryResultStore) Save(_ context.Context, requestID string, result StoredResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.results[requestID]; ok {
		if existing.RequestDigest != result.RequestDigest {
			return ErrIdempotencyConflict
		}
		return nil
	}
	s.results[requestID] = result
	return nil
}
