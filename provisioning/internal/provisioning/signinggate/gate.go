package signinggate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

type GateConfig struct {
	Registry  Registry
	Store     *StateStore
	Backend   signing.Backend
	BackendID string
	Now       func() time.Time
}

type Result struct {
	SignatureHex        string
	ReceiptDigest       bundle.Digest
	ReleaseIntentDigest bundle.Digest
	GrantID             string
	Replayed            bool
}

// Gate is the only component allowed to invoke the fixed private-key backend.
// It resolves every authorization field from the root-managed registry using
// the daemon-computed artifact digest.
type Gate struct {
	registry  Registry
	store     *StateStore
	backend   signing.Backend
	backendID string
	now       func() time.Time
	mu        sync.Mutex
}

func NewGate(config GateConfig) (*Gate, error) {
	if err := config.Registry.Validate(); err != nil {
		return nil, err
	}
	if config.Store == nil || config.Backend == nil || config.Now == nil {
		return nil, errors.New("signing gate requires a state store, backend, and clock")
	}
	if !grantIdentifierPattern.MatchString(config.BackendID) {
		return nil, errors.New("backend_id must be a canonical lower-case identifier")
	}
	return &Gate{
		registry: config.Registry, store: config.Store, backend: config.Backend,
		backendID: config.BackendID, now: config.Now,
	}, nil
}

func (g *Gate) Sign(ctx context.Context, artifact []byte) (Result, error) {
	if len(artifact) == 0 || len(artifact) > signing.MaxArtifactBytes {
		return Result{}, fmt.Errorf("artifact size must be between 1 and %d bytes", signing.MaxArtifactBytes)
	}
	artifact = append([]byte(nil), artifact...)
	digest := bundle.Sum(artifact)

	g.mu.Lock()
	defer g.mu.Unlock()
	var result Result
	err := g.store.withExclusive(ctx, func() error {
		grant, err := g.registry.CurrentGrant(digest, g.now().UTC())
		if err != nil {
			return err
		}
		state, found, err := g.store.Load(grant)
		if err != nil {
			return err
		}
		if found && state.Status == StateComplete {
			receiptDigest, err := state.Receipt.Digest()
			if err != nil {
				return err
			}
			result = Result{
				SignatureHex: state.Receipt.SignatureHex, ReceiptDigest: receiptDigest,
				ReleaseIntentDigest: grant.Request.Approval.ReleaseIntentDigest,
				GrantID:             grant.GrantID, Replayed: true,
			}
			return nil
		}
		if !found {
			state, err = g.store.RecordIntent(grant, g.now().UTC())
			if err != nil {
				return fmt.Errorf("record signing intent: %w", err)
			}
		}
		if state.Status != StateIntent {
			return errors.New("signing state is neither replayable nor an intent")
		}
		signature, err := g.backend.Sign(ctx, signing.AlgorithmRSA2048SHA256, artifact)
		if err != nil {
			return fmt.Errorf("fixed signing backend: %w", err)
		}
		signatureHex, err := canonicalSignature(signature)
		if err != nil {
			return err
		}
		requestDigest, err := grant.Request.Digest()
		if err != nil {
			return err
		}
		receipt := Receipt{
			SchemaVersion: ReceiptSchemaV1Alpha2, Grant: grant, RequestDigest: requestDigest,
			BackendID: g.backendID, SignatureHex: signatureHex,
			SignatureDigest: bundle.Sum(signature), SignedAt: canonicalTime(g.now()),
		}
		complete, err := g.store.RecordComplete(grant, state, receipt)
		if err != nil {
			return fmt.Errorf("record signing completion: %w", err)
		}
		receiptDigest, err := complete.Receipt.Digest()
		if err != nil {
			return err
		}
		result = Result{
			SignatureHex: hex.EncodeToString(signature), ReceiptDigest: receiptDigest,
			ReleaseIntentDigest: grant.Request.Approval.ReleaseIntentDigest,
			GrantID:             grant.GrantID,
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}
