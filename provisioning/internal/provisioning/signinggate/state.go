package signinggate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	StateSchemaV1Alpha1   = "kaiba.provisioning.signing-gate-state/v1alpha1"
	ReceiptSchemaV1Alpha1 = "kaiba.provisioning.signing-gate-receipt/v1alpha1"
	StateIntent           = "intent"
	StateComplete         = "complete"
	maxStateBytes         = 128 * 1024
)

// Receipt permanently binds the returned signature to the complete grant and
// the fixed backend identity used by the daemon.
type Receipt struct {
	SchemaVersion   string        `json:"schema_version"`
	Grant           Grant         `json:"grant"`
	RequestDigest   bundle.Digest `json:"request_digest"`
	BackendID       string        `json:"backend_id"`
	SignatureHex    string        `json:"signature_hex"`
	SignatureDigest bundle.Digest `json:"signature_digest"`
	SignedAt        string        `json:"signed_at"`
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != ReceiptSchemaV1Alpha1 {
		return fmt.Errorf("unsupported receipt schema_version %q", r.SchemaVersion)
	}
	if err := r.Grant.Validate(); err != nil {
		return fmt.Errorf("receipt grant: %w", err)
	}
	requestDigest, err := r.Grant.Request.Digest()
	if err != nil {
		return err
	}
	if r.RequestDigest != requestDigest {
		return errors.New("receipt request_digest does not match its grant")
	}
	if !grantIdentifierPattern.MatchString(r.BackendID) {
		return errors.New("receipt backend_id must be a canonical lower-case identifier")
	}
	signature, err := signing.ParseSignatureHex([]byte(r.SignatureHex))
	if err != nil {
		return fmt.Errorf("receipt signature_hex: %w", err)
	}
	if hex.EncodeToString(signature) != r.SignatureHex {
		return errors.New("receipt signature_hex is not canonical lowercase hexadecimal")
	}
	if r.SignatureDigest != bundle.Sum(signature) {
		return errors.New("receipt signature_digest does not match signature_hex")
	}
	if !expiryPattern.MatchString(r.SignedAt) {
		return errors.New("receipt signed_at must use canonical UTC RFC3339 seconds")
	}
	if _, err := time.Parse(time.RFC3339, r.SignedAt); err != nil {
		return errors.New("receipt signed_at must use canonical UTC RFC3339 seconds")
	}
	return nil
}

func (r Receipt) Digest() (bundle.Digest, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.signing-gate-receipt.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

type DurableState struct {
	SchemaVersion  string        `json:"schema_version"`
	Status         string        `json:"status"`
	GrantID        string        `json:"grant_id"`
	RequestDigest  bundle.Digest `json:"request_digest"`
	ArtifactDigest bundle.Digest `json:"artifact_digest"`
	IntentAt       string        `json:"intent_at"`
	Receipt        *Receipt      `json:"receipt,omitempty"`
}

func (s DurableState) validateFor(grant Grant) error {
	if s.SchemaVersion != StateSchemaV1Alpha1 {
		return fmt.Errorf("unsupported durable state schema_version %q", s.SchemaVersion)
	}
	if s.GrantID != grant.GrantID {
		return errors.New("durable state grant_id does not match registry grant")
	}
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		return err
	}
	if s.RequestDigest != requestDigest || s.ArtifactDigest != grant.Request.ArtifactDigest {
		return errors.New("durable state conflicts with the registry grant")
	}
	if !expiryPattern.MatchString(s.IntentAt) {
		return errors.New("durable state intent_at must use canonical UTC RFC3339 seconds")
	}
	if _, err := time.Parse(time.RFC3339, s.IntentAt); err != nil {
		return errors.New("durable state intent_at must use canonical UTC RFC3339 seconds")
	}
	switch s.Status {
	case StateIntent:
		if s.Receipt != nil {
			return errors.New("intent state must not contain a receipt")
		}
	case StateComplete:
		if s.Receipt == nil {
			return errors.New("complete state must contain a receipt")
		}
		if err := s.Receipt.Validate(); err != nil {
			return err
		}
		if s.Receipt.Grant.GrantID != grant.GrantID || s.Receipt.RequestDigest != requestDigest {
			return errors.New("durable receipt conflicts with registry grant")
		}
	default:
		return fmt.Errorf("unsupported durable state status %q", s.Status)
	}
	return nil
}

// StateStore persists one atomic state file per grant and holds a process- and
// host-wide lock across grant selection, intent, key use, and completion.
type StateStore struct {
	directory string
	ownerUID  uint32
	lockFile  *os.File
	processMu sync.Mutex
}

func OpenStateStore(directory string, ownerUID uint32) (*StateStore, error) {
	if err := validateManagedDirectory(directory, ownerUID, true); err != nil {
		return nil, fmt.Errorf("open signing state directory: %w", err)
	}
	lockPath := filepath.Join(directory, ".gate.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open signing state lock: %w", err)
	}
	info, err := lockFile.Stat()
	if err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = lockFile.Close()
		return nil, errors.New("signing state lock has unsafe type or permissions")
	}
	if err := requireOwner(info, ownerUID); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	return &StateStore{directory: directory, ownerUID: ownerUID, lockFile: lockFile}, nil
}

func (s *StateStore) Close() error {
	if s == nil || s.lockFile == nil {
		return nil
	}
	return s.lockFile.Close()
}

func (s *StateStore) withExclusive(ctx context.Context, operation func() error) error {
	s.processMu.Lock()
	defer s.processMu.Unlock()
	for {
		err := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("lock signing state: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	return operation()
}

func (s *StateStore) Load(grant Grant) (DurableState, bool, error) {
	path := s.statePath(grant.GrantID)
	data, err := readStateFile(path, s.ownerUID)
	if errors.Is(err, os.ErrNotExist) {
		return DurableState{}, false, nil
	}
	if err != nil {
		return DurableState{}, false, err
	}
	var state DurableState
	if err := strictDecode(data, &state); err != nil {
		return DurableState{}, false, fmt.Errorf("decode signing state: %w", err)
	}
	if err := state.validateFor(grant); err != nil {
		return DurableState{}, false, err
	}
	return state, true, nil
}

func (s *StateStore) RecordIntent(grant Grant, now time.Time) (DurableState, error) {
	if state, found, err := s.Load(grant); err != nil {
		return DurableState{}, err
	} else if found {
		return state, nil
	}
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		return DurableState{}, err
	}
	state := DurableState{
		SchemaVersion:  StateSchemaV1Alpha1,
		Status:         StateIntent,
		GrantID:        grant.GrantID,
		RequestDigest:  requestDigest,
		ArtifactDigest: grant.Request.ArtifactDigest,
		IntentAt:       canonicalTime(now),
	}
	if err := s.write(state); err != nil {
		return DurableState{}, err
	}
	return state, nil
}

func (s *StateStore) RecordComplete(grant Grant, intent DurableState, receipt Receipt) (DurableState, error) {
	if intent.Status != StateIntent {
		return DurableState{}, errors.New("signing completion requires a durable intent")
	}
	if err := intent.validateFor(grant); err != nil {
		return DurableState{}, err
	}
	complete := intent
	complete.Status = StateComplete
	complete.Receipt = &receipt
	if err := complete.validateFor(grant); err != nil {
		return DurableState{}, err
	}
	if err := s.write(complete); err != nil {
		return DurableState{}, err
	}
	return complete, nil
}

func (s *StateStore) statePath(grantID string) string {
	digest := sha256.Sum256([]byte("kaiba.provisioning.signing-grant-state.v1\x00" + grantID))
	return filepath.Join(s.directory, hex.EncodeToString(digest[:])+".json")
}

func (s *StateStore) write(state DurableState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(s.directory, ".state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.statePath(state.GrantID)); err != nil {
		return err
	}
	removeTemporary = false
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}

func readStateFile(path string, ownerUID uint32) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signing state file has unsafe type or permissions")
	}
	if err := requireOwner(info, ownerUID); err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > maxStateBytes {
		return nil, errors.New("signing state file has invalid size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("signing state changed while opening")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

func canonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func canonicalSignature(signature []byte) (string, error) {
	if len(signature) != signing.RSASignatureBytes {
		return "", fmt.Errorf("backend returned %d signature bytes, want %d", len(signature), signing.RSASignatureBytes)
	}
	return strings.ToLower(hex.EncodeToString(signature)), nil
}
