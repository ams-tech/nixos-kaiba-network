package laneguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AttemptStatus string

const (
	AttemptStarted     AttemptStatus = "started"
	AttemptUncertain   AttemptStatus = "uncertain"
	AttemptVerified    AttemptStatus = "verified"
	AttemptQuarantined AttemptStatus = "quarantined"
)

// Attempt is the durable execute-once record. Started is persisted before the
// hardware call, so a restart can only observe/reconcile that call, never
// repeat it.
type Attempt struct {
	SchemaVersion     string          `json:"schema_version"`
	Key               string          `json:"key"`
	TransactionID     string          `json:"transaction_id"`
	PlanDigest        string          `json:"plan_digest"`
	TargetFingerprint string          `json:"target_fingerprint"`
	FenceEpoch        uint64          `json:"fence_epoch"`
	ApprovalID        string          `json:"approval_id"`
	IntentReceipt     string          `json:"intent_receipt"`
	IntentSequence    uint32          `json:"intent_sequence"`
	Sequence          uint32          `json:"sequence"`
	Operation         Operation       `json:"operation"`
	OperationDigest   string          `json:"operation_digest"`
	Status            AttemptStatus   `json:"status"`
	StartedAt         time.Time       `json:"started_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	Result            OperationResult `json:"result"`
	ObservedState     DirectState     `json:"observed_state"`
	Detail            string          `json:"detail"`
}

type AttemptStore interface {
	Get(key string) (Attempt, bool, error)
	Put(Attempt) error
}

type MemoryStore struct {
	mu       sync.Mutex
	attempts map[string]Attempt
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{attempts: make(map[string]Attempt)}
}

func (store *MemoryStore) Get(key string) (Attempt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	attempt, ok := store.attempts[key]
	return attempt, ok, nil
}

func (store *MemoryStore) Put(attempt Attempt) error {
	if err := validateAttempt(attempt); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.attempts[attempt.Key]; ok {
		if err := validAttemptTransition(existing, attempt); err != nil {
			return err
		}
	} else if attempt.Status != AttemptStarted {
		return errors.New("a new attempt must begin with a durable started record")
	}
	store.attempts[attempt.Key] = attempt
	return nil
}

// FileStore is a small crash-safe reference store for a single guard process.
// It atomically replaces and fsyncs a secret-free JSON journal on every state
// transition. Cross-process access to one file is intentionally unsupported.
type FileStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStore(path string) (*FileStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("attempt journal path must be a clean absolute path")
	}
	return &FileStore{path: path}, nil
}

func (store *FileStore) Get(key string) (Attempt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	attempts, err := store.load()
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, ok := attempts[key]
	return attempt, ok, nil
}

func (store *FileStore) Put(attempt Attempt) error {
	if err := validateAttempt(attempt); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	attempts, err := store.load()
	if err != nil {
		return err
	}
	if existing, ok := attempts[attempt.Key]; ok {
		if err := validAttemptTransition(existing, attempt); err != nil {
			return err
		}
	} else if attempt.Status != AttemptStarted {
		return errors.New("a new attempt must begin with a durable started record")
	}
	attempts[attempt.Key] = attempt
	return store.save(attempts)
}

func (store *FileStore) load() (map[string]Attempt, error) {
	data, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]Attempt), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read attempt journal: %w", err)
	}
	var envelope struct {
		SchemaVersion string             `json:"schema_version"`
		Attempts      map[string]Attempt `json:"attempts"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode attempt journal: %w", err)
	}
	if envelope.SchemaVersion != ContractSchemaVersion || envelope.Attempts == nil {
		return nil, errors.New("attempt journal has an unsupported schema or missing records")
	}
	for key, attempt := range envelope.Attempts {
		if key != attempt.Key {
			return nil, errors.New("attempt journal key does not match its record")
		}
		if err := validateAttempt(attempt); err != nil {
			return nil, fmt.Errorf("invalid attempt journal record: %w", err)
		}
	}
	return envelope.Attempts, nil
}

func (store *FileStore) save(attempts map[string]Attempt) error {
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create attempt journal directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".lane-guard-attempts-*")
	if err != nil {
		return fmt.Errorf("create temporary attempt journal: %w", err)
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
		return fmt.Errorf("protect temporary attempt journal: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		SchemaVersion string             `json:"schema_version"`
		Attempts      map[string]Attempt `json:"attempts"`
	}{ContractSchemaVersion, attempts}); err != nil {
		return fmt.Errorf("encode attempt journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync attempt journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close attempt journal: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace attempt journal: %w", err)
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open attempt journal directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync attempt journal directory: %w", err)
	}
	return nil
}

func validateAttempt(attempt Attempt) error {
	if attempt.SchemaVersion != ContractSchemaVersion || attempt.Key == "" || attempt.TransactionID == "" || attempt.PlanDigest == "" || attempt.TargetFingerprint == "" || attempt.FenceEpoch == 0 || attempt.ApprovalID == "" || attempt.IntentReceipt == "" || attempt.IntentSequence == 0 || attempt.IntentSequence != attempt.Sequence || attempt.Sequence == 0 || attempt.OperationDigest == "" {
		return errors.New("attempt is missing required immutable bindings")
	}
	if _, allowed := operationClass(attempt.Operation); !allowed {
		return errors.New("attempt contains an unknown operation")
	}
	switch attempt.Status {
	case AttemptStarted, AttemptUncertain, AttemptVerified, AttemptQuarantined:
	default:
		return errors.New("attempt has an invalid status")
	}
	if attempt.StartedAt.IsZero() || attempt.UpdatedAt.IsZero() {
		return errors.New("attempt is missing timestamps")
	}
	return nil
}

func validAttemptTransition(existing, next Attempt) error {
	if existing.Key != next.Key || existing.TransactionID != next.TransactionID || existing.PlanDigest != next.PlanDigest || existing.TargetFingerprint != next.TargetFingerprint || existing.FenceEpoch != next.FenceEpoch || existing.ApprovalID != next.ApprovalID || existing.IntentReceipt != next.IntentReceipt || existing.IntentSequence != next.IntentSequence || existing.Sequence != next.Sequence || existing.Operation != next.Operation || existing.OperationDigest != next.OperationDigest || existing.StartedAt != next.StartedAt {
		return errors.New("attempt immutable bindings cannot change")
	}
	if existing.Status == AttemptVerified || existing.Status == AttemptQuarantined {
		if existing != next {
			return errors.New("terminal attempt record cannot change")
		}
		return nil
	}
	if existing.Status == AttemptUncertain && next.Status == AttemptStarted {
		return errors.New("an uncertain attempt cannot return to started")
	}
	return nil
}
