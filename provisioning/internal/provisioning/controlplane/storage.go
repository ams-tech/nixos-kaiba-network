package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrStoreNotFound = errors.New("control-plane store does not exist")

type idempotencyRecord struct {
	Operation     string `json:"operation"`
	RequestDigest string `json:"request_digest"`
	TransactionID string `json:"transaction_id"`
}

type persistedState struct {
	SchemaVersion string                       `json:"schema_version"`
	Transactions  map[string]Transaction       `json:"transactions"`
	FenceEpochs   map[string]uint64            `json:"fence_epochs"`
	Idempotency   map[string]idempotencyRecord `json:"idempotency"`
}

// Store is the coordinator durability boundary. Save must atomically make the
// full replacement durable before returning success.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

type FileStore struct {
	Path string
}

func (s FileStore) Load() ([]byte, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrStoreNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read control-plane store: %w", err)
	}
	return data, nil
}

func (s FileStore) Save(data []byte) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create control-plane store directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".control-store-*")
	if err != nil {
		return fmt.Errorf("create control-plane temporary file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("set control-plane store permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write control-plane store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync control-plane store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close control-plane store: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace control-plane store: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open control-plane store directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync control-plane store directory: %w", err)
	}
	return nil
}

type MemoryStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *MemoryStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil, ErrStoreNotFound
	}
	return append([]byte(nil), s.data...), nil
}

func (s *MemoryStore) Save(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]byte(nil), data...)
	return nil
}

func marshalState(state persistedState) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode control-plane store: %w", err)
	}
	return append(data, '\n'), nil
}

func cloneState(state persistedState) (persistedState, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return persistedState{}, fmt.Errorf("clone control-plane state: %w", err)
	}
	var result persistedState
	if err := json.Unmarshal(data, &result); err != nil {
		return persistedState{}, fmt.Errorf("clone control-plane state: %w", err)
	}
	return result, nil
}

func cloneTransaction(transaction Transaction) (Transaction, error) {
	data, err := json.Marshal(transaction)
	if err != nil {
		return Transaction{}, fmt.Errorf("clone transaction: %w", err)
	}
	var result Transaction
	if err := json.Unmarshal(data, &result); err != nil {
		return Transaction{}, fmt.Errorf("clone transaction: %w", err)
	}
	return result, nil
}
