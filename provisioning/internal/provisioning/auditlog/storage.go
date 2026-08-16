package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrStoreNotFound = errors.New("audit store does not exist")

type persistedState struct {
	SchemaVersion string            `json:"schema_version"`
	Records       []Record          `json:"records"`
	Idempotency   map[string]uint64 `json:"idempotency"`
}

// Store is the durability boundary used by Service. Save must make the entire
// new state durable atomically before returning success.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// FileStore persists one atomically replaced JSON snapshot. Audit semantics
// remain append-only because Service validates that records can only be added
// and verifies the complete hash chain whenever it opens the store.
type FileStore struct {
	Path string
}

func (s FileStore) Load() ([]byte, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrStoreNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read audit store: %w", err)
	}
	return data, nil
}

func (s FileStore) Save(data []byte) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit store directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".audit-store-*")
	if err != nil {
		return fmt.Errorf("create audit store temporary file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("set audit store permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write audit store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync audit store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close audit store: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace audit store: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open audit store directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync audit store directory: %w", err)
	}
	return nil
}

// MemoryStore is useful for embedding and tests. It copies all byte slices at
// the boundary so callers cannot mutate committed state.
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
		return nil, fmt.Errorf("encode audit store: %w", err)
	}
	return append(data, '\n'), nil
}
