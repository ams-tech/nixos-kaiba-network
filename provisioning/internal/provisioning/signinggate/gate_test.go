package signinggate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

var fixedNow = time.Date(2026, 8, 15, 18, 30, 0, 0, time.UTC)

func testGrant(artifact []byte, suffix string, expiresAt time.Time) Grant {
	digest := bundle.Sum(artifact)
	return Grant{
		SchemaVersion: GrantSchemaV1Alpha1,
		GrantID:       "grant:boot-" + suffix,
		ExpiresAt:     canonicalTime(expiresAt),
		Request: signing.Request{
			SchemaVersion:  signing.RequestSchemaV1Alpha1,
			RequestID:      "request:boot-" + suffix,
			Algorithm:      signing.AlgorithmRSA2048SHA256,
			Role:           bundle.RoleBootImage,
			ArtifactDigest: digest,
			Approval: signing.ApprovalBinding{
				ApprovalID:        "approval:boot-" + suffix,
				ApprovalDigest:    bundle.Sum([]byte("approval-" + suffix)),
				TransactionID:     "transaction:device-" + suffix,
				TransactionDigest: bundle.Sum([]byte("transaction-" + suffix)),
				ManifestDigest:    bundle.Sum([]byte("manifest-" + suffix)),
				PlanDigest:        bundle.Sum([]byte("plan-" + suffix)),
				TargetFingerprint: bundle.Sum([]byte("target-" + suffix)),
				FenceEpoch:        4,
				Role:              bundle.RoleBootImage,
				ArtifactDigest:    digest,
			},
		},
	}
}

func testRegistry(t *testing.T, grants ...Grant) Registry {
	t.Helper()
	registry, err := NewRegistry(grants)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testStore(t *testing.T) *StateStore {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateStore(directory, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

type inspectingBackend struct {
	store *StateStore
	grant Grant
	calls int
	err   error
}

type blockingBackend struct {
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (b *blockingBackend) Sign(ctx context.Context, _ signing.Algorithm, _ []byte) ([]byte, error) {
	b.calls++
	close(b.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
	}
	return make([]byte, signing.RSASignatureBytes), nil
}

func (b *inspectingBackend) Sign(_ context.Context, algorithm signing.Algorithm, artifact []byte) ([]byte, error) {
	b.calls++
	if algorithm != signing.AlgorithmRSA2048SHA256 || bundle.Sum(artifact) != b.grant.Request.ArtifactDigest {
		return nil, errors.New("backend received unbound signing input")
	}
	state, found, err := b.store.Load(b.grant)
	if err != nil || !found || state.Status != StateIntent || state.Receipt != nil {
		return nil, fmt.Errorf("durable intent was not present before key use: %#v / %v", state, err)
	}
	if b.err != nil {
		return nil, b.err
	}
	signature := make([]byte, signing.RSASignatureBytes)
	for index := range signature {
		signature[index] = byte(index)
	}
	return signature, nil
}

func testGate(t *testing.T, registry Registry, store *StateStore, backend signing.Backend) *Gate {
	t.Helper()
	gate, err := NewGate(GateConfig{
		Registry:  registry,
		Store:     store,
		Backend:   backend,
		BackendID: "backend:yubikey-development-01",
		Now:       func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func TestGateRecordsIntentBeforeKeyUseAndPersistsReceipt(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "01", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &inspectingBackend{store: store, grant: grant}
	gate := testGate(t, testRegistry(t, grant), store, backend)

	result, err := gate.Sign(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 || len(result.SignatureHex) != signing.RSASignatureBytes*2 || result.Replayed {
		t.Fatalf("backend/result = %d/%#v", backend.calls, result)
	}
	state, found, err := store.Load(grant)
	if err != nil || !found || state.Status != StateComplete || state.Receipt == nil {
		t.Fatalf("durable completion = %#v/%v/%v", state, found, err)
	}
	if digest, _ := state.Receipt.Digest(); digest != result.ReceiptDigest {
		t.Fatalf("receipt digest = %s, want %s", digest, result.ReceiptDigest)
	}
	if state.Receipt.Grant.Request.Approval != grant.Request.Approval {
		t.Fatal("receipt did not retain the complete approval binding")
	}
}

func TestGateReplaysCompletedSignatureWithoutKeyUse(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "01", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &inspectingBackend{store: store, grant: grant}
	registry := testRegistry(t, grant)
	first, err := testGate(t, registry, store, backend).Sign(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := testGate(t, registry, store, backend).Sign(context.Background(), append([]byte(nil), artifact...))
	if err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 || !second.Replayed || first.SignatureHex != second.SignatureHex || first.ReceiptDigest != second.ReceiptDigest {
		t.Fatalf("idempotent replay failed: calls=%d first=%#v second=%#v", backend.calls, first, second)
	}
}

func TestStateLockSerializesIndependentGateProcesses(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "lock", fixedNow.Add(time.Hour))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	firstStore, err := OpenStateStore(directory, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := OpenStateStore(directory, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	firstBackend := &blockingBackend{entered: make(chan struct{}), release: make(chan struct{})}
	secondBackend := &signing.DeterministicFakeBackend{}
	registry := testRegistry(t, grant)
	firstGate := testGate(t, registry, firstStore, firstBackend)
	secondGate := testGate(t, registry, secondStore, secondBackend)

	firstDone := make(chan error, 1)
	go func() {
		_, err := firstGate.Sign(context.Background(), artifact)
		firstDone <- err
	}()
	select {
	case <-firstBackend.entered:
	case <-time.After(time.Second):
		t.Fatal("first backend did not start")
	}
	secondDone := make(chan error, 1)
	go func() {
		result, err := secondGate.Sign(context.Background(), artifact)
		if err == nil && !result.Replayed {
			err = errors.New("second gate did not replay the persisted result")
		}
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second gate bypassed host lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(firstBackend.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if firstBackend.calls != 1 || secondBackend.Calls != 0 {
		t.Fatalf("backend calls = %d/%d, want 1/0", firstBackend.calls, secondBackend.Calls)
	}
}

func TestGateRejectsDifferentExpiredAndAmbiguousInputs(t *testing.T) {
	artifact := []byte("approved boot image")
	valid := testGrant(artifact, "01", fixedNow.Add(time.Hour))
	tests := []struct {
		name     string
		registry Registry
		input    []byte
		match    string
	}{
		{"different input", testRegistry(t, valid), []byte("different"), "no current"},
		{"expired", testRegistry(t, testGrant(artifact, "expired", fixedNow)), artifact, "no current"},
		{"ambiguous", testRegistry(t, valid, testGrant(artifact, "02", fixedNow.Add(time.Hour))), artifact, "2 current"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := testStore(t)
			backend := &signing.DeterministicFakeBackend{}
			gate := testGate(t, test.registry, store, backend)
			_, err := gate.Sign(context.Background(), test.input)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Sign() error = %v, want match %q", err, test.match)
			}
			if backend.Calls != 0 {
				t.Fatalf("rejected input reached backend %d times", backend.Calls)
			}
		})
	}
}

func TestGateRetainsIntentAcrossBackendFailureAndRecovers(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "01", fixedNow.Add(time.Hour))
	store := testStore(t)
	backend := &inspectingBackend{store: store, grant: grant, err: errors.New("touch timeout")}
	gate := testGate(t, testRegistry(t, grant), store, backend)
	if _, err := gate.Sign(context.Background(), artifact); err == nil || !strings.Contains(err.Error(), "touch timeout") {
		t.Fatalf("backend failure = %v", err)
	}
	state, found, err := store.Load(grant)
	if err != nil || !found || state.Status != StateIntent {
		t.Fatalf("persisted intent = %#v/%v/%v", state, found, err)
	}
	backend.err = nil
	if _, err := gate.Sign(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 2 {
		t.Fatalf("backend calls = %d, want 2", backend.calls)
	}
}

func TestRegistryLoadIsStrictAndOwnershipChecked(t *testing.T) {
	artifact := []byte("approved boot image")
	registry := testRegistry(t, testGrant(artifact, "01", fixedNow.Add(time.Hour)))
	encoded, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "grants.json")
	write := func(data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(encoded, 0o600)
	if _, err := LoadRegistry(RegistryConfig{Path: path, OwnerUID: uint32(os.Getuid())}); err != nil {
		t.Fatal(err)
	}

	unknown := bytes.Replace(encoded, []byte(`"grants"`), []byte(`"unknown":true,"grants"`), 1)
	write(unknown, 0o600)
	if _, err := LoadRegistry(RegistryConfig{Path: path, OwnerUID: uint32(os.Getuid())}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
	duplicate := bytes.Replace(encoded, []byte(`"schema_version"`), []byte(`"schema_version":"duplicate","schema_version"`), 1)
	write(duplicate, 0o600)
	if _, err := LoadRegistry(RegistryConfig{Path: path, OwnerUID: uint32(os.Getuid())}); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate-field error = %v", err)
	}
	write(encoded, 0o622)
	if _, err := LoadRegistry(RegistryConfig{Path: path, OwnerUID: uint32(os.Getuid())}); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("permissions error = %v", err)
	}
	write(encoded, 0o600)
	if _, err := LoadRegistry(RegistryConfig{Path: path, OwnerUID: uint32(os.Getuid()) + 1}); err == nil || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ownership error = %v", err)
	}
}

func TestStateStoreRejectsBroadDirectoryPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStateStore(directory, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("OpenStateStore error = %v", err)
	}
}
