package signinggate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

func TestReadCompleteStateSnapshotIsReadOnlyAndRegistryOrdered(t *testing.T) {
	firstArtifact := []byte("first approved image")
	secondArtifact := []byte("second approved image")
	first := testGrant(firstArtifact, "snapshot-01", fixedNow.Add(time.Hour))
	second := testGrant(secondArtifact, "snapshot-02", fixedNow.Add(time.Hour))
	registry := testRegistry(t, second, first)
	store := testStore(t)

	for _, fixture := range []struct {
		grant    Grant
		artifact []byte
	}{
		{first, firstArtifact},
		{second, secondArtifact},
	} {
		backend := &inspectingBackend{store: store, grant: fixture.grant}
		if _, err := testGate(t, testRegistry(t, fixture.grant), store, backend).Sign(context.Background(), fixture.artifact); err != nil {
			t.Fatal(err)
		}
	}

	before := directoryContents(t, store.directory)
	states, err := ReadCompleteStateSnapshot(context.Background(), store.directory, uint32(os.Getuid()), registry)
	if err != nil {
		t.Fatal(err)
	}
	after := directoryContents(t, store.directory)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("state directory changed during snapshot\nbefore=%#v\nafter=%#v", before, after)
	}
	if len(states) != 2 || states[0].GrantID != registry.Grants[0].GrantID || states[1].GrantID != registry.Grants[1].GrantID {
		t.Fatalf("snapshot order = %#v, registry = %#v", states, registry.Grants)
	}
}

func TestReadCompleteStateSnapshotRequiresPreexistingSafeLock(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := testRegistry(t, testGrant([]byte("artifact"), "missing-lock", fixedNow.Add(time.Hour)))
	_, err := ReadCompleteStateSnapshot(context.Background(), directory, uint32(os.Getuid()), registry)
	if err == nil || !strings.Contains(err.Error(), "existing signing state lock") {
		t.Fatalf("snapshot error = %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only snapshot created state directory entries: %#v", entries)
	}
}

func TestReadCompleteStateSnapshotHonorsGateLockAndContext(t *testing.T) {
	artifact := []byte("approved boot image")
	grant := testGrant(artifact, "snapshot-lock", fixedNow.Add(time.Hour))
	registry := testRegistry(t, grant)
	store := testStore(t)
	intent, err := store.RecordIntent(grant, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaV1Alpha3, Grant: grant, RequestDigest: requestDigest,
		BackendID: "backend:test", SignatureHex: strings.Repeat("00", 256),
		SignatureDigest: bundle.Sum(make([]byte, 256)), SignedAt: canonicalTime(fixedNow),
	}
	receipt, err = receipt.WithAttestationSignature(make([]byte, signing.RSASignatureBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordComplete(grant, intent, receipt); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- store.withExclusive(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = ReadCompleteStateSnapshot(ctx, store.directory, uint32(os.Getuid()), registry)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("snapshot lock error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func directoryContents(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	contents := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[entry.Name()] = data
	}
	return contents
}
