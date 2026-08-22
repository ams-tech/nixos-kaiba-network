//go:build linux

package evidencefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestWriteCanonicalNewPublishesReadOnlyAndNeverReplaces(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	if err := WriteCanonicalNew(path, []byte("{\"status\":\"verified\"}")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"status\":\"verified\"}" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := WriteCanonicalNew(path, []byte("{\"status\":\"replacement\"}")); err == nil {
		t.Fatal("WriteCanonicalNew replaced existing evidence")
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "{\"status\":\"verified\"}" {
		t.Fatalf("existing data = %q, %v", data, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory entries = %v, %v", entries, err)
	}
}

func TestValidateNewPathDoesNotBlockOnExistingFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ValidateNewPath(path) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ValidateNewPath accepted an existing FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("ValidateNewPath blocked while probing an existing FIFO")
	}
}

func TestValidateNewPathTreatsDanglingSymlinkAsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.Symlink("missing-target", path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNewPath(path); err == nil {
		t.Fatal("ValidateNewPath accepted an existing dangling symlink")
	}
}

func TestWriteCanonicalNewRejectsUnsafePaths(t *testing.T) {
	for _, path := range []string{"relative", "/dev/result.json", filepath.Join(t.TempDir(), "missing", "result.json")} {
		if err := WriteCanonicalNew(path, []byte("x")); err == nil {
			t.Fatalf("accepted path %q", path)
		}
	}
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(directory, "link")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if err := WriteCanonicalNew(filepath.Join(linkDirectory, "result.json"), []byte("x")); err == nil {
		t.Fatal("accepted symlinked output directory")
	}
}

func TestTrustedPublicationRejectsOperatorOwnedOrWritableParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := ValidateTrustedNewPath(path); err == nil {
		t.Fatal("trusted production validation accepted an operator-owned temporary directory")
	}
	if err := WriteCanonicalNewTrusted(path, []byte("{}")); err == nil {
		t.Fatal("trusted production publication accepted an operator-owned temporary directory")
	}
}

func TestReadTrustedExistingRejectsOperatorOwnedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage-receipt.json")
	if err := os.WriteFile(path, []byte("{}"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTrustedExisting(path, 1024); err == nil {
		t.Fatal("trusted production read accepted an operator-owned pathname chain")
	}
}

func TestReadTrustedExistingDoesNotBlockOnFIFOOrFollowSymlink(t *testing.T) {
	directory := t.TempDir()
	fifo := filepath.Join(directory, "stage-receipt.fifo")
	if err := syscall.Mkfifo(fifo, 0o444); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadTrustedExisting(fifo, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("trusted production read accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("trusted production read blocked on a FIFO")
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o444); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "stage-receipt.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTrustedExisting(link, 1024); err == nil {
		t.Fatal("trusted production read followed a symlink")
	}
}
