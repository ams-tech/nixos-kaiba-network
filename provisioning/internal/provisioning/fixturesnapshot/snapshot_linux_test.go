//go:build linux

package fixturesnapshot

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const sparseFixtureSize = int64(16 * 1024 * 1024)

func TestSnapshotCopiesSparseRegularFile(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	writeSparseFixture(t, sourcePath, sparseFixtureSize)

	if err := Snapshot(Options{
		Source:       sourcePath,
		Destination:  destinationPath,
		ExpectedSize: uint64(sparseFixtureSize),
	}); err != nil {
		t.Fatal(err)
	}

	sourceDigest := digestFile(t, sourcePath)
	destinationDigest := digestFile(t, destinationPath)
	if sourceDigest != destinationDigest {
		t.Fatalf("snapshot digest = %x, want %x", destinationDigest, sourceDigest)
	}
	destinationInfo, err := os.Lstat(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !destinationInfo.Mode().IsRegular() || destinationInfo.Mode().Perm() != 0o600 || destinationInfo.Size() != sparseFixtureSize {
		t.Fatalf("snapshot mode/size = %s/%d", destinationInfo.Mode(), destinationInfo.Size())
	}

	sourceBlocks := allocatedBlocks(t, sourcePath)
	destinationBlocks := allocatedBlocks(t, destinationPath)
	if sourceBlocks*512 < sparseFixtureSize/2 && destinationBlocks*512 >= sparseFixtureSize/2 {
		t.Fatalf("snapshot allocated %d bytes for sparse %d-byte source", destinationBlocks*512, sparseFixtureSize)
	}
}

func TestSnapshotRejectsSourceSymlinkAndSpecialFiles(t *testing.T) {
	directory := t.TempDir()
	regularPath := filepath.Join(directory, "regular.img")
	writeSizedFixture(t, regularPath, 4096)
	symlinkPath := filepath.Join(directory, "source-link.img")
	if err := os.Symlink(regularPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(directory, "source.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		path string
	}{
		{name: "symlink", path: symlinkPath},
		{name: "directory", path: directory},
		{name: "fifo", path: fifoPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			destinationPath := filepath.Join(directory, "snapshot-"+test.name+".img")
			err := Snapshot(Options{
				Source:       test.path,
				Destination:  destinationPath,
				ExpectedSize: 4096,
			})
			if err == nil {
				t.Fatal("Snapshot() succeeded for unsafe source")
			}
			assertNotExist(t, destinationPath)
		})
	}
}

func TestSnapshotRejectsSymlinkedPathAncestor(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	realSourcePath := filepath.Join(realDirectory, "source.img")
	writeSizedFixture(t, realSourcePath, 4096)
	linkedDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(directory, "snapshot.img")

	err := Snapshot(Options{
		Source:       filepath.Join(linkedDirectory, "source.img"),
		Destination:  destinationPath,
		ExpectedSize: 4096,
	})
	if err == nil {
		t.Fatal("Snapshot() succeeded through a symlinked path ancestor")
	}
	assertNotExist(t, destinationPath)
}

func TestOpenValidatedSourceRejectsFIFOBeforeReadableOpen(t *testing.T) {
	directory := t.TempDir()
	fifoPath := filepath.Join(directory, "source.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := pinParent(fifoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.file.Close()
	expected, err := lstatIdentity(fifoPath)
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		file, _, err := openValidatedSource(parent, expected, expected.size)
		if file != nil {
			file.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("openValidatedSource() accepted a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("openValidatedSource() blocked while rejecting a FIFO")
	}
}

func TestSnapshotRejectsExistingDestinationWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	writeSizedFixture(t, sourcePath, 4096)
	original := []byte("keep this destination")
	if err := os.WriteFile(destinationPath, original, 0o640); err != nil {
		t.Fatal(err)
	}

	err := Snapshot(Options{
		Source:       sourcePath,
		Destination:  destinationPath,
		ExpectedSize: 4096,
	})
	if err == nil {
		t.Fatal("Snapshot() succeeded with an existing destination")
	}
	actual, readErr := os.ReadFile(destinationPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(actual) != string(original) {
		t.Fatalf("existing destination = %q, want %q", actual, original)
	}
}

func TestSnapshotRejectsSourceSizeMismatch(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	writeSizedFixture(t, sourcePath, 4096)

	err := Snapshot(Options{
		Source:       sourcePath,
		Destination:  destinationPath,
		ExpectedSize: 8192,
	})
	if err == nil {
		t.Fatal("Snapshot() succeeded with a source size mismatch")
	}
	assertNotExist(t, destinationPath)
}

func TestSnapshotRejectsLockedSource(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	writeSizedFixture(t, sourcePath, 4096)

	locked, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(locked.Fd()), syscall.LOCK_UN)

	err = Snapshot(Options{
		Source:       sourcePath,
		Destination:  destinationPath,
		ExpectedSize: 4096,
	})
	if !errors.Is(err, ErrSourceBusy) {
		t.Fatalf("Snapshot() error = %v, want ErrSourceBusy", err)
	}
	assertNotExist(t, destinationPath)
}

func TestSnapshotRejectsUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	writeSizedFixture(t, sourcePath, 4096)
	uncleanSource := filepath.Join(directory, "child") + "/../" + filepath.Base(sourcePath)

	for _, test := range []struct {
		name        string
		source      string
		destination string
	}{
		{name: "relative source", source: "source.img", destination: destinationPath},
		{name: "unclean source", source: uncleanSource, destination: destinationPath},
		{name: "dev source", source: "/dev/null", destination: destinationPath},
		{name: "dev destination", source: sourcePath, destination: "/dev/snapshot.img"},
		{name: "same path", source: sourcePath, destination: sourcePath},
		{name: "zero expected size", source: sourcePath, destination: destinationPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedSize := uint64(4096)
			if test.name == "zero expected size" {
				expectedSize = 0
			}
			if err := Snapshot(Options{Source: test.source, Destination: test.destination, ExpectedSize: expectedSize}); err == nil {
				t.Fatal("Snapshot() succeeded for unsafe paths")
			}
		})
	}
}

func writeSizedFixture(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeSparseFixture(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		file.Close()
		t.Fatal(err)
	}
	for offset, value := range map[int64][]byte{
		0:          []byte("kaiba sparse fixture header"),
		size / 2:   []byte("middle extent"),
		size - 128: []byte("kaiba sparse fixture trailer"),
	} {
		if _, err := file.WriteAt(value, offset); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func digestFile(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	if copied := copy(digest[:], hash.Sum(nil)); copied != sha256.Size {
		t.Fatal("copy SHA-256 digest")
	}
	return digest
}

func allocatedBlocks(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat identity unavailable")
	}
	if stat.Blocks < 0 {
		t.Fatal("negative allocated block count")
	}
	return stat.Blocks
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lstat %q error = %v, want not exist", path, err)
	}
}
