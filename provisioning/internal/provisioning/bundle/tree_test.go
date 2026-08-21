//go:build linux

package bundle

import (
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	goldenDirectoryTreeJSON = `{"schema_version":"kaiba.provisioning.rpiboot-directory-tree/v1alpha1","root_mode":"0555","entries":[{"path":"README","type":"regular_file","mode":"0444","size_bytes":5,"digest":"sha256:53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a"},{"path":"nested","type":"directory","mode":"0555","size_bytes":0,"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},{"path":"nested/\u003c\u0026\u003e-雪","type":"regular_file","mode":"0555","size_bytes":0,"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}`
	goldenDirectoryTreeHash = "sha256:81dbed3e004087dc6c19fb107f2c1b7670a3678519278d7bd0570d606a198621"
)

func TestDirectoryTreeGoldenVector(t *testing.T) {
	source := []TreeEntry{
		{Path: "nested/<&>-雪", Type: TreeEntryRegularFile, Mode: "0555", SizeBytes: 0, Digest: Sum(nil)},
		{Path: "README", Type: TreeEntryRegularFile, Mode: "0444", SizeBytes: 5, Digest: Sum([]byte("root\n"))},
		{Path: "nested", Type: TreeEntryDirectory, Mode: "0555", SizeBytes: 0, Digest: Sum(nil)},
	}
	tree, err := NewDirectoryTree("0555", source)
	if err != nil {
		t.Fatal(err)
	}
	source[0].Path = "mutated-after-construction"
	if tree.Entries[0].Path != "README" || tree.Entries[1].Path != "nested" || tree.Entries[2].Path != "nested/<&>-雪" {
		t.Fatalf("entries are not a sorted independent copy: %#v", tree.Entries)
	}

	canonical, err := tree.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != goldenDirectoryTreeJSON {
		t.Fatalf("canonical directory tree = %s", canonical)
	}
	digest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != Digest(goldenDirectoryTreeHash) {
		t.Fatalf("directory tree digest = %q, want %q", digest, goldenDirectoryTreeHash)
	}
	size, err := tree.SizeBytes()
	if err != nil || size != 5 {
		t.Fatalf("directory tree size = %d, %v; want 5", size, err)
	}

	parsed, err := ParseDirectoryTree(canonical)
	if err != nil {
		t.Fatal(err)
	}
	parsedDigest, err := parsed.Digest()
	if err != nil || parsedDigest != digest {
		t.Fatalf("parsed directory tree digest = %q, %v; want %q", parsedDigest, err, digest)
	}
}

func TestDirectoryTreeRejectsInvalidAndAmbiguousRecords(t *testing.T) {
	valid := goldenDirectoryTree(t)
	tests := []struct {
		name   string
		mutate func(*DirectoryTree)
	}{
		{"schema", func(tree *DirectoryTree) { tree.SchemaVersion = "other" }},
		{"root mode short", func(tree *DirectoryTree) { tree.RootMode = "555" }},
		{"root mode non-octal", func(tree *DirectoryTree) { tree.RootMode = "08ff" }},
		{"empty", func(tree *DirectoryTree) { tree.Entries = nil }},
		{"unsorted", func(tree *DirectoryTree) { tree.Entries[0], tree.Entries[1] = tree.Entries[1], tree.Entries[0] }},
		{"duplicate", func(tree *DirectoryTree) { tree.Entries[2].Path = tree.Entries[1].Path }},
		{"absolute path", func(tree *DirectoryTree) { tree.Entries[0].Path = "/README" }},
		{"parent path", func(tree *DirectoryTree) { tree.Entries[0].Path = "../README" }},
		{"unclean path", func(tree *DirectoryTree) { tree.Entries[0].Path = "nested/../README" }},
		{"backslash path", func(tree *DirectoryTree) { tree.Entries[0].Path = `bad\name` }},
		{"invalid UTF-8", func(tree *DirectoryTree) { tree.Entries[0].Path = string([]byte{0xff}) }},
		{"long path", func(tree *DirectoryTree) {
			tree.Entries[0].Path = strings.Repeat("a", maximumDirectoryTreePathCharacters+1)
		}},
		{"unknown type", func(tree *DirectoryTree) { tree.Entries[0].Type = "symlink" }},
		{"entry mode", func(tree *DirectoryTree) { tree.Entries[0].Mode = "4755" }},
		{"digest", func(tree *DirectoryTree) { tree.Entries[0].Digest = "not-a-digest" }},
		{"directory size", func(tree *DirectoryTree) { tree.Entries[1].SizeBytes = 1 }},
		{"directory digest", func(tree *DirectoryTree) { tree.Entries[1].Digest = Sum([]byte("directory")) }},
		{"missing parent", func(tree *DirectoryTree) { tree.Entries[2].Path = "absent/file" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneDirectoryTree(valid)
			test.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid directory tree")
			}
		})
	}

	t.Run("regular parent", func(t *testing.T) {
		tree := DirectoryTree{
			SchemaVersion: DirectoryTreeSchemaV1Alpha1,
			RootMode:      "0555",
			Entries: []TreeEntry{
				{Path: "parent", Type: TreeEntryRegularFile, Mode: "0444", Digest: Sum(nil)},
				{Path: "parent/child", Type: TreeEntryRegularFile, Mode: "0444", Digest: Sum(nil)},
			},
		}
		if err := tree.Validate(); err == nil {
			t.Fatal("Validate() accepted a child below a regular file")
		}
	})

	t.Run("aggregate overflow", func(t *testing.T) {
		tree := DirectoryTree{
			SchemaVersion: DirectoryTreeSchemaV1Alpha1,
			RootMode:      "0555",
			Entries: []TreeEntry{
				{Path: "a", Type: TreeEntryRegularFile, Mode: "0444", SizeBytes: math.MaxUint64, Digest: Sum(nil)},
				{Path: "b", Type: TreeEntryRegularFile, Mode: "0444", SizeBytes: 1, Digest: Sum(nil)},
			},
		}
		if _, err := tree.SizeBytes(); err == nil {
			t.Fatal("SizeBytes() accepted uint64 overflow")
		}
	})

	t.Run("entry bound", func(t *testing.T) {
		entries := make([]TreeEntry, maximumDirectoryTreeEntries+1)
		for index := range entries {
			entries[index] = TreeEntry{
				Path: strings.Repeat("a", 8) + formatTestIndex(index), Type: TreeEntryRegularFile,
				Mode: "0444", Digest: Sum(nil),
			}
		}
		if _, err := NewDirectoryTree("0555", entries); err == nil {
			t.Fatal("NewDirectoryTree() accepted too many entries")
		}
	})

	t.Run("multibyte path length matches JSON Schema characters", func(t *testing.T) {
		fixture, err := os.ReadFile("testdata/rpiboot-directory-tree-multibyte-v1alpha1.json")
		if err != nil {
			t.Fatal(err)
		}
		fixtureTree, err := ParseDirectoryTree(fixture)
		if err != nil {
			t.Fatalf("ParseDirectoryTree() rejected shared multibyte schema fixture: %v", err)
		}
		if len(fixtureTree.Entries[0].Path) <= 1024 {
			t.Fatal("shared multibyte fixture no longer exceeds 1024 UTF-8 bytes")
		}

		pathAtLimit := strings.Repeat("雪", maximumDirectoryTreePathCharacters)
		tree, err := NewDirectoryTree("0555", []TreeEntry{{
			Path: pathAtLimit, Type: TreeEntryRegularFile, Mode: "0444", Digest: Sum(nil),
		}})
		if err != nil {
			t.Fatalf("NewDirectoryTree() rejected %d-character multibyte path: %v", maximumDirectoryTreePathCharacters, err)
		}
		canonical, err := tree.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDirectoryTree(canonical); err != nil {
			t.Fatalf("ParseDirectoryTree() rejected schema-length multibyte path: %v", err)
		}
		tree.Entries[0].Path += "雪"
		if err := tree.Validate(); err == nil {
			t.Fatalf("Validate() accepted a %d-character path", maximumDirectoryTreePathCharacters+1)
		}
	})
}

func TestDirectoryTreeStrictParserRejectsNullUnknownDuplicateAndTrailingJSON(t *testing.T) {
	valid := goldenDirectoryTreeJSON
	tests := []struct {
		name  string
		input string
	}{
		{"null", strings.Replace(valid, `"size_bytes":0`, `"size_bytes":null`, 1)},
		{"unknown", strings.Replace(valid, `"root_mode":`, `"unknown":true,"root_mode":`, 1)},
		{"duplicate", strings.Replace(valid, `"root_mode":"0555"`, `"root_mode":"0555","root_mode":"0555"`, 1)},
		{"trailing", valid + `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseDirectoryTree([]byte(test.input)); err == nil {
				t.Fatal("ParseDirectoryTree() accepted ambiguous JSON")
			}
		})
	}
}

func TestDirectoryTreeDigestCoversEveryCanonicalField(t *testing.T) {
	baseline := goldenDirectoryTree(t)
	baselineDigest, err := baseline.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DirectoryTree)
	}{
		{"root mode", func(tree *DirectoryTree) { tree.RootMode = "0755" }},
		{"path", func(tree *DirectoryTree) { tree.Entries[2].Path = "nested/changed" }},
		{"type", func(tree *DirectoryTree) {
			tree.Entries[0].Type = TreeEntryDirectory
			tree.Entries[0].SizeBytes = 0
			tree.Entries[0].Digest = Sum(nil)
		}},
		{"mode", func(tree *DirectoryTree) { tree.Entries[0].Mode = "0400" }},
		{"size", func(tree *DirectoryTree) { tree.Entries[0].SizeBytes++ }},
		{"digest", func(tree *DirectoryTree) { tree.Entries[0].Digest = Sum([]byte("changed")) }},
		{"entry", func(tree *DirectoryTree) {
			tree.Entries = append(tree.Entries, TreeEntry{Path: "z", Type: TreeEntryRegularFile, Mode: "0444", Digest: Sum(nil)})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneDirectoryTree(baseline)
			test.mutate(&changed)
			digest, err := changed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baselineDigest {
				t.Fatal("canonical field mutation retained the tree digest")
			}
		})
	}
}

func TestSnapshotDirectoryTreeBindsExactFilesystemTree(t *testing.T) {
	root := newSnapshotRoot(t)
	emptyPath := filepath.Join(root, "empty")
	nestedPath := filepath.Join(root, "nested")
	mustMakeSnapshotDirectory(t, emptyPath, 0o500)
	mustMakeSnapshotDirectory(t, nestedPath, 0o750)
	t.Cleanup(func() {
		_ = os.Chmod(emptyPath, 0o700)
		_ = os.Chmod(nestedPath, 0o700)
		_ = os.Chmod(root, 0o700)
	})
	mustWriteSnapshotFile(t, filepath.Join(root, "config.txt"), []byte("config\n"), 0o440)
	mustWriteSnapshotFile(t, filepath.Join(nestedPath, "empty.bin"), nil, 0o600)
	mustWriteSnapshotFile(t, filepath.Join(nestedPath, "recovery.bin"), []byte("recovery"), 0o500)
	if err := os.Chmod(nestedPath, 0o550); err != nil {
		t.Fatal(err)
	}

	tree, err := SnapshotDirectoryTree(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []TreeEntry{
		{Path: "config.txt", Type: TreeEntryRegularFile, Mode: "0440", SizeBytes: 7, Digest: Sum([]byte("config\n"))},
		{Path: "empty", Type: TreeEntryDirectory, Mode: "0500", Digest: Sum(nil)},
		{Path: "nested", Type: TreeEntryDirectory, Mode: "0550", Digest: Sum(nil)},
		{Path: "nested/empty.bin", Type: TreeEntryRegularFile, Mode: "0600", Digest: Sum(nil)},
		{Path: "nested/recovery.bin", Type: TreeEntryRegularFile, Mode: "0500", SizeBytes: 8, Digest: Sum([]byte("recovery"))},
	}
	if tree.SchemaVersion != DirectoryTreeSchemaV1Alpha1 || tree.RootMode != "0750" || !equalTreeEntries(tree.Entries, want) {
		t.Fatalf("snapshot = %#v, want entries %#v", tree, want)
	}
	if size, err := tree.SizeBytes(); err != nil || size != 15 {
		t.Fatalf("snapshot size = %d, %v; want 15", size, err)
	}
	firstDigest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := SnapshotDirectoryTree(root)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil || secondDigest != firstDigest {
		t.Fatalf("repeat snapshot digest = %q, %v; want %q", secondDigest, err, firstDigest)
	}

	configPath := filepath.Join(root, "config.txt")
	if err := os.Chmod(configPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("change\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o440); err != nil {
		t.Fatal(err)
	}
	changed, err := SnapshotDirectoryTree(root)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, _ := changed.Digest()
	if changedDigest == firstDigest {
		t.Fatal("content change retained the directory tree digest")
	}
	if err := os.Chmod(configPath, 0o400); err != nil {
		t.Fatal(err)
	}
	modeChanged, err := SnapshotDirectoryTree(root)
	if err != nil {
		t.Fatal(err)
	}
	modeDigest, _ := modeChanged.Digest()
	if modeDigest == changedDigest {
		t.Fatal("mode change retained the directory tree digest")
	}
}

func TestSnapshotDirectoryTreeRejectsUnsafeFilesystemObjectsAndPaths(t *testing.T) {
	t.Run("relative root", func(t *testing.T) {
		if _, err := SnapshotDirectoryTree("relative"); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a relative root")
		}
	})
	t.Run("filesystem root", func(t *testing.T) {
		if _, err := SnapshotDirectoryTree("/"); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted filesystem root")
		}
	})
	t.Run("regular root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		mustWriteSnapshotFile(t, path, []byte("file"), 0o400)
		if _, err := SnapshotDirectoryTree(path); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a regular-file root")
		}
	})
	t.Run("empty root", func(t *testing.T) {
		if _, err := SnapshotDirectoryTree(newSnapshotRoot(t)); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted an empty tree")
		}
	})
	t.Run("symlink root", func(t *testing.T) {
		root := newSnapshotRoot(t)
		mustWriteSnapshotFile(t, filepath.Join(root, "file"), []byte("file"), 0o400)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(link); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a symlink root")
		}
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		base := t.TempDir()
		realParent := filepath.Join(base, "real")
		mustMakeSnapshotDirectory(t, realParent, 0o700)
		root := filepath.Join(realParent, "bundle")
		mustMakeSnapshotDirectory(t, root, 0o750)
		mustWriteSnapshotFile(t, filepath.Join(root, "file"), []byte("file"), 0o400)
		alias := filepath.Join(base, "alias")
		if err := os.Symlink(realParent, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(filepath.Join(alias, "bundle")); err == nil {
			t.Fatal("SnapshotDirectoryTree() followed a symlink ancestor")
		}
	})
	t.Run("symlink file", func(t *testing.T) {
		root := newSnapshotRoot(t)
		mustWriteSnapshotFile(t, filepath.Join(root, "target"), []byte("file"), 0o400)
		if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a symlink entry")
		}
	})
	t.Run("symlink directory", func(t *testing.T) {
		root := newSnapshotRoot(t)
		mustMakeSnapshotDirectory(t, filepath.Join(root, "real"), 0o500)
		if err := os.Symlink("real", filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a symlink directory")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		root := newSnapshotRoot(t)
		if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a FIFO")
		}
	})
	t.Run("socket", func(t *testing.T) {
		root := newSnapshotRoot(t)
		listener, err := net.Listen("unix", filepath.Join(root, "socket"))
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("Unix sockets are not permitted in this sandbox")
			}
			t.Fatal(err)
		}
		defer listener.Close()
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a Unix socket")
		}
	})
	t.Run("setuid file", func(t *testing.T) {
		root := newSnapshotRoot(t)
		path := filepath.Join(root, "file")
		mustWriteSnapshotFile(t, path, []byte("file"), 0o500)
		if err := os.Chmod(path, 0o500|os.ModeSetuid); err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("setuid file modes are not permitted in this sandbox")
			}
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted setuid mode")
		}
	})
	t.Run("sticky directory", func(t *testing.T) {
		root := newSnapshotRoot(t)
		path := filepath.Join(root, "directory")
		mustMakeSnapshotDirectory(t, path, 0o500)
		if err := os.Chmod(path, 0o500|os.ModeSticky); err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("sticky directory modes are not permitted in this sandbox")
			}
			t.Fatal(err)
		}
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted sticky mode")
		}
	})
	t.Run("invalid UTF-8", func(t *testing.T) {
		root := newSnapshotRoot(t)
		mustWriteSnapshotFile(t, filepath.Join(root, string([]byte{0xff})), []byte("file"), 0o400)
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted an invalid UTF-8 path")
		}
	})
	t.Run("backslash", func(t *testing.T) {
		root := newSnapshotRoot(t)
		mustWriteSnapshotFile(t, filepath.Join(root, `bad\name`), []byte("file"), 0o400)
		if _, err := SnapshotDirectoryTree(root); err == nil {
			t.Fatal("SnapshotDirectoryTree() accepted a backslash path")
		}
	})
}

func TestSnapshotDirectoryTreeRejectsSpecialPermissionBitsWithoutFilesystemSupport(t *testing.T) {
	tests := []struct {
		name string
		mode uint32
	}{
		{"setuid", syscall.S_IFREG | 0o4755},
		{"setgid", syscall.S_IFREG | 0o2755},
		{"sticky", syscall.S_IFDIR | 0o1755},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTreePermissionBits("fixture", test.mode); err == nil {
				t.Fatal("special permission bits were accepted")
			}
		})
	}
	if err := validateTreePermissionBits("fixture", syscall.S_IFREG|0o0755); err != nil {
		t.Fatalf("ordinary permission bits were rejected: %v", err)
	}
}

func goldenDirectoryTree(t *testing.T) DirectoryTree {
	t.Helper()
	tree, err := NewDirectoryTree("0555", []TreeEntry{
		{Path: "README", Type: TreeEntryRegularFile, Mode: "0444", SizeBytes: 5, Digest: Sum([]byte("root\n"))},
		{Path: "nested", Type: TreeEntryDirectory, Mode: "0555", Digest: Sum(nil)},
		{Path: "nested/<&>-雪", Type: TreeEntryRegularFile, Mode: "0555", Digest: Sum(nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func cloneDirectoryTree(tree DirectoryTree) DirectoryTree {
	clone := tree
	clone.Entries = append([]TreeEntry(nil), tree.Entries...)
	return clone
}

func newSnapshotRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	mustMakeSnapshotDirectory(t, root, 0o750)
	return root
}

func mustMakeSnapshotDirectory(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWriteSnapshotFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func equalTreeEntries(left, right []TreeEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func formatTestIndex(index int) string {
	const digits = "0123456789"
	value := []byte("00000")
	for position := len(value) - 1; position >= 0; position-- {
		value[position] = digits[index%10]
		index /= 10
	}
	return string(value)
}
