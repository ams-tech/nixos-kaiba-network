//go:build linux

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

const treeOpenPath = 0x200000 // Linux O_PATH, absent from syscall on some Go versions.

type treeFileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

type directoryTreeSnapshot struct {
	entries   []TreeEntry
	sizeBytes uint64
}

// SnapshotDirectoryTree opens a clean absolute directory without following
// symbolic links and derives its canonical tree from pinned directory and file
// descriptors. Only ordinary directories and regular files without special
// permission bits are accepted. The caller must keep the complete tree
// immutable while it is snapshotted and retain or reverify the same content
// before approval; this function does not lock a multi-file filesystem tree.
func SnapshotDirectoryTree(root string) (DirectoryTree, error) {
	if err := validateDirectoryTreeRootPath(root); err != nil {
		return DirectoryTree{}, err
	}
	directory, rootIdentity, err := openDirectoryTreeRoot(root)
	if err != nil {
		return DirectoryTree{}, fmt.Errorf("open directory tree root: %w", err)
	}
	defer directory.Close()
	if err := validateTreeDirectoryIdentity("directory tree root", rootIdentity); err != nil {
		return DirectoryTree{}, err
	}

	snapshot := directoryTreeSnapshot{
		entries: make([]TreeEntry, 0),
	}
	if err := snapshot.scanDirectory(directory, ""); err != nil {
		return DirectoryTree{}, fmt.Errorf("snapshot directory tree: %w", err)
	}
	rootAfter, err := fstatTreeIdentity(int(directory.Fd()))
	if err != nil {
		return DirectoryTree{}, fmt.Errorf("reinspect directory tree root: %w", err)
	}
	if !sameTreeIdentity(rootIdentity, rootAfter) {
		return DirectoryTree{}, errors.New("directory tree root changed while snapshotting")
	}

	reopened, reopenedIdentity, err := openDirectoryTreeRoot(root)
	if err != nil {
		return DirectoryTree{}, fmt.Errorf("reopen directory tree root: %w", err)
	}
	reopened.Close()
	if !sameTreeIdentity(rootIdentity, reopenedIdentity) {
		return DirectoryTree{}, errors.New("directory tree root path changed while snapshotting")
	}

	tree, err := NewDirectoryTree(formatTreeMode(rootIdentity.mode), snapshot.entries)
	if err != nil {
		return DirectoryTree{}, fmt.Errorf("construct directory tree: %w", err)
	}
	derivedSize, err := tree.SizeBytes()
	if err != nil {
		return DirectoryTree{}, err
	}
	if derivedSize != snapshot.sizeBytes {
		return DirectoryTree{}, errors.New("directory tree aggregate size changed while snapshotting")
	}
	return tree, nil
}

func (snapshot *directoryTreeSnapshot) scanDirectory(directory *os.File, prefix string) error {
	before, err := fstatTreeIdentity(int(directory.Fd()))
	if err != nil {
		return fmt.Errorf("inspect directory %q: %w", prefix, err)
	}
	if err := validateTreeDirectoryIdentity("directory "+quotedTreePath(prefix), before); err != nil {
		return err
	}

	names, err := readSortedTreeNames(directory)
	if err != nil {
		return fmt.Errorf("list directory %q: %w", prefix, err)
	}
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) || !utf8.ValidString(name) {
			return fmt.Errorf("directory %q contains a non-canonical entry name", prefix)
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		if err := validateTreePath(relative); err != nil {
			return fmt.Errorf("path %q: %w", relative, err)
		}
		if len(snapshot.entries) >= maximumDirectoryTreeEntries {
			return fmt.Errorf("directory tree exceeds %d entries", maximumDirectoryTreeEntries)
		}
		entry, err := snapshot.scanEntry(directory, name, relative)
		if err != nil {
			return err
		}
		if entry.Path != "" {
			snapshot.entries = append(snapshot.entries, entry)
		}
	}

	namesAfter, err := readSortedTreeNames(directory)
	if err != nil {
		return fmt.Errorf("relist directory %q: %w", prefix, err)
	}
	if !equalTreeNames(names, namesAfter) {
		return fmt.Errorf("directory %q changed while snapshotting", prefix)
	}
	after, err := fstatTreeIdentity(int(directory.Fd()))
	if err != nil {
		return fmt.Errorf("reinspect directory %q: %w", prefix, err)
	}
	if !sameTreeIdentity(before, after) {
		return fmt.Errorf("directory %q identity or metadata changed while snapshotting", prefix)
	}
	return nil
}

func (snapshot *directoryTreeSnapshot) scanEntry(parent *os.File, name, relative string) (TreeEntry, error) {
	metadataFD, err := syscall.Openat(
		int(parent.Fd()),
		name,
		treeOpenPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("open path %q without following symbolic links: %w", relative, err)
	}
	defer syscall.Close(metadataFD)
	identity, err := fstatTreeIdentity(metadataFD)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("inspect path %q: %w", relative, err)
	}
	if identity.mode&0o7000 != 0 {
		return TreeEntry{}, fmt.Errorf("path %q has setuid, setgid, or sticky permission bits", relative)
	}

	switch identity.mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		return TreeEntry{}, fmt.Errorf("path %q is a symbolic link", relative)
	case syscall.S_IFDIR:
		return snapshot.scanDirectoryEntry(parent, name, relative, identity)
	case syscall.S_IFREG:
		return snapshot.scanRegularFileEntry(metadataFD, relative, identity)
	default:
		return TreeEntry{}, fmt.Errorf("path %q is a special file", relative)
	}
}

func (snapshot *directoryTreeSnapshot) scanDirectoryEntry(parent *os.File, name, relative string, expected treeFileIdentity) (TreeEntry, error) {
	fd, err := syscall.Openat(
		int(parent.Fd()),
		name,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("open directory %q: %w", relative, err)
	}
	directory := os.NewFile(uintptr(fd), relative)
	if directory == nil {
		_ = syscall.Close(fd)
		return TreeEntry{}, fmt.Errorf("construct directory handle for %q", relative)
	}
	defer directory.Close()
	opened, err := fstatTreeIdentity(fd)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("inspect opened directory %q: %w", relative, err)
	}
	if !sameTreeIdentity(expected, opened) {
		return TreeEntry{}, fmt.Errorf("directory %q changed while opening", relative)
	}

	entry := TreeEntry{
		Path: relative, Type: TreeEntryDirectory, Mode: formatTreeMode(expected.mode),
		SizeBytes: 0, Digest: Sum(nil),
	}
	// Append the directory before walking descendants so parent records are
	// present even though NewDirectoryTree performs the final global sort.
	snapshot.entries = append(snapshot.entries, entry)
	if len(snapshot.entries) > maximumDirectoryTreeEntries {
		return TreeEntry{}, fmt.Errorf("directory tree exceeds %d entries", maximumDirectoryTreeEntries)
	}
	if err := snapshot.scanDirectory(directory, relative); err != nil {
		return TreeEntry{}, err
	}
	after, err := fstatTreeIdentity(fd)
	if err != nil || !sameTreeIdentity(expected, after) {
		return TreeEntry{}, fmt.Errorf("directory %q changed while snapshotting", relative)
	}
	// The caller normally appends its returned record. Return a zero marker so
	// it can recognize that this directory was already appended before descent.
	return TreeEntry{}, nil
}

func (snapshot *directoryTreeSnapshot) scanRegularFileEntry(metadataFD int, relative string, expected treeFileIdentity) (TreeEntry, error) {
	if expected.size < 0 {
		return TreeEntry{}, fmt.Errorf("regular file %q has a negative size", relative)
	}
	size := uint64(expected.size)
	if math.MaxUint64-snapshot.sizeBytes < size {
		return TreeEntry{}, errors.New("directory tree regular-file size sum overflows uint64")
	}

	// Reopen the already validated O_PATH handle instead of resolving the
	// parent/name pair a second time. This prevents a path swap from causing a
	// FIFO or device to be opened, even transiently, before the identity check.
	fd, err := syscall.Open(
		fmt.Sprintf("/proc/self/fd/%d", metadataFD),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("open regular file %q: %w", relative, err)
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		_ = syscall.Close(fd)
		return TreeEntry{}, fmt.Errorf("construct regular file handle for %q", relative)
	}
	defer file.Close()
	opened, err := fstatTreeIdentity(fd)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("inspect opened regular file %q: %w", relative, err)
	}
	if !sameTreeIdentity(expected, opened) || opened.mode&syscall.S_IFMT != syscall.S_IFREG {
		return TreeEntry{}, fmt.Errorf("regular file %q changed while opening", relative)
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		return TreeEntry{}, fmt.Errorf("clear nonblocking mode for regular file %q: %w", relative, err)
	}

	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("hash regular file %q: %w", relative, err)
	}
	if written != expected.size {
		return TreeEntry{}, fmt.Errorf("regular file %q size changed while hashing", relative)
	}
	after, err := fstatTreeIdentity(fd)
	if err != nil {
		return TreeEntry{}, fmt.Errorf("reinspect regular file %q: %w", relative, err)
	}
	if !sameTreeIdentity(expected, after) {
		return TreeEntry{}, fmt.Errorf("regular file %q identity or metadata changed while hashing", relative)
	}

	snapshot.sizeBytes += size
	return TreeEntry{
		Path: relative, Type: TreeEntryRegularFile, Mode: formatTreeMode(expected.mode),
		SizeBytes: size, Digest: Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))),
	}, nil
}

func validateDirectoryTreeRootPath(root string) error {
	if root == "" || root == string(filepath.Separator) || !filepath.IsAbs(root) ||
		filepath.Clean(root) != root || strings.IndexByte(root, 0) >= 0 || !utf8.ValidString(root) {
		return errors.New("directory tree root must be a clean absolute UTF-8 path other than /")
	}
	return nil
}

func openDirectoryTreeRoot(root string) (*os.File, treeFileIdentity, error) {
	fd, err := syscall.Open(
		string(filepath.Separator),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, treeFileIdentity{}, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(fd)
		return nil, treeFileIdentity{}, errors.New("construct filesystem root handle")
	}
	components := strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		nextFD, err := syscall.Openat(
			int(current.Fd()),
			component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
			0,
		)
		if err != nil {
			current.Close()
			return nil, treeFileIdentity{}, fmt.Errorf("open component %q without following symbolic links: %w", component, err)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			current.Close()
			return nil, treeFileIdentity{}, fmt.Errorf("construct directory handle for component %q", component)
		}
		if err := current.Close(); err != nil {
			next.Close()
			return nil, treeFileIdentity{}, fmt.Errorf("close prior directory component: %w", err)
		}
		current = next
	}
	identity, err := fstatTreeIdentity(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, treeFileIdentity{}, fmt.Errorf("inspect directory tree root: %w", err)
	}
	return current, identity, nil
}

func readSortedTreeNames(directory *os.File) ([]string, error) {
	if _, err := directory.Seek(0, 0); err != nil {
		return nil, err
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func equalTreeNames(left, right []string) bool {
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

func validateTreeDirectoryIdentity(label string, identity treeFileIdentity) error {
	if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%s must be a directory", label)
	}
	if identity.mode&0o7000 != 0 {
		return fmt.Errorf("%s has setuid, setgid, or sticky permission bits", label)
	}
	return nil
}

func fstatTreeIdentity(fd int) (treeFileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return treeFileIdentity{}, err
	}
	return treeFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, mode: stat.Mode,
		mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func sameTreeIdentity(left, right treeFileIdentity) bool {
	return left.device == right.device && left.inode == right.inode &&
		left.size == right.size && left.mode == right.mode &&
		left.mtime == right.mtime && left.ctime == right.ctime
}

func formatTreeMode(mode uint32) string {
	return fmt.Sprintf("%04o", mode&0o777)
}

func quotedTreePath(path string) string {
	if path == "" {
		return "root"
	}
	return fmt.Sprintf("%q", path)
}
