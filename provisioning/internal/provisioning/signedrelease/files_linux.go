//go:build linux

package signedrelease

import (
	"bytes"
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

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

type regularSource struct {
	path     string
	contents []byte
	digest   bundle.Digest
	size     uint64
}

type treeSource struct {
	path string
	tree bundle.DirectoryTree
}

func validateAbsolutePath(value string) error {
	if value == "" || value == string(filepath.Separator) || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
		return errors.New("path must be a clean absolute UTF-8 path other than /")
	}
	return nil
}

func openAbsolute(path string, directory bool) (*os.File, fileIdentity, error) {
	if err := validateAbsolutePath(path); err != nil {
		return nil, fileIdentity{}, err
	}
	rootFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), "/")
	if current == nil {
		_ = syscall.Close(rootFD)
		return nil, fileIdentity{}, errors.New("construct filesystem root handle")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		last := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last || directory {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= syscall.O_NONBLOCK
		}
		fd, err := syscall.Openat(int(current.Fd()), component, flags, 0)
		if err != nil {
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("open component %q without following symbolic links: %w", component, err)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = syscall.Close(fd)
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("construct handle for component %q", component)
		}
		current.Close()
		current = next
	}
	identity, err := statIdentity(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, fileIdentity{}, err
	}
	if directory {
		if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
			current.Close()
			return nil, fileIdentity{}, errors.New("path is not a directory")
		}
	} else {
		if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
			current.Close()
			return nil, fileIdentity{}, errors.New("path is not a regular file")
		}
		if err := syscall.SetNonblock(int(current.Fd()), false); err != nil {
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("clear nonblocking mode: %w", err)
		}
	}
	if identity.mode&07000 != 0 {
		current.Close()
		return nil, fileIdentity{}, errors.New("path has unsupported special permission bits")
	}
	return current, identity, nil
}

func statIdentity(fd int) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, mode: stat.Mode,
		mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func sameIdentity(left, right fileIdentity) bool {
	return left == right
}

func requireSameDirectoryNode(path string, expected fileIdentity) error {
	directory, actual, err := openAbsolute(path, true)
	if err != nil {
		return err
	}
	directory.Close()
	if actual.device != expected.device || actual.inode != expected.inode || actual.mode != expected.mode {
		return errors.New("directory path no longer identifies the originally opened node")
	}
	return nil
}

func inspectRegular(path string, maximum int64, retain bool) (regularSource, error) {
	file, before, err := openAbsolute(path, false)
	if err != nil {
		return regularSource{}, err
	}
	defer file.Close()
	if before.size < 0 || before.size > maximum {
		return regularSource{}, fmt.Errorf("regular file size must be between 0 and %d bytes", maximum)
	}
	hash := sha256.New()
	var destination io.Writer = hash
	var buffer bytes.Buffer
	if retain {
		destination = io.MultiWriter(hash, &buffer)
	}
	written, err := copyExact(destination, file)
	if err != nil {
		return regularSource{}, err
	}
	if written != before.size {
		return regularSource{}, errors.New("regular file size changed while reading")
	}
	after, err := statIdentity(int(file.Fd()))
	if err != nil || !sameIdentity(before, after) {
		return regularSource{}, errors.New("regular file identity or metadata changed while reading")
	}
	result := regularSource{
		path: path, digest: bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), size: uint64(written),
	}
	if retain {
		result.contents = buffer.Bytes()
	}
	return result, nil
}

func copyExact(destination io.Writer, source io.Reader) (int64, error) {
	return io.CopyBuffer(destination, source, make([]byte, 64*1024))
}

func readExactDirectory(path string, limits map[string]int64) (map[string]regularSource, error) {
	directory, before, err := openAbsolute(path, true)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	wanted := make([]string, 0, len(limits))
	for name := range limits {
		if name == "" || filepath.Base(name) != name {
			return nil, errors.New("invalid fixed directory file name")
		}
		wanted = append(wanted, name)
	}
	sort.Strings(wanted)
	if err := requireExactNames(directory, wanted); err != nil {
		return nil, err
	}
	result := make(map[string]regularSource, len(wanted))
	for _, name := range wanted {
		fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		file := os.NewFile(uintptr(fd), name)
		identity, statErr := statIdentity(fd)
		if statErr != nil || identity.mode&syscall.S_IFMT != syscall.S_IFREG || identity.mode&07000 != 0 {
			file.Close()
			return nil, fmt.Errorf("%s is not an ordinary regular file", name)
		}
		if identity.size <= 0 || identity.size > limits[name] {
			file.Close()
			return nil, fmt.Errorf("%s size must be between 1 and %d bytes", name, limits[name])
		}
		if err := syscall.SetNonblock(fd, false); err != nil {
			file.Close()
			return nil, err
		}
		var contents bytes.Buffer
		hash := sha256.New()
		written, readErr := copyExact(io.MultiWriter(&contents, hash), file)
		after, afterErr := statIdentity(fd)
		file.Close()
		if readErr != nil || afterErr != nil || written != identity.size || !sameIdentity(identity, after) {
			return nil, fmt.Errorf("%s changed while reading", name)
		}
		result[name] = regularSource{
			path: filepath.Join(path, name), contents: contents.Bytes(),
			digest: bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), size: uint64(written),
		}
	}
	if err := requireExactNames(directory, wanted); err != nil {
		return nil, fmt.Errorf("directory changed while reading: %w", err)
	}
	after, err := statIdentity(int(directory.Fd()))
	if err != nil || !sameIdentity(before, after) {
		return nil, errors.New("directory identity or metadata changed while reading")
	}
	return result, nil
}

func requireExactNames(directory *os.File, wanted []string) error {
	if _, err := directory.Seek(0, 0); err != nil {
		return err
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	sort.Strings(names)
	if len(names) != len(wanted) {
		return fmt.Errorf("directory must contain exactly %s", strings.Join(wanted, ", "))
	}
	for index := range names {
		if names[index] != wanted[index] {
			return fmt.Errorf("directory must contain exactly %s", strings.Join(wanted, ", "))
		}
	}
	return nil
}

func inspectTree(path string) (treeSource, error) {
	tree, err := bundle.SnapshotDirectoryTree(path)
	if err != nil {
		return treeSource{}, err
	}
	size, err := tree.SizeBytes()
	if err != nil {
		return treeSource{}, err
	}
	if err := validateTreePayloadSize(size); err != nil {
		return treeSource{}, err
	}
	for _, entry := range tree.Entries {
		if entry.Type != bundle.TreeEntryRegularFile {
			continue
		}
		if _, err := inspectRegular(filepath.Join(path, filepath.FromSlash(entry.Path)), int64(entry.SizeBytes), false); err != nil {
			return treeSource{}, fmt.Errorf("inspect tree path %q: %w", entry.Path, err)
		}
	}
	again, err := bundle.SnapshotDirectoryTree(path)
	if err != nil {
		return treeSource{}, err
	}
	left, _ := tree.CanonicalJSON()
	right, _ := again.CanonicalJSON()
	if !bytes.Equal(left, right) {
		return treeSource{}, errors.New("directory tree changed while inspecting")
	}
	return treeSource{path: path, tree: tree}, nil
}

func validateTreePayloadSize(size uint64) error {
	if size == 0 || size > math.MaxInt64 {
		return fmt.Errorf("directory-tree payload size must be between 1 and %d bytes", int64(math.MaxInt64))
	}
	return nil
}

// CompareExactDirectories rejects symlinks and special files and compares all
// paths, file bytes, and permission modes through canonical tree snapshots.
func CompareExactDirectories(left, right string) error {
	leftTree, err := bundle.SnapshotDirectoryTree(left)
	if err != nil {
		return fmt.Errorf("snapshot left directory: %w", err)
	}
	rightTree, err := bundle.SnapshotDirectoryTree(right)
	if err != nil {
		return fmt.Errorf("snapshot right directory: %w", err)
	}
	leftJSON, _ := leftTree.CanonicalJSON()
	rightJSON, _ := rightTree.CanonicalJSON()
	if !bytes.Equal(leftJSON, rightJSON) {
		return errors.New("directories differ in paths, modes, sizes, or contents")
	}
	return nil
}
