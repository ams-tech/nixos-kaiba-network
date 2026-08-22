//go:build linux

// Package evidencefile publishes one complete canonical evidence object at a
// new path. The final name appears atomically and is never overwritten.
package evidencefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const directoryOpenFlags = syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_DIRECTORY

// These Linux flags are not exposed by the frozen syscall package. Keep the
// raw syscalls here, next to the only code which needs them, instead of making
// evidence publication depend on pathname-based convenience wrappers.
const (
	atEmptyPath       = 0x1000
	atSymlinkFollow   = 0x400
	atSymlinkNoFollow = 0x100
	oTmpfile          = 0x400000 | syscall.O_DIRECTORY
)

func WriteCanonicalNew(path string, data []byte) error {
	return writeCanonicalNew(path, data, false)
}

// WriteCanonicalNewTrusted is the production receipt boundary. In addition to
// atomic no-replace publication, it requires a root-owned output directory
// which group/other users cannot replace. Root-owned sticky ancestors such as
// /tmp are permitted, but the final receipt directory itself is never allowed
// to rely on sticky-bit semantics.
func WriteCanonicalNewTrusted(path string, data []byte) error {
	return writeCanonicalNew(path, data, true)
}

func writeCanonicalNew(path string, data []byte, trusted bool) error {
	directory, base, err := validateOutputPath(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("evidence output cannot be empty")
	}
	parent, parentInfo, err := openDirectoryAbsolute(directory)
	if err != nil {
		return fmt.Errorf("open evidence output directory: %w", err)
	}
	defer parent.Close()
	if trusted {
		if err := requireTrustedDirectoryPath(directory, parentInfo); err != nil {
			return fmt.Errorf("evidence output directory is not trusted: %w", err)
		}
	}
	if err := requireAbsentAt(parent, base); err != nil {
		return err
	}

	file, err := createTemporaryAt(parent)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := writeAll(file, data); err != nil {
		return fmt.Errorf("write evidence temporary: %w", err)
	}
	if err := file.Chmod(0o444); err != nil {
		return fmt.Errorf("freeze evidence permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("fsync evidence temporary: %w", err)
	}
	if err := requireSameDirectoryPath(directory, parentInfo); err != nil {
		return fmt.Errorf("evidence output directory changed before publication: %w", err)
	}
	if trusted {
		if err := requireTrustedDirectoryPath(directory, parentInfo); err != nil {
			return fmt.Errorf("evidence output directory became untrusted before publication: %w", err)
		}
	}
	if err := linkFileAt(file, parent, base); err != nil {
		return fmt.Errorf("publish evidence without replacement: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("fsync evidence directory: %w", err)
	}
	if err := verifyPublishedAt(parent, base, data); err != nil {
		return fmt.Errorf("reopen published evidence: %w", err)
	}
	if err := requireSameDirectoryPath(directory, parentInfo); err != nil {
		return fmt.Errorf("evidence output directory changed after publication: %w", err)
	}
	return nil
}

// ValidateNewPath performs the non-mutating portion of evidence publication.
// Destructive callers use it before touching a target so common output-path
// mistakes fail before the mutation boundary. WriteCanonicalNew still repeats
// every check and atomically refuses a race at publication time.
func ValidateNewPath(path string) error {
	return validateNewPath(path, false)
}

// ValidateTrustedNewPath performs the pre-mutation production check for a
// durable receipt destination. WriteCanonicalNewTrusted repeats it while
// holding the exact parent directory used for publication.
func ValidateTrustedNewPath(path string) error {
	return validateNewPath(path, true)
}

// ReadTrustedExisting reads an existing production evidence object through a
// descriptor pinned beneath an entirely trusted pathname chain. Receipt
// digests are integrity checks, not authentication, so a caller must not use a
// merely caller-owned file as authority for a physical-device ceremony.
//
// The file must be a root-owned, non-symlink regular file with exact 0444
// permissions. The directory chain follows the same policy as trusted output:
// every component is root-owned, writable ancestors must be sticky, and the
// final parent must not be group/other-writable.
func ReadTrustedExisting(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("trusted evidence maximum size must be positive")
	}
	directory, base, err := validateOutputPath(path)
	if err != nil {
		return nil, err
	}
	parent, parentInfo, err := openDirectoryAbsolute(directory)
	if err != nil {
		return nil, fmt.Errorf("open trusted evidence directory: %w", err)
	}
	defer parent.Close()
	if err := requireTrustedDirectoryPath(directory, parentInfo); err != nil {
		return nil, fmt.Errorf("trusted evidence directory is not trusted: %w", err)
	}
	fd, err := syscall.Openat(int(parent.Fd()), base, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open trusted evidence without following links: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct trusted evidence handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect trusted evidence: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
		return nil, errors.New("trusted evidence must be a root-owned non-symlink regular file with exact 0444 permissions")
	}
	if info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("trusted evidence size must be between 1 and %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read trusted evidence: %w", err)
	}
	if int64(len(data)) != info.Size() || int64(len(data)) > maximum {
		return nil, errors.New("trusted evidence size changed while reading or exceeds its fixed bound")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("reinspect trusted evidence: %w", err)
	}
	if !os.SameFile(info, after) || after.Size() != info.Size() || after.Mode() != info.Mode() {
		return nil, errors.New("trusted evidence identity, size, or mode changed while reading")
	}
	if err := requireSameDirectoryPath(directory, parentInfo); err != nil {
		return nil, fmt.Errorf("trusted evidence directory changed while reading: %w", err)
	}
	if err := requireTrustedDirectoryPath(directory, parentInfo); err != nil {
		return nil, fmt.Errorf("trusted evidence directory became untrusted while reading: %w", err)
	}
	return data, nil
}

func validateNewPath(path string, trusted bool) error {
	directory, base, err := validateOutputPath(path)
	if err != nil {
		return err
	}
	parent, parentInfo, err := openDirectoryAbsolute(directory)
	if err != nil {
		return fmt.Errorf("open evidence output directory: %w", err)
	}
	defer parent.Close()
	if trusted {
		if err := requireTrustedDirectoryPath(directory, parentInfo); err != nil {
			return fmt.Errorf("evidence output directory is not trusted: %w", err)
		}
	}
	return requireAbsentAt(parent, base)
}

func validateOutputPath(path string) (string, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return "", "", errors.New("evidence output must be a clean absolute path outside /dev")
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || strings.ContainsRune(base, '\x00') {
		return "", "", errors.New("evidence output basename is invalid")
	}
	return filepath.Dir(path), base, nil
}

// openDirectoryAbsolute walks from an already opened root, rejecting every
// symbolic-link component. The returned descriptor remains the authority for
// all publication operations even if the pathname is concurrently replaced.
func openDirectoryAbsolute(path string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, errors.New("directory path must be clean and absolute")
	}
	fd, err := syscall.Open("/", directoryOpenFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = syscall.Close(fd)
		return nil, nil, errors.New("construct root directory handle")
	}
	if path != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			nextFD, err := syscall.Openat(int(current.Fd()), component, directoryOpenFlags, 0)
			if err != nil {
				_ = current.Close()
				return nil, nil, err
			}
			next := os.NewFile(uintptr(nextFD), component)
			if next == nil {
				_ = syscall.Close(nextFD)
				_ = current.Close()
				return nil, nil, errors.New("construct directory component handle")
			}
			if err := current.Close(); err != nil {
				_ = next.Close()
				return nil, nil, err
			}
			current = next
		}
	}
	info, err := current.Stat()
	if err != nil {
		_ = current.Close()
		return nil, nil, err
	}
	if !info.IsDir() {
		_ = current.Close()
		return nil, nil, errors.New("output parent is not a directory")
	}
	return current, info, nil
}

func requireSameDirectoryPath(path string, expected os.FileInfo) error {
	current, info, err := openDirectoryAbsolute(path)
	if err != nil {
		return err
	}
	defer current.Close()
	if !os.SameFile(expected, info) {
		return errors.New("output directory pathname identifies a different directory")
	}
	return nil
}

func requireTrustedDirectoryPath(path string, expected os.FileInfo) error {
	fd, err := syscall.Open("/", directoryOpenFlags, 0)
	if err != nil {
		return err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = syscall.Close(fd)
		return errors.New("construct trusted root directory handle")
	}
	components := []string{}
	if path != "/" {
		components = strings.Split(strings.TrimPrefix(path, "/"), "/")
	}
	check := func(directory *os.File, final bool) error {
		info, err := directory.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("directory is not owned by root")
		}
		writableByOthers := info.Mode().Perm()&0o022 != 0
		if writableByOthers && (final || info.Mode()&os.ModeSticky == 0) {
			return errors.New("directory is group/other-writable without acceptable ancestor sticky protection")
		}
		return nil
	}
	if err := check(current, len(components) == 0); err != nil {
		_ = current.Close()
		return err
	}
	for index, component := range components {
		nextFD, err := syscall.Openat(int(current.Fd()), component, directoryOpenFlags, 0)
		if err != nil {
			_ = current.Close()
			return err
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return errors.New("construct trusted directory component handle")
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return err
		}
		current = next
		if err := check(current, index == len(components)-1); err != nil {
			_ = current.Close()
			return err
		}
	}
	info, err := current.Stat()
	closeErr := current.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if !os.SameFile(expected, info) {
		return errors.New("trusted output directory pathname identifies a different directory")
	}
	return nil
}

func requireAbsentAt(parent *os.File, name string) error {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("inspect evidence output: %w", err)
	}
	var stat syscall.Stat_t
	_, _, errno := syscall.Syscall6(
		syscall.SYS_NEWFSTATAT,
		parent.Fd(),
		uintptr(unsafe.Pointer(namePointer)),
		uintptr(unsafe.Pointer(&stat)),
		uintptr(atSymlinkNoFollow),
		0,
		0,
	)
	if errno == syscall.ENOENT {
		return nil
	}
	if errno != 0 {
		return fmt.Errorf("inspect evidence output: %w", errno)
	}
	return errors.New("evidence output already exists")
}

func createTemporaryAt(parent *os.File) (*os.File, error) {
	fd, err := syscall.Openat(
		int(parent.Fd()), ".",
		syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|oTmpfile,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("create unnamed evidence temporary: %w", err)
	}
	file := os.NewFile(uintptr(fd), "unnamed evidence temporary")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct evidence temporary handle")
	}
	return file, nil
}

func linkFileAt(file, newDirectory *os.File, newName string) error {
	emptyPath := [1]byte{0}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		file.Fd(),
		uintptr(unsafe.Pointer(&emptyPath[0])),
		newDirectory.Fd(),
		uintptr(unsafe.Pointer(newPointer)),
		uintptr(atEmptyPath),
		0,
	)
	if errno == 0 {
		return nil
	}

	// AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH on some supported kernels.
	// Following the process-owned /proc descriptor is the documented
	// unprivileged O_TMPFILE fallback and still names the open inode, never a
	// replaceable temporary pathname in the output directory.
	if errno != syscall.ENOENT && errno != syscall.EPERM && errno != syscall.EINVAL {
		return errno
	}
	procPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	procPointer, pointerErr := syscall.BytePtrFromString(procPath)
	if pointerErr != nil {
		return pointerErr
	}
	_, _, fallbackErrno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		0,
		uintptr(unsafe.Pointer(procPointer)),
		newDirectory.Fd(),
		uintptr(unsafe.Pointer(newPointer)),
		uintptr(atSymlinkFollow),
		0,
	)
	if fallbackErrno != 0 {
		return errors.Join(errno, fallbackErrno)
	}
	return nil
}

func verifyPublishedAt(parent *os.File, name string, expected []byte) error {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("construct published evidence handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 || info.Size() != int64(len(expected)) {
		return errors.New("published evidence type, permissions, or size differs")
	}
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("published evidence bytes differ")
	}
	return nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
