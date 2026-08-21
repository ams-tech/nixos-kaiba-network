//go:build linux

// Package fixturesnapshot copies a synthetic regular-file provisioning target
// without granting any block-device capability.
package fixturesnapshot

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	seekData       = 3
	seekHole       = 4
	openPath       = 0x200000
	scanBufferSize = 1024 * 1024
	scanBlockSize  = 4096
)

var ErrSourceBusy = errors.New("source fixture is busy")

type Options struct {
	Source       string
	Destination  string
	ExpectedSize uint64
}

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

type pinnedParent struct {
	file     *os.File
	leaf     string
	identity fileIdentity
}

func Snapshot(options Options) (result error) {
	if err := validateOptions(options); err != nil {
		return err
	}
	expectedSize := int64(options.ExpectedSize)

	sourcePathIdentity, err := lstatIdentity(options.Source)
	if err != nil {
		return fmt.Errorf("lstat source: %w", err)
	}
	if err := validateRegularIdentity("source", sourcePathIdentity, expectedSize); err != nil {
		return err
	}
	sourceParent, err := pinParent(options.Source)
	if err != nil {
		return fmt.Errorf("pin source parent without following symlinks: %w", err)
	}
	defer sourceParent.file.Close()

	source, sourceFDIdentity, err := openValidatedSource(sourceParent, sourcePathIdentity, expectedSize)
	if err != nil {
		return err
	}
	sourceFD := int(source.Fd())
	locked := false
	defer func() {
		if locked {
			_ = syscall.Flock(sourceFD, syscall.LOCK_UN)
		}
		_ = source.Close()
	}()

	if err := syscall.Flock(sourceFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("%w: another process holds a lock", ErrSourceBusy)
		}
		return fmt.Errorf("lock source fixture exclusively: %w", err)
	}
	locked = true
	if err := revalidateSource(options.Source, sourceParent, sourceFD, sourceFDIdentity, expectedSize); err != nil {
		return fmt.Errorf("revalidate locked source before copy: %w", err)
	}

	destinationParent, err := pinParent(options.Destination)
	if err != nil {
		return fmt.Errorf("pin destination parent without following symlinks: %w", err)
	}
	defer destinationParent.file.Close()
	if _, err := lstatIdentity(options.Destination); err == nil {
		return errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat destination: %w", err)
	}

	destinationFD, err := syscall.Openat(
		int(destinationParent.file.Fd()),
		destinationParent.leaf,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("destination already exists")
		}
		return fmt.Errorf("create destination exclusively: %w", err)
	}
	destination := os.NewFile(uintptr(destinationFD), options.Destination)
	if destination == nil {
		_ = syscall.Close(destinationFD)
		return errors.New("construct destination file handle")
	}
	destinationIdentity, err := fstatIdentity(destinationFD)
	if err != nil {
		_ = destination.Close()
		removeErr := unlinkPinnedLeaf(destinationParent)
		return errors.Join(fmt.Errorf("fstat new destination: %w", err), removeErr)
	}
	defer func() {
		if err := destination.Close(); err != nil && result == nil {
			result = fmt.Errorf("close destination: %w", err)
		}
		if result != nil {
			result = errors.Join(result, removePartialDestination(destinationParent, destinationIdentity))
		}
	}()
	if err := validateRegularIdentity("new destination", destinationIdentity, 0); err != nil {
		return err
	}
	if err := syscall.Fchmod(destinationFD, 0o600); err != nil {
		return fmt.Errorf("set destination mode: %w", err)
	}

	if err := copySparse(source, destination, expectedSize); err != nil {
		return fmt.Errorf("copy sparse fixture: %w", err)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("fsync destination: %w", err)
	}
	if err := revalidateDestination(options.Destination, destinationParent, destinationFD, destinationIdentity, expectedSize); err != nil {
		return fmt.Errorf("revalidate destination after copy: %w", err)
	}
	if err := revalidateSource(options.Source, sourceParent, sourceFD, sourceFDIdentity, expectedSize); err != nil {
		return fmt.Errorf("revalidate locked source after copy: %w", err)
	}
	if err := destinationParent.file.Sync(); err != nil {
		return fmt.Errorf("fsync destination parent: %w", err)
	}
	return nil
}

func validateOptions(options Options) error {
	if err := validatePath("source", options.Source); err != nil {
		return err
	}
	if err := validatePath("destination", options.Destination); err != nil {
		return err
	}
	if options.Source == options.Destination {
		return errors.New("source and destination must be different paths")
	}
	if options.ExpectedSize == 0 {
		return errors.New("expected size must be greater than zero")
	}
	if options.ExpectedSize > math.MaxInt64 {
		return errors.New("expected size exceeds the supported regular-file size")
	}
	return nil
}

func validatePath(label, path string) error {
	if path == "" || path == string(filepath.Separator) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	if path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return fmt.Errorf("%s must not be /dev or below /dev", label)
	}
	return nil
}

func pinParent(path string) (*pinnedParent, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	leaf := components[len(components)-1]
	components = components[:len(components)-1]

	fd, err := syscall.Open(
		string(filepath.Separator),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct filesystem root handle")
	}
	for _, component := range components {
		nextFD, err := syscall.Openat(
			int(current.Fd()),
			component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
			0,
		)
		if err != nil {
			current.Close()
			return nil, fmt.Errorf("open directory component %q without following symlinks: %w", component, err)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			current.Close()
			return nil, fmt.Errorf("construct handle for directory component %q", component)
		}
		if err := current.Close(); err != nil {
			next.Close()
			return nil, fmt.Errorf("close prior directory component: %w", err)
		}
		current = next
	}
	identity, err := fstatIdentity(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, fmt.Errorf("fstat pinned parent: %w", err)
	}
	if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
		current.Close()
		return nil, errors.New("pinned parent is not a directory")
	}
	return &pinnedParent{file: current, leaf: leaf, identity: identity}, nil
}

func statPinnedLeaf(parent *pinnedParent) (fileIdentity, error) {
	fd, err := syscall.Openat(
		int(parent.file.Fd()),
		parent.leaf,
		openPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fileIdentity{}, err
	}
	defer syscall.Close(fd)
	return fstatIdentity(fd)
}

func openValidatedSource(parent *pinnedParent, expected fileIdentity, expectedSize int64) (*os.File, fileIdentity, error) {
	pathFD, err := syscall.Openat(
		int(parent.file.Fd()),
		parent.leaf,
		openPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open source metadata handle without following symlinks: %w", err)
	}
	defer syscall.Close(pathFD)
	pathIdentity, err := fstatIdentity(pathFD)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("fstat source metadata handle: %w", err)
	}
	if err := validateRegularIdentity("source metadata handle", pathIdentity, expectedSize); err != nil {
		return nil, fileIdentity{}, err
	}
	if !sameIdentity(expected, pathIdentity) {
		return nil, fileIdentity{}, errors.New("source identity changed while its metadata handle was opened")
	}

	fd, err := syscall.Open(
		fmt.Sprintf("/proc/self/fd/%d", pathFD),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open validated regular source through procfd: %w", err)
	}
	file := os.NewFile(uintptr(fd), parent.leaf)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fileIdentity{}, errors.New("construct readable source file handle")
	}
	identity, err := fstatIdentity(fd)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, fmt.Errorf("fstat readable source: %w", err)
	}
	if err := validateRegularIdentity("readable source", identity, expectedSize); err != nil {
		file.Close()
		return nil, fileIdentity{}, err
	}
	if !sameIdentity(pathIdentity, identity) {
		file.Close()
		return nil, fileIdentity{}, errors.New("readable source identity differs from its validated metadata handle")
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		file.Close()
		return nil, fileIdentity{}, fmt.Errorf("clear nonblocking mode on regular source: %w", err)
	}
	return file, identity, nil
}

func lstatIdentity(path string) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(stat), nil
}

func fstatIdentity(fd int) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(stat), nil
}

func identityFromStat(stat syscall.Stat_t) fileIdentity {
	return fileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		size:   stat.Size,
		mode:   stat.Mode,
		mtime:  stat.Mtim,
		ctime:  stat.Ctim,
	}
}

func validateRegularIdentity(label string, identity fileIdentity, expectedSize int64) error {
	if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if identity.size != expectedSize {
		return fmt.Errorf("%s size is %d bytes, expected %d", label, identity.size, expectedSize)
	}
	return nil
}

func sameIdentity(left, right fileIdentity) bool {
	return left.device == right.device &&
		left.inode == right.inode &&
		left.size == right.size &&
		left.mtime == right.mtime &&
		left.ctime == right.ctime
}

func sameObject(left, right fileIdentity) bool {
	return left.device == right.device && left.inode == right.inode
}

func revalidateSource(path string, parent *pinnedParent, fd int, expected fileIdentity, expectedSize int64) error {
	pathIdentity, err := lstatIdentity(path)
	if err != nil {
		return fmt.Errorf("lstat source: %w", err)
	}
	if err := validateRegularIdentity("source", pathIdentity, expectedSize); err != nil {
		return err
	}
	fdIdentity, err := fstatIdentity(fd)
	if err != nil {
		return fmt.Errorf("fstat source: %w", err)
	}
	if err := validateRegularIdentity("opened source", fdIdentity, expectedSize); err != nil {
		return err
	}
	if !sameIdentity(expected, pathIdentity) || !sameIdentity(expected, fdIdentity) {
		return errors.New("source identity, size, or timestamps changed")
	}
	if err := revalidatePinnedPath(path, parent, expected, expectedSize, true); err != nil {
		return err
	}
	return nil
}

func revalidateDestination(path string, parent *pinnedParent, fd int, expected fileIdentity, expectedSize int64) error {
	pathIdentity, err := lstatIdentity(path)
	if err != nil {
		return fmt.Errorf("lstat destination: %w", err)
	}
	if err := validateRegularIdentity("destination", pathIdentity, expectedSize); err != nil {
		return err
	}
	fdIdentity, err := fstatIdentity(fd)
	if err != nil {
		return fmt.Errorf("fstat destination: %w", err)
	}
	if err := validateRegularIdentity("opened destination", fdIdentity, expectedSize); err != nil {
		return err
	}
	if !sameObject(expected, pathIdentity) || !sameObject(expected, fdIdentity) {
		return errors.New("destination device, inode, or size changed")
	}
	if pathIdentity.mode&0o777 != 0o600 || fdIdentity.mode&0o777 != 0o600 {
		return errors.New("destination mode is not 0600")
	}
	if err := revalidatePinnedPath(path, parent, expected, expectedSize, false); err != nil {
		return err
	}
	return nil
}

func revalidatePinnedPath(path string, parent *pinnedParent, expected fileIdentity, expectedSize int64, exactIdentity bool) error {
	currentParent, err := pinParent(path)
	if err != nil {
		return fmt.Errorf("re-pin path parent without following symlinks: %w", err)
	}
	defer currentParent.file.Close()
	if !sameObject(parent.identity, currentParent.identity) {
		return errors.New("path parent identity changed")
	}
	leafIdentity, err := statPinnedLeaf(currentParent)
	if err != nil {
		return fmt.Errorf("stat pinned path leaf: %w", err)
	}
	if err := validateRegularIdentity("pinned path leaf", leafIdentity, expectedSize); err != nil {
		return err
	}
	if exactIdentity {
		if !sameIdentity(expected, leafIdentity) {
			return errors.New("pinned path leaf identity, size, or timestamps changed")
		}
	} else if !sameObject(expected, leafIdentity) {
		return errors.New("pinned path leaf identity changed")
	}
	return nil
}

func copySparse(source, destination *os.File, size int64) error {
	if size == 0 {
		return destination.Truncate(0)
	}
	dataOffset, err := syscall.Seek(int(source.Fd()), 0, seekData)
	if errors.Is(err, syscall.ENXIO) {
		return destination.Truncate(size)
	}
	if seekUnsupported(err) {
		return copySparseByScanning(source, destination, size)
	}
	if err != nil {
		return fmt.Errorf("seek first data extent: %w", err)
	}

	for dataOffset < size {
		holeOffset, err := syscall.Seek(int(source.Fd()), dataOffset, seekHole)
		if errors.Is(err, syscall.ENXIO) {
			holeOffset = size
		} else if err != nil {
			return fmt.Errorf("seek hole after offset %d: %w", dataOffset, err)
		}
		if holeOffset > size {
			holeOffset = size
		}
		if holeOffset <= dataOffset {
			return fmt.Errorf("invalid data extent [%d,%d)", dataOffset, holeOffset)
		}
		if _, err := source.Seek(dataOffset, io.SeekStart); err != nil {
			return fmt.Errorf("seek source data extent: %w", err)
		}
		if _, err := destination.Seek(dataOffset, io.SeekStart); err != nil {
			return fmt.Errorf("seek destination data extent: %w", err)
		}
		length := holeOffset - dataOffset
		copied, err := io.CopyN(destination, source, length)
		if err != nil {
			return fmt.Errorf("copy data extent [%d,%d): %w", dataOffset, holeOffset, err)
		}
		if copied != length {
			return fmt.Errorf("copied %d bytes for data extent [%d,%d), expected %d", copied, dataOffset, holeOffset, length)
		}

		dataOffset, err = syscall.Seek(int(source.Fd()), holeOffset, seekData)
		if errors.Is(err, syscall.ENXIO) {
			break
		}
		if err != nil {
			return fmt.Errorf("seek data after offset %d: %w", holeOffset, err)
		}
	}
	return destination.Truncate(size)
}

func seekUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP)
}

func copySparseByScanning(source, destination *os.File, size int64) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind source: %w", err)
	}
	if err := destination.Truncate(0); err != nil {
		return fmt.Errorf("reset destination: %w", err)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind destination: %w", err)
	}

	buffer := make([]byte, scanBufferSize)
	remaining := size
	for remaining > 0 {
		length := int64(len(buffer))
		if remaining < length {
			length = remaining
		}
		chunk := buffer[:int(length)]
		if _, err := io.ReadFull(source, chunk); err != nil {
			return fmt.Errorf("read source for sparse scan: %w", err)
		}
		for offset := 0; offset < len(chunk); offset += scanBlockSize {
			end := offset + scanBlockSize
			if end > len(chunk) {
				end = len(chunk)
			}
			block := chunk[offset:end]
			if allZero(block) {
				if _, err := destination.Seek(int64(len(block)), io.SeekCurrent); err != nil {
					return fmt.Errorf("seek over zero block: %w", err)
				}
				continue
			}
			if err := writeAll(destination, block); err != nil {
				return fmt.Errorf("write nonzero block: %w", err)
			}
		}
		remaining -= length
	}
	return destination.Truncate(size)
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

func writeAll(destination *os.File, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func removePartialDestination(parent *pinnedParent, expected fileIdentity) error {
	identity, err := statPinnedLeaf(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat partial destination: %w", err)
	}
	if !sameObject(expected, identity) {
		return errors.New("partial destination path identity changed; refusing to remove it")
	}
	return unlinkPinnedLeaf(parent)
}

func unlinkPinnedLeaf(parent *pinnedParent) error {
	if err := syscall.Unlinkat(int(parent.file.Fd()), parent.leaf); err != nil {
		return fmt.Errorf("remove partial destination: %w", err)
	}
	if err := parent.file.Sync(); err != nil {
		return fmt.Errorf("fsync destination parent after removal: %w", err)
	}
	return nil
}
