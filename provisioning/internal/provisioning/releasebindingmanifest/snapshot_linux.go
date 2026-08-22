//go:build linux

package releasebindingmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const snapshotOpenPath = 0x200000 // Linux O_PATH, absent from some syscall versions.

type snapshotFileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

func snapshotArtifact(role ArtifactRole, path string, mode ValidationMode) (Artifact, error) {
	if err := validateArtifactPath(path, mode); err != nil {
		return Artifact{}, err
	}
	expectedType, supported := expectedArtifactType(role)
	if !supported {
		return Artifact{}, fmt.Errorf("unsupported artifact role %q", role)
	}

	switch expectedType {
	case ArtifactRegularFile:
		return snapshotRegularFile(role, path)
	case ArtifactDirectoryTree:
		tree, err := bundle.SnapshotDirectoryTree(path)
		if err != nil {
			return Artifact{}, err
		}
		digest, err := tree.Digest()
		if err != nil {
			return Artifact{}, fmt.Errorf("derive directory-tree digest: %w", err)
		}
		size, err := tree.SizeBytes()
		if err != nil {
			return Artifact{}, fmt.Errorf("derive directory-tree size: %w", err)
		}
		artifact := Artifact{
			Role: role, Path: path, Type: ArtifactDirectoryTree,
			Mode: tree.RootMode, SizeBytes: size, Digest: digest,
		}
		if err := artifact.Validate(mode); err != nil {
			return Artifact{}, err
		}
		return artifact, nil
	default:
		return Artifact{}, fmt.Errorf("unsupported artifact type %q", expectedType)
	}
}

func snapshotRegularFile(role ArtifactRole, path string) (Artifact, error) {
	parent, parentBefore, basename, err := openSnapshotParent(path)
	if err != nil {
		return Artifact{}, err
	}
	defer parent.Close()

	metadataFD, err := syscall.Openat(
		int(parent.Fd()), basename,
		snapshotOpenPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("open regular-file path without following symbolic links: %w", err)
	}
	defer syscall.Close(metadataFD)
	expected, err := inspectSnapshotFD(metadataFD)
	if err != nil {
		return Artifact{}, fmt.Errorf("inspect regular-file path: %w", err)
	}
	if expected.mode&syscall.S_IFMT == syscall.S_IFLNK {
		return Artifact{}, errors.New("artifact path is a symbolic link")
	}
	if expected.mode&syscall.S_IFMT != syscall.S_IFREG {
		return Artifact{}, errors.New("artifact path is not a regular file")
	}
	if expected.mode&0o7000 != 0 {
		return Artifact{}, errors.New("artifact path has setuid, setgid, or sticky permission bits")
	}
	if expected.size < 0 {
		return Artifact{}, errors.New("artifact regular file has a negative size")
	}

	fd, err := syscall.Open(
		fmt.Sprintf("/proc/self/fd/%d", metadataFD),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("open pinned regular file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return Artifact{}, errors.New("construct pinned regular-file handle")
	}
	defer file.Close()
	opened, err := inspectSnapshotFD(fd)
	if err != nil {
		return Artifact{}, fmt.Errorf("inspect opened regular file: %w", err)
	}
	if !sameSnapshotIdentity(expected, opened) || opened.mode&syscall.S_IFMT != syscall.S_IFREG {
		return Artifact{}, errors.New("artifact regular file changed while opening")
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		return Artifact{}, fmt.Errorf("clear nonblocking regular-file mode: %w", err)
	}

	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return Artifact{}, fmt.Errorf("hash regular file: %w", err)
	}
	if written != expected.size {
		return Artifact{}, errors.New("artifact regular-file size changed while hashing")
	}
	after, err := inspectSnapshotFD(fd)
	if err != nil {
		return Artifact{}, fmt.Errorf("reinspect regular file: %w", err)
	}
	if !sameSnapshotIdentity(expected, after) {
		return Artifact{}, errors.New("artifact regular file changed while hashing")
	}

	parentAfter, err := inspectSnapshotFD(int(parent.Fd()))
	if err != nil || !sameSnapshotIdentity(parentBefore, parentAfter) {
		return Artifact{}, errors.New("artifact regular-file parent changed while hashing")
	}
	reopenedParent, reopenedParentIdentity, reopenedBasename, err := openSnapshotParent(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("reopen regular-file parent path: %w", err)
	}
	defer reopenedParent.Close()
	if reopenedBasename != basename || !sameSnapshotIdentity(parentBefore, reopenedParentIdentity) {
		return Artifact{}, errors.New("artifact regular-file parent path changed while hashing")
	}
	reopenedFD, err := syscall.Openat(
		int(reopenedParent.Fd()), reopenedBasename,
		snapshotOpenPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("reopen regular-file path: %w", err)
	}
	reopened, inspectErr := inspectSnapshotFD(reopenedFD)
	_ = syscall.Close(reopenedFD)
	if inspectErr != nil || !sameSnapshotIdentity(expected, reopened) {
		return Artifact{}, errors.New("artifact regular-file path changed while hashing")
	}

	return Artifact{
		Role: role, Path: path, Type: ArtifactRegularFile,
		Mode:      fmt.Sprintf("%04o", expected.mode&0o777),
		SizeBytes: uint64(expected.size),
		Digest:    bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))),
	}, nil
}

func openSnapshotParent(path string) (*os.File, snapshotFileIdentity, string, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) < 1 || components[len(components)-1] == "" {
		return nil, snapshotFileIdentity{}, "", errors.New("artifact path has no basename")
	}
	basename := components[len(components)-1]
	components = components[:len(components)-1]

	fd, err := syscall.Open(
		string(filepath.Separator),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, snapshotFileIdentity{}, "", fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(fd)
		return nil, snapshotFileIdentity{}, "", errors.New("construct filesystem-root handle")
	}

	for _, component := range components {
		nextFD, err := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
			0,
		)
		if err != nil {
			current.Close()
			return nil, snapshotFileIdentity{}, "", fmt.Errorf("open path component %q without following symbolic links: %w", component, err)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			current.Close()
			return nil, snapshotFileIdentity{}, "", fmt.Errorf("construct directory handle for component %q", component)
		}
		if err := current.Close(); err != nil {
			next.Close()
			return nil, snapshotFileIdentity{}, "", fmt.Errorf("close prior path component: %w", err)
		}
		current = next
	}
	identity, err := inspectSnapshotFD(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, snapshotFileIdentity{}, "", fmt.Errorf("inspect regular-file parent: %w", err)
	}
	if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
		current.Close()
		return nil, snapshotFileIdentity{}, "", errors.New("artifact parent is not a directory")
	}
	return current, identity, basename, nil
}

func inspectSnapshotFD(fd int) (snapshotFileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return snapshotFileIdentity{}, err
	}
	return snapshotFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink),
		size: stat.Size, mode: stat.Mode, mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func sameSnapshotIdentity(left, right snapshotFileIdentity) bool {
	return left.device == right.device && left.inode == right.inode && left.links == right.links &&
		left.size == right.size && left.mode == right.mode &&
		left.mtime == right.mtime && left.ctime == right.ctime
}
