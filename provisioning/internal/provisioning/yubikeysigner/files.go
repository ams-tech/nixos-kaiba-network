package yubikeysigner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	maxPublicKeyBytes = 64 * 1024
	maxConfigBytes    = 64 * 1024
	minPINFileBytes   = 7 // six-byte PIV PIN plus LF
	maxPINFileBytes   = 9 // eight-byte PIV PIN plus LF
)

func validatePrivateDirectory(path string, runtimeOwnerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("temporary root must be a non-symlink directory")
	}
	identity, err := statIdentity(info)
	if err != nil {
		return err
	}
	if identity.uid != runtimeOwnerUID || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("private directory must be runtime-owned with mode 0700")
	}
	return nil
}

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	uid    uint32
	gid    uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

func cleanAbsolutePath(name, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be an absolute clean path", name)
	}
	for _, character := range path {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '/' && character != '.' &&
			character != '_' && character != '-' && character != '+' {
			return fmt.Errorf("%s contains a non-canonical path character", name)
		}
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, errors.New("path must identify a regular non-symlink file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("file changed while opening")
	}
	return file, opened, nil
}

func statIdentity(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("file ownership metadata is unavailable")
	}
	return fileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size,
		mode: stat.Mode, uid: stat.Uid, gid: stat.Gid,
		mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func trustedFile(path string, ownerUID uint32, executable bool, maxBytes int64) ([]byte, error) {
	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	identity, err := statIdentity(info)
	if err != nil {
		return nil, err
	}
	if identity.uid != ownerUID {
		return nil, fmt.Errorf("file owner UID is %d, want %d", identity.uid, ownerUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("file must not be group- or world-writable")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("file must not have special permission bits")
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("file is not executable")
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("file size must be between 1 and %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("file changed while reading")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil {
		return nil, err
	}
	if identity != afterIdentity {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func validateCredential(path string, runtimeOwnerUID uint32) (fileIdentity, error) {
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fileIdentity{}, err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fileIdentity{}, errors.New("credential parent must be a non-symlink directory")
	}
	parentIdentity, err := statIdentity(parentInfo)
	if err != nil {
		return fileIdentity{}, err
	}
	if parentIdentity.uid != 0 && parentIdentity.uid != runtimeOwnerUID {
		return fileIdentity{}, errors.New("credential parent has an untrusted owner")
	}
	if parentInfo.Mode().Perm()&0o077 != 0 {
		return fileIdentity{}, errors.New("credential parent must not grant group or world access")
	}
	if parentInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileIdentity{}, errors.New("credential parent must not have special permission bits")
	}

	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return fileIdentity{}, err
	}
	defer file.Close()
	identity, err := statIdentity(info)
	if err != nil {
		return fileIdentity{}, err
	}
	if identity.uid != runtimeOwnerUID {
		return fileIdentity{}, fmt.Errorf("credential owner UID is %d, want runtime UID %d", identity.uid, runtimeOwnerUID)
	}
	if info.Mode().Perm() != 0o400 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileIdentity{}, errors.New("credential mode must be 0400")
	}
	if info.Size() < minPINFileBytes || info.Size() > maxPINFileBytes {
		return fileIdentity{}, fmt.Errorf("credential size must be between %d and %d bytes", minPINFileBytes, maxPINFileBytes)
	}
	// Deliberately do not read the PIN. The fixed provider configuration is the
	// only component that consumes this file.
	return identity, nil
}

func validateUnchanged(path string, expected fileIdentity) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("file is no longer a regular non-symlink file")
	}
	actual, err := statIdentity(info)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("file changed during signing")
	}
	return nil
}

func snapshotInput(sourcePath, destinationPath string, runtimeOwnerUID uint32) (fileIdentity, fileIdentity, error) {
	parentInfo, err := os.Lstat(filepath.Dir(sourcePath))
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fileIdentity{}, fileIdentity{}, errors.New("input parent must be a non-symlink directory")
	}
	parentIdentity, err := statIdentity(parentInfo)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	if parentIdentity.uid != runtimeOwnerUID || parentInfo.Mode().Perm() != 0o700 ||
		parentInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileIdentity{}, fileIdentity{}, errors.New("input parent must be runtime-owned with mode 0700")
	}
	file, info, err := openRegularNoFollow(sourcePath)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	defer file.Close()
	identity, err := statIdentity(info)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	if identity.uid != runtimeOwnerUID {
		return fileIdentity{}, fileIdentity{}, fmt.Errorf("input owner UID is %d, want runtime UID %d", identity.uid, runtimeOwnerUID)
	}
	if info.Mode().Perm() != 0o400 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileIdentity{}, fileIdentity{}, errors.New("input mode must be 0400")
	}
	if info.Size() <= 0 || info.Size() > int64(signing.MaxArtifactBytes) {
		return fileIdentity{}, fileIdentity{}, fmt.Errorf("input size must be between 1 and %d bytes", signing.MaxArtifactBytes)
	}

	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	written, copyErr := io.Copy(destination, io.LimitReader(file, int64(signing.MaxArtifactBytes)+1))
	destinationInfo, statErr := destination.Stat()
	closeErr := destination.Close()
	if copyErr != nil {
		return fileIdentity{}, fileIdentity{}, copyErr
	}
	if statErr != nil {
		return fileIdentity{}, fileIdentity{}, statErr
	}
	if closeErr != nil {
		return fileIdentity{}, fileIdentity{}, closeErr
	}
	if written != info.Size() {
		return fileIdentity{}, fileIdentity{}, errors.New("input changed while copying")
	}
	destinationIdentity, err := statIdentity(destinationInfo)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	after, err := file.Stat()
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	if identity != afterIdentity {
		return fileIdentity{}, fileIdentity{}, errors.New("input changed while copying")
	}
	if err := validateUnchanged(sourcePath, identity); err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	return identity, destinationIdentity, nil
}

func writePrivateFile(path string, data []byte, mode os.FileMode) (fileIdentity, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fileIdentity{}, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fileIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fileIdentity{}, err
	}
	identity, err := statIdentity(info)
	if err != nil {
		_ = file.Close()
		return fileIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return fileIdentity{}, err
	}
	return identity, nil
}

func readSignature(path string, runtimeOwnerUID uint32, expectedObject fileIdentity) ([]byte, fileIdentity, error) {
	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	defer file.Close()
	identity, err := statIdentity(info)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if identity.device != expectedObject.device || identity.inode != expectedObject.inode {
		return nil, fileIdentity{}, errors.New("signature output file was replaced")
	}
	if identity.uid != runtimeOwnerUID || info.Mode().Perm() != 0o600 {
		return nil, fileIdentity{}, errors.New("signature output has unsafe ownership or permissions")
	}
	if info.Size() != int64(signing.RSASignatureBytes) {
		return nil, fileIdentity{}, fmt.Errorf("signature is %d bytes, want %d", info.Size(), signing.RSASignatureBytes)
	}
	signature := make([]byte, signing.RSASignatureBytes)
	if _, err := io.ReadFull(file, signature); err != nil {
		return nil, fileIdentity{}, err
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); err != io.EOF || count != 0 {
		return nil, fileIdentity{}, errors.New("signature output changed while reading")
	}
	return signature, identity, nil
}
