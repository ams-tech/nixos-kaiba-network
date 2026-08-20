package yubikeysigner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	posixACLAccessXattr  = "system.posix_acl_access"
	posixACLDefaultXattr = "system.posix_acl_default"
	posixACLVersion      = uint32(2)
	posixACLUndefinedID  = ^uint32(0)
	credentialACLSize    = 4 + 8*5

	aclTagUserObject  = uint16(0x01)
	aclTagUser        = uint16(0x02)
	aclTagGroupObject = uint16(0x04)
	aclTagGroup       = uint16(0x08)
	aclTagMask        = uint16(0x10)
	aclTagOther       = uint16(0x20)

	aclPermissionRead    = uint16(0x04)
	aclPermissionExecute = uint16(0x01)
)

type posixACLEntry struct {
	tag        uint16
	permission uint16
	id         uint32
}

type credentialACL struct {
	encoded []byte
	present bool
}

// fgetxattrFile binds ACL inspection to the descriptor that was already
// opened and validated. A path-based xattr read would permit an inode swap
// between the metadata and ACL checks.
func fgetxattrFile(file *os.File, name string, destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, syscall.EINVAL
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}
	var size int
	var callErr error
	controlErr := raw.Control(func(fd uintptr) {
		result, _, errno := syscall.Syscall6(
			syscall.SYS_FGETXATTR,
			fd,
			uintptr(unsafe.Pointer(namePointer)),
			uintptr(unsafe.Pointer(&destination[0])),
			uintptr(len(destination)),
			0,
			0,
		)
		if errno != 0 {
			callErr = errno
			return
		}
		size = int(result)
	})
	runtime.KeepAlive(namePointer)
	runtime.KeepAlive(destination)
	if controlErr != nil {
		return 0, controlErr
	}
	return size, callErr
}

// readCredentialACL reads exactly the canonical five-entry systemd ACL in one
// syscall. ERANGE therefore rejects an ACL with additional principals without
// introducing a size-probe/read race.
func readCredentialACL(file *os.File, name string) (credentialACL, error) {
	buffer := make([]byte, credentialACLSize)
	size, err := fgetxattrFile(file, name, buffer)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
			return credentialACL{}, nil
		}
		if errors.Is(err, syscall.ERANGE) {
			return credentialACL{}, errors.New("credential ACL has invalid size")
		}
		return credentialACL{}, err
	}
	if size != len(buffer) {
		return credentialACL{}, errors.New("credential ACL has invalid size")
	}
	return credentialACL{encoded: append([]byte(nil), buffer[:size]...), present: true}, nil
}

// credentialACLPresent checks whether an ACL exists without reading or
// disclosing it. ERANGE means that a value is present but larger than the
// one-byte probe.
func credentialACLPresent(file *os.File, name string) (bool, error) {
	buffer := []byte{0}
	_, err := fgetxattrFile(file, name, buffer)
	if err == nil || errors.Is(err, syscall.ERANGE) {
		return true, nil
	}
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
		return false, nil
	}
	return false, err
}

func fileSystemReadOnly(file *os.File) (bool, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return false, err
	}
	var metadata syscall.Statfs_t
	var callErr error
	controlErr := raw.Control(func(fd uintptr) {
		callErr = syscall.Fstatfs(int(fd), &metadata)
	})
	if controlErr != nil {
		return false, controlErr
	}
	if callErr != nil {
		return false, callErr
	}
	return metadata.Flags&syscall.MS_RDONLY != 0, nil
}

func parsePOSIXACL(encoded []byte) ([]posixACLEntry, error) {
	if len(encoded) < 4 || (len(encoded)-4)%8 != 0 {
		return nil, errors.New("POSIX ACL has invalid size")
	}
	if binary.LittleEndian.Uint32(encoded[:4]) != posixACLVersion {
		return nil, errors.New("POSIX ACL has unsupported version")
	}
	entries := make([]posixACLEntry, 0, (len(encoded)-4)/8)
	for offset := 4; offset < len(encoded); offset += 8 {
		entry := posixACLEntry{
			tag:        binary.LittleEndian.Uint16(encoded[offset : offset+2]),
			permission: binary.LittleEndian.Uint16(encoded[offset+2 : offset+4]),
			id:         binary.LittleEndian.Uint32(encoded[offset+4 : offset+8]),
		}
		if entry.permission&^uint16(0o7) != 0 {
			return nil, errors.New("POSIX ACL contains invalid permission bits")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// validateSystemdAccessACL accepts only the ACL that systemd creates for one
// non-root service UID. In particular, apparent group mode bits are accepted
// only when they are the ACL mask for that exact named user; ordinary group
// access, additional users or groups, and every write permission are rejected.
func validateSystemdAccessACL(encoded []byte, runtimeOwnerUID uint32, permission uint16) error {
	if runtimeOwnerUID == 0 {
		return errors.New("systemd credential ACL requires a non-root runtime UID")
	}
	entries, err := parsePOSIXACL(encoded)
	if err != nil {
		return err
	}
	if len(entries) != 5 {
		return errors.New("systemd credential ACL must contain exactly five entries")
	}

	expected := []posixACLEntry{
		{tag: aclTagUserObject, permission: permission, id: posixACLUndefinedID},
		{tag: aclTagUser, permission: permission, id: runtimeOwnerUID},
		{tag: aclTagGroupObject, permission: 0, id: posixACLUndefinedID},
		{tag: aclTagMask, permission: permission, id: posixACLUndefinedID},
		{tag: aclTagOther, permission: 0, id: posixACLUndefinedID},
	}
	for index := range expected {
		if entries[index] != expected[index] {
			return fmt.Errorf("systemd credential ACL entry %d is not canonical", index)
		}
	}
	return nil
}

func validateCredentialLayout(
	parentIdentity fileIdentity,
	parentMode os.FileMode,
	parentAccessACL credentialACL,
	parentDefaultACL credentialACL,
	identity fileIdentity,
	mode os.FileMode,
	accessACL credentialACL,
	parentFileSystemReadOnly bool,
	credentialFileSystemReadOnly bool,
	trustedOwnerUID uint32,
	runtimeOwnerUID uint32,
) error {
	if runtimeOwnerUID == 0 {
		return errors.New("credential runtime owner must be non-root")
	}
	if trustedOwnerUID == runtimeOwnerUID {
		return errors.New("credential trusted and runtime owners must differ")
	}
	if parentMode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("credential path must not have special permission bits")
	}

	if parentAccessACL.present || accessACL.present {
		if parentIdentity.uid != trustedOwnerUID || identity.uid != trustedOwnerUID {
			return errors.New("ACL-backed credential ownership does not match the trusted owner")
		}
		if parentMode.Perm() != 0o550 || mode.Perm() != 0o440 {
			return errors.New("ACL-backed credential layout must use parent mode 0550 and file mode 0440")
		}
		if parentDefaultACL.present {
			return errors.New("ACL-backed credential parent must not contain a default ACL")
		}
		if !parentAccessACL.present || !accessACL.present {
			return errors.New("ACL-backed credential layout is missing a POSIX access ACL")
		}
		if err := validateSystemdAccessACL(
			parentAccessACL.encoded,
			runtimeOwnerUID,
			aclPermissionRead|aclPermissionExecute,
		); err != nil {
			return fmt.Errorf("credential parent ACL: %w", err)
		}
		if err := validateSystemdAccessACL(accessACL.encoded, runtimeOwnerUID, aclPermissionRead); err != nil {
			return fmt.Errorf("credential file ACL: %w", err)
		}
		return nil
	}

	if parentIdentity.uid == runtimeOwnerUID && identity.uid == runtimeOwnerUID {
		if parentMode.Perm() != 0o500 || mode.Perm() != 0o400 {
			return errors.New("ownership-based credential layout must use parent mode 0500 and file mode 0400")
		}
		if parentAccessACL.present || parentDefaultACL.present || accessACL.present {
			return errors.New("ownership-based credential layout must not contain POSIX ACLs")
		}
		if !parentFileSystemReadOnly || !credentialFileSystemReadOnly {
			return errors.New("ownership-based credential layout must reside on read-only filesystems")
		}
		return nil
	}

	return errors.New("credential ownership does not match a supported systemd layout")
}
