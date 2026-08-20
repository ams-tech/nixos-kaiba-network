package yubikeysigner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func encodePOSIXACL(entries []posixACLEntry) []byte {
	encoded := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(encoded[:4], posixACLVersion)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(encoded[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:offset+4], entry.permission)
		binary.LittleEndian.PutUint32(encoded[offset+4:offset+8], entry.id)
	}
	return encoded
}

func systemdACLEntries(runtimeOwnerUID uint32, permission uint16) []posixACLEntry {
	return []posixACLEntry{
		{tag: aclTagUserObject, permission: permission, id: posixACLUndefinedID},
		{tag: aclTagUser, permission: permission, id: runtimeOwnerUID},
		{tag: aclTagGroupObject, id: posixACLUndefinedID},
		{tag: aclTagMask, permission: permission, id: posixACLUndefinedID},
		{tag: aclTagOther, id: posixACLUndefinedID},
	}
}

func systemdACL(runtimeOwnerUID uint32, permission uint16) credentialACL {
	return credentialACL{
		encoded: encodePOSIXACL(systemdACLEntries(runtimeOwnerUID, permission)),
		present: true,
	}
}

func TestValidateCredentialLayoutAcceptsSystemdAndOwnershipFallbacks(t *testing.T) {
	const trustedOwnerUID = uint32(0)
	const runtimeOwnerUID = uint32(998)
	tests := []struct {
		name                         string
		parentIdentity               fileIdentity
		parentMode                   os.FileMode
		parentAccessACL              credentialACL
		parentDefaultACL             credentialACL
		identity                     fileIdentity
		mode                         os.FileMode
		accessACL                    credentialACL
		parentFileSystemReadOnly     bool
		credentialFileSystemReadOnly bool
	}{
		{
			name:            "systemd ACL",
			parentIdentity:  fileIdentity{uid: 0, gid: 0},
			parentMode:      os.ModeDir | 0o550,
			parentAccessACL: systemdACL(runtimeOwnerUID, aclPermissionRead|aclPermissionExecute),
			identity:        fileIdentity{uid: 0, gid: 0},
			mode:            0o440,
			accessACL:       systemdACL(runtimeOwnerUID, aclPermissionRead),
		},
		{
			name:                     "ownership fallback",
			parentIdentity:           fileIdentity{uid: runtimeOwnerUID, gid: 42},
			parentMode:               os.ModeDir | 0o500,
			identity:                 fileIdentity{uid: runtimeOwnerUID, gid: 42},
			mode:                     0o400,
			parentFileSystemReadOnly: true, credentialFileSystemReadOnly: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCredentialLayout(
				test.parentIdentity,
				test.parentMode,
				test.parentAccessACL,
				test.parentDefaultACL,
				test.identity,
				test.mode,
				test.accessACL,
				test.parentFileSystemReadOnly,
				test.credentialFileSystemReadOnly,
				trustedOwnerUID,
				runtimeOwnerUID,
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateCredentialLayoutRejectsUnsafeMetadata(t *testing.T) {
	const trustedOwnerUID = uint32(0)
	const runtimeOwnerUID = uint32(998)
	validParentACL := systemdACL(runtimeOwnerUID, aclPermissionRead|aclPermissionExecute)
	validFileACL := systemdACL(runtimeOwnerUID, aclPermissionRead)
	tests := []struct {
		name                         string
		parentIdentity               fileIdentity
		parentMode                   os.FileMode
		parentAccessACL              credentialACL
		parentDefaultACL             credentialACL
		identity                     fileIdentity
		mode                         os.FileMode
		accessACL                    credentialACL
		parentFileSystemReadOnly     bool
		credentialFileSystemReadOnly bool
	}{
		{
			name: "root modes without ACLs", parentIdentity: fileIdentity{uid: 0, gid: 0},
			parentMode: os.ModeDir | 0o550, identity: fileIdentity{uid: 0, gid: 0}, mode: 0o440,
		},
		{
			name: "untrusted ACL owner", parentIdentity: fileIdentity{uid: 7, gid: 0},
			parentMode: os.ModeDir | 0o550, parentAccessACL: validParentACL,
			identity: fileIdentity{uid: 0, gid: 0}, mode: 0o440, accessACL: validFileACL,
		},
		{
			name: "mixed ownership", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o500, identity: fileIdentity{uid: 0}, mode: 0o400,
		},
		{
			name: "writable fallback parent", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o700, identity: fileIdentity{uid: runtimeOwnerUID}, mode: 0o400,
			parentFileSystemReadOnly: true, credentialFileSystemReadOnly: true,
		},
		{
			name: "writable fallback file", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o500, identity: fileIdentity{uid: runtimeOwnerUID}, mode: 0o600,
			parentFileSystemReadOnly: true, credentialFileSystemReadOnly: true,
		},
		{
			name: "fallback parent filesystem is writable", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o500, identity: fileIdentity{uid: runtimeOwnerUID}, mode: 0o400,
			credentialFileSystemReadOnly: true,
		},
		{
			name: "fallback file filesystem is writable", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o500, identity: fileIdentity{uid: runtimeOwnerUID}, mode: 0o400,
			parentFileSystemReadOnly: true,
		},
		{
			name: "fallback with ACL", parentIdentity: fileIdentity{uid: runtimeOwnerUID},
			parentMode: os.ModeDir | 0o500, parentAccessACL: validParentACL,
			identity: fileIdentity{uid: runtimeOwnerUID}, mode: 0o400,
		},
		{
			name: "ACL parent mode drift", parentIdentity: fileIdentity{uid: 0, gid: 0},
			parentMode: os.ModeDir | 0o570, parentAccessACL: validParentACL,
			identity: fileIdentity{uid: 0, gid: 0}, mode: 0o440, accessACL: validFileACL,
		},
		{
			name: "ACL file mode drift", parentIdentity: fileIdentity{uid: 0, gid: 0},
			parentMode: os.ModeDir | 0o550, parentAccessACL: validParentACL,
			identity: fileIdentity{uid: 0, gid: 0}, mode: 0o460, accessACL: validFileACL,
		},
		{
			name: "default parent ACL", parentIdentity: fileIdentity{uid: 0, gid: 0},
			parentMode: os.ModeDir | 0o550, parentAccessACL: validParentACL,
			parentDefaultACL: credentialACL{encoded: []byte{1}, present: true},
			identity:         fileIdentity{uid: 0, gid: 0}, mode: 0o440, accessACL: validFileACL,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCredentialLayout(
				test.parentIdentity,
				test.parentMode,
				test.parentAccessACL,
				test.parentDefaultACL,
				test.identity,
				test.mode,
				test.accessACL,
				test.parentFileSystemReadOnly,
				test.credentialFileSystemReadOnly,
				trustedOwnerUID,
				runtimeOwnerUID,
			); err == nil {
				t.Fatal("unsafe credential metadata was accepted")
			}
		})
	}
}

func TestValidateSystemdAccessACLRejectsMalformedOrBroadenedACLs(t *testing.T) {
	const runtimeOwnerUID = uint32(998)
	const permission = aclPermissionRead
	valid := systemdACLEntries(runtimeOwnerUID, permission)
	clone := func() []posixACLEntry { return append([]posixACLEntry(nil), valid...) }
	tests := []struct {
		name    string
		encoded func() []byte
	}{
		{name: "truncated", encoded: func() []byte { return []byte{2, 0, 0, 0, 1} }},
		{name: "wrong version", encoded: func() []byte {
			encoded := encodePOSIXACL(valid)
			binary.LittleEndian.PutUint32(encoded[:4], 3)
			return encoded
		}},
		{name: "missing service user", encoded: func() []byte { return encodePOSIXACL(valid[:1]) }},
		{name: "wrong service user", encoded: func() []byte {
			entries := clone()
			entries[1].id++
			return encodePOSIXACL(entries)
		}},
		{name: "extra user", encoded: func() []byte {
			entries := clone()
			return encodePOSIXACL(append(entries, posixACLEntry{tag: aclTagUser, permission: permission, id: 1234}))
		}},
		{name: "permuted entries", encoded: func() []byte {
			entries := clone()
			entries[1], entries[2] = entries[2], entries[1]
			return encodePOSIXACL(entries)
		}},
		{name: "named group", encoded: func() []byte {
			entries := clone()
			entries[1] = posixACLEntry{tag: aclTagGroup, permission: permission, id: 1234}
			return encodePOSIXACL(entries)
		}},
		{name: "owning group access", encoded: func() []byte {
			entries := clone()
			entries[2].permission = permission
			return encodePOSIXACL(entries)
		}},
		{name: "other access", encoded: func() []byte {
			entries := clone()
			entries[4].permission = permission
			return encodePOSIXACL(entries)
		}},
		{name: "write access", encoded: func() []byte {
			entries := clone()
			entries[1].permission |= 0o2
			return encodePOSIXACL(entries)
		}},
		{name: "mask mismatch", encoded: func() []byte {
			entries := clone()
			entries[3].permission = 0
			return encodePOSIXACL(entries)
		}},
		{name: "duplicate base entry", encoded: func() []byte {
			entries := clone()
			entries[1] = entries[0]
			return encodePOSIXACL(entries)
		}},
		{name: "base entry ID", encoded: func() []byte {
			entries := clone()
			entries[0].id = 0
			return encodePOSIXACL(entries)
		}},
		{name: "invalid permission bits", encoded: func() []byte {
			entries := clone()
			entries[0].permission = 0x80
			return encodePOSIXACL(entries)
		}},
		{name: "unknown tag", encoded: func() []byte {
			entries := clone()
			entries[1].tag = 0x40
			return encodePOSIXACL(entries)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSystemdAccessACL(test.encoded(), runtimeOwnerUID, permission); err == nil {
				t.Fatal("malformed or broadened ACL was accepted")
			}
		})
	}
}

func TestReadCredentialACLRoundTrip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not a representative named service UID")
	}
	directory := t.TempDir()
	credentialDirectory := filepath.Join(directory, "credential")
	if err := os.Mkdir(credentialDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(credentialDirectory, 0o700)
	})
	credentialPath := filepath.Join(credentialDirectory, "pin")
	if err := os.WriteFile(credentialPath, []byte("654321\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runtimeOwnerUID := uint32(os.Geteuid())
	directoryACL := encodePOSIXACL(systemdACLEntries(runtimeOwnerUID, aclPermissionRead|aclPermissionExecute))
	fileACL := encodePOSIXACL(systemdACLEntries(runtimeOwnerUID, aclPermissionRead))
	for path, encoded := range map[string][]byte{
		credentialDirectory: directoryACL,
		credentialPath:      fileACL,
	} {
		if err := syscall.Setxattr(path, posixACLAccessXattr, encoded, 0); err != nil {
			if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
				t.Skipf("POSIX ACL xattrs are unavailable: %v", err)
			}
			t.Fatalf("set ACL on %s: %v", filepath.Base(path), err)
		}
	}

	for path, expected := range map[string][]byte{
		credentialDirectory: directoryACL,
		credentialPath:      fileACL,
	} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		actual, readErr := readCredentialACL(file, posixACLAccessXattr)
		closeErr := file.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if !actual.present || !bytes.Equal(actual.encoded, expected) {
			t.Fatalf("ACL round trip for %s = %x, want %x", filepath.Base(path), actual.encoded, expected)
		}
	}

	if mode := mustMode(t, credentialDirectory); mode.Perm() != 0o550 {
		t.Fatalf("credential directory mode = %#o, want 0550", mode.Perm())
	}
	if mode := mustMode(t, credentialPath); mode.Perm() != 0o440 {
		t.Fatalf("credential file mode = %#o, want 0440", mode.Perm())
	}
}

func TestReadCredentialACLUsesOpenedDescriptor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not a representative named service UID")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	replacementPath := filepath.Join(directory, "replacement")
	if err := os.WriteFile(path, []byte("654321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalACL := encodePOSIXACL(systemdACLEntries(uint32(os.Geteuid()), aclPermissionRead))
	if err := syscall.Setxattr(path, posixACLAccessXattr, originalACL, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("POSIX ACL xattrs are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	opened, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Rename(path, replacementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	actual, err := readCredentialACL(opened, posixACLAccessXattr)
	if err != nil {
		t.Fatal(err)
	}
	if !actual.present || !bytes.Equal(actual.encoded, originalACL) {
		t.Fatalf("descriptor ACL = %x, want original ACL %x", actual.encoded, originalACL)
	}
}

func TestReadCredentialACLRejectsAdditionalPrincipal(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	if err := os.WriteFile(path, []byte("654321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded := encodePOSIXACL([]posixACLEntry{
		{tag: aclTagUserObject, permission: aclPermissionRead, id: posixACLUndefinedID},
		{tag: aclTagUser, permission: aclPermissionRead, id: uint32(os.Geteuid())},
		{tag: aclTagGroupObject, id: posixACLUndefinedID},
		{tag: aclTagGroup, id: uint32(os.Getegid())},
		{tag: aclTagMask, permission: aclPermissionRead, id: posixACLUndefinedID},
		{tag: aclTagOther, id: posixACLUndefinedID},
	})
	if err := syscall.Setxattr(path, posixACLAccessXattr, encoded, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("POSIX ACL xattrs are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := readCredentialACL(file, posixACLAccessXattr); err == nil ||
		!strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("additional-principal ACL error = %v", err)
	}
}

func TestWritableTemporaryFilesystemIsNotFallbackSafe(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	readOnly, err := fileSystemReadOnly(file)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("test temporary filesystem unexpectedly reports read-only")
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s became a symlink", path)
	}
	return info.Mode()
}

func TestParsePOSIXACLErrorMessagesDoNotDiscloseData(t *testing.T) {
	_, err := parsePOSIXACL([]byte("not-an-acl"))
	if err == nil || strings.Contains(err.Error(), "not-an-acl") {
		t.Fatalf("ACL parse error = %v", err)
	}
}
