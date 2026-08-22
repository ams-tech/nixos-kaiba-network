//go:build linux

package signedrelease

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	renameNoReplaceFlag = uintptr(1)
)

func renameNoReplaceAt(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string) error {
	if renameat2Trap == 0 {
		return errors.New("renameat2 is unavailable on this architecture")
	}
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.RawSyscall6(renameat2Trap, uintptr(oldDirectoryFD), uintptr(unsafe.Pointer(oldPointer)), uintptr(newDirectoryFD), uintptr(unsafe.Pointer(newPointer)), renameNoReplaceFlag, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
