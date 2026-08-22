//go:build linux && (amd64 || arm64)

package main

import (
	"syscall"
	"unsafe"
)

const (
	renameNoReplaceFlag = 1
	atFDCWD             = ^uintptr(99)
)

func renameNoReplace(oldPath, newPath string) error {
	oldPointer, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		renameat2Trap, atFDCWD, uintptr(unsafe.Pointer(oldPointer)), atFDCWD,
		uintptr(unsafe.Pointer(newPointer)), renameNoReplaceFlag, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
