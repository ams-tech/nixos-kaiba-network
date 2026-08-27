package signinggate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ReadCompleteStateSnapshot takes a shared host-wide gate lock and returns one
// validated complete durable state for every grant in registry order. Unlike
// OpenStateStore, it never creates the lock file or writes the state directory,
// so it is suitable for a receipt-export process running beside the gate.
func ReadCompleteStateSnapshot(ctx context.Context, directory string, ownerUID uint32, registry Registry) ([]DurableState, error) {
	if ctx == nil {
		return nil, errors.New("read signing state snapshot: context is unavailable")
	}
	if err := registry.Validate(); err != nil {
		return nil, fmt.Errorf("read signing state snapshot: registry: %w", err)
	}
	if err := validateManagedDirectory(directory, ownerUID, true); err != nil {
		return nil, fmt.Errorf("read signing state snapshot: directory: %w", err)
	}
	lockFile, err := openExistingStateLock(filepath.Join(directory, ".gate.lock"), ownerUID)
	if err != nil {
		return nil, fmt.Errorf("read signing state snapshot: %w", err)
	}
	defer lockFile.Close()
	if err := lockShared(ctx, lockFile); err != nil {
		return nil, fmt.Errorf("read signing state snapshot: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// Load only uses the validated directory and owner. Deliberately leave its
	// lockFile nil: the already-opened, pre-existing lock above is the authority
	// for this read-only snapshot and cannot create filesystem state.
	store := &StateStore{directory: directory, ownerUID: ownerUID}
	states := make([]DurableState, 0, len(registry.Grants))
	for _, grant := range registry.Grants {
		state, found, err := store.Load(grant)
		if err != nil {
			return nil, fmt.Errorf("grant %q: %w", grant.GrantID, err)
		}
		if !found {
			return nil, fmt.Errorf("grant %q has no durable state", grant.GrantID)
		}
		if state.Status != StateComplete || state.Receipt == nil {
			return nil, fmt.Errorf("grant %q does not have a complete durable receipt", grant.GrantID)
		}
		states = append(states, state)
	}
	return states, nil
}

func openExistingStateLock(path string, ownerUID uint32) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect existing signing state lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("existing signing state lock has unsafe type or permissions")
	}
	if err := requireOwner(info, ownerUID); err != nil {
		return nil, fmt.Errorf("existing signing state lock: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open existing signing state lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct existing signing state lock handle")
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened signing state lock: %w", err)
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("signing state lock changed while opening")
	}
	if err := requireOwner(opened, ownerUID); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("opened signing state lock: %w", err)
	}
	return file, nil
}

func lockShared(ctx context.Context, file *os.File) error {
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("lock signing state for receipt snapshot: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
