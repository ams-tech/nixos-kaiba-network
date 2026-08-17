package mediastager

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const defaultCopyBufferBytes = 1024 * 1024

type Executor struct {
	Inventory  Inventory
	BufferSize int
}

type preparedImage struct {
	spec ImageSpec
	file *os.File
}

func (executor Executor) DryRun(ctx context.Context, plan Plan, mode Mode) (Result, error) {
	if err := executor.validateConfiguration(); err != nil {
		return Result{}, err
	}
	prepared, _, target, err := executor.prepareForWrite(ctx, plan, mode, false)
	if err != nil {
		return Result{}, err
	}
	defer closePreparedImages(prepared)
	defer closeLockedTarget(target)
	return resultFor(plan, ActionDryRun, "validated_no_write"), nil
}

// Stage verifies every source before opening the target for writing, takes an
// exclusive nonblocking lock, rechecks target usage, writes only the approved
// extents, and fsyncs the target. A later Readback call is deliberately
// separate so the caller can close the physical power boundary first.
func (executor Executor) Stage(ctx context.Context, plan Plan, mode Mode) (Result, error) {
	if err := executor.validateConfiguration(); err != nil {
		return Result{}, err
	}
	prepared, _, target, err := executor.prepareForWrite(ctx, plan, mode, true)
	if err != nil {
		return Result{}, err
	}
	defer closePreparedImages(prepared)
	defer closeLockedTarget(target)
	bufferSize := executor.bufferSize()
	buffer := make([]byte, bufferSize)
	for _, image := range prepared {
		copiedDigest, err := copyExact(ctx, target, image.file, image.spec.OffsetBytes, image.spec.SizeBytes, buffer)
		if err != nil {
			return Result{}, fmt.Errorf("write image %q: %w", image.spec.Role, err)
		}
		// Advisory source locks are not an integrity boundary: a writer that
		// ignores flock could still race the preflight hash.  Bind the bytes
		// actually copied as well, and fail the staging attempt if they differ.
		if copiedDigest != image.spec.Digest {
			return Result{}, fmt.Errorf("%w: image %q changed after preflight (copied %s, expected %s)", ErrImageMismatch, image.spec.Role, copiedDigest, image.spec.Digest)
		}
	}
	if err := target.Sync(); err != nil {
		return Result{}, fmt.Errorf("fsync staged target: %w", err)
	}
	return resultFor(plan, ActionStage, "fsync_complete_readback_required"), nil
}

// Readback opens and locks the target afresh and verifies each approved extent.
// It never opens source images and never writes target bytes.
func (executor Executor) Readback(ctx context.Context, plan Plan, mode Mode) (Result, error) {
	if err := executor.validateConfiguration(); err != nil {
		return Result{}, err
	}
	if err := plan.Validate(mode); err != nil {
		return Result{}, err
	}
	inventory := executor.Inventory
	if inventory == nil {
		inventory = SystemInventory{}
	}
	facts, err := inventory.Inspect(ctx, plan.Target.Path, mode)
	if err != nil {
		return Result{}, fmt.Errorf("inspect readback target: %w", err)
	}
	usage, err := inventory.Usage(ctx, facts, mode)
	if err != nil {
		return Result{}, fmt.Errorf("inspect readback target usage: %w", err)
	}
	if err := validateTargetFacts(plan, mode, facts, usage); err != nil {
		return Result{}, err
	}
	target, err := openLockedTarget(facts, mode, false)
	if err != nil {
		return Result{}, err
	}
	defer closeLockedTarget(target)
	if err := validateOpenedTarget(target, facts, mode); err != nil {
		return Result{}, err
	}
	usage, err = inventory.Usage(ctx, facts, mode)
	if err != nil {
		return Result{}, fmt.Errorf("recheck readback target usage: %w", err)
	}
	if err := validateTargetFacts(plan, mode, facts, usage); err != nil {
		return Result{}, err
	}
	for _, image := range plan.Images {
		digest, err := hashRange(ctx, target, image.OffsetBytes, image.SizeBytes, executor.bufferSize())
		if err != nil {
			return Result{}, fmt.Errorf("read image %q extent: %w", image.Role, err)
		}
		if digest != image.Digest {
			return Result{}, fmt.Errorf("%w: image %q digest is %s, expected %s", ErrReadbackMismatch, image.Role, digest, image.Digest)
		}
	}
	return resultFor(plan, ActionReadback, "reopened_readback_verified"), nil
}

func (executor Executor) prepareForWrite(ctx context.Context, plan Plan, mode Mode, writable bool) ([]preparedImage, TargetFacts, *os.File, error) {
	if err := plan.Validate(mode); err != nil {
		return nil, TargetFacts{}, nil, err
	}
	inventory := executor.Inventory
	if inventory == nil {
		inventory = SystemInventory{}
	}
	facts, err := inventory.Inspect(ctx, plan.Target.Path, mode)
	if err != nil {
		return nil, TargetFacts{}, nil, fmt.Errorf("inspect target: %w", err)
	}
	usage, err := inventory.Usage(ctx, facts, mode)
	if err != nil {
		return nil, TargetFacts{}, nil, fmt.Errorf("inspect target usage: %w", err)
	}
	if err := validateTargetFacts(plan, mode, facts, usage); err != nil {
		return nil, TargetFacts{}, nil, err
	}
	prepared, err := executor.prepareImages(ctx, plan.Images)
	if err != nil {
		return nil, TargetFacts{}, nil, err
	}
	target, err := openLockedTarget(facts, mode, writable)
	if err != nil {
		closePreparedImages(prepared)
		return nil, TargetFacts{}, nil, err
	}
	if err := validateOpenedTarget(target, facts, mode); err != nil {
		closeLockedTarget(target)
		closePreparedImages(prepared)
		return nil, TargetFacts{}, nil, err
	}
	if err := rejectTargetSourceAlias(target, prepared, mode); err != nil {
		closeLockedTarget(target)
		closePreparedImages(prepared)
		return nil, TargetFacts{}, nil, err
	}
	usage, err = inventory.Usage(ctx, facts, mode)
	if err != nil {
		closeLockedTarget(target)
		closePreparedImages(prepared)
		return nil, TargetFacts{}, nil, fmt.Errorf("recheck target usage: %w", err)
	}
	if err := validateTargetFacts(plan, mode, facts, usage); err != nil {
		closeLockedTarget(target)
		closePreparedImages(prepared)
		return nil, TargetFacts{}, nil, err
	}
	return prepared, facts, target, nil
}

func (executor Executor) prepareImages(ctx context.Context, images []ImageSpec) ([]preparedImage, error) {
	prepared := make([]preparedImage, 0, len(images))
	for _, image := range images {
		file, err := openLockedSource(image.Path)
		if err != nil {
			closePreparedImages(prepared)
			return nil, fmt.Errorf("open image %q: %w", image.Role, err)
		}
		info, err := file.Stat()
		if err != nil {
			closeLockedSource(file)
			closePreparedImages(prepared)
			return nil, fmt.Errorf("stat image %q: %w", image.Role, err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != image.SizeBytes {
			closeLockedSource(file)
			closePreparedImages(prepared)
			return nil, fmt.Errorf("%w: image %q size or file type differs", ErrImageMismatch, image.Role)
		}
		digest, err := hashRange(ctx, file, 0, image.SizeBytes, executor.bufferSize())
		if err != nil {
			closeLockedSource(file)
			closePreparedImages(prepared)
			return nil, fmt.Errorf("hash image %q: %w", image.Role, err)
		}
		if digest != image.Digest {
			closeLockedSource(file)
			closePreparedImages(prepared)
			return nil, fmt.Errorf("%w: image %q digest is %s, expected %s", ErrImageMismatch, image.Role, digest, image.Digest)
		}
		prepared = append(prepared, preparedImage{spec: image, file: file})
	}
	return prepared, nil
}

func (executor Executor) bufferSize() int {
	if executor.BufferSize == 0 {
		return defaultCopyBufferBytes
	}
	return executor.BufferSize
}

func (executor Executor) validateConfiguration() error {
	if executor.BufferSize != 0 && (executor.BufferSize < 4096 || executor.BufferSize > 16*1024*1024) {
		return invalidPlan("copy buffer size must be between 4096 and 16777216 bytes")
	}
	return nil
}

func openLockedSource(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct source image handle")
	}
	if err := syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock source image: %w", err)
	}
	return file, nil
}

func closeLockedSource(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func closePreparedImages(images []preparedImage) {
	for _, image := range images {
		closeLockedSource(image.file)
	}
}

func openLockedTarget(facts TargetFacts, _ Mode, writable bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	if writable {
		flags = syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	}
	fd, err := syscall.Open(facts.ResolvedPath, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %v", ErrTargetBusy, err)
		}
		return nil, fmt.Errorf("open target with no-follow and exclusive-device flags: %w", err)
	}
	file := os.NewFile(uintptr(fd), facts.ResolvedPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct target handle")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %v", ErrTargetBusy, err)
		}
		return nil, fmt.Errorf("lock target exclusively: %w", err)
	}
	return file, nil
}

func closeLockedTarget(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func validateOpenedTarget(file *os.File, facts TargetFacts, mode Mode) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: opened target identity is unavailable", ErrTargetMismatch)
	}
	if mode == ModeFixture {
		if !info.Mode().IsRegular() || uint64(stat.Dev) != facts.FileDevice || stat.Ino != facts.Inode || info.Size() < 0 || uint64(info.Size()) != facts.SizeBytes {
			return fmt.Errorf("%w: opened fixture identity or size changed", ErrTargetMismatch)
		}
		return nil
	}
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 || uint64(stat.Rdev) != facts.DeviceNumber {
		return fmt.Errorf("%w: opened block-device identity changed", ErrTargetMismatch)
	}
	size, err := blockDeviceSize(file)
	if err != nil {
		return err
	}
	if size != facts.SizeBytes {
		return fmt.Errorf("%w: opened block-device size changed", ErrTargetMismatch)
	}
	return nil
}

func rejectTargetSourceAlias(target *os.File, images []preparedImage, mode Mode) error {
	if mode != ModeFixture {
		return nil
	}
	targetInfo, err := target.Stat()
	if err != nil {
		return err
	}
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: fixture target identity is unavailable", ErrTargetMismatch)
	}
	for _, image := range images {
		info, err := image.file.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%w: source image identity is unavailable", ErrImageMismatch)
		}
		if stat.Dev == targetStat.Dev && stat.Ino == targetStat.Ino {
			return fmt.Errorf("%w: fixture target is also a source image", ErrUnsafeTarget)
		}
	}
	return nil
}

func hashRange(ctx context.Context, file *os.File, offset, size uint64, bufferSize int) (string, error) {
	hash := sha256.New()
	buffer := make([]byte, bufferSize)
	remaining := size
	position := offset
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := uint64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := file.ReadAt(buffer[:int(chunk)], int64(position))
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			position += uint64(n)
			remaining -= uint64(n)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if n == 0 || (errors.Is(err, io.EOF) && remaining != 0) {
			return "", io.ErrUnexpectedEOF
		}
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

func copyExact(ctx context.Context, target, source *os.File, targetOffset, size uint64, buffer []byte) (string, error) {
	hash := sha256.New()
	remaining := size
	sourceOffset := uint64(0)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := uint64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := source.ReadAt(buffer[:int(chunk)], int64(sourceOffset))
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if n != int(chunk) {
			return "", io.ErrUnexpectedEOF
		}
		_, _ = hash.Write(buffer[:n])
		written := 0
		for written < n {
			count, writeErr := target.WriteAt(buffer[written:n], int64(targetOffset+sourceOffset+uint64(written)))
			if writeErr != nil {
				return "", writeErr
			}
			if count == 0 {
				return "", io.ErrShortWrite
			}
			written += count
		}
		sourceOffset += uint64(n)
		remaining -= uint64(n)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}
