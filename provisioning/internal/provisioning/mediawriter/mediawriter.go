// Package mediawriter performs the byte-copy portion of media staging.
//
// It deliberately knows nothing about device discovery, mount state, Linux
// block-device ioctls, receipts, or ceremony policy. Callers must establish
// those boundaries before passing an exclusively held WriterAt here.
package mediawriter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

const transferBufferBytes = 1024 * 1024

var sourceOrder = [...]mediacontract.SourceRole{
	mediacontract.SourcePrimaryGPT,
	mediacontract.SourceBootFilesystem,
	mediacontract.SourceRootData,
	mediacontract.SourceRootHash,
	mediacontract.SourceBackupGPT,
}

// AssetPaths is the complete immutable source set resolved by a production
// adapter. Production binaries are expected to fill these fields from
// linker-fixed paths, never from operator-supplied target-time input.
type AssetPaths struct {
	PrimaryGPT     string
	BootFilesystem string
	RootData       string
	RootHash       string
	BackupGPT      string
}

func (paths AssetPaths) path(role mediacontract.SourceRole) (string, bool) {
	switch role {
	case mediacontract.SourcePrimaryGPT:
		return paths.PrimaryGPT, true
	case mediacontract.SourceBootFilesystem:
		return paths.BootFilesystem, true
	case mediacontract.SourceRootData:
		return paths.RootData, true
	case mediacontract.SourceRootHash:
		return paths.RootHash, true
	case mediacontract.SourceBackupGPT:
		return paths.BackupGPT, true
	default:
		return "", false
	}
}

type sourceFile struct {
	role   mediacontract.SourceRole
	path   string
	file   *os.File
	size   uint64
	digest mediacontract.Digest
	device uint64
	inode  uint64
}

// Sources owns shared, non-blocking locks on the five validated source files.
// Close must be called when staging is complete. A Sources value is bound to
// the exact canonical plan used by OpenSources and cannot be reused with a
// different plan.
type Sources struct {
	mu         sync.Mutex
	planDigest mediacontract.Digest
	files      map[mediacontract.SourceRole]*sourceFile
	closed     bool
}

// OpenSources opens, shared-locks, sizes, and hashes all five immutable source
// assets. All validation completes before the returned value can be supplied
// to Stage. Final path components may not be symlinks, and distinct roles may
// not name the same path or underlying inode.
func OpenSources(ctx context.Context, plan mediacontract.Plan, paths AssetPaths) (_ *Sources, returnErr error) {
	if ctx == nil {
		return nil, errors.New("open media sources: nil context")
	}
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("open media sources: validate plan: %w", err)
	}

	expected := make(map[mediacontract.SourceRole]mediacontract.SourceBinding, len(plan.Layout.Sources))
	for _, binding := range plan.Layout.Sources {
		expected[binding.Role] = binding
	}

	sources := &Sources{
		planDigest: plan.PlanDigest,
		files:      make(map[mediacontract.SourceRole]*sourceFile, len(sourceOrder)),
	}
	defer func() {
		if returnErr != nil {
			_ = sources.Close()
		}
	}()

	seenPaths := make(map[string]mediacontract.SourceRole, len(sourceOrder))
	type fileIdentity struct {
		device uint64
		inode  uint64
	}
	seenFiles := make(map[fileIdentity]mediacontract.SourceRole, len(sourceOrder))

	for _, role := range sourceOrder {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("open media source %q: %w", role, err)
		}
		path, present := paths.path(role)
		if !present || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("media source %q path must be clean and absolute", role)
		}
		if previous, duplicate := seenPaths[path]; duplicate {
			return nil, fmt.Errorf("media sources %q and %q use the same path", previous, role)
		}
		seenPaths[path] = role

		binding, present := expected[role]
		if !present {
			return nil, fmt.Errorf("validated plan has no source binding for %q", role)
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("open non-symlink media source %q: %w", role, err)
		}
		entry := &sourceFile{role: role, path: path, file: file, size: binding.SizeBytes, digest: binding.Digest}
		sources.files[role] = entry

		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			return nil, fmt.Errorf("shared-lock media source %q: %w", role, err)
		}
		stat, err := inspectSource(entry)
		if err != nil {
			return nil, err
		}
		entry.device, entry.inode = uint64(stat.Dev), uint64(stat.Ino)
		identity := fileIdentity{device: entry.device, inode: entry.inode}
		if previous, duplicate := seenFiles[identity]; duplicate {
			return nil, fmt.Errorf("media sources %q and %q identify the same underlying file", previous, role)
		}
		seenFiles[identity] = role

		digest, err := HashRange(ctx, file, 0, binding.SizeBytes)
		if err != nil {
			return nil, fmt.Errorf("hash media source %q: %w", role, err)
		}
		if digest != binding.Digest {
			return nil, fmt.Errorf("media source %q digest is %s, expected %s", role, digest, binding.Digest)
		}
		if _, err := inspectSource(entry); err != nil {
			return nil, err
		}
	}

	return sources, nil
}

// Close releases every source lock and descriptor. It is safe to call more
// than once, but not concurrently with methods other than Close.
func (sources *Sources) Close() error {
	if sources == nil {
		return nil
	}
	sources.mu.Lock()
	defer sources.mu.Unlock()
	if sources.closed {
		return nil
	}
	sources.closed = true
	var closeErrors []error
	for _, role := range sourceOrder {
		entry := sources.files[role]
		if entry == nil || entry.file == nil {
			continue
		}
		if err := syscall.Flock(int(entry.file.Fd()), syscall.LOCK_UN); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("unlock media source %q: %w", role, err))
		}
		if err := entry.file.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close media source %q: %w", role, err))
		}
	}
	return errors.Join(closeErrors...)
}

// ValidateDistinctRegularTarget proves that a pinned regular-file fixture
// target is not any of the five already opened source inodes. Path inequality
// is insufficient because a hard link can give one inode multiple names.
// Production block-device targets are separated by type; the fixture adapter
// calls this after opening both sides and before its first target write.
func (sources *Sources) ValidateDistinctRegularTarget(target *os.File) error {
	if sources == nil {
		return errors.New("validate media target alias: sources are nil")
	}
	if target == nil {
		return errors.New("validate media target alias: target is nil")
	}
	info, err := target.Stat()
	if err != nil {
		return fmt.Errorf("validate media target alias: inspect target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return errors.New("validate media target alias: target is not one regular file with a Linux identity")
	}
	targetDevice, targetInode := uint64(stat.Dev), uint64(stat.Ino)

	sources.mu.Lock()
	defer sources.mu.Unlock()
	if sources.closed {
		return errors.New("validate media target alias: sources are closed")
	}
	for _, role := range sourceOrder {
		entry := sources.files[role]
		if entry == nil {
			return fmt.Errorf("validate media target alias: missing source %q", role)
		}
		if entry.device == targetDevice && entry.inode == targetInode {
			return fmt.Errorf("fixture target identifies the same underlying file as media source %q", role)
		}
	}
	return nil
}

// DurableTarget is the deliberately small target capability required by
// Stage. Sync is part of the interface because write call order alone does not
// establish durable ordering through the Linux page cache.
type DurableTarget interface {
	io.WriterAt
	Sync() error
}

// Stage writes a complete canonical target image in four durability phases:
//
//  1. zero both GPT regions and sync, durably invalidating any old layout;
//  2. zero all remaining bytes, copy the payloads, and sync;
//  3. copy the backup GPT and sync; and
//  4. copy the primary GPT as the commit record and sync.
//
// A newly written primary GPT can therefore become durable only after the
// exact payload bytes and backup GPT are durable. Any error after the first
// target write is an uncertain destructive result which callers must
// quarantine rather than retry automatically.
//
// The returned count is the number of bytes accepted by WriterAt: the complete
// target zero pass plus all five source files.
func Stage(ctx context.Context, target DurableTarget, plan mediacontract.Plan, sources *Sources) (uint64, error) {
	if ctx == nil {
		return 0, errors.New("stage media: nil context")
	}
	if target == nil {
		return 0, errors.New("stage media: nil target")
	}
	if sources == nil {
		return 0, errors.New("stage media: nil sources")
	}
	if err := plan.Validate(); err != nil {
		return 0, fmt.Errorf("stage media: validate plan: %w", err)
	}

	sources.mu.Lock()
	defer sources.mu.Unlock()
	if sources.closed {
		return 0, errors.New("stage media: sources are closed")
	}
	if sources.planDigest != plan.PlanDigest {
		return 0, errors.New("stage media: sources were opened for a different plan")
	}

	expectedWrites := plan.Target.SizeBytes
	for _, binding := range plan.Layout.Sources {
		if binding.SizeBytes > math.MaxUint64-expectedWrites {
			return 0, errors.New("stage media: byte count overflows uint64")
		}
		expectedWrites += binding.SizeBytes
	}

	// This second complete source pass is intentionally before the first target
	// write. It detects changes between OpenSources and the mutation boundary.
	for _, role := range sourceOrder {
		entry := sources.files[role]
		if entry == nil {
			return 0, fmt.Errorf("stage media: missing source %q", role)
		}
		if _, err := inspectSource(entry); err != nil {
			return 0, fmt.Errorf("stage media preflight: %w", err)
		}
		digest, err := HashRange(ctx, entry.file, 0, entry.size)
		if err != nil {
			return 0, fmt.Errorf("stage media preflight hash %q: %w", role, err)
		}
		if digest != entry.digest {
			return 0, fmt.Errorf("stage media preflight source %q digest is %s, expected %s", role, digest, entry.digest)
		}
		if _, err := inspectSource(entry); err != nil {
			return 0, fmt.Errorf("stage media preflight: %w", err)
		}
	}

	primaryRegion, primaryPresent := findRegion(plan.Layout.Regions, mediacontract.RegionPrimaryGPT)
	backupRegion, backupPresent := findRegion(plan.Layout.Regions, mediacontract.RegionBackupGPT)
	if !primaryPresent || !backupPresent {
		return 0, errors.New("stage media: validated plan is missing a GPT region")
	}

	var written uint64
	for _, region := range []mediacontract.MediaRegion{primaryRegion, backupRegion} {
		zeroed, err := zeroRange(ctx, target, region.OffsetBytes, region.SizeBytes)
		written += zeroed
		if err != nil {
			return written, fmt.Errorf("invalidate %q at byte %d: %w", region.Role, region.OffsetBytes, err)
		}
	}
	if err := target.Sync(); err != nil {
		return written, fmt.Errorf("sync invalidated GPT regions: %w", err)
	}

	for _, region := range plan.Layout.Regions {
		if region.Role == mediacontract.RegionPrimaryGPT || region.Role == mediacontract.RegionBackupGPT {
			continue
		}
		zeroed, err := zeroRange(ctx, target, region.OffsetBytes, region.SizeBytes)
		written += zeroed
		if err != nil {
			return written, fmt.Errorf("zero media region %q at byte %d: %w", region.Role, region.OffsetBytes, err)
		}
	}
	for _, operation := range [...]struct {
		source mediacontract.SourceRole
		region mediacontract.RegionRole
	}{
		{mediacontract.SourceBootFilesystem, mediacontract.RegionBootFilesystem},
		{mediacontract.SourceRootData, mediacontract.RegionRootData},
		{mediacontract.SourceRootHash, mediacontract.RegionRootHash},
	} {
		copied, err := copyBoundSource(ctx, target, plan, sources, operation.source, operation.region)
		written += copied
		if err != nil {
			return written, err
		}
	}
	if err := target.Sync(); err != nil {
		return written, fmt.Errorf("sync staged payloads: %w", err)
	}

	copied, err := copyBoundSource(ctx, target, plan, sources, mediacontract.SourceBackupGPT, mediacontract.RegionBackupGPT)
	written += copied
	if err != nil {
		return written, err
	}
	if err := target.Sync(); err != nil {
		return written, fmt.Errorf("sync backup GPT: %w", err)
	}

	copied, err = copyBoundSource(ctx, target, plan, sources, mediacontract.SourcePrimaryGPT, mediacontract.RegionPrimaryGPT)
	written += copied
	if err != nil {
		return written, err
	}
	if err := target.Sync(); err != nil {
		return written, fmt.Errorf("sync primary GPT commit: %w", err)
	}
	if written != expectedWrites {
		return written, fmt.Errorf("stage media wrote %d bytes, expected %d", written, expectedWrites)
	}
	return written, nil
}

func zeroRange(ctx context.Context, target io.WriterAt, offset, size uint64) (uint64, error) {
	zeroBuffer := make([]byte, transferBufferBytes)
	var written uint64
	for written < size {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		chunk := size - written
		if chunk > uint64(len(zeroBuffer)) {
			chunk = uint64(len(zeroBuffer))
		}
		accepted, err := writeExactAt(target, zeroBuffer[:int(chunk)], offset+written)
		written += accepted
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func copyBoundSource(
	ctx context.Context,
	target io.WriterAt,
	plan mediacontract.Plan,
	sources *Sources,
	sourceRole mediacontract.SourceRole,
	regionRole mediacontract.RegionRole,
) (uint64, error) {
	entry := sources.files[sourceRole]
	if entry == nil {
		return 0, fmt.Errorf("stage media: missing source %q", sourceRole)
	}
	region, present := findRegion(plan.Layout.Regions, regionRole)
	if !present {
		return 0, fmt.Errorf("stage media: validated plan is missing region %q", regionRole)
	}
	copied, digest, err := copySource(ctx, target, region.OffsetBytes, entry)
	if err != nil {
		return copied, fmt.Errorf("write media source %q at byte %d: %w", sourceRole, region.OffsetBytes, err)
	}
	if digest != entry.digest {
		return copied, fmt.Errorf("bytes copied from media source %q digest to %s, expected %s", sourceRole, digest, entry.digest)
	}
	if _, err := inspectSource(entry); err != nil {
		return copied, fmt.Errorf("post-copy source validation: %w", err)
	}
	return copied, nil
}

func inspectSource(entry *sourceFile) (*syscall.Stat_t, error) {
	info, err := entry.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect media source %q: %w", entry.role, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("media source %q must remain a regular file", entry.role)
	}
	if info.Size() < 0 || uint64(info.Size()) != entry.size {
		return nil, fmt.Errorf("media source %q size is %d, expected %d", entry.role, info.Size(), entry.size)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("media source %q has no Linux file identity", entry.role)
	}
	if entry.device != 0 || entry.inode != 0 {
		if uint64(stat.Dev) != entry.device || uint64(stat.Ino) != entry.inode {
			return nil, fmt.Errorf("media source %q file identity changed", entry.role)
		}
	}
	return stat, nil
}

func findRegion(regions []mediacontract.MediaRegion, role mediacontract.RegionRole) (mediacontract.MediaRegion, bool) {
	for _, region := range regions {
		if region.Role == role {
			return region, true
		}
	}
	return mediacontract.MediaRegion{}, false
}

func copySource(ctx context.Context, target io.WriterAt, targetOffset uint64, source *sourceFile) (uint64, mediacontract.Digest, error) {
	hash := sha256.New()
	buffer := make([]byte, transferBufferBytes)
	var copied uint64
	for copied < source.size {
		if err := ctx.Err(); err != nil {
			return copied, digestFromHash(hash), err
		}
		chunk := source.size - copied
		if chunk > uint64(len(buffer)) {
			chunk = uint64(len(buffer))
		}
		n, err := source.file.ReadAt(buffer[:int(chunk)], int64(copied))
		if err != nil && !errors.Is(err, io.EOF) {
			return copied, digestFromHash(hash), err
		}
		if n != int(chunk) {
			return copied, digestFromHash(hash), io.ErrUnexpectedEOF
		}
		accepted, err := writeExactAt(target, buffer[:n], targetOffset+copied)
		if accepted > 0 {
			_, _ = hash.Write(buffer[:int(accepted)])
			copied += accepted
		}
		if err != nil {
			return copied, digestFromHash(hash), err
		}
	}
	return copied, digestFromHash(hash), nil
}

func writeExactAt(target io.WriterAt, data []byte, offset uint64) (uint64, error) {
	if offset > math.MaxInt64 || uint64(len(data)) > math.MaxInt64-offset {
		return 0, errors.New("write range exceeds supported file offsets")
	}
	n, err := target.WriteAt(data, int64(offset))
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("WriterAt returned invalid byte count %d for %d-byte write", n, len(data))
	}
	if err != nil {
		return uint64(n), err
	}
	if n != len(data) {
		return uint64(n), io.ErrShortWrite
	}
	return uint64(n), nil
}

// HashRange computes the canonical SHA-256 digest of one exact ReaderAt range.
// It never depends on or changes a shared seek position.
func HashRange(ctx context.Context, reader io.ReaderAt, offset, size uint64) (mediacontract.Digest, error) {
	if ctx == nil {
		return "", errors.New("hash range: nil context")
	}
	if reader == nil {
		return "", errors.New("hash range: nil reader")
	}
	if offset > math.MaxInt64 || size > math.MaxInt64 || size > math.MaxInt64-offset {
		return "", errors.New("hash range exceeds supported file offsets")
	}
	hash := sha256.New()
	buffer := make([]byte, transferBufferBytes)
	position := offset
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := remaining
		if chunk > uint64(len(buffer)) {
			chunk = uint64(len(buffer))
		}
		n, err := reader.ReadAt(buffer[:int(chunk)], int64(position))
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if n != int(chunk) {
			return "", io.ErrUnexpectedEOF
		}
		_, _ = hash.Write(buffer[:n])
		position += uint64(n)
		remaining -= uint64(n)
	}
	return digestFromHash(hash), nil
}

func digestFromHash(hash interface{ Sum([]byte) []byte }) mediacontract.Digest {
	return mediacontract.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}
