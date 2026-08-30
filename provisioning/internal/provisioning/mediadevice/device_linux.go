//go:build linux

// Package mediadevice contains the narrow Linux adapter shared by the
// production media stager and its separately built read-only verifier. It
// resolves an explicit station-local selector through the existing system
// inventory and pins one exact block-device attachment before either caller
// may use it.
package mediadevice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

const (
	blockGetSize64       = uintptr(0x80081272)
	blockGetDiskSequence = uintptr(0x80081280)
	defaultBufferBytes   = 1024 * 1024
	maximumSysfsBytes    = 4096
)

var stationHostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var inspectProtectedDevice = func(path string) (uint64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 || stat.Rdev == 0 {
		return 0, errors.New("path is not one direct block-device node")
	}
	return uint64(stat.Rdev), nil
}

// StationPolicy is linker-fixed operational policy for the host which is
// allowed to run a specialized media binary. ProtectedDevicePaths are direct
// host device nodes which must never identify the selected target.
type StationPolicy struct {
	ExpectedHostname     string
	ProtectedDevicePaths []string
}

func NewStationPolicy(expectedHostname, protectedDevicePathsCSV string) (StationPolicy, error) {
	if !stationHostnamePattern.MatchString(expectedHostname) {
		return StationPolicy{}, errors.New("linker-fixed execution hostname is not canonical")
	}
	policy := StationPolicy{ExpectedHostname: expectedHostname}
	if protectedDevicePathsCSV == "" {
		return policy, nil
	}
	seen := make(map[string]struct{})
	for _, path := range strings.Split(protectedDevicePathsCSV, ",") {
		if len(policy.ProtectedDevicePaths) == 16 {
			return StationPolicy{}, errors.New("linker-fixed protected device list exceeds 16 entries")
		}
		name := strings.TrimPrefix(path, "/dev/")
		if !strings.HasPrefix(path, "/dev/") || name == "" || name == "." || strings.Contains(name, "/") || strings.ContainsAny(name, " \t\r\n") || filepath.Clean(path) != path {
			return StationPolicy{}, errors.New("linker-fixed protected device path must be one immediate clean /dev node")
		}
		if _, duplicate := seen[path]; duplicate {
			return StationPolicy{}, errors.New("linker-fixed protected device paths contain a duplicate")
		}
		if len(policy.ProtectedDevicePaths) != 0 && policy.ProtectedDevicePaths[len(policy.ProtectedDevicePaths)-1] > path {
			return StationPolicy{}, errors.New("linker-fixed protected device paths are not sorted")
		}
		seen[path] = struct{}{}
		policy.ProtectedDevicePaths = append(policy.ProtectedDevicePaths, path)
	}
	return policy, nil
}

func (policy StationPolicy) ValidateHost(actualHostname string) error {
	if actualHostname != policy.ExpectedHostname {
		return fmt.Errorf("media binary is bound to execution host %q, current host is %q", policy.ExpectedHostname, actualHostname)
	}
	return nil
}

// ValidateTarget rejects a selected attachment which is any linker-protected
// host device. A missing, replaced, symlinked, or non-block protected path also
// fails closed: the independent system-disk barrier must be observable before
// a destructive target is opened.
func (policy StationPolicy) ValidateTarget(facts mediainventory.TargetFacts) error {
	if facts.DeviceNumber == 0 || facts.ResolvedPath == "" {
		return errors.New("selected target has no pinned block-device identity")
	}
	for _, path := range policy.ProtectedDevicePaths {
		if facts.RequestedPath == path || facts.ResolvedPath == path {
			return fmt.Errorf("selected target is protected by station policy: %s", path)
		}
		deviceNumber, err := inspectProtectedDevice(path)
		if err != nil {
			return fmt.Errorf("inspect station-protected device %q: %w", path, err)
		}
		if deviceNumber == facts.DeviceNumber {
			return fmt.Errorf("selected target resolves to station-protected device %s", path)
		}
	}
	return nil
}

type Inspector struct {
	Inventory mediainventory.Inventory
}

func (inspector Inspector) inventory() mediainventory.Inventory {
	if inspector.Inventory != nil {
		return inspector.Inventory
	}
	return mediainventory.SystemInventory{}
}

// InspectSelected proves the read-only safety inventory and required geometry
// for one explicit station-local selector. Physical-media identity is not part
// of the media plan and is not inferred from model, serial, WWID, or by-id data.
func (inspector Inspector) InspectSelected(ctx context.Context, plan mediacontract.Plan, selectedPath string) (mediainventory.TargetFacts, error) {
	if err := plan.Validate(); err != nil {
		return mediainventory.TargetFacts{}, err
	}
	inventory := inspector.inventory()
	facts, err := inventory.Inspect(ctx, selectedPath, mediainventory.ModeSelectedDevice)
	if err != nil {
		return mediainventory.TargetFacts{}, fmt.Errorf("inspect selected device: %w", err)
	}
	usage, err := inventory.Usage(ctx, facts, mediainventory.ModeSelectedDevice)
	if err != nil {
		return mediainventory.TargetFacts{}, fmt.Errorf("inspect selected device usage: %w", err)
	}
	if err := validateFacts(plan, selectedPath, facts, usage); err != nil {
		return mediainventory.TargetFacts{}, err
	}
	if err := validateLogicalSectorSize(plan.Target, facts.SysfsPath); err != nil {
		return mediainventory.TargetFacts{}, err
	}
	if err := validateInactiveBlockGraph(facts.SysfsPath); err != nil {
		return mediainventory.TargetFacts{}, err
	}
	return facts, nil
}

func validateFacts(plan mediacontract.Plan, selectedPath string, facts mediainventory.TargetFacts, usage mediainventory.TargetUsage) error {
	if facts.RequestedPath != selectedPath {
		return errors.New("inventory target path differs from the explicit station selector")
	}
	if facts.ResolvedPath == "" || !filepath.IsAbs(facts.ResolvedPath) || filepath.Clean(facts.ResolvedPath) != facts.ResolvedPath || (facts.ResolvedPath != "/dev" && !strings.HasPrefix(facts.ResolvedPath, "/dev/")) {
		return errors.New("inventory resolved target outside the clean /dev namespace")
	}
	if facts.Kind != mediainventory.TargetBlockDevice || !facts.WholeDevice || facts.DeviceNumber == 0 || facts.DiskSequence == 0 || facts.BootID == "" || facts.SysfsPath == "" {
		return errors.New("inventory target is not one identified whole block-device attachment")
	}
	if facts.SizeBytes != plan.Target.SizeBytes {
		return fmt.Errorf("inventory target size is %d, expected %d", facts.SizeBytes, plan.Target.SizeBytes)
	}
	if usage.Mounted || usage.System || usage.Root || usage.Swap {
		return fmt.Errorf("selected target is in use: mounted=%t system=%t root=%t swap=%t", usage.Mounted, usage.System, usage.Root, usage.Swap)
	}
	return nil
}

func validateLogicalSectorSize(target mediacontract.TargetBinding, sysfsPath string) error {
	if sysfsPath == "" || !filepath.IsAbs(sysfsPath) || filepath.Clean(sysfsPath) != sysfsPath || !strings.HasPrefix(sysfsPath, "/sys/") {
		return errors.New("target sysfs path is not a clean absolute path below /sys")
	}
	logical, err := readSysfsUint(filepath.Join(sysfsPath, "queue", "logical_block_size"))
	if err != nil {
		return fmt.Errorf("read target logical sector size: %w", err)
	}
	if logical != target.LogicalSectorSizeBytes {
		return errors.New("live logical sector size differs from the required media geometry")
	}
	return nil
}

func readSysfsValue(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", errors.New("construct sysfs attribute handle")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximumSysfsBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maximumSysfsBytes {
		return "", errors.New("sysfs attribute exceeds fixed bound")
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("sysfs attribute is empty or contains NUL")
	}
	return value, nil
}

func readSysfsUint(path string) (uint64, error) {
	value, err := readSysfsValue(path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, errors.New("sysfs attribute is not one positive canonical integer")
	}
	if strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("sysfs integer is not canonical decimal")
	}
	return parsed, nil
}

// validateInactiveBlockGraph rejects device-mapper, MD, crypto, loop, or
// other live consumers which may not currently appear in mountinfo or swaps.
// The whole target and every extant partition must have no holders, and the
// approved whole device may not itself be a composite over slave devices.
func validateInactiveBlockGraph(sysfsPath string) error {
	for _, relationship := range []string{"holders", "slaves"} {
		entries, err := readDirectoryNoFollow(filepath.Join(sysfsPath, relationship))
		if err != nil {
			return fmt.Errorf("inspect target %s graph: %w", relationship, err)
		}
		if len(entries) != 0 {
			return fmt.Errorf("target has active sysfs %s dependencies", relationship)
		}
	}
	entries, err := readDirectoryNoFollow(sysfsPath)
	if err != nil {
		return fmt.Errorf("inspect target sysfs children: %w", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect target sysfs child %q: %w", entry.Name(), err)
		}
		if !info.IsDir() {
			continue
		}
		child := filepath.Join(sysfsPath, entry.Name())
		partition, err := os.Lstat(filepath.Join(child, "partition"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect target partition %q: %w", entry.Name(), err)
		}
		if !partition.Mode().IsRegular() {
			return fmt.Errorf("target partition marker %q is not a regular sysfs attribute", entry.Name())
		}
		holders, err := readDirectoryNoFollow(filepath.Join(child, "holders"))
		if err != nil {
			return fmt.Errorf("inspect target partition %q holders: %w", entry.Name(), err)
		}
		if len(holders) != 0 {
			return fmt.Errorf("target partition %q has active sysfs holders", entry.Name())
		}
	}
	return nil
}

func readDirectoryNoFollow(path string) ([]os.DirEntry, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct sysfs directory handle")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	return entries, errors.Join(readErr, closeErr)
}

// SameAttachment requires the entire inventory record, including Linux's
// boot-local disk sequence, to remain fixed across a single staging phase.
func SameAttachment(initial, current mediainventory.TargetFacts) error {
	if current != initial {
		return errors.New("block-device attachment identity changed during the operation")
	}
	return nil
}

func (inspector Inspector) ReinspectSame(ctx context.Context, plan mediacontract.Plan, selectedPath string, initial mediainventory.TargetFacts) (mediainventory.TargetFacts, error) {
	current, err := inspector.InspectSelected(ctx, plan, selectedPath)
	if err != nil {
		return mediainventory.TargetFacts{}, err
	}
	if err := SameAttachment(initial, current); err != nil {
		return mediainventory.TargetFacts{}, err
	}
	return current, nil
}

func OpenLocked(facts mediainventory.TargetFacts, writable bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	if writable {
		flags = syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_EXCL
	}
	fd, err := syscall.Open(facts.ResolvedPath, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned block device: %w", err)
	}
	file := os.NewFile(uintptr(fd), facts.ResolvedPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct pinned block-device handle")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock pinned block device exclusively: %w", err)
	}
	if err := ValidateOpened(file, facts); err != nil {
		_ = CloseLocked(file)
		return nil, err
	}
	return file, nil
}

func CloseLocked(file *os.File) error {
	if file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

func ValidateOpened(file *os.File, facts mediainventory.TargetFacts) error {
	if file == nil {
		return errors.New("block-device handle is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat pinned block device: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 || uint64(stat.Rdev) != facts.DeviceNumber {
		return errors.New("opened target is not the inventoried block device")
	}
	resolved, err := filepath.EvalSymlinks(facts.RequestedPath)
	if err != nil || resolved != facts.ResolvedPath {
		return errors.New("selected device path no longer resolves to the pinned device")
	}
	alias, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat re-resolved selected target: %w", err)
	}
	aliasStat, ok := alias.Sys().(*syscall.Stat_t)
	if !ok || alias.Mode()&os.ModeDevice == 0 || alias.Mode()&os.ModeCharDevice != 0 || aliasStat.Rdev != stat.Rdev {
		return errors.New("selected device path no longer identifies the pinned device number")
	}
	size, err := ioctlUint64(file, blockGetSize64)
	if err != nil {
		return fmt.Errorf("read pinned block-device size: %w", err)
	}
	sequence, err := ioctlUint64(file, blockGetDiskSequence)
	if err != nil {
		return fmt.Errorf("read pinned block-device disk sequence: %w", err)
	}
	if size != facts.SizeBytes || sequence == 0 || sequence != facts.DiskSequence {
		return errors.New("pinned block-device capacity or attachment sequence changed")
	}
	return nil
}

func ioctlUint64(file *os.File, operation uintptr) (uint64, error) {
	var value uint64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), operation, uintptr(unsafe.Pointer(&value)))
	if errno != 0 {
		return 0, errno
	}
	return value, nil
}

func HashRange(ctx context.Context, reader io.ReaderAt, offset, size uint64) (mediacontract.Digest, error) {
	if reader == nil || offset > uint64(^uint64(0)>>1) || size > uint64(^uint64(0)>>1) || offset+size < offset || offset+size > uint64(^uint64(0)>>1) {
		return "", errors.New("hash range exceeds supported file offsets")
	}
	hash := sha256.New()
	buffer := make([]byte, defaultBufferBytes)
	position, remaining := offset, size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := uint64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := reader.ReadAt(buffer[:int(chunk)], int64(position))
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
	return mediacontract.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
