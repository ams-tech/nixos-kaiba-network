//go:build linux

package mediastager

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	blockGetSize64       = uintptr(0x80081272)
	blockGetDiskSequence = uintptr(0x80081280)
)

type SystemInventory struct {
	MountInfoPath string
	SwapsPath     string
	SysDevPath    string
}

func (inventory SystemInventory) defaults() SystemInventory {
	if inventory.MountInfoPath == "" {
		inventory.MountInfoPath = "/proc/self/mountinfo"
	}
	if inventory.SwapsPath == "" {
		inventory.SwapsPath = "/proc/swaps"
	}
	if inventory.SysDevPath == "" {
		inventory.SysDevPath = "/sys/dev/block"
	}
	return inventory
}

func (inventory SystemInventory) Inspect(ctx context.Context, requestedPath string, mode Mode) (TargetFacts, error) {
	if err := ctx.Err(); err != nil {
		return TargetFacts{}, err
	}
	if err := validateTargetPath(requestedPath, mode); err != nil {
		return TargetFacts{}, err
	}
	if mode == ModeFixture {
		return inspectRegularFixture(requestedPath)
	}
	return inventory.defaults().inspectDevice(requestedPath)
}

func inspectRegularFixture(path string) (TargetFacts, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return TargetFacts{}, fmt.Errorf("inspect fixture target: %w", err)
	}
	if !info.Mode().IsRegular() {
		return TargetFacts{}, fmt.Errorf("%w: fixture target must be a non-symlink regular file", ErrUnsafeTarget)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 || info.Size() < 0 {
		return TargetFacts{}, fmt.Errorf("%w: fixture target identity is unavailable", ErrUnsafeTarget)
	}
	return TargetFacts{
		RequestedPath: path,
		ResolvedPath:  path,
		Identity:      filepath.Base(path),
		SizeBytes:     uint64(info.Size()),
		Kind:          TargetRegularFile,
		FileDevice:    uint64(stat.Dev),
		Inode:         stat.Ino,
	}, nil
}

func (inventory SystemInventory) inspectDevice(requestedPath string) (TargetFacts, error) {
	entry, err := os.Lstat(requestedPath)
	if err != nil {
		return TargetFacts{}, fmt.Errorf("inspect by-id target: %w", err)
	}
	if entry.Mode()&os.ModeSymlink == 0 && entry.Mode()&os.ModeDevice == 0 {
		return TargetFacts{}, fmt.Errorf("%w: by-id target is neither a device alias nor a device node", ErrUnsafeTarget)
	}
	resolvedPath, err := filepath.EvalSymlinks(requestedPath)
	if err != nil {
		return TargetFacts{}, fmt.Errorf("resolve by-id target: %w", err)
	}
	if !cleanAbsolutePath(resolvedPath) || (resolvedPath != "/dev" && !strings.HasPrefix(resolvedPath, "/dev/")) {
		return TargetFacts{}, fmt.Errorf("%w: by-id alias resolves outside /dev", ErrUnsafeTarget)
	}
	fd, err := syscall.Open(resolvedPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return TargetFacts{}, fmt.Errorf("open resolved block device for inventory: %w", err)
	}
	file := os.NewFile(uintptr(fd), resolvedPath)
	if file == nil {
		_ = syscall.Close(fd)
		return TargetFacts{}, errors.New("construct block-device inventory handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return TargetFacts{}, fmt.Errorf("stat resolved block device: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 || stat.Rdev == 0 {
		return TargetFacts{}, fmt.Errorf("%w: resolved target is not a block device", ErrUnsafeTarget)
	}
	size, err := blockDeviceSize(file)
	if err != nil {
		return TargetFacts{}, err
	}
	diskSequence, err := blockDeviceDiskSequence(file)
	if err != nil {
		return TargetFacts{}, err
	}
	deviceKey := majorMinor(uint64(stat.Rdev))
	sysfsPath, err := filepath.EvalSymlinks(filepath.Join(inventory.SysDevPath, deviceKey))
	if err != nil {
		return TargetFacts{}, fmt.Errorf("resolve target sysfs identity: %w", err)
	}
	_, partitionErr := os.Stat(filepath.Join(sysfsPath, "partition"))
	if partitionErr != nil && !errors.Is(partitionErr, os.ErrNotExist) {
		return TargetFacts{}, fmt.Errorf("inspect target partition marker: %w", partitionErr)
	}
	return TargetFacts{
		RequestedPath: requestedPath,
		ResolvedPath:  resolvedPath,
		Identity:      filepath.Base(requestedPath),
		SizeBytes:     size,
		Kind:          TargetBlockDevice,
		WholeDevice:   errors.Is(partitionErr, os.ErrNotExist),
		DeviceNumber:  uint64(stat.Rdev),
		DiskSequence:  diskSequence,
		SysfsPath:     sysfsPath,
	}, nil
}

func (inventory SystemInventory) Usage(ctx context.Context, facts TargetFacts, mode Mode) (TargetUsage, error) {
	if err := ctx.Err(); err != nil {
		return TargetUsage{}, err
	}
	if mode == ModeFixture {
		return TargetUsage{}, nil
	}
	inventory = inventory.defaults()
	usage := TargetUsage{}
	mounts, err := os.Open(inventory.MountInfoPath)
	if err != nil {
		return TargetUsage{}, fmt.Errorf("open mount inventory: %w", err)
	}
	scanner := bufio.NewScanner(mounts)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			mounts.Close()
			return TargetUsage{}, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			mounts.Close()
			return TargetUsage{}, errors.New("mount inventory contains a malformed record")
		}
		candidate, err := inventory.sysfsForDevice(fields[2])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			mounts.Close()
			return TargetUsage{}, err
		}
		uses, err := deviceUsesTarget(candidate, facts.SysfsPath, make(map[string]bool))
		if err != nil {
			mounts.Close()
			return TargetUsage{}, err
		}
		if !uses {
			continue
		}
		mountPoint, err := unescapeProcField(fields[4])
		if err != nil {
			mounts.Close()
			return TargetUsage{}, err
		}
		usage.Mounted = true
		usage.MountPoints = append(usage.MountPoints, mountPoint)
		if mountPoint == "/" {
			usage.Root = true
		}
		switch mountPoint {
		case "/", "/boot", "/boot/efi", "/home", "/nix", "/usr", "/var":
			usage.System = true
		}
	}
	if err := scanner.Err(); err != nil {
		mounts.Close()
		return TargetUsage{}, fmt.Errorf("read mount inventory: %w", err)
	}
	if err := mounts.Close(); err != nil {
		return TargetUsage{}, fmt.Errorf("close mount inventory: %w", err)
	}

	swaps, err := os.Open(inventory.SwapsPath)
	if err != nil {
		return TargetUsage{}, fmt.Errorf("open swap inventory: %w", err)
	}
	scanner = bufio.NewScanner(swaps)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		source, err := unescapeProcField(fields[0])
		if err != nil {
			swaps.Close()
			return TargetUsage{}, err
		}
		candidate, err := inventory.sysfsForPath(source)
		if err != nil {
			swaps.Close()
			return TargetUsage{}, fmt.Errorf("inspect swap source %q: %w", source, err)
		}
		uses, err := deviceUsesTarget(candidate, facts.SysfsPath, make(map[string]bool))
		if err != nil {
			swaps.Close()
			return TargetUsage{}, err
		}
		if uses {
			usage.Swap = true
			usage.SwapSources = append(usage.SwapSources, source)
		}
	}
	if err := scanner.Err(); err != nil {
		swaps.Close()
		return TargetUsage{}, fmt.Errorf("read swap inventory: %w", err)
	}
	if err := swaps.Close(); err != nil {
		return TargetUsage{}, fmt.Errorf("close swap inventory: %w", err)
	}
	return usage, nil
}

func (inventory SystemInventory) sysfsForPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("swap source identity is unavailable")
	}
	device := uint64(stat.Dev)
	if info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
		device = uint64(stat.Rdev)
	}
	return inventory.sysfsForDevice(majorMinor(device))
}

func (inventory SystemInventory) sysfsForDevice(key string) (string, error) {
	if _, _, err := parseMajorMinor(key); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(inventory.SysDevPath, key))
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func blockDeviceSize(file *os.File) (uint64, error) {
	var size uint64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blockGetSize64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, fmt.Errorf("read block-device size: %w", errno)
	}
	if size == 0 {
		return 0, fmt.Errorf("%w: block-device size is zero", ErrUnsafeTarget)
	}
	return size, nil
}

func blockDeviceDiskSequence(file *os.File) (uint64, error) {
	var sequence uint64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blockGetDiskSequence, uintptr(unsafe.Pointer(&sequence)))
	if errno != 0 {
		return 0, fmt.Errorf("read block-device disk sequence: %w", errno)
	}
	if sequence == 0 {
		return 0, fmt.Errorf("%w: block-device disk sequence is zero", ErrUnsafeTarget)
	}
	return sequence, nil
}

func majorMinor(device uint64) string {
	major := ((device & 0x00000000000fff00) >> 8) | ((device & 0xfffff00000000000) >> 32)
	minor := (device & 0x00000000000000ff) | ((device & 0x00000ffffff00000) >> 12)
	return fmt.Sprintf("%d:%d", major, minor)
}

func parseMajorMinor(value string) (uint64, uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("device number is malformed")
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, errors.New("device major number is malformed")
	}
	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, errors.New("device minor number is malformed")
	}
	return major, minor, nil
}

func deviceUsesTarget(candidate, target string, seen map[string]bool) (bool, error) {
	if candidate == target || strings.HasPrefix(candidate, target+string(filepath.Separator)) {
		return true, nil
	}
	if seen[candidate] {
		return false, nil
	}
	seen[candidate] = true
	slaves, err := os.ReadDir(filepath.Join(candidate, "slaves"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect block-device dependencies: %w", err)
	}
	for _, slave := range slaves {
		resolved, err := filepath.EvalSymlinks(filepath.Join(candidate, "slaves", slave.Name()))
		if err != nil {
			return false, fmt.Errorf("resolve block-device dependency: %w", err)
		}
		uses, err := deviceUsesTarget(resolved, target, seen)
		if err != nil {
			return false, err
		}
		if uses {
			return true, nil
		}
	}
	return false, nil
}

func unescapeProcField(value string) (string, error) {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	result := replacer.Replace(value)
	if strings.Contains(result, `\0`) {
		return "", errors.New("proc inventory contains an unsupported escape")
	}
	return result, nil
}
