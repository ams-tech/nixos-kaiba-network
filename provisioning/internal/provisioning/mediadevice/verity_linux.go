//go:build linux

package mediadevice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

const (
	defaultByPARTUUIDRoot        = "/dev/disk/by-partuuid"
	defaultSysDevBlockPath       = "/sys/dev/block"
	maximumVerityDiagnosticBytes = 64 * 1024
)

// PartitionVerityVerifier runs one linker-fixed veritysetup over read-only,
// pinned partition descriptors. It resolves only the two PARTUUIDs already
// validated by the media plan, proves that both are exact children of Whole,
// and exposes neither a writable descriptor nor a caller-selected executable.
//
// ByPARTUUIDRoot and SysDevPath are injectable filesystem roots for isolated
// tests. Production callers leave them empty to select /dev/disk/by-partuuid
// and /sys/dev/block.
type PartitionVerityVerifier struct {
	Path           string
	Whole          mediainventory.TargetFacts
	ByPARTUUIDRoot string
	SysDevPath     string
	hooks          *partitionVerityHooks
}

var _ mediacontract.VerityVerifier = PartitionVerityVerifier{}

type partitionVerityHooks struct {
	lstat         func(string) (os.FileInfo, error)
	evalSymlinks  func(string) (string, error)
	openReadOnly  func(string) (*os.File, error)
	inspectFD     func(*os.File) (partitionFDIdentity, error)
	readSysfs     func(string) (string, error)
	validateWhole func(io.ReaderAt, mediainventory.TargetFacts) error
	run           func(context.Context, partitionVerityCommand) error
}

type partitionFDIdentity struct {
	DeviceNumber uint64
	SizeBytes    uint64
	BlockDevice  bool
}

type partitionVerityCommand struct {
	Path        string
	Arguments   []string
	Environment []string
	Directory   string
	ExtraFiles  []*os.File
}

type partitionSnapshot struct {
	AliasPath    string
	ResolvedPath string
	SysfsPath    string
	DeviceNumber uint64
	SizeBytes    uint64
	StartBytes   uint64
	Number       uint32
}

func (verifier PartitionVerityVerifier) defaults() (PartitionVerityVerifier, partitionVerityHooks) {
	if verifier.ByPARTUUIDRoot == "" {
		verifier.ByPARTUUIDRoot = defaultByPARTUUIDRoot
	}
	if verifier.SysDevPath == "" {
		verifier.SysDevPath = defaultSysDevBlockPath
	}
	hooks := partitionVerityHooks{
		lstat:         os.Lstat,
		evalSymlinks:  filepath.EvalSymlinks,
		openReadOnly:  openPartitionReadOnly,
		inspectFD:     inspectPartitionFD,
		readSysfs:     readSysfsValue,
		validateWhole: validateWholeReader,
		run:           runPartitionVerity,
	}
	if verifier.hooks != nil {
		provided := verifier.hooks
		if provided.lstat != nil {
			hooks.lstat = provided.lstat
		}
		if provided.evalSymlinks != nil {
			hooks.evalSymlinks = provided.evalSymlinks
		}
		if provided.openReadOnly != nil {
			hooks.openReadOnly = provided.openReadOnly
		}
		if provided.inspectFD != nil {
			hooks.inspectFD = provided.inspectFD
		}
		if provided.readSysfs != nil {
			hooks.readSysfs = provided.readSysfs
		}
		if provided.validateWhole != nil {
			hooks.validateWhole = provided.validateWhole
		}
		if provided.run != nil {
			hooks.run = provided.run
		}
	}
	return verifier, hooks
}

// Validate checks immutable configuration that does not require a live target.
func (verifier PartitionVerityVerifier) Validate() error {
	verifier, hooks := verifier.defaults()
	if verifier.Path == "" || !filepath.IsAbs(verifier.Path) || filepath.Clean(verifier.Path) != verifier.Path || !strings.HasPrefix(verifier.Path, "/nix/store/") {
		return errors.New("generic build has no linker-fixed veritysetup store executable")
	}
	info, err := hooks.lstat(verifier.Path)
	if err != nil {
		return fmt.Errorf("inspect linker-fixed veritysetup: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("linker-fixed veritysetup must be an executable non-symlink regular file")
	}
	if err := validatePartitionRoots(verifier.ByPARTUUIDRoot, verifier.SysDevPath); err != nil {
		return err
	}
	if err := validateWholeFacts(verifier.Whole, verifier.SysDevPath); err != nil {
		return err
	}
	return nil
}

// Verify implements mediacontract.VerityVerifier without copying either
// partition into scratch storage. The whole-device ReaderAt must be the pinned
// *os.File already held by the independent device verifier in production.
func (verifier PartitionVerityVerifier) Verify(ctx context.Context, target io.ReaderAt, data, hash mediacontract.GPTPartition, contract mediacontract.VerityContract) error {
	if ctx == nil {
		return errors.New("partition dm-verity verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	verifier, hooks := verifier.defaults()
	if err := verifier.Validate(); err != nil {
		return err
	}
	dataBlocks, err := validatePartitionVerityContract(data, hash, contract)
	if err != nil {
		return err
	}
	if err := hooks.validateWhole(target, verifier.Whole); err != nil {
		return fmt.Errorf("validate pinned whole target before dm-verity: %w", err)
	}
	if err := verifier.validateWholeSysfs(hooks); err != nil {
		return err
	}

	dataFile, dataSnapshot, err := verifier.openPartition(hooks, data, contract.DataPartitionGUID)
	if err != nil {
		return fmt.Errorf("open root-data partition: %w", err)
	}
	defer dataFile.Close() //nolint:errcheck
	hashFile, hashSnapshot, err := verifier.openPartition(hooks, hash, contract.HashPartitionGUID)
	if err != nil {
		return fmt.Errorf("open root-hash partition: %w", err)
	}
	defer hashFile.Close() //nolint:errcheck
	if dataSnapshot.DeviceNumber == hashSnapshot.DeviceNumber || dataSnapshot.ResolvedPath == hashSnapshot.ResolvedPath || dataSnapshot.SysfsPath == hashSnapshot.SysfsPath {
		return errors.New("root-data and root-hash PARTUUIDs resolve to the same partition")
	}

	command := partitionVerityCommand{
		Path: verifier.Path,
		Arguments: []string{
			"verify",
			"--hash=" + contract.Algorithm,
			fmt.Sprintf("--data-block-size=%d", contract.DataBlockSizeBytes),
			fmt.Sprintf("--hash-block-size=%d", contract.HashBlockSizeBytes),
			fmt.Sprintf("--data-blocks=%d", dataBlocks),
			"/proc/self/fd/3",
			"/proc/self/fd/4",
			strings.TrimPrefix(string(contract.RootHash), "sha256:"),
		},
		Environment: []string{"LC_ALL=C", "TZ=UTC", "PATH=/nonexistent"},
		Directory:   "/",
		ExtraFiles:  []*os.File{dataFile, hashFile},
	}
	runErr := hooks.run(ctx, command)
	if runErr != nil {
		runErr = fmt.Errorf("linker-fixed veritysetup rejected the pinned partition pair: %w", runErr)
	}
	return errors.Join(runErr, ctx.Err(), verifier.revalidateAfterCommand(hooks, target, dataFile, hashFile, data, hash, contract, dataSnapshot, hashSnapshot))
}

func (verifier PartitionVerityVerifier) revalidateAfterCommand(hooks partitionVerityHooks, target io.ReaderAt, dataFile, hashFile *os.File, data, hash mediacontract.GPTPartition, contract mediacontract.VerityContract, dataSnapshot, hashSnapshot partitionSnapshot) error {
	if err := hooks.validateWhole(target, verifier.Whole); err != nil {
		return fmt.Errorf("revalidate pinned whole target after dm-verity: %w", err)
	}
	if err := verifier.validateWholeSysfs(hooks); err != nil {
		return fmt.Errorf("revalidate whole-target sysfs identity after dm-verity: %w", err)
	}
	if err := verifier.revalidatePartition(hooks, dataFile, data, contract.DataPartitionGUID, dataSnapshot); err != nil {
		return fmt.Errorf("revalidate root-data partition after dm-verity: %w", err)
	}
	if err := verifier.revalidatePartition(hooks, hashFile, hash, contract.HashPartitionGUID, hashSnapshot); err != nil {
		return fmt.Errorf("revalidate root-hash partition after dm-verity: %w", err)
	}
	return nil
}

func validatePartitionRoots(byPARTUUIDRoot, sysDevPath string) error {
	for label, value := range map[string]string{
		"PARTUUID root":     byPARTUUIDRoot,
		"sysfs device root": sysDevPath,
	} {
		if value == "" || value == "/" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be one clean absolute non-root path", label)
		}
	}
	if filepath.Base(byPARTUUIDRoot) != "by-partuuid" || filepath.Base(filepath.Dir(byPARTUUIDRoot)) != "disk" {
		return errors.New("PARTUUID root must end in /disk/by-partuuid")
	}
	if filepath.Base(sysDevPath) != "block" || filepath.Base(filepath.Dir(sysDevPath)) != "dev" {
		return errors.New("sysfs device root must end in /dev/block")
	}
	deviceNamespace := filepath.Dir(filepath.Dir(byPARTUUIDRoot))
	sysNamespace := filepath.Dir(filepath.Dir(sysDevPath))
	if deviceNamespace == "/" || sysNamespace == "/" {
		return errors.New("device and sysfs namespaces must not resolve to filesystem root")
	}
	return nil
}

func validateWholeFacts(facts mediainventory.TargetFacts, sysDevPath string) error {
	if facts.Kind != mediainventory.TargetBlockDevice || !facts.WholeDevice || facts.DeviceNumber == 0 || facts.SizeBytes == 0 || facts.DiskSequence == 0 || facts.BootID == "" {
		return errors.New("partition verifier requires one pinned whole block-device attachment")
	}
	if facts.SysfsPath == "" || !filepath.IsAbs(facts.SysfsPath) || filepath.Clean(facts.SysfsPath) != facts.SysfsPath {
		return errors.New("whole target has no clean absolute sysfs identity")
	}
	sysNamespace := filepath.Dir(filepath.Dir(sysDevPath))
	if facts.SysfsPath == sysNamespace || !strings.HasPrefix(facts.SysfsPath, sysNamespace+string(filepath.Separator)) {
		return errors.New("whole target sysfs identity is outside the configured sysfs namespace")
	}
	return nil
}

func validatePartitionVerityContract(data, hash mediacontract.GPTPartition, contract mediacontract.VerityContract) (uint64, error) {
	if data.Role != mediacontract.PartitionRootData || hash.Role != mediacontract.PartitionRootHash || data.Number == 0 || hash.Number == 0 || data.Number == hash.Number {
		return 0, errors.New("dm-verity requires distinct canonical root-data and root-hash partitions")
	}
	if data.UniqueGUID != contract.DataPartitionGUID || hash.UniqueGUID != contract.HashPartitionGUID || data.UniqueGUID == hash.UniqueGUID {
		return 0, errors.New("dm-verity PARTUUIDs differ from the exact GPT partition bindings")
	}
	if contract.Algorithm != "sha256" || contract.DataBlockSizeBytes != 4096 || contract.HashBlockSizeBytes != 4096 || contract.Mapper != "/dev/mapper/root" {
		return 0, errors.New("dm-verity contract differs from the frozen SHA-256/4096-byte policy")
	}
	rootHash := string(contract.RootHash)
	if len(rootHash) != len("sha256:")+64 || !strings.HasPrefix(rootHash, "sha256:") {
		return 0, errors.New("dm-verity root hash is not canonical SHA-256")
	}
	for _, value := range rootHash[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", value) {
			return 0, errors.New("dm-verity root hash is not canonical lowercase hexadecimal")
		}
	}
	for label, partition := range map[string]mediacontract.GPTPartition{"root-data": data, "root-hash": hash} {
		if partition.OffsetBytes == 0 || partition.SizeBytes == 0 || partition.UsedSizeBytes == 0 || partition.UsedSizeBytes > partition.SizeBytes || partition.OffsetBytes%mediacontract.SectorSizeBytes != 0 || partition.SizeBytes%mediacontract.SectorSizeBytes != 0 {
			return 0, fmt.Errorf("%s partition geometry is invalid", label)
		}
	}
	if data.UsedSizeBytes%uint64(contract.DataBlockSizeBytes) != 0 || hash.UsedSizeBytes%uint64(contract.HashBlockSizeBytes) != 0 {
		return 0, errors.New("dm-verity used sizes must be exact whole block counts")
	}
	dataEnd := data.OffsetBytes + data.SizeBytes
	hashEnd := hash.OffsetBytes + hash.SizeBytes
	if dataEnd < data.OffsetBytes || hashEnd < hash.OffsetBytes || !(dataEnd <= hash.OffsetBytes || hashEnd <= data.OffsetBytes) {
		return 0, errors.New("dm-verity partitions overlap or overflow")
	}
	dataBlocks := data.UsedSizeBytes / uint64(contract.DataBlockSizeBytes)
	if dataBlocks == 0 {
		return 0, errors.New("dm-verity data block count is zero")
	}
	return dataBlocks, nil
}

func (verifier PartitionVerityVerifier) validateWholeSysfs(hooks partitionVerityHooks) error {
	resolved, err := resolveSysfsDevice(hooks, verifier.SysDevPath, verifier.Whole.DeviceNumber)
	if err != nil {
		return fmt.Errorf("resolve whole-target sysfs device: %w", err)
	}
	if resolved != verifier.Whole.SysfsPath {
		return errors.New("whole-target device number resolves to a different sysfs identity")
	}
	return nil
}

func (verifier PartitionVerityVerifier) openPartition(hooks partitionVerityHooks, partition mediacontract.GPTPartition, guid string) (*os.File, partitionSnapshot, error) {
	snapshot, err := verifier.resolvePartition(hooks, partition, guid)
	if err != nil {
		return nil, partitionSnapshot{}, err
	}
	file, err := hooks.openReadOnly(snapshot.ResolvedPath)
	if err != nil {
		return nil, partitionSnapshot{}, fmt.Errorf("open resolved partition read-only: %w", err)
	}
	identity, err := hooks.inspectFD(file)
	if err != nil {
		file.Close()
		return nil, partitionSnapshot{}, fmt.Errorf("inspect opened partition descriptor: %w", err)
	}
	if !identity.BlockDevice || identity.DeviceNumber != snapshot.DeviceNumber || identity.SizeBytes != partition.SizeBytes {
		file.Close()
		return nil, partitionSnapshot{}, errors.New("opened partition descriptor identity or exact size differs from sysfs and the media plan")
	}
	return file, snapshot, nil
}

func (verifier PartitionVerityVerifier) resolvePartition(hooks partitionVerityHooks, partition mediacontract.GPTPartition, guid string) (partitionSnapshot, error) {
	alias := filepath.Join(verifier.ByPARTUUIDRoot, guid)
	if filepath.Dir(alias) != verifier.ByPARTUUIDRoot {
		return partitionSnapshot{}, errors.New("PARTUUID escaped its fixed alias root")
	}
	aliasInfo, err := hooks.lstat(alias)
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("inspect PARTUUID alias: %w", err)
	}
	if aliasInfo.Mode()&os.ModeSymlink == 0 {
		return partitionSnapshot{}, errors.New("PARTUUID selector is not one symbolic link")
	}
	resolved, err := hooks.evalSymlinks(alias)
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("resolve PARTUUID alias: %w", err)
	}
	deviceNamespace := filepath.Dir(filepath.Dir(verifier.ByPARTUUIDRoot))
	if resolved == deviceNamespace || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved || !strings.HasPrefix(resolved, deviceNamespace+string(filepath.Separator)) {
		return partitionSnapshot{}, errors.New("PARTUUID alias resolves outside the configured device namespace")
	}

	info, err := hooks.lstat(resolved)
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("inspect resolved PARTUUID target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 || info.Mode()&os.ModeSymlink != 0 || uint64(stat.Rdev) == 0 {
		return partitionSnapshot{}, errors.New("PARTUUID alias does not resolve to one non-symlink block device")
	}
	deviceNumber := uint64(stat.Rdev)
	if deviceNumber == verifier.Whole.DeviceNumber {
		return partitionSnapshot{}, errors.New("PARTUUID selector resolves to the whole target rather than a partition")
	}
	sysfsPath, err := resolveSysfsDevice(hooks, verifier.SysDevPath, deviceNumber)
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("resolve partition sysfs identity: %w", err)
	}
	if filepath.Dir(sysfsPath) != verifier.Whole.SysfsPath {
		return partitionSnapshot{}, errors.New("PARTUUID partition is not a direct child of the exact whole target")
	}

	deviceText, err := hooks.readSysfs(filepath.Join(sysfsPath, "dev"))
	if err != nil || deviceText != linuxDeviceKey(deviceNumber) {
		return partitionSnapshot{}, errors.New("partition sysfs device number differs from the opened PARTUUID target")
	}
	number, err := readCanonicalPositive(hooks, filepath.Join(sysfsPath, "partition"))
	if err != nil || number != uint64(partition.Number) {
		return partitionSnapshot{}, errors.New("partition sysfs number differs from the exact GPT role")
	}
	startSectors, err := readCanonicalPositive(hooks, filepath.Join(sysfsPath, "start"))
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("read partition start geometry: %w", err)
	}
	sizeSectors, err := readCanonicalPositive(hooks, filepath.Join(sysfsPath, "size"))
	if err != nil {
		return partitionSnapshot{}, fmt.Errorf("read partition size geometry: %w", err)
	}
	if startSectors > ^uint64(0)/mediacontract.SectorSizeBytes || sizeSectors > ^uint64(0)/mediacontract.SectorSizeBytes {
		return partitionSnapshot{}, errors.New("partition sysfs geometry overflows bytes")
	}
	startBytes := startSectors * mediacontract.SectorSizeBytes
	sizeBytes := sizeSectors * mediacontract.SectorSizeBytes
	if startBytes != partition.OffsetBytes || sizeBytes != partition.SizeBytes {
		return partitionSnapshot{}, errors.New("partition sysfs geometry differs from the exact media plan")
	}
	return partitionSnapshot{
		AliasPath: alias, ResolvedPath: resolved, SysfsPath: sysfsPath,
		DeviceNumber: deviceNumber, SizeBytes: sizeBytes, StartBytes: startBytes, Number: partition.Number,
	}, nil
}

func (verifier PartitionVerityVerifier) revalidatePartition(hooks partitionVerityHooks, file *os.File, partition mediacontract.GPTPartition, guid string, initial partitionSnapshot) error {
	current, err := verifier.resolvePartition(hooks, partition, guid)
	if err != nil {
		return err
	}
	if current != initial {
		return errors.New("PARTUUID alias, sysfs identity, or partition geometry changed during verification")
	}
	identity, err := hooks.inspectFD(file)
	if err != nil {
		return err
	}
	if !identity.BlockDevice || identity.DeviceNumber != initial.DeviceNumber || identity.SizeBytes != partition.SizeBytes {
		return errors.New("pinned partition descriptor identity or size changed during verification")
	}
	return nil
}

func resolveSysfsDevice(hooks partitionVerityHooks, root string, deviceNumber uint64) (string, error) {
	alias := filepath.Join(root, linuxDeviceKey(deviceNumber))
	if filepath.Dir(alias) != root {
		return "", errors.New("device number escaped the sysfs device root")
	}
	info, err := hooks.lstat(alias)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("sysfs device selector is not a symbolic link")
	}
	resolved, err := hooks.evalSymlinks(alias)
	if err != nil {
		return "", err
	}
	sysNamespace := filepath.Dir(filepath.Dir(root))
	if resolved == sysNamespace || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved || !strings.HasPrefix(resolved, sysNamespace+string(filepath.Separator)) {
		return "", errors.New("sysfs device selector resolves outside the configured sysfs namespace")
	}
	return resolved, nil
}

func readCanonicalPositive(hooks partitionVerityHooks, path string) (uint64, error) {
	value, err := hooks.readSysfs(path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("sysfs attribute is not one positive canonical decimal integer")
	}
	return parsed, nil
}

func openPartitionReadOnly(path string) (*os.File, error) {
	// Whole is already held under the caller's O_EXCL claim. Linux rejects a
	// second exclusive claim on one of its child partitions because each open
	// file is a distinct holder. A non-exclusive read-only child descriptor is
	// permitted while preserving the whole-device claim, and is pinned below by
	// its rdev, exact size, parent sysfs identity, and partition geometry.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("construct partition descriptor")
	}
	return file, nil
}

func inspectPartitionFD(file *os.File) (partitionFDIdentity, error) {
	if file == nil {
		return partitionFDIdentity{}, errors.New("partition descriptor is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return partitionFDIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return partitionFDIdentity{}, errors.New("partition descriptor identity is unavailable")
	}
	size, err := ioctlUint64(file, blockGetSize64)
	if err != nil {
		return partitionFDIdentity{}, fmt.Errorf("read partition size: %w", err)
	}
	return partitionFDIdentity{
		DeviceNumber: uint64(stat.Rdev), SizeBytes: size,
		BlockDevice: info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0,
	}, nil
}

func validateWholeReader(target io.ReaderAt, facts mediainventory.TargetFacts) error {
	file, ok := target.(*os.File)
	if !ok {
		return errors.New("whole target reader is not one pinned file descriptor")
	}
	return ValidateOpened(file, facts)
}

func runPartitionVerity(ctx context.Context, specification partitionVerityCommand) error {
	if len(specification.ExtraFiles) != 2 || specification.ExtraFiles[0] == nil || specification.ExtraFiles[1] == nil {
		return errors.New("veritysetup requires exactly two pinned partition descriptors")
	}
	command := exec.CommandContext(ctx, specification.Path, specification.Arguments...)
	command.Env = append([]string(nil), specification.Environment...)
	command.Dir = specification.Directory
	command.ExtraFiles = append([]*os.File(nil), specification.ExtraFiles...)
	diagnostic := &partitionVerityDiagnostic{maximum: maximumVerityDiagnosticBytes}
	command.Stdout = diagnostic
	command.Stderr = diagnostic
	if err := command.Run(); err != nil {
		if diagnostic.overflow {
			return errors.New("veritysetup diagnostic exceeded its fixed byte bound")
		}
		message := strings.TrimSpace(diagnostic.String())
		if message == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, message)
	}
	if diagnostic.overflow {
		return errors.New("veritysetup diagnostic exceeded its fixed byte bound")
	}
	return nil
}

type partitionVerityDiagnostic struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *partitionVerityDiagnostic) Write(value []byte) (int, error) {
	accepted := len(value)
	remaining := buffer.maximum - buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = buffer.Buffer.Write(value)
	}
	if accepted > remaining {
		buffer.overflow = true
	}
	return accepted, nil
}

func linuxDeviceKey(device uint64) string {
	major := ((device & 0x00000000000fff00) >> 8) | ((device & 0xfffff00000000000) >> 32)
	minor := (device & 0x00000000000000ff) | ((device & 0x00000ffffff00000) >> 12)
	return fmt.Sprintf("%d:%d", major, minor)
}
