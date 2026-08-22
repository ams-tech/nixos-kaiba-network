//go:build linux

package mediadevice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

const (
	testDataGUID = "33333333-3333-4333-8333-333333333333"
	testHashGUID = "44444444-4444-4444-8444-444444444444"
)

type partitionVerityFixture struct {
	verifier PartitionVerityVerifier
	target   io.ReaderAt
	data     mediacontract.GPTPartition
	hash     mediacontract.GPTPartition
	contract mediacontract.VerityContract

	dataPath  string
	hashPath  string
	dataAlias string
	hashAlias string
	dataSysfs string
	hashSysfs string

	wholeDevice       uint64
	dataDevice        uint64
	hashDevice        uint64
	fdIdentity        map[string]partitionFDIdentity
	pathDevice        map[string]uint64
	captured          []partitionVerityCommand
	capturedByte      [2]byte
	wholeChecks       int
	failWholeAfterRun bool
}

func TestPartitionVerityVerifierUsesExactPinnedDescriptors(t *testing.T) {
	fixture := newPartitionVerityFixture(t)
	if err := fixture.verifier.Verify(context.Background(), fixture.target, fixture.data, fixture.hash, fixture.contract); err != nil {
		t.Fatal(err)
	}
	if fixture.wholeChecks != 2 {
		t.Fatalf("whole target validation count = %d, want 2", fixture.wholeChecks)
	}
	if len(fixture.captured) != 1 {
		t.Fatalf("command count = %d, want 1", len(fixture.captured))
	}
	command := fixture.captured[0]
	wantArguments := []string{
		"verify",
		"--hash=sha256",
		"--data-block-size=4096",
		"--hash-block-size=4096",
		"--data-blocks=2",
		"/proc/self/fd/3",
		"/proc/self/fd/4",
		strings.Repeat("a", 64),
	}
	if command.Path != fixture.verifier.Path || !reflect.DeepEqual(command.Arguments, wantArguments) {
		t.Fatalf("command = %q %q", command.Path, command.Arguments)
	}
	if !reflect.DeepEqual(command.Environment, []string{"LC_ALL=C", "TZ=UTC", "PATH=/nonexistent"}) || command.Directory != "/" {
		t.Fatalf("environment=%q directory=%q", command.Environment, command.Directory)
	}
	if len(command.ExtraFiles) != 2 || command.ExtraFiles[0].Name() != fixture.dataPath || command.ExtraFiles[1].Name() != fixture.hashPath {
		t.Fatalf("extra files = %#v", command.ExtraFiles)
	}
	if fixture.capturedByte != [2]byte{'d', 'h'} {
		t.Fatalf("child descriptor bytes = %q", fixture.capturedByte)
	}
}

func TestPartitionVerityVerifierRejectsBadContractGeometryAndIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*partitionVerityFixture)
		want   string
	}{
		{
			name: "partial data block",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.data.UsedSizeBytes++
			},
			want: "exact whole block counts",
		},
		{
			name: "partial hash block",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.hash.UsedSizeBytes++
			},
			want: "exact whole block counts",
		},
		{
			name: "wrong PARTUUID binding",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.contract.DataPartitionGUID = testHashGUID
			},
			want: "PARTUUIDs differ",
		},
		{
			name: "whole device masquerades as partition",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.setResolvedIdentity(fixture.dataPath, partitionFDIdentity{DeviceNumber: fixture.wholeDevice, SizeBytes: fixture.data.SizeBytes, BlockDevice: true})
			},
			want: "whole target rather than a partition",
		},
		{
			name: "opened descriptor device differs",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.fdIdentity[fixture.dataPath] = partitionFDIdentity{DeviceNumber: fixture.hashDevice, SizeBytes: fixture.data.SizeBytes, BlockDevice: true}
			},
			want: "descriptor identity or exact size differs",
		},
		{
			name: "opened descriptor size differs",
			mutate: func(fixture *partitionVerityFixture) {
				fixture.fdIdentity[fixture.dataPath] = partitionFDIdentity{DeviceNumber: fixture.dataDevice, SizeBytes: fixture.data.SizeBytes - 512, BlockDevice: true}
			},
			want: "descriptor identity or exact size differs",
		},
		{
			name: "partition number differs",
			mutate: func(fixture *partitionVerityFixture) {
				writeTestAttribute(t, filepath.Join(fixture.dataSysfs, "partition"), "7")
			},
			want: "number differs",
		},
		{
			name: "partition start differs",
			mutate: func(fixture *partitionVerityFixture) {
				writeTestAttribute(t, filepath.Join(fixture.dataSysfs, "start"), "4097")
			},
			want: "geometry differs",
		},
		{
			name: "partition sysfs size differs",
			mutate: func(fixture *partitionVerityFixture) {
				writeTestAttribute(t, filepath.Join(fixture.hashSysfs, "size"), "2047")
			},
			want: "geometry differs",
		},
		{
			name: "partition belongs to another whole device",
			mutate: func(fixture *partitionVerityFixture) {
				other := filepath.Join(filepath.Dir(fixture.verifier.Whole.SysfsPath), "other", filepath.Base(fixture.dataSysfs))
				if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(fixture.dataSysfs, other); err != nil {
					t.Fatal(err)
				}
				replaceTestSymlink(t, filepath.Join(fixture.verifier.SysDevPath, linuxDeviceKey(fixture.dataDevice)), other)
			},
			want: "not a direct child",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPartitionVerityFixture(t)
			test.mutate(fixture)
			err := fixture.verifier.Verify(context.Background(), fixture.target, fixture.data, fixture.hash, fixture.contract)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want %q", err, test.want)
			}
			if len(fixture.captured) != 0 {
				t.Fatal("veritysetup ran after a preflight identity or geometry failure")
			}
		})
	}
}

func TestPartitionVerityVerifierPropagatesVerityTamperFailure(t *testing.T) {
	fixture := newPartitionVerityFixture(t)
	fixture.verifier.hooks.run = func(context.Context, partitionVerityCommand) error {
		return errors.New("root hash verification failed")
	}
	err := fixture.verifier.Verify(context.Background(), fixture.target, fixture.data, fixture.hash, fixture.contract)
	if err == nil || !strings.Contains(err.Error(), "rejected the pinned partition pair") || !strings.Contains(err.Error(), "root hash verification failed") {
		t.Fatalf("Verify() error = %v", err)
	}
	if fixture.wholeChecks != 2 {
		t.Fatalf("whole target validation count after failed command = %d, want 2", fixture.wholeChecks)
	}
}

func TestPartitionVerityVerifierRejectsPostRunChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *partitionVerityFixture)
		want   string
	}{
		{
			name: "PARTUUID alias",
			mutate: func(t *testing.T, fixture *partitionVerityFixture) {
				replaceTestSymlink(t, fixture.dataAlias, fixture.hashPath)
			},
			want: "revalidate root-data partition",
		},
		{
			name: "sysfs geometry",
			mutate: func(t *testing.T, fixture *partitionVerityFixture) {
				writeTestAttribute(t, filepath.Join(fixture.hashSysfs, "start"), "6145")
			},
			want: "revalidate root-hash partition",
		},
		{
			name: "pinned descriptor identity",
			mutate: func(_ *testing.T, fixture *partitionVerityFixture) {
				fixture.fdIdentity[fixture.dataPath] = partitionFDIdentity{DeviceNumber: fixture.hashDevice, SizeBytes: fixture.data.SizeBytes, BlockDevice: true}
			},
			want: "pinned partition descriptor identity",
		},
		{
			name: "whole target attachment",
			mutate: func(_ *testing.T, fixture *partitionVerityFixture) {
				fixture.failWholeAfterRun = true
			},
			want: "revalidate pinned whole target",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPartitionVerityFixture(t)
			originalRun := fixture.verifier.hooks.run
			fixture.verifier.hooks.run = func(ctx context.Context, command partitionVerityCommand) error {
				if err := originalRun(ctx, command); err != nil {
					return err
				}
				test.mutate(t, fixture)
				return nil
			}
			err := fixture.verifier.Verify(context.Background(), fixture.target, fixture.data, fixture.hash, fixture.contract)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunPartitionVerityMapsExtraFilesToChildFDThreeAndFour(t *testing.T) {
	if os.Getenv("KAIBA_PARTITION_VERITY_HELPER") == "1" {
		data, dataErr := os.ReadFile("/proc/self/fd/3")
		hash, hashErr := os.ReadFile("/proc/self/fd/4")
		if dataErr != nil || hashErr != nil || string(data) != "root-data" || string(hash) != "root-hash" || os.Getenv("LC_ALL") != "C" {
			os.Exit(23)
		}
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data := writeTestFile(t, filepath.Join(t.TempDir(), "data"), []byte("root-data"), 0o600)
	hash := writeTestFile(t, filepath.Join(t.TempDir(), "hash"), []byte("root-hash"), 0o600)
	dataFile, err := os.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer dataFile.Close()
	hashFile, err := os.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer hashFile.Close()
	err = runPartitionVerity(context.Background(), partitionVerityCommand{
		Path:        executable,
		Arguments:   []string{"-test.run=TestRunPartitionVerityMapsExtraFilesToChildFDThreeAndFour"},
		Environment: []string{"KAIBA_PARTITION_VERITY_HELPER=1", "LC_ALL=C"},
		Directory:   "/",
		ExtraFiles:  []*os.File{dataFile, hashFile},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPartitionVerityDiagnosticIsBounded(t *testing.T) {
	buffer := &partitionVerityDiagnostic{maximum: 4}
	if n, err := buffer.Write([]byte("123456")); err != nil || n != 6 || buffer.String() != "1234" || !buffer.overflow {
		t.Fatalf("Write() = %d, %v; buffer=%q overflow=%t", n, err, buffer.String(), buffer.overflow)
	}
}

func newPartitionVerityFixture(t *testing.T) *partitionVerityFixture {
	t.Helper()
	root := t.TempDir()
	deviceRoot := filepath.Join(root, "dev")
	byRoot := filepath.Join(deviceRoot, "disk", "by-partuuid")
	sysNamespace := filepath.Join(root, "sys")
	sysDev := filepath.Join(sysNamespace, "dev", "block")
	wholeSysfs := filepath.Join(sysNamespace, "devices", "nvme0n1")
	dataSysfs := filepath.Join(wholeSysfs, "nvme0n1p2")
	hashSysfs := filepath.Join(wholeSysfs, "nvme0n1p3")
	for _, path := range []string{byRoot, sysDev, dataSysfs, hashSysfs} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dataPath := writeSizedTestFile(t, filepath.Join(deviceRoot, "nvme0n1p2"), 'd', mediacontract.AlignmentBytes)
	hashPath := writeSizedTestFile(t, filepath.Join(deviceRoot, "nvme0n1p3"), 'h', mediacontract.AlignmentBytes)
	dataAlias := filepath.Join(byRoot, testDataGUID)
	hashAlias := filepath.Join(byRoot, testHashGUID)
	if err := os.Symlink(dataPath, dataAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hashPath, hashAlias); err != nil {
		t.Fatal(err)
	}

	wholeDevice := testLinuxDevice(259, 0)
	dataDevice := testLinuxDevice(259, 2)
	hashDevice := testLinuxDevice(259, 3)
	for device, target := range map[uint64]string{
		wholeDevice: wholeSysfs,
		dataDevice:  dataSysfs,
		hashDevice:  hashSysfs,
	} {
		if err := os.Symlink(target, filepath.Join(sysDev, linuxDeviceKey(device))); err != nil {
			t.Fatal(err)
		}
	}
	writeTestAttribute(t, filepath.Join(dataSysfs, "dev"), linuxDeviceKey(dataDevice))
	writeTestAttribute(t, filepath.Join(dataSysfs, "partition"), "2")
	writeTestAttribute(t, filepath.Join(dataSysfs, "start"), "4096")
	writeTestAttribute(t, filepath.Join(dataSysfs, "size"), "2048")
	writeTestAttribute(t, filepath.Join(hashSysfs, "dev"), linuxDeviceKey(hashDevice))
	writeTestAttribute(t, filepath.Join(hashSysfs, "partition"), "3")
	writeTestAttribute(t, filepath.Join(hashSysfs, "start"), "6144")
	writeTestAttribute(t, filepath.Join(hashSysfs, "size"), "2048")

	fixture := &partitionVerityFixture{
		target:      bytes.NewReader([]byte("pinned whole target")),
		dataPath:    dataPath,
		hashPath:    hashPath,
		dataAlias:   dataAlias,
		hashAlias:   hashAlias,
		dataSysfs:   dataSysfs,
		hashSysfs:   hashSysfs,
		wholeDevice: wholeDevice,
		dataDevice:  dataDevice,
		hashDevice:  hashDevice,
		fdIdentity: map[string]partitionFDIdentity{
			dataPath: {DeviceNumber: dataDevice, SizeBytes: mediacontract.AlignmentBytes, BlockDevice: true},
			hashPath: {DeviceNumber: hashDevice, SizeBytes: mediacontract.AlignmentBytes, BlockDevice: true},
		},
		pathDevice: map[string]uint64{
			dataPath: dataDevice,
			hashPath: hashDevice,
		},
		data: mediacontract.GPTPartition{
			Number: 2, Role: mediacontract.PartitionRootData, UniqueGUID: testDataGUID,
			OffsetBytes: 2 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, UsedSizeBytes: 8192,
		},
		hash: mediacontract.GPTPartition{
			Number: 3, Role: mediacontract.PartitionRootHash, UniqueGUID: testHashGUID,
			OffsetBytes: 3 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, UsedSizeBytes: 4096,
		},
		contract: mediacontract.VerityContract{
			Algorithm: "sha256", RootHash: mediacontract.Digest("sha256:" + strings.Repeat("a", 64)),
			DataBlockSizeBytes: 4096, HashBlockSizeBytes: 4096,
			DataPartitionGUID: testDataGUID, HashPartitionGUID: testHashGUID, Mapper: "/dev/mapper/root",
		},
	}
	fixture.verifier = PartitionVerityVerifier{
		Path: "/nix/store/00000000000000000000000000000000-cryptsetup/bin/veritysetup",
		Whole: mediainventory.TargetFacts{
			RequestedPath: "/dev/disk/by-id/nvme-kaiba-test", ResolvedPath: "/dev/nvme0n1", Identity: "nvme-kaiba-test",
			SizeBytes: 8 * mediacontract.AlignmentBytes, Kind: mediainventory.TargetBlockDevice, WholeDevice: true,
			DeviceNumber: wholeDevice, DiskSequence: 17, BootID: "11111111-1111-4111-8111-111111111111", SysfsPath: wholeSysfs,
		},
		ByPARTUUIDRoot: byRoot,
		SysDevPath:     sysDev,
	}
	fixture.verifier.hooks = &partitionVerityHooks{
		lstat: func(path string) (os.FileInfo, error) {
			switch path {
			case fixture.verifier.Path:
				return fakeVerityFileInfo{name: "veritysetup", mode: 0o555}, nil
			case fixture.dataPath:
				return fakeVerityFileInfo{name: filepath.Base(path), mode: os.ModeDevice | 0o600, stat: &syscall.Stat_t{Rdev: fixture.pathDevice[path]}}, nil
			case fixture.hashPath:
				return fakeVerityFileInfo{name: filepath.Base(path), mode: os.ModeDevice | 0o600, stat: &syscall.Stat_t{Rdev: fixture.pathDevice[path]}}, nil
			default:
				return os.Lstat(path)
			}
		},
		openReadOnly: os.Open,
		inspectFD: func(file *os.File) (partitionFDIdentity, error) {
			identity, ok := fixture.fdIdentity[file.Name()]
			if !ok {
				return partitionFDIdentity{}, fmt.Errorf("unknown descriptor %q", file.Name())
			}
			return identity, nil
		},
		validateWhole: func(target io.ReaderAt, facts mediainventory.TargetFacts) error {
			fixture.wholeChecks++
			if target != fixture.target || facts != fixture.verifier.Whole {
				return errors.New("wrong whole target")
			}
			if fixture.failWholeAfterRun && fixture.wholeChecks > 1 {
				return errors.New("attachment changed")
			}
			return nil
		},
		run: func(_ context.Context, command partitionVerityCommand) error {
			for index := range command.ExtraFiles {
				buffer := []byte{0}
				if _, err := command.ExtraFiles[index].ReadAt(buffer, 0); err != nil {
					return err
				}
				fixture.capturedByte[index] = buffer[0]
			}
			fixture.captured = append(fixture.captured, command)
			return nil
		},
	}
	return fixture
}

func (fixture *partitionVerityFixture) setResolvedIdentity(path string, identity partitionFDIdentity) {
	fixture.pathDevice[path] = identity.DeviceNumber
}

type fakeVerityFileInfo struct {
	name string
	mode os.FileMode
	stat *syscall.Stat_t
}

func (info fakeVerityFileInfo) Name() string       { return info.name }
func (info fakeVerityFileInfo) Size() int64        { return 0 }
func (info fakeVerityFileInfo) Mode() os.FileMode  { return info.mode }
func (info fakeVerityFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeVerityFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeVerityFileInfo) Sys() any           { return info.stat }

func testLinuxDevice(major, minor uint64) uint64 {
	return ((major & 0xfff) << 8) |
		((major & ^uint64(0xfff)) << 32) |
		(minor & 0xff) |
		((minor & ^uint64(0xff)) << 12)
}

func writeSizedTestFile(t *testing.T, path string, first byte, size uint64) string {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{first}); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestFile(t *testing.T, path string, value []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestAttribute(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceTestSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}
