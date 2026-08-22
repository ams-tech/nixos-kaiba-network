//go:build linux

package mediadevice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

func TestHashRangeIsExactAndContextAware(t *testing.T) {
	reader := bytes.NewReader([]byte("prefix-payload-suffix"))
	digest, err := HashRange(context.Background(), reader, 7, 7)
	if err != nil {
		t.Fatal(err)
	}
	if digest != mediacontract.Digest("sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5") {
		t.Fatalf("digest = %s", digest)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashRange(ctx, reader, 0, 1); err == nil {
		t.Fatal("HashRange accepted a canceled context")
	}
	if _, err := HashRange(context.Background(), reader, 0, 100); err == nil {
		t.Fatal("HashRange accepted a short reader")
	}
}

func TestSysfsReadersAreBoundedCanonicalAndNoFollow(t *testing.T) {
	directory := t.TempDir()
	valuePath := filepath.Join(directory, "value")
	if err := os.WriteFile(valuePath, []byte("Model Name 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readSysfsValue(valuePath)
	if err != nil || value != "Model Name 1" {
		t.Fatalf("readSysfsValue() = %q, %v", value, err)
	}
	numberPath := filepath.Join(directory, "number")
	if err := os.WriteFile(numberPath, []byte("512\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	number, err := readSysfsUint(numberPath)
	if err != nil || number != 512 {
		t.Fatalf("readSysfsUint() = %d, %v", number, err)
	}
	if err := os.WriteFile(numberPath, []byte("0512\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSysfsUint(numberPath); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical integer error = %v", err)
	}
	linkPath := filepath.Join(directory, "link")
	if err := os.Symlink(valuePath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readSysfsValue(linkPath); err == nil {
		t.Fatal("readSysfsValue followed a symlink")
	}
}

func TestSameAttachmentComparesEveryInventoryFact(t *testing.T) {
	initial := mediainventory.TargetFacts{
		RequestedPath: "/dev/disk/by-id/example", ResolvedPath: "/dev/sda", Identity: "example",
		SizeBytes: 1024, Kind: mediainventory.TargetBlockDevice, WholeDevice: true,
		DeviceNumber: 17, DiskSequence: 23, BootID: "11111111-1111-4111-8111-111111111111", SysfsPath: "/sys/devices/example",
	}
	if err := SameAttachment(initial, initial); err != nil {
		t.Fatal(err)
	}
	current := initial
	current.DiskSequence++
	if err := SameAttachment(initial, current); err == nil {
		t.Fatal("SameAttachment accepted a new disk sequence")
	}
	current = initial
	current.SysfsPath += "-replacement"
	if err := SameAttachment(initial, current); err == nil {
		t.Fatal("SameAttachment accepted a new sysfs identity")
	}
}

func TestInactiveBlockGraphRejectsWholeAndPartitionHolders(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "holders"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "slaves"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dev"), []byte("259:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	partition := filepath.Join(root, "device1")
	if err := os.Mkdir(partition, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partition, "partition"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(partition, "holders"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateInactiveBlockGraph(root); err != nil {
		t.Fatal(err)
	}
	holder := filepath.Join(partition, "holders", "dm-0")
	if err := os.Symlink("../../dm-0", holder); err != nil {
		t.Fatal(err)
	}
	if err := validateInactiveBlockGraph(root); err == nil || !strings.Contains(err.Error(), "active sysfs holders") {
		t.Fatalf("partition holder error = %v", err)
	}
	if err := os.Remove(holder); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../dm-0", filepath.Join(root, "holders", "dm-0")); err != nil {
		t.Fatal(err)
	}
	if err := validateInactiveBlockGraph(root); err == nil || !strings.Contains(err.Error(), "active sysfs holders") {
		t.Fatalf("whole-device holder error = %v", err)
	}
}
