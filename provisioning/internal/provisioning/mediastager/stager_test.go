//go:build linux

package mediastager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const fixtureTargetSize = uint64(16 * 1024 * 1024)

type usageInventory struct {
	base   Inventory
	values []TargetUsage
	calls  int
}

type lockCheckingInventory struct {
	base                    Inventory
	inspectCalls            int
	targetLockedOnReinspect bool
	lockCheckErr            error
}

func (inventory *usageInventory) Inspect(ctx context.Context, path string, mode Mode) (TargetFacts, error) {
	return inventory.base.Inspect(ctx, path, mode)
}

func (inventory *usageInventory) Usage(ctx context.Context, facts TargetFacts, mode Mode) (TargetUsage, error) {
	if inventory.calls >= len(inventory.values) {
		return inventory.values[len(inventory.values)-1], nil
	}
	value := inventory.values[inventory.calls]
	inventory.calls++
	return value, nil
}

func (inventory *lockCheckingInventory) Inspect(ctx context.Context, path string, mode Mode) (TargetFacts, error) {
	facts, err := inventory.base.Inspect(ctx, path, mode)
	if err != nil {
		return TargetFacts{}, err
	}
	inventory.inspectCalls++
	if inventory.inspectCalls != 2 {
		return facts, nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		inventory.lockCheckErr = err
		return facts, nil
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		inventory.targetLockedOnReinspect = true
		return facts, nil
	}
	if err != nil {
		inventory.lockCheckErr = err
		return facts, nil
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return facts, nil
}

func (inventory *lockCheckingInventory) Usage(ctx context.Context, facts TargetFacts, mode Mode) (TargetUsage, error) {
	return inventory.base.Usage(ctx, facts, mode)
}

func TestPlanValidateRequiresClosedLayoutAndTargetModes(t *testing.T) {
	plan := newFixture(t).plan
	if err := plan.Validate(ModeFixture); err != nil {
		t.Fatal(err)
	}

	devicePlan := plan
	devicePlan.Target.Path = "/dev/disk/by-id/nvme-example"
	devicePlan.Target.ExpectedIdentity = "nvme-example"
	if err := devicePlan.Validate(ModeDevice); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mode   Mode
		mutate func(*Plan)
	}{
		{"raw device path", ModeDevice, func(value *Plan) { value.Target.Path = "/dev/nvme0n1" }},
		{"partition alias", ModeDevice, func(value *Plan) { value.Target.Path = "/dev/disk/by-id/nvme-example-part1" }},
		{"fixture below dev", ModeFixture, func(value *Plan) { value.Target.Path = "/dev/test-fixture" }},
		{"wrong role order", ModeFixture, func(value *Plan) { value.Images[0].Role = RoleRootData }},
		{"overlapping extent", ModeFixture, func(value *Plan) { value.Images[1].OffsetBytes = value.Images[0].OffsetBytes }},
		{"unaligned extent", ModeFixture, func(value *Plan) { value.Images[0].OffsetBytes++ }},
		{"partition-table extent", ModeFixture, func(value *Plan) { value.Images[0].OffsetBytes = 0 }},
		{"extent beyond target", ModeFixture, func(value *Plan) { value.Images[2].OffsetBytes = value.Target.ExpectedSizeBytes }},
		{"target beyond signed offset range", ModeFixture, func(value *Plan) { value.Target.ExpectedSizeBytes = ^uint64(0) }},
		{"noncanonical digest", ModeFixture, func(value *Plan) { value.Images[0].Digest = strings.Repeat("a", 64) }},
		{"duplicate image path", ModeFixture, func(value *Plan) { value.Images[1].Path = value.Images[0].Path }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestPlan(plan)
			if test.mode == ModeDevice {
				candidate.Target.Path = "/dev/disk/by-id/nvme-example"
				candidate.Target.ExpectedIdentity = "nvme-example"
			}
			test.mutate(&candidate)
			if err := candidate.Validate(test.mode); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("error = %v, want invalid plan", err)
			}
		})
	}
}

func TestDeviceFactsRequirePerAttachmentIdentity(t *testing.T) {
	fixture := newFixture(t)
	plan := fixture.plan
	plan.Target.Path = "/dev/disk/by-id/nvme-example"
	plan.Target.ExpectedIdentity = "nvme-example"
	facts := TargetFacts{
		RequestedPath: plan.Target.Path, ResolvedPath: "/dev/nvme0n1",
		Identity: plan.Target.ExpectedIdentity, SizeBytes: plan.Target.ExpectedSizeBytes,
		Kind: TargetBlockDevice, WholeDevice: true, DeviceNumber: 0x103,
		SysfsPath: "/sys/devices/pci0000:00/nvme/nvme0/nvme0n1",
	}

	if err := validateTargetFacts(plan, ModeDevice, facts, TargetUsage{}); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("device facts without a kernel attachment identity error = %v", err)
	}
	facts.DiskSequence = 17
	if err := validateTargetFacts(plan, ModeDevice, facts, TargetUsage{}); err != nil {
		t.Fatalf("complete device facts error = %v", err)
	}
}

func TestDeviceInstanceRejectsReenumeration(t *testing.T) {
	facts := TargetFacts{DeviceNumber: 0x103, SizeBytes: fixtureTargetSize, DiskSequence: 17}
	if err := validateDeviceInstance(facts, facts.DeviceNumber, facts.SizeBytes, facts.DiskSequence); err != nil {
		t.Fatalf("unchanged device instance error = %v", err)
	}
	for name, values := range map[string][3]uint64{
		"device number": {0x104, facts.SizeBytes, facts.DiskSequence},
		"size":          {facts.DeviceNumber, facts.SizeBytes + 4096, facts.DiskSequence},
		"disk sequence": {facts.DeviceNumber, facts.SizeBytes, facts.DiskSequence + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDeviceInstance(facts, values[0], values[1], values[2]); !errors.Is(err, ErrTargetMismatch) {
				t.Fatalf("changed device instance error = %v", err)
			}
		})
	}
}

func TestTargetFactsSnapshotRejectsAttachmentReplacement(t *testing.T) {
	initial := TargetFacts{
		RequestedPath: "/dev/disk/by-id/nvme-example",
		ResolvedPath:  "/dev/nvme0n1",
		Identity:      "nvme-example",
		SizeBytes:     fixtureTargetSize,
		Kind:          TargetBlockDevice,
		WholeDevice:   true,
		DeviceNumber:  0x103,
		DiskSequence:  17,
		SysfsPath:     "/sys/devices/pci0000:00/nvme/nvme0/nvme0n1",
	}
	if err := validateSameTargetFacts(initial, initial); err != nil {
		t.Fatalf("unchanged target snapshot error = %v", err)
	}
	for name, mutate := range map[string]func(*TargetFacts){
		"resolved path":  func(value *TargetFacts) { value.ResolvedPath = "/dev/nvme1n1" },
		"device number":  func(value *TargetFacts) { value.DeviceNumber++ },
		"disk sequence":  func(value *TargetFacts) { value.DiskSequence++ },
		"capacity":       func(value *TargetFacts) { value.SizeBytes += 4096 },
		"sysfs identity": func(value *TargetFacts) { value.SysfsPath += "-replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			current := initial
			mutate(&current)
			if err := validateSameTargetFacts(initial, current); !errors.Is(err, ErrTargetMismatch) {
				t.Fatalf("changed target snapshot error = %v", err)
			}
		})
	}
}

func TestDecodePlanRejectsUnknownDuplicateAndTrailingJSON(t *testing.T) {
	plan := newFixture(t).plan
	valid, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlan(valid, ModeFixture); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"unknown":        bytes.Replace(valid, []byte(`"images":`), []byte(`"unexpected":true,"images":`), 1),
		"wrong key case": bytes.Replace(valid, []byte(`"schema_version":`), []byte(`"SCHEMA_VERSION":`), 1),
		"duplicate":      bytes.Replace(valid, []byte(`"schema_version":`), []byte(`"schema_version":"duplicate","schema_version":`), 1),
		"trailing":       append(append([]byte(nil), valid...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePlan(data, ModeFixture); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("error = %v, want invalid plan", err)
			}
		})
	}
}

func TestDryRunFixtureValidatesWithoutWriting(t *testing.T) {
	fixture := newFixture(t)
	before := readWholeFile(t, fixture.targetPath)
	result, err := (Executor{}).DryRun(context.Background(), fixture.plan, ModeFixture)
	if err != nil {
		t.Fatal(err)
	}
	after := readWholeFile(t, fixture.targetPath)
	if !bytes.Equal(after, before) {
		t.Fatal("dry-run changed target bytes")
	}
	if result.Action != ActionDryRun || result.Status != "validated_no_write" || len(result.Images) != 3 {
		t.Fatalf("dry-run result = %#v", result)
	}
	if result.PlanDigest == "" || result.ReceiptDigest == "" || result.ReopenedTarget || result.ColdPowerCycleObserved || result.OneTimeSettingsChanged {
		t.Fatalf("dry-run safety receipt = %#v", result)
	}
	if err := VerifyResult(fixture.plan, ModeFixture, result); err != nil {
		t.Fatalf("verify dry-run receipt: %v", err)
	}
	tampered := result
	tampered.Status = "reopened_readback_verified"
	if err := VerifyResult(fixture.plan, ModeFixture, tampered); err == nil {
		t.Fatal("tampered dry-run receipt was accepted")
	}
}

func TestStageThenReopenedReadbackFixture(t *testing.T) {
	fixture := newFixture(t)
	sentinelOffset := int64(12 * 1024 * 1024)
	sentinel := []byte("outside-approved-extents")
	target, err := os.OpenFile(fixture.targetPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteAt(sentinel, sentinelOffset); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}

	executor := Executor{BufferSize: 4096}
	staged, err := executor.Stage(context.Background(), fixture.plan, ModeFixture)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Status != "fsync_complete_readback_required" {
		t.Fatalf("stage result = %#v", staged)
	}
	for _, image := range fixture.plan.Images {
		actual := readExtent(t, fixture.targetPath, image.OffsetBytes, image.SizeBytes)
		want := readWholeFile(t, image.Path)
		if !bytes.Equal(actual, want) {
			t.Fatalf("staged %q bytes differ", image.Role)
		}
	}
	if actual := readExtent(t, fixture.targetPath, uint64(sentinelOffset), uint64(len(sentinel))); !bytes.Equal(actual, sentinel) {
		t.Fatal("stage changed bytes outside approved extents")
	}
	verified, err := executor.Readback(context.Background(), fixture.plan, ModeFixture)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Action != ActionReadback || verified.Status != "reopened_readback_verified" {
		t.Fatalf("readback result = %#v", verified)
	}
	if !verified.ReopenedTarget || verified.ColdPowerCycleObserved || verified.OneTimeSettingsChanged {
		t.Fatalf("readback safety receipt = %#v", verified)
	}
	if err := VerifyResult(fixture.plan, ModeFixture, verified); err != nil {
		t.Fatalf("verify readback receipt: %v", err)
	}
}

func TestCopyExactBindsTheBytesActuallyWritten(t *testing.T) {
	contents := []byte("source-bytes-after-preflight")
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	targetPath := filepath.Join(directory, "target.img")
	if err := os.WriteFile(sourcePath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, make([]byte, len(contents)+4096), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	digest, err := copyExact(context.Background(), target, source, 4096, uint64(len(contents)), make([]byte, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if want := digestBytes(contents); digest != want {
		t.Fatalf("copied digest = %s, want %s", digest, want)
	}
	if actual := readExtent(t, targetPath, 4096, uint64(len(contents))); !bytes.Equal(actual, contents) {
		t.Fatal("target bytes differ from the digest-bound source bytes")
	}
}

func TestStagePreflightsEverySourceBeforeWriting(t *testing.T) {
	fixture := newFixture(t)
	fixture.plan.Images[2].Digest = digestBytes([]byte("not-the-last-image"))
	before := readWholeFile(t, fixture.targetPath)
	if _, err := (Executor{}).Stage(context.Background(), fixture.plan, ModeFixture); !errors.Is(err, ErrImageMismatch) {
		t.Fatalf("error = %v, want image mismatch", err)
	}
	if after := readWholeFile(t, fixture.targetPath); !bytes.Equal(after, before) {
		t.Fatal("failed source preflight changed target bytes")
	}
}

func TestStagePinsTargetBeforeReinspection(t *testing.T) {
	fixture := newFixture(t)
	inventory := &lockCheckingInventory{base: SystemInventory{}}
	if _, err := (Executor{Inventory: inventory}).Stage(context.Background(), fixture.plan, ModeFixture); err != nil {
		t.Fatal(err)
	}
	if inventory.inspectCalls != 2 {
		t.Fatalf("target inspections = %d, want 2", inventory.inspectCalls)
	}
	if inventory.lockCheckErr != nil {
		t.Fatalf("check target lock during reinspection: %v", inventory.lockCheckErr)
	}
	if !inventory.targetLockedOnReinspect {
		t.Fatal("target was not exclusively locked during final reinspection")
	}
}

func TestStageRejectsUnsafeInventoryBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name  string
		usage TargetUsage
	}{
		{"mounted", TargetUsage{Mounted: true, MountPoints: []string{"/mnt/target"}}},
		{"system", TargetUsage{System: true}},
		{"root", TargetUsage{Root: true, Mounted: true, MountPoints: []string{"/"}}},
		{"swap", TargetUsage{Swap: true, SwapSources: []string{"/dev/example"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			before := readWholeFile(t, fixture.targetPath)
			inventory := &usageInventory{base: SystemInventory{}, values: []TargetUsage{test.usage}}
			if _, err := (Executor{Inventory: inventory}).Stage(context.Background(), fixture.plan, ModeFixture); !errors.Is(err, ErrUnsafeTarget) {
				t.Fatalf("error = %v, want unsafe target", err)
			}
			if after := readWholeFile(t, fixture.targetPath); !bytes.Equal(after, before) {
				t.Fatal("unsafe inventory changed target bytes")
			}
		})
	}
}

func TestStageRechecksUsageAfterLockBeforeWriting(t *testing.T) {
	fixture := newFixture(t)
	before := readWholeFile(t, fixture.targetPath)
	inventory := &usageInventory{
		base: SystemInventory{},
		values: []TargetUsage{
			{},
			{Mounted: true, MountPoints: []string{"/late-mount"}},
		},
	}
	if _, err := (Executor{Inventory: inventory}).Stage(context.Background(), fixture.plan, ModeFixture); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("error = %v, want unsafe target", err)
	}
	if inventory.calls != 2 {
		t.Fatalf("usage inventory calls = %d, want 2", inventory.calls)
	}
	if after := readWholeFile(t, fixture.targetPath); !bytes.Equal(after, before) {
		t.Fatal("late unsafe inventory changed target bytes")
	}
}

func TestStageRejectsExclusiveLockBeforeWriting(t *testing.T) {
	fixture := newFixture(t)
	before := readWholeFile(t, fixture.targetPath)
	locked, err := os.OpenFile(fixture.targetPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(locked.Fd()), syscall.LOCK_UN)
	if _, err := (Executor{}).Stage(context.Background(), fixture.plan, ModeFixture); !errors.Is(err, ErrTargetBusy) {
		t.Fatalf("error = %v, want target busy", err)
	}
	if after := readWholeFile(t, fixture.targetPath); !bytes.Equal(after, before) {
		t.Fatal("locked target changed")
	}
}

func TestNoFollowRejectsFixtureAndSourceSymlinks(t *testing.T) {
	t.Run("target", func(t *testing.T) {
		fixture := newFixture(t)
		alias := filepath.Join(t.TempDir(), "target-alias")
		if err := os.Symlink(fixture.targetPath, alias); err != nil {
			t.Fatal(err)
		}
		fixture.plan.Target.Path = alias
		fixture.plan.Target.ExpectedIdentity = filepath.Base(alias)
		if _, err := (Executor{}).DryRun(context.Background(), fixture.plan, ModeFixture); err == nil {
			t.Fatal("fixture target symlink was accepted")
		}
	})

	t.Run("source", func(t *testing.T) {
		fixture := newFixture(t)
		alias := filepath.Join(t.TempDir(), "source-alias")
		if err := os.Symlink(fixture.plan.Images[0].Path, alias); err != nil {
			t.Fatal(err)
		}
		fixture.plan.Images[0].Path = alias
		if _, err := (Executor{}).DryRun(context.Background(), fixture.plan, ModeFixture); err == nil {
			t.Fatal("source symlink was accepted")
		}
	})
}

func TestReadbackDetectsChangedTargetExtent(t *testing.T) {
	fixture := newFixture(t)
	executor := Executor{}
	if _, err := executor.Stage(context.Background(), fixture.plan, ModeFixture); err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(fixture.targetPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteAt([]byte{0xff}, int64(fixture.plan.Images[1].OffsetBytes+17)); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Readback(context.Background(), fixture.plan, ModeFixture); !errors.Is(err, ErrReadbackMismatch) {
		t.Fatalf("error = %v, want readback mismatch", err)
	}
}

type fixture struct {
	plan       Plan
	targetPath string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "target.img")
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Truncate(int64(fixtureTargetSize)); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{
		bytes.Repeat([]byte("boot-image\n"), 701),
		bytes.Repeat([]byte("root-data-image\n"), 911),
		bytes.Repeat([]byte("root-hash-image\n"), 257),
	}
	roles := []ImageRole{RoleBootFilesystem, RoleRootData, RoleRootHash}
	offsets := []uint64{1 * 1024 * 1024, 3 * 1024 * 1024, 5 * 1024 * 1024}
	images := make([]ImageSpec, len(roles))
	for index, role := range roles {
		path := filepath.Join(directory, string(role)+".img")
		if err := os.WriteFile(path, contents[index], 0600); err != nil {
			t.Fatal(err)
		}
		images[index] = ImageSpec{
			Role: role, Path: path, Digest: digestBytes(contents[index]),
			SizeBytes: uint64(len(contents[index])), OffsetBytes: offsets[index],
		}
	}
	return fixture{
		targetPath: targetPath,
		plan: Plan{
			SchemaVersion: PlanSchemaVersion,
			Target: TargetSpec{
				Path: targetPath, ExpectedIdentity: filepath.Base(targetPath), ExpectedSizeBytes: fixtureTargetSize,
			},
			Images: images,
		},
	}
}

func cloneTestPlan(plan Plan) Plan {
	copy := plan
	copy.Images = append([]ImageSpec(nil), plan.Images...)
	return copy
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return sumString(digest)
}

func readWholeFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readExtent(t *testing.T, path string, offset, size uint64) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data := make([]byte, int(size))
	if _, err := file.ReadAt(data, int64(offset)); err != nil {
		t.Fatal(err)
	}
	return data
}
