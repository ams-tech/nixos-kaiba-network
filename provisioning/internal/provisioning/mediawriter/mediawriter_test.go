package mediawriter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

type mediaFixture struct {
	plan     mediacontract.Plan
	paths    AssetPaths
	expected []byte
	primary  []byte
	boot     []byte
	root     []byte
	hash     []byte
	backup   []byte
}

func TestStageWritesCompleteTargetWithDurableGPTCommitLast(t *testing.T) {
	fixture := newMediaFixture(t)
	sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sources.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	target := &recordingWriterAt{data: bytes.Repeat([]byte{0xa5}, len(fixture.expected))}
	written, err := Stage(context.Background(), target, fixture.plan, sources)
	if err != nil {
		t.Fatal(err)
	}
	wantWritten := fixture.plan.Target.SizeBytes
	for _, binding := range fixture.plan.Layout.Sources {
		wantWritten += binding.SizeBytes
	}
	if written != wantWritten {
		t.Fatalf("Stage() wrote %d bytes, want %d", written, wantWritten)
	}
	if !bytes.Equal(target.data, fixture.expected) {
		t.Fatal("Stage() did not produce the exact canonical complete-media bytes")
	}
	if got := testDigest(target.data); got != fixture.plan.ExpectedMediaDigest {
		t.Fatalf("staged digest = %s, want %s", got, fixture.plan.ExpectedMediaDigest)
	}

	mib := int64(mediacontract.AlignmentBytes)
	wantEvents := []targetEvent{
		{kind: "write", offset: 0, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 7 * mib, length: transferBufferBytes, allZero: true},
		{kind: "sync"},
		{kind: "write", offset: 1 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 2 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 3 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 4 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 5 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 6 * mib, length: transferBufferBytes, allZero: true},
		{kind: "write", offset: 1 * mib, length: len(fixture.boot), first: 0x22},
		{kind: "write", offset: 2 * mib, length: len(fixture.root), first: 0x33},
		{kind: "write", offset: 3 * mib, length: len(fixture.hash), first: 0x44},
		{kind: "sync"},
		{kind: "write", offset: 7 * mib, length: len(fixture.backup), first: 0x55},
		{kind: "sync"},
		{kind: "write", offset: 0, length: len(fixture.primary), first: 0x11},
		{kind: "sync"},
	}
	if len(target.events) != len(wantEvents) {
		t.Fatalf("target event count = %d, want %d: %#v", len(target.events), len(wantEvents), target.events)
	}
	for index, want := range wantEvents {
		got := target.events[index]
		if got != want {
			t.Fatalf("target event %d = %#v, want %#v", index, got, want)
		}
	}
}

func TestStageFailsClosedAtEveryDurabilityBarrier(t *testing.T) {
	for _, test := range []struct {
		name       string
		failSyncAt int
		wantWrites int
		wantError  string
		primary    byte
		backup     byte
	}{
		{"invalidate GPT", 1, 2, "sync invalidated GPT regions", 0x00, 0x00},
		{"payloads", 2, 11, "sync staged payloads", 0x00, 0x00},
		{"backup GPT", 3, 12, "sync backup GPT", 0x00, 0x55},
		{"primary GPT", 4, 13, "sync primary GPT commit", 0x11, 0x55},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMediaFixture(t)
			sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
			if err != nil {
				t.Fatal(err)
			}
			defer sources.Close()
			injected := errors.New("injected sync failure")
			target := &recordingWriterAt{
				data:       bytes.Repeat([]byte{0xa5}, len(fixture.expected)),
				failSyncAt: test.failSyncAt,
				syncErr:    injected,
			}
			if _, err := Stage(context.Background(), target, fixture.plan, sources); !errors.Is(err, injected) || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Stage() error = %v, want wrapped %q", err, test.wantError)
			}
			if target.syncCalls != test.failSyncAt {
				t.Fatalf("Sync() calls = %d, want %d", target.syncCalls, test.failSyncAt)
			}
			writes := 0
			for _, event := range target.events {
				if event.kind == "write" {
					writes++
				}
			}
			if writes != test.wantWrites {
				t.Fatalf("WriteAt() calls = %d, want %d", writes, test.wantWrites)
			}
			if target.data[0] != test.primary || target.data[7*int(mediacontract.AlignmentBytes)] != test.backup {
				t.Fatalf("GPT first bytes = primary %#x, backup %#x; want %#x, %#x", target.data[0], target.data[7*int(mediacontract.AlignmentBytes)], test.primary, test.backup)
			}
		})
	}
}

func TestStageDetectsSourceTamperBeforeFirstTargetWrite(t *testing.T) {
	fixture := newMediaFixture(t)
	sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	file, err := os.OpenFile(fixture.paths.RootData, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0x99}, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	target := &recordingWriterAt{data: bytes.Repeat([]byte{0xa5}, len(fixture.expected))}
	if _, err := Stage(context.Background(), target, fixture.plan, sources); err == nil || !strings.Contains(err.Error(), "preflight source") {
		t.Fatalf("Stage() tamper error = %v", err)
	}
	if len(target.events) != 0 {
		t.Fatalf("Stage() wrote %d target chunks after preflight tamper", len(target.events))
	}
}

func TestStageFailsClosedOnShortWriteAndWriteError(t *testing.T) {
	t.Run("short write", func(t *testing.T) {
		fixture := newMediaFixture(t)
		sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
		if err != nil {
			t.Fatal(err)
		}
		defer sources.Close()
		writer := &shortWriterAt{}
		written, err := Stage(context.Background(), writer, fixture.plan, sources)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("Stage() error = %v, want io.ErrShortWrite", err)
		}
		if written != transferBufferBytes-1 {
			t.Fatalf("Stage() reported %d accepted bytes, want %d", written, transferBufferBytes-1)
		}
		if writer.calls != 1 {
			t.Fatalf("Stage() made %d calls after a short write, want 1", writer.calls)
		}
	})

	t.Run("write error", func(t *testing.T) {
		fixture := newMediaFixture(t)
		sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
		if err != nil {
			t.Fatal(err)
		}
		defer sources.Close()
		wantErr := errors.New("injected target failure")
		writer := &failingWriterAt{failAt: 2, err: wantErr}
		if _, err := Stage(context.Background(), writer, fixture.plan, sources); !errors.Is(err, wantErr) {
			t.Fatalf("Stage() error = %v, want %v", err, wantErr)
		}
		if writer.calls != 2 {
			t.Fatalf("Stage() made %d calls, want failure on call 2", writer.calls)
		}
	})

	t.Run("canceled before mutation", func(t *testing.T) {
		fixture := newMediaFixture(t)
		sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
		if err != nil {
			t.Fatal(err)
		}
		defer sources.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		writer := &recordingWriterAt{data: make([]byte, len(fixture.expected))}
		if _, err := Stage(ctx, writer, fixture.plan, sources); !errors.Is(err, context.Canceled) {
			t.Fatalf("Stage() error = %v, want context.Canceled", err)
		}
		if len(writer.events) != 0 {
			t.Fatalf("Stage() wrote %d chunks with an already canceled context", len(writer.events))
		}
	})
}

func TestOpenSourcesRejectsUnsafeOrMismatchedAssets(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		fixture := newMediaFixture(t)
		fixture.paths.RootData = "root.img"
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "clean and absolute") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		fixture := newMediaFixture(t)
		link := filepath.Join(t.TempDir(), "primary-link")
		if err := os.Symlink(fixture.paths.PrimaryGPT, link); err != nil {
			t.Fatal(err)
		}
		fixture.paths.PrimaryGPT = link
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("same path", func(t *testing.T) {
		fixture := newMediaFixture(t)
		fixture.paths.BootFilesystem = fixture.paths.PrimaryGPT
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "same path") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("same inode", func(t *testing.T) {
		fixture := newMediaFixture(t)
		link := filepath.Join(t.TempDir(), "boot-hardlink")
		if err := os.Link(fixture.paths.PrimaryGPT, link); err != nil {
			t.Fatal(err)
		}
		fixture.paths.BootFilesystem = link
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "same underlying file") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("wrong digest", func(t *testing.T) {
		fixture := newMediaFixture(t)
		file, err := os.OpenFile(fixture.paths.RootHash, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte{0x00}, 0); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "digest is") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("wrong size", func(t *testing.T) {
		fixture := newMediaFixture(t)
		if err := os.Truncate(fixture.paths.RootData, int64(len(fixture.root)-1)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "size is") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("nonblocking shared lock", func(t *testing.T) {
		fixture := newMediaFixture(t)
		locked, err := os.Open(fixture.paths.RootData)
		if err != nil {
			t.Fatal(err)
		}
		defer locked.Close()
		if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		defer syscall.Flock(int(locked.Fd()), syscall.LOCK_UN)
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "shared-lock") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})

	t.Run("regular file only", func(t *testing.T) {
		fixture := newMediaFixture(t)
		fixture.paths.RootData = t.TempDir()
		if _, err := OpenSources(context.Background(), fixture.plan, fixture.paths); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("OpenSources() error = %v", err)
		}
	})
}

func TestSourcesRejectHardLinkedRegularTargetBeforeStaging(t *testing.T) {
	fixture := newMediaFixture(t)
	sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	targetPath := filepath.Join(t.TempDir(), "hard-linked-target.img")
	if err := os.Link(fixture.paths.PrimaryGPT, targetPath); err != nil {
		t.Fatal(err)
	}
	target, err := os.Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := sources.ValidateDistinctRegularTarget(target); err == nil || !strings.Contains(err.Error(), "same underlying file") {
		t.Fatalf("ValidateDistinctRegularTarget() error = %v", err)
	}

	distinctPath := filepath.Join(t.TempDir(), "distinct-target.img")
	if err := os.WriteFile(distinctPath, make([]byte, len(fixture.primary)), 0o600); err != nil {
		t.Fatal(err)
	}
	distinct, err := os.Open(distinctPath)
	if err != nil {
		t.Fatal(err)
	}
	defer distinct.Close()
	if err := sources.ValidateDistinctRegularTarget(distinct); err != nil {
		t.Fatalf("ValidateDistinctRegularTarget(distinct): %v", err)
	}
}

func TestSourcesArePlanBoundAndCannotBeUsedAfterClose(t *testing.T) {
	fixture := newMediaFixture(t)
	sources, err := OpenSources(context.Background(), fixture.plan, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	other := fixture.plan
	other.TransactionID = "transaction:media:other"
	other, err = other.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriterAt{data: make([]byte, len(fixture.expected))}
	if _, err := Stage(context.Background(), writer, other, sources); err == nil || !strings.Contains(err.Error(), "different plan") {
		t.Fatalf("Stage() plan-binding error = %v", err)
	}
	if len(writer.events) != 0 {
		t.Fatal("Stage() mutated target for a different plan")
	}
	if err := sources.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sources.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if _, err := Stage(context.Background(), writer, fixture.plan, sources); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Stage() closed-source error = %v", err)
	}
}

func TestHashRangeIsExactBoundedAndContextAware(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), transferBufferBytes/8)
	got, err := HashRange(context.Background(), bytes.NewReader(data), 17, uint64(len(data)-31))
	if err != nil {
		t.Fatal(err)
	}
	if want := testDigest(data[17 : len(data)-14]); got != want {
		t.Fatalf("HashRange() = %s, want %s", got, want)
	}
	empty, err := HashRange(context.Background(), bytes.NewReader(nil), 0, 0)
	if err != nil || empty != testDigest(nil) {
		t.Fatalf("empty HashRange() = %s, %v", empty, err)
	}
	if _, err := HashRange(context.Background(), bytes.NewReader([]byte("short")), 0, 6); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short HashRange() error = %v", err)
	}
	if _, err := HashRange(context.Background(), bytes.NewReader(nil), math.MaxInt64, 1); err == nil {
		t.Fatal("HashRange() accepted an overflowing range")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashRange(ctx, bytes.NewReader(data), 0, uint64(len(data))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled HashRange() error = %v", err)
	}
}

type targetEvent struct {
	kind    string
	offset  int64
	length  int
	first   byte
	allZero bool
}

type recordingWriterAt struct {
	data       []byte
	events     []targetEvent
	syncCalls  int
	failSyncAt int
	syncErr    error
}

func (writer *recordingWriterAt) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(writer.data)) || len(data) > len(writer.data)-int(offset) {
		return 0, io.ErrShortWrite
	}
	event := targetEvent{kind: "write", offset: offset, length: len(data), allZero: true}
	if len(data) != 0 {
		event.first = data[0]
	}
	for _, value := range data {
		if value != 0 {
			event.allZero = false
			break
		}
	}
	writer.events = append(writer.events, event)
	copy(writer.data[int(offset):], data)
	return len(data), nil
}

func (writer *recordingWriterAt) Sync() error {
	writer.syncCalls++
	writer.events = append(writer.events, targetEvent{kind: "sync"})
	if writer.failSyncAt == writer.syncCalls {
		return writer.syncErr
	}
	return nil
}

type shortWriterAt struct{ calls int }

func (writer *shortWriterAt) WriteAt(data []byte, _ int64) (int, error) {
	writer.calls++
	return len(data) - 1, nil
}

func (*shortWriterAt) Sync() error { return nil }

type failingWriterAt struct {
	calls  int
	failAt int
	err    error
}

func (writer *failingWriterAt) WriteAt(data []byte, _ int64) (int, error) {
	writer.calls++
	if writer.calls == writer.failAt {
		return 0, writer.err
	}
	return len(data), nil
}

func (*failingWriterAt) Sync() error { return nil }

func newMediaFixture(t *testing.T) mediaFixture {
	t.Helper()
	const mib = int(mediacontract.AlignmentBytes)
	primary := bytes.Repeat([]byte{0x11}, mib)
	boot := bytes.Repeat([]byte{0x22}, mib)
	root := bytes.Repeat([]byte{0x33}, 4096)
	hashTree := bytes.Repeat([]byte{0x44}, 4096)
	backup := bytes.Repeat([]byte{0x55}, mib)

	rootRegion := make([]byte, mib)
	copy(rootRegion, root)
	hashRegion := make([]byte, mib)
	copy(hashRegion, hashTree)
	tailRegion := make([]byte, 3*mib)
	expected := make([]byte, 8*mib)
	copy(expected[0*mib:], primary)
	copy(expected[1*mib:], boot)
	copy(expected[2*mib:], root)
	copy(expected[3*mib:], hashTree)
	copy(expected[7*mib:], backup)

	primaryBinding := binding(primary)
	bootBinding := binding(boot)
	rootBinding := binding(root)
	hashBinding := binding(hashTree)
	backupBinding := binding(backup)
	bootImage := binding([]byte("boot-image"))
	bootSignature := binding([]byte("boot-signature"))
	rootIntegrity := binding([]byte("root-integrity"))
	mediaBinding := binding([]byte("media-binding"))

	layout := mediacontract.Layout{
		SchemaVersion:   mediacontract.LayoutSchemaVersion,
		SectorSizeBytes: mediacontract.SectorSizeBytes,
		AlignmentBytes:  mediacontract.AlignmentBytes,
		DiskGUID:        "11111111-1111-4111-8111-111111111111",
		FirstUsableLBA:  34,
		LastUsableLBA:   8*mediacontract.AlignmentBytes/mediacontract.SectorSizeBytes - 34,
		Payloads: mediacontract.PayloadBindings{
			BootImage:     bootImage,
			BootSignature: bootSignature,
			RootData:      rootBinding,
			RootHashTree:  hashBinding,
			RootIntegrity: rootIntegrity,
			MediaBinding:  mediaBinding,
			OuterBootFAT:  bootBinding,
			PrimaryGPT:    primaryBinding,
			BackupGPT:     backupBinding,
		},
		Sources: []mediacontract.SourceBinding{
			{Role: mediacontract.SourcePrimaryGPT, Digest: primaryBinding.Digest, SizeBytes: primaryBinding.SizeBytes},
			{Role: mediacontract.SourceBootFilesystem, Digest: bootBinding.Digest, SizeBytes: bootBinding.SizeBytes},
			{Role: mediacontract.SourceRootData, Digest: rootBinding.Digest, SizeBytes: rootBinding.SizeBytes},
			{Role: mediacontract.SourceRootHash, Digest: hashBinding.Digest, SizeBytes: hashBinding.SizeBytes},
			{Role: mediacontract.SourceBackupGPT, Digest: backupBinding.Digest, SizeBytes: backupBinding.SizeBytes},
		},
		Regions: []mediacontract.MediaRegion{
			{Role: mediacontract.RegionPrimaryGPT, ContentKind: mediacontract.ContentExactFile, SourceRole: mediacontract.SourcePrimaryGPT, OffsetBytes: 0, SizeBytes: mediacontract.AlignmentBytes, SourceSizeBytes: mediacontract.AlignmentBytes, SourceDigest: primaryBinding.Digest, ContentDigest: primaryBinding.Digest},
			{Role: mediacontract.RegionBootFilesystem, ContentKind: mediacontract.ContentExactFile, SourceRole: mediacontract.SourceBootFilesystem, OffsetBytes: mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, SourceSizeBytes: mediacontract.AlignmentBytes, SourceDigest: bootBinding.Digest, ContentDigest: bootBinding.Digest},
			{Role: mediacontract.RegionRootData, ContentKind: mediacontract.ContentFileZeroPadded, SourceRole: mediacontract.SourceRootData, OffsetBytes: 2 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, SourceSizeBytes: rootBinding.SizeBytes, SourceDigest: rootBinding.Digest, ContentDigest: testDigest(rootRegion)},
			{Role: mediacontract.RegionRootHash, ContentKind: mediacontract.ContentFileZeroPadded, SourceRole: mediacontract.SourceRootHash, OffsetBytes: 3 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, SourceSizeBytes: hashBinding.SizeBytes, SourceDigest: hashBinding.Digest, ContentDigest: testDigest(hashRegion)},
			{Role: mediacontract.RegionTailZero, ContentKind: mediacontract.ContentZero, SourceRole: mediacontract.SourceZero, OffsetBytes: 4 * mediacontract.AlignmentBytes, SizeBytes: 3 * mediacontract.AlignmentBytes, SourceDigest: testDigest(nil), ContentDigest: testDigest(tailRegion)},
			{Role: mediacontract.RegionBackupGPT, ContentKind: mediacontract.ContentExactFile, SourceRole: mediacontract.SourceBackupGPT, OffsetBytes: 7 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, SourceSizeBytes: mediacontract.AlignmentBytes, SourceDigest: backupBinding.Digest, ContentDigest: backupBinding.Digest},
		},
		Partitions: []mediacontract.GPTPartition{
			{Number: 1, Role: mediacontract.PartitionBoot, Name: "kaiba-boot", TypeGUID: mediacontract.ESPTypeGUID, UniqueGUID: "22222222-2222-4222-8222-222222222222", OffsetBytes: mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, UsedSizeBytes: bootBinding.SizeBytes, UsedDigest: bootBinding.Digest, PartitionDigest: bootBinding.Digest},
			{Number: 2, Role: mediacontract.PartitionRootData, Name: "kaiba-root", TypeGUID: mediacontract.ARM64RootTypeGUID, UniqueGUID: "33333333-3333-4333-8333-333333333333", OffsetBytes: 2 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, UsedSizeBytes: rootBinding.SizeBytes, UsedDigest: rootBinding.Digest, PartitionDigest: testDigest(rootRegion)},
			{Number: 3, Role: mediacontract.PartitionRootHash, Name: "kaiba-root-verity", TypeGUID: mediacontract.ARM64VerityGUID, UniqueGUID: "44444444-4444-4444-8444-444444444444", OffsetBytes: 3 * mediacontract.AlignmentBytes, SizeBytes: mediacontract.AlignmentBytes, UsedSizeBytes: hashBinding.SizeBytes, UsedDigest: hashBinding.Digest, PartitionDigest: testDigest(hashRegion)},
		},
		FAT: mediacontract.FATContract{
			Filesystem: "fat32",
			Label:      "KAIBA_BOOT",
			VolumeID:   "4b414942",
			Allowlist: []mediacontract.FATFile{
				{Path: "boot.img", Digest: bootImage.Digest, SizeBytes: bootImage.SizeBytes},
				{Path: "boot.sig", Digest: bootSignature.Digest, SizeBytes: bootSignature.SizeBytes},
				{Path: "config.txt", Digest: testDigest([]byte("boot_ramdisk=1\n")), SizeBytes: uint64(len("boot_ramdisk=1\n"))},
				{Path: "kaiba-media-binding.json", Digest: mediaBinding.Digest, SizeBytes: mediaBinding.SizeBytes},
			},
		},
		Verity: mediacontract.VerityContract{
			Algorithm:          "sha256",
			RootHash:           testDigest([]byte("verity-root-hash")),
			DataBlockSizeBytes: 4096,
			HashBlockSizeBytes: 4096,
			DataPartitionGUID:  "33333333-3333-4333-8333-333333333333",
			HashPartitionGUID:  "44444444-4444-4444-8444-444444444444",
			Mapper:             "/dev/mapper/root",
		},
	}
	var err error
	layout, err = layout.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan := mediacontract.Plan{
		SchemaVersion: mediacontract.PlanSchemaVersion,
		TransactionID: "transaction:media:writer-test",
		Release: mediacontract.ReleaseBinding{
			ReleaseID:                   "release:rpi5:writer-test",
			SignedReleaseManifestDigest: testDigest([]byte("signed-release")),
			CapsuleDigest:               testDigest([]byte("capsule")),
		},
		Target: mediacontract.TargetBinding{
			SizeBytes:              uint64(len(expected)),
			LogicalSectorSizeBytes: mediacontract.SectorSizeBytes,
		},
		Layout:              layout,
		ExpectedMediaDigest: testDigest(expected),
	}
	plan, err = plan.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	paths := AssetPaths{
		PrimaryGPT:     filepath.Join(directory, "primary-gpt.img"),
		BootFilesystem: filepath.Join(directory, "boot-fat.img"),
		RootData:       filepath.Join(directory, "root-data.img"),
		RootHash:       filepath.Join(directory, "root-hash.img"),
		BackupGPT:      filepath.Join(directory, "backup-gpt.img"),
	}
	for path, data := range map[string][]byte{
		paths.PrimaryGPT: primary, paths.BootFilesystem: boot, paths.RootData: root,
		paths.RootHash: hashTree, paths.BackupGPT: backup,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return mediaFixture{plan: plan, paths: paths, expected: expected, primary: primary, boot: boot, root: root, hash: hashTree, backup: backup}
}

func binding(data []byte) mediacontract.ArtifactBinding {
	return mediacontract.ArtifactBinding{Digest: testDigest(data), SizeBytes: uint64(len(data))}
}

func testDigest(data []byte) mediacontract.Digest {
	sum := sha256.Sum256(data)
	return mediacontract.Digest("sha256:" + hex.EncodeToString(sum[:]))
}
