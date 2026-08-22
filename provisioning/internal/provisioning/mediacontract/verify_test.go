package mediacontract

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
)

const testBootPartitionBytes = uint64(35 * AlignmentBytes)

type fullMediaFixture struct {
	plan     Plan
	media    []byte
	rootData []byte
	rootHash []byte
}

func TestVerifyFullMediaChecksEveryLayerIndependently(t *testing.T) {
	fixture := buildFullMediaFixture(t)
	verityCalls := 0
	releaseCalls := 0
	checker := VerityVerifierFunc(func(_ context.Context, target io.ReaderAt, data, hash GPTPartition, contract VerityContract) error {
		verityCalls++
		actualData := make([]byte, data.UsedSizeBytes)
		actualHash := make([]byte, hash.UsedSizeBytes)
		if err := readExact(target, data.OffsetBytes, actualData); err != nil {
			return err
		}
		if err := readExact(target, hash.OffsetBytes, actualHash); err != nil {
			return err
		}
		if sumBytes(actualData) != fixture.plan.Layout.Payloads.RootData.Digest || sumBytes(actualHash) != fixture.plan.Layout.Payloads.RootHashTree.Digest || contract.RootHash != fixture.plan.Layout.Verity.RootHash {
			return fmt.Errorf("verity checker received the wrong trusted ranges")
		}
		return nil
	})
	releaseChecker := SignedReleaseVerifierFunc(func(_ context.Context, files VerifiedBootFiles, plan Plan) error {
		releaseCalls++
		if sumBytes(files.BootImage) != plan.Layout.Payloads.BootImage.Digest || sumBytes(files.BootSignature) != plan.Layout.Payloads.BootSignature.Digest {
			return fmt.Errorf("release checker received the wrong boot files")
		}
		return nil
	})
	report, err := VerifyFullMedia(context.Background(), bytesReaderAt(fixture.media), uint64(len(fixture.media)), fixture.plan, checker, releaseChecker)
	if err != nil {
		t.Fatalf("VerifyFullMedia(): %v", err)
	}
	if verityCalls != 1 || releaseCalls != 1 || !report.GPTVerified || !report.FATVerified || !report.PartitionDigestsVerified || !report.DMVerityVerified || !report.BootSignatureVerified || !report.ReleaseLineageVerified || report.HardwareObserved || report.ColdPowerCycleObserved || report.SecurityEnforced || report.MutationEligible {
		t.Fatalf("verification report = %#v, verity_calls=%d release_calls=%d", report, verityCalls, releaseCalls)
	}
}

func TestVerifyFullMediaRejectsSemanticallyInvalidBytesEvenWhenDigestsAreRebound(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fullMediaFixture)
		region RegionRole
		want   string
	}{
		{
			name:   "hybrid MBR",
			mutate: func(fixture *fullMediaFixture) { fixture.media[462+4] = 0x83 },
			region: RegionPrimaryGPT,
			want:   "protective MBR",
		},
		{
			name:   "hidden protective MBR CHS bytes",
			mutate: func(fixture *fullMediaFixture) { fixture.media[446+1] = 1 },
			region: RegionPrimaryGPT,
			want:   "protective MBR",
		},
		{
			name:   "hidden primary GPT region padding",
			mutate: func(fixture *fullMediaFixture) { fixture.media[34*SectorSizeBytes] = 1 },
			region: RegionPrimaryGPT,
			want:   "GPT region padding",
		},
		{
			name: "hidden backup GPT region padding",
			mutate: func(fixture *fullMediaFixture) {
				fixture.media[uint64(len(fixture.media))-AlignmentBytes] = 1
			},
			region: RegionBackupGPT,
			want:   "GPT region padding",
		},
		{
			name:   "extra FAT file",
			mutate: addExtraFATFile,
			region: RegionBootFilesystem,
			want:   "FAT root contains",
		},
		{
			name:   "self-consistent but wrong media binding",
			mutate: changeFATMediaBindingTransaction,
			region: RegionBootFilesystem,
			want:   "media binding differs",
		},
		{
			name:   "hidden FAT file slack",
			mutate: addFATFileSlack,
			region: RegionBootFilesystem,
			want:   "file slack",
		},
		{
			name:   "hidden unallocated FAT data",
			mutate: addUnallocatedFATData,
			region: RegionBootFilesystem,
			want:   "unallocated data clusters",
		},
		{
			name:   "hidden FAT boot code",
			mutate: addFATBootCode,
			region: RegionBootFilesystem,
			want:   "boot-code bytes",
		},
		{
			name:   "hidden FAT reserved sector",
			mutate: addFATReservedSectorData,
			region: RegionBootFilesystem,
			want:   "unused reserved sectors",
		},
		{
			name:   "hidden FAT FSInfo payload",
			mutate: changeFATFSInfoPayload,
			region: RegionBootFilesystem,
			want:   "FSInfo sector differs",
		},
		{
			name:   "hidden FAT entry high nibble",
			mutate: changeFATEntryHighNibble,
			region: RegionBootFilesystem,
			want:   "reserved high bits",
		},
		{
			name:   "hidden FAT table tail",
			mutate: addFATTableTailData,
			region: RegionBootFilesystem,
			want:   "allocation-table tail",
		},
		{
			name:   "hidden FAT directory metadata",
			mutate: changeFATDirectoryMetadata,
			region: RegionBootFilesystem,
			want:   "directory metadata",
		},
		{
			name:   "alternate FAT long-name padding",
			mutate: changeFATLongNamePadding,
			region: RegionBootFilesystem,
			want:   "more than one terminator",
		},
		{
			name:   "extra FAT long-name entry",
			mutate: addFATLongNameEntry,
			region: RegionBootFilesystem,
			want:   "canonical short/long-name form",
		},
		{
			name:   "hidden FAT directory end-marker metadata",
			mutate: addFATDirectoryEndMarkerMetadata,
			region: RegionBootFilesystem,
			want:   "end marker contains hidden metadata",
		},
		{
			name:   "alternate FAT end-of-chain marker",
			mutate: changeFATEndOfChainMarker,
			region: RegionBootFilesystem,
			want:   "non-canonical allocation chain",
		},
		{
			name:   "reordered FAT directory entries",
			mutate: reorderFATDirectoryEntries,
			region: RegionBootFilesystem,
			want:   "canonical allowlist order",
		},
		{
			name:   "alternate FAT file cluster placement",
			mutate: swapFATFileClusters,
			region: RegionBootFilesystem,
			want:   "canonical contiguous clusters",
		},
		{
			name: "nonzero root padding",
			mutate: func(fixture *fullMediaFixture) {
				partition, _ := fixture.plan.Layout.partition(PartitionRootData)
				fixture.media[partition.OffsetBytes+partition.UsedSizeBytes] = 1
			},
			region: RegionRootData,
			want:   "padding",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := buildFullMediaFixture(t)
			test.mutate(&fixture)
			fixture.plan = rebindChangedRegion(t, fixture.plan, fixture.media, test.region)
			checker := VerityVerifierFunc(func(context.Context, io.ReaderAt, GPTPartition, GPTPartition, VerityContract) error { return nil })
			releaseChecker := SignedReleaseVerifierFunc(func(context.Context, VerifiedBootFiles, Plan) error { return nil })
			if _, err := VerifyFullMedia(context.Background(), bytesReaderAt(fixture.media), uint64(len(fixture.media)), fixture.plan, checker, releaseChecker); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("VerifyFullMedia() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestVerifyFullMediaRequiresAnActualVerityChecker(t *testing.T) {
	fixture := buildFullMediaFixture(t)
	releaseChecker := SignedReleaseVerifierFunc(func(context.Context, VerifiedBootFiles, Plan) error { return nil })
	if _, err := VerifyFullMedia(context.Background(), bytesReaderAt(fixture.media), uint64(len(fixture.media)), fixture.plan, nil, releaseChecker); err == nil {
		t.Fatal("VerifyFullMedia accepted a caller-asserted or absent dm-verity result")
	}
	verityChecker := VerityVerifierFunc(func(context.Context, io.ReaderAt, GPTPartition, GPTPartition, VerityContract) error { return nil })
	if _, err := VerifyFullMedia(context.Background(), bytesReaderAt(fixture.media), uint64(len(fixture.media)), fixture.plan, verityChecker, nil); err == nil {
		t.Fatal("VerifyFullMedia accepted an absent signed-release checker")
	}
}

func TestVerifyFATDataTailRejectsNonzeroBytes(t *testing.T) {
	partition := GPTPartition{OffsetBytes: 3, SizeBytes: 10}
	media := make([]byte, 13)
	if err := verifyFATDataTail(context.Background(), bytesReaderAt(media), partition, 1, 10, 1, 4, 2); err != nil {
		t.Fatalf("verifyFATDataTail(zero): %v", err)
	}
	media[12] = 1
	if err := verifyFATDataTail(context.Background(), bytesReaderAt(media), partition, 1, 10, 1, 4, 2); err == nil || !strings.Contains(err.Error(), "trailing non-cluster") {
		t.Fatalf("verifyFATDataTail(nonzero) error = %v", err)
	}
}

type bytesReaderAt []byte

func (value bytesReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(value)) {
		return 0, io.EOF
	}
	n := copy(buffer, value[offset:])
	if n != len(buffer) {
		return n, io.EOF
	}
	return n, nil
}

func buildFullMediaFixture(t *testing.T) fullMediaFixture {
	t.Helper()
	transactionID := "transaction:full-media:1"
	release := ReleaseBinding{ReleaseID: "release:rpi5:1", SignedReleaseManifestDigest: testDigest("signed release"), CapsuleDigest: testDigest("capsule")}
	rootData := make([]byte, 4096)
	rootHash := make([]byte, 4096)
	copy(rootData, []byte("immutable root data used bytes"))
	copy(rootHash, []byte("dm-verity hash tree used bytes"))
	rootIntegrity := ArtifactBinding{Digest: testDigest("root integrity record"), SizeBytes: 64}
	verityRootHash := testDigest("trusted root hash")
	diskGUID := "11111111-1111-4111-8111-111111111111"
	bootGUID := "22222222-2222-4222-8222-222222222222"
	dataGUID := "33333333-3333-4333-8333-333333333333"
	hashGUID := "44444444-4444-4444-8444-444444444444"
	bootImage := []byte("signed inner boot image")
	bootSignature := []byte("canonical detached signature")
	mediaBinding, err := (MediaBinding{
		SchemaVersion:               MediaBindingSchemaVersion,
		TransactionID:               transactionID,
		ReleaseID:                   release.ReleaseID,
		SignedReleaseManifestDigest: release.SignedReleaseManifestDigest,
		CapsuleDigest:               release.CapsuleDigest,
		BootImageDigest:             sumBytes(bootImage),
		BootSignatureDigest:         sumBytes(bootSignature),
		RootDataDigest:              sumBytes(rootData),
		RootHashTreeDigest:          sumBytes(rootHash),
		RootIntegrityDigest:         rootIntegrity.Digest,
		VerityRootHash:              verityRootHash,
		BootPartitionGUID:           bootGUID,
		DataPartitionGUID:           dataGUID,
		HashPartitionGUID:           hashGUID,
	}).CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	bootFiles := map[string][]byte{
		"boot.img":                 bootImage,
		"boot.sig":                 bootSignature,
		"config.txt":               []byte("boot_ramdisk=1\n"),
		"kaiba-media-binding.json": mediaBinding,
	}
	bootFAT := buildTestFAT32(t, bootFiles)
	if uint64(len(bootFAT)) != testBootPartitionBytes {
		t.Fatalf("boot FAT size = %d", len(bootFAT))
	}
	primaryOffset := uint64(0)
	bootOffset := AlignmentBytes
	rootOffset := bootOffset + testBootPartitionBytes
	hashOffset := rootOffset + AlignmentBytes
	tailOffset := hashOffset + AlignmentBytes
	backupOffset := tailOffset + AlignmentBytes
	targetSize := backupOffset + AlignmentBytes
	media := make([]byte, int(targetSize))
	copy(media[bootOffset:], bootFAT)
	copy(media[rootOffset:], rootData)
	copy(media[hashOffset:], rootHash)

	partitions := []GPTPartition{
		{Number: 1, Role: PartitionBoot, Name: "kaiba-boot", TypeGUID: ESPTypeGUID, UniqueGUID: bootGUID, OffsetBytes: bootOffset, SizeBytes: testBootPartitionBytes, UsedSizeBytes: testBootPartitionBytes},
		{Number: 2, Role: PartitionRootData, Name: "kaiba-root", TypeGUID: ARM64RootTypeGUID, UniqueGUID: dataGUID, OffsetBytes: rootOffset, SizeBytes: AlignmentBytes, UsedSizeBytes: uint64(len(rootData))},
		{Number: 3, Role: PartitionRootHash, Name: "kaiba-root-verity", TypeGUID: ARM64VerityGUID, UniqueGUID: hashGUID, OffsetBytes: hashOffset, SizeBytes: AlignmentBytes, UsedSizeBytes: uint64(len(rootHash))},
	}
	writeTestGPT(t, media, diskGUID, partitions)

	primaryBytes := media[primaryOffset : primaryOffset+AlignmentBytes]
	backupBytes := media[backupOffset : backupOffset+AlignmentBytes]
	bootBytes := media[bootOffset : bootOffset+testBootPartitionBytes]
	rootBytes := media[rootOffset : rootOffset+AlignmentBytes]
	hashBytes := media[hashOffset : hashOffset+AlignmentBytes]
	tailBytes := media[tailOffset : tailOffset+AlignmentBytes]
	primaryBinding := ArtifactBinding{Digest: sumBytes(primaryBytes), SizeBytes: AlignmentBytes}
	bootBinding := ArtifactBinding{Digest: sumBytes(bootBytes), SizeBytes: testBootPartitionBytes}
	rootBinding := ArtifactBinding{Digest: sumBytes(rootData), SizeBytes: uint64(len(rootData))}
	hashBinding := ArtifactBinding{Digest: sumBytes(rootHash), SizeBytes: uint64(len(rootHash))}
	backupBinding := ArtifactBinding{Digest: sumBytes(backupBytes), SizeBytes: AlignmentBytes}
	partitions[0].UsedDigest, partitions[0].PartitionDigest = bootBinding.Digest, bootBinding.Digest
	partitions[1].UsedDigest, partitions[1].PartitionDigest = rootBinding.Digest, sumBytes(rootBytes)
	partitions[2].UsedDigest, partitions[2].PartitionDigest = hashBinding.Digest, sumBytes(hashBytes)
	layout := Layout{
		SchemaVersion:   LayoutSchemaVersion,
		SectorSizeBytes: SectorSizeBytes,
		AlignmentBytes:  AlignmentBytes,
		DiskGUID:        diskGUID,
		FirstUsableLBA:  34,
		LastUsableLBA:   targetSize/SectorSizeBytes - 34,
		Payloads: PayloadBindings{
			BootImage:     ArtifactBinding{Digest: sumBytes(bootFiles["boot.img"]), SizeBytes: uint64(len(bootFiles["boot.img"]))},
			BootSignature: ArtifactBinding{Digest: sumBytes(bootFiles["boot.sig"]), SizeBytes: uint64(len(bootFiles["boot.sig"]))},
			RootData:      rootBinding,
			RootHashTree:  hashBinding,
			RootIntegrity: rootIntegrity,
			MediaBinding:  ArtifactBinding{Digest: sumBytes(bootFiles["kaiba-media-binding.json"]), SizeBytes: uint64(len(bootFiles["kaiba-media-binding.json"]))},
			OuterBootFAT:  bootBinding,
			PrimaryGPT:    primaryBinding,
			BackupGPT:     backupBinding,
		},
		Sources: []SourceBinding{
			{Role: SourcePrimaryGPT, Digest: primaryBinding.Digest, SizeBytes: primaryBinding.SizeBytes},
			{Role: SourceBootFilesystem, Digest: bootBinding.Digest, SizeBytes: bootBinding.SizeBytes},
			{Role: SourceRootData, Digest: rootBinding.Digest, SizeBytes: rootBinding.SizeBytes},
			{Role: SourceRootHash, Digest: hashBinding.Digest, SizeBytes: hashBinding.SizeBytes},
			{Role: SourceBackupGPT, Digest: backupBinding.Digest, SizeBytes: backupBinding.SizeBytes},
		},
		Regions: []MediaRegion{
			{Role: RegionPrimaryGPT, ContentKind: ContentExactFile, SourceRole: SourcePrimaryGPT, OffsetBytes: primaryOffset, SizeBytes: AlignmentBytes, SourceSizeBytes: AlignmentBytes, SourceDigest: primaryBinding.Digest, ContentDigest: primaryBinding.Digest},
			{Role: RegionBootFilesystem, ContentKind: ContentExactFile, SourceRole: SourceBootFilesystem, OffsetBytes: bootOffset, SizeBytes: testBootPartitionBytes, SourceSizeBytes: testBootPartitionBytes, SourceDigest: bootBinding.Digest, ContentDigest: bootBinding.Digest},
			{Role: RegionRootData, ContentKind: ContentFileZeroPadded, SourceRole: SourceRootData, OffsetBytes: rootOffset, SizeBytes: AlignmentBytes, SourceSizeBytes: rootBinding.SizeBytes, SourceDigest: rootBinding.Digest, ContentDigest: sumBytes(rootBytes)},
			{Role: RegionRootHash, ContentKind: ContentFileZeroPadded, SourceRole: SourceRootHash, OffsetBytes: hashOffset, SizeBytes: AlignmentBytes, SourceSizeBytes: hashBinding.SizeBytes, SourceDigest: hashBinding.Digest, ContentDigest: sumBytes(hashBytes)},
			{Role: RegionTailZero, ContentKind: ContentZero, SourceRole: SourceZero, OffsetBytes: tailOffset, SizeBytes: AlignmentBytes, SourceDigest: sumBytes(nil), ContentDigest: sumBytes(tailBytes)},
			{Role: RegionBackupGPT, ContentKind: ContentExactFile, SourceRole: SourceBackupGPT, OffsetBytes: backupOffset, SizeBytes: AlignmentBytes, SourceSizeBytes: AlignmentBytes, SourceDigest: backupBinding.Digest, ContentDigest: backupBinding.Digest},
		},
		Partitions: partitions,
		FAT: FATContract{
			Filesystem: "fat32", Label: "KAIBA_BOOT", VolumeID: "4b414942",
			Allowlist: []FATFile{
				{Path: "boot.img", Digest: sumBytes(bootFiles["boot.img"]), SizeBytes: uint64(len(bootFiles["boot.img"]))},
				{Path: "boot.sig", Digest: sumBytes(bootFiles["boot.sig"]), SizeBytes: uint64(len(bootFiles["boot.sig"]))},
				{Path: "config.txt", Digest: sumBytes(bootFiles["config.txt"]), SizeBytes: uint64(len(bootFiles["config.txt"]))},
				{Path: "kaiba-media-binding.json", Digest: sumBytes(bootFiles["kaiba-media-binding.json"]), SizeBytes: uint64(len(bootFiles["kaiba-media-binding.json"]))},
			},
		},
		Verity: VerityContract{
			Algorithm: "sha256", RootHash: verityRootHash, DataBlockSizeBytes: 4096, HashBlockSizeBytes: 4096,
			DataPartitionGUID: dataGUID, HashPartitionGUID: hashGUID, Mapper: "/dev/mapper/root",
		},
	}
	layout, err = layout.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		SchemaVersion:       PlanSchemaVersion,
		TransactionID:       transactionID,
		Release:             release,
		Target:              TargetBinding{ByIDPath: "/dev/disk/by-id/nvme-kaiba-full-media", Model: "KAIBA-NVME", Serial: "SERIAL-FULL", WWID: "eui.2222222222222222", SizeBytes: targetSize, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 4096},
		Layout:              layout,
		InitialMediaDigest:  testDigest("reviewed prestate"),
		ExpectedMediaDigest: sumBytes(media),
	}
	plan, err = plan.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	return fullMediaFixture{plan: plan, media: media, rootData: rootData, rootHash: rootHash}
}

func buildTestFAT32(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	const totalSectors = uint32(testBootPartitionBytes / SectorSizeBytes)
	const reservedSectors = uint32(32)
	const sectorsPerFAT = uint32(552)
	filesystem := make([]byte, int(testBootPartitionBytes))
	boot := filesystem[:SectorSizeBytes]
	boot[0], boot[1], boot[2] = 0xeb, 0x58, 0x90
	copy(boot[3:11], []byte("KAIBA   "))
	binary.LittleEndian.PutUint16(boot[11:13], 512)
	boot[13] = 1
	binary.LittleEndian.PutUint16(boot[14:16], uint16(reservedSectors))
	boot[16] = 2
	boot[21] = 0xf8
	binary.LittleEndian.PutUint16(boot[24:26], 32)
	binary.LittleEndian.PutUint16(boot[26:28], 8)
	binary.LittleEndian.PutUint32(boot[32:36], totalSectors)
	binary.LittleEndian.PutUint32(boot[36:40], sectorsPerFAT)
	binary.LittleEndian.PutUint32(boot[44:48], 2)
	binary.LittleEndian.PutUint16(boot[48:50], 1)
	binary.LittleEndian.PutUint16(boot[50:52], 6)
	boot[64] = 0x80
	boot[66] = 0x29
	binary.LittleEndian.PutUint32(boot[67:71], 0x4b414942)
	copy(boot[71:82], []byte("KAIBA_BOOT "))
	copy(boot[82:90], []byte("FAT32   "))
	boot[510], boot[511] = 0x55, 0xaa
	copy(filesystem[6*SectorSizeBytes:7*SectorSizeBytes], boot)
	for _, sector := range []uint64{1, 7} {
		fsInfo := filesystem[sector*SectorSizeBytes : (sector+1)*SectorSizeBytes]
		binary.LittleEndian.PutUint32(fsInfo[0:4], 0x41615252)
		binary.LittleEndian.PutUint32(fsInfo[484:488], 0x61417272)
		binary.LittleEndian.PutUint32(fsInfo[488:492], 0xffffffff)
		binary.LittleEndian.PutUint32(fsInfo[492:496], 0xffffffff)
		binary.LittleEndian.PutUint32(fsInfo[508:512], 0xaa550000)
	}

	fatBytes := int(sectorsPerFAT * 512)
	firstFAT := filesystem[int(reservedSectors*512) : int(reservedSectors*512)+fatBytes]
	for cluster, value := range map[uint32]uint32{0: 0x0ffffff8, 1: 0x0fffffff, 2: 0x0fffffff, 3: 0x0fffffff, 4: 0x0fffffff, 5: 0x0fffffff} {
		binary.LittleEndian.PutUint32(firstFAT[cluster*4:cluster*4+4], value)
	}
	bindingClusters := (len(files["kaiba-media-binding.json"]) + 511) / 512
	for index := 0; index < bindingClusters; index++ {
		cluster := uint32(6 + index)
		next := uint32(0x0fffffff)
		if index+1 < bindingClusters {
			next = cluster + 1
		}
		binary.LittleEndian.PutUint32(firstFAT[cluster*4:cluster*4+4], next)
	}
	copy(filesystem[int(reservedSectors*512)+fatBytes:int(reservedSectors*512)+2*fatBytes], firstFAT)
	dataStart := uint64(reservedSectors+2*sectorsPerFAT) * 512
	root := filesystem[dataStart : dataStart+512]
	position := 0
	copy(root[position:position+11], []byte("KAIBA_BOOT "))
	root[position+11] = 0x08
	binary.LittleEndian.PutUint16(root[position+16:position+18], canonicalFATDate)
	binary.LittleEndian.PutUint16(root[position+18:position+20], canonicalFATDate)
	binary.LittleEndian.PutUint16(root[position+24:position+26], canonicalFATDate)
	position += 32
	entries := []struct {
		name    string
		short   string
		cluster uint32
	}{
		{"boot.img", "BOOT    IMG", 3},
		{"boot.sig", "BOOT    SIG", 4},
		{"config.txt", "CONFIG  TXT", 5},
	}
	for _, item := range entries {
		writeShortFATEntry(root[position:position+32], item.short, item.cluster, files[item.name])
		position += 32
	}
	longName := "kaiba-media-binding.json"
	shortAlias := "KAIBA-~1JSO"
	for _, raw := range encodeLFNEntries(t, longName, []byte(shortAlias)) {
		copy(root[position:position+32], raw)
		position += 32
	}
	writeShortFATEntry(root[position:position+32], shortAlias, 6, files[longName])
	for _, item := range []struct {
		cluster uint32
		data    []byte
	}{
		{3, files["boot.img"]}, {4, files["boot.sig"]}, {5, files["config.txt"]}, {6, files[longName]},
	} {
		offset := dataStart + uint64(item.cluster-2)*512
		copy(filesystem[offset:offset+uint64(len(item.data))], item.data)
	}
	return filesystem
}

func writeShortFATEntry(raw []byte, short string, cluster uint32, data []byte) {
	copy(raw[:11], []byte(short))
	raw[11] = 0x20
	if short != canonicalFATShortNames["kaiba-media-binding.json"] {
		raw[12] = 0x18
	}
	binary.LittleEndian.PutUint16(raw[16:18], canonicalFATDate)
	binary.LittleEndian.PutUint16(raw[18:20], canonicalFATDate)
	binary.LittleEndian.PutUint16(raw[20:22], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(raw[24:26], canonicalFATDate)
	binary.LittleEndian.PutUint16(raw[26:28], uint16(cluster))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(len(data)))
}

func encodeLFNEntries(t *testing.T, name string, short []byte) [][]byte {
	t.Helper()
	units := utf16.Encode([]rune(name))
	units = append(units, 0)
	count := (len(units) + 12) / 13
	for len(units) < count*13 {
		units = append(units, 0xffff)
	}
	entries := make([][]byte, 0, count)
	for ordinal := count; ordinal >= 1; ordinal-- {
		raw := make([]byte, 32)
		raw[0] = byte(ordinal)
		if ordinal == count {
			raw[0] |= 0x40
		}
		raw[11] = 0x0f
		raw[13] = lfnChecksum(short)
		part := units[(ordinal-1)*13 : ordinal*13]
		unitIndex := 0
		for _, bounds := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
			for index := bounds[0]; index < bounds[1]; index += 2 {
				binary.LittleEndian.PutUint16(raw[index:index+2], part[unitIndex])
				unitIndex++
			}
		}
		entries = append(entries, raw)
	}
	return entries
}

func writeTestGPT(t *testing.T, media []byte, diskGUID string, partitions []GPTPartition) {
	t.Helper()
	totalLBAs := uint64(len(media)) / SectorSizeBytes
	mbr := media[:SectorSizeBytes]
	entry := mbr[446:462]
	entry[4] = 0xee
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], uint32(totalLBAs-1))
	mbr[510], mbr[511] = 0x55, 0xaa
	entries := make([]byte, gptEntryArrayBytes)
	for index, partition := range partitions {
		raw := entries[index*gptEntrySize : (index+1)*gptEntrySize]
		copy(raw[:16], guidToGPTBytes(t, partition.TypeGUID))
		copy(raw[16:32], guidToGPTBytes(t, partition.UniqueGUID))
		firstLBA := partition.OffsetBytes / SectorSizeBytes
		lastLBA := firstLBA + partition.SizeBytes/SectorSizeBytes - 1
		binary.LittleEndian.PutUint64(raw[32:40], firstLBA)
		binary.LittleEndian.PutUint64(raw[40:48], lastLBA)
		binary.LittleEndian.PutUint64(raw[48:56], partition.Attributes)
		for nameIndex, unit := range utf16.Encode([]rune(partition.Name)) {
			binary.LittleEndian.PutUint16(raw[56+nameIndex*2:58+nameIndex*2], unit)
		}
	}
	entriesCRC := crc32.ChecksumIEEE(entries)
	copy(media[2*SectorSizeBytes:2*SectorSizeBytes+gptEntryArrayBytes], entries)
	backupEntriesLBA := totalLBAs - 1 - gptEntryArraySectors
	copy(media[backupEntriesLBA*SectorSizeBytes:backupEntriesLBA*SectorSizeBytes+gptEntryArrayBytes], entries)
	writeGPTHeader(media[SectorSizeBytes:2*SectorSizeBytes], 1, totalLBAs-1, 2, totalLBAs, diskGUID, entriesCRC, t)
	writeGPTHeader(media[(totalLBAs-1)*SectorSizeBytes:totalLBAs*SectorSizeBytes], totalLBAs-1, 1, backupEntriesLBA, totalLBAs, diskGUID, entriesCRC, t)
}

func writeGPTHeader(raw []byte, current, backup, entriesLBA, totalLBAs uint64, diskGUID string, entriesCRC uint32, t *testing.T) {
	copy(raw[:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(raw[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(raw[12:16], gptHeaderSize)
	binary.LittleEndian.PutUint64(raw[24:32], current)
	binary.LittleEndian.PutUint64(raw[32:40], backup)
	binary.LittleEndian.PutUint64(raw[40:48], 34)
	binary.LittleEndian.PutUint64(raw[48:56], totalLBAs-34)
	copy(raw[56:72], guidToGPTBytes(t, diskGUID))
	binary.LittleEndian.PutUint64(raw[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(raw[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(raw[84:88], gptEntrySize)
	binary.LittleEndian.PutUint32(raw[88:92], entriesCRC)
	copyForCRC := append([]byte(nil), raw[:gptHeaderSize]...)
	binary.LittleEndian.PutUint32(raw[16:20], crc32.ChecksumIEEE(copyForCRC))
}

func guidToGPTBytes(t *testing.T, guid string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.ReplaceAll(guid, "-", ""))
	if err != nil || len(decoded) != 16 {
		t.Fatalf("decode GUID %q", guid)
	}
	return []byte{decoded[3], decoded[2], decoded[1], decoded[0], decoded[5], decoded[4], decoded[7], decoded[6], decoded[8], decoded[9], decoded[10], decoded[11], decoded[12], decoded[13], decoded[14], decoded[15]}
}

func addExtraFATFile(fixture *fullMediaFixture) {
	bootOffset := fixture.plan.Layout.Partitions[0].OffsetBytes
	boot := fixture.media[bootOffset : bootOffset+testBootPartitionBytes]
	reserved := uint32(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := binary.LittleEndian.Uint32(boot[36:40])
	fatBytes := sectorsPerFAT * 512
	extraCluster := uint32(20)
	for binary.LittleEndian.Uint32(boot[reserved*512+extraCluster*4:reserved*512+extraCluster*4+4])&0x0fffffff != 0 {
		extraCluster++
	}
	for copyIndex := uint32(0); copyIndex < 2; copyIndex++ {
		fatOffset := (reserved*512 + copyIndex*fatBytes) + extraCluster*4
		binary.LittleEndian.PutUint32(boot[fatOffset:fatOffset+4], 0x0fffffff)
	}
	dataStart := uint64(reserved+2*sectorsPerFAT) * 512
	root := boot[dataStart : dataStart+512]
	position := 0
	for position < len(root) && root[position] != 0 {
		position += 32
	}
	writeShortFATEntry(root[position:position+32], "EXTRA   TXT", extraCluster, []byte("evil"))
	extraOffset := dataStart + uint64(extraCluster-2)*512
	copy(boot[extraOffset:extraOffset+4], []byte("evil"))
}

func changeFATMediaBindingTransaction(fixture *fullMediaFixture) {
	bootOffset := fixture.plan.Layout.Partitions[0].OffsetBytes
	boot := fixture.media[bootOffset : bootOffset+testBootPartitionBytes]
	reserved := uint64(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := uint64(binary.LittleEndian.Uint32(boot[36:40]))
	dataStart := (reserved + 2*sectorsPerFAT) * 512
	bindingEntry := fixture.plan.Layout.FAT.Allowlist[3]
	bindingOffset := dataStart + uint64(6-2)*512
	original := append([]byte(nil), boot[bindingOffset:bindingOffset+bindingEntry.SizeBytes]...)
	binding, err := ParseMediaBinding(original)
	if err != nil {
		panic(err)
	}
	binding.TransactionID = "transaction:full-media:2"
	canonical, err := binding.CanonicalJSON()
	if err != nil || len(canonical) != len(original) {
		panic("mutated media binding did not preserve its fixture length")
	}
	copy(boot[bindingOffset:bindingOffset+uint64(len(canonical))], canonical)
	digest := sumBytes(canonical)
	fixture.plan.Layout.Payloads.MediaBinding.Digest = digest
	fixture.plan.Layout.FAT.Allowlist = append([]FATFile(nil), fixture.plan.Layout.FAT.Allowlist...)
	fixture.plan.Layout.FAT.Allowlist[3].Digest = digest
}

func addFATFileSlack(fixture *fullMediaFixture) {
	boot := fixture.media[fixture.plan.Layout.Partitions[0].OffsetBytes:]
	reserved := uint64(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := uint64(binary.LittleEndian.Uint32(boot[36:40]))
	dataStart := (reserved + 2*sectorsPerFAT) * 512
	bootImageSize := fixture.plan.Layout.FAT.Allowlist[0].SizeBytes
	boot[dataStart+uint64(3-2)*512+bootImageSize] = 1
}

func addUnallocatedFATData(fixture *fullMediaFixture) {
	boot := fixture.media[fixture.plan.Layout.Partitions[0].OffsetBytes:]
	reserved := uint64(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := uint64(binary.LittleEndian.Uint32(boot[36:40]))
	dataStart := (reserved + 2*sectorsPerFAT) * 512
	boot[dataStart+uint64(100-2)*512] = 1
}

func fixtureBootFAT(fixture *fullMediaFixture) []byte {
	partition := fixture.plan.Layout.Partitions[0]
	return fixture.media[partition.OffsetBytes : partition.OffsetBytes+partition.SizeBytes]
}

func addFATBootCode(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	boot[90] = 1
	backupSector := uint64(binary.LittleEndian.Uint16(boot[50:52]))
	boot[backupSector*SectorSizeBytes+90] = 1
}

func addFATReservedSectorData(fixture *fullMediaFixture) {
	fixtureBootFAT(fixture)[2*SectorSizeBytes] = 1
}

func changeFATFSInfoPayload(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	fsInfoSector := uint64(binary.LittleEndian.Uint16(boot[48:50]))
	boot[fsInfoSector*SectorSizeBytes+16] = 1
}

func mutateFATEntryCopies(fixture *fullMediaFixture, cluster, value uint32) {
	boot := fixtureBootFAT(fixture)
	reserved := uint64(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := uint64(binary.LittleEndian.Uint32(boot[36:40]))
	for copyIndex := uint64(0); copyIndex < 2; copyIndex++ {
		offset := (reserved+copyIndex*sectorsPerFAT)*SectorSizeBytes + uint64(cluster)*4
		binary.LittleEndian.PutUint32(boot[offset:offset+4], value)
	}
}

func changeFATEntryHighNibble(fixture *fullMediaFixture) {
	mutateFATEntryCopies(fixture, 3, 0x1fffffff)
}

func addFATTableTailData(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	totalSectors := binary.LittleEndian.Uint32(boot[32:36])
	reserved := uint32(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := binary.LittleEndian.Uint32(boot[36:40])
	sectorsPerCluster := uint32(boot[13])
	clusterCount := (totalSectors - reserved - 2*sectorsPerFAT) / sectorsPerCluster
	mutateFATEntryCopies(fixture, clusterCount+2, 1)
}

func rootDirectoryOffset(fixture *fullMediaFixture) uint64 {
	boot := fixtureBootFAT(fixture)
	reserved := uint64(binary.LittleEndian.Uint16(boot[14:16]))
	sectorsPerFAT := uint64(binary.LittleEndian.Uint32(boot[36:40]))
	return (reserved + 2*sectorsPerFAT) * SectorSizeBytes
}

func changeFATDirectoryMetadata(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	boot[rootDirectoryOffset(fixture)+32+13] = 1
}

func changeFATLongNamePadding(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	// The first long-name slot follows the volume label and three short entries.
	// Its final UTF-16 code unit is canonical 0xffff padding after the terminator.
	paddingOffset := rootDirectoryOffset(fixture) + 4*32 + 30
	boot[paddingOffset], boot[paddingOffset+1] = 0, 0
}

func addFATLongNameEntry(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	rootOffset := rootDirectoryOffset(fixture)
	root := boot[rootOffset : rootOffset+SectorSizeBytes]
	// Shift the two canonical LFN entries and their short entry one slot right,
	// then prepend a third, semantically redundant all-padding LFN entry.
	copy(root[5*32:8*32], root[4*32:7*32])
	root[5*32] &^= 0x40
	extra := root[4*32 : 5*32]
	for index := range extra {
		extra[index] = 0
	}
	extra[0] = 0x43
	extra[11] = 0x0f
	extra[13] = lfnChecksum([]byte(canonicalFATShortNames["kaiba-media-binding.json"]))
	for _, bounds := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for index := bounds[0]; index < bounds[1]; index += 2 {
			binary.LittleEndian.PutUint16(extra[index:index+2], 0xffff)
		}
	}
}

func addFATDirectoryEndMarkerMetadata(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	// The canonical root has one label, three short entries, two LFN entries,
	// and the binding short entry before its all-zero end marker.
	boot[rootDirectoryOffset(fixture)+7*32+1] = 1
}

func changeFATEndOfChainMarker(fixture *fullMediaFixture) {
	mutateFATEntryCopies(fixture, 3, 0x0ffffff8)
}

func reorderFATDirectoryEntries(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	rootOffset := rootDirectoryOffset(fixture)
	first := append([]byte(nil), boot[rootOffset+32:rootOffset+64]...)
	copy(boot[rootOffset+32:rootOffset+64], boot[rootOffset+64:rootOffset+96])
	copy(boot[rootOffset+64:rootOffset+96], first)
}

func swapFATFileClusters(fixture *fullMediaFixture) {
	boot := fixtureBootFAT(fixture)
	rootOffset := rootDirectoryOffset(fixture)
	binary.LittleEndian.PutUint16(boot[rootOffset+32+26:rootOffset+32+28], 4)
	binary.LittleEndian.PutUint16(boot[rootOffset+64+26:rootOffset+64+28], 3)
	cluster3 := rootOffset + SectorSizeBytes
	cluster4 := cluster3 + SectorSizeBytes
	temporary := append([]byte(nil), boot[cluster3:cluster3+SectorSizeBytes]...)
	copy(boot[cluster3:cluster3+SectorSizeBytes], boot[cluster4:cluster4+SectorSizeBytes])
	copy(boot[cluster4:cluster4+SectorSizeBytes], temporary)
}

func rebindChangedRegion(t *testing.T, plan Plan, media []byte, role RegionRole) Plan {
	t.Helper()
	layout := plan.Layout
	layout.Regions = append([]MediaRegion(nil), layout.Regions...)
	layout.Sources = append([]SourceBinding(nil), layout.Sources...)
	layout.Partitions = append([]GPTPartition(nil), layout.Partitions...)
	for index := range layout.Regions {
		region := &layout.Regions[index]
		if region.Role != role {
			continue
		}
		region.ContentDigest = sumBytes(media[region.OffsetBytes : region.OffsetBytes+region.SizeBytes])
		switch role {
		case RegionPrimaryGPT:
			layout.Payloads.PrimaryGPT.Digest = region.ContentDigest
			layout.Sources[0].Digest, region.SourceDigest = region.ContentDigest, region.ContentDigest
		case RegionBootFilesystem:
			layout.Payloads.OuterBootFAT.Digest = region.ContentDigest
			layout.Sources[1].Digest, region.SourceDigest = region.ContentDigest, region.ContentDigest
			layout.Partitions[0].UsedDigest, layout.Partitions[0].PartitionDigest = region.ContentDigest, region.ContentDigest
		case RegionRootData:
			layout.Partitions[1].PartitionDigest = region.ContentDigest
		case RegionRootHash:
			layout.Partitions[2].PartitionDigest = region.ContentDigest
		case RegionBackupGPT:
			layout.Payloads.BackupGPT.Digest = region.ContentDigest
			layout.Sources[4].Digest, region.SourceDigest = region.ContentDigest, region.ContentDigest
		}
	}
	layout.LayoutDigest = ""
	var err error
	layout, err = layout.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Layout = layout
	plan.ExpectedMediaDigest = sumBytes(media)
	plan.PlanDigest = ""
	plan, err = plan.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
