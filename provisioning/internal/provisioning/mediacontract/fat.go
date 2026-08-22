package mediacontract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

const maximumFATBytes = 64 * 1024 * 1024
const maximumVerifiedBootImageBytes = 128 * 1024 * 1024
const maximumVerifiedBootSignatureBytes = 4 * 1024

const (
	canonicalFATReservedSectors = uint32(32)
	canonicalFATRootCluster     = uint32(2)
	canonicalFATFSInfoSector    = uint16(1)
	canonicalFATBackupSector    = uint16(6)
	canonicalFATEndOfChain      = uint32(0x0fffffff)
	canonicalFATDate            = uint16(0x0021) // 1980-01-01, FAT's first representable date.
)

var canonicalFATShortNames = map[string]string{
	"boot.img":                 "BOOT    IMG",
	"boot.sig":                 "BOOT    SIG",
	"config.txt":               "CONFIG  TXT",
	"kaiba-media-binding.json": "KAIBA-~1JSO",
}

// VerifiedBootFiles are the exact allowlisted bytes independently recovered
// from the staged outer FAT after its complete structural verification.
type VerifiedBootFiles struct {
	BootImage     []byte
	BootSignature []byte
	MediaBinding  []byte
}

type fat32View struct {
	target            io.ReaderAt
	partition         GPTPartition
	bytesPerSector    uint32
	sectorsPerCluster uint32
	reservedSectors   uint32
	fatCount          uint32
	sectorsPerFAT     uint32
	totalSectors      uint32
	rootCluster       uint32
	dataStartSector   uint32
	clusterCount      uint32
	fat               []byte
}

type fatDirectoryEntry struct {
	name         string
	attributes   byte
	firstCluster uint32
	sizeBytes    uint32
}

type rawLFNEntry struct {
	ordinal  byte
	checksum byte
	units    []uint16
}

func verifyFAT32(ctx context.Context, target io.ReaderAt, partition GPTPartition, contract FATContract) (VerifiedBootFiles, error) {
	view, err := parseFAT32(ctx, target, partition, contract)
	if err != nil {
		return VerifiedBootFiles{}, err
	}
	entries, rootClusters, err := view.readRootDirectory(ctx, contract.Label)
	if err != nil {
		return VerifiedBootFiles{}, err
	}
	if len(entries) != len(contract.Allowlist) {
		return VerifiedBootFiles{}, fmt.Errorf("FAT root contains %d regular files, expected %d", len(entries), len(contract.Allowlist))
	}
	if len(rootClusters) != 1 || rootClusters[0] != canonicalFATRootCluster || view.rawFATEntry(canonicalFATRootCluster) != canonicalFATEndOfChain {
		return VerifiedBootFiles{}, errors.New("FAT root directory does not use the one canonical cluster")
	}
	byName := make(map[string]fatDirectoryEntry, len(entries))
	for index, entry := range entries {
		if entry.name != contract.Allowlist[index].Path {
			return VerifiedBootFiles{}, errors.New("FAT root entries are not in canonical allowlist order")
		}
		if _, duplicate := byName[entry.name]; duplicate {
			return VerifiedBootFiles{}, fmt.Errorf("FAT root contains duplicate file %q", entry.name)
		}
		byName[entry.name] = entry
	}
	usedClusters := make(map[uint32]struct{}, len(rootClusters)+len(entries))
	for _, cluster := range rootClusters {
		usedClusters[cluster] = struct{}{}
	}
	nextCanonicalCluster := canonicalFATRootCluster + 1
	for _, expected := range contract.Allowlist {
		entry, ok := byName[expected.Path]
		if !ok {
			return VerifiedBootFiles{}, fmt.Errorf("FAT root is missing %q", expected.Path)
		}
		if uint64(entry.sizeBytes) != expected.SizeBytes {
			return VerifiedBootFiles{}, fmt.Errorf("FAT file %q size is %d, expected %d", expected.Path, entry.sizeBytes, expected.SizeBytes)
		}
		digest, clusters, err := view.hashFile(ctx, entry)
		if err != nil {
			return VerifiedBootFiles{}, fmt.Errorf("FAT file %q: %w", expected.Path, err)
		}
		if digest != expected.Digest {
			return VerifiedBootFiles{}, fmt.Errorf("FAT file %q digest is %s, expected %s", expected.Path, digest, expected.Digest)
		}
		for index, cluster := range clusters {
			if cluster != nextCanonicalCluster {
				return VerifiedBootFiles{}, fmt.Errorf("FAT file %q does not use its canonical contiguous clusters", expected.Path)
			}
			wantedNext := canonicalFATEndOfChain
			if index+1 < len(clusters) {
				wantedNext = cluster + 1
			}
			if view.rawFATEntry(cluster) != wantedNext {
				return VerifiedBootFiles{}, fmt.Errorf("FAT file %q has a non-canonical allocation chain", expected.Path)
			}
			if _, duplicate := usedClusters[cluster]; duplicate {
				return VerifiedBootFiles{}, fmt.Errorf("FAT cluster %d is shared by multiple root objects", cluster)
			}
			usedClusters[cluster] = struct{}{}
			nextCanonicalCluster++
		}
	}
	for cluster := uint32(2); cluster < view.clusterCount+2; cluster++ {
		allocated := view.fatEntry(cluster) != 0
		_, referenced := usedClusters[cluster]
		if allocated != referenced {
			return VerifiedBootFiles{}, fmt.Errorf("FAT cluster %d allocation is not exactly referenced by the allowlist", cluster)
		}
	}
	clusterBytes := uint64(view.sectorsPerCluster) * uint64(view.bytesPerSector)
	var freeStart uint32
	flushFree := func(end uint32) error {
		if freeStart == 0 {
			return nil
		}
		offset, err := view.clusterOffset(freeStart)
		if err != nil {
			return err
		}
		size := uint64(end-freeStart) * clusterBytes
		freeStart = 0
		return verifyZeroRange(ctx, view.target, offset, size)
	}
	for cluster := uint32(2); cluster < view.clusterCount+2; cluster++ {
		if _, used := usedClusters[cluster]; !used {
			if freeStart == 0 {
				freeStart = cluster
			}
			continue
		}
		if err := flushFree(cluster); err != nil {
			return VerifiedBootFiles{}, fmt.Errorf("FAT unallocated data clusters are not zero: %w", err)
		}
	}
	if err := flushFree(view.clusterCount + 2); err != nil {
		return VerifiedBootFiles{}, fmt.Errorf("FAT unallocated data clusters are not zero: %w", err)
	}
	bootImage, err := view.readFile(ctx, byName["boot.img"], maximumVerifiedBootImageBytes)
	if err != nil {
		return VerifiedBootFiles{}, fmt.Errorf("read FAT boot image: %w", err)
	}
	bootSignature, err := view.readFile(ctx, byName["boot.sig"], maximumVerifiedBootSignatureBytes)
	if err != nil {
		return VerifiedBootFiles{}, fmt.Errorf("read FAT boot signature: %w", err)
	}
	binding, err := view.readFile(ctx, byName["kaiba-media-binding.json"], MaximumMediaBindingBytes)
	if err != nil {
		return VerifiedBootFiles{}, fmt.Errorf("read FAT media binding: %w", err)
	}
	return VerifiedBootFiles{BootImage: bootImage, BootSignature: bootSignature, MediaBinding: binding}, nil
}

func parseFAT32(ctx context.Context, target io.ReaderAt, partition GPTPartition, contract FATContract) (fat32View, error) {
	if ctx == nil {
		return fat32View{}, errors.New("FAT32 verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return fat32View{}, err
	}
	boot := make([]byte, SectorSizeBytes)
	if err := readExact(target, partition.OffsetBytes, boot); err != nil {
		return fat32View{}, fmt.Errorf("read FAT boot sector: %w", err)
	}
	if !bytes.Equal(boot[0:3], []byte{0xeb, 0x58, 0x90}) || string(boot[3:11]) != "KAIBA   " || boot[510] != 0x55 || boot[511] != 0xaa {
		return fat32View{}, errors.New("FAT32 jump, OEM name, or boot signature differs from the canonical profile")
	}
	bytesPerSector := uint32(binary.LittleEndian.Uint16(boot[11:13]))
	sectorsPerCluster := uint32(boot[13])
	reserved := uint32(binary.LittleEndian.Uint16(boot[14:16]))
	fatCount := uint32(boot[16])
	rootEntries := binary.LittleEndian.Uint16(boot[17:19])
	total16 := uint32(binary.LittleEndian.Uint16(boot[19:21]))
	fat16 := binary.LittleEndian.Uint16(boot[22:24])
	total32 := binary.LittleEndian.Uint32(boot[32:36])
	fat32Sectors := binary.LittleEndian.Uint32(boot[36:40])
	extFlags := binary.LittleEndian.Uint16(boot[40:42])
	version := binary.LittleEndian.Uint16(boot[42:44])
	rootCluster := binary.LittleEndian.Uint32(boot[44:48])
	fsInfoSector := binary.LittleEndian.Uint16(boot[48:50])
	backupSector := binary.LittleEndian.Uint16(boot[50:52])
	if bytesPerSector != uint32(SectorSizeBytes) || sectorsPerCluster != 1 || reserved != canonicalFATReservedSectors || fatCount != 2 || rootEntries != 0 || total16 != 0 || boot[21] != 0xf8 || fat16 != 0 || binary.LittleEndian.Uint16(boot[24:26]) != 32 || binary.LittleEndian.Uint16(boot[26:28]) != 8 || binary.LittleEndian.Uint32(boot[28:32]) != 0 || fat32Sectors == 0 || extFlags != 0 || version != 0 || rootCluster != canonicalFATRootCluster || fsInfoSector != canonicalFATFSInfoSector || backupSector != canonicalFATBackupSector {
		return fat32View{}, errors.New("FAT32 BPB differs from the closed two-FAT geometry")
	}
	if !allZero(boot[52:64]) || boot[64] != 0x80 || boot[65] != 0 || boot[66] != 0x29 || !allZero(boot[90:510]) {
		return fat32View{}, errors.New("FAT32 reserved or boot-code bytes differ from the zero-normalized profile")
	}
	if uint64(total32)*uint64(bytesPerSector) != partition.SizeBytes {
		return fat32View{}, errors.New("FAT32 BPB size differs from the GPT boot partition")
	}
	if string(boot[82:90]) != "FAT32   " || strings.TrimRight(string(boot[71:82]), " ") != contract.Label {
		return fat32View{}, errors.New("FAT32 type marker or volume label differs from the contract")
	}
	volumeID, err := strconv.ParseUint(contract.VolumeID, 16, 32)
	if err != nil || binary.LittleEndian.Uint32(boot[67:71]) != uint32(volumeID) {
		return fat32View{}, errors.New("FAT32 volume ID differs from the contract")
	}
	backupBoot := make([]byte, SectorSizeBytes)
	if err := readExact(target, partition.OffsetBytes+uint64(backupSector)*uint64(bytesPerSector), backupBoot); err != nil {
		return fat32View{}, fmt.Errorf("read FAT32 backup boot sector: %w", err)
	}
	if !bytes.Equal(boot, backupBoot) {
		return fat32View{}, errors.New("FAT32 primary and backup boot sectors differ")
	}
	for _, span := range []struct {
		start uint64
		count uint64
	}{{2, 4}, {8, uint64(reserved) - 8}} {
		if err := verifyZeroRange(ctx, target, partition.OffsetBytes+span.start*uint64(bytesPerSector), span.count*uint64(bytesPerSector)); err != nil {
			return fat32View{}, fmt.Errorf("FAT32 unused reserved sectors are not zero: %w", err)
		}
	}
	canonicalFSInfo := make([]byte, SectorSizeBytes)
	binary.LittleEndian.PutUint32(canonicalFSInfo[0:4], 0x41615252)
	binary.LittleEndian.PutUint32(canonicalFSInfo[484:488], 0x61417272)
	binary.LittleEndian.PutUint32(canonicalFSInfo[488:492], 0xffffffff)
	binary.LittleEndian.PutUint32(canonicalFSInfo[492:496], 0xffffffff)
	binary.LittleEndian.PutUint32(canonicalFSInfo[508:512], 0xaa550000)
	for label, sector := range map[string]uint16{"primary": fsInfoSector, "backup": backupSector + 1} {
		fsInfo := make([]byte, SectorSizeBytes)
		if err := readExact(target, partition.OffsetBytes+uint64(sector)*uint64(bytesPerSector), fsInfo); err != nil {
			return fat32View{}, fmt.Errorf("read %s FAT32 FSInfo sector: %w", label, err)
		}
		if !bytes.Equal(fsInfo, canonicalFSInfo) {
			return fat32View{}, fmt.Errorf("%s FAT32 FSInfo sector differs from the canonical unknown-count, zero-reserved profile", label)
		}
	}
	metadataSectors64 := uint64(reserved) + uint64(fatCount)*uint64(fat32Sectors)
	if metadataSectors64 >= uint64(total32) || metadataSectors64 > uint64(^uint32(0)) {
		return fat32View{}, errors.New("FAT32 metadata consumes the whole partition")
	}
	metadataSectors := uint32(metadataSectors64)
	dataSectors := total32 - metadataSectors
	clusterCount := dataSectors / sectorsPerCluster
	if clusterCount < 65525 || clusterCount > 0x0ffffff5 || rootCluster >= clusterCount+2 {
		return fat32View{}, errors.New("FAT32 data-cluster count is outside the FAT32 range")
	}
	requiredFATSectors := (uint64(clusterCount+2)*4 + uint64(bytesPerSector) - 1) / uint64(bytesPerSector)
	if uint64(fat32Sectors) != requiredFATSectors {
		return fat32View{}, errors.New("FAT32 allocation table does not use the canonical minimal geometry")
	}
	fatBytes := uint64(fat32Sectors) * uint64(bytesPerSector)
	if fatBytes > maximumFATBytes || fatBytes/4 < uint64(clusterCount+2) {
		return fat32View{}, errors.New("FAT32 allocation table is unbounded or too small")
	}
	first := make([]byte, int(fatBytes))
	second := make([]byte, int(fatBytes))
	firstOffset := partition.OffsetBytes + uint64(reserved)*uint64(bytesPerSector)
	if err := readExact(target, firstOffset, first); err != nil {
		return fat32View{}, fmt.Errorf("read first FAT: %w", err)
	}
	if err := readExact(target, firstOffset+fatBytes, second); err != nil {
		return fat32View{}, fmt.Errorf("read second FAT: %w", err)
	}
	if !bytes.Equal(first, second) {
		return fat32View{}, errors.New("FAT32 allocation-table copies differ")
	}
	if binary.LittleEndian.Uint32(first[:4]) != 0x0ffffff8 || binary.LittleEndian.Uint32(first[4:8]) != canonicalFATEndOfChain {
		return fat32View{}, errors.New("FAT32 reserved entries are invalid")
	}
	for cluster := uint32(2); cluster < clusterCount+2; cluster++ {
		if binary.LittleEndian.Uint32(first[cluster*4:cluster*4+4])&0xf0000000 != 0 {
			return fat32View{}, fmt.Errorf("FAT32 entry %d has non-zero reserved high bits", cluster)
		}
	}
	if !allZero(first[uint64(clusterCount+2)*4:]) {
		return fat32View{}, errors.New("FAT32 allocation-table tail is not zero")
	}
	if err := verifyFATDataTail(ctx, target, partition, bytesPerSector, total32, metadataSectors, sectorsPerCluster, clusterCount); err != nil {
		return fat32View{}, err
	}
	return fat32View{
		target: target, partition: partition, bytesPerSector: bytesPerSector,
		sectorsPerCluster: sectorsPerCluster, reservedSectors: reserved,
		fatCount: fatCount, sectorsPerFAT: fat32Sectors, totalSectors: total32,
		rootCluster: rootCluster, dataStartSector: metadataSectors,
		clusterCount: clusterCount, fat: first,
	}, nil
}

func verifyFATDataTail(ctx context.Context, target io.ReaderAt, partition GPTPartition, bytesPerSector, totalSectors, metadataSectors, sectorsPerCluster, clusterCount uint32) error {
	if metadataSectors > totalSectors || bytesPerSector == 0 || sectorsPerCluster == 0 {
		return errors.New("FAT32 trailing-data geometry is invalid")
	}
	usedDataSectors := uint64(clusterCount) * uint64(sectorsPerCluster)
	dataSectors := uint64(totalSectors) - uint64(metadataSectors)
	if usedDataSectors > dataSectors {
		return errors.New("FAT32 cluster geometry exceeds its data sectors")
	}
	trailingSectors := dataSectors - usedDataSectors
	if trailingSectors == 0 {
		return nil
	}
	offset := partition.OffsetBytes + (uint64(metadataSectors)+usedDataSectors)*uint64(bytesPerSector)
	if err := verifyZeroRange(ctx, target, offset, trailingSectors*uint64(bytesPerSector)); err != nil {
		return fmt.Errorf("FAT32 trailing non-cluster data sectors are not zero: %w", err)
	}
	return nil
}

func (view fat32View) fatEntry(cluster uint32) uint32 {
	return view.rawFATEntry(cluster) & 0x0fffffff
}

func (view fat32View) rawFATEntry(cluster uint32) uint32 {
	offset := uint64(cluster) * 4
	if offset+4 > uint64(len(view.fat)) {
		return 0x0ffffff7
	}
	return binary.LittleEndian.Uint32(view.fat[offset : offset+4])
}

func (view fat32View) clusterOffset(cluster uint32) (uint64, error) {
	if cluster < 2 || cluster >= view.clusterCount+2 {
		return 0, fmt.Errorf("cluster %d is out of range", cluster)
	}
	sector := uint64(view.dataStartSector) + uint64(cluster-2)*uint64(view.sectorsPerCluster)
	offset := view.partition.OffsetBytes + sector*uint64(view.bytesPerSector)
	clusterBytes := uint64(view.sectorsPerCluster) * uint64(view.bytesPerSector)
	if offset < view.partition.OffsetBytes || offset+clusterBytes > view.partition.OffsetBytes+view.partition.SizeBytes {
		return 0, errors.New("cluster range exceeds the FAT partition")
	}
	return offset, nil
}

func (view fat32View) clusterChain(start uint32) ([]uint32, error) {
	if start < 2 || start >= view.clusterCount+2 {
		return nil, errors.New("cluster chain has an invalid start")
	}
	seen := make(map[uint32]struct{})
	chain := make([]uint32, 0, 4)
	current := start
	for {
		if _, duplicate := seen[current]; duplicate {
			return nil, errors.New("cluster chain contains a loop")
		}
		if current < 2 || current >= view.clusterCount+2 {
			return nil, errors.New("cluster chain escapes the data area")
		}
		seen[current] = struct{}{}
		chain = append(chain, current)
		next := view.fatEntry(current)
		switch {
		case next >= 0x0ffffff8:
			return chain, nil
		case next == 0:
			return nil, errors.New("allocated cluster chain terminates in a free cluster")
		case next == 1 || next == 0x0ffffff7 || next >= 0x0ffffff0:
			return nil, errors.New("cluster chain contains a reserved or bad cluster")
		default:
			current = next
		}
		if uint32(len(chain)) > view.clusterCount {
			return nil, errors.New("cluster chain exceeds the filesystem")
		}
	}
}

func (view fat32View) readRootDirectory(ctx context.Context, expectedLabel string) ([]fatDirectoryEntry, []uint32, error) {
	chain, err := view.clusterChain(view.rootCluster)
	if err != nil {
		return nil, nil, fmt.Errorf("root directory chain: %w", err)
	}
	clusterBytes := int(view.sectorsPerCluster * view.bytesPerSector)
	entries := make([]fatDirectoryEntry, 0, 4)
	pendingLFN := make([]rawLFNEntry, 0, 4)
	labelCount := 0
	terminated := false
	for _, cluster := range chain {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		offset, err := view.clusterOffset(cluster)
		if err != nil {
			return nil, nil, err
		}
		data := make([]byte, clusterBytes)
		if err := readExact(view.target, offset, data); err != nil {
			return nil, nil, err
		}
		for index := 0; index < len(data); index += 32 {
			raw := data[index : index+32]
			if terminated {
				if !allZero(raw) {
					return nil, nil, errors.New("FAT directory contains data after its end marker")
				}
				continue
			}
			if raw[0] == 0x00 {
				if len(pendingLFN) != 0 {
					return nil, nil, errors.New("FAT directory ends in an incomplete long filename")
				}
				if !allZero(raw) {
					return nil, nil, errors.New("FAT directory end marker contains hidden metadata")
				}
				terminated = true
				continue
			}
			if raw[0] == 0xe5 {
				return nil, nil, errors.New("FAT directory contains a deleted entry")
			}
			if raw[11] == 0x0f {
				lfn, err := parseLFNEntry(raw)
				if err != nil {
					return nil, nil, err
				}
				pendingLFN = append(pendingLFN, lfn)
				continue
			}
			attributes := raw[11]
			if attributes&0x08 != 0 {
				if len(pendingLFN) != 0 || labelCount != 0 || len(entries) != 0 || !isCanonicalFATVolumeLabel(raw, expectedLabel) {
					return nil, nil, errors.New("FAT volume-label entry is malformed")
				}
				labelCount++
				continue
			}
			if attributes != 0x20 {
				return nil, nil, errors.New("FAT root contains a directory or unsupported file attributes")
			}
			longNameEntries := len(pendingLFN)
			name, err := resolveFATName(raw[:11], pendingLFN)
			if err != nil {
				return nil, nil, err
			}
			pendingLFN = pendingLFN[:0]
			cluster := uint32(binary.LittleEndian.Uint16(raw[26:28])) | uint32(binary.LittleEndian.Uint16(raw[20:22]))<<16
			size := binary.LittleEndian.Uint32(raw[28:32])
			if size == 0 || cluster < 2 {
				return nil, nil, fmt.Errorf("FAT file %q must be non-empty and allocated", name)
			}
			if err := validateCanonicalFATFileEntry(raw, name, longNameEntries, cluster, size); err != nil {
				return nil, nil, err
			}
			entries = append(entries, fatDirectoryEntry{name: name, attributes: attributes, firstCluster: cluster, sizeBytes: size})
		}
	}
	if len(pendingLFN) != 0 || !terminated || labelCount != 1 {
		return nil, nil, errors.New("FAT root lacks one exact label/end marker or has an incomplete long filename")
	}
	return entries, chain, nil
}

func isCanonicalFATVolumeLabel(raw []byte, expectedLabel string) bool {
	if len(raw) != 32 || len(expectedLabel) > 11 {
		return false
	}
	expected := make([]byte, 32)
	for index := 0; index < 11; index++ {
		expected[index] = ' '
	}
	copy(expected[:11], expectedLabel)
	expected[11] = 0x08
	binary.LittleEndian.PutUint16(expected[16:18], canonicalFATDate)
	binary.LittleEndian.PutUint16(expected[18:20], canonicalFATDate)
	binary.LittleEndian.PutUint16(expected[24:26], canonicalFATDate)
	return bytes.Equal(raw, expected)
}

func validateCanonicalFATFileEntry(raw []byte, name string, longNameEntries int, firstCluster, size uint32) error {
	short, known := canonicalFATShortNames[name]
	if !known {
		// An unknown entry will fail the closed allowlist/count check. Keeping that
		// diagnostic distinct makes an accidental extra file easier to identify.
		return nil
	}
	wantsLongName := name == "kaiba-media-binding.json"
	expectedLongNameEntries := 0
	if wantsLongName {
		expectedLongNameEntries = (len(utf16.Encode([]rune(name))) + 1 + 12) / 13
	}
	if longNameEntries != expectedLongNameEntries {
		return fmt.Errorf("FAT file %q does not use its canonical short/long-name form", name)
	}
	expected := make([]byte, 32)
	copy(expected[:11], short)
	expected[11] = 0x20
	if !wantsLongName {
		expected[12] = 0x18 // lowercase base and extension in the FAT NT-reserved field.
	}
	binary.LittleEndian.PutUint16(expected[16:18], canonicalFATDate)
	binary.LittleEndian.PutUint16(expected[18:20], canonicalFATDate)
	binary.LittleEndian.PutUint16(expected[20:22], uint16(firstCluster>>16))
	binary.LittleEndian.PutUint16(expected[24:26], canonicalFATDate)
	binary.LittleEndian.PutUint16(expected[26:28], uint16(firstCluster))
	binary.LittleEndian.PutUint32(expected[28:32], size)
	if !bytes.Equal(raw, expected) {
		return fmt.Errorf("FAT file %q directory metadata differs from the canonical alias, attributes, or 1980-01-01 timestamp profile", name)
	}
	return nil
}

func parseLFNEntry(raw []byte) (rawLFNEntry, error) {
	if len(raw) != 32 || raw[11] != 0x0f || raw[12] != 0 || binary.LittleEndian.Uint16(raw[26:28]) != 0 {
		return rawLFNEntry{}, errors.New("FAT long-filename entry is malformed")
	}
	ordinal := raw[0]
	if ordinal&0x1f == 0 || ordinal&0xa0 != 0 {
		return rawLFNEntry{}, errors.New("FAT long-filename ordinal is invalid")
	}
	units := make([]uint16, 0, 13)
	for _, bounds := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for index := bounds[0]; index < bounds[1]; index += 2 {
			units = append(units, binary.LittleEndian.Uint16(raw[index:index+2]))
		}
	}
	return rawLFNEntry{ordinal: ordinal, checksum: raw[13], units: units}, nil
}

func resolveFATName(short []byte, long []rawLFNEntry) (string, error) {
	if len(short) != 11 {
		return "", errors.New("FAT short name has the wrong size")
	}
	if len(long) == 0 {
		return shortFATName(short)
	}
	expectedChecksum := lfnChecksum(short)
	count := int(long[0].ordinal & 0x1f)
	if long[0].ordinal&0x40 == 0 || count != len(long) {
		return "", errors.New("FAT long-filename sequence lacks one canonical last entry")
	}
	ordered := make([][]uint16, count)
	for index, entry := range long {
		expectedOrdinal := count - index
		if int(entry.ordinal&0x1f) != expectedOrdinal || index > 0 && entry.ordinal&0x40 != 0 || entry.checksum != expectedChecksum {
			return "", errors.New("FAT long-filename sequence or checksum is invalid")
		}
		ordered[expectedOrdinal-1] = entry.units
	}
	units := make([]uint16, 0, count*13)
	terminated := false
	for _, part := range ordered {
		for _, unit := range part {
			switch {
			case unit == 0:
				if terminated {
					return "", errors.New("FAT long filename has more than one terminator")
				}
				terminated = true
			case unit == 0xffff:
				if !terminated {
					return "", errors.New("FAT long filename has padding before its terminator")
				}
			default:
				if terminated {
					return "", errors.New("FAT long filename has data after its terminator")
				}
				units = append(units, unit)
			}
		}
	}
	if !terminated {
		return "", errors.New("FAT long filename is not terminated")
	}
	runes := utf16.Decode(units)
	if len(runes) == 0 {
		return "", errors.New("FAT long filename is empty")
	}
	for _, character := range runes {
		if character < 0x21 || character > 0x7e || strings.ContainsRune(`"*/:<>?\\|`, character) {
			return "", errors.New("FAT long filename is not canonical printable ASCII")
		}
	}
	return string(runes), nil
}

func shortFATName(raw []byte) (string, error) {
	base := strings.TrimRight(string(raw[:8]), " ")
	extension := strings.TrimRight(string(raw[8:11]), " ")
	if base == "" {
		return "", errors.New("FAT short filename has an empty base")
	}
	for _, character := range base + extension {
		if character < 0x21 || character > 0x7e {
			return "", errors.New("FAT short filename is not printable ASCII")
		}
	}
	name := strings.ToLower(base)
	if extension != "" {
		name += "." + strings.ToLower(extension)
	}
	return name, nil
}

func lfnChecksum(short []byte) byte {
	var sum byte
	for _, value := range short {
		sum = (sum>>1 | sum<<7) + value
	}
	return sum
}

func (view fat32View) hashFile(ctx context.Context, entry fatDirectoryEntry) (Digest, []uint32, error) {
	chain, err := view.clusterChain(entry.firstCluster)
	if err != nil {
		return "", nil, err
	}
	clusterBytes := uint64(view.sectorsPerCluster) * uint64(view.bytesPerSector)
	expectedClusters := (uint64(entry.sizeBytes) + clusterBytes - 1) / clusterBytes
	if uint64(len(chain)) != expectedClusters {
		return "", nil, errors.New("cluster chain length does not match the file size")
	}
	hash := sha256.New()
	remaining := uint64(entry.sizeBytes)
	for _, cluster := range chain {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		offset, err := view.clusterOffset(cluster)
		if err != nil {
			return "", nil, err
		}
		chunk := clusterBytes
		if chunk > remaining {
			chunk = remaining
		}
		buffer := make([]byte, int(chunk))
		if err := readExact(view.target, offset, buffer); err != nil {
			return "", nil, err
		}
		_, _ = hash.Write(buffer)
		if chunk < clusterBytes {
			if err := verifyZeroRange(ctx, view.target, offset+chunk, clusterBytes-chunk); err != nil {
				return "", nil, fmt.Errorf("file slack is not zero: %w", err)
			}
		}
		remaining -= chunk
	}
	if remaining != 0 {
		return "", nil, io.ErrUnexpectedEOF
	}
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), chain, nil
}

func (view fat32View) readFile(ctx context.Context, entry fatDirectoryEntry, maximum uint64) ([]byte, error) {
	if uint64(entry.sizeBytes) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	chain, err := view.clusterChain(entry.firstCluster)
	if err != nil {
		return nil, err
	}
	clusterBytes := uint64(view.sectorsPerCluster) * uint64(view.bytesPerSector)
	expectedClusters := (uint64(entry.sizeBytes) + clusterBytes - 1) / clusterBytes
	if uint64(len(chain)) != expectedClusters {
		return nil, errors.New("cluster chain length does not match the file size")
	}
	result := make([]byte, 0, entry.sizeBytes)
	remaining := uint64(entry.sizeBytes)
	for _, cluster := range chain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		offset, err := view.clusterOffset(cluster)
		if err != nil {
			return nil, err
		}
		chunk := clusterBytes
		if chunk > remaining {
			chunk = remaining
		}
		buffer := make([]byte, int(chunk))
		if err := readExact(view.target, offset, buffer); err != nil {
			return nil, err
		}
		result = append(result, buffer...)
		remaining -= chunk
	}
	if remaining != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return result, nil
}
