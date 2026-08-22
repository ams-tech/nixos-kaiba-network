package mediacontract

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

const (
	gptHeaderSize        = 92
	gptEntryCount        = 128
	gptEntrySize         = 128
	gptEntryArrayBytes   = gptEntryCount * gptEntrySize
	gptEntryArraySectors = uint64(gptEntryArrayBytes) / SectorSizeBytes
)

type parsedGPTHeader struct {
	currentLBA     uint64
	backupLBA      uint64
	firstUsableLBA uint64
	lastUsableLBA  uint64
	diskGUID       string
	entriesLBA     uint64
	entryCount     uint32
	entrySize      uint32
	entriesCRC     uint32
}

func verifyGPT(ctx context.Context, target io.ReaderAt, sizeBytes uint64, layout Layout) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	totalLBAs := sizeBytes / SectorSizeBytes
	if totalLBAs < 68 {
		return errors.New("target is too small for primary and backup GPT")
	}
	mbr := make([]byte, SectorSizeBytes)
	if err := readExact(target, 0, mbr); err != nil {
		return fmt.Errorf("read protective MBR: %w", err)
	}
	if err := verifyProtectiveMBR(mbr, totalLBAs); err != nil {
		return err
	}
	primary, err := parseGPTHeader(target, 1, totalLBAs)
	if err != nil {
		return fmt.Errorf("primary header: %w", err)
	}
	backup, err := parseGPTHeader(target, totalLBAs-1, totalLBAs)
	if err != nil {
		return fmt.Errorf("backup header: %w", err)
	}
	if primary.currentLBA != 1 || primary.backupLBA != totalLBAs-1 || primary.entriesLBA != 2 ||
		backup.currentLBA != totalLBAs-1 || backup.backupLBA != 1 || backup.entriesLBA != totalLBAs-1-gptEntryArraySectors {
		return errors.New("GPT primary/backup header locations are not canonical")
	}
	for label, header := range map[string]parsedGPTHeader{"primary": primary, "backup": backup} {
		if header.firstUsableLBA != layout.FirstUsableLBA || header.lastUsableLBA != layout.LastUsableLBA || header.diskGUID != layout.DiskGUID || header.entryCount != gptEntryCount || header.entrySize != gptEntrySize {
			return fmt.Errorf("%s GPT header differs from the frozen layout", label)
		}
	}
	primaryEntries, err := readGPTEntries(target, primary)
	if err != nil {
		return fmt.Errorf("primary entries: %w", err)
	}
	backupEntries, err := readGPTEntries(target, backup)
	if err != nil {
		return fmt.Errorf("backup entries: %w", err)
	}
	if !bytes.Equal(primaryEntries, backupEntries) {
		return errors.New("primary and backup GPT entry arrays differ")
	}
	if err := verifyGPTEntries(primaryEntries, layout, totalLBAs); err != nil {
		return err
	}
	primaryPaddingOffset := (uint64(2) + gptEntryArraySectors) * SectorSizeBytes
	if primaryPaddingOffset > GPTRegionSizeBytes {
		return errors.New("primary GPT metadata exceeds its frozen region")
	}
	if err := verifyZeroRange(ctx, target, primaryPaddingOffset, GPTRegionSizeBytes-primaryPaddingOffset); err != nil {
		return fmt.Errorf("primary GPT region padding is not zero: %w", err)
	}
	backupRegionOffset := sizeBytes - GPTRegionSizeBytes
	backupEntriesOffset := backup.entriesLBA * SectorSizeBytes
	if backupEntriesOffset < backupRegionOffset {
		return errors.New("backup GPT entry array begins before its frozen region")
	}
	if err := verifyZeroRange(ctx, target, backupRegionOffset, backupEntriesOffset-backupRegionOffset); err != nil {
		return fmt.Errorf("backup GPT region padding is not zero: %w", err)
	}
	return nil
}

func verifyProtectiveMBR(mbr []byte, totalLBAs uint64) error {
	if len(mbr) != int(SectorSizeBytes) || mbr[510] != 0x55 || mbr[511] != 0xaa {
		return errors.New("protective MBR signature is invalid")
	}
	// Hybrid MBRs are forbidden. Boot code and disk signature are also frozen
	// to zero so the first-MiB digest and semantic view agree.
	if !allZero(mbr[:446]) || !allZero(mbr[462:510]) {
		return errors.New("protective MBR contains boot code, a disk signature, or hybrid entries")
	}
	entry := mbr[446:462]
	if entry[0] != 0 || !allZero(entry[1:4]) || entry[4] != 0xee || !allZero(entry[5:8]) || binary.LittleEndian.Uint32(entry[8:12]) != 1 {
		return errors.New("protective MBR does not contain the exact 0xEE entry")
	}
	expectedSize := totalLBAs - 1
	if expectedSize > 0xffffffff {
		expectedSize = 0xffffffff
	}
	if uint64(binary.LittleEndian.Uint32(entry[12:16])) != expectedSize {
		return errors.New("protective MBR size does not cover the target")
	}
	return nil
}

func parseGPTHeader(target io.ReaderAt, lba, totalLBAs uint64) (parsedGPTHeader, error) {
	sector := make([]byte, SectorSizeBytes)
	if err := readExact(target, lba*SectorSizeBytes, sector); err != nil {
		return parsedGPTHeader{}, err
	}
	if string(sector[:8]) != "EFI PART" || binary.LittleEndian.Uint32(sector[8:12]) != 0x00010000 || binary.LittleEndian.Uint32(sector[12:16]) != gptHeaderSize || binary.LittleEndian.Uint32(sector[20:24]) != 0 {
		return parsedGPTHeader{}, errors.New("signature, revision, header size, or reserved field is invalid")
	}
	storedCRC := binary.LittleEndian.Uint32(sector[16:20])
	copyForCRC := append([]byte(nil), sector[:gptHeaderSize]...)
	for index := 16; index < 20; index++ {
		copyForCRC[index] = 0
	}
	if crc32.ChecksumIEEE(copyForCRC) != storedCRC {
		return parsedGPTHeader{}, errors.New("header CRC32 is invalid")
	}
	header := parsedGPTHeader{
		currentLBA:     binary.LittleEndian.Uint64(sector[24:32]),
		backupLBA:      binary.LittleEndian.Uint64(sector[32:40]),
		firstUsableLBA: binary.LittleEndian.Uint64(sector[40:48]),
		lastUsableLBA:  binary.LittleEndian.Uint64(sector[48:56]),
		diskGUID:       guidFromGPTBytes(sector[56:72]),
		entriesLBA:     binary.LittleEndian.Uint64(sector[72:80]),
		entryCount:     binary.LittleEndian.Uint32(sector[80:84]),
		entrySize:      binary.LittleEndian.Uint32(sector[84:88]),
		entriesCRC:     binary.LittleEndian.Uint32(sector[88:92]),
	}
	if header.currentLBA >= totalLBAs || header.backupLBA >= totalLBAs || header.firstUsableLBA > header.lastUsableLBA || header.lastUsableLBA >= totalLBAs || header.entriesLBA >= totalLBAs {
		return parsedGPTHeader{}, errors.New("header contains an out-of-range LBA")
	}
	if !allZero(sector[gptHeaderSize:]) {
		return parsedGPTHeader{}, errors.New("GPT header sector contains non-zero trailing bytes")
	}
	return header, nil
}

func readGPTEntries(target io.ReaderAt, header parsedGPTHeader) ([]byte, error) {
	if header.entryCount != gptEntryCount || header.entrySize != gptEntrySize {
		return nil, errors.New("GPT entry geometry is not the frozen 128 x 128-byte form")
	}
	entries := make([]byte, gptEntryArrayBytes)
	if err := readExact(target, header.entriesLBA*SectorSizeBytes, entries); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(entries) != header.entriesCRC {
		return nil, errors.New("GPT entry-array CRC32 is invalid")
	}
	return entries, nil
}

func verifyGPTEntries(entries []byte, layout Layout, totalLBAs uint64) error {
	for index := 0; index < gptEntryCount; index++ {
		entry := entries[index*gptEntrySize : (index+1)*gptEntrySize]
		if index >= len(layout.Partitions) {
			if !allZero(entry) {
				return fmt.Errorf("unexpected allocated GPT entry %d", index+1)
			}
			continue
		}
		expected := layout.Partitions[index]
		firstLBA := binary.LittleEndian.Uint64(entry[32:40])
		lastLBA := binary.LittleEndian.Uint64(entry[40:48])
		if firstLBA > lastLBA {
			return fmt.Errorf("GPT partition %d has an inverted range", index+1)
		}
		// firstLBA and lastLBA are untrusted disk bytes. Bound both before
		// converting sectors to bytes so multiplication or the inclusive-size
		// addition cannot wrap and accidentally compare equal to the plan.
		if firstLBA < layout.FirstUsableLBA || lastLBA > layout.LastUsableLBA ||
			firstLBA >= totalLBAs || lastLBA >= totalLBAs ||
			firstLBA > ^uint64(0)/SectorSizeBytes || lastLBA-firstLBA == ^uint64(0) ||
			lastLBA-firstLBA+1 > ^uint64(0)/SectorSizeBytes {
			return fmt.Errorf("GPT partition %d has an out-of-range byte extent", index+1)
		}
		offset := firstLBA * SectorSizeBytes
		size := (lastLBA - firstLBA + 1) * SectorSizeBytes
		name, err := decodeGPTName(entry[56:128])
		if err != nil {
			return fmt.Errorf("GPT partition %d name: %w", index+1, err)
		}
		if guidFromGPTBytes(entry[:16]) != expected.TypeGUID || guidFromGPTBytes(entry[16:32]) != expected.UniqueGUID || binary.LittleEndian.Uint64(entry[48:56]) != expected.Attributes || offset != expected.OffsetBytes || size != expected.SizeBytes || name != expected.Name {
			return fmt.Errorf("GPT partition %d differs from the frozen layout", index+1)
		}
	}
	return nil
}

func decodeGPTName(value []byte) (string, error) {
	units := make([]uint16, 0, len(value)/2)
	terminated := false
	for index := 0; index < len(value); index += 2 {
		unit := binary.LittleEndian.Uint16(value[index : index+2])
		if unit == 0 {
			terminated = true
			continue
		}
		if terminated {
			return "", errors.New("partition name has non-zero data after its terminator")
		}
		units = append(units, unit)
	}
	for _, runeValue := range utf16.Decode(units) {
		if runeValue < 0x21 || runeValue > 0x7e {
			return "", errors.New("partition name must be printable ASCII")
		}
	}
	return string(utf16.Decode(units)), nil
}

func guidFromGPTBytes(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(value[0:4]),
		binary.LittleEndian.Uint16(value[4:6]),
		binary.LittleEndian.Uint16(value[6:8]),
		value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15])
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
