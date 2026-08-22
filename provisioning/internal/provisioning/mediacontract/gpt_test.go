package mediacontract

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestVerifyGPTEntriesBoundsUntrustedLBAsBeforeByteArithmetic(t *testing.T) {
	entries := make([]byte, gptEntryArrayBytes)
	copy(entries[:16], guidToGPTBytes(t, ESPTypeGUID))
	copy(entries[16:32], guidToGPTBytes(t, "22222222-2222-4222-8222-222222222222"))
	binary.LittleEndian.PutUint64(entries[32:40], ^uint64(0)-1)
	binary.LittleEndian.PutUint64(entries[40:48], ^uint64(0))
	layout := Layout{
		FirstUsableLBA: 34,
		LastUsableLBA:  2047,
		Partitions: []GPTPartition{{
			Number: 1, Role: PartitionBoot, Name: "kaiba-boot", TypeGUID: ESPTypeGUID,
			UniqueGUID: "22222222-2222-4222-8222-222222222222", OffsetBytes: AlignmentBytes,
			SizeBytes: AlignmentBytes,
		}},
	}
	if err := verifyGPTEntries(entries, layout, 2048); err == nil || !strings.Contains(err.Error(), "out-of-range") {
		t.Fatalf("verifyGPTEntries() error = %v", err)
	}
}
