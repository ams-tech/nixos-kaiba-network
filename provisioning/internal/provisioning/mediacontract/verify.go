package mediacontract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const verificationBufferBytes = 1024 * 1024

// VerityVerifier is the deliberately narrow adapter boundary for dm-verity.
// Implementations receive only a read-only ReaderAt and the already validated
// partition ranges and trusted root hash. Production invokes one linker-fixed
// veritysetup binary over independently pinned read-only partition descriptors;
// regular-file fixtures may extract bounded ranges. Tests can provide an
// independent in-process checker.
type VerityVerifier interface {
	Verify(context.Context, io.ReaderAt, GPTPartition, GPTPartition, VerityContract) error
}

type VerityVerifierFunc func(context.Context, io.ReaderAt, GPTPartition, GPTPartition, VerityContract) error

func (function VerityVerifierFunc) Verify(ctx context.Context, target io.ReaderAt, data, hash GPTPartition, contract VerityContract) error {
	return function(ctx, target, data, hash, contract)
}

// SignedReleaseVerifier independently re-establishes that the staged boot
// image has a valid detached signature under the fixed release key and that
// its embedded root-integrity selectors match the signed release and GPT.
type SignedReleaseVerifier interface {
	Verify(context.Context, VerifiedBootFiles, Plan) error
}

type SignedReleaseVerifierFunc func(context.Context, VerifiedBootFiles, Plan) error

func (function SignedReleaseVerifierFunc) Verify(ctx context.Context, files VerifiedBootFiles, plan Plan) error {
	return function(ctx, files, plan)
}

// VerificationReport is structural verification output, not ceremony
// evidence. It becomes a receipt only through NewVerificationReceipt, which
// also requires the exact plan, stage receipt, target facts, and phase mode.
type VerificationReport struct {
	SchemaVersion            string               `json:"schema_version"`
	FullMediaDigest          Digest               `json:"full_media_digest"`
	Regions                  []RegionVerification `json:"regions"`
	GPTVerified              bool                 `json:"gpt_verified"`
	FATVerified              bool                 `json:"fat_verified"`
	PartitionDigestsVerified bool                 `json:"partition_digests_verified"`
	DMVerityVerified         bool                 `json:"dm_verity_verified"`
	BootSignatureVerified    bool                 `json:"boot_signature_verified"`
	ReleaseLineageVerified   bool                 `json:"release_lineage_verified"`
	HardwareObserved         bool                 `json:"hardware_observed"`
	ColdPowerCycleObserved   bool                 `json:"cold_power_cycle_observed"`
	SecurityEnforced         bool                 `json:"security_enforced"`
	MutationEligible         bool                 `json:"mutation_eligible"`
}

// VerifyFullMedia independently reads every target byte, each complete
// canonical region, both GPT copies, the FAT metadata and exact allowlist, and
// the dm-verity pair. It imports no staging writer and never writes target
// bytes. Device identity and cold-power provenance remain caller boundaries.
func VerifyFullMedia(ctx context.Context, target io.ReaderAt, sizeBytes uint64, plan Plan, verity VerityVerifier, release SignedReleaseVerifier) (VerificationReport, error) {
	if target == nil {
		return VerificationReport{}, errors.New("full-media verifier requires a read-only target")
	}
	if verity == nil {
		return VerificationReport{}, errors.New("full-media verifier requires an independent dm-verity checker")
	}
	if release == nil {
		return VerificationReport{}, errors.New("full-media verifier requires an independent signed-release checker")
	}
	if err := plan.Validate(); err != nil {
		return VerificationReport{}, err
	}
	if sizeBytes != plan.Target.SizeBytes {
		return VerificationReport{}, fmt.Errorf("target size is %d, expected %d", sizeBytes, plan.Target.SizeBytes)
	}
	fullDigest, err := hashReaderRange(ctx, target, 0, sizeBytes)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("hash complete target: %w", err)
	}
	if fullDigest != plan.ExpectedMediaDigest {
		return VerificationReport{}, fmt.Errorf("complete target digest is %s, expected %s", fullDigest, plan.ExpectedMediaDigest)
	}

	regions := make([]RegionVerification, 0, len(plan.Layout.Regions))
	for _, region := range plan.Layout.Regions {
		digest, err := hashReaderRange(ctx, target, region.OffsetBytes, region.SizeBytes)
		if err != nil {
			return VerificationReport{}, fmt.Errorf("hash region %q: %w", region.Role, err)
		}
		if digest != region.ContentDigest {
			return VerificationReport{}, fmt.Errorf("region %q digest is %s, expected %s", region.Role, digest, region.ContentDigest)
		}
		if region.ContentKind == ContentFileZeroPadded {
			used, err := hashReaderRange(ctx, target, region.OffsetBytes, region.SourceSizeBytes)
			if err != nil {
				return VerificationReport{}, fmt.Errorf("hash used bytes in region %q: %w", region.Role, err)
			}
			if used != region.SourceDigest {
				return VerificationReport{}, fmt.Errorf("region %q used-byte digest is %s, expected %s", region.Role, used, region.SourceDigest)
			}
			if err := verifyZeroRange(ctx, target, region.OffsetBytes+region.SourceSizeBytes, region.SizeBytes-region.SourceSizeBytes); err != nil {
				return VerificationReport{}, fmt.Errorf("region %q padding: %w", region.Role, err)
			}
		}
		if region.ContentKind == ContentZero {
			if err := verifyZeroRange(ctx, target, region.OffsetBytes, region.SizeBytes); err != nil {
				return VerificationReport{}, fmt.Errorf("region %q: %w", region.Role, err)
			}
		}
		regions = append(regions, RegionVerification{Role: region.Role, Digest: digest, Verified: true})
	}

	if err := verifyGPT(ctx, target, sizeBytes, plan.Layout); err != nil {
		return VerificationReport{}, fmt.Errorf("verify GPT: %w", err)
	}
	boot, _ := plan.Layout.partition(PartitionBoot)
	bootFiles, err := verifyFAT32(ctx, target, boot, plan.Layout.FAT)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("verify boot FAT: %w", err)
	}
	mediaBinding, err := ParseMediaBinding(bootFiles.MediaBinding)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("verify boot FAT media binding: %w", err)
	}
	if err := mediaBinding.ValidateAgainst(plan); err != nil {
		return VerificationReport{}, fmt.Errorf("verify boot FAT media binding: %w", err)
	}
	if err := release.Verify(ctx, bootFiles, plan); err != nil {
		return VerificationReport{}, fmt.Errorf("verify signed release and boot lineage: %w", err)
	}
	data, _ := plan.Layout.partition(PartitionRootData)
	hash, _ := plan.Layout.partition(PartitionRootHash)
	if err := verity.Verify(ctx, target, data, hash, plan.Layout.Verity); err != nil {
		return VerificationReport{}, fmt.Errorf("verify dm-verity: %w", err)
	}
	return VerificationReport{
		SchemaVersion:            VerificationReportSchemaVersion,
		FullMediaDigest:          fullDigest,
		Regions:                  regions,
		GPTVerified:              true,
		FATVerified:              true,
		PartitionDigestsVerified: true,
		DMVerityVerified:         true,
		BootSignatureVerified:    true,
		ReleaseLineageVerified:   true,
	}, nil
}

func hashReaderRange(ctx context.Context, reader io.ReaderAt, offset, size uint64) (Digest, error) {
	if offset > uint64(^uint64(0)>>1) || size > uint64(^uint64(0)>>1) || offset+size < offset || offset+size > uint64(^uint64(0)>>1) {
		return "", errors.New("range exceeds supported file offsets")
	}
	hash := sha256.New()
	buffer := make([]byte, verificationBufferBytes)
	position := offset
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := uint64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := reader.ReadAt(buffer[:int(chunk)], int64(position))
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			position += uint64(n)
			remaining -= uint64(n)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if n == 0 || (errors.Is(err, io.EOF) && remaining != 0) {
			return "", io.ErrUnexpectedEOF
		}
	}
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func verifyZeroRange(ctx context.Context, reader io.ReaderAt, offset, size uint64) error {
	buffer := make([]byte, verificationBufferBytes)
	position := offset
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := uint64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := reader.ReadAt(buffer[:int(chunk)], int64(position))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n != int(chunk) {
			return io.ErrUnexpectedEOF
		}
		for index, value := range buffer[:n] {
			if value != 0 {
				return fmt.Errorf("non-zero byte at target offset %d", position+uint64(index))
			}
		}
		position += uint64(n)
		remaining -= uint64(n)
	}
	return nil
}

func readExact(reader io.ReaderAt, offset uint64, buffer []byte) error {
	if offset > uint64(^uint64(0)>>1) {
		return errors.New("read offset exceeds supported file offsets")
	}
	n, err := reader.ReadAt(buffer, int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n != len(buffer) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
