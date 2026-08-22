// Package mediacontract defines the secret-free, canonical contract for one
// exact Raspberry Pi 5 target medium. It contains no block-device writer,
// physical lane, UART device, EEPROM, OTP, or signing implementation.
package mediacontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	PlanSchemaVersion                = "kaiba.provisioning.rpi5-media-staging-plan/v1alpha1"
	LayoutSchemaVersion              = "kaiba.provisioning.rpi5-device-media-layout/v1alpha1"
	StageReceiptSchemaVersion        = "kaiba.provisioning.rpi5-media-stage-receipt/v1alpha1"
	VerificationReceiptSchemaVersion = "kaiba.provisioning.rpi5-media-verification-receipt/v1alpha1"
	ColdObservationSchemaVersion     = "kaiba.provisioning.rpi5-media-cold-power-observation/v1alpha1"
	FinalReceiptSchemaVersion        = "kaiba.provisioning.rpi5-media-staging-receipt/v1alpha1"
	VerificationReportSchemaVersion  = "kaiba.provisioning.rpi5-media-verification-report/v1alpha1"

	SectorSizeBytes    = uint64(512)
	AlignmentBytes     = uint64(1024 * 1024)
	GPTRegionSizeBytes = AlignmentBytes
)

const (
	planDigestDomain         = "kaiba.provisioning.rpi5-media-staging-plan.v1alpha1"
	layoutDigestDomain       = "kaiba.provisioning.rpi5-device-media-layout.v1alpha1"
	stageReceiptDigestDomain = "kaiba.provisioning.rpi5-media-stage-receipt.v1alpha1"
	verifyReceiptDomain      = "kaiba.provisioning.rpi5-media-verification-receipt.v1alpha1"
	coldObservationDomain    = "kaiba.provisioning.rpi5-media-cold-power-observation.v1alpha1"
	finalReceiptDomain       = "kaiba.provisioning.rpi5-media-staging-receipt.v1alpha1"
)

type SourceRole string

const (
	SourcePrimaryGPT     SourceRole = "primary-gpt"
	SourceBootFilesystem SourceRole = "boot-filesystem"
	SourceRootData       SourceRole = "root-data"
	SourceRootHash       SourceRole = "root-hash"
	SourceBackupGPT      SourceRole = "backup-gpt"
	SourceZero           SourceRole = "zero"
)

type RegionRole string

const (
	RegionPrimaryGPT     RegionRole = "primary-gpt"
	RegionBootFilesystem RegionRole = "boot-filesystem"
	RegionRootData       RegionRole = "root-data"
	RegionRootHash       RegionRole = "root-hash"
	RegionTailZero       RegionRole = "tail-zero"
	RegionBackupGPT      RegionRole = "backup-gpt"
)

type ContentKind string

const (
	ContentExactFile      ContentKind = "exact-file"
	ContentFileZeroPadded ContentKind = "file-zero-padded"
	ContentZero           ContentKind = "zero"
)

type PartitionRole string

const (
	PartitionBoot     PartitionRole = "boot-filesystem"
	PartitionRootData PartitionRole = "root-data"
	PartitionRootHash PartitionRole = "root-hash"
)

const (
	ESPTypeGUID       = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	ARM64RootTypeGUID = "b921b045-1df0-41c3-af44-4c6f280d3fae"
	ARM64VerityGUID   = "df3300ce-d69f-4c92-978c-9bfb0f38d820"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	guidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	volumeIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}$`)
	partitionAlias    = regexp.MustCompile(`-part[0-9]+$`)
)

// ReleaseBinding identifies the already complete, signer-anchored release.
// The media contract verifies this binding; it never chooses a signer.
type ReleaseBinding struct {
	ReleaseID                   string `json:"release_id"`
	SignedReleaseManifestDigest Digest `json:"signed_release_manifest_digest"`
	CapsuleDigest               Digest `json:"capsule_digest"`
}

// TargetBinding contains stable device facts. Linux disk sequence is
// intentionally absent: it is attachment-local and belongs in phase receipts.
type TargetBinding struct {
	ByIDPath                string `json:"by_id_path"`
	Model                   string `json:"model"`
	Serial                  string `json:"serial"`
	WWID                    string `json:"wwid"`
	SizeBytes               uint64 `json:"size_bytes"`
	LogicalSectorSizeBytes  uint64 `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes uint64 `json:"physical_sector_size_bytes"`
}

type ArtifactBinding struct {
	Digest    Digest `json:"digest"`
	SizeBytes uint64 `json:"size_bytes"`
}

type PayloadBindings struct {
	BootImage     ArtifactBinding `json:"boot_image"`
	BootSignature ArtifactBinding `json:"boot_signature"`
	RootData      ArtifactBinding `json:"root_data"`
	RootHashTree  ArtifactBinding `json:"root_hash_tree"`
	RootIntegrity ArtifactBinding `json:"root_integrity"`
	MediaBinding  ArtifactBinding `json:"media_binding"`
	OuterBootFAT  ArtifactBinding `json:"outer_boot_fat"`
	PrimaryGPT    ArtifactBinding `json:"primary_gpt"`
	BackupGPT     ArtifactBinding `json:"backup_gpt"`
}

type SourceBinding struct {
	Role      SourceRole `json:"role"`
	Digest    Digest     `json:"digest"`
	SizeBytes uint64     `json:"size_bytes"`
}

// MediaRegion covers a complete, ordered target range. SourceSizeBytes may be
// smaller than SizeBytes only for file-zero-padded content. Zero regions bind
// the digest of an empty source and the digest of the exact zero-filled range.
type MediaRegion struct {
	Role            RegionRole  `json:"role"`
	ContentKind     ContentKind `json:"content_kind"`
	SourceRole      SourceRole  `json:"source_role"`
	OffsetBytes     uint64      `json:"offset_bytes"`
	SizeBytes       uint64      `json:"size_bytes"`
	SourceSizeBytes uint64      `json:"source_size_bytes"`
	SourceDigest    Digest      `json:"source_digest"`
	ContentDigest   Digest      `json:"content_digest"`
}

type GPTPartition struct {
	Number          uint32        `json:"number"`
	Role            PartitionRole `json:"role"`
	Name            string        `json:"name"`
	TypeGUID        string        `json:"type_guid"`
	UniqueGUID      string        `json:"unique_guid"`
	Attributes      uint64        `json:"attributes"`
	OffsetBytes     uint64        `json:"offset_bytes"`
	SizeBytes       uint64        `json:"size_bytes"`
	UsedSizeBytes   uint64        `json:"used_size_bytes"`
	UsedDigest      Digest        `json:"used_digest"`
	PartitionDigest Digest        `json:"partition_digest"`
}

type FATFile struct {
	Path      string `json:"path"`
	Digest    Digest `json:"digest"`
	SizeBytes uint64 `json:"size_bytes"`
}

type FATContract struct {
	Filesystem string    `json:"filesystem"`
	Label      string    `json:"label"`
	VolumeID   string    `json:"volume_id"`
	Allowlist  []FATFile `json:"allowlist"`
}

type VerityContract struct {
	Algorithm          string `json:"algorithm"`
	RootHash           Digest `json:"root_hash"`
	DataBlockSizeBytes uint32 `json:"data_block_size_bytes"`
	HashBlockSizeBytes uint32 `json:"hash_block_size_bytes"`
	DataPartitionGUID  string `json:"data_partition_guid"`
	HashPartitionGUID  string `json:"hash_partition_guid"`
	Mapper             string `json:"mapper"`
}

type Layout struct {
	SchemaVersion   string          `json:"schema_version"`
	SectorSizeBytes uint64          `json:"sector_size_bytes"`
	AlignmentBytes  uint64          `json:"alignment_bytes"`
	DiskGUID        string          `json:"disk_guid"`
	FirstUsableLBA  uint64          `json:"first_usable_lba"`
	LastUsableLBA   uint64          `json:"last_usable_lba"`
	Payloads        PayloadBindings `json:"payloads"`
	Sources         []SourceBinding `json:"sources"`
	Regions         []MediaRegion   `json:"regions"`
	Partitions      []GPTPartition  `json:"partitions"`
	FAT             FATContract     `json:"fat"`
	Verity          VerityContract  `json:"verity"`
	LayoutDigest    Digest          `json:"layout_digest"`
}

// Plan binds one transaction, one exact whole device, the reviewed prestate,
// and every byte expected after staging. Runtime source paths are deliberately
// not part of the contract; a privileged writer must resolve SourceRole values
// only from its immutable build-time asset set.
type Plan struct {
	SchemaVersion       string         `json:"schema_version"`
	TransactionID       string         `json:"transaction_id"`
	Release             ReleaseBinding `json:"release"`
	Target              TargetBinding  `json:"target"`
	Layout              Layout         `json:"layout"`
	InitialMediaDigest  Digest         `json:"initial_media_digest"`
	ExpectedMediaDigest Digest         `json:"expected_media_digest"`
	PlanDigest          Digest         `json:"plan_digest"`
}

func validateIdentifier(label, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s must be a canonical lowercase identifier", label)
	}
	return nil
}

func validatePrintable(label, value string, maximum int) error {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be non-empty printable ASCII no longer than %d bytes", label, maximum)
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return fmt.Errorf("%s must contain printable ASCII", label)
		}
	}
	return nil
}

func validateGUID(label, value string) error {
	if !guidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("%s must be one non-zero canonical lowercase GUID", label)
	}
	return nil
}

func (binding ArtifactBinding) validate(label string) error {
	if err := validateDigest(label+".digest", binding.Digest); err != nil {
		return err
	}
	if binding.SizeBytes == 0 || binding.SizeBytes > math.MaxInt64 {
		return fmt.Errorf("%s.size_bytes must be between 1 and %d", label, int64(math.MaxInt64))
	}
	return nil
}

func (release ReleaseBinding) Validate() error {
	if err := validateIdentifier("release_id", release.ReleaseID); err != nil {
		return err
	}
	if err := validateDigest("signed_release_manifest_digest", release.SignedReleaseManifestDigest); err != nil {
		return err
	}
	return validateDigest("capsule_digest", release.CapsuleDigest)
}

func (target TargetBinding) Validate() error {
	const prefix = "/dev/disk/by-id/"
	if !strings.HasPrefix(target.ByIDPath, prefix) || filepath.Clean(target.ByIDPath) != target.ByIDPath {
		return errors.New("target by_id_path must be a clean immediate /dev/disk/by-id path")
	}
	name := strings.TrimPrefix(target.ByIDPath, prefix)
	if name == "" || name == "." || strings.Contains(name, "/") || strings.ContainsAny(name, " \t\r\n") || partitionAlias.MatchString(name) {
		return errors.New("target by_id_path must identify one whole device, not a partition")
	}
	for label, value := range map[string]string{"model": target.Model, "serial": target.Serial, "wwid": target.WWID} {
		if err := validatePrintable(label, value, 255); err != nil {
			return err
		}
	}
	if target.SizeBytes < 8*AlignmentBytes || target.SizeBytes > math.MaxInt64 || target.SizeBytes%SectorSizeBytes != 0 {
		return errors.New("target size_bytes must be a sector-aligned supported whole-device capacity")
	}
	if target.LogicalSectorSizeBytes != SectorSizeBytes {
		return fmt.Errorf("target logical_sector_size_bytes must be %d", SectorSizeBytes)
	}
	physical := target.PhysicalSectorSizeBytes
	if physical < target.LogicalSectorSizeBytes || physical > 64*1024 || physical&(physical-1) != 0 {
		return errors.New("target physical_sector_size_bytes must be a supported power of two")
	}
	return nil
}

func (layout Layout) digestMaterial() ([]byte, error) {
	material := layout
	material.LayoutDigest = ""
	return json.Marshal(material)
}

func (layout Layout) DerivedDigest() (Digest, error) {
	if err := layout.validate(false); err != nil {
		return "", err
	}
	material, err := layout.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode layout digest material: %w", err)
	}
	return domainDigest(layoutDigestDomain, material), nil
}

func (layout Layout) WithDerivedDigest() (Layout, error) {
	derived := layout
	derived.LayoutDigest = ""
	digest, err := derived.DerivedDigest()
	if err != nil {
		return Layout{}, err
	}
	derived.LayoutDigest = digest
	return derived, nil
}

func (layout Layout) Validate() error { return layout.validate(true) }

func (layout Layout) validate(requireDigest bool) error {
	if layout.SchemaVersion != LayoutSchemaVersion {
		return fmt.Errorf("unsupported layout schema_version %q", layout.SchemaVersion)
	}
	if layout.SectorSizeBytes != SectorSizeBytes || layout.AlignmentBytes != AlignmentBytes {
		return errors.New("layout must use frozen 512-byte sectors and 1 MiB alignment")
	}
	if err := validateGUID("disk_guid", layout.DiskGUID); err != nil {
		return err
	}
	if layout.FirstUsableLBA != 34 {
		return errors.New("layout first_usable_lba must be 34")
	}
	for label, binding := range map[string]ArtifactBinding{
		"payloads.boot_image":     layout.Payloads.BootImage,
		"payloads.boot_signature": layout.Payloads.BootSignature,
		"payloads.root_data":      layout.Payloads.RootData,
		"payloads.root_hash_tree": layout.Payloads.RootHashTree,
		"payloads.root_integrity": layout.Payloads.RootIntegrity,
		"payloads.media_binding":  layout.Payloads.MediaBinding,
		"payloads.outer_boot_fat": layout.Payloads.OuterBootFAT,
		"payloads.primary_gpt":    layout.Payloads.PrimaryGPT,
		"payloads.backup_gpt":     layout.Payloads.BackupGPT,
	} {
		if err := binding.validate(label); err != nil {
			return err
		}
	}
	if err := layout.validateSources(); err != nil {
		return err
	}
	if err := layout.validateRegions(); err != nil {
		return err
	}
	if err := layout.validatePartitions(); err != nil {
		return err
	}
	if err := layout.validateFAT(); err != nil {
		return err
	}
	if err := layout.validateVerity(); err != nil {
		return err
	}
	if requireDigest {
		if err := validateDigest("layout_digest", layout.LayoutDigest); err != nil {
			return err
		}
		derived, err := layout.DerivedDigest()
		if err != nil {
			return err
		}
		if layout.LayoutDigest != derived {
			return errors.New("layout_digest does not match canonical layout content")
		}
	}
	return nil
}

func (layout Layout) validateSources() error {
	expected := []struct {
		role    SourceRole
		binding ArtifactBinding
	}{
		{SourcePrimaryGPT, layout.Payloads.PrimaryGPT},
		{SourceBootFilesystem, layout.Payloads.OuterBootFAT},
		{SourceRootData, layout.Payloads.RootData},
		{SourceRootHash, layout.Payloads.RootHashTree},
		{SourceBackupGPT, layout.Payloads.BackupGPT},
	}
	if len(layout.Sources) != len(expected) {
		return errors.New("sources must contain exactly primary GPT, boot FAT, root data, root hash, and backup GPT")
	}
	for index, item := range expected {
		source := layout.Sources[index]
		if source.Role != item.role || source.Digest != item.binding.Digest || source.SizeBytes != item.binding.SizeBytes {
			return fmt.Errorf("sources[%d] does not match payload %q", index, item.role)
		}
	}
	return nil
}

func (layout Layout) validateRegions() error {
	expectedRoles := []RegionRole{RegionPrimaryGPT, RegionBootFilesystem, RegionRootData, RegionRootHash, RegionTailZero, RegionBackupGPT}
	expectedKinds := []ContentKind{ContentExactFile, ContentExactFile, ContentFileZeroPadded, ContentFileZeroPadded, ContentZero, ContentExactFile}
	expectedSources := []SourceRole{SourcePrimaryGPT, SourceBootFilesystem, SourceRootData, SourceRootHash, SourceZero, SourceBackupGPT}
	if len(layout.Regions) != len(expectedRoles) {
		return errors.New("regions must contain the exact six-role complete-media sequence")
	}
	var next uint64
	for index, region := range layout.Regions {
		if region.Role != expectedRoles[index] || region.ContentKind != expectedKinds[index] || region.SourceRole != expectedSources[index] {
			return fmt.Errorf("regions[%d] has a non-canonical role, content kind, or source role", index)
		}
		if region.OffsetBytes != next || region.OffsetBytes%layout.SectorSizeBytes != 0 || region.SizeBytes%layout.SectorSizeBytes != 0 {
			return fmt.Errorf("regions[%d] does not begin at the exact next sector boundary", index)
		}
		if region.SizeBytes == 0 && region.Role != RegionTailZero {
			return fmt.Errorf("region %q must be non-empty", region.Role)
		}
		if region.SizeBytes > math.MaxInt64 || region.OffsetBytes > math.MaxInt64-region.SizeBytes {
			return fmt.Errorf("region %q exceeds supported media offsets", region.Role)
		}
		if err := validateDigest(fmt.Sprintf("regions[%d].source_digest", index), region.SourceDigest); err != nil {
			return err
		}
		if err := validateDigest(fmt.Sprintf("regions[%d].content_digest", index), region.ContentDigest); err != nil {
			return err
		}
		if region.ContentKind == ContentZero {
			if region.SourceSizeBytes != 0 || region.SourceDigest != sumBytes(nil) {
				return errors.New("zero region must bind the empty source digest and zero source size")
			}
		} else {
			binding, ok := layout.source(region.SourceRole)
			if !ok || region.SourceDigest != binding.Digest || region.SourceSizeBytes != binding.SizeBytes {
				return fmt.Errorf("region %q source does not match its canonical source binding", region.Role)
			}
			if region.SourceSizeBytes > region.SizeBytes {
				return fmt.Errorf("region %q source exceeds the region", region.Role)
			}
			if region.ContentKind == ContentExactFile && region.SourceSizeBytes != region.SizeBytes {
				return fmt.Errorf("exact-file region %q must have equal source and region sizes", region.Role)
			}
		}
		next += region.SizeBytes
	}
	if layout.Regions[0].SizeBytes != GPTRegionSizeBytes || layout.Regions[5].SizeBytes != GPTRegionSizeBytes {
		return errors.New("primary and backup GPT regions must each cover exactly 1 MiB")
	}
	if layout.Regions[0].ContentDigest != layout.Payloads.PrimaryGPT.Digest || layout.Regions[5].ContentDigest != layout.Payloads.BackupGPT.Digest {
		return errors.New("GPT region digests must match the exact GPT source bytes")
	}
	if layout.Regions[1].ContentDigest != layout.Payloads.OuterBootFAT.Digest {
		return errors.New("boot region digest must match the exact outer FAT image")
	}
	return nil
}

func (layout Layout) source(role SourceRole) (SourceBinding, bool) {
	for _, source := range layout.Sources {
		if source.Role == role {
			return source, true
		}
	}
	return SourceBinding{}, false
}

func (layout Layout) region(role RegionRole) (MediaRegion, bool) {
	for _, region := range layout.Regions {
		if region.Role == role {
			return region, true
		}
	}
	return MediaRegion{}, false
}

func (layout Layout) partition(role PartitionRole) (GPTPartition, bool) {
	for _, partition := range layout.Partitions {
		if partition.Role == role {
			return partition, true
		}
	}
	return GPTPartition{}, false
}

func (layout Layout) validatePartitions() error {
	expected := []struct {
		number         uint32
		role           PartitionRole
		name, typeGUID string
		region         RegionRole
		payload        ArtifactBinding
	}{
		{1, PartitionBoot, "kaiba-boot", ESPTypeGUID, RegionBootFilesystem, layout.Payloads.OuterBootFAT},
		{2, PartitionRootData, "kaiba-root", ARM64RootTypeGUID, RegionRootData, layout.Payloads.RootData},
		{3, PartitionRootHash, "kaiba-root-verity", ARM64VerityGUID, RegionRootHash, layout.Payloads.RootHashTree},
	}
	if len(layout.Partitions) != len(expected) {
		return errors.New("partitions must contain exactly boot, root-data, and root-hash")
	}
	seenGUID := map[string]struct{}{layout.DiskGUID: {}}
	for index, item := range expected {
		partition := layout.Partitions[index]
		region, _ := layout.region(item.region)
		if partition.Number != item.number || partition.Role != item.role || partition.Name != item.name || partition.TypeGUID != item.typeGUID {
			return fmt.Errorf("partitions[%d] does not match the frozen GPT role", index)
		}
		if err := validateGUID(fmt.Sprintf("partitions[%d].unique_guid", index), partition.UniqueGUID); err != nil {
			return err
		}
		if _, duplicate := seenGUID[partition.UniqueGUID]; duplicate {
			return errors.New("disk and partition GUIDs must be distinct")
		}
		seenGUID[partition.UniqueGUID] = struct{}{}
		if partition.Attributes != 0 {
			return fmt.Errorf("partition %q attributes must be zero", partition.Role)
		}
		if partition.OffsetBytes != region.OffsetBytes || partition.SizeBytes != region.SizeBytes || partition.UsedSizeBytes != item.payload.SizeBytes || partition.UsedDigest != item.payload.Digest || partition.PartitionDigest != region.ContentDigest {
			return fmt.Errorf("partition %q does not match its complete region and payload", partition.Role)
		}
		if partition.OffsetBytes%layout.AlignmentBytes != 0 || partition.SizeBytes%layout.AlignmentBytes != 0 {
			return fmt.Errorf("partition %q must use exact 1 MiB alignment", partition.Role)
		}
	}
	return nil
}

func (layout Layout) validateFAT() error {
	if layout.FAT.Filesystem != "fat32" || layout.FAT.Label != "KAIBA_BOOT" || !volumeIDPattern.MatchString(layout.FAT.VolumeID) {
		return errors.New("outer boot filesystem must be FAT32 with the frozen label and canonical volume ID")
	}
	expectedPaths := []string{"boot.img", "boot.sig", "config.txt", "kaiba-media-binding.json"}
	if len(layout.FAT.Allowlist) != len(expectedPaths) {
		return errors.New("FAT allowlist must contain exactly four files")
	}
	for index, path := range expectedPaths {
		entry := layout.FAT.Allowlist[index]
		if entry.Path != path || entry.SizeBytes == 0 {
			return fmt.Errorf("FAT allowlist entry %d must be %q with positive size", index, path)
		}
		if err := validateDigest(fmt.Sprintf("fat.allowlist[%d].digest", index), entry.Digest); err != nil {
			return err
		}
	}
	if layout.FAT.Allowlist[0].Digest != layout.Payloads.BootImage.Digest || layout.FAT.Allowlist[0].SizeBytes != layout.Payloads.BootImage.SizeBytes ||
		layout.FAT.Allowlist[1].Digest != layout.Payloads.BootSignature.Digest || layout.FAT.Allowlist[1].SizeBytes != layout.Payloads.BootSignature.SizeBytes ||
		layout.FAT.Allowlist[3].Digest != layout.Payloads.MediaBinding.Digest || layout.FAT.Allowlist[3].SizeBytes != layout.Payloads.MediaBinding.SizeBytes {
		return errors.New("FAT allowlist does not match boot, signature, and media-binding payloads")
	}
	if layout.Payloads.BootImage.SizeBytes > maximumVerifiedBootImageBytes {
		return fmt.Errorf("FAT boot.img exceeds its fixed %d-byte verifier bound", maximumVerifiedBootImageBytes)
	}
	if layout.Payloads.BootSignature.SizeBytes > maximumVerifiedBootSignatureBytes {
		return fmt.Errorf("FAT boot.sig exceeds its fixed %d-byte verifier bound", maximumVerifiedBootSignatureBytes)
	}
	config := []byte("boot_ramdisk=1\n")
	if layout.FAT.Allowlist[2].Digest != sumBytes(config) || layout.FAT.Allowlist[2].SizeBytes != uint64(len(config)) {
		return errors.New("FAT config.txt must contain exactly boot_ramdisk=1 followed by one newline")
	}
	if layout.Payloads.MediaBinding.SizeBytes > MaximumMediaBindingBytes {
		return errors.New("FAT media binding exceeds its fixed byte bound")
	}
	return nil
}

func (layout Layout) validateVerity() error {
	if layout.Verity.Algorithm != "sha256" || layout.Verity.DataBlockSizeBytes != 4096 || layout.Verity.HashBlockSizeBytes != 4096 || layout.Verity.Mapper != "/dev/mapper/root" {
		return errors.New("verity contract must use the frozen SHA-256/4096-byte /dev/mapper/root policy")
	}
	if err := validateDigest("verity.root_hash", layout.Verity.RootHash); err != nil {
		return err
	}
	data, ok := layout.partition(PartitionRootData)
	if !ok || data.UniqueGUID != layout.Verity.DataPartitionGUID {
		return errors.New("verity data_partition_guid does not match the root-data GPT partition")
	}
	if data.UsedSizeBytes == 0 || data.UsedSizeBytes%uint64(layout.Verity.DataBlockSizeBytes) != 0 {
		return errors.New("verity root-data used size must contain a positive whole number of data blocks")
	}
	hash, ok := layout.partition(PartitionRootHash)
	if !ok || hash.UniqueGUID != layout.Verity.HashPartitionGUID {
		return errors.New("verity hash_partition_guid does not match the root-hash GPT partition")
	}
	if hash.UsedSizeBytes == 0 || hash.UsedSizeBytes%uint64(layout.Verity.HashBlockSizeBytes) != 0 {
		return errors.New("verity root-hash used size must contain a positive whole number of hash blocks")
	}
	return nil
}

func (plan Plan) digestMaterial() ([]byte, error) {
	material := plan
	material.PlanDigest = ""
	return json.Marshal(material)
}

func (plan Plan) DerivedDigest() (Digest, error) {
	if err := plan.validate(false); err != nil {
		return "", err
	}
	material, err := plan.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode plan digest material: %w", err)
	}
	return domainDigest(planDigestDomain, material), nil
}

func (plan Plan) WithDerivedDigest() (Plan, error) {
	derived := plan
	derived.PlanDigest = ""
	digest, err := derived.DerivedDigest()
	if err != nil {
		return Plan{}, err
	}
	derived.PlanDigest = digest
	return derived, nil
}

func (plan Plan) Validate() error { return plan.validate(true) }

func (plan Plan) validate(requireDigest bool) error {
	if plan.SchemaVersion != PlanSchemaVersion {
		return fmt.Errorf("unsupported plan schema_version %q", plan.SchemaVersion)
	}
	if err := validateIdentifier("transaction_id", plan.TransactionID); err != nil {
		return err
	}
	if err := plan.Release.Validate(); err != nil {
		return err
	}
	if err := plan.Target.Validate(); err != nil {
		return err
	}
	if err := plan.Layout.Validate(); err != nil {
		return err
	}
	regions := plan.Layout.Regions
	if regions[len(regions)-1].OffsetBytes+regions[len(regions)-1].SizeBytes != plan.Target.SizeBytes {
		return errors.New("layout regions do not cover every target byte")
	}
	totalLBAs := plan.Target.SizeBytes / plan.Layout.SectorSizeBytes
	if totalLBAs < 68 || plan.Layout.LastUsableLBA != totalLBAs-34 {
		return errors.New("layout last_usable_lba does not match the exact target capacity")
	}
	backup := regions[len(regions)-1]
	if backup.OffsetBytes != plan.Target.SizeBytes-GPTRegionSizeBytes {
		return errors.New("backup GPT region is not anchored to the exact end of the target")
	}
	if err := validateDigest("initial_media_digest", plan.InitialMediaDigest); err != nil {
		return err
	}
	if err := validateDigest("expected_media_digest", plan.ExpectedMediaDigest); err != nil {
		return err
	}
	if requireDigest {
		if err := validateDigest("plan_digest", plan.PlanDigest); err != nil {
			return err
		}
		derived, err := plan.DerivedDigest()
		if err != nil {
			return err
		}
		if plan.PlanDigest != derived {
			return errors.New("plan_digest does not match canonical plan content")
		}
	}
	return nil
}

func (plan Plan) CanonicalJSON() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("encode canonical media plan: %w", err)
	}
	return encoded, nil
}

func ParsePlan(data []byte) (Plan, error) {
	var plan Plan
	err := strictCanonicalDecode(data, &plan, func() ([]byte, error) { return plan.CanonicalJSON() })
	return plan, err
}
