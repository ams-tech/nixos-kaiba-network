package mediacontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	RuntimeFactsSchemaVersion = "kaiba.provisioning.rpi5-unfused-runtime-facts/v1alpha1"
	UARTRecordsSchemaVersion  = "kaiba.provisioning.rpi5-unfused-uart-records/v1alpha1"

	CompatibilityMarkerPrefix = "KAIBA_UNFUSED_COMPATIBILITY=pass"
	DMVerityMarkerPrefix      = "KAIBA_DM_VERITY=active"
	MaximumUARTRecordBytes    = 2048
	MaximumUARTCaptureBytes   = 64 * 1024
)

var partUUIDPattern = regexp.MustCompile(`^PARTUUID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RuntimeFacts is a serialization contract, not a collector. The target
// service integrating it must derive every field from read-only boot/FAT,
// device-mapper, mount, and signed-release state rather than caller input.
type RuntimeFacts struct {
	SchemaVersion               string `json:"schema_version"`
	TransactionID               string `json:"transaction_id"`
	ReleaseID                   string `json:"release_id"`
	SignedReleaseManifestDigest Digest `json:"signed_release_manifest_digest"`
	MediaBindingDigest          Digest `json:"media_binding_digest"`
	BootImageDigest             Digest `json:"boot_image_digest"`
	BootSignatureDigest         Digest `json:"boot_signature_digest"`
	RootDataDigest              Digest `json:"root_data_digest"`
	RootHashTreeDigest          Digest `json:"root_hash_tree_digest"`
	VerityRootHash              Digest `json:"verity_root_hash"`
	DataPARTUUID                string `json:"data_partuuid"`
	HashPARTUUID                string `json:"hash_partuuid"`
	Mapper                      string `json:"mapper"`
	BootRAMDisk                 bool   `json:"boot_ramdisk"`
	RootReadOnly                bool   `json:"root_read_only"`
	EnrollmentReady             bool   `json:"enrollment_ready"`
	CustomerKeyOTP              bool   `json:"customer_key_otp"`
}

type UARTRecords struct {
	SchemaVersion     string `json:"schema_version"`
	CompatibilityLine string `json:"compatibility_line"`
	DMVerityLine      string `json:"dm_verity_line"`
}

func (facts RuntimeFacts) Validate() error {
	if facts.SchemaVersion != RuntimeFactsSchemaVersion {
		return fmt.Errorf("unsupported runtime facts schema_version %q", facts.SchemaVersion)
	}
	if err := validateIdentifier("transaction_id", facts.TransactionID); err != nil {
		return err
	}
	if err := validateIdentifier("release_id", facts.ReleaseID); err != nil {
		return err
	}
	for label, digest := range map[string]Digest{
		"signed_release_manifest_digest": facts.SignedReleaseManifestDigest,
		"media_binding_digest":           facts.MediaBindingDigest,
		"boot_image_digest":              facts.BootImageDigest,
		"boot_signature_digest":          facts.BootSignatureDigest,
		"root_data_digest":               facts.RootDataDigest,
		"root_hash_tree_digest":          facts.RootHashTreeDigest,
		"verity_root_hash":               facts.VerityRootHash,
	} {
		if err := validateDigest(label, digest); err != nil {
			return err
		}
	}
	if !partUUIDPattern.MatchString(facts.DataPARTUUID) || !partUUIDPattern.MatchString(facts.HashPARTUUID) || facts.DataPARTUUID == facts.HashPARTUUID {
		return errors.New("runtime facts require distinct canonical PARTUUID data and hash selectors")
	}
	if facts.Mapper != "/dev/mapper/root" || !facts.BootRAMDisk || !facts.RootReadOnly || facts.EnrollmentReady || facts.CustomerKeyOTP {
		return errors.New("runtime facts do not describe the exact unfused, boot_ramdisk, read-only dm-verity state")
	}
	return nil
}

// ValidateAgainst correlates target-derivable runtime facts with an
// independently supplied approved plan. PlanDigest is intentionally absent
// from RuntimeFacts: it is not present in the non-circular on-media binding
// and therefore cannot honestly be claimed as a target-observed value.
func (facts RuntimeFacts) ValidateAgainst(plan Plan) error {
	if err := facts.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if facts.TransactionID != plan.TransactionID || facts.ReleaseID != plan.Release.ReleaseID ||
		facts.SignedReleaseManifestDigest != plan.Release.SignedReleaseManifestDigest ||
		facts.MediaBindingDigest != plan.Layout.Payloads.MediaBinding.Digest ||
		facts.BootImageDigest != plan.Layout.Payloads.BootImage.Digest ||
		facts.BootSignatureDigest != plan.Layout.Payloads.BootSignature.Digest ||
		facts.RootDataDigest != plan.Layout.Payloads.RootData.Digest ||
		facts.RootHashTreeDigest != plan.Layout.Payloads.RootHashTree.Digest ||
		facts.VerityRootHash != plan.Layout.Verity.RootHash ||
		facts.DataPARTUUID != "PARTUUID="+plan.Layout.Verity.DataPartitionGUID ||
		facts.HashPARTUUID != "PARTUUID="+plan.Layout.Verity.HashPartitionGUID ||
		facts.Mapper != plan.Layout.Verity.Mapper {
		return errors.New("runtime facts differ from the independently approved media plan")
	}
	return nil
}

func (facts RuntimeFacts) CanonicalJSON() ([]byte, error) {
	if err := facts.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(facts)
}

func ParseRuntimeFacts(data []byte) (RuntimeFacts, error) {
	var facts RuntimeFacts
	err := strictCanonicalDecode(data, &facts, func() ([]byte, error) { return facts.CanonicalJSON() })
	return facts, err
}

func BuildUARTRecords(facts RuntimeFacts) (UARTRecords, error) {
	if err := facts.Validate(); err != nil {
		return UARTRecords{}, err
	}
	compatibility := fmt.Sprintf(
		"%s transaction_id=%s release_id=%s signed_release_manifest_sha256=%s media_binding_sha256=%s boot_img_sha256=%s boot_sig_sha256=%s boot_ramdisk=true enrollment_ready=false customer_key_otp=false",
		CompatibilityMarkerPrefix,
		facts.TransactionID,
		facts.ReleaseID,
		facts.SignedReleaseManifestDigest,
		facts.MediaBindingDigest,
		facts.BootImageDigest,
		facts.BootSignatureDigest,
	)
	verity := fmt.Sprintf(
		"%s root_data_sha256=%s root_hash_tree_sha256=%s verity_root_hash=%s data_partuuid=%s hash_partuuid=%s mapper=%s root_read_only=true",
		DMVerityMarkerPrefix,
		facts.RootDataDigest,
		facts.RootHashTreeDigest,
		facts.VerityRootHash,
		facts.DataPARTUUID,
		facts.HashPARTUUID,
		facts.Mapper,
	)
	if len(compatibility) > MaximumUARTRecordBytes || len(verity) > MaximumUARTRecordBytes {
		return UARTRecords{}, errors.New("canonical UART record exceeds its fixed byte bound")
	}
	return UARTRecords{SchemaVersion: UARTRecordsSchemaVersion, CompatibilityLine: compatibility, DMVerityLine: verity}, nil
}

func (records UARTRecords) ValidateAgainst(facts RuntimeFacts) error {
	expected, err := BuildUARTRecords(facts)
	if err != nil {
		return err
	}
	if records != expected {
		return errors.New("UART records do not exactly match the runtime facts")
	}
	return nil
}

func (records UARTRecords) Text(facts RuntimeFacts) ([]byte, error) {
	if err := records.ValidateAgainst(facts); err != nil {
		return nil, err
	}
	return []byte(records.CompatibilityLine + "\n" + records.DMVerityLine + "\n"), nil
}

// ParseUARTCapture permits unrelated bounded boot diagnostics but requires
// exactly one canonical compatibility record followed by exactly one canonical
// dm-verity record. Any prefixed near-match, duplicate, reordering, oversized
// line, invalid UTF-8, or NUL fails closed.
func ParseUARTCapture(capture []byte, facts RuntimeFacts) (UARTRecords, error) {
	if len(capture) == 0 || len(capture) > MaximumUARTCaptureBytes {
		return UARTRecords{}, fmt.Errorf("UART capture size must be between 1 and %d bytes", MaximumUARTCaptureBytes)
	}
	if !utf8.Valid(capture) || strings.IndexByte(string(capture), 0) >= 0 {
		return UARTRecords{}, errors.New("UART capture must be valid NUL-free UTF-8")
	}
	expected, err := BuildUARTRecords(facts)
	if err != nil {
		return UARTRecords{}, err
	}
	compatibilityCount := 0
	verityCount := 0
	compatibilityLineIndex := -1
	verityLineIndex := -1
	for index, raw := range strings.Split(string(capture), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if len(line) > MaximumUARTRecordBytes {
			return UARTRecords{}, fmt.Errorf("UART line %d exceeds %d bytes", index+1, MaximumUARTRecordBytes)
		}
		if strings.HasPrefix(line, "KAIBA_UNFUSED_COMPATIBILITY=") {
			if line != expected.CompatibilityLine {
				return UARTRecords{}, errors.New("UART compatibility record is not the exact canonical binding")
			}
			compatibilityCount++
			compatibilityLineIndex = index
		}
		if strings.HasPrefix(line, "KAIBA_DM_VERITY=") {
			if line != expected.DMVerityLine {
				return UARTRecords{}, errors.New("UART dm-verity record is not the exact canonical binding")
			}
			verityCount++
			verityLineIndex = index
		}
	}
	if compatibilityCount != 1 || verityCount != 1 {
		return UARTRecords{}, fmt.Errorf("UART capture contains %d compatibility and %d dm-verity records, want exactly one each", compatibilityCount, verityCount)
	}
	if compatibilityLineIndex >= verityLineIndex {
		return UARTRecords{}, errors.New("UART compatibility record must precede the dm-verity record")
	}
	return expected, nil
}
