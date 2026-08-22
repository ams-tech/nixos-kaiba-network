package signedrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const unsignedArtifactSchema = "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"

var (
	sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	versionPattern        = regexp.MustCompile(`^[ -~]{1,128}$`)
	uuidPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	partUUIDPattern       = regexp.MustCompile(`^PARTUUID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type unsignedArtifact struct {
	Path   string        `json:"path"`
	Digest bundle.Digest `json:"digest"`
}

type unsignedArtifacts struct {
	BootImage    unsignedArtifact `json:"boot_image"`
	RootData     unsignedArtifact `json:"root_data"`
	RootHashTree unsignedArtifact `json:"root_hash_tree"`
}

type unsignedToolchain struct {
	Cryptsetup string `json:"cryptsetup"`
	Dosfstools string `json:"dosfstools"`
	Mtools     string `json:"mtools"`
}

type unsignedVerity struct {
	Algorithm     string `json:"algorithm"`
	DataBlockSize uint64 `json:"data_block_size"`
	HashBlockSize uint64 `json:"hash_block_size"`
	UUID          string `json:"uuid"`
	DataDevice    string `json:"data_device"`
	HashDevice    string `json:"hash_device"`
	Mapper        string `json:"mapper"`
}

type unsignedArtifactSet struct {
	Schema                      string            `json:"schema"`
	SourceRevision              string            `json:"source_revision"`
	ExpectedCustomerKeyHash     bundle.Digest     `json:"expected_customer_key_hash"`
	BootOrderPolicy             string            `json:"boot_order_policy"`
	BootCommandLinePath         string            `json:"boot_command_line_path"`
	FirmwareAllowlist           []string          `json:"firmware_allowlist"`
	BootImageSizeBytes          uint64            `json:"boot_image_size_bytes"`
	PersistentMutableState      string            `json:"persistent_mutable_state"`
	RollbackPolicy              string            `json:"rollback_policy"`
	DebugPolicy                 string            `json:"debug_policy"`
	EEPROMWriteProtectionPolicy string            `json:"eeprom_write_protection_policy"`
	Toolchain                   unsignedToolchain `json:"toolchain"`
	Artifacts                   unsignedArtifacts `json:"artifacts"`
	Verity                      unsignedVerity    `json:"verity"`
	RootIntegrityDigest         bundle.Digest     `json:"root_integrity_digest"`
	BundleDigest                bundle.Digest     `json:"bundle_digest"`
	SigningStatus               string            `json:"signing_status"`
}

func parseUnsignedArtifactSet(encoded []byte) (unsignedArtifactSet, error) {
	object, err := decodeUniqueJSON(encoded)
	if err != nil {
		return unsignedArtifactSet{}, fmt.Errorf("decode unsigned artifact set: %w", err)
	}
	var manifest unsignedArtifactSet
	if err := strictDecode(encoded, &manifest); err != nil {
		return unsignedArtifactSet{}, fmt.Errorf("decode unsigned artifact set: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return unsignedArtifactSet{}, err
	}
	delete(object, "bundle_digest")
	canonical, err := json.Marshal(object)
	if err != nil {
		return unsignedArtifactSet{}, err
	}
	if actual := domainDigest("kaiba.rpi5.unsigned-artifacts.v1", canonical); actual != manifest.BundleDigest {
		return unsignedArtifactSet{}, errors.New("unsigned artifact set bundle_digest does not match its canonical contents")
	}
	return manifest, nil
}

func (m unsignedArtifactSet) validate() error {
	if m.Schema != unsignedArtifactSchema {
		return fmt.Errorf("unsupported unsigned artifact schema %q", m.Schema)
	}
	if !sourceRevisionPattern.MatchString(m.SourceRevision) {
		return errors.New("unsigned source_revision must be 40 or 64 lowercase hexadecimal characters")
	}
	for name, digest := range map[string]bundle.Digest{
		"expected_customer_key_hash": m.ExpectedCustomerKeyHash,
		"root_integrity_digest":      m.RootIntegrityDigest,
		"bundle_digest":              m.BundleDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("unsigned %s: %w", name, err)
		}
	}
	if m.BootOrderPolicy != "nvme-only" || m.BootCommandLinePath != "nixos/default/cmdline.txt" {
		return errors.New("unsigned artifact set does not use the fixed NVMe-only boot policy")
	}
	wantAllowlist := []string{
		"config.txt", "kaiba-root-integrity.json", "nixos/default/bcm2712-rpi-5-b.dtb",
		"nixos/default/cmdline.txt", "nixos/default/initrd", "nixos/default/kernel.img",
	}
	if len(m.FirmwareAllowlist) != len(wantAllowlist) {
		return errors.New("unsigned firmware_allowlist is not the fixed reviewed set")
	}
	for index := range wantAllowlist {
		if m.FirmwareAllowlist[index] != wantAllowlist[index] {
			return errors.New("unsigned firmware_allowlist is not the fixed reviewed set")
		}
	}
	if m.BootImageSizeBytes < 32*1024*1024 || m.BootImageSizeBytes > 96*1024*1024 {
		return errors.New("unsigned boot_image_size_bytes is outside the reviewed 32-96 MiB range")
	}
	if m.PersistentMutableState != "tmpfs-only" || m.RollbackPolicy != "unimplemented-block-enrollment-ready" ||
		m.DebugPolicy != "videocore-jtag-unlocked-development" || m.EEPROMWriteProtectionPolicy != "unlocked-development" || m.SigningStatus != "unsigned" {
		return errors.New("unsigned artifact policy fields do not match the development release contract")
	}
	for name, version := range map[string]string{
		"cryptsetup": m.Toolchain.Cryptsetup, "dosfstools": m.Toolchain.Dosfstools, "mtools": m.Toolchain.Mtools,
	} {
		if !versionPattern.MatchString(version) {
			return fmt.Errorf("unsigned toolchain %s version is not canonical printable text", name)
		}
	}
	for _, item := range []struct {
		label string
		want  string
		value unsignedArtifact
	}{
		{"boot_image", "unsigned/boot.img", m.Artifacts.BootImage},
		{"root_data", "nvme/root-data.img", m.Artifacts.RootData},
		{"root_hash_tree", "nvme/root-hash.img", m.Artifacts.RootHashTree},
	} {
		if item.value.Path != item.want {
			return fmt.Errorf("unsigned artifact %s path must be %q", item.label, item.want)
		}
		if err := item.value.Digest.Validate(); err != nil {
			return fmt.Errorf("unsigned artifact %s digest: %w", item.label, err)
		}
	}
	if m.Verity.Algorithm != "sha256" || m.Verity.DataBlockSize != 4096 || m.Verity.HashBlockSize != 4096 ||
		m.Verity.Mapper != "/dev/mapper/root" || !uuidPattern.MatchString(m.Verity.UUID) ||
		!canonicalPARTUUID(m.Verity.DataDevice) || !canonicalPARTUUID(m.Verity.HashDevice) ||
		m.Verity.DataDevice == m.Verity.HashDevice {
		return errors.New("unsigned dm-verity parameters are not canonical")
	}
	return nil
}

func canonicalPARTUUID(value string) bool {
	return partUUIDPattern.MatchString(value) && value != "PARTUUID=00000000-0000-0000-0000-000000000000"
}

type rootIntegrity struct {
	Schema        string `json:"schema"`
	Algorithm     string `json:"algorithm"`
	DataBlockSize uint64 `json:"data_block_size"`
	HashBlockSize uint64 `json:"hash_block_size"`
	NoSuperblock  bool   `json:"no_superblock"`
	RootHash      string `json:"root_hash"`
	DataDevice    string `json:"data_device"`
	HashDevice    string `json:"hash_device"`
}

func parseRootIntegrity(encoded []byte, unsigned unsignedArtifactSet) (rootIntegrity, error) {
	var record rootIntegrity
	if err := strictDecode(encoded, &record); err != nil {
		return rootIntegrity{}, fmt.Errorf("decode root-integrity record: %w", err)
	}
	rootHash := strings.TrimPrefix(string(unsigned.RootIntegrityDigest), "sha256:")
	if record.Schema != "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1" || record.Algorithm != "sha256" ||
		record.DataBlockSize != 4096 || record.HashBlockSize != 4096 || record.NoSuperblock || record.RootHash != rootHash ||
		record.DataDevice != unsigned.Verity.DataDevice || record.HashDevice != unsigned.Verity.HashDevice {
		return rootIntegrity{}, errors.New("root-integrity record does not match the unsigned dm-verity contract")
	}
	return record, nil
}

func validateEEPROMRelease(encoded []byte) error {
	object, err := decodeUniqueJSON(encoded)
	if err != nil {
		return fmt.Errorf("decode EEPROM release manifest: %w", err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"authority", "device_class", "firmware", "provenance", "required_capability", "schema_version", "source", "toolchain"}
	if len(keys) != len(want) {
		return errors.New("EEPROM release manifest has an unexpected top-level shape")
	}
	for index := range want {
		if keys[index] != want[index] {
			return errors.New("EEPROM release manifest has an unexpected top-level shape")
		}
	}
	if object["schema_version"] != "kaiba.provisioning.rpi5-eeprom-release/v1alpha1" ||
		object["device_class"] != bundle.SignedReleaseDeviceClassV1Alpha1 {
		return errors.New("EEPROM release manifest schema or device class is unsupported")
	}
	return nil
}
