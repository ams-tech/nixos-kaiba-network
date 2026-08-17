// Package unfusedcompat defines the offline contract for proving that one
// immutable Raspberry Pi 5 boot capsule is represented by a compatibility
// fixture. It has no physical-device execution boundary.
package unfusedcompat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ManifestSchemaVersion = "provisioning.kaiba.network/rpi5-unfused-capsule-manifest/v1alpha1"
	FixtureSchemaVersion  = "provisioning.kaiba.network/rpi5-unfused-compatibility-fixture/v1alpha1"
	OutcomeSchemaVersion  = "provisioning.kaiba.network/rpi5-unfused-compatibility-result/v1alpha2"

	EvidenceModeOfflineFixture = "offline_fixture"
	BootModeRAMDisk            = "boot_ramdisk"
	StatusCompatibilityPassed  = "compatibility_passed"

	maximumCapsuleFiles = 4096
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// CapsuleFile is one regular file in the exact capsule tree.
type CapsuleFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// CapsuleManifest binds a capsule identifier, its boot image, and the exact
// sorted regular-file tree used by an unfused compatibility fixture.
type CapsuleManifest struct {
	SchemaVersion     string        `json:"schema_version"`
	CapsuleID         string        `json:"capsule_id"`
	CapsuleDigest     string        `json:"capsule_digest"`
	BootImagePath     string        `json:"boot_image_path"`
	BootSignaturePath string        `json:"boot_signature_path"`
	RootDataPath      string        `json:"root_data_path"`
	RootHashPath      string        `json:"root_hash_path"`
	Files             []CapsuleFile `json:"files"`
}

// OfflineFixture is deliberately narrow synthetic evidence. A later physical
// adapter can produce a different evidence type without changing this offline
// contract or gaining a device-facing capability here.
type OfflineFixture struct {
	SchemaVersion               string `json:"schema_version"`
	FixtureID                   string `json:"fixture_id"`
	CapsuleID                   string `json:"capsule_id"`
	CapsuleDigest               string `json:"capsule_digest"`
	BootImageDigest             string `json:"boot_image_digest"`
	BootSignatureDigest         string `json:"boot_signature_digest"`
	RootDataDigest              string `json:"root_data_digest"`
	RootHashDigest              string `json:"root_hash_digest"`
	BootMode                    string `json:"boot_mode"`
	FirmwareLoaded              bool   `json:"firmware_loaded"`
	KernelStarted               bool   `json:"kernel_started"`
	InitramfsStarted            bool   `json:"initramfs_started"`
	CompatibilityMarkerObserved bool   `json:"compatibility_marker_observed"`
}

// Outcome is the only successful result. Hardware observation, enforcement,
// and mutation eligibility remain false. Signer trust is asserted only when
// signed verification matches an independently supplied trust policy.
type Outcome struct {
	SchemaVersion                string `json:"schema_version"`
	Status                       string `json:"status"`
	EvidenceMode                 string `json:"evidence_mode"`
	FixtureID                    string `json:"fixture_id"`
	CapsuleID                    string `json:"capsule_id"`
	ManifestDigest               string `json:"manifest_digest"`
	CapsuleDigest                string `json:"capsule_digest"`
	BootImageDigest              string `json:"boot_image_digest"`
	BootSignatureDigest          string `json:"boot_signature_digest"`
	RootDataDigest               string `json:"root_data_digest"`
	RootHashDigest               string `json:"root_hash_digest"`
	BootPublicKeyFingerprint     string `json:"boot_public_key_fingerprint,omitempty"`
	SignatureVerificationReceipt string `json:"signature_verification_receipt,omitempty"`
	SignatureVerified            bool   `json:"signature_verified"`
	SignerTrustAnchored          bool   `json:"signer_trust_anchored"`
	SignerTrustPolicyDigest      string `json:"signer_trust_policy_digest,omitempty"`
	FixtureDigest                string `json:"fixture_digest"`
	FilesVerified                int    `json:"files_verified"`
	HardwareObserved             bool   `json:"hardware_observed"`
	SecurityEnforced             bool   `json:"security_enforced"`
	MutationEligible             bool   `json:"mutation_eligible"`
}

type capsuleRoles struct {
	bootImage     CapsuleFile
	bootSignature CapsuleFile
	rootData      CapsuleFile
	rootHash      CapsuleFile
}

func (manifest CapsuleManifest) validate() (capsuleRoles, error) {
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return capsuleRoles{}, fmt.Errorf("unsupported capsule manifest schema %q", manifest.SchemaVersion)
	}
	if !identifierPattern.MatchString(manifest.CapsuleID) {
		return capsuleRoles{}, errors.New("capsule_id is invalid")
	}
	if !validDigest(manifest.CapsuleDigest) {
		return capsuleRoles{}, errors.New("capsule_digest must be a canonical lowercase SHA-256 digest")
	}
	rolePaths := []struct {
		label string
		value string
	}{
		{"boot_image_path", manifest.BootImagePath},
		{"boot_signature_path", manifest.BootSignaturePath},
		{"root_data_path", manifest.RootDataPath},
		{"root_hash_path", manifest.RootHashPath},
	}
	seenRolePaths := make(map[string]string, len(rolePaths))
	for _, role := range rolePaths {
		if err := validateRelativePath(role.value); err != nil {
			return capsuleRoles{}, fmt.Errorf("%s: %w", role.label, err)
		}
		if previous, duplicate := seenRolePaths[role.value]; duplicate {
			return capsuleRoles{}, fmt.Errorf("%s and %s must identify distinct files", previous, role.label)
		}
		seenRolePaths[role.value] = role.label
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maximumCapsuleFiles {
		return capsuleRoles{}, fmt.Errorf("capsule manifest must contain between 1 and %d files", maximumCapsuleFiles)
	}

	filesByPath := make(map[string]CapsuleFile, len(manifest.Files))
	for index, file := range manifest.Files {
		if err := validateRelativePath(file.Path); err != nil {
			return capsuleRoles{}, fmt.Errorf("files[%d].path: %w", index, err)
		}
		if index > 0 && manifest.Files[index-1].Path >= file.Path {
			return capsuleRoles{}, errors.New("capsule files must be uniquely sorted by path")
		}
		if file.SizeBytes < 0 {
			return capsuleRoles{}, fmt.Errorf("files[%d].size_bytes must not be negative", index)
		}
		if !validDigest(file.SHA256) {
			return capsuleRoles{}, fmt.Errorf("files[%d].sha256 must be a canonical lowercase SHA-256 digest", index)
		}
		filesByPath[file.Path] = file
	}
	roles := capsuleRoles{}
	roleRecords := []struct {
		label       string
		path        string
		destination *CapsuleFile
	}{
		{"boot_image_path", manifest.BootImagePath, &roles.bootImage},
		{"boot_signature_path", manifest.BootSignaturePath, &roles.bootSignature},
		{"root_data_path", manifest.RootDataPath, &roles.rootData},
		{"root_hash_path", manifest.RootHashPath, &roles.rootHash},
	}
	for _, role := range roleRecords {
		record, present := filesByPath[role.path]
		if !present {
			return capsuleRoles{}, fmt.Errorf("%s is not present in files", role.label)
		}
		if record.SizeBytes == 0 {
			return capsuleRoles{}, fmt.Errorf("%s must identify a non-empty file", role.label)
		}
		*role.destination = record
	}
	derived, err := ComputeCapsuleDigest(manifest.Files)
	if err != nil {
		return capsuleRoles{}, err
	}
	if manifest.CapsuleDigest != derived {
		return capsuleRoles{}, errors.New("capsule_digest does not match the manifest file set")
	}
	return roles, nil
}

func (fixture OfflineFixture) validate(manifest CapsuleManifest, roles capsuleRoles) error {
	if fixture.SchemaVersion != FixtureSchemaVersion {
		return fmt.Errorf("unsupported offline fixture schema %q", fixture.SchemaVersion)
	}
	if !identifierPattern.MatchString(fixture.FixtureID) {
		return errors.New("fixture_id is invalid")
	}
	if fixture.CapsuleID != manifest.CapsuleID || fixture.CapsuleDigest != manifest.CapsuleDigest {
		return errors.New("offline fixture does not match the capsule manifest")
	}
	if fixture.BootImageDigest != roles.bootImage.SHA256 ||
		fixture.BootSignatureDigest != roles.bootSignature.SHA256 ||
		fixture.RootDataDigest != roles.rootData.SHA256 ||
		fixture.RootHashDigest != roles.rootHash.SHA256 {
		return errors.New("offline fixture role digests do not match the capsule manifest")
	}
	if fixture.BootMode != BootModeRAMDisk {
		return errors.New("offline fixture boot_mode must be boot_ramdisk")
	}
	if !fixture.FirmwareLoaded || !fixture.KernelStarted || !fixture.InitramfsStarted || !fixture.CompatibilityMarkerObserved {
		return errors.New("offline fixture does not contain the complete compatibility sequence")
	}
	return nil
}

// ComputeCapsuleDigest derives the content identity used by the manifest. The
// caller must supply the same canonical sorted records accepted by validation.
func ComputeCapsuleDigest(files []CapsuleFile) (string, error) {
	if len(files) == 0 || len(files) > maximumCapsuleFiles {
		return "", errors.New("capsule digest requires a bounded non-empty file set")
	}
	for index, file := range files {
		if err := validateRelativePath(file.Path); err != nil {
			return "", fmt.Errorf("files[%d].path: %w", index, err)
		}
		if index > 0 && files[index-1].Path >= file.Path {
			return "", errors.New("capsule files must be uniquely sorted by path")
		}
		if file.SizeBytes < 0 || !validDigest(file.SHA256) {
			return "", fmt.Errorf("files[%d] has invalid size or digest", index)
		}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.rpi5.unfused-capsule.v1\x00"))
	for _, file := range files {
		for _, value := range []string{file.Path, strconv.FormatInt(file.SizeBytes, 10), file.SHA256} {
			_, _ = hash.Write([]byte(value))
			_, _ = hash.Write([]byte{0})
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func manifestDigest(manifest CapsuleManifest) (string, error) {
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("encode canonical capsule manifest: %w", err)
	}
	return domainDigest("kaiba.rpi5.unfused-capsule-manifest.v1", canonical), nil
}

func fixtureDigest(fixture OfflineFixture) (string, error) {
	canonical, err := json.Marshal(fixture)
	if err != nil {
		return "", fmt.Errorf("encode canonical offline fixture: %w", err)
	}
	return domainDigest("kaiba.rpi5.unfused-compatibility-fixture.v1", canonical), nil
}

func domainDigest(domain string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validateRelativePath(value string) error {
	if value == "" || value != path.Clean(value) || strings.HasPrefix(value, "/") || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return errors.New("must be a canonical relative slash-separated path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("must not contain empty, dot, or parent components")
		}
	}
	return nil
}

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func sortedManifestPaths(manifest CapsuleManifest) []string {
	paths := make([]string, len(manifest.Files))
	for index, file := range manifest.Files {
		paths[index] = file.Path
	}
	sort.Strings(paths)
	return paths
}
