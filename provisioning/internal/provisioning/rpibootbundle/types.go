// Package rpibootbundle constructs and verifies the exact immutable directory
// set consumed by the Raspberry Pi 5 provisioning lane. It contains no USB,
// GPIO, block-device, signing, EEPROM-programming, or OTP authority.
package rpibootbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	SetSchemaV1Alpha1     = "kaiba.provisioning.rpi5-rpiboot-bundle-set/v1alpha1"
	FixtureSchemaV1Alpha1 = "kaiba.provisioning.rpi5-acceptance-fixture/v1alpha1"
	maxSetBytes           = 16 * 1024 * 1024
)

// Role is the closed, canonical six-directory vocabulary used by the complete
// signed-release manifest.
type Role string

const (
	RoleFreshCommit        Role = "rpi5.fresh_commit_bundle"
	RoleFreshReadback      Role = "rpi5.fresh_readback_bundle"
	RoleNegativeBoot       Role = "rpi5.negative_boot_bundle"
	RoleOwnedReadback      Role = "rpi5.owned_readback_bundle"
	RoleOwnedRecovery      Role = "rpi5.owned_recovery_bundle"
	RoleRootIntegrity      Role = "rpi5.root_integrity_test_bundle"
	negativeFixtureID           = "unauthorized-owned-recovery"
	rootIntegrityFixtureID      = "persistent-root-data-tamper"
)

var canonicalRoles = [...]Role{
	RoleFreshCommit,
	RoleFreshReadback,
	RoleNegativeBoot,
	RoleOwnedReadback,
	RoleOwnedRecovery,
	RoleRootIntegrity,
}

// File records one immutable regular file without leaking a host path.
type File struct {
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// Input records the canonical public inputs from which the bundle set was
// built. Paths are deliberately excluded from the publication record.
type Input struct {
	Name string `json:"name"`
	File File   `json:"file"`
}

// Fixture records a deterministic rejection case. Hardware observations are
// intentionally not represented by this software-only artifact record.
type Fixture struct {
	SchemaVersion    string        `json:"schema_version"`
	FixtureID        string        `json:"fixture_id"`
	FailureClass     string        `json:"failure_class"`
	Mutation         string        `json:"mutation"`
	OriginalDigest   bundle.Digest `json:"original_digest"`
	TestInputDigest  bundle.Digest `json:"test_input_digest"`
	ExpectedOutcome  string        `json:"expected_outcome"`
	HardwareObserved bool          `json:"hardware_observed"`
}

// Record binds one canonical directory tree to its fixed relative path.
type Record struct {
	Role         Role                 `json:"role"`
	RelativePath string               `json:"relative_path"`
	Digest       bundle.Digest        `json:"digest"`
	SizeBytes    uint64               `json:"size_bytes"`
	Tree         bundle.DirectoryTree `json:"tree"`
}

// Set is the canonical public record for all six RPIBOOT/acceptance trees.
type Set struct {
	SchemaVersion       string        `json:"schema_version"`
	ReleaseIntentDigest bundle.Digest `json:"release_intent_digest"`
	Inputs              []Input       `json:"inputs"`
	Bundles             []Record      `json:"bundles"`
	Fixtures            []Fixture     `json:"fixtures"`
}

// Roles returns a defensive copy of the canonical role order.
func Roles() []Role { return append([]Role(nil), canonicalRoles[:]...) }

func (f File) validate(label string) error {
	if err := f.Digest.Validate(); err != nil {
		return fmt.Errorf("%s.digest: %w", label, err)
	}
	if f.SizeBytes == 0 {
		return fmt.Errorf("%s.size_bytes must be positive", label)
	}
	return nil
}

func (f Fixture) Validate() error {
	if f.SchemaVersion != FixtureSchemaV1Alpha1 {
		return fmt.Errorf("unsupported fixture schema_version %q", f.SchemaVersion)
	}
	if err := f.OriginalDigest.Validate(); err != nil {
		return fmt.Errorf("original_digest: %w", err)
	}
	if err := f.TestInputDigest.Validate(); err != nil {
		return fmt.Errorf("test_input_digest: %w", err)
	}
	if f.OriginalDigest == f.TestInputDigest {
		return errors.New("fixture test input must differ from its original")
	}
	if f.HardwareObserved {
		return errors.New("software bundle construction cannot claim a hardware observation")
	}
	switch f.FixtureID {
	case negativeFixtureID:
		if f.FailureClass != "unauthorized_recovery" || f.Mutation != "replace_customer_counter_signed_recovery_with_unsigned_fresh_recovery" || f.ExpectedOutcome != "owned_rom_rejects_second_stage" {
			return errors.New("unauthorized-recovery fixture fields are not canonical")
		}
	case rootIntegrityFixtureID:
		if f.FailureClass != "root_integrity" || f.Mutation != "flip_first_root_data_byte_keep_hash_tree" || f.ExpectedOutcome != "verity_rejects_root_data" {
			return errors.New("root-integrity fixture fields are not canonical")
		}
	default:
		return fmt.Errorf("unsupported fixture_id %q", f.FixtureID)
	}
	return nil
}

// Validate checks the exact input, role, path, tree and fixture vocabulary.
func (s Set) Validate() error {
	if s.SchemaVersion != SetSchemaV1Alpha1 {
		return fmt.Errorf("unsupported bundle-set schema_version %q", s.SchemaVersion)
	}
	if err := s.ReleaseIntentDigest.Validate(); err != nil {
		return fmt.Errorf("release_intent_digest: %w", err)
	}
	expectedInputs := []string{
		"boot_image", "boot_public_key", "boot_signature", "eeprom_update_metadata",
		"fresh_recovery_bootcode", "owned_recovery_bootcode", "root_data_image",
		"root_hash_tree_image", "signed_eeprom_image",
	}
	if len(s.Inputs) != len(expectedInputs) {
		return fmt.Errorf("inputs must contain exactly %d records", len(expectedInputs))
	}
	for index, input := range s.Inputs {
		if input.Name != expectedInputs[index] {
			return fmt.Errorf("inputs[%d].name must be %q", index, expectedInputs[index])
		}
		if err := input.File.validate(fmt.Sprintf("inputs[%d].file", index)); err != nil {
			return err
		}
	}
	inputFiles := make(map[string]File, len(s.Inputs))
	for _, input := range s.Inputs {
		inputFiles[input.Name] = input.File
	}
	if len(s.Bundles) != len(canonicalRoles) {
		return fmt.Errorf("bundles must contain exactly %d records", len(canonicalRoles))
	}
	for index, record := range s.Bundles {
		expectedRole := canonicalRoles[index]
		if record.Role != expectedRole {
			return fmt.Errorf("bundles[%d].role must be %q", index, expectedRole)
		}
		if record.RelativePath != rolePath(expectedRole) {
			return fmt.Errorf("bundles[%d].relative_path is not canonical", index)
		}
		if err := record.Tree.Validate(); err != nil {
			return fmt.Errorf("bundles[%d].tree: %w", index, err)
		}
		digest, err := record.Tree.Digest()
		if err != nil {
			return fmt.Errorf("bundles[%d].tree digest: %w", index, err)
		}
		size, err := record.Tree.SizeBytes()
		if err != nil {
			return fmt.Errorf("bundles[%d].tree size: %w", index, err)
		}
		if record.Digest != digest || record.SizeBytes != size || size == 0 {
			return fmt.Errorf("bundles[%d] digest or size does not match its tree", index)
		}
		expectedPaths := expectedBundlePaths(expectedRole)
		if len(record.Tree.Entries) != len(expectedPaths) {
			return fmt.Errorf("bundles[%d] does not contain the exact canonical file set", index)
		}
		for entryIndex, entry := range record.Tree.Entries {
			if entry.Path != expectedPaths[entryIndex] || entry.Type != bundle.TreeEntryRegularFile || entry.Mode != "0444" {
				return fmt.Errorf("bundles[%d].tree.entries[%d] is not the expected immutable regular file", index, entryIndex)
			}
		}
	}
	if len(s.Fixtures) != 2 || s.Fixtures[0].FixtureID != negativeFixtureID || s.Fixtures[1].FixtureID != rootIntegrityFixtureID {
		return errors.New("fixtures must contain the two canonical rejection cases in order")
	}
	for index, fixture := range s.Fixtures {
		if err := fixture.Validate(); err != nil {
			return fmt.Errorf("fixtures[%d]: %w", index, err)
		}
	}
	if s.Fixtures[0].OriginalDigest != inputFiles["owned_recovery_bootcode"].Digest ||
		s.Fixtures[0].TestInputDigest != inputFiles["fresh_recovery_bootcode"].Digest ||
		s.Fixtures[1].OriginalDigest != inputFiles["root_data_image"].Digest {
		return errors.New("fixtures do not bind the canonical input records")
	}
	return nil
}

// CanonicalJSON returns the unique whitespace-free bundle-set encoding.
func (s Set) CanonicalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode canonical bundle set: %w", err)
	}
	if len(encoded) > maxSetBytes {
		return nil, fmt.Errorf("canonical bundle set exceeds %d bytes", maxSetBytes)
	}
	return encoded, nil
}

// Digest returns the domain-separated digest of the canonical set record.
func (s Set) Digest() (bundle.Digest, error) {
	encoded, err := s.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-rpiboot-bundle-set.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// ParseSet strictly parses and validates a canonical bundle-set record.
func ParseSet(encoded []byte) (Set, error) {
	if len(encoded) == 0 || len(encoded) > maxSetBytes {
		return Set{}, fmt.Errorf("bundle-set size must be between 1 and %d bytes", maxSetBytes)
	}
	var result Set
	if err := strictDecode(encoded, &result); err != nil {
		return Set{}, fmt.Errorf("decode bundle set: %w", err)
	}
	canonical, err := result.CanonicalJSON()
	if err != nil {
		return Set{}, err
	}
	if !bytes.Equal(encoded, canonical) && !bytes.Equal(encoded, append(append([]byte(nil), canonical...), '\n')) {
		return Set{}, errors.New("bundle set is not canonical JSON")
	}
	return result, nil
}

func canonicalInputs(files map[string]File) []Input {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	inputs := make([]Input, 0, len(names))
	for _, name := range names {
		inputs = append(inputs, Input{Name: name, File: files[name]})
	}
	return inputs
}

func rolePath(role Role) string {
	switch role {
	case RoleFreshCommit:
		return "fresh-commit"
	case RoleFreshReadback:
		return "fresh-readback"
	case RoleNegativeBoot:
		return "negative-boot"
	case RoleOwnedReadback:
		return "owned-readback"
	case RoleOwnedRecovery:
		return "owned-recovery"
	case RoleRootIntegrity:
		return "root-integrity-test"
	default:
		return ""
	}
}

func expectedBundlePaths(role Role) []string {
	switch role {
	case RoleFreshCommit:
		return []string{"bootcode5.bin", "config.txt", "pieeprom.bin", "pieeprom.sig"}
	case RoleFreshReadback, RoleOwnedReadback:
		return []string{"bootcode5.bin", "config.txt"}
	case RoleNegativeBoot:
		return []string{"bootcode5.bin", "config.txt", "fixture.json"}
	case RoleOwnedRecovery:
		return []string{"bootcode5.bin", "config.txt", "pieeprom.bin", "pieeprom.sig"}
	case RoleRootIntegrity:
		return []string{"boot.img", "boot.sig", "bootcode5.bin", "config.txt", "fixture.json", "public.pem", "root-data.tampered.img", "root-hash-tree.img"}
	default:
		return nil
	}
}
