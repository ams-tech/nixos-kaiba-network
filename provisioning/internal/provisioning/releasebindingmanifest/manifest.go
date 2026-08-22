// Package releasebindingmanifest derives the content identities used by a
// physical lane's immutable release binding. It contains no signing, approval,
// device, or execution authority.
package releasebindingmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	CompiledArtifactSetSchemaV1Alpha1 = "kaiba.provisioning.rpi5-compiled-artifact-set/v1alpha1"
	LaneGuardPackageSchemaV1Alpha1    = "kaiba.provisioning.rpi5-lane-guard-package/v1alpha1"

	MaxManifestBytes = 128 * 1024

	compiledArtifactSetDigestDomain = "kaiba.provisioning.rpi5-compiled-artifact-set.v1alpha1"
	laneGuardPackageDigestDomain    = "kaiba.provisioning.rpi5-lane-guard-package.v1alpha1"
	maximumArtifactPathBytes        = 4096
)

// ValidationMode makes the non-production path escape hatch explicit. A zero
// value is invalid so a caller cannot accidentally weaken the production
// boundary by omitting the mode.
type ValidationMode uint8

const (
	DevelopmentMode ValidationMode = iota + 1
	ProductionMode
)

// ArtifactRole is the closed vocabulary consumed by the current physical
// Raspberry Pi 5 lane. Adding a runtime input requires a new schema version.
type ArtifactRole string

const (
	RolePatchedRPIBoot      ArtifactRole = "rpi5.patched_rpiboot_binary"
	RoleGPIOSet             ArtifactRole = "rpi5.gpio_set_binary"
	RoleFreshCommitBundle   ArtifactRole = "rpi5.fresh_commit_bundle"
	RoleFreshReadbackBundle ArtifactRole = "rpi5.fresh_readback_bundle"
	RoleNegativeBootBundle  ArtifactRole = "rpi5.negative_boot_bundle"
	RoleOwnedReadbackBundle ArtifactRole = "rpi5.owned_readback_bundle"
	RoleOwnedRecoveryBundle ArtifactRole = "rpi5.owned_recovery_bundle"
	RoleRootIntegrityBundle ArtifactRole = "rpi5.root_integrity_test_bundle"
	RoleLaneGuardExecutable ArtifactRole = "rpi5.lane_guard_executable"
)

var compiledArtifactRoles = [...]ArtifactRole{
	RolePatchedRPIBoot,
	RoleGPIOSet,
	RoleFreshCommitBundle,
	RoleFreshReadbackBundle,
	RoleNegativeBootBundle,
	RoleOwnedReadbackBundle,
	RoleOwnedRecoveryBundle,
	RoleRootIntegrityBundle,
}

// ArtifactType determines how Digest was derived. A regular-file digest is
// SHA-256 over its exact bytes. A directory-tree digest is bundle.DirectoryTree
// material, which also covers every descendant path, type, mode, size, and
// regular-file digest.
type ArtifactType string

const (
	ArtifactRegularFile   ArtifactType = "regular_file"
	ArtifactDirectoryTree ArtifactType = "directory_tree"
)

var nixStorePathPattern = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+(?:/.*)?$`)

// ArtifactPath is an untrusted path assignment supplied to the snapshot
// constructor. Type and content metadata are derived rather than accepted from
// the caller.
type ArtifactPath struct {
	Role ArtifactRole
	Path string
}

// Artifact binds one exact runtime path to its observed filesystem type,
// permission mode, logical byte size, and content identity.
type Artifact struct {
	Role      ArtifactRole  `json:"role"`
	Path      string        `json:"path"`
	Type      ArtifactType  `json:"type"`
	Mode      string        `json:"mode"`
	SizeBytes uint64        `json:"size_bytes"`
	Digest    bundle.Digest `json:"digest"`
}

// ReleaseExpectations are the independently published release values covered
// by the lane-guard package identity and returned in the derived binding.
type ReleaseExpectations struct {
	SignedReleaseManifestDigest bundle.Digest `json:"signed_release_manifest_digest"`
	ExpectedCustomerKeyHash     bundle.Digest `json:"expected_customer_key_hash"`
	ExpectedEEPROMDigest        bundle.Digest `json:"expected_eeprom_digest"`
	ExpectedBootImageDigest     bundle.Digest `json:"expected_boot_image_digest"`
}

// CompiledArtifactSet is the canonical record of every immutable runtime
// artifact selected by the physical lane build.
type CompiledArtifactSet struct {
	SchemaVersion string     `json:"schema_version"`
	Artifacts     []Artifact `json:"artifacts"`
}

// LaneGuardPackage is deliberately acyclic: it covers the actual executable,
// the compiled-artifact-set digest, and the release expectations, but it
// has no lane-guard-package-digest field. Its own digest is derived only after
// the executable exists.
type LaneGuardPackage struct {
	SchemaVersion             string              `json:"schema_version"`
	Executable                Artifact            `json:"executable"`
	CompiledArtifactSetDigest bundle.Digest       `json:"compiled_artifact_set_digest"`
	Release                   ReleaseExpectations `json:"release"`
}

// CompiledArtifactRoles returns the exact v1alpha1 role order.
func CompiledArtifactRoles() []ArtifactRole {
	return append([]ArtifactRole(nil), compiledArtifactRoles[:]...)
}

// Validate checks all release digests.
func (expectations ReleaseExpectations) Validate() error {
	for _, field := range []struct {
		name   string
		digest bundle.Digest
	}{
		{"signed_release_manifest_digest", expectations.SignedReleaseManifestDigest},
		{"expected_customer_key_hash", expectations.ExpectedCustomerKeyHash},
		{"expected_eeprom_digest", expectations.ExpectedEEPROMDigest},
		{"expected_boot_image_digest", expectations.ExpectedBootImageDigest},
	} {
		if err := field.digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
	}
	return nil
}

// Validate checks one artifact's canonical role, path, type, mode, size, and
// digest. It does not touch the filesystem; Verify performs that comparison.
func (artifact Artifact) Validate(mode ValidationMode) error {
	expectedType, ok := expectedArtifactType(artifact.Role)
	if !ok {
		return fmt.Errorf("unsupported artifact role %q", artifact.Role)
	}
	if artifact.Type != expectedType {
		return fmt.Errorf("role %q must use artifact type %q", artifact.Role, expectedType)
	}
	if err := validateArtifactPath(artifact.Path, mode); err != nil {
		return err
	}
	permission, err := parseMode(artifact.Mode)
	if err != nil {
		return err
	}
	if permission&0o111 == 0 {
		return errors.New("artifact mode must include an execute/search permission")
	}
	if artifact.SizeBytes == 0 {
		return errors.New("artifact size_bytes must be positive")
	}
	if err := artifact.Digest.Validate(); err != nil {
		return fmt.Errorf("artifact digest: %w", err)
	}
	return nil
}

// Validate checks the exact closed role order and rejects duplicate paths.
func (manifest CompiledArtifactSet) Validate(mode ValidationMode) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	if manifest.SchemaVersion != CompiledArtifactSetSchemaV1Alpha1 {
		return fmt.Errorf("unsupported compiled artifact-set schema_version %q", manifest.SchemaVersion)
	}
	if len(manifest.Artifacts) != len(compiledArtifactRoles) {
		return fmt.Errorf("artifacts must contain exactly %d records", len(compiledArtifactRoles))
	}
	paths := make(map[string]struct{}, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		if artifact.Role != compiledArtifactRoles[index] {
			return fmt.Errorf("artifacts[%d].role must be %q", index, compiledArtifactRoles[index])
		}
		if err := artifact.Validate(mode); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", index, err)
		}
		if _, duplicate := paths[artifact.Path]; duplicate {
			return fmt.Errorf("artifacts[%d].path duplicates another artifact path", index)
		}
		paths[artifact.Path] = struct{}{}
	}
	return nil
}

// CanonicalJSON returns the unique fixed-order JSON covered by Digest.
func (manifest CompiledArtifactSet) CanonicalJSON(mode ValidationMode) ([]byte, error) {
	if err := manifest.Validate(mode); err != nil {
		return nil, err
	}
	return marshalBounded("compiled artifact set", manifest)
}

// Digest derives the compiled-artifact-set identity from canonical manifest
// material. The caller cannot supply this value to the constructor.
func (manifest CompiledArtifactSet) Digest(mode ValidationMode) (bundle.Digest, error) {
	canonical, err := manifest.CanonicalJSON(mode)
	if err != nil {
		return "", err
	}
	return domainDigest(compiledArtifactSetDigestDomain, canonical), nil
}

// Validate checks the acyclic package material and its production path policy.
func (manifest LaneGuardPackage) Validate(mode ValidationMode) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	if manifest.SchemaVersion != LaneGuardPackageSchemaV1Alpha1 {
		return fmt.Errorf("unsupported lane-guard package schema_version %q", manifest.SchemaVersion)
	}
	if manifest.Executable.Role != RoleLaneGuardExecutable {
		return fmt.Errorf("executable.role must be %q", RoleLaneGuardExecutable)
	}
	if err := manifest.Executable.Validate(mode); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if err := manifest.CompiledArtifactSetDigest.Validate(); err != nil {
		return fmt.Errorf("compiled_artifact_set_digest: %w", err)
	}
	if err := manifest.Release.Validate(); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	return nil
}

// CanonicalJSON returns the package digest material. No field can contain the
// digest returned by Digest, avoiding a fixed-point/self-reference problem.
func (manifest LaneGuardPackage) CanonicalJSON(mode ValidationMode) ([]byte, error) {
	if err := manifest.Validate(mode); err != nil {
		return nil, err
	}
	return marshalBounded("lane-guard package", manifest)
}

// Digest derives the package identity only from the already-built executable,
// compiled artifact set, and release expectations.
func (manifest LaneGuardPackage) Digest(mode ValidationMode) (bundle.Digest, error) {
	canonical, err := manifest.CanonicalJSON(mode)
	if err != nil {
		return "", err
	}
	return domainDigest(laneGuardPackageDigestDomain, canonical), nil
}

// DeriveBinding reopens and verifies every covered path, checks that the
// package binds the supplied compiled manifest, and returns the six-field lane
// release binding. Production callers should always pass ProductionMode.
func DeriveBinding(compiled CompiledArtifactSet, laneGuard LaneGuardPackage, mode ValidationMode) (releasebinding.Binding, error) {
	if err := compiled.Verify(mode); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("verify compiled artifact set: %w", err)
	}
	if err := laneGuard.Verify(mode); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("verify lane-guard package: %w", err)
	}
	return deriveBindingFromValidatedManifests(compiled, laneGuard, mode)
}

// deriveBindingFromValidatedManifests performs the filesystem-free portion of
// DeriveBinding. SnapshotProductionReleaseMaterial may use it because that
// constructor has just observed production-only /nix/store paths, whose
// immutability closes the gap between its sequential snapshots.
func deriveBindingFromValidatedManifests(compiled CompiledArtifactSet, laneGuard LaneGuardPackage, mode ValidationMode) (releasebinding.Binding, error) {
	if err := compiled.Validate(mode); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("validate compiled artifact set: %w", err)
	}
	if err := laneGuard.Validate(mode); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("validate lane-guard package: %w", err)
	}
	if err := rejectLaneGuardPathCollision(compiled, laneGuard.Executable.Path); err != nil {
		return releasebinding.Binding{}, err
	}
	compiledDigest, err := compiled.Digest(mode)
	if err != nil {
		return releasebinding.Binding{}, err
	}
	if laneGuard.CompiledArtifactSetDigest != compiledDigest {
		return releasebinding.Binding{}, errors.New("lane-guard package does not bind the compiled artifact set")
	}
	laneGuardDigest, err := laneGuard.Digest(mode)
	if err != nil {
		return releasebinding.Binding{}, err
	}
	binding := releasebinding.Binding{
		SignedReleaseManifestDigest: string(laneGuard.Release.SignedReleaseManifestDigest),
		LaneGuardPackageDigest:      string(laneGuardDigest),
		CompiledArtifactSetDigest:   string(compiledDigest),
		ExpectedCustomerKeyHash:     string(laneGuard.Release.ExpectedCustomerKeyHash),
		ExpectedEEPROMDigest:        string(laneGuard.Release.ExpectedEEPROMDigest),
		ExpectedBootImageDigest:     string(laneGuard.Release.ExpectedBootImageDigest),
	}
	if err := binding.Validate(); err != nil {
		return releasebinding.Binding{}, fmt.Errorf("derived release binding: %w", err)
	}
	return binding, nil
}

func marshalBounded(label string, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical %s: %w", label, err)
	}
	if len(encoded) > MaxManifestBytes {
		return nil, fmt.Errorf("canonical %s exceeds %d bytes", label, MaxManifestBytes)
	}
	return encoded, nil
}

func domainDigest(domain string, canonical []byte) bundle.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func validateMode(mode ValidationMode) error {
	if mode != DevelopmentMode && mode != ProductionMode {
		return errors.New("validation mode must be DevelopmentMode or ProductionMode")
	}
	return nil
}

func expectedArtifactType(role ArtifactRole) (ArtifactType, bool) {
	switch role {
	case RolePatchedRPIBoot, RoleGPIOSet, RoleLaneGuardExecutable:
		return ArtifactRegularFile, true
	case RoleFreshCommitBundle, RoleFreshReadbackBundle, RoleNegativeBootBundle,
		RoleOwnedReadbackBundle, RoleOwnedRecoveryBundle, RoleRootIntegrityBundle:
		return ArtifactDirectoryTree, true
	default:
		return "", false
	}
}

func validateArtifactPath(value string, mode ValidationMode) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	if value == "" || value == string(filepath.Separator) || len(value) > maximumArtifactPathBytes ||
		!utf8.ValidString(value) || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		strings.IndexByte(value, 0) >= 0 || strings.Contains(value, `\`) {
		return fmt.Errorf("artifact path must be a clean absolute UTF-8 path other than / of at most %d bytes", maximumArtifactPathBytes)
	}
	if mode == ProductionMode && !nixStorePathPattern.MatchString(value) {
		return errors.New("artifact path must be in /nix/store in production mode")
	}
	return nil
}

func parseMode(value string) (uint64, error) {
	if len(value) != 4 || value[0] != '0' {
		return 0, errors.New("artifact mode must be a canonical four-character octal mode")
	}
	parsed, err := strconv.ParseUint(value[1:], 8, 9)
	if err != nil {
		return 0, errors.New("artifact mode must be a canonical four-character octal mode")
	}
	return parsed, nil
}
