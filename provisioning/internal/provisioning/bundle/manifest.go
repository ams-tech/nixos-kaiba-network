package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const (
	ManifestSchemaV1Alpha1 = "kaiba.provisioning.secure-boot-bundle/v1alpha1"
	MaxManifestBytes       = 256 * 1024
	maxArtifacts           = 64
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// Artifact is one immutable, content-addressed input or output in a secure-boot
// bundle. Role is unique within a manifest.
type Artifact struct {
	Role      ArtifactRole `json:"role"`
	Digest    Digest       `json:"digest"`
	SizeBytes uint64       `json:"size_bytes"`
}

// Manifest is the strict, secret-free description of a secure-boot artifact
// set. It contains digests, never executable paths, private-key paths, PINs, or
// artifact bytes.
type Manifest struct {
	SchemaVersion       string     `json:"schema_version"`
	ManifestID          string     `json:"manifest_id"`
	DeviceClass         string     `json:"device_class"`
	SigningPolicyDigest Digest     `json:"signing_policy_digest"`
	Artifacts           []Artifact `json:"artifacts"`
}

// ParseManifest strictly parses a manifest. Unknown fields, duplicate object
// keys, trailing values, unsupported schema versions, duplicate roles, and
// non-canonical values are rejected.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest size must be between 1 and %d bytes", MaxManifestBytes)
	}
	var manifest Manifest
	if err := strictDecode(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode secure-boot bundle manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate checks all semantic and canonical-form constraints.
func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaV1Alpha1 {
		return fmt.Errorf("unsupported manifest schema_version %q", m.SchemaVersion)
	}
	if !identifierPattern.MatchString(m.ManifestID) {
		return errors.New("manifest_id must be a canonical lower-case identifier")
	}
	if !identifierPattern.MatchString(m.DeviceClass) {
		return errors.New("device_class must be a canonical lower-case identifier")
	}
	if err := m.SigningPolicyDigest.Validate(); err != nil {
		return fmt.Errorf("signing_policy_digest: %w", err)
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > maxArtifacts {
		return fmt.Errorf("artifacts must contain between 1 and %d entries", maxArtifacts)
	}
	seen := make(map[ArtifactRole]struct{}, len(m.Artifacts))
	var previous ArtifactRole
	for index, artifact := range m.Artifacts {
		if err := artifact.Role.Validate(); err != nil {
			return fmt.Errorf("artifacts[%d].role: %w", index, err)
		}
		if _, exists := seen[artifact.Role]; exists {
			return fmt.Errorf("artifact role %q is duplicated", artifact.Role)
		}
		seen[artifact.Role] = struct{}{}
		if index > 0 && artifact.Role <= previous {
			return errors.New("artifacts must be sorted by role in strictly increasing order")
		}
		previous = artifact.Role
		if err := artifact.Digest.Validate(); err != nil {
			return fmt.Errorf("artifacts[%d].digest: %w", index, err)
		}
		if artifact.SizeBytes == 0 {
			return fmt.Errorf("artifacts[%d].size_bytes must be positive", index)
		}
	}
	return nil
}

// NewManifest returns a manifest with artifacts copied and sorted into the
// canonical role order. It then applies the same validation as parsed input.
func NewManifest(id, deviceClass string, policyDigest Digest, artifacts []Artifact) (Manifest, error) {
	canonicalArtifacts := append([]Artifact(nil), artifacts...)
	sort.Slice(canonicalArtifacts, func(i, j int) bool {
		return canonicalArtifacts[i].Role < canonicalArtifacts[j].Role
	})
	manifest := Manifest{
		SchemaVersion:       ManifestSchemaV1Alpha1,
		ManifestID:          id,
		DeviceClass:         deviceClass,
		SigningPolicyDigest: policyDigest,
		Artifacts:           canonicalArtifacts,
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// CanonicalJSON returns the deterministic JSON representation used for bundle
// identity. A trailing newline and transport whitespace are deliberately not
// part of the representation.
func (m Manifest) CanonicalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode canonical manifest: %w", err)
	}
	return encoded, nil
}

// Digest returns a domain-separated digest of the canonical manifest.
func (m Manifest) Digest() (Digest, error) {
	canonical, err := m.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.secure-boot-bundle.v1alpha1\x00"))
	_, _ = hash.Write(canonical)
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
