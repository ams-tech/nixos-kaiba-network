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
	SignedReleaseManifestSchemaV1Alpha1 = "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha1"
	SignedReleaseDeviceClassV1Alpha1    = "raspberry-pi-5-model-b-v1alpha1"
)

// MaxSignedReleaseManifestBytes leaves room for six directory trees, each
// bounded independently by MaxDirectoryTreeBytes, plus the regular artifacts.
const MaxSignedReleaseManifestBytes = 64 * 1024 * 1024

var sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// ArtifactKind distinguishes an immutable regular file from a canonical
// directory tree. Directory-tree digests bind the paths and metadata consumed
// by rpiboot -d; they are not byte-file digests of an archive.
type ArtifactKind string

const (
	ArtifactKindRegularFile   ArtifactKind = "regular_file"
	ArtifactKindDirectoryTree ArtifactKind = "directory_tree"
)

// ReleaseArtifact binds one required role in the complete Raspberry Pi 5
// signed release. Tree is present exactly when Kind is directory_tree.
type ReleaseArtifact struct {
	Role      ArtifactRole   `json:"role"`
	Kind      ArtifactKind   `json:"kind"`
	Digest    Digest         `json:"digest"`
	SizeBytes uint64         `json:"size_bytes"`
	Tree      *DirectoryTree `json:"tree,omitempty"`
}

// SignedReleaseManifest is the strict, complete, secret-free release contract
// for the frozen Raspberry Pi 5 Model B development device class.
type SignedReleaseManifest struct {
	SchemaVersion           string            `json:"schema_version"`
	ReleaseID               string            `json:"release_id"`
	DeviceClass             string            `json:"device_class"`
	SourceRevision          string            `json:"source_revision"`
	SigningPolicyDigest     Digest            `json:"signing_policy_digest"`
	ExpectedCustomerKeyHash Digest            `json:"expected_customer_key_hash"`
	Artifacts               []ReleaseArtifact `json:"artifacts"`
}

var signedReleaseRoles = [...]ArtifactRole{
	RoleBootPublicKey,
	RoleDeviceProfile,
	RolePlatformAdapter,
	RoleRootIntegrity,
	RoleBootImage,
	RoleBootSignature,
	RoleEEPROMBootsys,
	RoleEEPROMConfig,
	RoleFreshCommitBundle,
	RoleFreshReadbackBundle,
	RoleNegativeBootBundle,
	RoleOwnedReadbackBundle,
	RoleOwnedRecoveryBootcode,
	RoleOwnedRecoveryBundle,
	RoleRootDataImage,
	RoleRootHashTreeImage,
	RoleRootIntegrityTestBundle,
	RoleSignedEEPROMImage,
}

var signedReleaseTreeRoles = map[ArtifactRole]struct{}{
	RoleFreshCommitBundle:       {},
	RoleFreshReadbackBundle:     {},
	RoleNegativeBootBundle:      {},
	RoleOwnedReadbackBundle:     {},
	RoleOwnedRecoveryBundle:     {},
	RoleRootIntegrityTestBundle: {},
}

// SignedReleaseRoles returns the exact complete role set in canonical order.
func SignedReleaseRoles() []ArtifactRole {
	return append([]ArtifactRole(nil), signedReleaseRoles[:]...)
}

// NewSignedReleaseManifest copies and sorts artifacts into canonical role
// order, fixes the schema and device class, and validates the complete release.
func NewSignedReleaseManifest(
	releaseID string,
	sourceRevision string,
	signingPolicyDigest Digest,
	expectedCustomerKeyHash Digest,
	artifacts []ReleaseArtifact,
) (SignedReleaseManifest, error) {
	canonicalArtifacts := cloneReleaseArtifacts(artifacts)
	sort.Slice(canonicalArtifacts, func(i, j int) bool {
		return canonicalArtifacts[i].Role < canonicalArtifacts[j].Role
	})
	manifest := SignedReleaseManifest{
		SchemaVersion:           SignedReleaseManifestSchemaV1Alpha1,
		ReleaseID:               releaseID,
		DeviceClass:             SignedReleaseDeviceClassV1Alpha1,
		SourceRevision:          sourceRevision,
		SigningPolicyDigest:     signingPolicyDigest,
		ExpectedCustomerKeyHash: expectedCustomerKeyHash,
		Artifacts:               canonicalArtifacts,
	}
	if err := manifest.Validate(); err != nil {
		return SignedReleaseManifest{}, err
	}
	return manifest, nil
}

// ParseSignedReleaseManifest strictly parses and validates a complete signed
// release. Unknown fields, duplicate object keys, trailing JSON values, and all
// incomplete or non-canonical artifact sets are rejected.
func ParseSignedReleaseManifest(data []byte) (SignedReleaseManifest, error) {
	if len(data) == 0 || len(data) > MaxSignedReleaseManifestBytes {
		return SignedReleaseManifest{}, fmt.Errorf(
			"signed-release manifest size must be between 1 and %d bytes",
			MaxSignedReleaseManifestBytes,
		)
	}
	if err := rejectDirectoryTreeNulls(data); err != nil {
		return SignedReleaseManifest{}, fmt.Errorf("decode signed-release manifest: %w", err)
	}
	var manifest SignedReleaseManifest
	if err := strictDecode(data, &manifest); err != nil {
		return SignedReleaseManifest{}, fmt.Errorf("decode signed-release manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return SignedReleaseManifest{}, err
	}
	return manifest, nil
}

// Validate enforces the exact role set, canonical order, artifact kinds, and
// every embedded directory-tree digest and size binding.
func (m SignedReleaseManifest) Validate() error {
	if m.SchemaVersion != SignedReleaseManifestSchemaV1Alpha1 {
		return fmt.Errorf("unsupported signed-release manifest schema_version %q", m.SchemaVersion)
	}
	if !identifierPattern.MatchString(m.ReleaseID) {
		return errors.New("release_id must be a canonical lower-case identifier")
	}
	if m.DeviceClass != SignedReleaseDeviceClassV1Alpha1 {
		return fmt.Errorf("device_class must be %q", SignedReleaseDeviceClassV1Alpha1)
	}
	if !sourceRevisionPattern.MatchString(m.SourceRevision) {
		return errors.New("source_revision must contain exactly 40 or 64 lower-case hexadecimal characters")
	}
	if err := m.SigningPolicyDigest.Validate(); err != nil {
		return fmt.Errorf("signing_policy_digest: %w", err)
	}
	if err := m.ExpectedCustomerKeyHash.Validate(); err != nil {
		return fmt.Errorf("expected_customer_key_hash: %w", err)
	}
	if len(m.Artifacts) != len(signedReleaseRoles) {
		return fmt.Errorf("artifacts must contain exactly %d entries", len(signedReleaseRoles))
	}

	seen := make(map[ArtifactRole]struct{}, len(m.Artifacts))
	for index, artifact := range m.Artifacts {
		if err := artifact.Role.Validate(); err != nil {
			return fmt.Errorf("artifacts[%d].role: %w", index, err)
		}
		if _, exists := seen[artifact.Role]; exists {
			return fmt.Errorf("artifact role %q is duplicated", artifact.Role)
		}
		seen[artifact.Role] = struct{}{}
		if expected := signedReleaseRoles[index]; artifact.Role != expected {
			return fmt.Errorf("artifacts[%d].role must be %q", index, expected)
		}
		if err := artifact.validate(index); err != nil {
			return err
		}
	}
	return nil
}

func (a ReleaseArtifact) validate(index int) error {
	if err := a.Digest.Validate(); err != nil {
		return fmt.Errorf("artifacts[%d].digest: %w", index, err)
	}
	if a.SizeBytes == 0 {
		return fmt.Errorf("artifacts[%d].size_bytes must be positive", index)
	}
	_, isTreeRole := signedReleaseTreeRoles[a.Role]
	if !isTreeRole {
		if a.Kind != ArtifactKindRegularFile {
			return fmt.Errorf("artifacts[%d].kind must be %q", index, ArtifactKindRegularFile)
		}
		if a.Tree != nil {
			return fmt.Errorf("artifacts[%d].tree must be absent for a regular-file role", index)
		}
		return nil
	}
	if a.Kind != ArtifactKindDirectoryTree {
		return fmt.Errorf("artifacts[%d].kind must be %q", index, ArtifactKindDirectoryTree)
	}
	if a.Tree == nil {
		return fmt.Errorf("artifacts[%d].tree is required for a directory-tree role", index)
	}
	if err := a.Tree.Validate(); err != nil {
		return fmt.Errorf("artifacts[%d].tree: %w", index, err)
	}
	treeDigest, err := a.Tree.Digest()
	if err != nil {
		return fmt.Errorf("artifacts[%d].tree digest: %w", index, err)
	}
	if treeDigest != a.Digest {
		return fmt.Errorf("artifacts[%d].digest does not match the embedded directory tree", index)
	}
	treeSize, err := a.Tree.SizeBytes()
	if err != nil {
		return fmt.Errorf("artifacts[%d].tree size: %w", index, err)
	}
	if treeSize == 0 {
		return fmt.Errorf("artifacts[%d].tree must contain positive file content", index)
	}
	if treeSize != a.SizeBytes {
		return fmt.Errorf("artifacts[%d].size_bytes does not match the embedded directory tree", index)
	}
	return nil
}

// CanonicalJSON returns the deterministic, whitespace-free representation used
// to identify this signed release.
func (m SignedReleaseManifest) CanonicalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode canonical signed-release manifest: %w", err)
	}
	return encoded, nil
}

// Digest returns the domain-separated digest of the canonical signed release.
func (m SignedReleaseManifest) Digest() (Digest, error) {
	canonical, err := m.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-signed-release-manifest.v1alpha1\x00"))
	_, _ = hash.Write(canonical)
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func cloneReleaseArtifacts(artifacts []ReleaseArtifact) []ReleaseArtifact {
	cloned := append([]ReleaseArtifact(nil), artifacts...)
	for index := range cloned {
		if cloned[index].Tree == nil {
			continue
		}
		tree := *cloned[index].Tree
		tree.Entries = append([]TreeEntry(nil), tree.Entries...)
		cloned[index].Tree = &tree
	}
	return cloned
}
