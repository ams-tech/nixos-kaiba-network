// Package releaseintent defines the canonical, pre-signature authorization
// boundary for one complete Raspberry Pi 5 signed release.
package releaseintent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	SchemaV1Alpha1            = "kaiba.provisioning.rpi5-release-intent/v1alpha1"
	DeviceClassV1Alpha1       = "raspberry-pi-5-model-b-v1alpha1"
	ScopeCohortRelease        = "cohort_release"
	MaxBytes                  = 64 * 1024
	MaxSigningInputBytes      = 96 * 1024 * 1024
	maximumSourceDateEpoch    = 253402300799
	releaseIntentDigestDomain = "kaiba.provisioning.rpi5-release-intent.v1alpha1"
)

var (
	identifierPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	signingInputRoles     = [...]bundle.ArtifactRole{
		bundle.RoleBootImage,
		bundle.RoleEEPROMBootcode,
		bundle.RoleEEPROMBootsys,
		bundle.RoleEEPROMConfig,
		bundle.RoleOwnedRecoveryBootcode,
	}
)

// Parameters are the caller-supplied fields used to construct an Intent. New
// fixes all versioned constants and canonical role sets itself.
type Parameters struct {
	ReleaseID                   string
	SourceRevision              string
	SourceDateEpoch             uint64
	UnsignedArtifactSetDigest   bundle.Digest
	EEPROMReleaseManifestDigest bundle.Digest
	PublicKeyFingerprint        bundle.Digest
	SigningPolicyDigest         bundle.Digest
	ExpectedCustomerKeyHash     bundle.Digest
	SigningInputs               []bundle.Artifact
}

// Intent binds every private-key input to the public release sources and
// fixes the complete set of outputs that must exist before lane authorization.
// It is intentionally cohort-scoped: the current device transaction digest
// already depends on the final signed-release manifest and therefore cannot be
// included here without reintroducing a signing cycle.
type Intent struct {
	SchemaVersion               string                `json:"schema_version"`
	ReleaseID                   string                `json:"release_id"`
	DeviceClass                 string                `json:"device_class"`
	SourceRevision              string                `json:"source_revision"`
	SourceDateEpoch             uint64                `json:"source_date_epoch"`
	UnsignedArtifactSetDigest   bundle.Digest         `json:"unsigned_artifact_set_digest"`
	EEPROMReleaseManifestDigest bundle.Digest         `json:"eeprom_release_manifest_digest"`
	PublicKeyFingerprint        bundle.Digest         `json:"public_key_fingerprint"`
	SigningPolicyDigest         bundle.Digest         `json:"signing_policy_digest"`
	ExpectedCustomerKeyHash     bundle.Digest         `json:"expected_customer_key_hash"`
	AuthorizationScope          string                `json:"authorization_scope"`
	SigningInputs               []bundle.Artifact     `json:"signing_inputs"`
	RequiredOutputRoles         []bundle.ArtifactRole `json:"required_output_roles"`
}

// New copies and canonicalizes caller-owned signing inputs, fixes the exact
// final output role set, and applies the same validation used for parsed data.
func New(parameters Parameters) (Intent, error) {
	inputs := append([]bundle.Artifact(nil), parameters.SigningInputs...)
	sort.Slice(inputs, func(left, right int) bool {
		return inputs[left].Role < inputs[right].Role
	})
	intent := Intent{
		SchemaVersion:               SchemaV1Alpha1,
		ReleaseID:                   parameters.ReleaseID,
		DeviceClass:                 DeviceClassV1Alpha1,
		SourceRevision:              parameters.SourceRevision,
		SourceDateEpoch:             parameters.SourceDateEpoch,
		UnsignedArtifactSetDigest:   parameters.UnsignedArtifactSetDigest,
		EEPROMReleaseManifestDigest: parameters.EEPROMReleaseManifestDigest,
		PublicKeyFingerprint:        parameters.PublicKeyFingerprint,
		SigningPolicyDigest:         parameters.SigningPolicyDigest,
		ExpectedCustomerKeyHash:     parameters.ExpectedCustomerKeyHash,
		AuthorizationScope:          ScopeCohortRelease,
		SigningInputs:               inputs,
		RequiredOutputRoles:         bundle.SignedReleaseRoles(),
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// Parse strictly decodes and validates one bounded release intent. Unknown
// fields, duplicate keys, JSON nulls, trailing values, non-canonical role
// order, and unsupported versions are rejected.
func Parse(data []byte) (Intent, error) {
	if len(data) == 0 || len(data) > MaxBytes {
		return Intent{}, fmt.Errorf("release intent size must be between 1 and %d bytes", MaxBytes)
	}
	if err := rejectJSONNulls(data); err != nil {
		return Intent{}, fmt.Errorf("decode release intent: %w", err)
	}
	var intent Intent
	if err := strictDecode(data, &intent); err != nil {
		return Intent{}, fmt.Errorf("decode release intent: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// Validate enforces the complete v1alpha1 identity, digest, signing-input, and
// required-output contract.
func (intent Intent) Validate() error {
	if intent.SchemaVersion != SchemaV1Alpha1 {
		return fmt.Errorf("unsupported release intent schema_version %q", intent.SchemaVersion)
	}
	if !identifierPattern.MatchString(intent.ReleaseID) {
		return errors.New("release_id must be a canonical lower-case identifier")
	}
	if intent.DeviceClass != DeviceClassV1Alpha1 {
		return fmt.Errorf("device_class must be %q", DeviceClassV1Alpha1)
	}
	if !sourceRevisionPattern.MatchString(intent.SourceRevision) {
		return errors.New("source_revision must contain exactly 40 or 64 lower-case hexadecimal characters")
	}
	if intent.SourceDateEpoch == 0 || intent.SourceDateEpoch > maximumSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must be between 1 and %d", maximumSourceDateEpoch)
	}
	for name, digest := range map[string]bundle.Digest{
		"unsigned_artifact_set_digest":   intent.UnsignedArtifactSetDigest,
		"eeprom_release_manifest_digest": intent.EEPROMReleaseManifestDigest,
		"public_key_fingerprint":         intent.PublicKeyFingerprint,
		"signing_policy_digest":          intent.SigningPolicyDigest,
		"expected_customer_key_hash":     intent.ExpectedCustomerKeyHash,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if intent.AuthorizationScope != ScopeCohortRelease {
		return fmt.Errorf("authorization_scope must be %q", ScopeCohortRelease)
	}
	if len(intent.SigningInputs) != len(signingInputRoles) {
		return fmt.Errorf("signing_inputs must contain exactly %d entries", len(signingInputRoles))
	}
	for index, input := range intent.SigningInputs {
		if input.Role != signingInputRoles[index] {
			return fmt.Errorf("signing_inputs[%d].role must be %q", index, signingInputRoles[index])
		}
		if err := input.Role.Validate(); err != nil {
			return fmt.Errorf("signing_inputs[%d].role: %w", index, err)
		}
		if !input.Role.Signable() {
			return fmt.Errorf("signing_inputs[%d].role %q is not signable", index, input.Role)
		}
		if err := input.Digest.Validate(); err != nil {
			return fmt.Errorf("signing_inputs[%d].digest: %w", index, err)
		}
		if input.SizeBytes == 0 || input.SizeBytes > MaxSigningInputBytes {
			return fmt.Errorf("signing_inputs[%d].size_bytes must be between 1 and %d", index, MaxSigningInputBytes)
		}
	}

	expectedOutputs := bundle.SignedReleaseRoles()
	if len(intent.RequiredOutputRoles) != len(expectedOutputs) {
		return fmt.Errorf("required_output_roles must contain exactly %d entries", len(expectedOutputs))
	}
	for index, role := range intent.RequiredOutputRoles {
		if role != expectedOutputs[index] {
			return fmt.Errorf("required_output_roles[%d] must be %q", index, expectedOutputs[index])
		}
		if err := role.Validate(); err != nil {
			return fmt.Errorf("required_output_roles[%d]: %w", index, err)
		}
	}
	return nil
}

// CanonicalJSON returns the fixed-order, whitespace-free representation
// covered by Digest.
func (intent Intent) CanonicalJSON() ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, fmt.Errorf("encode canonical release intent: %w", err)
	}
	if len(encoded) > MaxBytes {
		return nil, fmt.Errorf("canonical release intent exceeds %d bytes", MaxBytes)
	}
	return encoded, nil
}

// Digest returns the domain-separated identity of the canonical release
// intent. It deliberately exists before any signature or lane plan.
func (intent Intent) Digest() (bundle.Digest, error) {
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(releaseIntentDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// SigningInput returns the exact approved input record for role.
func (intent Intent) SigningInput(role bundle.ArtifactRole) (bundle.Artifact, bool) {
	for _, input := range intent.SigningInputs {
		if input.Role == role {
			return input, true
		}
	}
	return bundle.Artifact{}, false
}

// SigningInputRoles returns the exact signing-input vocabulary in canonical
// order without exposing the package's backing array.
func SigningInputRoles() []bundle.ArtifactRole {
	return append([]bundle.ArtifactRole(nil), signingInputRoles[:]...)
}
