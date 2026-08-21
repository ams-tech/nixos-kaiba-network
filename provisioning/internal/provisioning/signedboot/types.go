// Package signedboot implements the host-side, non-mutating Raspberry Pi 5
// boot-image signing workflow. Private-key authority remains behind the fixed
// signing gate; this package only handles public plans, signatures, and bundles.
package signedboot

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	PlanSchemaV1Alpha1   = "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1"
	ResultSchemaV1Alpha1 = "kaiba.provisioning.rpi5-boot-signing-result/v1alpha1"

	maxPlanBytes              = 64 * 1024
	maxResultBytes            = 64 * 1024
	maxPublicKeyBytes         = 16 * 1024
	maxBootSigBytes           = 4 * 1024
	maxSourceDateEpoch uint64 = 253402300799
)

var planIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// Plan is the complete immutable public input to one boot-image signature.
// Its digest is canonical and domain separated; filesystem paths and private
// key selectors are deliberately absent.
type Plan struct {
	SchemaVersion        string        `json:"schema_version"`
	PlanID               string        `json:"plan_id"`
	BootImageDigest      bundle.Digest `json:"boot_image_digest"`
	BootImageSizeBytes   uint64        `json:"boot_image_size_bytes"`
	PublicKeyFingerprint bundle.Digest `json:"public_key_fingerprint"`
	SignerPolicyDigest   bundle.Digest `json:"signer_policy_digest"`
	SourceDateEpoch      uint64        `json:"source_date_epoch"`
}

// Result correlates the signing-gate receipt digest and canonical Raspberry Pi
// boot.sig artifact with the exact plan and public signer policy used by the
// adapter. Offline finalization validates this binding but does not claim to
// authenticate the separate gate receipt from its digest alone.
type Result struct {
	SchemaVersion          string        `json:"schema_version"`
	PlanID                 string        `json:"plan_id"`
	PlanDigest             bundle.Digest `json:"plan_digest"`
	BootImageDigest        bundle.Digest `json:"boot_image_digest"`
	BootImageSizeBytes     uint64        `json:"boot_image_size_bytes"`
	BootSignatureDigest    bundle.Digest `json:"boot_signature_digest"`
	BootSignatureSizeBytes uint64        `json:"boot_signature_size_bytes"`
	PublicKeyFingerprint   bundle.Digest `json:"public_key_fingerprint"`
	SignerPolicyDigest     bundle.Digest `json:"signer_policy_digest"`
	GateReceiptDigest      bundle.Digest `json:"gate_receipt_digest"`
	SourceDateEpoch        uint64        `json:"source_date_epoch"`
}

// LoadedPlan is an immutable in-memory snapshot of an exact plan directory.
type LoadedPlan struct {
	Plan       Plan
	PlanJSON   []byte
	BootImage  []byte
	PublicPEM  []byte
	PublicKey  *rsa.PublicKey
	PlanDigest bundle.Digest
}

// LoadedResult is an immutable in-memory snapshot of an exact signing output.
type LoadedResult struct {
	Result     Result
	ResultJSON []byte
	BootSig    []byte
}

func (p Plan) Validate() error {
	if p.SchemaVersion != PlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported signing plan schema_version %q", p.SchemaVersion)
	}
	if !planIdentifierPattern.MatchString(p.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	if err := p.BootImageDigest.Validate(); err != nil {
		return fmt.Errorf("boot_image_digest: %w", err)
	}
	if p.BootImageSizeBytes == 0 || p.BootImageSizeBytes > uint64(signing.MaxArtifactBytes) {
		return fmt.Errorf("boot_image_size_bytes must be between 1 and %d", signing.MaxArtifactBytes)
	}
	if err := p.PublicKeyFingerprint.Validate(); err != nil {
		return fmt.Errorf("public_key_fingerprint: %w", err)
	}
	if err := p.SignerPolicyDigest.Validate(); err != nil {
		return fmt.Errorf("signer_policy_digest: %w", err)
	}
	if p.SourceDateEpoch > maxSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must not exceed %d", maxSourceDateEpoch)
	}
	return nil
}

func (p Plan) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode canonical signing plan: %w", err)
	}
	return encoded, nil
}

func (p Plan) Digest() (bundle.Digest, error) {
	encoded, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-boot-signing-plan.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func (r Result) Validate() error {
	if r.SchemaVersion != ResultSchemaV1Alpha1 {
		return fmt.Errorf("unsupported signing result schema_version %q", r.SchemaVersion)
	}
	if !planIdentifierPattern.MatchString(r.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	for name, digest := range map[string]bundle.Digest{
		"plan_digest":            r.PlanDigest,
		"boot_image_digest":      r.BootImageDigest,
		"boot_signature_digest":  r.BootSignatureDigest,
		"public_key_fingerprint": r.PublicKeyFingerprint,
		"signer_policy_digest":   r.SignerPolicyDigest,
		"gate_receipt_digest":    r.GateReceiptDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if r.BootImageSizeBytes == 0 || r.BootImageSizeBytes > uint64(signing.MaxArtifactBytes) {
		return fmt.Errorf("boot_image_size_bytes must be between 1 and %d", signing.MaxArtifactBytes)
	}
	if r.BootSignatureSizeBytes == 0 || r.BootSignatureSizeBytes > maxBootSigBytes {
		return fmt.Errorf("boot_signature_size_bytes must be between 1 and %d", maxBootSigBytes)
	}
	if r.SourceDateEpoch > maxSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must not exceed %d", maxSourceDateEpoch)
	}
	return nil
}

func (r Result) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode canonical signing result: %w", err)
	}
	return encoded, nil
}

func (r Result) Digest() (bundle.Digest, error) {
	encoded, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-boot-signing-result.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func parsePlan(encoded []byte) (Plan, error) {
	if len(encoded) == 0 || len(encoded) > maxPlanBytes {
		return Plan{}, fmt.Errorf("signing plan size must be between 1 and %d bytes", maxPlanBytes)
	}
	var plan Plan
	if err := strictDecode(encoded, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode signing plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func parseResult(encoded []byte) (Result, error) {
	if len(encoded) == 0 || len(encoded) > maxResultBytes {
		return Result{}, fmt.Errorf("signing result size must be between 1 and %d bytes", maxResultBytes)
	}
	var result Result
	if err := strictDecode(encoded, &result); err != nil {
		return Result{}, fmt.Errorf("decode signing result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func parsePublicKey(encoded []byte) (*rsa.PublicKey, bundle.Digest, error) {
	if len(encoded) == 0 || len(encoded) > maxPublicKeyBytes {
		return nil, "", fmt.Errorf("public key size must be between 1 and %d bytes", maxPublicKeyBytes)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, "", errors.New("public.pem must contain exactly one headerless PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", errors.New("public.pem is not valid PKIX public-key DER")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 2048 || publicKey.E != 65537 || publicKey.Size() != 256 {
		return nil, "", errors.New("public.pem must be RSA-2048 with exponent 65537")
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize public key: %w", err)
	}
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: canonicalDER})
	if string(canonicalPEM) != string(encoded) {
		return nil, "", errors.New("public.pem is not canonical PKIX PEM")
	}
	return publicKey, bundle.Sum(canonicalDER), nil
}
