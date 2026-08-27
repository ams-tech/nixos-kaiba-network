// Package signingreceipts exports and independently verifies the secret-free
// receipts retained by the signing gate's root-provisioned, service-owned
// durable state.
package signingreceipts

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	ExportSchemaV1Alpha2 = "kaiba.provisioning.signing-gate-receipt-export/v1alpha2"
	MaxExportBytes       = 2 * 1024 * 1024
	MaxPublicKeyBytes    = 64 * 1024
)

const (
	registryDigestDomain = "kaiba.provisioning.signing-grant-registry.v1alpha2\x00"
	exportDigestDomain   = "kaiba.provisioning.signing-gate-receipt-export.v1alpha2\x00"
)

// Record carries the canonical receipt digest returned to the signing caller
// beside the exact durable receipt from which that digest was calculated.
type Record struct {
	ReceiptDigest bundle.Digest       `json:"receipt_digest"`
	Receipt       signinggate.Receipt `json:"receipt"`
}

// Export is safe to publish: it contains approval metadata and signatures but
// no PIN, private key, credential path, PKCS#11 configuration, or artifact
// bytes. Registry and public-key digests bind it to independently reviewed
// offline trust anchors.
type Export struct {
	SchemaVersion        string        `json:"schema_version"`
	RegistryDigest       bundle.Digest `json:"registry_digest"`
	ReleaseIntentDigest  bundle.Digest `json:"release_intent_digest"`
	PublicKeyFingerprint bundle.Digest `json:"public_key_fingerprint"`
	Receipts             []Record      `json:"receipts"`
}

// Verification summarizes the authenticated bindings without repeating the
// large signatures on stdout.
type Verification struct {
	SchemaVersion        string          `json:"schema_version"`
	Status               string          `json:"status"`
	ExportDigest         bundle.Digest   `json:"export_digest"`
	RegistryDigest       bundle.Digest   `json:"registry_digest"`
	ReleaseIntentDigest  bundle.Digest   `json:"release_intent_digest"`
	PublicKeyFingerprint bundle.Digest   `json:"public_key_fingerprint"`
	ReceiptDigests       []bundle.Digest `json:"receipt_digests"`
}

const VerificationSchemaV1Alpha2 = "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"

// New builds an export for the complete registry. states must be the snapshot
// returned in registry order by signinggate.ReadCompleteStateSnapshot.
func New(registry signinggate.Registry, states []signinggate.DurableState, publicKeyPEM []byte) (Export, error) {
	publicKey, fingerprint, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return Export{}, fmt.Errorf("receipt export public key: %w", err)
	}
	registryDigest, err := RegistryDigest(registry)
	if err != nil {
		return Export{}, err
	}
	releaseIntentDigest, err := registryReleaseIntentDigest(registry)
	if err != nil {
		return Export{}, err
	}
	if len(states) != len(registry.Grants) {
		return Export{}, fmt.Errorf("receipt export has %d durable states, want %d", len(states), len(registry.Grants))
	}
	records := make([]Record, 0, len(states))
	for index, state := range states {
		grant := registry.Grants[index]
		if state.Status != signinggate.StateComplete || state.Receipt == nil {
			return Export{}, fmt.Errorf("grant %q does not have a complete durable receipt", grant.GrantID)
		}
		if err := validateStateBinding(state, grant); err != nil {
			return Export{}, fmt.Errorf("grant %q: %w", grant.GrantID, err)
		}
		digest, err := state.Receipt.Digest()
		if err != nil {
			return Export{}, fmt.Errorf("grant %q receipt: %w", grant.GrantID, err)
		}
		if err := verifyReceiptSignature(publicKey, *state.Receipt); err != nil {
			return Export{}, fmt.Errorf("grant %q receipt: %w", grant.GrantID, err)
		}
		records = append(records, Record{ReceiptDigest: digest, Receipt: *state.Receipt})
	}
	exported := Export{
		SchemaVersion: ExportSchemaV1Alpha2, RegistryDigest: registryDigest,
		ReleaseIntentDigest: releaseIntentDigest, PublicKeyFingerprint: fingerprint, Receipts: records,
	}
	if err := exported.Validate(registry, publicKeyPEM); err != nil {
		return Export{}, err
	}
	return exported, nil
}

// Validate requires an exact one-to-one match with the independently supplied
// registry and verifies every RSA signature against the independently supplied
// public key. Expired grants remain valid historical evidence, but the recorded
// signed_at time must precede the grant expiry.
func (e Export) Validate(registry signinggate.Registry, publicKeyPEM []byte) error {
	if e.SchemaVersion != ExportSchemaV1Alpha2 {
		return fmt.Errorf("unsupported receipt export schema_version %q", e.SchemaVersion)
	}
	registryDigest, err := RegistryDigest(registry)
	if err != nil {
		return err
	}
	if e.RegistryDigest != registryDigest {
		return errors.New("receipt export registry_digest does not match the reviewed registry")
	}
	releaseIntentDigest, err := registryReleaseIntentDigest(registry)
	if err != nil {
		return err
	}
	if e.ReleaseIntentDigest != releaseIntentDigest {
		return errors.New("receipt export release_intent_digest does not match the reviewed registry")
	}
	publicKey, fingerprint, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("receipt export public key: %w", err)
	}
	if e.PublicKeyFingerprint != fingerprint {
		return errors.New("receipt export public_key_fingerprint does not match the reviewed public key")
	}
	if len(e.Receipts) != len(registry.Grants) {
		return fmt.Errorf("receipt export contains %d receipts, want exactly %d", len(e.Receipts), len(registry.Grants))
	}
	seenDigests := make(map[bundle.Digest]struct{}, len(e.Receipts))
	var backendID string
	for index, record := range e.Receipts {
		grant := registry.Grants[index]
		if record.Receipt.Grant != grant {
			return fmt.Errorf("receipts[%d] does not exactly match registry grant %q", index, grant.GrantID)
		}
		digest, err := record.Receipt.Digest()
		if err != nil {
			return fmt.Errorf("receipts[%d]: %w", index, err)
		}
		if record.ReceiptDigest != digest {
			return fmt.Errorf("receipts[%d] receipt_digest does not match its canonical receipt", index)
		}
		if _, exists := seenDigests[digest]; exists {
			return fmt.Errorf("receipts[%d] duplicates receipt_digest %s", index, digest)
		}
		seenDigests[digest] = struct{}{}
		if err := verifyReceiptSignature(publicKey, record.Receipt); err != nil {
			return fmt.Errorf("receipts[%d]: %w", index, err)
		}
		if index == 0 {
			backendID = record.Receipt.BackendID
		} else if record.Receipt.BackendID != backendID {
			return fmt.Errorf("receipts[%d] uses backend_id %q, want the release backend_id %q", index, record.Receipt.BackendID, backendID)
		}
	}
	return nil
}

func validateStateBinding(state signinggate.DurableState, grant signinggate.Grant) error {
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		return err
	}
	if state.SchemaVersion != signinggate.StateSchemaV1Alpha3 || state.GrantID != grant.GrantID ||
		state.RequestDigest != requestDigest || state.ArtifactDigest != grant.Request.ArtifactDigest {
		return errors.New("durable state does not match the reviewed registry grant")
	}
	if state.Receipt.Grant != grant || state.Receipt.RequestDigest != requestDigest {
		return errors.New("durable receipt does not exactly match the reviewed registry grant")
	}
	intentAt, err := time.Parse(time.RFC3339, state.IntentAt)
	if err != nil || intentAt.UTC().Truncate(time.Second).Format(time.RFC3339) != state.IntentAt {
		return errors.New("durable state intent_at is not canonical UTC RFC3339 seconds")
	}
	signedAt, err := time.Parse(time.RFC3339, state.Receipt.SignedAt)
	if err != nil {
		return errors.New("durable receipt signed_at is invalid")
	}
	if intentAt.After(signedAt) {
		return errors.New("durable signing intent was recorded after receipt signed_at")
	}
	return nil
}

func verifyReceiptSignature(publicKey *rsa.PublicKey, receipt signinggate.Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	signedAt, err := time.Parse(time.RFC3339, receipt.SignedAt)
	if err != nil {
		return errors.New("receipt signed_at is invalid")
	}
	expiresAt, err := receipt.Grant.Expiry()
	if err != nil {
		return err
	}
	if !signedAt.Before(expiresAt) {
		return errors.New("receipt signed_at is not before its grant expiry")
	}
	signature, err := signing.ParseSignatureHex([]byte(receipt.SignatureHex))
	if err != nil {
		return fmt.Errorf("signature_hex: %w", err)
	}
	digestBytes, err := digestBytes(receipt.Grant.Request.ArtifactDigest)
	if err != nil {
		return fmt.Errorf("artifact_digest: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digestBytes, signature); err != nil {
		return errors.New("receipt signature does not verify against the reviewed public key and artifact digest")
	}
	attestation, err := receipt.CanonicalAttestation()
	if err != nil {
		return fmt.Errorf("receipt attestation: %w", err)
	}
	attestationSignature, err := signing.ParseSignatureHex([]byte(receipt.AttestationSignatureHex))
	if err != nil {
		return fmt.Errorf("attestation_signature_hex: %w", err)
	}
	attestationDigest := sha256.Sum256(attestation)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, attestationDigest[:], attestationSignature); err != nil {
		return errors.New("receipt attestation signature does not verify against the reviewed public key and canonical receipt metadata")
	}
	return nil
}

func digestBytes(digest bundle.Digest) ([]byte, error) {
	parsed, err := bundle.ParseDigest(string(digest))
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(string(parsed), "sha256:"))
}

// RegistryDigest identifies the complete canonical reviewed registry rather
// than a path or a caller-provided subset of grants.
func RegistryDigest(registry signinggate.Registry) (bundle.Digest, error) {
	if err := registry.Validate(); err != nil {
		return "", fmt.Errorf("receipt export registry: %w", err)
	}
	encoded, err := json.Marshal(registry)
	if err != nil {
		return "", fmt.Errorf("encode receipt export registry: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(registryDigestDomain))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func registryReleaseIntentDigest(registry signinggate.Registry) (bundle.Digest, error) {
	if err := registry.Validate(); err != nil {
		return "", fmt.Errorf("receipt export registry: %w", err)
	}
	releaseIntentDigest := registry.Grants[0].Request.Approval.ReleaseIntentDigest
	for index, grant := range registry.Grants[1:] {
		if grant.Request.Approval.ReleaseIntentDigest != releaseIntentDigest {
			return "", fmt.Errorf("registry grant %d belongs to a different release intent", index+1)
		}
	}
	return releaseIntentDigest, nil
}

// ParsePublicKey accepts exactly one canonical RSA-2048 SubjectPublicKeyInfo
// PEM object and returns its SHA-256 fingerprint over canonical DER.
func ParsePublicKey(encoded []byte) (*rsa.PublicKey, bundle.Digest, error) {
	if len(encoded) == 0 || len(encoded) > MaxPublicKeyBytes {
		return nil, "", fmt.Errorf("public key size must be between 1 and %d bytes", MaxPublicKeyBytes)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, "", errors.New("public key must contain exactly one headerless PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", errors.New("public key is not valid SubjectPublicKeyInfo DER")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N == nil || publicKey.N.BitLen() != 2048 || publicKey.Size() != signing.RSASignatureBytes || publicKey.E != 65537 {
		return nil, "", errors.New("public key must be RSA-2048 with exponent 65537")
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", err
	}
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: canonicalDER})
	if !bytes.Equal(block.Bytes, canonicalDER) || !bytes.Equal(encoded, canonicalPEM) {
		return nil, "", errors.New("public key is not canonical SubjectPublicKeyInfo PEM")
	}
	return publicKey, bundle.Sum(canonicalDER), nil
}

// CanonicalJSON emits the sole accepted export encoding, including one final
// LF for safe command-line publication.
func (e Export) CanonicalJSON(registry signinggate.Registry, publicKeyPEM []byte) ([]byte, error) {
	if err := e.Validate(registry, publicKeyPEM); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ParseAndVerify rejects unknown fields, trailing values, non-canonical JSON,
// registry substitution, receipt tampering, signatures from another key, and
// any receipt whose digest was not independently captured by the live caller.
func ParseAndVerify(encoded []byte, registry signinggate.Registry, publicKeyPEM []byte, expectedReceiptDigests []bundle.Digest) (Export, Verification, error) {
	if len(encoded) == 0 || len(encoded) > MaxExportBytes {
		return Export{}, Verification{}, fmt.Errorf("receipt export size must be between 1 and %d bytes", MaxExportBytes)
	}
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return Export{}, Verification{}, fmt.Errorf("decode receipt export: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var exported Export
	if err := decoder.Decode(&exported); err != nil {
		return Export{}, Verification{}, fmt.Errorf("decode receipt export: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Export{}, Verification{}, fmt.Errorf("decode receipt export: %w", err)
	}
	canonical, err := exported.CanonicalJSON(registry, publicKeyPEM)
	if err != nil {
		return Export{}, Verification{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return Export{}, Verification{}, errors.New("receipt export is not canonical JSON")
	}
	if err := validateExpectedReceiptDigests(exported.Receipts, expectedReceiptDigests); err != nil {
		return Export{}, Verification{}, err
	}
	digest := digestCanonicalExport(canonical[:len(canonical)-1])
	receiptDigests := make([]bundle.Digest, len(exported.Receipts))
	for index, record := range exported.Receipts {
		receiptDigests[index] = record.ReceiptDigest
	}
	return exported, Verification{
		SchemaVersion: VerificationSchemaV1Alpha2, Status: "valid", ExportDigest: digest,
		RegistryDigest: exported.RegistryDigest, ReleaseIntentDigest: exported.ReleaseIntentDigest,
		PublicKeyFingerprint: exported.PublicKeyFingerprint,
		ReceiptDigests:       receiptDigests,
	}, nil
}

func validateExpectedReceiptDigests(records []Record, expected []bundle.Digest) error {
	if len(expected) != len(records) {
		return fmt.Errorf("expected %d independently captured receipt digests, got %d", len(records), len(expected))
	}
	expectedSet := make(map[bundle.Digest]struct{}, len(expected))
	for index, digest := range expected {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("expected receipt digest %d: %w", index, err)
		}
		if _, exists := expectedSet[digest]; exists {
			return fmt.Errorf("expected receipt digest %d duplicates %s", index, digest)
		}
		expectedSet[digest] = struct{}{}
	}
	for _, record := range records {
		if _, exists := expectedSet[record.ReceiptDigest]; !exists {
			return fmt.Errorf("receipt digest %s was not independently captured from a signing result", record.ReceiptDigest)
		}
	}
	return nil
}

// ReceiptDigests returns a defensive copy in registry order. Export uses this
// for its gate-host self-check; offline callers must instead supply digests
// captured independently from the live signing result documents.
func (e Export) ReceiptDigests() []bundle.Digest {
	digests := make([]bundle.Digest, len(e.Receipts))
	for index, record := range e.Receipts {
		digests[index] = record.ReceiptDigest
	}
	return digests
}

// Digest verifies and identifies an in-memory export.
func (e Export) Digest(registry signinggate.Registry, publicKeyPEM []byte) (bundle.Digest, error) {
	canonical, err := e.CanonicalJSON(registry, publicKeyPEM)
	if err != nil {
		return "", err
	}
	return digestCanonicalExport(canonical[:len(canonical)-1]), nil
}

func digestCanonicalExport(canonical []byte) bundle.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(exportDigestDomain))
	_, _ = hash.Write(canonical)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("trailing JSON value")
}

// ParseRegistry strictly decodes an offline registry trust anchor. The file's
// provenance remains the offline reviewer's responsibility; its canonical
// semantic digest must match the export.
func ParseRegistry(encoded []byte) (signinggate.Registry, error) {
	if len(encoded) == 0 || len(encoded) > signinggate.MaxRegistryBytes {
		return signinggate.Registry{}, fmt.Errorf("registry size must be between 1 and %d bytes", signinggate.MaxRegistryBytes)
	}
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return signinggate.Registry{}, fmt.Errorf("decode registry: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var registry signinggate.Registry
	if err := decoder.Decode(&registry); err != nil {
		return signinggate.Registry{}, fmt.Errorf("decode registry: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return signinggate.Registry{}, fmt.Errorf("decode registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return signinggate.Registry{}, err
	}
	return registry, nil
}

func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("JSON object key %q is duplicated", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
