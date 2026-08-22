package signing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	RequestSchemaV1Alpha2            = "kaiba.provisioning.signing-request/v1alpha2"
	ResultSchemaV1Alpha2             = "kaiba.provisioning.signing-result/v1alpha2"
	AlgorithmRSA2048SHA256 Algorithm = "rsa2048-sha256"
	MaxRequestBytes                  = 64 * 1024
	RSASignatureBytes                = 256
	MaxArtifactBytes                 = 96 * 1024 * 1024
)

var requestIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// Algorithm is the closed signing algorithm vocabulary supported by Raspberry
// Pi's HSM wrapper contract.
type Algorithm string

// ApprovalBinding is the exact authorization context for one immutable
// artifact. ApprovalVerifier establishes the authenticity and current validity
// of this secret-free record before the private key is used.
type ApprovalBinding struct {
	ApprovalID          string              `json:"approval_id"`
	ApprovalDigest      bundle.Digest       `json:"approval_digest"`
	ReleaseIntentDigest bundle.Digest       `json:"release_intent_digest"`
	Role                bundle.ArtifactRole `json:"role"`
	ArtifactDigest      bundle.Digest       `json:"artifact_digest"`
}

// Request contains no filesystem or executable paths and no key selector. The
// artifact role and digest must exactly match the independently issued
// approval binding.
type Request struct {
	SchemaVersion  string              `json:"schema_version"`
	RequestID      string              `json:"request_id"`
	Algorithm      Algorithm           `json:"algorithm"`
	Role           bundle.ArtifactRole `json:"role"`
	ArtifactDigest bundle.Digest       `json:"artifact_digest"`
	Approval       ApprovalBinding     `json:"approval"`
}

// Result is the idempotent, secret-free signing receipt.
type Result struct {
	SchemaVersion       string              `json:"schema_version"`
	RequestID           string              `json:"request_id"`
	RequestDigest       bundle.Digest       `json:"request_digest"`
	Role                bundle.ArtifactRole `json:"role"`
	ArtifactDigest      bundle.Digest       `json:"artifact_digest"`
	Algorithm           Algorithm           `json:"algorithm"`
	SignatureHex        string              `json:"signature_hex"`
	SignatureDigest     bundle.Digest       `json:"signature_digest"`
	SignerPolicyDigest  bundle.Digest       `json:"signer_policy_digest"`
	ReleaseIntentDigest bundle.Digest       `json:"release_intent_digest"`
}

// ParseRequest rejects unknown fields, duplicate keys, trailing JSON values,
// unsupported versions, and any semantically invalid approval binding.
func ParseRequest(data []byte) (Request, error) {
	if len(data) == 0 || len(data) > MaxRequestBytes {
		return Request{}, fmt.Errorf("signing request size must be between 1 and %d bytes", MaxRequestBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Request{}, fmt.Errorf("decode signing request: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode signing request: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return Request{}, fmt.Errorf("decode signing request: %w", err)
		}
		return Request{}, fmt.Errorf("decode signing request: trailing JSON value %v", token)
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

// Validate enforces the exact algorithm, signable role, digest, and approval
// bindings. It cannot be used to authorize an arbitrary RSA operation.
func (r Request) Validate() error {
	if r.SchemaVersion != RequestSchemaV1Alpha2 {
		return fmt.Errorf("unsupported signing request schema_version %q", r.SchemaVersion)
	}
	if !requestIdentifierPattern.MatchString(r.RequestID) {
		return errors.New("request_id must be a canonical lower-case identifier")
	}
	if r.Algorithm != AlgorithmRSA2048SHA256 {
		return fmt.Errorf("unsupported signing algorithm %q", r.Algorithm)
	}
	if err := r.Role.Validate(); err != nil {
		return fmt.Errorf("role: %w", err)
	}
	if !r.Role.Signable() {
		return fmt.Errorf("artifact role %q is not an approved boot-key signing input", r.Role)
	}
	if err := r.ArtifactDigest.Validate(); err != nil {
		return fmt.Errorf("artifact_digest: %w", err)
	}
	if err := r.Approval.validate(); err != nil {
		return err
	}
	if r.Role != r.Approval.Role || r.ArtifactDigest != r.Approval.ArtifactDigest {
		return errors.New("request artifact role and digest do not match the approval binding")
	}
	return nil
}

func (a ApprovalBinding) validate() error {
	if !requestIdentifierPattern.MatchString(a.ApprovalID) {
		return errors.New("approval.approval_id must be a canonical lower-case identifier")
	}
	for name, digest := range map[string]bundle.Digest{
		"approval.approval_digest":       a.ApprovalDigest,
		"approval.release_intent_digest": a.ReleaseIntentDigest,
		"approval.artifact_digest":       a.ArtifactDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := a.Role.Validate(); err != nil {
		return fmt.Errorf("approval.role: %w", err)
	}
	if !a.Role.Signable() {
		return fmt.Errorf("approval artifact role %q is not signable", a.Role)
	}
	return nil
}

// Digest returns a domain-separated digest over the canonical request.
func (r Request) Digest() (bundle.Digest, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode signing request: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.signing-request.v1alpha2\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
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
