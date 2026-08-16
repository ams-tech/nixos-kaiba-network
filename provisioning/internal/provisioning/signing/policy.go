// Package signing provides the approval-gated Raspberry Pi secure-boot signing
// boundary. It deliberately contains no browser-facing executable, key, PIN,
// module, or input-path selection.
package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	PolicySchemaV1Alpha1 = "kaiba.provisioning.yubikey-signing-policy/v1alpha1"
	DevelopmentPIVSlot   = "9c"
	YubiKeyPIVProvider   = "yubikey-piv"
	RSA2048KeyAlgorithm  = "rsa-2048"
)

var (
	policyIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	policyAttributePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	pkcs11PathAttributes    = map[string]struct{}{
		"token": {}, "manufacturer": {}, "serial": {}, "model": {},
		"library-manufacturer": {}, "library-description": {}, "library-version": {},
		"object": {}, "type": {}, "id": {}, "slot-id": {}, "slot-description": {},
	}
)

// YubiKeyPolicy is public, secret-free signer metadata. The development policy
// is intentionally fixed to a non-exportable RSA-2048 key in PIV slot 9c and
// requires both PIN verification and physical touch for every signature.
type YubiKeyPolicy struct {
	SchemaVersion        string        `json:"schema_version"`
	SignerID             string        `json:"signer_id"`
	CohortID             string        `json:"cohort_id"`
	Provider             string        `json:"provider"`
	PIVSlot              string        `json:"piv_slot"`
	PKCS11URI            string        `json:"pkcs11_uri"`
	PublicKeyFingerprint bundle.Digest `json:"public_key_fingerprint"`
	KeyAlgorithm         string        `json:"key_algorithm"`
	PINRequired          bool          `json:"pin_required"`
	TouchRequired        bool          `json:"touch_required"`
	PrivateKeyExportable bool          `json:"private_key_exportable"`
}

// NewDevelopmentYubiKeyPolicy builds and validates the one supported
// development-cohort policy. The URI and fingerprint identify public metadata;
// a PIN value is never part of this type.
func NewDevelopmentYubiKeyPolicy(signerID, cohortID, pkcs11URI string, publicKeyFingerprint bundle.Digest) (YubiKeyPolicy, error) {
	policy := YubiKeyPolicy{
		SchemaVersion:        PolicySchemaV1Alpha1,
		SignerID:             signerID,
		CohortID:             cohortID,
		Provider:             YubiKeyPIVProvider,
		PIVSlot:              DevelopmentPIVSlot,
		PKCS11URI:            pkcs11URI,
		PublicKeyFingerprint: publicKeyFingerprint,
		KeyAlgorithm:         RSA2048KeyAlgorithm,
		PINRequired:          true,
		TouchRequired:        true,
		PrivateKeyExportable: false,
	}
	if err := policy.Validate(); err != nil {
		return YubiKeyPolicy{}, err
	}
	return policy, nil
}

// Validate enforces the complete development YubiKey policy rather than
// treating its security properties as caller-selected preferences.
func (p YubiKeyPolicy) Validate() error {
	if p.SchemaVersion != PolicySchemaV1Alpha1 {
		return fmt.Errorf("unsupported YubiKey policy schema_version %q", p.SchemaVersion)
	}
	if !policyIdentifierPattern.MatchString(p.SignerID) {
		return errors.New("signer_id must be a canonical lower-case identifier")
	}
	if !policyIdentifierPattern.MatchString(p.CohortID) {
		return errors.New("cohort_id must be a canonical lower-case identifier")
	}
	if p.Provider != YubiKeyPIVProvider || p.PIVSlot != DevelopmentPIVSlot || p.KeyAlgorithm != RSA2048KeyAlgorithm {
		return errors.New("development signer must use a YubiKey RSA-2048 key in PIV slot 9c")
	}
	if !p.PINRequired || !p.TouchRequired || p.PrivateKeyExportable {
		return errors.New("development signer must require PIN and touch and use a non-exportable private key")
	}
	if err := validatePKCS11URI(p.PKCS11URI); err != nil {
		return err
	}
	if err := p.PublicKeyFingerprint.Validate(); err != nil {
		return fmt.Errorf("public_key_fingerprint: %w", err)
	}
	return nil
}

func validatePKCS11URI(uri string) error {
	if len(uri) < len("pkcs11:")+1 || len(uri) > 512 || !strings.HasPrefix(uri, "pkcs11:") {
		return errors.New("pkcs11_uri must be a non-empty PKCS#11 URI")
	}
	for _, char := range uri {
		if char <= 0x20 || char == 0x7f || char > 0x7e {
			return errors.New("pkcs11_uri must contain canonical printable ASCII without whitespace")
		}
	}
	if strings.ContainsAny(uri, "?#") {
		return errors.New("pkcs11_uri must not contain query parameters or fragments")
	}
	attributes := make(map[string]string)
	for _, encoded := range strings.Split(strings.TrimPrefix(uri, "pkcs11:"), ";") {
		name, value, found := strings.Cut(encoded, "=")
		if !found || name == "" || value == "" || !policyAttributePattern.MatchString(name) {
			return errors.New("pkcs11_uri contains a malformed path attribute")
		}
		if _, supported := pkcs11PathAttributes[name]; !supported {
			return fmt.Errorf("pkcs11_uri path attribute %q is not permitted", name)
		}
		if _, exists := attributes[name]; exists {
			return fmt.Errorf("pkcs11_uri path attribute %q is duplicated", name)
		}
		attributes[name] = value
	}
	if attributes["type"] != "private" {
		return errors.New("pkcs11_uri must identify a private-key object")
	}
	// YKCS11 maps object id 2 to PIV slot 9c. Requiring the canonical binary
	// id makes the URI and the separately recorded PIV slot describe the same
	// key rather than two independent, potentially conflicting selectors.
	if attributes["id"] != "%02" {
		return errors.New("pkcs11_uri must select YKCS11 object id %02 for PIV slot 9c")
	}
	if attributes["token"] == "" && attributes["serial"] == "" {
		return errors.New("pkcs11_uri must bind a token label or serial")
	}
	return nil
}

// Digest returns a domain-separated digest of the canonical public policy.
func (p YubiKeyPolicy) Digest() (bundle.Digest, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode signing policy: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.yubikey-signing-policy.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
