package unfusedcompat

import (
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
	"os"
	"path/filepath"
	"syscall"
)

const (
	SignatureReceiptSchemaVersion    = "provisioning.kaiba.network/rpi5-unfused-signature-receipt/v1alpha2"
	TrustedSignerPolicySchemaVersion = "provisioning.kaiba.network/rpi5-unfused-trusted-signer-policy/v1alpha1"
	SignatureAlgorithmRSA2048SHA256  = "rsa2048-sha256"
	maximumPublicKeyBytes            = 16 * 1024
)

// SignatureReceipt proves only offline cryptographic verification. It does
// not claim that an unfused target enforced the customer key.
type SignatureReceipt struct {
	SchemaVersion            string `json:"schema_version"`
	CapsuleID                string `json:"capsule_id"`
	CapsuleDigest            string `json:"capsule_digest"`
	BootImageDigest          string `json:"boot_image_digest"`
	BootSignatureDigest      string `json:"boot_signature_digest"`
	BootPublicKeyFingerprint string `json:"boot_public_key_fingerprint"`
	SignerTrustPolicyDigest  string `json:"signer_trust_policy_digest"`
	SignerTrustAnchored      bool   `json:"signer_trust_anchored"`
	Algorithm                string `json:"algorithm"`
	SignatureValid           bool   `json:"signature_valid"`
	SecurityEnforced         bool   `json:"security_enforced"`
	ReceiptDigest            string `json:"receipt_digest"`
}

// TrustedSignerPolicy is supplied by an immutable caller boundary. A public
// key file is accepted only when its canonical SPKI fingerprint matches this
// independently configured value.
type TrustedSignerPolicy struct {
	SchemaVersion                string `json:"schema_version"`
	ExpectedPublicKeyFingerprint string `json:"expected_public_key_fingerprint"`
}

type signatureReceiptMaterial struct {
	SchemaVersion            string `json:"schema_version"`
	CapsuleID                string `json:"capsule_id"`
	CapsuleDigest            string `json:"capsule_digest"`
	BootImageDigest          string `json:"boot_image_digest"`
	BootSignatureDigest      string `json:"boot_signature_digest"`
	BootPublicKeyFingerprint string `json:"boot_public_key_fingerprint"`
	SignerTrustPolicyDigest  string `json:"signer_trust_policy_digest"`
	SignerTrustAnchored      bool   `json:"signer_trust_anchored"`
	Algorithm                string `json:"algorithm"`
	SignatureValid           bool   `json:"signature_valid"`
	SecurityEnforced         bool   `json:"security_enforced"`
}

// NewTrustedSignerPolicy validates one immutable signer trust anchor.
func NewTrustedSignerPolicy(expectedPublicKeyFingerprint string) (TrustedSignerPolicy, error) {
	policy := TrustedSignerPolicy{
		SchemaVersion:                TrustedSignerPolicySchemaVersion,
		ExpectedPublicKeyFingerprint: expectedPublicKeyFingerprint,
	}
	if err := policy.validate(); err != nil {
		return TrustedSignerPolicy{}, err
	}
	return policy, nil
}

func (policy TrustedSignerPolicy) validate() error {
	if policy.SchemaVersion != TrustedSignerPolicySchemaVersion || !validDigest(policy.ExpectedPublicKeyFingerprint) {
		return errors.New("trusted signer policy requires a canonical pinned public-key fingerprint")
	}
	return nil
}

func (policy TrustedSignerPolicy) digest() (string, error) {
	if err := policy.validate(); err != nil {
		return "", err
	}
	material, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode trusted signer policy: %w", err)
	}
	return domainDigest("kaiba.rpi5.unfused-trusted-signer-policy.v1", material), nil
}

// VerifyDetachedSignature verifies the exact manifest-bound boot image and
// detached signature with an RSA-2048 public key authorized by policy. It opens
// only regular files with O_NOFOLLOW and performs no subprocess or device
// access.
func VerifyDetachedSignature(manifestPath, capsuleRoot, publicKeyPath string, policy TrustedSignerPolicy) (SignatureReceipt, error) {
	policyDigest, err := policy.digest()
	if err != nil {
		return SignatureReceipt{}, err
	}
	var manifest CapsuleManifest
	if err := loadStrictJSONFile(manifestPath, maximumManifestBytes, &manifest); err != nil {
		return SignatureReceipt{}, fmt.Errorf("load capsule manifest: %w", err)
	}
	roles, err := manifest.validate()
	if err != nil {
		return SignatureReceipt{}, fmt.Errorf("validate capsule manifest: %w", err)
	}
	if err := verifyCapsuleTree(capsuleRoot, manifest); err != nil {
		return SignatureReceipt{}, err
	}

	publicKey, fingerprint, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		return SignatureReceipt{}, err
	}
	if fingerprint != policy.ExpectedPublicKeyFingerprint {
		return SignatureReceipt{}, errors.New("reviewed public key is not authorized by the trusted signer policy")
	}
	bootImagePath := filepath.Join(capsuleRoot, filepath.FromSlash(manifest.BootImagePath))
	bootDigest, err := hashRegularFile(bootImagePath, roles.bootImage.SizeBytes)
	if err != nil {
		return SignatureReceipt{}, fmt.Errorf("hash boot image: %w", err)
	}
	if bootDigest != roles.bootImage.SHA256 {
		return SignatureReceipt{}, errors.New("boot image digest changed after capsule verification")
	}
	signaturePath := filepath.Join(capsuleRoot, filepath.FromSlash(manifest.BootSignaturePath))
	signature, err := readRegularFile(signaturePath, int64(publicKey.Size()))
	if err != nil {
		return SignatureReceipt{}, fmt.Errorf("read boot signature: %w", err)
	}
	hashBytes, err := hex.DecodeString(bootDigest[len("sha256:"):])
	if err != nil || len(hashBytes) != sha256.Size {
		return SignatureReceipt{}, errors.New("manifest boot image digest is invalid")
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashBytes, signature); err != nil {
		return SignatureReceipt{}, errors.New("boot signature does not verify against the reviewed public key")
	}

	receipt := SignatureReceipt{
		SchemaVersion: SignatureReceiptSchemaVersion,
		CapsuleID:     manifest.CapsuleID, CapsuleDigest: manifest.CapsuleDigest,
		BootImageDigest: roles.bootImage.SHA256, BootSignatureDigest: roles.bootSignature.SHA256,
		BootPublicKeyFingerprint: fingerprint, SignerTrustPolicyDigest: policyDigest,
		SignerTrustAnchored: true, Algorithm: SignatureAlgorithmRSA2048SHA256,
		SignatureValid: true, SecurityEnforced: false,
	}
	material, err := json.Marshal(signatureReceiptMaterial{
		SchemaVersion: receipt.SchemaVersion, CapsuleID: receipt.CapsuleID,
		CapsuleDigest: receipt.CapsuleDigest, BootImageDigest: receipt.BootImageDigest,
		BootSignatureDigest:      receipt.BootSignatureDigest,
		BootPublicKeyFingerprint: receipt.BootPublicKeyFingerprint,
		SignerTrustPolicyDigest:  receipt.SignerTrustPolicyDigest,
		SignerTrustAnchored:      receipt.SignerTrustAnchored,
		Algorithm:                receipt.Algorithm, SignatureValid: receipt.SignatureValid,
		SecurityEnforced: receipt.SecurityEnforced,
	})
	if err != nil {
		return SignatureReceipt{}, fmt.Errorf("encode signature receipt: %w", err)
	}
	receipt.ReceiptDigest = domainDigest("kaiba.rpi5.unfused-signature-receipt.v2", material)
	return receipt, nil
}

// VerifySignedOfflineFixture combines exact capsule verification, the complete
// offline compatibility sequence, and detached-signature verification.
func VerifySignedOfflineFixture(manifestPath, capsuleRoot, fixturePath, publicKeyPath string, policy TrustedSignerPolicy) (Outcome, error) {
	outcome, err := VerifyOfflineFixture(manifestPath, capsuleRoot, fixturePath)
	if err != nil {
		return Outcome{}, err
	}
	receipt, err := VerifyDetachedSignature(manifestPath, capsuleRoot, publicKeyPath, policy)
	if err != nil {
		return Outcome{}, err
	}
	if outcome.CapsuleID != receipt.CapsuleID || outcome.CapsuleDigest != receipt.CapsuleDigest ||
		outcome.BootImageDigest != receipt.BootImageDigest || outcome.BootSignatureDigest != receipt.BootSignatureDigest {
		return Outcome{}, errors.New("signature receipt does not match the compatibility outcome")
	}
	outcome.BootPublicKeyFingerprint = receipt.BootPublicKeyFingerprint
	outcome.SignatureVerificationReceipt = receipt.ReceiptDigest
	outcome.SignatureVerified = true
	outcome.SignerTrustAnchored = receipt.SignerTrustAnchored
	outcome.SignerTrustPolicyDigest = receipt.SignerTrustPolicyDigest
	return outcome, nil
}

func loadRSAPublicKey(filePath string) (*rsa.PublicKey, string, error) {
	data, err := readRegularFile(filePath, maximumPublicKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read reviewed public key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, "", errors.New("reviewed public key must contain exactly one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", errors.New("reviewed public key is not valid PKIX public-key DER")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 2048 || publicKey.E != 65537 || publicKey.Size() != 256 {
		return nil, "", errors.New("reviewed public key must be RSA-2048 with exponent 65537")
	}
	digest := sha256.Sum256(block.Bytes)
	return publicKey, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func readRegularFile(filePath string, maximum int64) ([]byte, error) {
	if filePath == "" || !filepath.IsAbs(filePath) || filepath.Clean(filePath) != filePath || maximum <= 0 {
		return nil, errors.New("regular file path must be clean and absolute")
	}
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open regular non-symlink file: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if before.Size() < 1 || before.Size() > maximum {
		return nil, fmt.Errorf("regular file size is %d, maximum is %d", before.Size(), maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errors.New("regular file changed while reading")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("regular file identity changed while reading")
	}
	return data, nil
}

func hashRegularFile(filePath string, expectedSize int64) (string, error) {
	if expectedSize <= 0 {
		return "", errors.New("expected file size must be positive")
	}
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != expectedSize {
		return "", errors.New("regular file size or type changed")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil || written != expectedSize {
		return "", errors.New("regular file changed while hashing")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", errors.New("regular file identity changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
