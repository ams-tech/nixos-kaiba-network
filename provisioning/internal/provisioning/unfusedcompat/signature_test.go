package unfusedcompat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
)

type signedTestInputs struct {
	testInputs
	privateKey    *rsa.PrivateKey
	publicKeyPath string
}

func TestVerifyDetachedSignatureBindsReviewedKeyAndCapsule(t *testing.T) {
	inputs := makeSignedTestInputs(t)
	policy := trustedPolicyFor(t, inputs.publicKeyPath)
	first, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("signature receipt is not deterministic:\n%#v\n%#v", first, second)
	}
	if !first.SignatureValid || first.SecurityEnforced || first.Algorithm != SignatureAlgorithmRSA2048SHA256 ||
		first.CapsuleDigest != inputs.manifest.CapsuleDigest || first.ReceiptDigest == "" ||
		first.BootSignatureDigest != inputs.manifest.Files[1].SHA256 ||
		first.BootPublicKeyFingerprint != policy.ExpectedPublicKeyFingerprint ||
		!first.SignerTrustAnchored || first.SignerTrustPolicyDigest == "" {
		t.Fatalf("signature receipt = %#v", first)
	}
	policyDigest, err := policy.digest()
	if err != nil {
		t.Fatal(err)
	}
	if first.SignerTrustPolicyDigest != policyDigest {
		t.Fatalf("signer trust policy digest = %q, want %q", first.SignerTrustPolicyDigest, policyDigest)
	}

	outcome, err := VerifySignedOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath, inputs.publicKeyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.SignatureVerified || outcome.SignatureVerificationReceipt != first.ReceiptDigest ||
		outcome.BootPublicKeyFingerprint != first.BootPublicKeyFingerprint || !outcome.SignerTrustAnchored ||
		outcome.SignerTrustPolicyDigest != first.SignerTrustPolicyDigest || outcome.SecurityEnforced || outcome.MutationEligible {
		t.Fatalf("signed compatibility outcome = %#v", outcome)
	}
}

func TestVerifyDetachedSignatureRejectsCryptographicMismatch(t *testing.T) {
	t.Run("manifest-bound altered signature", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		policy := trustedPolicyFor(t, inputs.publicKeyPath)
		rawSignature := make([]byte, inputs.privateKey.PublicKey.Size())
		if _, err := rand.Read(rawSignature); err != nil {
			t.Fatal(err)
		}
		signature := marshalBootSignature(t, bundle.Digest(inputs.manifest.Files[0].SHA256), rawSignature)
		mustWrite(t, filepath.Join(inputs.root, "boot.sig"), signature)
		inputs.manifest.Files[1].SizeBytes = int64(len(signature))
		inputs.manifest.Files[1].SHA256 = digestBytes(signature)
		refreshSignedManifest(t, &inputs.testInputs)
		_, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("raw signature representation", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		policy := trustedPolicyFor(t, inputs.publicKeyPath)
		rawSignature, err := rsa.SignPKCS1v15(rand.Reader, inputs.privateKey, crypto.SHA256, mustDigestBytes(t, inputs.manifest.Files[0].SHA256))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(inputs.root, "boot.sig"), rawSignature)
		inputs.manifest.Files[1].SizeBytes = int64(len(rawSignature))
		inputs.manifest.Files[1].SHA256 = digestBytes(rawSignature)
		refreshSignedManifest(t, &inputs.testInputs)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
		if err == nil || !strings.Contains(err.Error(), "parse boot signature") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("self-consistent signature for different image digest", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		policy := trustedPolicyFor(t, inputs.publicKeyPath)
		otherDigestBytes := sha256.Sum256([]byte("attacker-selected image"))
		otherDigest := bundle.Digest("sha256:" + fmtHex(otherDigestBytes[:]))
		rawSignature, err := rsa.SignPKCS1v15(rand.Reader, inputs.privateKey, crypto.SHA256, otherDigestBytes[:])
		if err != nil {
			t.Fatal(err)
		}
		signatureDocument := marshalBootSignature(t, otherDigest, rawSignature)
		mustWrite(t, filepath.Join(inputs.root, "boot.sig"), signatureDocument)
		inputs.manifest.Files[1].SizeBytes = int64(len(signatureDocument))
		inputs.manifest.Files[1].SHA256 = digestBytes(signatureDocument)
		refreshSignedManifest(t, &inputs.testInputs)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
		if err == nil || !strings.Contains(err.Error(), "does not match the manifest boot image") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		policy := trustedPolicyFor(t, inputs.publicKeyPath)
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		writePublicKey(t, inputs.publicKeyPath, &wrong.PublicKey)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
		if err == nil || !strings.Contains(err.Error(), "not authorized") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		policy := trustedPolicyFor(t, inputs.publicKeyPath)
		short, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		writePublicKey(t, inputs.publicKeyPath, &short.PublicKey)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
		if err == nil || !strings.Contains(err.Error(), "RSA-2048") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestVerifyDetachedSignatureRejectsPublicKeySymlink(t *testing.T) {
	inputs := makeSignedTestInputs(t)
	policy := trustedPolicyFor(t, inputs.publicKeyPath)
	link := filepath.Join(filepath.Dir(inputs.publicKeyPath), "public-link.pem")
	if err := os.Symlink(inputs.publicKeyPath, link); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, link, policy)
	if err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyDetachedSignatureRequiresAnIndependentTrustAnchor(t *testing.T) {
	inputs := makeSignedTestInputs(t)
	for name, policy := range map[string]TrustedSignerPolicy{
		"empty":            {},
		"malformed":        {SchemaVersion: TrustedSignerPolicySchemaVersion, ExpectedPublicKeyFingerprint: "not-a-digest"},
		"different signer": {SchemaVersion: TrustedSignerPolicySchemaVersion, ExpectedPublicKeyFingerprint: "sha256:" + strings.Repeat("f", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath, policy)
			if err == nil {
				t.Fatal("self-consistent signature was accepted without the configured signer anchor")
			}
		})
	}
}

func TestNewTrustedSignerPolicyRejectsInvalidAnchors(t *testing.T) {
	for name, fingerprint := range map[string]string{
		"empty":           "",
		"malformed":       "not-a-digest",
		"uppercase":       "sha256:" + strings.Repeat("A", 64),
		"wrong algorithm": "sha512:" + strings.Repeat("a", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewTrustedSignerPolicy(fingerprint); err == nil {
				t.Fatalf("NewTrustedSignerPolicy(%q) succeeded", fingerprint)
			}
		})
	}
}

func makeSignedTestInputs(t *testing.T) signedTestInputs {
	t.Helper()
	inputs := makeTestInputs(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bootImage, err := os.ReadFile(filepath.Join(inputs.root, "boot.img"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bootImage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signatureDocument := marshalBootSignature(t, bundle.Digest("sha256:"+fmtHex(digest[:])), signature)
	mustWrite(t, filepath.Join(inputs.root, "boot.sig"), signatureDocument)
	inputs.manifest.Files[1].SizeBytes = int64(len(signatureDocument))
	inputs.manifest.Files[1].SHA256 = digestBytes(signatureDocument)
	refreshSignedManifest(t, &inputs)
	publicKeyPath := filepath.Join(filepath.Dir(inputs.root), "public.pem")
	writePublicKey(t, publicKeyPath, &privateKey.PublicKey)
	return signedTestInputs{testInputs: inputs, privateKey: privateKey, publicKeyPath: publicKeyPath}
}

func marshalBootSignature(t *testing.T, digest bundle.Digest, signature []byte) []byte {
	t.Helper()
	document, err := rpi5bootsig.New(digest, 1_725_000_123, signature)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := document.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustDigestBytes(t *testing.T, digest string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("invalid test digest %q", digest)
	}
	return decoded
}

func fmtHex(value []byte) string {
	return hex.EncodeToString(value)
}

func refreshSignedManifest(t *testing.T, inputs *testInputs) {
	t.Helper()
	capsuleDigest, err := ComputeCapsuleDigest(inputs.manifest.Files)
	if err != nil {
		t.Fatal(err)
	}
	inputs.manifest.CapsuleDigest = capsuleDigest
	inputs.fixture.CapsuleDigest = capsuleDigest
	inputs.fixture.BootSignatureDigest = inputs.manifest.Files[1].SHA256
	writeJSON(t, inputs.manifestPath, inputs.manifest)
	writeJSON(t, inputs.fixturePath, inputs.fixture)
}

func writePublicKey(t *testing.T, filePath string, publicKey *rsa.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filePath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func trustedPolicyFor(t *testing.T, publicKeyPath string) TrustedSignerPolicy {
	t.Helper()
	_, fingerprint, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewTrustedSignerPolicy(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
