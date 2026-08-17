package unfusedcompat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type signedTestInputs struct {
	testInputs
	privateKey    *rsa.PrivateKey
	publicKeyPath string
}

func TestVerifyDetachedSignatureBindsReviewedKeyAndCapsule(t *testing.T) {
	inputs := makeSignedTestInputs(t)
	first, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("signature receipt is not deterministic:\n%#v\n%#v", first, second)
	}
	if !first.SignatureValid || first.SecurityEnforced || first.Algorithm != SignatureAlgorithmRSA2048SHA256 ||
		first.CapsuleDigest != inputs.manifest.CapsuleDigest || first.ReceiptDigest == "" || first.BootPublicKeyFingerprint == "" {
		t.Fatalf("signature receipt = %#v", first)
	}

	outcome, err := VerifySignedOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath, inputs.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.SignatureVerified || outcome.SignatureVerificationReceipt != first.ReceiptDigest ||
		outcome.BootPublicKeyFingerprint != first.BootPublicKeyFingerprint || outcome.SecurityEnforced || outcome.MutationEligible {
		t.Fatalf("signed compatibility outcome = %#v", outcome)
	}
}

func TestVerifyDetachedSignatureRejectsCryptographicMismatch(t *testing.T) {
	t.Run("manifest-bound altered signature", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		signature := make([]byte, inputs.privateKey.PublicKey.Size())
		if _, err := rand.Read(signature); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(inputs.root, "boot.sig"), signature)
		inputs.manifest.Files[1].SizeBytes = int64(len(signature))
		inputs.manifest.Files[1].SHA256 = digestBytes(signature)
		refreshSignedManifest(t, &inputs.testInputs)
		_, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		writePublicKey(t, inputs.publicKeyPath, &wrong.PublicKey)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		inputs := makeSignedTestInputs(t)
		short, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		writePublicKey(t, inputs.publicKeyPath, &short.PublicKey)
		_, err = VerifyDetachedSignature(inputs.manifestPath, inputs.root, inputs.publicKeyPath)
		if err == nil || !strings.Contains(err.Error(), "RSA-2048") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestVerifyDetachedSignatureRejectsPublicKeySymlink(t *testing.T) {
	inputs := makeSignedTestInputs(t)
	link := filepath.Join(filepath.Dir(inputs.publicKeyPath), "public-link.pem")
	if err := os.Symlink(inputs.publicKeyPath, link); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyDetachedSignature(inputs.manifestPath, inputs.root, link)
	if err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("error = %v", err)
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
	mustWrite(t, filepath.Join(inputs.root, "boot.sig"), signature)
	inputs.manifest.Files[1].SizeBytes = int64(len(signature))
	inputs.manifest.Files[1].SHA256 = digestBytes(signature)
	refreshSignedManifest(t, &inputs)
	publicKeyPath := filepath.Join(filepath.Dir(inputs.root), "public.pem")
	writePublicKey(t, publicKeyPath, &privateKey.PublicKey)
	return signedTestInputs{testInputs: inputs, privateKey: privateKey, publicKeyPath: publicKeyPath}
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
