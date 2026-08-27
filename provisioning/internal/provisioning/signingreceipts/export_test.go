package signingreceipts

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

type exportFixture struct {
	privateKey *rsa.PrivateKey
	publicPEM  []byte
	registry   signinggate.Registry
	states     []signinggate.DurableState
	exported   Export
	canonical  []byte
	artifacts  [][]byte
}

func newExportFixture(t *testing.T) exportFixture {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	now := time.Date(2026, 8, 27, 15, 10, 0, 0, time.UTC)
	artifacts := [][]byte{[]byte("reviewed boot image bytes"), []byte("reviewed EEPROM bootcode preimage")}
	roles := []bundle.ArtifactRole{bundle.RoleBootImage, bundle.RoleEEPROMBootcode}
	grants := make([]signinggate.Grant, len(artifacts))
	states := make([]signinggate.DurableState, len(artifacts))
	for index, artifact := range artifacts {
		artifactDigest := bundle.Sum(artifact)
		suffix := string(rune('a' + index))
		grant := signinggate.Grant{
			SchemaVersion: signinggate.GrantSchemaV1Alpha2,
			GrantID:       "grant:receipt-" + suffix,
			ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339),
			Request: signing.Request{
				SchemaVersion: signing.RequestSchemaV1Alpha2,
				RequestID:     "request:receipt-" + suffix,
				Algorithm:     signing.AlgorithmRSA2048SHA256,
				Role:          roles[index], ArtifactDigest: artifactDigest,
				Approval: signing.ApprovalBinding{
					ApprovalID: "approval:receipt-" + suffix, ApprovalDigest: bundle.Sum([]byte("approval-" + suffix)),
					ReleaseIntentDigest: bundle.Sum([]byte("release-intent")), Role: roles[index], ArtifactDigest: artifactDigest,
				},
			},
		}
		requestDigest, err := grant.Request.Digest()
		if err != nil {
			t.Fatal(err)
		}
		artifactHash := sha256.Sum256(artifact)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, artifactHash[:])
		if err != nil {
			t.Fatal(err)
		}
		receipt := signinggate.Receipt{
			SchemaVersion: signinggate.ReceiptSchemaV1Alpha3, Grant: grant, RequestDigest: requestDigest,
			BackendID: "backend:yubikey-development-01", SignatureHex: hex.EncodeToString(signature),
			SignatureDigest: bundle.Sum(signature), SignedAt: now.Format(time.RFC3339),
		}
		attestation, err := receipt.CanonicalAttestation()
		if err != nil {
			t.Fatal(err)
		}
		attestationHash := sha256.Sum256(attestation)
		attestationSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, attestationHash[:])
		if err != nil {
			t.Fatal(err)
		}
		receipt, err = receipt.WithAttestationSignature(attestationSignature)
		if err != nil {
			t.Fatal(err)
		}
		grants[index] = grant
		states[index] = signinggate.DurableState{
			SchemaVersion: signinggate.StateSchemaV1Alpha3, Status: signinggate.StateComplete,
			GrantID: grant.GrantID, RequestDigest: requestDigest, ArtifactDigest: artifactDigest,
			IntentAt: now.Add(-time.Minute).Format(time.RFC3339), Receipt: &receipt,
		}
	}
	registry, err := signinggate.NewRegistry(grants)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := New(registry, states, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := exported.CanonicalJSON(registry, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	return exportFixture{
		privateKey: privateKey, publicPEM: publicPEM, registry: registry,
		states: states, exported: exported, canonical: canonical, artifacts: artifacts,
	}
}

func TestExportRoundTripAuthenticatesEveryBinding(t *testing.T) {
	fixture := newExportFixture(t)
	parsed, verification, err := ParseAndVerify(fixture.canonical, fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture.canonical, mustCanonical(t, parsed, fixture.registry, fixture.publicPEM)) {
		t.Fatal("receipt export did not round-trip canonically")
	}
	if verification.Status != "valid" || len(verification.ReceiptDigests) != len(fixture.registry.Grants) {
		t.Fatalf("verification = %#v", verification)
	}
	if err := verification.ExportDigest.Validate(); err != nil {
		t.Fatalf("export digest: %v", err)
	}
	attestation, err := parsed.Receipts[0].Receipt.CanonicalAttestation()
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("kaiba.provisioning.signing-gate-receipt-attestation.v1alpha1\x00")
	if !bytes.HasPrefix(attestation, domain) {
		t.Fatal("receipt attestation omitted its fixed domain separator")
	}
	attestationSignature, err := signing.ParseSignatureHex([]byte(parsed.Receipts[0].Receipt.AttestationSignatureHex))
	if err != nil {
		t.Fatal(err)
	}
	attestationHash := sha256.Sum256(attestation)
	if err := rsa.VerifyPKCS1v15(&fixture.privateKey.PublicKey, crypto.SHA256, attestationHash[:], attestationSignature); err != nil {
		t.Fatalf("domain-prefixed receipt attestation did not verify: %v", err)
	}
	undomainedHash := sha256.Sum256(attestation[len(domain):])
	if err := rsa.VerifyPKCS1v15(&fixture.privateKey.PublicKey, crypto.SHA256, undomainedHash[:], attestationSignature); err == nil {
		t.Fatal("receipt attestation signature verified without its domain separator")
	}
	for _, prohibited := range [][]byte{
		[]byte("pin"), []byte("pkcs11"), []byte("credential"), fixture.artifacts[0], fixture.artifacts[1],
	} {
		if bytes.Contains(bytes.ToLower(fixture.canonical), bytes.ToLower(prohibited)) {
			t.Fatalf("secret or raw signing input leaked into export: %q", prohibited)
		}
	}
}

func TestExportRejectsReceiptRegistryAndKeySubstitution(t *testing.T) {
	fixture := newExportFixture(t)

	t.Run("canonical receipt digest", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		altered.Receipts[0].ReceiptDigest = bundle.Sum([]byte("substituted receipt digest"))
		_, _, err := ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "canonical receipt") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("cryptographic signature", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		otherHash := sha256.Sum256([]byte("different artifact"))
		signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.privateKey, crypto.SHA256, otherHash[:])
		if err != nil {
			t.Fatal(err)
		}
		altered.Receipts[0].Receipt.SignatureHex = hex.EncodeToString(signature)
		altered.Receipts[0].Receipt.SignatureDigest = bundle.Sum(signature)
		altered.Receipts[0].ReceiptDigest, err = altered.Receipts[0].Receipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("attestation signature size", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		altered.Receipts[0].Receipt.AttestationSignatureHex =
			altered.Receipts[0].Receipt.AttestationSignatureHex[:len(altered.Receipts[0].Receipt.AttestationSignatureHex)-2]
		_, _, err := ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "exactly 512") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("attestation signature digest", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		first := byte('0')
		if altered.Receipts[0].Receipt.AttestationSignatureHex[0] == '0' {
			first = '1'
		}
		altered.Receipts[0].Receipt.AttestationSignatureHex =
			string(first) + altered.Receipts[0].Receipt.AttestationSignatureHex[1:]
		_, _, err := ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "attestation_signature_digest does not match") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("attestation cryptographic signature", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		otherHash := sha256.Sum256([]byte("different receipt attestation"))
		attestationSignature, err := rsa.SignPKCS1v15(rand.Reader, fixture.privateKey, crypto.SHA256, otherHash[:])
		if err != nil {
			t.Fatal(err)
		}
		altered.Receipts[0].Receipt.AttestationSignatureHex = hex.EncodeToString(attestationSignature)
		altered.Receipts[0].Receipt.AttestationSignatureDigest = bundle.Sum(attestationSignature)
		altered.Receipts[0].ReceiptDigest, err = altered.Receipts[0].Receipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		expected := fixture.exported.ReceiptDigests()
		expected[0] = altered.Receipts[0].ReceiptDigest
		_, _, err = ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, expected)
		if err == nil || !strings.Contains(err.Error(), "attestation signature does not verify") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("self-consistent signed_at forgery", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		altered.Receipts[0].Receipt.SignedAt = "2026-08-27T15:11:00Z"
		var err error
		altered.Receipts[0].ReceiptDigest, err = altered.Receipts[0].Receipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		expected := fixture.exported.ReceiptDigests()
		expected[0] = altered.Receipts[0].ReceiptDigest
		_, _, err = ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, expected)
		if err == nil || !strings.Contains(err.Error(), "attestation signature does not verify") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("self-consistent backend_id forgery", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		altered.Receipts[0].Receipt.BackendID = "backend:forged"
		var err error
		altered.Receipts[0].ReceiptDigest, err = altered.Receipts[0].Receipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		expected := fixture.exported.ReceiptDigests()
		expected[0] = altered.Receipts[0].ReceiptDigest
		_, _, err = ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, expected)
		if err == nil || !strings.Contains(err.Error(), "attestation signature does not verify") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("reviewed registry", func(t *testing.T) {
		alteredRegistry := fixture.registry
		alteredRegistry.Grants = append([]signinggate.Grant(nil), fixture.registry.Grants...)
		alteredRegistry.Grants[0].ExpiresAt = "2026-08-29T15:10:00Z"
		_, _, err := ParseAndVerify(fixture.canonical, alteredRegistry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "registry_digest") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("reviewed public key", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		otherPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		_, _, err = ParseAndVerify(fixture.canonical, fixture.registry, otherPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "public_key_fingerprint") {
			t.Fatalf("verification error = %v", err)
		}
	})

	t.Run("grant expiry", func(t *testing.T) {
		altered := cloneExport(fixture.exported)
		altered.Receipts[0].Receipt.SignedAt = altered.Receipts[0].Receipt.Grant.ExpiresAt
		var err error
		altered.Receipts[0].ReceiptDigest, err = altered.Receipts[0].Receipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ParseAndVerify(marshalUnchecked(t, altered), fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests())
		if err == nil || !strings.Contains(err.Error(), "before its grant expiry") {
			t.Fatalf("verification error = %v", err)
		}
	})
}

func TestOfflineVerificationRequiresExactIndependentDigestSet(t *testing.T) {
	fixture := newExportFixture(t)
	tests := []struct {
		name     string
		expected []bundle.Digest
	}{
		{name: "missing", expected: nil},
		{name: "short", expected: fixture.exported.ReceiptDigests()[:1]},
		{name: "duplicate", expected: []bundle.Digest{fixture.exported.Receipts[0].ReceiptDigest, fixture.exported.Receipts[0].ReceiptDigest}},
		{name: "different", expected: []bundle.Digest{fixture.exported.Receipts[0].ReceiptDigest, bundle.Sum([]byte("different"))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := ParseAndVerify(fixture.canonical, fixture.registry, fixture.publicPEM, test.expected); err == nil {
				t.Fatal("invalid independent receipt digest set was accepted")
			}
		})
	}
	reversed := fixture.exported.ReceiptDigests()
	reversed[0], reversed[1] = reversed[1], reversed[0]
	if _, _, err := ParseAndVerify(fixture.canonical, fixture.registry, fixture.publicPEM, reversed); err != nil {
		t.Fatalf("receipt digest set should be order independent: %v", err)
	}
}

func TestExportRejectsNonCanonicalUnknownAndTrailingJSON(t *testing.T) {
	fixture := newExportFixture(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, fixture.canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(fixture.canonical, []byte(`{"schema_version":`), []byte(`{"unknown":true,"schema_version":`), 1)
	duplicate := bytes.Replace(fixture.canonical, []byte(`{"schema_version":`), []byte(`{"schema_version":"`+ExportSchemaV1Alpha2+`","schema_version":`), 1)
	for name, encoded := range map[string][]byte{
		"pretty": pretty.Bytes(), "unknown": unknown, "duplicate": duplicate,
		"trailing": append(append([]byte(nil), fixture.canonical...), []byte("{}\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseAndVerify(encoded, fixture.registry, fixture.publicPEM, fixture.exported.ReceiptDigests()); err == nil {
				t.Fatal("non-canonical receipt export was accepted")
			}
		})
	}
}

func TestNewRequiresCompleteExactRegistrySnapshot(t *testing.T) {
	fixture := newExportFixture(t)
	if _, err := New(fixture.registry, fixture.states[:1], fixture.publicPEM); err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("short snapshot error = %v", err)
	}
	swapped := append([]signinggate.DurableState(nil), fixture.states...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := New(fixture.registry, swapped, fixture.publicPEM); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("swapped snapshot error = %v", err)
	}
	mixedRegistry := fixture.registry
	mixedRegistry.Grants = append([]signinggate.Grant(nil), fixture.registry.Grants...)
	mixedRegistry.Grants[1].Request.Approval.ReleaseIntentDigest = bundle.Sum([]byte("another release intent"))
	if _, err := New(mixedRegistry, fixture.states, fixture.publicPEM); err == nil || !strings.Contains(err.Error(), "different release intent") {
		t.Fatalf("mixed release registry error = %v", err)
	}
	mixedBackendStates := append([]signinggate.DurableState(nil), fixture.states...)
	secondReceipt := *mixedBackendStates[1].Receipt
	secondReceipt.BackendID = "backend:other"
	attestation, err := secondReceipt.CanonicalAttestation()
	if err != nil {
		t.Fatal(err)
	}
	attestationHash := sha256.Sum256(attestation)
	attestationSignature, err := rsa.SignPKCS1v15(rand.Reader, fixture.privateKey, crypto.SHA256, attestationHash[:])
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err = secondReceipt.WithAttestationSignature(attestationSignature)
	if err != nil {
		t.Fatal(err)
	}
	mixedBackendStates[1].Receipt = &secondReceipt
	if _, err := New(fixture.registry, mixedBackendStates, fixture.publicPEM); err == nil || !strings.Contains(err.Error(), "release backend_id") {
		t.Fatalf("mixed backend snapshot error = %v", err)
	}
	lateIntentStates := append([]signinggate.DurableState(nil), fixture.states...)
	lateIntentStates[0].IntentAt = "2026-08-27T15:11:00Z"
	if _, err := New(fixture.registry, lateIntentStates, fixture.publicPEM); err == nil || !strings.Contains(err.Error(), "recorded after") {
		t.Fatalf("late durable intent error = %v", err)
	}
}

func cloneExport(exported Export) Export {
	clone := exported
	clone.Receipts = append([]Record(nil), exported.Receipts...)
	return clone
}

func marshalUnchecked(t *testing.T, exported Export) []byte {
	t.Helper()
	encoded, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func mustCanonical(t *testing.T, exported Export, registry signinggate.Registry, publicKeyPEM []byte) []byte {
	t.Helper()
	encoded, err := exported.CanonicalJSON(registry, publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
