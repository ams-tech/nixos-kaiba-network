// Command testfixture emits deterministic, public signing-receipt evidence for
// the Nix integration test. It is deliberately kept below internal/ and is not
// installed in any production package.
package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
)

type artifactPaths map[bundle.ArtifactRole]string

func (paths *artifactPaths) String() string {
	if paths == nil {
		return ""
	}
	values := make([]string, 0, len(*paths))
	for role, path := range *paths {
		values = append(values, string(role)+"="+path)
	}
	return strings.Join(values, ",")
}

func (paths *artifactPaths) Set(value string) error {
	roleValue, path, found := strings.Cut(value, "=")
	if !found || roleValue == "" || path == "" {
		return errors.New("artifact must use ROLE=ABSOLUTE_PATH form")
	}
	role := bundle.ArtifactRole(roleValue)
	if err := role.Validate(); err != nil || !role.Signable() {
		return fmt.Errorf("artifact role %q is not signable", roleValue)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("artifact path must be absolute and clean")
	}
	if *paths == nil {
		*paths = make(artifactPaths)
	}
	if _, exists := (*paths)[role]; exists {
		return fmt.Errorf("artifact role %q is duplicated", role)
	}
	(*paths)[role] = path
	return nil
}

type receiptDigestRecord struct {
	Role          bundle.ArtifactRole `json:"role"`
	ReceiptDigest bundle.Digest       `json:"receipt_digest"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("signing-receipts-testfixture", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	releaseIntentPath := flags.String("release-intent", "", "canonical release-intent JSON")
	privateKeyPath := flags.String("private-key", "", "deterministic fixture-only RSA private key")
	outputPath := flags.String("output", "", "new public fixture output directory")
	reviewerID := flags.String("reviewer-id", "reviewer:nix-receipt-fixture", "fixture reviewer identifier")
	approvedAt := flags.String("approved-at", "2026-08-27T12:00:00Z", "fixture approval time")
	expiresAt := flags.String("expires-at", "2026-08-28T12:00:00Z", "fixture grant expiry")
	signedAt := flags.String("signed-at", "2026-08-27T12:01:00Z", "fixture receipt signing time")
	var artifacts artifactPaths
	flags.Var(&artifacts, "artifact", "ROLE=ABSOLUTE_PATH; repeat for every release signing input")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *releaseIntentPath == "" || *privateKeyPath == "" || *outputPath == "" {
		return errors.New("release-intent, private-key, output, and five artifact arguments are required")
	}

	intentData, err := os.ReadFile(*releaseIntentPath)
	if err != nil {
		return fmt.Errorf("read release intent: %w", err)
	}
	payload := bytes.TrimSuffix(intentData, []byte{'\n'})
	intent, err := releaseintent.Parse(payload)
	if err != nil {
		return fmt.Errorf("parse release intent: %w", err)
	}
	canonicalIntent, err := intent.CanonicalJSON()
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, canonicalIntent) {
		return errors.New("release intent is not canonical JSON")
	}

	privateKey, publicPEM, err := loadPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	_, publicKeyFingerprint, err := signingreceipts.ParsePublicKey(publicPEM)
	if err != nil {
		return fmt.Errorf("fixture public key: %w", err)
	}
	if publicKeyFingerprint != intent.PublicKeyFingerprint {
		return errors.New("fixture key does not match release-intent public_key_fingerprint")
	}

	roles := releaseintent.SigningInputRoles()
	if len(artifacts) != len(roles) {
		return fmt.Errorf("got %d artifacts, want exactly %d", len(artifacts), len(roles))
	}
	artifactData := make(map[bundle.ArtifactRole][]byte, len(roles))
	for _, role := range roles {
		path, exists := artifacts[role]
		if !exists {
			return fmt.Errorf("artifact role %q is missing", role)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read artifact %q: %w", role, err)
		}
		expected, found := intent.SigningInput(role)
		if !found || expected.Digest != bundle.Sum(data) || expected.SizeBytes != uint64(len(data)) {
			return fmt.Errorf("artifact %q does not match the release intent", role)
		}
		artifactData[role] = data
	}

	authorization, err := signingapproval.New(intent, *reviewerID, *approvedAt, *expiresAt)
	if err != nil {
		return fmt.Errorf("construct fixture authorization: %w", err)
	}
	states := make([]signinggate.DurableState, 0, len(authorization.Registry.Grants))
	for _, grant := range authorization.Registry.Grants {
		data := artifactData[grant.Request.Role]
		digest := sha256.Sum256(data)
		signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, digest[:])
		if err != nil {
			return fmt.Errorf("sign fixture artifact %q: %w", grant.Request.Role, err)
		}
		requestDigest, err := grant.Request.Digest()
		if err != nil {
			return err
		}
		receipt := signinggate.Receipt{
			SchemaVersion:   signinggate.ReceiptSchemaV1Alpha3,
			Grant:           grant,
			RequestDigest:   requestDigest,
			BackendID:       "backend:nix-receipt-fixture",
			SignatureHex:    fmt.Sprintf("%x", signature),
			SignatureDigest: bundle.Sum(signature),
			SignedAt:        *signedAt,
		}
		attestation, err := receipt.CanonicalAttestation()
		if err != nil {
			return fmt.Errorf("construct fixture receipt attestation %q: %w", grant.Request.Role, err)
		}
		attestationDigest := sha256.Sum256(attestation)
		attestationSignature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, attestationDigest[:])
		if err != nil {
			return fmt.Errorf("sign fixture receipt attestation %q: %w", grant.Request.Role, err)
		}
		receipt, err = receipt.WithAttestationSignature(attestationSignature)
		if err != nil {
			return fmt.Errorf("attach fixture receipt attestation %q: %w", grant.Request.Role, err)
		}
		states = append(states, signinggate.DurableState{
			SchemaVersion:  signinggate.StateSchemaV1Alpha3,
			Status:         signinggate.StateComplete,
			GrantID:        grant.GrantID,
			RequestDigest:  requestDigest,
			ArtifactDigest: grant.Request.ArtifactDigest,
			IntentAt:       *approvedAt,
			Receipt:        &receipt,
		})
	}

	exported, err := signingreceipts.New(authorization.Registry, states, publicPEM)
	if err != nil {
		return fmt.Errorf("construct authenticated receipt export: %w", err)
	}
	exportJSON, err := exported.CanonicalJSON(authorization.Registry, publicPEM)
	if err != nil {
		return err
	}
	if _, _, err := signingreceipts.ParseAndVerify(exportJSON, authorization.Registry, publicPEM, exported.ReceiptDigests()); err != nil {
		return fmt.Errorf("self-verify authenticated receipt export: %w", err)
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		return err
	}
	registryJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		return err
	}
	digestRecords := make([]receiptDigestRecord, len(exported.Receipts))
	for index, record := range exported.Receipts {
		digestRecords[index] = receiptDigestRecord{
			Role:          record.Receipt.Grant.Request.Role,
			ReceiptDigest: record.ReceiptDigest,
		}
	}
	digestsJSON, err := json.Marshal(digestRecords)
	if err != nil {
		return err
	}

	if err := os.Mkdir(*outputPath, 0o755); err != nil {
		return fmt.Errorf("create fixture output: %w", err)
	}
	for name, data := range map[string][]byte{
		"approval.json":         append(approvalJSON, '\n'),
		"public.pem":            publicPEM,
		"receipt-digests.json":  append(digestsJSON, '\n'),
		"signing-grants.json":   append(registryJSON, '\n'),
		"signing-receipts.json": exportJSON,
	} {
		if err := os.WriteFile(filepath.Join(*outputPath, name), data, 0o444); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, []byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read fixture private key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, errors.New("fixture private key must be one canonical RSA PRIVATE KEY PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse fixture private key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validate fixture private key: %w", err)
	}
	if privateKey.N.BitLen() != 2048 || privateKey.E != 65537 {
		return nil, nil, errors.New("fixture private key must be RSA-2048 with exponent 65537")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateKey, publicPEM, nil
}
