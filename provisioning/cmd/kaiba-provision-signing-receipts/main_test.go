package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

func TestExportThenOfflineVerifyWithoutMutatingState(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDirectory := filepath.Join(root, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	publicKeyPath := filepath.Join(root, "public.pem")
	if err := os.WriteFile(publicKeyPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)
	artifact := []byte("approved signing input that must not appear in evidence")
	artifactDigest := bundle.Sum(artifact)
	grant := signinggate.Grant{
		SchemaVersion: signinggate.GrantSchemaV1Alpha2, GrantID: "grant:cli-export",
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Request: signing.Request{
			SchemaVersion: signing.RequestSchemaV1Alpha2, RequestID: "request:cli-export",
			Algorithm: signing.AlgorithmRSA2048SHA256, Role: bundle.RoleBootImage, ArtifactDigest: artifactDigest,
			Approval: signing.ApprovalBinding{
				ApprovalID: "approval:cli-export", ApprovalDigest: bundle.Sum([]byte("approved")),
				ReleaseIntentDigest: bundle.Sum([]byte("release intent")), Role: bundle.RoleBootImage, ArtifactDigest: artifactDigest,
			},
		},
	}
	registry, err := signinggate.NewRegistry([]signinggate.Grant{grant})
	if err != nil {
		t.Fatal(err)
	}
	registryJSON, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "registry.json")
	if err := os.WriteFile(registryPath, append(registryJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := signinggate.OpenStateStore(stateDirectory, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	intent, err := store.RecordIntent(grant, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	receipt := signinggate.Receipt{
		SchemaVersion: signinggate.ReceiptSchemaV1Alpha3, Grant: grant, RequestDigest: requestDigest,
		BackendID: "backend:cli-test", SignatureHex: hex.EncodeToString(signature),
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
	if _, err := store.RecordComplete(grant, intent, receipt); err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}

	before := readDirectoryFiles(t, stateDirectory)
	outputPath := filepath.Join(root, "receipts.json")
	var exportStdout, exportStderr bytes.Buffer
	testOwnerUID := uint32(os.Getuid())
	code := runWithOwners(context.Background(), []string{
		"export", "--registry", registryPath, "--state-directory", stateDirectory,
		"--public-key", publicKeyPath, "--output", outputPath,
	}, &exportStdout, &exportStderr, testOwnerUID, testOwnerUID)
	if code != exitOK {
		t.Fatalf("export code = %d, stderr = %s", code, exportStderr.String())
	}
	after := readDirectoryFiles(t, stateDirectory)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("signing state changed during export\nbefore=%#v\nafter=%#v", before, after)
	}
	exported, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(exported, artifact) || bytes.Contains(bytes.ToLower(exported), []byte("pin")) || bytes.Contains(bytes.ToLower(exported), []byte("pkcs11")) {
		t.Fatal("receipt export leaked raw artifact or credential metadata")
	}

	var verifyStdout, verifyStderr bytes.Buffer
	code = run(context.Background(), []string{
		"verify", "--export", outputPath, "--registry", registryPath, "--public-key", publicKeyPath,
		"--expected-receipt-digest", string(receiptDigest),
	}, &verifyStdout, &verifyStderr)
	if code != exitOK {
		t.Fatalf("verify code = %d, stderr = %s", code, verifyStderr.String())
	}
	if exportStdout.String() != verifyStdout.String() || !strings.Contains(verifyStdout.String(), `"status":"valid"`) {
		t.Fatalf("export/verify summaries differ\nexport=%s\nverify=%s", exportStdout.String(), verifyStdout.String())
	}

	var insideStdout, insideStderr bytes.Buffer
	insidePath := filepath.Join(stateDirectory, "forbidden-export.json")
	code = runWithOwners(context.Background(), []string{
		"export", "--registry", registryPath, "--state-directory", stateDirectory,
		"--public-key", publicKeyPath, "--output", insidePath,
	}, &insideStdout, &insideStderr, testOwnerUID, testOwnerUID)
	if code != exitVerification || !strings.Contains(insideStderr.String(), "outside the signing-gate state directory") {
		t.Fatalf("state-directory output code/error = %d/%s", code, insideStderr.String())
	}
	if _, err := os.Lstat(insidePath); !os.IsNotExist(err) {
		t.Fatalf("forbidden state-directory export was created: %v", err)
	}

	var secondStdout, secondStderr bytes.Buffer
	code = runWithOwners(context.Background(), []string{
		"export", "--registry", registryPath, "--state-directory", stateDirectory,
		"--public-key", publicKeyPath, "--output", outputPath,
	}, &secondStdout, &secondStderr, testOwnerUID, testOwnerUID)
	if code != exitVerification || !strings.Contains(secondStderr.String(), "already exists") {
		t.Fatalf("overwrite code/error = %d/%s", code, secondStderr.String())
	}
}

func TestCLIRejectsIncompleteInvocation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("empty invocation code = %d", code)
	}
	if !strings.Contains(stderr.String(), "kaiba-provision-signing-receipts export") {
		t.Fatalf("usage = %s", stderr.String())
	}
}

func TestReadRegularFileRejectsWritableAndSymlinkInputs(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "input.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(regular, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(regular, 1024); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("writable input error = %v", err)
	}
	if err := os.Chmod(regular, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "input-link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(symlink, 1024); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink input error = %v", err)
	}
}

func readDirectoryFiles(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	contents := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[entry.Name()] = data
	}
	return contents
}
