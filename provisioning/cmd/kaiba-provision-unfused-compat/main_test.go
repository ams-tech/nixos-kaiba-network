package main

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
)

func TestCommandVerifiesOfflineFixture(t *testing.T) {
	manifestPath, root, fixturePath := commandFixture(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"verify-offline-fixture",
		"--manifest", manifestPath,
		"--capsule-root", root,
		"--fixture", fixturePath,
	}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result unfusedcompat.Outcome
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != unfusedcompat.StatusCompatibilityPassed || result.EvidenceMode != unfusedcompat.EvidenceModeOfflineFixture {
		t.Fatalf("unexpected outcome: %#v", result)
	}
	if result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("offline command emitted a prohibited policy claim: %#v", result)
	}
	if result.BootImageDigest == "" || result.BootSignatureDigest == "" || result.RootDataDigest == "" || result.RootHashDigest == "" {
		t.Fatalf("offline command omitted a required capsule role digest: %#v", result)
	}
}

func TestCommandVerifiesSignedOfflineFixture(t *testing.T) {
	manifestPath, root, fixturePath, publicKeyPath := signedCommandFixture(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"verify-signed-offline-fixture",
		"--manifest", manifestPath,
		"--capsule-root", root,
		"--fixture", fixturePath,
		"--public-key", publicKeyPath,
	}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result unfusedcompat.Outcome
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.SignatureVerified || result.SignatureVerificationReceipt == "" ||
		result.BootPublicKeyFingerprint == "" || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("signed outcome = %#v", result)
	}
}

func TestCommandRejectsIncompleteOrExpandedInterface(t *testing.T) {
	manifestPath, root, fixturePath := commandFixture(t)
	tests := [][]string{
		nil,
		{"other"},
		{"verify-offline-fixture"},
		{"verify-offline-fixture", "--manifest", manifestPath, "--capsule-root", root},
		{"verify-offline-fixture", "--manifest", manifestPath, "--capsule-root", root, "--fixture", fixturePath, "extra"},
		{"verify-offline-fixture", "--manifest", manifestPath, "--capsule-root", root, "--fixture", fixturePath, "--device", "/dev/example"},
	}
	for _, arguments := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandReturnsVerificationFailureWithoutResult(t *testing.T) {
	manifestPath, root, fixturePath := commandFixture(t)
	if err := os.WriteFile(filepath.Join(root, "boot.img"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"verify-offline-fixture",
		"--manifest", manifestPath,
		"--capsule-root", root,
		"--fixture", fixturePath,
	}, &stdout, &stderr)
	if code != exitVerification || stdout.Len() != 0 || !strings.Contains(stderr.String(), "verify offline compatibility fixture") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandImportsOnlyTheOfflineContractFromThisModule(t *testing.T) {
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.HasPrefix(dependency, "github.com/ams-tech/nixos-kaiba-network/provisioning/") && dependency != "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat" {
			t.Fatalf("command gained a production repository dependency %q", dependency)
		}
		if dependency == "os/exec" || dependency == "net" || strings.HasPrefix(dependency, "net/") {
			t.Fatalf("command gained a process or network dependency %q", dependency)
		}
	}
}

func commandFixture(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "capsule")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []struct {
		path string
		data []byte
	}{
		{"boot.img", []byte("offline capsule")},
		{"boot.sig", []byte("offline signature")},
		{"nvme/root-data.img", []byte("offline root data")},
		{"nvme/root-hash.img", []byte("offline root hash tree")},
	}
	files := make([]unfusedcompat.CapsuleFile, 0, len(contents))
	for _, content := range contents {
		filePath := filepath.Join(root, filepath.FromSlash(content.path))
		if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, content.data, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, unfusedcompat.CapsuleFile{Path: content.path, SizeBytes: int64(len(content.data)), SHA256: commandDigest(content.data)})
	}
	capsuleDigest, err := unfusedcompat.ComputeCapsuleDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := unfusedcompat.CapsuleManifest{
		SchemaVersion: unfusedcompat.ManifestSchemaVersion, CapsuleID: "command-capsule",
		CapsuleDigest: capsuleDigest, BootImagePath: files[0].Path, BootSignaturePath: files[1].Path,
		RootDataPath: files[2].Path, RootHashPath: files[3].Path, Files: files,
	}
	fixture := unfusedcompat.OfflineFixture{
		SchemaVersion: unfusedcompat.FixtureSchemaVersion, FixtureID: "command-fixture",
		CapsuleID: manifest.CapsuleID, CapsuleDigest: manifest.CapsuleDigest,
		BootImageDigest: files[0].SHA256, BootSignatureDigest: files[1].SHA256,
		RootDataDigest: files[2].SHA256, RootHashDigest: files[3].SHA256,
		BootMode:       unfusedcompat.BootModeRAMDisk,
		FirmwareLoaded: true, KernelStarted: true, InitramfsStarted: true,
		CompatibilityMarkerObserved: true,
	}
	manifestPath := filepath.Join(base, "manifest.json")
	fixturePath := filepath.Join(base, "fixture.json")
	writeCommandJSON(t, manifestPath, manifest)
	writeCommandJSON(t, fixturePath, fixture)
	return manifestPath, root, fixturePath
}

func signedCommandFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	manifestPath, root, fixturePath := commandFixture(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bootImage, err := os.ReadFile(filepath.Join(root, "boot.img"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bootImage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot.sig"), signature, 0o600); err != nil {
		t.Fatal(err)
	}
	var manifest unfusedcompat.CapsuleManifest
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files[1].SizeBytes = int64(len(signature))
	manifest.Files[1].SHA256 = commandDigest(signature)
	manifest.CapsuleDigest, err = unfusedcompat.ComputeCapsuleDigest(manifest.Files)
	if err != nil {
		t.Fatal(err)
	}
	var fixture unfusedcompat.OfflineFixture
	fixtureData, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.CapsuleDigest = manifest.CapsuleDigest
	fixture.BootSignatureDigest = manifest.Files[1].SHA256
	writeCommandJSON(t, manifestPath, manifest)
	writeCommandJSON(t, fixturePath, fixture)
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(filepath.Dir(root), "public.pem")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, root, fixturePath, publicKeyPath
}

func writeCommandJSON(t *testing.T, filePath string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func commandDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
