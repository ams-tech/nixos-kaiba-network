package unfusedcompat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type testInputs struct {
	root         string
	manifestPath string
	fixturePath  string
	manifest     CapsuleManifest
	fixture      OfflineFixture
}

func TestVerifyOfflineFixtureProducesNonEnforcementOutcome(t *testing.T) {
	inputs := makeTestInputs(t)
	result, err := VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != OutcomeSchemaVersion || result.Status != StatusCompatibilityPassed || result.EvidenceMode != EvidenceModeOfflineFixture {
		t.Fatalf("unexpected result identity: %#v", result)
	}
	if result.FixtureID != inputs.fixture.FixtureID || result.CapsuleID != inputs.manifest.CapsuleID || result.CapsuleDigest != inputs.manifest.CapsuleDigest {
		t.Fatalf("result lost fixture or capsule binding: %#v", result)
	}
	if result.BootImageDigest != inputs.fixture.BootImageDigest ||
		result.BootSignatureDigest != inputs.fixture.BootSignatureDigest ||
		result.RootDataDigest != inputs.fixture.RootDataDigest ||
		result.RootHashDigest != inputs.fixture.RootHashDigest ||
		result.FilesVerified != len(inputs.manifest.Files) {
		t.Fatalf("result lost verified content binding: %#v", result)
	}
	if result.ManifestDigest == "" || result.FixtureDigest == "" {
		t.Fatalf("result lacks derived evidence digests: %#v", result)
	}
	if result.HardwareObserved || result.SecurityEnforced || result.MutationEligible {
		t.Fatalf("offline fixture acquired a prohibited policy claim: %#v", result)
	}
}

func TestManifestValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testInputs)
		want   string
	}{
		{"schema", func(value *testInputs) { value.manifest.SchemaVersion = "other" }, "unsupported"},
		{"identifier", func(value *testInputs) { value.manifest.CapsuleID = "../capsule" }, "capsule_id"},
		{"uppercase digest", func(value *testInputs) { value.manifest.CapsuleDigest = strings.ToUpper(value.manifest.CapsuleDigest) }, "canonical"},
		{"parent path", func(value *testInputs) { value.manifest.Files[0].Path = "../boot.img" }, "canonical relative"},
		{"absolute path", func(value *testInputs) { value.manifest.Files[0].Path = "/boot.img" }, "canonical relative"},
		{"unsorted files", func(value *testInputs) {
			value.manifest.Files[0], value.manifest.Files[1] = value.manifest.Files[1], value.manifest.Files[0]
		}, "uniquely sorted"},
		{"duplicate files", func(value *testInputs) { value.manifest.Files[1].Path = value.manifest.Files[0].Path }, "uniquely sorted"},
		{"negative size", func(value *testInputs) { value.manifest.Files[0].SizeBytes = -1 }, "must not be negative"},
		{"missing boot image", func(value *testInputs) { value.manifest.BootImagePath = "other.img" }, "not present"},
		{"missing boot signature", func(value *testInputs) { value.manifest.BootSignaturePath = "other.sig" }, "not present"},
		{"missing root data", func(value *testInputs) { value.manifest.RootDataPath = "other-data.img" }, "not present"},
		{"missing root hash", func(value *testInputs) { value.manifest.RootHashPath = "other-hash.img" }, "not present"},
		{"duplicate role", func(value *testInputs) { value.manifest.RootHashPath = value.manifest.RootDataPath }, "distinct"},
		{"empty role", func(value *testInputs) {
			value.manifest.Files[1].SizeBytes = 0
			value.manifest.Files[1].SHA256 = digestBytes(nil)
		}, "non-empty"},
		{"stale capsule digest", func(value *testInputs) { value.manifest.CapsuleDigest = digestBytes([]byte("other capsule")) }, "does not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeTestInputs(t)
			test.mutate(&inputs)
			writeJSON(t, inputs.manifestPath, inputs.manifest)
			_, err := VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateUnknownTrailingAndSymlinkInputs(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		inputs := makeTestInputs(t)
		raw, err := os.ReadFile(inputs.manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), `"capsule_id":`, `"capsule_id":"duplicate","capsule_id":`, 1))
		if err := os.WriteFile(inputs.manifestPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		inputs := makeTestInputs(t)
		raw, err := os.ReadFile(inputs.fixturePath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), `"fixture_id":`, `"security_enforced":true,"fixture_id":`, 1))
		if err := os.WriteFile(inputs.fixturePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("trailing", func(t *testing.T) {
		inputs := makeTestInputs(t)
		file, err := os.OpenFile(inputs.fixturePath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(` {}`)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("append: %v, close: %v", writeErr, closeErr)
		}
		_, err = VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
		if err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("manifest symlink", func(t *testing.T) {
		inputs := makeTestInputs(t)
		link := filepath.Join(filepath.Dir(inputs.manifestPath), "manifest-link.json")
		if err := os.Symlink(inputs.manifestPath, link); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyOfflineFixture(link, inputs.root, inputs.fixturePath)
		if err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCapsuleTreeRejectsAnyContentOrFilesystemChange(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(testInputs)
		want   string
	}{
		{"content", func(value testInputs) {
			mustWrite(t, filepath.Join(value.root, "boot.img"), []byte("tampered capsule"))
		}, "size is"},
		{"same-size content", func(value testInputs) {
			mustWrite(t, filepath.Join(value.root, "boot.sig"), []byte("zzzzzzzzzzzzzzzzzz"))
		}, "digest does not match"},
		{"extra file", func(value testInputs) {
			mustWrite(t, filepath.Join(value.root, "unexpected"), []byte("extra"))
		}, "file count"},
		{"extra directory", func(value testInputs) {
			if err := os.Mkdir(filepath.Join(value.root, "unexpected-directory"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "not required"},
		{"missing file", func(value testInputs) {
			if err := os.Remove(filepath.Join(value.root, "boot.sig")); err != nil {
				t.Fatal(err)
			}
		}, "file count"},
		{"symlink file", func(value testInputs) {
			if err := os.Remove(filepath.Join(value.root, "boot.sig")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("boot.img", filepath.Join(value.root, "boot.sig")); err != nil {
				t.Fatal(err)
			}
		}, "symbolic link"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeTestInputs(t)
			test.mutate(inputs)
			_, err := VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	t.Run("root symlink", func(t *testing.T) {
		inputs := makeTestInputs(t)
		link := filepath.Join(filepath.Dir(inputs.root), "capsule-link")
		if err := os.Symlink(inputs.root, link); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyOfflineFixture(inputs.manifestPath, link, inputs.fixturePath)
		if err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestOfflineFixtureMustBindCompleteCompatibilitySequence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OfflineFixture)
		want   string
	}{
		{"schema", func(value *OfflineFixture) { value.SchemaVersion = "other" }, "unsupported"},
		{"fixture id", func(value *OfflineFixture) { value.FixtureID = "../fixture" }, "fixture_id"},
		{"capsule id", func(value *OfflineFixture) { value.CapsuleID = "other" }, "does not match"},
		{"capsule digest", func(value *OfflineFixture) { value.CapsuleDigest = digestBytes([]byte("other")) }, "does not match"},
		{"boot image", func(value *OfflineFixture) { value.BootImageDigest = digestBytes([]byte("other")) }, "role digests"},
		{"boot signature", func(value *OfflineFixture) { value.BootSignatureDigest = digestBytes([]byte("other")) }, "role digests"},
		{"root data", func(value *OfflineFixture) { value.RootDataDigest = digestBytes([]byte("other")) }, "role digests"},
		{"root hash", func(value *OfflineFixture) { value.RootHashDigest = digestBytes([]byte("other")) }, "role digests"},
		{"boot mode", func(value *OfflineFixture) { value.BootMode = "normal" }, "boot_ramdisk"},
		{"firmware", func(value *OfflineFixture) { value.FirmwareLoaded = false }, "complete"},
		{"kernel", func(value *OfflineFixture) { value.KernelStarted = false }, "complete"},
		{"initramfs", func(value *OfflineFixture) { value.InitramfsStarted = false }, "complete"},
		{"marker", func(value *OfflineFixture) { value.CompatibilityMarkerObserved = false }, "complete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := makeTestInputs(t)
			test.mutate(&inputs.fixture)
			writeJSON(t, inputs.fixturePath, inputs.fixture)
			_, err := VerifyOfflineFixture(inputs.manifestPath, inputs.root, inputs.fixturePath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPackageHasNoRepositoryDependencies(t *testing.T) {
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "github.com/ams-tech/nixos-kaiba-network/provisioning/") {
		t.Fatalf("unfused compatibility package gained a repository dependency:\n%s", output)
	}
	if strings.Contains(string(output), "os/exec") || strings.Contains(string(output), "net") {
		t.Fatalf("unfused compatibility package gained an execution or network dependency:\n%s", output)
	}
}

func makeTestInputs(t *testing.T) testInputs {
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
		{"boot.img", []byte("immutable boot capsule")},
		{"boot.sig", []byte("detached-signature")},
		{"nvme/root-data.img", []byte("immutable root data")},
		{"nvme/root-hash.img", []byte("immutable verity hash tree")},
	}
	files := make([]CapsuleFile, 0, len(contents))
	for _, content := range contents {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, content.path)), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(root, content.path), content.data)
		files = append(files, CapsuleFile{Path: content.path, SizeBytes: int64(len(content.data)), SHA256: digestBytes(content.data)})
	}
	capsuleDigest, err := ComputeCapsuleDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	manifest := CapsuleManifest{
		SchemaVersion: ManifestSchemaVersion, CapsuleID: "capsule-fixture-1",
		CapsuleDigest: capsuleDigest, BootImagePath: "boot.img", BootSignaturePath: "boot.sig",
		RootDataPath: "nvme/root-data.img", RootHashPath: "nvme/root-hash.img", Files: files,
	}
	fixture := OfflineFixture{
		SchemaVersion: FixtureSchemaVersion, FixtureID: "fixture-1",
		CapsuleID: manifest.CapsuleID, CapsuleDigest: manifest.CapsuleDigest,
		BootImageDigest: files[0].SHA256, BootSignatureDigest: files[1].SHA256,
		RootDataDigest: files[2].SHA256, RootHashDigest: files[3].SHA256,
		BootMode:       BootModeRAMDisk,
		FirmwareLoaded: true, KernelStarted: true, InitramfsStarted: true,
		CompatibilityMarkerObserved: true,
	}
	manifestPath := filepath.Join(base, "manifest.json")
	fixturePath := filepath.Join(base, "fixture.json")
	writeJSON(t, manifestPath, manifest)
	writeJSON(t, fixturePath, fixture)
	return testInputs{root: root, manifestPath: manifestPath, fixturePath: fixturePath, manifest: manifest, fixture: fixture}
}

func writeJSON(t *testing.T, filePath string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filePath, data)
}

func mustWrite(t *testing.T, filePath string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
