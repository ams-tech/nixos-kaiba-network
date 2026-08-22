//go:build linux

package releasebindingmanifest

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	goldenCompiledArtifactSetDigest = "sha256:5e64434e63a4adec34dbb1cc19d42b22bd5740066b32d556a6b2c5348bf1cac9"
	goldenLaneGuardPackageDigest    = "sha256:b011e2609d363b2043b6f03f01f76147844ddfb554c7455e069c4f40302e550c"
)

func TestGoldenDigestVectors(t *testing.T) {
	compiled := goldenCompiledArtifactSet()
	compiledDigest, err := compiled.Digest(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	if compiledDigest != bundle.Digest(goldenCompiledArtifactSetDigest) {
		t.Fatalf("compiled-artifact-set digest = %q, want %q", compiledDigest, goldenCompiledArtifactSetDigest)
	}

	guard := goldenLaneGuardPackage(t, compiled)
	guardDigest, err := guard.Digest(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	if guardDigest != bundle.Digest(goldenLaneGuardPackageDigest) {
		t.Fatalf("lane-guard-package digest = %q, want %q", guardDigest, goldenLaneGuardPackageDigest)
	}
}

func TestCompiledArtifactSetDigestCoversOnlyClosedArtifactMaterial(t *testing.T) {
	compiled := goldenCompiledArtifactSet()
	canonical, err := compiled.CanonicalJSON(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{
		"signed_release_manifest_digest",
		"expected_customer_key_hash",
		"expected_eeprom_digest",
		"expected_boot_image_digest",
	} {
		if strings.Contains(string(canonical), excluded) {
			t.Fatalf("compiled artifact set unexpectedly contains release field %q", excluded)
		}
	}
	baseline, _ := compiled.Digest(ProductionMode)
	tests := []struct {
		name   string
		mutate func(*CompiledArtifactSet)
	}{
		{"path", func(value *CompiledArtifactSet) {
			value.Artifacts[0].Path = strings.Replace(value.Artifacts[0].Path, "artifact", "changed", 1)
		}},
		{"mode", func(value *CompiledArtifactSet) { value.Artifacts[0].Mode = "0500" }},
		{"size", func(value *CompiledArtifactSet) { value.Artifacts[0].SizeBytes++ }},
		{"content digest", func(value *CompiledArtifactSet) { value.Artifacts[0].Digest = testDigest("f") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCompiledArtifactSet(compiled)
			test.mutate(&changed)
			digest, err := changed.Digest(ProductionMode)
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatal("covered artifact mutation retained compiled-artifact-set digest")
			}
		})
	}
}

func TestSnapshotManifestsDeriveCanonicalBindingFromActualContent(t *testing.T) {
	fixture := newFilesystemFixture(t)
	reversed := append([]ArtifactPath(nil), fixture.assignments...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}

	compiled, err := SnapshotCompiledArtifactSet(reversed, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	for index, role := range CompiledArtifactRoles() {
		if compiled.Artifacts[index].Role != role {
			t.Fatalf("artifacts[%d].role = %q, want %q", index, compiled.Artifacts[index].Role, role)
		}
		if compiled.Artifacts[index].Path != fixture.paths[role] {
			t.Fatalf("artifacts[%d].path = %q, want %q", index, compiled.Artifacts[index].Path, fixture.paths[role])
		}
	}
	if compiled.Artifacts[0].Type != ArtifactRegularFile || compiled.Artifacts[0].Mode != "0555" || compiled.Artifacts[0].SizeBytes == 0 {
		t.Fatalf("regular artifact metadata was not derived: %#v", compiled.Artifacts[0])
	}
	if compiled.Artifacts[2].Type != ArtifactDirectoryTree || compiled.Artifacts[2].Mode != "0555" || compiled.Artifacts[2].SizeBytes == 0 {
		t.Fatalf("directory artifact metadata was not derived: %#v", compiled.Artifacts[2])
	}
	tree, err := bundle.SnapshotDirectoryTree(fixture.paths[RoleFreshCommitBundle])
	if err != nil {
		t.Fatal(err)
	}
	treeDigest, err := tree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Artifacts[2].Digest != treeDigest {
		t.Fatalf("directory artifact digest = %q, want tree digest %q", compiled.Artifacts[2].Digest, treeDigest)
	}
	if err := compiled.Verify(DevelopmentMode); err != nil {
		t.Fatalf("freshly snapshotted compiled set failed verification: %v", err)
	}

	canonical, err := compiled.CanonicalJSON(DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompiledArtifactSet(append(append([]byte(nil), canonical...), '\n'), DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	if parsedDigest, err := parsed.Digest(DevelopmentMode); err != nil {
		t.Fatal(err)
	} else if originalDigest, _ := compiled.Digest(DevelopmentMode); parsedDigest != originalDigest {
		t.Fatalf("parsed digest = %q, want %q", parsedDigest, originalDigest)
	}

	guard, err := SnapshotLaneGuardPackage(fixture.guardPath, compiled, fixture.release, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	guardCanonical, err := guard.CanonicalJSON(DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(guardCanonical), "lane_guard_package_digest") {
		t.Fatalf("acyclic package material contains its own digest field: %s", guardCanonical)
	}
	parsedGuard, err := ParseLaneGuardPackage(guardCanonical, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsedGuard.Verify(DevelopmentMode); err != nil {
		t.Fatalf("freshly snapshotted lane guard failed verification: %v", err)
	}

	binding, err := DeriveBinding(compiled, guard, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	compiledDigest, _ := compiled.Digest(DevelopmentMode)
	guardDigest, _ := guard.Digest(DevelopmentMode)
	if binding.CompiledArtifactSetDigest != string(compiledDigest) ||
		binding.LaneGuardPackageDigest != string(guardDigest) ||
		binding.SignedReleaseManifestDigest != string(fixture.release.SignedReleaseManifestDigest) ||
		binding.ExpectedCustomerKeyHash != string(fixture.release.ExpectedCustomerKeyHash) ||
		binding.ExpectedEEPROMDigest != string(fixture.release.ExpectedEEPROMDigest) ||
		binding.ExpectedBootImageDigest != string(fixture.release.ExpectedBootImageDigest) {
		t.Fatalf("derived binding does not match manifests: %#v", binding)
	}
}

func TestSnapshotCompiledArtifactSetIsOrderIndependentAndDefensive(t *testing.T) {
	fixture := newFilesystemFixture(t)
	first, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	reordered := append([]ArtifactPath(nil), fixture.assignments...)
	reordered[0], reordered[7] = reordered[7], reordered[0]
	second, err := SnapshotCompiledArtifactSet(reordered, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Digest(DevelopmentMode)
	secondDigest, _ := second.Digest(DevelopmentMode)
	if firstDigest != secondDigest {
		t.Fatalf("input order changed digest: %q != %q", firstDigest, secondDigest)
	}

	reordered[0].Path = "/changed-after-snapshot"
	if first.Artifacts[0].Path != fixture.paths[RolePatchedRPIBoot] {
		t.Fatal("snapshot retained caller-owned path storage")
	}
	roles := CompiledArtifactRoles()
	roles[0] = "mutated"
	if CompiledArtifactRoles()[0] != RolePatchedRPIBoot {
		t.Fatal("CompiledArtifactRoles exposed its backing array")
	}
}

func TestContentAndModeChangesInvalidateSnapshotsAndDerivedDigests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, filesystemFixture)
	}{
		{
			name: "regular-file bytes",
			mutate: func(t *testing.T, fixture filesystemFixture) {
				mustReplaceFile(t, fixture.paths[RolePatchedRPIBoot], []byte("rpiboot changed\n"), 0o555)
			},
		},
		{
			name: "regular-file mode",
			mutate: func(t *testing.T, fixture filesystemFixture) {
				if err := os.Chmod(fixture.paths[RoleGPIOSet], 0o500); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory-tree bytes",
			mutate: func(t *testing.T, fixture filesystemFixture) {
				path := filepath.Join(fixture.paths[RoleOwnedRecoveryBundle], "payload.bin")
				mustReplaceFile(t, path, []byte("changed bundle\n"), 0o444)
			},
		},
		{
			name: "directory-root mode",
			mutate: func(t *testing.T, fixture filesystemFixture) {
				if err := os.Chmod(fixture.paths[RoleRootIntegrityBundle], 0o511); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFilesystemFixture(t)
			before, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
			if err != nil {
				t.Fatal(err)
			}
			beforeDigest, _ := before.Digest(DevelopmentMode)
			test.mutate(t, fixture)
			if err := before.Verify(DevelopmentMode); err == nil {
				t.Fatal("content/metadata mutation retained verification")
			}
			after, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
			if err != nil {
				t.Fatal(err)
			}
			afterDigest, _ := after.Digest(DevelopmentMode)
			if afterDigest == beforeDigest {
				t.Fatal("content/metadata mutation retained compiled-artifact-set digest")
			}
		})
	}
}

func TestLaneGuardDigestCoversExecutableCompiledSetAndReleaseWithoutSelfReference(t *testing.T) {
	fixture := newFilesystemFixture(t)
	compiled, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := SnapshotLaneGuardPackage(fixture.guardPath, compiled, fixture.release, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := guard.Digest(DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*LaneGuardPackage)
	}{
		{"executable path", func(value *LaneGuardPackage) { value.Executable.Path += "-other" }},
		{"executable mode", func(value *LaneGuardPackage) { value.Executable.Mode = "0500" }},
		{"executable size", func(value *LaneGuardPackage) { value.Executable.SizeBytes++ }},
		{"executable digest", func(value *LaneGuardPackage) { value.Executable.Digest = testDigest("a") }},
		{"compiled set", func(value *LaneGuardPackage) { value.CompiledArtifactSetDigest = testDigest("b") }},
		{"signed release", func(value *LaneGuardPackage) { value.Release.SignedReleaseManifestDigest = testDigest("c") }},
		{"customer key", func(value *LaneGuardPackage) { value.Release.ExpectedCustomerKeyHash = testDigest("d") }},
		{"EEPROM", func(value *LaneGuardPackage) { value.Release.ExpectedEEPROMDigest = testDigest("e") }},
		{"boot image", func(value *LaneGuardPackage) { value.Release.ExpectedBootImageDigest = testDigest("f") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := guard
			test.mutate(&changed)
			digest, err := changed.Digest(DevelopmentMode)
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatal("covered field mutation retained lane-guard-package digest")
			}
		})
	}

	mustReplaceFile(t, fixture.guardPath, []byte("new guard bytes\n"), 0o555)
	if err := guard.Verify(DevelopmentMode); err == nil {
		t.Fatal("lane-guard executable byte mutation retained verification")
	}
	changed, err := SnapshotLaneGuardPackage(fixture.guardPath, compiled, fixture.release, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, _ := changed.Digest(DevelopmentMode)
	if changedDigest == baseline {
		t.Fatal("lane-guard executable byte mutation retained package digest")
	}
}

func TestDeriveBindingChecksCompiledIdentityAndUsesPackageExpectations(t *testing.T) {
	fixture := newFilesystemFixture(t)
	compiled, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := SnapshotLaneGuardPackage(fixture.guardPath, compiled, fixture.release, DevelopmentMode)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("compiled digest", func(t *testing.T) {
		changed := guard
		changed.CompiledArtifactSetDigest = testDigest("a")
		if _, err := DeriveBinding(compiled, changed, DevelopmentMode); err == nil {
			t.Fatal("mismatched compiled-artifact-set digest was accepted")
		}
	})
	t.Run("release expectations", func(t *testing.T) {
		changed := guard
		changed.Release.ExpectedBootImageDigest = testDigest("b")
		binding, err := DeriveBinding(compiled, changed, DevelopmentMode)
		if err != nil {
			t.Fatal(err)
		}
		if binding.ExpectedBootImageDigest != string(testDigest("b")) {
			t.Fatal("derived binding did not use lane-package release expectations")
		}
	})
	t.Run("duplicate executable path", func(t *testing.T) {
		changed := guard
		changed.Executable = compiled.Artifacts[0]
		changed.Executable.Role = RoleLaneGuardExecutable
		if _, err := DeriveBinding(compiled, changed, DevelopmentMode); err == nil {
			t.Fatal("lane-guard path duplicated from the compiled artifact set was accepted")
		}
	})
}

func TestFilesystemFreeProductionDerivationMatchesGoldenManifests(t *testing.T) {
	compiled := goldenCompiledArtifactSet()
	guard := goldenLaneGuardPackage(t, compiled)

	binding, err := deriveBindingFromValidatedManifests(compiled, guard, ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	if binding.CompiledArtifactSetDigest != goldenCompiledArtifactSetDigest ||
		binding.LaneGuardPackageDigest != goldenLaneGuardPackageDigest ||
		binding.SignedReleaseManifestDigest != string(guard.Release.SignedReleaseManifestDigest) ||
		binding.ExpectedCustomerKeyHash != string(guard.Release.ExpectedCustomerKeyHash) ||
		binding.ExpectedEEPROMDigest != string(guard.Release.ExpectedEEPROMDigest) ||
		binding.ExpectedBootImageDigest != string(guard.Release.ExpectedBootImageDigest) {
		t.Fatalf("filesystem-free binding does not match golden manifests: %#v", binding)
	}
}

func TestProductionValidationRequiresClosedUniqueNixStoreArtifacts(t *testing.T) {
	valid := goldenCompiledArtifactSet()
	if err := valid.Validate(ProductionMode); err != nil {
		t.Fatalf("valid production manifest rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CompiledArtifactSet)
	}{
		{"schema", func(value *CompiledArtifactSet) { value.SchemaVersion = "other" }},
		{"missing role", func(value *CompiledArtifactSet) { value.Artifacts = value.Artifacts[:7] }},
		{"role order", func(value *CompiledArtifactSet) {
			value.Artifacts[0], value.Artifacts[1] = value.Artifacts[1], value.Artifacts[0]
		}},
		{"duplicate path", func(value *CompiledArtifactSet) { value.Artifacts[1].Path = value.Artifacts[0].Path }},
		{"non-store path", func(value *CompiledArtifactSet) { value.Artifacts[0].Path = "/tmp/rpiboot" }},
		{"unclean path", func(value *CompiledArtifactSet) { value.Artifacts[0].Path += "/../rpiboot" }},
		{"backslash path", func(value *CompiledArtifactSet) { value.Artifacts[0].Path += `\bad` }},
		{"wrong type", func(value *CompiledArtifactSet) { value.Artifacts[0].Type = ArtifactDirectoryTree }},
		{"mode", func(value *CompiledArtifactSet) { value.Artifacts[0].Mode = "444" }},
		{"not executable", func(value *CompiledArtifactSet) { value.Artifacts[0].Mode = "0444" }},
		{"zero size", func(value *CompiledArtifactSet) { value.Artifacts[0].SizeBytes = 0 }},
		{"digest", func(value *CompiledArtifactSet) { value.Artifacts[0].Digest = "bad" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCompiledArtifactSet(valid)
			test.mutate(&changed)
			if err := changed.Validate(ProductionMode); err == nil {
				t.Fatal("invalid production manifest was accepted")
			}
		})
	}
	if err := valid.Validate(0); err == nil {
		t.Fatal("zero validation mode was accepted")
	}
	if err := valid.Validate(ValidationMode(255)); err == nil {
		t.Fatal("unknown validation mode was accepted")
	}

	development := cloneCompiledArtifactSet(valid)
	development.Artifacts[0].Path = "/tmp/rpiboot"
	if err := development.Validate(DevelopmentMode); err != nil {
		t.Fatalf("development mode did not allow a clean non-store path: %v", err)
	}
}

func TestSnapshotConstructorsRejectDuplicateMissingAndNonStoreAssignments(t *testing.T) {
	fixture := newFilesystemFixture(t)
	t.Run("duplicate role", func(t *testing.T) {
		paths := append([]ArtifactPath(nil), fixture.assignments...)
		paths[1].Role = paths[0].Role
		if _, err := SnapshotCompiledArtifactSet(paths, DevelopmentMode); err == nil {
			t.Fatal("duplicate role was accepted")
		}
	})
	t.Run("duplicate path", func(t *testing.T) {
		paths := append([]ArtifactPath(nil), fixture.assignments...)
		paths[1].Path = paths[0].Path
		if _, err := SnapshotCompiledArtifactSet(paths, DevelopmentMode); err == nil {
			t.Fatal("duplicate path was accepted")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := SnapshotCompiledArtifactSet(fixture.assignments[:7], DevelopmentMode); err == nil {
			t.Fatal("missing role was accepted")
		}
	})
	t.Run("lane executable role", func(t *testing.T) {
		paths := append([]ArtifactPath(nil), fixture.assignments...)
		paths[0].Role = RoleLaneGuardExecutable
		if _, err := SnapshotCompiledArtifactSet(paths, DevelopmentMode); err == nil {
			t.Fatal("lane executable was accepted in compiled artifacts")
		}
	})
	t.Run("production non-store", func(t *testing.T) {
		if _, err := SnapshotCompiledArtifactSet(fixture.assignments, ProductionMode); err == nil {
			t.Fatal("non-store production paths were accepted")
		}
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, fixture.guardPath, ProductionMode); err == nil {
			t.Fatal("non-store production executable was accepted")
		}
	})
	t.Run("lane executable duplicates compiled path", func(t *testing.T) {
		compiled, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SnapshotLaneGuardPackage(fixture.paths[RolePatchedRPIBoot], compiled, fixture.release, DevelopmentMode); err == nil {
			t.Fatal("lane-guard executable path duplicated from compiled artifacts was accepted")
		}
	})
	t.Run("invalid release expectations", func(t *testing.T) {
		compiled, err := SnapshotCompiledArtifactSet(fixture.assignments, DevelopmentMode)
		if err != nil {
			t.Fatal(err)
		}
		invalid := fixture.release
		invalid.ExpectedEEPROMDigest = "not-a-digest"
		if _, err := SnapshotLaneGuardPackage(fixture.guardPath, compiled, invalid, DevelopmentMode); err == nil {
			t.Fatal("invalid lane-package release expectations were accepted")
		}
	})
}

func TestSnapshotRejectsSymlinksAndSpecialFiles(t *testing.T) {
	t.Run("regular-file symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		mustWriteFile(t, target, []byte("target\n"), 0o555)
		link := filepath.Join(root, "link")
		if err := os.Symlink("target", link); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, link, DevelopmentMode); err == nil {
			t.Fatal("regular-file symlink was accepted")
		}
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		root := t.TempDir()
		real := filepath.Join(root, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(real, "guard")
		mustWriteFile(t, target, []byte("guard\n"), 0o555)
		alias := filepath.Join(root, "alias")
		if err := os.Symlink("real", alias); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, filepath.Join(alias, "guard"), DevelopmentMode); err == nil {
			t.Fatal("symlink ancestor was accepted")
		}
	})
	t.Run("FIFO", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(path, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, path, DevelopmentMode); err == nil {
			t.Fatal("FIFO was accepted")
		}
	})
	t.Run("socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "socket")
		listener, err := net.Listen("unix", path)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("Unix sockets are not permitted in this sandbox")
			}
			t.Fatal(err)
		}
		defer listener.Close()
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, path, DevelopmentMode); err == nil {
			t.Fatal("Unix socket was accepted")
		}
	})
	t.Run("setuid regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "guard")
		mustWriteFile(t, path, []byte("guard\n"), 0o555)
		if err := os.Chmod(path, 0o555|os.ModeSetuid); err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("setuid file modes are not permitted in this sandbox")
			}
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RoleLaneGuardExecutable, path, DevelopmentMode); err == nil {
			t.Fatal("setuid regular file was accepted")
		}
	})
	t.Run("directory-tree symlink", func(t *testing.T) {
		root := t.TempDir()
		bundlePath := filepath.Join(root, "bundle")
		mustMkdir(t, bundlePath, 0o755)
		t.Cleanup(func() { _ = os.Chmod(bundlePath, 0o755) })
		mustWriteFile(t, filepath.Join(bundlePath, "target"), []byte("target\n"), 0o444)
		if err := os.Symlink("target", filepath.Join(bundlePath, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(bundlePath, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RoleFreshCommitBundle, bundlePath, DevelopmentMode); err == nil {
			t.Fatal("directory-tree symlink was accepted")
		}
	})
	t.Run("wrong kind", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "directory")
		mustMkdir(t, directory, 0o755)
		t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })
		mustWriteFile(t, filepath.Join(directory, "file"), []byte("file\n"), 0o444)
		if err := os.Chmod(directory, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotArtifact(RolePatchedRPIBoot, directory, DevelopmentMode); err == nil {
			t.Fatal("directory was accepted for a regular-file role")
		}
		file := filepath.Join(root, "file")
		mustWriteFile(t, file, []byte("file\n"), 0o555)
		if _, err := snapshotArtifact(RoleFreshCommitBundle, file, DevelopmentMode); err == nil {
			t.Fatal("regular file was accepted for a directory-tree role")
		}
	})
}

func TestStrictCanonicalParsersRejectAmbiguousJSON(t *testing.T) {
	compiled := goldenCompiledArtifactSet()
	canonical, err := compiled.CanonicalJSON(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	guard := goldenLaneGuardPackage(t, compiled)
	guardCanonical, err := guard.CanonicalJSON(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}

	compiledTests := []struct {
		name  string
		input []byte
	}{
		{"null", []byte(strings.Replace(string(canonical), `"artifacts":[`, `"artifacts":null,"discarded":[`, 1))},
		{"unknown", []byte(strings.Replace(string(canonical), `"schema_version":`, `"unknown":true,"schema_version":`, 1))},
		{"duplicate", []byte(strings.Replace(string(canonical), `"schema_version":"`+CompiledArtifactSetSchemaV1Alpha1+`"`, `"schema_version":"`+CompiledArtifactSetSchemaV1Alpha1+`","schema_version":"`+CompiledArtifactSetSchemaV1Alpha1+`"`, 1))},
		{"leading whitespace", append([]byte{' '}, canonical...)},
		{"trailing value", append(append([]byte(nil), canonical...), []byte(`{}`)...)},
	}
	for _, test := range compiledTests {
		t.Run("compiled "+test.name, func(t *testing.T) {
			if _, err := ParseCompiledArtifactSet(test.input, ProductionMode); err == nil {
				t.Fatal("ambiguous compiled manifest JSON was accepted")
			}
		})
	}
	guardTests := []struct {
		name  string
		input []byte
	}{
		{"null", []byte(strings.Replace(string(guardCanonical), `"release":{`, `"release":null,"discarded":{`, 1))},
		{"unknown", []byte(strings.Replace(string(guardCanonical), `"executable":`, `"unknown":true,"executable":`, 1))},
		{"self digest", []byte(strings.Replace(string(guardCanonical), `"compiled_artifact_set_digest":`, `"lane_guard_package_digest":"`+strings.Repeat("f", 64)+`","compiled_artifact_set_digest":`, 1))},
		{"duplicate", []byte(strings.Replace(string(guardCanonical), `"compiled_artifact_set_digest":"`, `"compiled_artifact_set_digest":"`+strings.Repeat("a", 64)+`","compiled_artifact_set_digest":"`, 1))},
		{"leading whitespace", append([]byte{'\n'}, guardCanonical...)},
		{"trailing value", append(append([]byte(nil), guardCanonical...), []byte(`[]`)...)},
	}
	for _, test := range guardTests {
		t.Run("guard "+test.name, func(t *testing.T) {
			if _, err := ParseLaneGuardPackage(test.input, ProductionMode); err == nil {
				t.Fatal("ambiguous lane-guard manifest JSON was accepted")
			}
		})
	}

	if _, err := ParseCompiledArtifactSet(append(append([]byte(nil), canonical...), '\n'), ProductionMode); err != nil {
		t.Fatalf("single final LF was rejected: %v", err)
	}
	if _, err := ParseLaneGuardPackage(append(append([]byte(nil), guardCanonical...), '\n'), ProductionMode); err != nil {
		t.Fatalf("single final LF was rejected: %v", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	compiled := goldenCompiledArtifactSet()
	compiledJSON, err := compiled.CanonicalJSON(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	compiledDigest, _ := compiled.Digest(ProductionMode)
	if raw := bundle.Sum(compiledJSON); raw == compiledDigest {
		t.Fatal("compiled-artifact-set digest was not domain separated")
	}

	guard := goldenLaneGuardPackage(t, compiled)
	guardJSON, err := guard.CanonicalJSON(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	guardDigest, _ := guard.Digest(ProductionMode)
	if raw := bundle.Sum(guardJSON); raw == guardDigest {
		t.Fatal("lane-guard-package digest was not domain separated")
	}
	if sameMaterialWrongDomain := domainDigest(compiledArtifactSetDigestDomain, guardJSON); sameMaterialWrongDomain == guardDigest {
		t.Fatal("compiled and lane-guard domains are not distinct")
	}
}

type filesystemFixture struct {
	release     ReleaseExpectations
	assignments []ArtifactPath
	paths       map[ArtifactRole]string
	guardPath   string
}

func newFilesystemFixture(t *testing.T) filesystemFixture {
	t.Helper()
	root := t.TempDir()
	paths := make(map[ArtifactRole]string, len(compiledArtifactRoles))
	for index, role := range compiledArtifactRoles {
		kind, _ := expectedArtifactType(role)
		path := filepath.Join(root, strings.TrimPrefix(string(role), "rpi5."))
		paths[role] = path
		switch kind {
		case ArtifactRegularFile:
			mustWriteFile(t, path, []byte("executable "+string(role)+"\n"), 0o555)
		case ArtifactDirectoryTree:
			mustMkdir(t, path, 0o755)
			t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
			mustWriteFile(t, filepath.Join(path, "payload.bin"), []byte("bundle "+string(role)+"\n"), 0o444)
			mustWriteFile(t, filepath.Join(path, "sequence.txt"), []byte{byte('0' + index), '\n'}, 0o444)
			if err := os.Chmod(path, 0o555); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("fixture role %q has no type", role)
		}
	}
	assignments := make([]ArtifactPath, 0, len(compiledArtifactRoles))
	for _, role := range compiledArtifactRoles {
		assignments = append(assignments, ArtifactPath{Role: role, Path: paths[role]})
	}
	guardPath := filepath.Join(root, "kaiba-provision-lane-guard")
	mustWriteFile(t, guardPath, []byte("lane guard executable\n"), 0o555)
	return filesystemFixture{
		release:     testReleaseExpectations(),
		assignments: assignments,
		paths:       paths,
		guardPath:   guardPath,
	}
}

func goldenCompiledArtifactSet() CompiledArtifactSet {
	artifacts := make([]Artifact, 0, len(compiledArtifactRoles))
	for index, role := range compiledArtifactRoles {
		kind, _ := expectedArtifactType(role)
		artifacts = append(artifacts, Artifact{
			Role:      role,
			Path:      "/nix/store/" + strings.Repeat(string('0'+rune(index)), 32) + "-artifact-" + strings.ReplaceAll(string(role), ".", "-") + artifactSuffix(kind),
			Type:      kind,
			Mode:      "0555",
			SizeBytes: uint64(index + 1),
			Digest:    testDigest(string('1' + rune(index))),
		})
	}
	return CompiledArtifactSet{
		SchemaVersion: CompiledArtifactSetSchemaV1Alpha1,
		Artifacts:     artifacts,
	}
}

func goldenLaneGuardPackage(t *testing.T, compiled CompiledArtifactSet) LaneGuardPackage {
	t.Helper()
	compiledDigest, err := compiled.Digest(ProductionMode)
	if err != nil {
		t.Fatal(err)
	}
	return LaneGuardPackage{
		SchemaVersion: LaneGuardPackageSchemaV1Alpha1,
		Executable: Artifact{
			Role: RoleLaneGuardExecutable,
			Path: "/nix/store/99999999999999999999999999999999-lane-guard/bin/kaiba-provision-lane-guard",
			Type: ArtifactRegularFile,
			Mode: "0555", SizeBytes: 1234, Digest: testDigest("a"),
		},
		CompiledArtifactSetDigest: compiledDigest,
		Release:                   testReleaseExpectations(),
	}
}

func artifactSuffix(kind ArtifactType) string {
	if kind == ArtifactRegularFile {
		return "/bin/tool"
	}
	return "/bundle"
}

func testReleaseExpectations() ReleaseExpectations {
	return ReleaseExpectations{
		SignedReleaseManifestDigest: testDigest("1"),
		ExpectedCustomerKeyHash:     testDigest("2"),
		ExpectedEEPROMDigest:        testDigest("3"),
		ExpectedBootImageDigest:     testDigest("4"),
	}
}

func testDigest(character string) bundle.Digest {
	return bundle.Digest("sha256:" + strings.Repeat(character, 64))
}

func cloneCompiledArtifactSet(source CompiledArtifactSet) CompiledArtifactSet {
	clone := source
	clone.Artifacts = append([]Artifact(nil), source.Artifacts...)
	return clone
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustReplaceFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
