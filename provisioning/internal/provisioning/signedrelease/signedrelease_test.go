package signedrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func TestPublishAndVerifyCompleteContentAddressedRelease(t *testing.T) {
	release := syntheticResolvedRelease(t)
	output := filepath.Join(t.TempDir(), "release")
	t.Cleanup(func() { removeTemporaryTree(output) })
	if err := Publish(release, output); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	manifest, err := VerifyPublication(output)
	if err != nil {
		t.Fatalf("VerifyPublication() error = %v", err)
	}
	wantDigest, _ := release.Manifest.Digest()
	gotDigest, _ := manifest.Digest()
	if gotDigest != wantDigest || len(manifest.Artifacts) != 18 {
		t.Fatalf("published manifest digest=%s artifacts=%d", gotDigest, len(manifest.Artifacts))
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("publication root mode=%v err=%v, want 0555", info.Mode().Perm(), err)
	}
	if err := Publish(release, output); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Publish() error=%v, want no-replace rejection", err)
	}
}

func TestVerifyPublicationRejectsTamperingAndAdditions(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, ResolvedRelease)
	}{
		{
			name: "publication digest",
			mutate: func(t *testing.T, root string, _ ResolvedRelease) {
				path := filepath.Join(root, "publication-digest")
				mustChmod(t, path, 0644)
				mustWriteExisting(t, path, []byte("sha256:"+strings.Repeat("0", 64)+"\n"))
			},
		},
		{
			name: "regular object",
			mutate: func(t *testing.T, root string, release ResolvedRelease) {
				artifact := release.Manifest.Artifacts[0]
				path := filepath.Join(root, "objects", "sha256", digestHex(artifact.Digest))
				mustChmod(t, path, 0644)
				mustWriteExisting(t, path, []byte("tampered"))
			},
		},
		{
			name: "extra root entry",
			mutate: func(t *testing.T, root string, _ ResolvedRelease) {
				mustChmod(t, root, 0755)
				if err := os.WriteFile(filepath.Join(root, "extra"), []byte("extra"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := syntheticResolvedRelease(t)
			output := filepath.Join(t.TempDir(), "release")
			t.Cleanup(func() { removeTemporaryTree(output) })
			if err := Publish(release, output); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, output, release)
			if _, err := VerifyPublication(output); err == nil {
				t.Fatal("VerifyPublication() accepted a mutated publication")
			}
		})
	}
}

func TestNoFollowAndSecretBoundaries(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { removeTemporaryTree(root) })
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("prefix -----BEGIN PRIVATE KEY----- suffix"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectRegular(secret, 1024, true); err == nil || !strings.Contains(err.Error(), "private-key") {
		t.Fatalf("inspectRegular(secret) error=%v", err)
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectRegular(link, 1024, true); err == nil {
		t.Fatal("inspectRegular() followed a symbolic link")
	}
	tree := filepath.Join(root, "tree")
	if err := os.Mkdir(tree, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, filepath.Join(tree, "entry")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectTree(tree); err == nil {
		t.Fatal("inspectTree() accepted a symbolic link")
	}
}

func TestResolveRequiresReplayVerifierBeforeReadingInputs(t *testing.T) {
	_, err := Resolve(context.Background(), Inputs{}, Options{})
	if err == nil || !strings.Contains(err.Error(), "replay verifier") {
		t.Fatalf("Resolve() error=%v, want fail-closed replay boundary", err)
	}
}

func TestUnsignedArtifactSetRejectsDuplicateNullAndBadDigest(t *testing.T) {
	valid := validUnsignedArtifactSet(t)
	if _, err := parseUnsignedArtifactSet(valid); err != nil {
		t.Fatalf("parseUnsignedArtifactSet(valid) error=%v", err)
	}
	for _, test := range []struct {
		name  string
		value []byte
	}{
		{"duplicate", []byte(`{"schema":"x","schema":"y"}`)},
		{"null", []byte(`{"schema":null}`)},
		{"bad digest", bytes.Replace(valid, []byte(`"bundle_digest":"sha256:`), []byte(`"bundle_digest":"sha256:0`), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseUnsignedArtifactSet(test.value); err == nil {
				t.Fatal("invalid unsigned artifact set was accepted")
			}
		})
	}
}

func TestUnsignedArtifactSetRequiresDistinctCanonicalPARTUUIDSelectors(t *testing.T) {
	valid, err := parseUnsignedArtifactSet(validUnsignedArtifactSet(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*unsignedArtifactSet)
	}{
		{"kernel enumeration path", func(value *unsignedArtifactSet) { value.Verity.DataDevice = "/dev/nvme0n1p2" }},
		{"by-partuuid path", func(value *unsignedArtifactSet) {
			value.Verity.DataDevice = "/dev/disk/by-partuuid/bdd5be20-f7ea-56e7-ae90-4465ae950596"
		}},
		{"uppercase guid", func(value *unsignedArtifactSet) {
			value.Verity.DataDevice = "PARTUUID=BDD5BE20-F7EA-56E7-AE90-4465AE950596"
		}},
		{"zero guid", func(value *unsignedArtifactSet) {
			value.Verity.DataDevice = "PARTUUID=00000000-0000-0000-0000-000000000000"
		}},
		{"same partition", func(value *unsignedArtifactSet) { value.Verity.HashDevice = value.Verity.DataDevice }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("unsigned artifact set accepted an unsafe partition selector")
			}
		})
	}
}

func TestCompareExactDirectoriesBindsModesAndContent(t *testing.T) {
	root := t.TempDir()
	left, right := filepath.Join(root, "left"), filepath.Join(root, "right")
	for _, path := range []string{left, right} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "file"), []byte("same"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CompareExactDirectories(left, right); err != nil {
		t.Fatalf("CompareExactDirectories()=%v", err)
	}
	if err := os.Chmod(filepath.Join(right, "file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CompareExactDirectories(left, right); err == nil {
		t.Fatal("mode difference was accepted")
	}
}

func TestTreePayloadLimitAccommodatesProductionRootImages(t *testing.T) {
	if err := validateTreePayloadSize(513 * 1024 * 1024); err != nil {
		t.Fatalf("production-sized root-integrity tree was rejected: %v", err)
	}
	if err := validateTreePayloadSize(0); err == nil {
		t.Fatal("empty directory-tree payload was accepted")
	}
	if err := validateTreePayloadSize(uint64(^uint64(0)>>1) + 1); err == nil {
		t.Fatal("directory-tree payload beyond supported file offsets was accepted")
	}
}

func TestRetainedPublicationParentDetectsPathReplacement(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	handle, identity, err := openAbsolute(parent, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	displaced := filepath.Join(root, "displaced")
	if err := os.Rename(parent, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := requireSameDirectoryNode(parent, identity); err == nil {
		t.Fatal("replaced publication parent retained the original identity")
	}
	if err := os.Mkdir(filepath.Join(displaced, "temporary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplaceAt(int(handle.Fd()), "temporary", int(handle.Fd()), "published"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(displaced, "published")); err != nil {
		t.Fatalf("fd-relative publication did not remain under retained parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "published")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fd-relative publication was redirected through replaced path: %v", err)
	}
}

func syntheticResolvedRelease(t *testing.T) ResolvedRelease {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() { removeTemporaryTree(root) })
	files := make(map[bundle.ArtifactRole]regularSource)
	trees := make(map[bundle.ArtifactRole]treeSource)
	treeRoles := map[bundle.ArtifactRole]bool{
		bundle.RoleFreshCommitBundle: true, bundle.RoleFreshReadbackBundle: true,
		bundle.RoleNegativeBootBundle: true, bundle.RoleOwnedReadbackBundle: true,
		bundle.RoleOwnedRecoveryBundle: true, bundle.RoleRootIntegrityTestBundle: true,
	}
	artifacts := make([]bundle.ReleaseArtifact, 0, 18)
	for index, role := range bundle.SignedReleaseRoles() {
		if treeRoles[role] {
			path := filepath.Join(root, fmt.Sprintf("tree-%02d", index))
			if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, "payload.bin")
			if err := os.WriteFile(file, []byte(fmt.Sprintf("tree payload %d", index)), 0444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0555); err != nil {
				t.Fatal(err)
			}
			source, err := inspectTree(path)
			if err != nil {
				t.Fatal(err)
			}
			trees[role] = source
			digest, _ := source.tree.Digest()
			size, _ := source.tree.SizeBytes()
			tree := source.tree
			artifacts = append(artifacts, bundle.ReleaseArtifact{Role: role, Kind: bundle.ArtifactKindDirectoryTree, Digest: digest, SizeBytes: size, Tree: &tree})
			continue
		}
		path := filepath.Join(root, fmt.Sprintf("file-%02d", index))
		if err := os.WriteFile(path, []byte(fmt.Sprintf("public artifact %d", index)), 0444); err != nil {
			t.Fatal(err)
		}
		source, err := inspectRegular(path, 1024, false)
		if err != nil {
			t.Fatal(err)
		}
		files[role] = source
		artifacts = append(artifacts, bundle.ReleaseArtifact{Role: role, Kind: bundle.ArtifactKindRegularFile, Digest: source.digest, SizeBytes: source.size})
	}
	manifest, err := bundle.NewSignedReleaseManifest(
		"release:rpi5:test", strings.Repeat("a", 40), bundle.Sum([]byte("intent")), bundle.Sum([]byte("policy")), bundle.Sum([]byte("customer")), artifacts,
	)
	if err != nil {
		t.Fatal(err)
	}
	records := make(map[string]regularSource)
	for _, id := range []string{"boot_signing_plan", "boot_signing_result", "eeprom_release_manifest", "eeprom_signing_plan", "eeprom_signing_result", "owned_recovery_plan", "owned_recovery_result", "release_intent", "unsigned_artifact_set"} {
		records[id] = memorySource([]byte("record " + id + "\n"))
	}
	publication, err := newPublication(manifest, records)
	if err != nil {
		t.Fatal(err)
	}
	return ResolvedRelease{Manifest: manifest, Publication: publication, files: files, trees: trees, records: records}
}

func validUnsignedArtifactSet(t *testing.T) []byte {
	t.Helper()
	value := unsignedArtifactSet{
		Schema: unsignedArtifactSchema, SourceRevision: strings.Repeat("a", 40), ExpectedCustomerKeyHash: bundle.Sum([]byte("key")),
		BootOrderPolicy: "nvme-only", BootCommandLinePath: "nixos/default/cmdline.txt",
		FirmwareAllowlist:  []string{"config.txt", "kaiba-root-integrity.json", "nixos/default/bcm2712-rpi-5-b.dtb", "nixos/default/cmdline.txt", "nixos/default/initrd", "nixos/default/kernel.img"},
		BootImageSizeBytes: 32 * 1024 * 1024, PersistentMutableState: "tmpfs-only", RollbackPolicy: "unimplemented-block-enrollment-ready",
		DebugPolicy: "videocore-jtag-unlocked-development", EEPROMWriteProtectionPolicy: "unlocked-development",
		Toolchain: unsignedToolchain{Cryptsetup: "1", Dosfstools: "1", Mtools: "1"},
		Artifacts: unsignedArtifacts{
			BootImage:    unsignedArtifact{Path: "unsigned/boot.img", Digest: bundle.Sum([]byte("boot"))},
			RootData:     unsignedArtifact{Path: "nvme/root-data.img", Digest: bundle.Sum([]byte("root"))},
			RootHashTree: unsignedArtifact{Path: "nvme/root-hash.img", Digest: bundle.Sum([]byte("hash"))},
		},
		Verity:              unsignedVerity{Algorithm: "sha256", DataBlockSize: 4096, HashBlockSize: 4096, UUID: "12345678-1234-1234-1234-123456789abc", DataDevice: "PARTUUID=bdd5be20-f7ea-56e7-ae90-4465ae950596", HashDevice: "PARTUUID=62616022-71fb-5036-8cc4-b7949cc6e52c", Mapper: "/dev/mapper/root"},
		RootIntegrityDigest: bundle.Sum([]byte("root hash")), SigningStatus: "unsigned",
	}
	without, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(without))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	delete(object, "bundle_digest")
	canonical, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	value.BundleDigest = domainDigest("kaiba.rpi5.unsigned-artifacts.v1", canonical)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
func mustWriteExisting(t *testing.T, path string, contents []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
