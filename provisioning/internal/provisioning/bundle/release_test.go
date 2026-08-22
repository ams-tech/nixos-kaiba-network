package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const testSourceRevision = "0123456789abcdef0123456789abcdef01234567"

func TestSignedReleaseManifestCanonicalDigestIsStable(t *testing.T) {
	artifacts := testReleaseArtifacts(t)
	reversed := append([]ReleaseArtifact(nil), artifacts...)
	slices.Reverse(reversed)

	first := newTestSignedReleaseManifest(t, reversed)
	second := newTestSignedReleaseManifest(t, artifacts)
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("signed-release digests differ: %s != %s", firstDigest, secondDigest)
	}
	const want Digest = "sha256:ee712323f508f3961a6268045bd0aa793b6233e63b94b4adea9b385378528cad"
	if firstDigest != want {
		t.Fatalf("signed-release digest = %s, want golden %s", firstDigest, want)
	}

	canonical, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/rpi5-signed-release-manifest-v1alpha2.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture = bytes.TrimSuffix(fixture, []byte("\n"))
	if !bytes.Equal(canonical, fixture) {
		t.Fatalf("canonical manifest differs from checked golden fixture\ngot:  %s\nwant: %s", canonical, fixture)
	}
	parsed, err := ParseSignedReleaseManifest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	parsedDigest, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if parsedDigest != firstDigest {
		t.Fatalf("round-trip digest = %s, want %s", parsedDigest, firstDigest)
	}
	for index, role := range SignedReleaseRoles() {
		if parsed.Artifacts[index].Role != role {
			t.Fatalf("artifacts[%d].role = %q, want %q", index, parsed.Artifacts[index].Role, role)
		}
	}
}

func TestSignedReleaseManifestDigestBindsReleaseIntent(t *testing.T) {
	manifest := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	first, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest.ReleaseIntentDigest = Sum([]byte("different release intent"))
	second, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("signed-release digest did not bind release_intent_digest: %s", first)
	}
}

func TestNewSignedReleaseManifestCopiesArtifactsAndTrees(t *testing.T) {
	artifacts := testReleaseArtifacts(t)
	manifest := newTestSignedReleaseManifest(t, artifacts)

	artifacts[0].Role = RoleBootImage
	for index := range artifacts {
		if artifacts[index].Tree != nil {
			artifacts[index].Tree.Entries[0].Path = "changed"
			break
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("manifest changed through caller-owned input: %v", err)
	}
}

func TestSignedReleaseManifestRejectsIncompleteOrAmbiguousRoleSets(t *testing.T) {
	valid := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	for index, role := range SignedReleaseRoles() {
		t.Run("missing "+string(role), func(t *testing.T) {
			candidate := cloneTestSignedReleaseManifest(valid)
			candidate.Artifacts = append(candidate.Artifacts[:index:index], candidate.Artifacts[index+1:]...)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), "exactly 18") {
				t.Fatalf("Validate() error = %v, want exact-set rejection", err)
			}
		})
	}
	tests := []struct {
		name  string
		match string
		alter func(*SignedReleaseManifest)
	}{
		{
			name: "extra role", match: "exactly 18",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts = append(manifest.Artifacts, manifest.Artifacts[0])
			},
		},
		{
			name: "duplicate role", match: "duplicated",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[1].Role = manifest.Artifacts[0].Role
			},
		},
		{
			name: "wrong order", match: "role must be",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[0], manifest.Artifacts[1] = manifest.Artifacts[1], manifest.Artifacts[0]
			},
		},
		{
			name: "unknown role", match: "not supported",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[0].Role = ArtifactRole("rpi5.browser_supplied")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestSignedReleaseManifest(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestSignedReleaseManifestRejectsArtifactKindMismatch(t *testing.T) {
	valid := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	fileIndex := releaseArtifactIndex(t, valid, RoleBootImage)
	treeIndex := releaseArtifactIndex(t, valid, RoleFreshCommitBundle)
	emptyTree, err := NewDirectoryTree("0755", []TreeEntry{{
		Path: "empty", Type: TreeEntryRegularFile, Mode: "0644", Digest: Sum(nil),
	}})
	if err != nil {
		t.Fatal(err)
	}
	emptyTreeDigest, err := emptyTree.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		match string
		alter func(*SignedReleaseManifest)
	}{
		{
			name: "file declared as tree", match: `kind must be "regular_file"`,
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[fileIndex].Kind = ArtifactKindDirectoryTree
			},
		},
		{
			name: "file embeds tree", match: "tree must be absent",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[fileIndex].Tree = manifest.Artifacts[treeIndex].Tree
			},
		},
		{
			name: "tree declared as file", match: `kind must be "directory_tree"`,
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].Kind = ArtifactKindRegularFile
			},
		},
		{
			name: "tree omitted", match: "tree is required",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].Tree = nil
			},
		},
		{
			name: "zero file size", match: "must be positive",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[fileIndex].SizeBytes = 0
			},
		},
		{
			name: "zero tree payload size", match: "must be positive",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].Tree = &emptyTree
				manifest.Artifacts[treeIndex].Digest = emptyTreeDigest
				manifest.Artifacts[treeIndex].SizeBytes = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestSignedReleaseManifest(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestSignedReleaseManifestRejectsStaleTreeBinding(t *testing.T) {
	valid := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	treeIndex := releaseArtifactIndex(t, valid, RoleOwnedRecoveryBundle)
	tests := []struct {
		name  string
		match string
		alter func(*SignedReleaseManifest)
	}{
		{
			name: "stale digest", match: "digest does not match",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].Digest = Sum([]byte("stale tree"))
			},
		},
		{
			name: "stale size", match: "size_bytes does not match",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].SizeBytes++
			},
		},
		{
			name: "mutated tree", match: "digest does not match",
			alter: func(manifest *SignedReleaseManifest) {
				manifest.Artifacts[treeIndex].Tree.Entries[0].Digest = Sum([]byte("mutated content"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestSignedReleaseManifest(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestSignedReleaseManifestRejectsInvalidIdentityBindings(t *testing.T) {
	valid := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	tests := []struct {
		name  string
		match string
		alter func(*SignedReleaseManifest)
	}{
		{"schema", "unsupported", func(value *SignedReleaseManifest) { value.SchemaVersion = "v2" }},
		{"release ID", "release_id", func(value *SignedReleaseManifest) { value.ReleaseID = "UPPER" }},
		{"device class", "device_class", func(value *SignedReleaseManifest) { value.DeviceClass = "raspberry-pi-5" }},
		{"short revision", "source_revision", func(value *SignedReleaseManifest) { value.SourceRevision = strings.Repeat("a", 39) }},
		{"uppercase revision", "source_revision", func(value *SignedReleaseManifest) { value.SourceRevision = strings.Repeat("A", 40) }},
		{"release intent digest", "release_intent_digest", func(value *SignedReleaseManifest) { value.ReleaseIntentDigest = "sha256:no" }},
		{"policy digest", "signing_policy_digest", func(value *SignedReleaseManifest) { value.SigningPolicyDigest = "sha256:no" }},
		{"customer key hash", "expected_customer_key_hash", func(value *SignedReleaseManifest) { value.ExpectedCustomerKeyHash = "sha256:no" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestSignedReleaseManifest(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}

	valid.SourceRevision = strings.Repeat("a", 64)
	if err := valid.Validate(); err != nil {
		t.Fatalf("64-character source revision rejected: %v", err)
	}
}

func TestSignedReleaseManifestStrictJSON(t *testing.T) {
	manifest := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	canonical, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	valid := string(canonical)
	v1alpha1, err := os.ReadFile("testdata/rpi5-signed-release-manifest-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		input string
		match string
	}{
		{
			"unknown top-level field",
			strings.Replace(valid, `"release_id"`, `"unexpected":true,"release_id"`, 1),
			"unknown field",
		},
		{
			"duplicate top-level field",
			strings.Replace(valid, `"release_id":"release:rpi5:1"`, `"release_id":"release:rpi5:1","release_id":"release:rpi5:2"`, 1),
			"duplicated",
		},
		{
			"null field",
			strings.Replace(valid, `"release_id":"release:rpi5:1"`, `"release_id":null`, 1),
			"null",
		},
		{
			"missing release-intent lineage",
			strings.Replace(valid, `"release_intent_digest":"`+string(manifest.ReleaseIntentDigest)+`",`, "", 1),
			"release_intent_digest",
		},
		{
			"v1alpha1 schema with release-intent lineage",
			strings.Replace(valid, SignedReleaseManifestSchemaV1Alpha2, "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha1", 1),
			"unsupported",
		},
		{
			"v1alpha1 manifest without release-intent lineage",
			string(v1alpha1),
			"unsupported",
		},
		{
			"unknown tree field",
			strings.Replace(valid, `"root_mode":"0755"`, `"root_mode":"0755","owner":"root"`, 1),
			"unknown field",
		},
		{"trailing value", valid + `{}`, "trailing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseSignedReleaseManifest([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseSignedReleaseManifest() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestSignedReleaseManifestPreservesLegacyManifest(t *testing.T) {
	legacy, err := NewManifest(
		"legacy-signed-boot",
		"raspberry-pi-5",
		Sum([]byte("legacy policy")),
		[]Artifact{
			{Role: RoleBootSignature, Digest: Sum([]byte("signature")), SizeBytes: 256},
			{Role: RoleBootImage, Digest: Sum([]byte("image")), SizeBytes: 5},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.SchemaVersion != ManifestSchemaV1Alpha1 || len(legacy.Artifacts) != 2 {
		t.Fatalf("legacy manifest changed: %+v", legacy)
	}
	encoded, err := legacy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(encoded); err != nil {
		t.Fatalf("legacy manifest no longer parses: %v", err)
	}
	expandedSubset, err := NewManifest(
		"legacy-root-data-subset",
		"raspberry-pi-5",
		Sum([]byte("legacy policy")),
		[]Artifact{{Role: RoleRootDataImage, Digest: Sum([]byte("root data")), SizeBytes: 9}},
	)
	if err != nil {
		t.Fatalf("v1alpha1 subset manifest rejected an expanded closed role: %v", err)
	}
	if expandedSubset.SchemaVersion != ManifestSchemaV1Alpha1 || len(expandedSubset.Artifacts) != 1 {
		t.Fatalf("unexpected expanded v1alpha1 subset: %+v", expandedSubset)
	}
}

func TestSignedReleaseArtifactRolesAreClosedAndNonSignable(t *testing.T) {
	want := []ArtifactRole{
		RoleBootPublicKey, RoleDeviceProfile, RolePlatformAdapter, RoleRootIntegrity,
		RoleBootImage, RoleBootSignature, RoleEEPROMBootsys, RoleEEPROMConfig,
		RoleFreshCommitBundle, RoleFreshReadbackBundle, RoleNegativeBootBundle,
		RoleOwnedReadbackBundle, RoleOwnedRecoveryBootcode, RoleOwnedRecoveryBundle,
		RoleRootDataImage, RoleRootHashTreeImage, RoleRootIntegrityTestBundle,
		RoleSignedEEPROMImage,
	}
	if got := SignedReleaseRoles(); !slices.Equal(got, want) {
		t.Fatalf("SignedReleaseRoles() = %q, want %q", got, want)
	}
	for _, role := range []ArtifactRole{
		RoleFreshReadbackBundle,
		RoleNegativeBootBundle,
		RoleOwnedReadbackBundle,
		RoleRootDataImage,
		RoleRootHashTreeImage,
		RoleRootIntegrityTestBundle,
	} {
		if err := role.Validate(); err != nil {
			t.Fatalf("new role %q is not in the closed vocabulary: %v", role, err)
		}
		if role.Signable() {
			t.Fatalf("new release output role %q unexpectedly signable", role)
		}
	}
	for _, role := range []ArtifactRole{RoleBootImage, RoleEEPROMBootcode, RoleEEPROMConfig, RoleEEPROMBootsys, RoleOwnedRecoveryBootcode} {
		if !role.Signable() {
			t.Fatalf("existing signing-input role %q is no longer signable", role)
		}
	}
	if slices.Contains(SignedReleaseRoles(), RoleEEPROMBootcode) {
		t.Fatal("EEPROM bootcode signing input unexpectedly became a final signed-release role")
	}
}

func testReleaseArtifacts(t *testing.T) []ReleaseArtifact {
	t.Helper()
	artifacts := make([]ReleaseArtifact, 0, len(signedReleaseRoles))
	for _, role := range signedReleaseRoles {
		payload := []byte("artifact:" + string(role))
		if _, isTree := signedReleaseTreeRoles[role]; !isTree {
			artifacts = append(artifacts, ReleaseArtifact{
				Role: role, Kind: ArtifactKindRegularFile,
				Digest: Sum(payload), SizeBytes: uint64(len(payload)),
			})
			continue
		}
		tree, err := NewDirectoryTree("0755", []TreeEntry{{
			Path: "bootcode4.bin", Type: TreeEntryRegularFile, Mode: "0644",
			SizeBytes: uint64(len(payload)), Digest: Sum(payload),
		}})
		if err != nil {
			t.Fatalf("construct tree for %q: %v", role, err)
		}
		digest, err := tree.Digest()
		if err != nil {
			t.Fatal(err)
		}
		size, err := tree.SizeBytes()
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, ReleaseArtifact{
			Role: role, Kind: ArtifactKindDirectoryTree,
			Digest: digest, SizeBytes: size, Tree: &tree,
		})
	}
	return artifacts
}

func newTestSignedReleaseManifest(t *testing.T, artifacts []ReleaseArtifact) SignedReleaseManifest {
	t.Helper()
	manifest, err := NewSignedReleaseManifest(
		"release:rpi5:1",
		testSourceRevision,
		Sum([]byte("release intent")),
		Sum([]byte("signing policy")),
		Sum([]byte("customer key")),
		artifacts,
	)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func cloneTestSignedReleaseManifest(manifest SignedReleaseManifest) SignedReleaseManifest {
	manifest.Artifacts = cloneReleaseArtifacts(manifest.Artifacts)
	return manifest
}

func releaseArtifactIndex(t *testing.T, manifest SignedReleaseManifest, role ArtifactRole) int {
	t.Helper()
	for index, artifact := range manifest.Artifacts {
		if artifact.Role == role {
			return index
		}
	}
	t.Fatalf("release artifact role %q not found", role)
	return -1
}

func TestSignedReleaseManifestJSONUsesNoNullTrees(t *testing.T) {
	manifest := newTestSignedReleaseManifest(t, testReleaseArtifacts(t))
	canonical, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(canonical, &document); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), `"tree":null`) {
		t.Fatal("canonical regular-file artifacts contain null tree fields")
	}
}
