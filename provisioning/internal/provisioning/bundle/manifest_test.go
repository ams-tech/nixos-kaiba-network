package bundle

import (
	"strings"
	"testing"
)

func TestManifestCanonicalDigestIsStable(t *testing.T) {
	policyDigest := Sum([]byte("development-yubikey-policy"))
	artifacts := []Artifact{
		{Role: RoleBootSignature, Digest: Sum([]byte("boot signature")), SizeBytes: 256},
		{Role: RoleBootImage, Digest: Sum([]byte("boot image")), SizeBytes: 10},
	}
	first, err := NewManifest("kaiba-rpi5-development-v1", "raspberry-pi-5-model-b-v1alpha1", policyDigest, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewManifest("kaiba-rpi5-development-v1", "raspberry-pi-5-model-b-v1alpha1", policyDigest, []Artifact{artifacts[1], artifacts[0]})
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("manifest digests differ: %s != %s", firstDigest, secondDigest)
	}
	canonical, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := parsed.Digest(); got != firstDigest {
		t.Fatalf("round-trip digest = %s, want %s", got, firstDigest)
	}
}

func TestManifestRejectsNonCanonicalOrAmbiguousInput(t *testing.T) {
	valid := `{"schema_version":"kaiba.provisioning.secure-boot-bundle/v1alpha1","manifest_id":"manifest-1","device_class":"raspberry-pi-5","signing_policy_digest":"` + string(Sum([]byte("policy"))) + `","artifacts":[{"role":"rpi5.boot_image","digest":"` + string(Sum([]byte("image"))) + `","size_bytes":5}]}`
	tests := []struct {
		name  string
		input string
		match string
	}{
		{"unknown field", strings.Replace(valid, `"manifest_id"`, `"unexpected":true,"manifest_id"`, 1), "unknown field"},
		{"duplicate field", strings.Replace(valid, `"manifest_id":"manifest-1"`, `"manifest_id":"manifest-1","manifest_id":"manifest-2"`, 1), "duplicated"},
		{"unsupported schema", strings.Replace(valid, "v1alpha1", "v2", 1), "unsupported"},
		{"uppercase digest", strings.Replace(valid, string(Sum([]byte("image"))), strings.ToUpper(string(Sum([]byte("image")))), 1), "canonical"},
		{"unknown role", strings.Replace(valid, "rpi5.boot_image", "arbitrary_payload", 1), "not supported"},
		{"trailing value", valid + `{}`, "trailing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseManifest() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestArtifactRolesAreClosedAndSigningIsNarrow(t *testing.T) {
	for _, role := range Roles() {
		if err := role.Validate(); err != nil {
			t.Fatalf("role %q: %v", role, err)
		}
	}
	if !RoleBootImage.Signable() || !RoleEEPROMConfig.Signable() || !RoleEEPROMBootsys.Signable() || !RoleOwnedRecoveryBootcode.Signable() {
		t.Fatal("expected Raspberry Pi signing input role is not signable")
	}
	for _, role := range []ArtifactRole{RoleBootPublicKey, RoleBootSignature, RoleSignedEEPROMImage, RoleFreshCommitBundle, RoleOwnedRecoveryBundle, RoleDeviceProfile, RolePlatformAdapter} {
		if role.Signable() {
			t.Fatalf("output/reference role %q unexpectedly signable", role)
		}
	}
	if ArtifactRole("browser.supplied").Signable() {
		t.Fatal("unknown role unexpectedly signable")
	}
}

func TestParseDigestRequiresLowercaseCanonicalForm(t *testing.T) {
	valid := string(Sum([]byte("artifact")))
	if _, err := ParseDigest(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", valid[7:], strings.ToUpper(valid), valid + "0", "sha512:" + valid[7:]} {
		if _, err := ParseDigest(invalid); err == nil {
			t.Fatalf("ParseDigest(%q) succeeded", invalid)
		}
	}
}
