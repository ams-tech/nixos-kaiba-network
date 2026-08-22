package releaseintent

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const testSourceRevision = "0123456789abcdef0123456789abcdef01234567"

func TestReleaseIntentCanonicalDigestIsStable(t *testing.T) {
	inputs := testSigningInputs()
	reversed := append([]bundle.Artifact(nil), inputs...)
	slices.Reverse(reversed)

	first := newTestIntent(t, reversed)
	second := newTestIntent(t, inputs)
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("release-intent digests differ: %s != %s", firstDigest, secondDigest)
	}
	const want bundle.Digest = "sha256:6e6efd03752d49da1af1631c6e44fb6e0c935059b31677ce80f0877f0a88024a"
	if firstDigest != want {
		t.Fatalf("release-intent digest = %s, want golden %s", firstDigest, want)
	}

	canonical, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/rpi5-release-intent-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture = bytes.TrimSuffix(fixture, []byte("\n"))
	if !bytes.Equal(canonical, fixture) {
		t.Fatalf("canonical release intent differs from checked golden fixture\ngot:  %s\nwant: %s", canonical, fixture)
	}
	parsed, err := Parse(fixture)
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
}

func TestNewReleaseIntentCopiesInputsAndFixesClosedSets(t *testing.T) {
	inputs := testSigningInputs()
	intent := newTestIntent(t, inputs)
	inputs[0].Role = bundle.RoleBootSignature
	inputs[1].Digest = digest("f")
	if err := intent.Validate(); err != nil {
		t.Fatalf("release intent changed through caller-owned inputs: %v", err)
	}

	roles := SigningInputRoles()
	roles[0] = bundle.RoleBootSignature
	if SigningInputRoles()[0] != bundle.RoleBootImage {
		t.Fatal("SigningInputRoles exposed its backing array")
	}
	outputs := bundle.SignedReleaseRoles()
	if !slices.Equal(intent.RequiredOutputRoles, outputs) {
		t.Fatalf("required outputs = %q, want %q", intent.RequiredOutputRoles, outputs)
	}
	if slices.Contains(intent.RequiredOutputRoles, bundle.RoleEEPROMBootcode) {
		t.Fatal("EEPROM bootcode signing input unexpectedly became a final output")
	}
	for _, role := range SigningInputRoles() {
		if !role.Signable() {
			t.Fatalf("release-intent input role %q is not signable", role)
		}
		input, ok := intent.SigningInput(role)
		if !ok || input.Role != role {
			t.Fatalf("SigningInput(%q) = %#v/%v", role, input, ok)
		}
	}
	if _, ok := intent.SigningInput(bundle.RoleBootSignature); ok {
		t.Fatal("SigningInput returned an unapproved output role")
	}
}

func TestReleaseIntentRejectsInvalidIdentityAndDigestFields(t *testing.T) {
	valid := newTestIntent(t, testSigningInputs())
	tests := []struct {
		name  string
		match string
		alter func(*Intent)
	}{
		{"schema", "unsupported", func(value *Intent) { value.SchemaVersion = "v2" }},
		{"release ID", "release_id", func(value *Intent) { value.ReleaseID = "UPPER" }},
		{"device class", "device_class", func(value *Intent) { value.DeviceClass = "raspberry-pi-5" }},
		{"short source revision", "source_revision", func(value *Intent) { value.SourceRevision = strings.Repeat("a", 39) }},
		{"uppercase source revision", "source_revision", func(value *Intent) { value.SourceRevision = strings.Repeat("A", 40) }},
		{"zero source epoch", "source_date_epoch", func(value *Intent) { value.SourceDateEpoch = 0 }},
		{"excessive source epoch", "source_date_epoch", func(value *Intent) { value.SourceDateEpoch = maximumSourceDateEpoch + 1 }},
		{"unsigned artifact digest", "unsigned_artifact_set_digest", func(value *Intent) { value.UnsignedArtifactSetDigest = "sha256:no" }},
		{"EEPROM release digest", "eeprom_release_manifest_digest", func(value *Intent) { value.EEPROMReleaseManifestDigest = "sha256:no" }},
		{"public key fingerprint", "public_key_fingerprint", func(value *Intent) { value.PublicKeyFingerprint = "sha256:no" }},
		{"signing policy digest", "signing_policy_digest", func(value *Intent) { value.SigningPolicyDigest = "sha256:no" }},
		{"customer key hash", "expected_customer_key_hash", func(value *Intent) { value.ExpectedCustomerKeyHash = "sha256:no" }},
		{"authorization scope", "authorization_scope", func(value *Intent) { value.AuthorizationScope = "target" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneIntent(valid)
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

func TestReleaseIntentRequiresExactSigningInputs(t *testing.T) {
	valid := newTestIntent(t, testSigningInputs())
	tests := []struct {
		name  string
		match string
		alter func(*Intent)
	}{
		{
			"missing input", "exactly 5",
			func(value *Intent) { value.SigningInputs = value.SigningInputs[:len(value.SigningInputs)-1] },
		},
		{
			"extra input", "exactly 5",
			func(value *Intent) { value.SigningInputs = append(value.SigningInputs, value.SigningInputs[0]) },
		},
		{
			"duplicate input", "role must be",
			func(value *Intent) { value.SigningInputs[1] = value.SigningInputs[0] },
		},
		{
			"wrong order", "role must be",
			func(value *Intent) {
				value.SigningInputs[0], value.SigningInputs[1] = value.SigningInputs[1], value.SigningInputs[0]
			},
		},
		{
			"output role", "role must be",
			func(value *Intent) { value.SigningInputs[0].Role = bundle.RoleBootSignature },
		},
		{
			"invalid digest", "digest",
			func(value *Intent) { value.SigningInputs[2].Digest = "sha256:no" },
		},
		{
			"zero size", "size_bytes",
			func(value *Intent) { value.SigningInputs[3].SizeBytes = 0 },
		},
		{
			"oversized input", "size_bytes",
			func(value *Intent) { value.SigningInputs[3].SizeBytes = MaxSigningInputBytes + 1 },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneIntent(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestReleaseIntentRequiresExactFinalOutputRoles(t *testing.T) {
	valid := newTestIntent(t, testSigningInputs())
	tests := []struct {
		name  string
		match string
		alter func(*Intent)
	}{
		{
			"missing output", "exactly 18",
			func(value *Intent) {
				value.RequiredOutputRoles = value.RequiredOutputRoles[:len(value.RequiredOutputRoles)-1]
			},
		},
		{
			"extra output", "exactly 18",
			func(value *Intent) {
				value.RequiredOutputRoles = append(value.RequiredOutputRoles, bundle.RoleEEPROMBootcode)
			},
		},
		{
			"EEPROM bootcode output", "must be",
			func(value *Intent) { value.RequiredOutputRoles[0] = bundle.RoleEEPROMBootcode },
		},
		{
			"duplicate output", "must be",
			func(value *Intent) { value.RequiredOutputRoles[1] = value.RequiredOutputRoles[0] },
		},
		{
			"wrong order", "must be",
			func(value *Intent) {
				value.RequiredOutputRoles[0], value.RequiredOutputRoles[1] = value.RequiredOutputRoles[1], value.RequiredOutputRoles[0]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneIntent(valid)
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestReleaseIntentStrictJSON(t *testing.T) {
	intent := newTestIntent(t, testSigningInputs())
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	valid := string(canonical)
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
			"unknown signing-input field",
			strings.Replace(valid, `"role":"rpi5.boot_image"`, `"role":"rpi5.boot_image","path":"/tmp/image"`, 1),
			"unknown field",
		},
		{
			"missing source epoch",
			strings.Replace(valid, `"source_date_epoch":1786968000,`, ``, 1),
			"source_date_epoch",
		},
		{"trailing value", valid + `{}`, "trailing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Parse() error = %v, want match %q", err, test.match)
			}
		})
	}

	oversized := bytes.Repeat([]byte(" "), MaxBytes+1)
	if _, err := Parse(oversized); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized Parse() error = %v", err)
	}
}

func TestReleaseIntentDigestCoversEveryField(t *testing.T) {
	valid := newTestIntent(t, testSigningInputs())
	base, err := valid.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		alter func(*Intent)
	}{
		{"schema", func(value *Intent) { value.SchemaVersion = "v2" }},
		{"release ID", func(value *Intent) { value.ReleaseID = "release:rpi5:2" }},
		{"device class", func(value *Intent) { value.DeviceClass = "raspberry-pi-5" }},
		{"source revision", func(value *Intent) { value.SourceRevision = strings.Repeat("a", 40) }},
		{"source date epoch", func(value *Intent) { value.SourceDateEpoch++ }},
		{"unsigned artifact set", func(value *Intent) { value.UnsignedArtifactSetDigest = digest("6") }},
		{"EEPROM release", func(value *Intent) { value.EEPROMReleaseManifestDigest = digest("7") }},
		{"public key", func(value *Intent) { value.PublicKeyFingerprint = digest("8") }},
		{"signer policy", func(value *Intent) { value.SigningPolicyDigest = digest("9") }},
		{"customer key", func(value *Intent) { value.ExpectedCustomerKeyHash = digest("0") }},
		{"authorization scope", func(value *Intent) { value.AuthorizationScope = "target" }},
		{"signing input role", func(value *Intent) { value.SigningInputs[0].Role = bundle.RoleBootSignature }},
		{"signing input digest", func(value *Intent) { value.SigningInputs[0].Digest = digest("f") }},
		{"signing input size", func(value *Intent) { value.SigningInputs[0].SizeBytes++ }},
		{"required output role", func(value *Intent) { value.RequiredOutputRoles[0] = bundle.RoleEEPROMBootcode }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireChangedOrInvalid(t, base, valid, test.alter)
		})
	}
	for index := range valid.SigningInputs {
		t.Run("signing input role "+string(rune('0'+index)), func(t *testing.T) {
			requireChangedOrInvalid(t, base, valid, func(value *Intent) {
				value.SigningInputs[index].Role = bundle.RoleBootSignature
			})
		})
		t.Run("signing input digest "+string(rune('0'+index)), func(t *testing.T) {
			requireChangedOrInvalid(t, base, valid, func(value *Intent) {
				value.SigningInputs[index].Digest = digest("f")
			})
		})
		t.Run("signing input size "+string(rune('0'+index)), func(t *testing.T) {
			requireChangedOrInvalid(t, base, valid, func(value *Intent) {
				value.SigningInputs[index].SizeBytes++
			})
		})
	}
	for index := range valid.RequiredOutputRoles {
		t.Run("required output "+string(rune('a'+index)), func(t *testing.T) {
			requireChangedOrInvalid(t, base, valid, func(value *Intent) {
				value.RequiredOutputRoles[index] = bundle.RoleEEPROMBootcode
			})
		})
	}
}

func requireChangedOrInvalid(t *testing.T, base bundle.Digest, valid Intent, alter func(*Intent)) {
	t.Helper()
	candidate := cloneIntent(valid)
	alter(&candidate)
	digest, err := candidate.Digest()
	if err == nil && digest == base {
		t.Fatalf("field mutation retained release-intent digest %s", digest)
	}
}

func testSigningInputs() []bundle.Artifact {
	roles := SigningInputRoles()
	inputs := make([]bundle.Artifact, len(roles))
	for index, role := range roles {
		inputs[index] = bundle.Artifact{
			Role: role, Digest: digest(string(rune('a' + index))), SizeBytes: uint64(100 + index),
		}
	}
	return inputs
}

func newTestIntent(t *testing.T, inputs []bundle.Artifact) Intent {
	t.Helper()
	intent, err := New(Parameters{
		ReleaseID:                   "release:rpi5:1",
		SourceRevision:              testSourceRevision,
		SourceDateEpoch:             1786968000,
		UnsignedArtifactSetDigest:   digest("1"),
		EEPROMReleaseManifestDigest: digest("2"),
		PublicKeyFingerprint:        digest("3"),
		SigningPolicyDigest:         digest("4"),
		ExpectedCustomerKeyHash:     digest("5"),
		SigningInputs:               inputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func cloneIntent(intent Intent) Intent {
	intent.SigningInputs = append([]bundle.Artifact(nil), intent.SigningInputs...)
	intent.RequiredOutputRoles = append([]bundle.ArtifactRole(nil), intent.RequiredOutputRoles...)
	return intent
}

func digest(character string) bundle.Digest {
	return bundle.Digest("sha256:" + strings.Repeat(character, 64))
}
