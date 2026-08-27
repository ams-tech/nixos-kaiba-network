package signingapproval

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	testApprovedAt = "2026-08-18T12:00:00Z"
	testExpiresAt  = "2026-08-18T16:00:00Z"
)

func TestNewProducesStableIndependentApprovalAndExactFiveGrants(t *testing.T) {
	intent := testIntent(t)
	first, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(intent); err != nil {
		t.Fatal(err)
	}
	firstApproval, err := first.Approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondApproval, _ := second.Approval.CanonicalJSON()
	firstRegistry, err := CanonicalRegistryJSON(first.Registry)
	if err != nil {
		t.Fatal(err)
	}
	secondRegistry, _ := CanonicalRegistryJSON(second.Registry)
	if !bytes.Equal(firstApproval, secondApproval) || !bytes.Equal(firstRegistry, secondRegistry) {
		t.Fatal("same review inputs did not produce byte-identical authorization")
	}

	const wantApprovalDigest bundle.Digest = "sha256:f13b7e75b1a94c06f2ec324d54ec09b0cc25057e889e3000a2126000c3e4bfb1"
	if first.Approval.ApprovalDigest != wantApprovalDigest {
		t.Fatalf("approval digest = %s, want golden %s", first.Approval.ApprovalDigest, wantApprovalDigest)
	}
	if first.Approval.ApprovalID != "approval:"+strings.TrimPrefix(string(wantApprovalDigest), "sha256:") {
		t.Fatalf("approval ID = %q", first.Approval.ApprovalID)
	}
	if bundle.Sum(firstApproval) == first.Approval.ApprovalDigest {
		t.Fatal("approval digest is not domain separated from ordinary JSON SHA-256")
	}
	if len(first.Registry.Grants) != len(releaseintent.SigningInputRoles()) {
		t.Fatalf("grant count = %d", len(first.Registry.Grants))
	}
	intentDigest, _ := intent.Digest()
	for index, grant := range first.Registry.Grants {
		input := intent.SigningInputs[index]
		if grant.ExpiresAt != testExpiresAt || grant.Request.Role != input.Role || grant.Request.ArtifactDigest != input.Digest {
			t.Fatalf("grant[%d] does not match intent input: %#v", index, grant)
		}
		if grant.Request.Algorithm != signing.AlgorithmRSA2048SHA256 || grant.Request.Approval.ApprovalID != first.Approval.ApprovalID || grant.Request.Approval.ApprovalDigest != first.Approval.ApprovalDigest || grant.Request.Approval.ReleaseIntentDigest != intentDigest || grant.Request.Approval.Role != input.Role || grant.Request.Approval.ArtifactDigest != input.Digest {
			t.Fatalf("grant[%d] has incomplete approval binding: %#v", index, grant.Request)
		}
		if !strings.HasSuffix(grant.GrantID, ":"+string(input.Role)) || !strings.HasSuffix(grant.Request.RequestID, ":"+string(input.Role)) {
			t.Fatalf("grant[%d] IDs are not deterministic role IDs: %#v", index, grant)
		}
	}

	parsedApproval, err := ParseApproval(append(firstApproval, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	parsedRegistry, err := ParseRegistry(append(firstRegistry, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if err := (Authorization{Approval: parsedApproval, Registry: parsedRegistry}).Validate(intent); err != nil {
		t.Fatalf("canonical round trip failed: %v", err)
	}
}

func TestNewCopiesIntentInputsAndCanonicalizesThroughReleaseIntent(t *testing.T) {
	intent := testIntent(t)
	authorization, err := New(intent, "reviewer:bob", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]bundle.Artifact(nil), intent.SigningInputs...)
	intent.SigningInputs[0].Digest = testDigest("f")
	if !slices.Equal(authorization.Approval.SigningInputs, original) {
		t.Fatal("authorization changed through caller-owned release-intent slice")
	}
}

func TestApprovalIdentityChangesWithReviewerOrTime(t *testing.T) {
	intent := testIntent(t)
	first, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	differentReviewer, err := New(intent, "reviewer:bob", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	differentTime, err := New(intent, "reviewer:alice", "2026-08-18T12:00:01Z", testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Approval.ApprovalDigest == differentReviewer.Approval.ApprovalDigest || first.Approval.ApprovalDigest == differentTime.Approval.ApprovalDigest {
		t.Fatal("reviewer identity or approval timestamp did not change the approval digest")
	}
}

func TestNewRejectsDuplicateArtifactDigestsThatGateCannotDisambiguate(t *testing.T) {
	intent := testIntent(t)
	intent.SigningInputs = append([]bundle.Artifact(nil), intent.SigningInputs...)
	intent.SigningInputs[1].Digest = intent.SigningInputs[0].Digest
	if err := intent.Validate(); err != nil {
		t.Fatalf("release-intent fixture should permit this gate-level ambiguity: %v", err)
	}
	_, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err == nil || !strings.Contains(err.Error(), "must be unique") {
		t.Fatalf("New() duplicate-digest error = %v", err)
	}
}

func TestNewRejectsAmbiguousReviewerAndTimeInputs(t *testing.T) {
	intent := testIntent(t)
	tests := []struct {
		name       string
		reviewer   string
		approvedAt string
		expiresAt  string
		match      string
	}{
		{"missing reviewer", "", testApprovedAt, testExpiresAt, "reviewer_id"},
		{"noncanonical reviewer", "Reviewer Alice", testApprovedAt, testExpiresAt, "reviewer_id"},
		{"fractional approval", "reviewer:alice", "2026-08-18T12:00:00.000Z", testExpiresAt, "approved_at"},
		{"offset expiry", "reviewer:alice", testApprovedAt, "2026-08-18T12:30:00-04:00", "expires_at"},
		{"expiry not after", "reviewer:alice", testApprovedAt, testApprovedAt, "after approved_at"},
		{"expiry too long", "reviewer:alice", testApprovedAt, "2026-08-19T12:00:01Z", "24 hours"},
		{"approval predates release", "reviewer:alice", "2026-08-16T12:00:00Z", "2026-08-16T13:00:00Z", "source_date_epoch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(intent, test.reviewer, test.approvedAt, test.expiresAt)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("New() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestValidateRejectsEveryManualRegistryVariation(t *testing.T) {
	intent := testIntent(t)
	valid, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		match string
		alter func(*Authorization)
	}{
		{"missing grant", "exact deterministic five-grant", func(value *Authorization) { value.Registry.Grants = value.Registry.Grants[1:] }},
		{"extra grant", "duplicated", func(value *Authorization) {
			value.Registry.Grants = append(value.Registry.Grants, value.Registry.Grants[len(value.Registry.Grants)-1])
		}},
		{"manual grant ID", "exact deterministic five-grant", func(value *Authorization) { value.Registry.Grants[0].GrantID = "grant:0manual" }},
		{"manual request ID", "exact deterministic five-grant", func(value *Authorization) { value.Registry.Grants[0].Request.RequestID = "request:manual" }},
		{"different expiry", "exact deterministic five-grant", func(value *Authorization) { value.Registry.Grants[0].ExpiresAt = "2026-08-18T15:00:00Z" }},
		{"different role", "request artifact role", func(value *Authorization) { value.Registry.Grants[0].Request.Role = bundle.RoleEEPROMBootcode }},
		{"different digest", "request artifact role", func(value *Authorization) { value.Registry.Grants[0].Request.ArtifactDigest = testDigest("f") }},
		{"different approval digest", "exact deterministic five-grant", func(value *Authorization) { value.Registry.Grants[0].Request.Approval.ApprovalDigest = testDigest("f") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneAuthorization(t, valid)
			test.alter(&candidate)
			err := candidate.Validate(intent)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestValidateRejectsApprovalAndIntentMismatch(t *testing.T) {
	intent := testIntent(t)
	valid, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	tampered := cloneAuthorization(t, valid)
	tampered.Approval.ReviewerID = "reviewer:mallory"
	if err := tampered.Validate(intent); err == nil || !strings.Contains(err.Error(), "approval_digest") {
		t.Fatalf("reviewer tampering error = %v", err)
	}
	tampered = cloneAuthorization(t, valid)
	tampered.Approval.ApprovalDigest = testDigest("f")
	if err := tampered.Validate(intent); err == nil || !strings.Contains(err.Error(), "approval_digest") {
		t.Fatalf("digest tampering error = %v", err)
	}

	differentIntent := intent
	differentIntent.SigningInputs = append([]bundle.Artifact(nil), intent.SigningInputs...)
	differentIntent.SigningInputs[0].Digest = testDigest("f")
	if err := valid.Validate(differentIntent); err == nil || !strings.Contains(err.Error(), "supplied release intent") {
		t.Fatalf("intent mismatch error = %v", err)
	}
}

func TestStrictCanonicalApprovalAndRegistryJSON(t *testing.T) {
	intent := testIntent(t)
	valid, err := New(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	approvalJSON, _ := valid.Approval.CanonicalJSON()
	registryJSON, _ := CanonicalRegistryJSON(valid.Registry)
	approvalCases := []struct {
		name  string
		value string
		match string
	}{
		{"unknown field", strings.Replace(string(approvalJSON), `"decision"`, `"unknown":true,"decision"`, 1), "unknown field"},
		{"duplicate field", strings.Replace(string(approvalJSON), `"decision":"approved"`, `"decision":"approved","decision":"approved"`, 1), "duplicated"},
		{"null", strings.Replace(string(approvalJSON), `"reviewer_id":"reviewer:alice"`, `"reviewer_id":null`, 1), "null"},
		{"leading space", " " + string(approvalJSON), "canonical"},
		{"second newline", string(approvalJSON) + "\n\n", "canonical"},
		{"trailing value", string(approvalJSON) + `{}`, "trailing"},
	}
	for _, test := range approvalCases {
		t.Run("approval "+test.name, func(t *testing.T) {
			_, err := ParseApproval([]byte(test.value))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseApproval() error = %v, want match %q", err, test.match)
			}
		})
	}
	registryCases := []struct {
		name  string
		value string
		match string
	}{
		{"unknown field", strings.Replace(string(registryJSON), `"grants"`, `"unknown":true,"grants"`, 1), "unknown field"},
		{"duplicate field", strings.Replace(string(registryJSON), `"schema_version"`, `"schema_version":"kaiba.provisioning.signing-grant-registry/v1alpha2","schema_version"`, 1), "duplicated"},
		{"null", strings.Replace(string(registryJSON), `"grants":[`, `"grants":null,"discarded":[`, 1), "null"},
		{"leading space", " " + string(registryJSON), "canonical"},
		{"second newline", string(registryJSON) + "\n\n", "canonical"},
	}
	for _, test := range registryCases {
		t.Run("registry "+test.name, func(t *testing.T) {
			_, err := ParseRegistry([]byte(test.value))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseRegistry() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func testIntent(t *testing.T) releaseintent.Intent {
	t.Helper()
	roles := releaseintent.SigningInputRoles()
	inputs := make([]bundle.Artifact, len(roles))
	for index, role := range roles {
		inputs[index] = bundle.Artifact{Role: role, Digest: testDigest(string(rune('a' + index))), SizeBytes: uint64(100 + index)}
	}
	intent, err := releaseintent.New(releaseintent.Parameters{
		ReleaseID:                   "release:rpi5:1",
		SourceRevision:              "0123456789abcdef0123456789abcdef01234567",
		SourceDateEpoch:             1786968000,
		UnsignedArtifactSetDigest:   testDigest("1"),
		EEPROMReleaseManifestDigest: testDigest("2"),
		PublicKeyFingerprint:        testDigest("3"),
		SigningPolicyDigest:         testDigest("4"),
		ExpectedCustomerKeyHash:     testDigest("5"),
		SigningInputs:               inputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func testDigest(character string) bundle.Digest {
	return bundle.Digest("sha256:" + strings.Repeat(character, 64))
}

func cloneAuthorization(t *testing.T, value Authorization) Authorization {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned struct {
		Approval Approval             `json:"Approval"`
		Registry signinggate.Registry `json:"Registry"`
	}
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return Authorization{Approval: cloned.Approval, Registry: cloned.Registry}
}
