package signing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

type recordingVerifier struct {
	calls int
	err   error
}

func (v *recordingVerifier) VerifyApproval(_ context.Context, _ ApprovalBinding) error {
	v.calls++
	return v.err
}

func developmentPolicy(t *testing.T) YubiKeyPolicy {
	t.Helper()
	policy, err := NewDevelopmentYubiKeyPolicy(
		"signer:kaiba-boot-development-01",
		"cohort:kaiba-rpi5-development",
		"pkcs11:token=Kaiba%20Development;object=Boot%20Signing;id=%02;type=private",
		bundle.Sum([]byte("development public key")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func approvedRequest(artifact []byte) Request {
	artifactDigest := bundle.Sum(artifact)
	return Request{
		SchemaVersion:  RequestSchemaV1Alpha2,
		RequestID:      "request:boot-image-0001",
		Algorithm:      AlgorithmRSA2048SHA256,
		Role:           bundle.RoleBootImage,
		ArtifactDigest: artifactDigest,
		Approval: ApprovalBinding{
			ApprovalID:          "approval:boot-image-0001",
			ApprovalDigest:      bundle.Sum([]byte("approval receipt")),
			ReleaseIntentDigest: bundle.Sum([]byte("release intent")),
			Role:                bundle.RoleBootImage,
			ArtifactDigest:      artifactDigest,
		},
	}
}

func TestServiceSignsApprovedArtifactAndIdempotentlyReplays(t *testing.T) {
	artifact := []byte("deterministic boot image")
	request := approvedRequest(artifact)
	backend := &DeterministicFakeBackend{Domain: "test-key"}
	verifier := &recordingVerifier{}
	service, err := NewService(developmentPolicy(t), backend, verifier, NewMemoryResultStore())
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Sign(context.Background(), request, artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Sign(context.Background(), request, append([]byte(nil), artifact...))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotent result changed:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if backend.Calls != 1 || verifier.calls != 1 {
		t.Fatalf("backend/verifier calls = %d/%d, want 1/1", backend.Calls, verifier.calls)
	}
	if len(first.SignatureHex) != RSASignatureBytes*2 || first.SignatureHex != strings.ToLower(first.SignatureHex) {
		t.Fatalf("signature_hex is not canonical: %q", first.SignatureHex)
	}
	if first.Role != request.Role || first.ArtifactDigest != request.ArtifactDigest || first.SignerPolicyDigest == "" || first.ReleaseIntentDigest != request.Approval.ReleaseIntentDigest {
		t.Fatalf("result lost binding: %#v", first)
	}
}

func TestServiceRejectsUnapprovedAndChangedInputsBeforeKeyUse(t *testing.T) {
	artifact := []byte("boot image")
	tests := []struct {
		name   string
		mutate func(*Request)
		input  []byte
		match  string
	}{
		{
			name:  "digest mismatch",
			input: []byte("changed boot image"),
			match: "does not match approved digest",
		},
		{
			name:   "role mismatch",
			mutate: func(request *Request) { request.Role = bundle.RoleEEPROMConfig },
			input:  artifact,
			match:  "do not match the approval binding",
		},
		{
			name: "output role",
			mutate: func(request *Request) {
				request.Role = bundle.RoleBootSignature
				request.Approval.Role = bundle.RoleBootSignature
			},
			input: artifact,
			match: "not an approved boot-key signing input",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := approvedRequest(artifact)
			if test.mutate != nil {
				test.mutate(&request)
			}
			backend := &DeterministicFakeBackend{}
			verifier := &recordingVerifier{}
			service, err := NewService(developmentPolicy(t), backend, verifier, NewMemoryResultStore())
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Sign(context.Background(), request, test.input)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Sign() error = %v, want match %q", err, test.match)
			}
			if backend.Calls != 0 || verifier.calls != 0 {
				t.Fatalf("rejected input reached verifier/backend: %d/%d", verifier.calls, backend.Calls)
			}
		})
	}
}

func TestServiceRequiresValidApprovalAndPreservesIdempotencyKey(t *testing.T) {
	artifact := []byte("boot image")
	backend := &DeterministicFakeBackend{}
	verifier := &recordingVerifier{err: errors.New("approval expired")}
	service, err := NewService(developmentPolicy(t), backend, verifier, NewMemoryResultStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Sign(context.Background(), approvedRequest(artifact), artifact); err == nil || !strings.Contains(err.Error(), "approval expired") {
		t.Fatalf("approval error = %v", err)
	}
	if backend.Calls != 0 {
		t.Fatalf("unapproved request reached backend %d times", backend.Calls)
	}

	verifier.err = nil
	first := approvedRequest(artifact)
	if _, err := service.Sign(context.Background(), first, artifact); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Approval.ReleaseIntentDigest = bundle.Sum([]byte("changed release intent"))
	if _, err := service.Sign(context.Background(), second, artifact); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed request error = %v, want ErrIdempotencyConflict", err)
	}
	if backend.Calls != 1 {
		t.Fatalf("idempotency conflict reached backend; calls = %d", backend.Calls)
	}
}

func TestParseRequestIsStrict(t *testing.T) {
	request := approvedRequest([]byte("boot image"))
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(encoded); err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(encoded), `"request_id"`, `"unknown":true,"request_id"`, 1)
	if _, err := ParseRequest([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
	duplicate := strings.Replace(string(encoded), `"request_id":"request:boot-image-0001"`, `"request_id":"request:boot-image-0001","request_id":"other"`, 1)
	if _, err := ParseRequest([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate-field error = %v", err)
	}
}

func TestYubiKeyPolicyFixesSlotPINAndTouch(t *testing.T) {
	valid := developmentPolicy(t)
	if valid.PIVSlot != "9c" || !valid.PINRequired || !valid.TouchRequired || valid.PrivateKeyExportable {
		t.Fatalf("development policy = %#v", valid)
	}
	tests := []struct {
		name   string
		mutate func(*YubiKeyPolicy)
	}{
		{"wrong slot", func(policy *YubiKeyPolicy) { policy.PIVSlot = "9a" }},
		{"no pin", func(policy *YubiKeyPolicy) { policy.PINRequired = false }},
		{"no touch", func(policy *YubiKeyPolicy) { policy.TouchRequired = false }},
		{"exportable", func(policy *YubiKeyPolicy) { policy.PrivateKeyExportable = true }},
		{"pin in uri", func(policy *YubiKeyPolicy) { policy.PKCS11URI += ";pin-value=123456" }},
		{"wrong object id", func(policy *YubiKeyPolicy) {
			policy.PKCS11URI = strings.Replace(policy.PKCS11URI, "id=%02", "id=%01", 1)
		}},
		{"query parameter", func(policy *YubiKeyPolicy) { policy.PKCS11URI += "?module-path=/tmp/browser-selected.so" }},
		{"public object", func(policy *YubiKeyPolicy) {
			policy.PKCS11URI = strings.Replace(policy.PKCS11URI, "type=private", "type=public", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := valid
			test.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatalf("modified policy validated: %#v", policy)
			}
		})
	}
}
