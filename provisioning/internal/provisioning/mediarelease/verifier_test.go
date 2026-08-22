package mediarelease

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func TestCustomerKeyHashMustDeriveFromVerifiedPublicKeyBinary(t *testing.T) {
	keyBinary := []byte("canonical customer key binary")
	manifest := bundle.SignedReleaseManifest{ExpectedCustomerKeyHash: bundle.Sum(keyBinary)}
	if err := verifyCustomerKeyHash(manifest, keyBinary); err != nil {
		t.Fatal(err)
	}
	manifest.ExpectedCustomerKeyHash = bundle.Sum([]byte("different irreversible OTP hash"))
	if err := verifyCustomerKeyHash(manifest, keyBinary); err == nil || !strings.Contains(err.Error(), "customer-key hash") {
		t.Fatalf("verifyCustomerKeyHash() error = %v", err)
	}
}

func TestRootIntegrityParsingRejectsEveryAmbiguousOrMismatchedBoundary(t *testing.T) {
	plan := mediacontract.Plan{Layout: mediacontract.Layout{Verity: mediacontract.VerityContract{
		RootHash:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DataPartitionGUID: "33333333-3333-4333-8333-333333333333",
		HashPartitionGUID: "44444444-4444-4444-8444-444444444444",
	}}}
	valid := []byte(fmt.Sprintf(`{"schema":"provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1","algorithm":"sha256","data_block_size":4096,"hash_block_size":4096,"no_superblock":false,"root_hash":"%s","data_device":"PARTUUID=%s","hash_device":"PARTUUID=%s"}`,
		strings.TrimPrefix(string(plan.Layout.Verity.RootHash), "sha256:"), plan.Layout.Verity.DataPartitionGUID, plan.Layout.Verity.HashPartitionGUID))
	if err := validateRootIntegrity(valid, plan); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate":  []byte(strings.Replace(string(valid), `"algorithm":"sha256"`, `"algorithm":"sha512","algorithm":"sha256"`, 1)),
		"unknown":    []byte(strings.Replace(string(valid), `"schema":`, `"unknown":false,"schema":`, 1)),
		"trailing":   append(append([]byte(nil), valid...), []byte(` {}`)...),
		"data block": []byte(strings.Replace(string(valid), `"data_block_size":4096`, `"data_block_size":512`, 1)),
		"hash block": []byte(strings.Replace(string(valid), `"hash_block_size":4096`, `"hash_block_size":512`, 1)),
		"superblock": []byte(strings.Replace(string(valid), `"no_superblock":false`, `"no_superblock":true`, 1)),
		"root hash":  []byte(strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("b", 64), 1)),
		"data guid":  []byte(strings.Replace(string(valid), plan.Layout.Verity.DataPartitionGUID, "55555555-5555-4555-8555-555555555555", 1)),
		"hash guid":  []byte(strings.Replace(string(valid), plan.Layout.Verity.HashPartitionGUID, "66666666-6666-4666-8666-666666666666", 1)),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateRootIntegrity(encoded, plan); err == nil {
				t.Fatalf("accepted %s root-integrity record", name)
			}
		})
	}
}

func TestFixedVerifierFailsClosedWithoutLinkerFixedStorePaths(t *testing.T) {
	for _, verifier := range []FixedVerifier{
		{},
		{ReleaseRoot: "/tmp/release", MTypePath: "/tmp/mtype"},
		{ReleaseRoot: "/nix/store/../release", MTypePath: "/nix/store/../mtype"},
	} {
		if err := verifier.Validate(); err == nil {
			t.Fatalf("Validate() accepted %#v", verifier)
		}
	}
}
