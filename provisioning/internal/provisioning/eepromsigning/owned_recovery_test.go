package eepromsigning

import (
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func TestOwnedRecoveryPlanAndResultBindings(t *testing.T) {
	fixture := newFixture(t)
	input, err := NewOwnedRecoverySigningInput(fixture.final.OriginalRecovery)
	if err != nil {
		t.Fatal(err)
	}
	plan := OwnedRecoveryPlan{
		SchemaVersion: OwnedRecoveryPlanSchemaV1Alpha1,
		PlanID:        "owned-recovery:test", UpdaterMode: UpdaterModeOwnedRecovery,
		UpdaterFlags: []string{"-f", "-r"}, FreshEEPROMPlan: fixture.plan,
		FreshEEPROMResult: fixture.result, OwnedRecoverySigningInput: input,
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	_, recoverySignature := signFirmware(t, fixture.privateKey, fixture.final.ExtractedPublicKeyBinary, fixture.final.OriginalRecovery)
	result := OwnedRecoveryResult{
		SchemaVersion: OwnedRecoveryResultSchemaV1Alpha1, PlanID: plan.PlanID,
		PlanDigest: planDigest, ReleaseIntentDigest: fixture.plan.ReleaseIntentDigest,
		EEPROMReleaseManifestDigest: fixture.plan.EEPROMReleaseManifestDigest,
		SignerPolicyDigest:          fixture.plan.SignerPolicyDigest,
		PublicKeyFingerprint:        fixture.plan.PublicKeyFingerprint,
		CustomerKeyHash:             fixture.plan.CustomerKeyHash, SourceDateEpoch: fixture.plan.SourceDateEpoch,
		UpdaterMode: UpdaterModeOwnedRecovery, RecoveryMode: RecoveryModeCustomerCounterSigned,
		Signature:              signatureResult(RoleOwnedRecovery, input, recoverySignature, "owned recovery receipt"),
		OwnedRecoveryBootcode:  file(append(append([]byte(nil), fixture.final.OriginalRecovery...), make([]byte, firmwareSigningTrailerBytes)...)),
		ReplayedSignedEEPROM:   fixture.result.SignedEEPROM,
		ReplayedEEPROMMetadata: fixture.result.EEPROMUpdateMetadata,
	}
	if err := VerifyOwnedRecoveryBindings(plan, result); err != nil {
		t.Fatal(err)
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOwnedRecoveryPlan(append(planJSON, '\n')); err != nil {
		t.Fatalf("parse plan: %v", err)
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOwnedRecoveryResult(resultJSON); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	t.Run("changed EEPROM", func(t *testing.T) {
		tampered := result
		tampered.ReplayedSignedEEPROM = file([]byte("different EEPROM"))
		err := VerifyOwnedRecoveryBindings(plan, tampered)
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("additional signing role", func(t *testing.T) {
		tampered := result
		tampered.Signature.Role = RoleEEPROMBootcode
		if err := tampered.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("different release intent", func(t *testing.T) {
		tampered := result
		tampered.ReleaseIntentDigest = bundle.Sum([]byte("different intent"))
		err := VerifyOwnedRecoveryBindings(plan, tampered)
		if err == nil || !strings.Contains(err.Error(), "lineage") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestOwnedRecoveryPlanRejectsUnsafeUpdaterModes(t *testing.T) {
	fixture := newFixture(t)
	input, err := NewOwnedRecoverySigningInput(fixture.final.OriginalRecovery)
	if err != nil {
		t.Fatal(err)
	}
	plan := OwnedRecoveryPlan{
		SchemaVersion: OwnedRecoveryPlanSchemaV1Alpha1, PlanID: "owned-recovery:test",
		UpdaterMode: UpdaterModeOwnedRecovery, UpdaterFlags: []string{"-f", "-r"},
		FreshEEPROMPlan: fixture.plan, FreshEEPROMResult: fixture.result,
		OwnedRecoverySigningInput: input,
	}
	for _, flags := range [][]string{{"-r"}, {"-f"}, {"-f", "-r", "--extra"}, {"-r", "-f"}} {
		candidate := plan
		candidate.UpdaterFlags = flags
		if err := candidate.Validate(); err == nil {
			t.Fatalf("Validate accepted flags %#v", flags)
		}
	}
}
