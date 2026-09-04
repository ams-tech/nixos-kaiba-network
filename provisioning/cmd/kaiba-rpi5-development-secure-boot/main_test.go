package main

import (
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const testFingerprint = "sha256:e7e61cab9b971a61207fcb17b15971c208d2374d14d62c9506e3b1717fb576dd"

func setTestBuildValues(t *testing.T) {
	t.Helper()
	oldKey, oldEEPROM, oldBoot, oldTarget := expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest, expectedTargetFingerprint
	expectedCustomerKeyHash = strings.Repeat("a", 64)
	expectedEEPROMHash = strings.Repeat("b", 64)
	expectedBootImageDigest = "sha256:" + strings.Repeat("c", 64)
	expectedTargetFingerprint = testFingerprint
	t.Cleanup(func() {
		expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest, expectedTargetFingerprint = oldKey, oldEEPROM, oldBoot, oldTarget
	})
}

func TestFreshCommitAndOwnedValidation(t *testing.T) {
	setTestBuildValues(t)
	fresh := rpi5.Observation{TargetFingerprint: testFingerprint, CustomerKeyHash: zeroCustomerKey, CustomerKeyState: "unset"}
	if err := validateFresh(fresh); err != nil {
		t.Fatalf("fresh observation rejected: %v", err)
	}
	commit := rpi5.Observation{
		TargetFingerprint: testFingerprint, CustomerKeyHash: expectedCustomerKeyHash,
		CustomerKeyState: "set", EEPROMHash: expectedEEPROMHash,
		UpstreamFields: map[string]string{"EEPROM_UPDATE": "success", "SECURE_BOOT_PROVISION": "success"},
	}
	if err := validateCommit(commit); err != nil {
		t.Fatalf("commit observation rejected: %v", err)
	}
	if err := validateOwned(commit); err != nil {
		t.Fatalf("owned observation rejected: %v", err)
	}
	commit.EEPROMHash = ""
	if err := validateOwned(commit); err != nil {
		t.Fatalf("owned observation without optional EEPROM hash rejected: %v", err)
	}
	if err := validateCommit(commit); err == nil {
		t.Fatal("commit response without the EEPROM hash was accepted")
	}
	commit.EEPROMHash = strings.Repeat("d", 64)
	if err := validateCommit(commit); err == nil {
		t.Fatal("mismatched EEPROM was accepted")
	}
}

func TestFreshValidationRejectsWrongBoardAndProgrammedKey(t *testing.T) {
	setTestBuildValues(t)
	observation := rpi5.Observation{TargetFingerprint: "sha256:" + strings.Repeat("f", 64), CustomerKeyHash: zeroCustomerKey, CustomerKeyState: "unset"}
	if err := validateFresh(observation); err == nil {
		t.Fatal("wrong board was accepted")
	}
	observation.TargetFingerprint = testFingerprint
	observation.CustomerKeyHash = expectedCustomerKeyHash
	observation.CustomerKeyState = "set"
	if err := validateFresh(observation); err == nil {
		t.Fatal("programmed target was accepted as fresh")
	}
}

func TestSignedBootEvidenceRequiresExpectedImageAndOTPBit(t *testing.T) {
	setTestBuildValues(t)
	valid := "noise\n" + signedBootMarker + " signed=00000008 boot_img_sha256=" + expectedBootImageDigest + " root=/dev/mapper/root rollback=unimplemented enrollment_ready=false\n"
	if err := validateSignedBootEvidence([]byte(valid)); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	withoutBit := strings.Replace(valid, "signed=00000008", "signed=00000000", 1)
	if err := validateSignedBootEvidence([]byte(withoutBit)); err == nil {
		t.Fatal("evidence without OTP bit was accepted")
	}
	wrongImage := strings.Replace(valid, expectedBootImageDigest, "sha256:"+strings.Repeat("d", 64), 1)
	if err := validateSignedBootEvidence([]byte(wrongImage)); err == nil {
		t.Fatal("evidence for wrong image was accepted")
	}
	duplicate := valid + strings.TrimPrefix(valid, "noise\n")
	if err := validateSignedBootEvidence([]byte(duplicate)); err == nil {
		t.Fatal("duplicate secure-boot evidence was accepted")
	}
}
