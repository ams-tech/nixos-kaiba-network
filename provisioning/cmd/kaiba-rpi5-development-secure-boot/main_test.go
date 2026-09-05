package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const testFingerprint = "sha256:e7e61cab9b971a61207fcb17b15971c208d2374d14d62c9506e3b1717fb576dd"

func setTestBuildValues(t *testing.T) {
	t.Helper()
	oldKey, oldEEPROM, oldBoot, oldTarget, oldRPIBootPath := expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest, expectedTargetFingerprint, fixedRPIBootSysfsPath
	expectedCustomerKeyHash = strings.Repeat("a", 64)
	expectedEEPROMHash = strings.Repeat("b", 64)
	expectedBootImageDigest = "sha256:" + strings.Repeat("c", 64)
	expectedTargetFingerprint = testFingerprint
	fixedRPIBootSysfsPath = "/sys/bus/usb/devices/3-1"
	t.Cleanup(func() {
		expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest, expectedTargetFingerprint, fixedRPIBootSysfsPath = oldKey, oldEEPROM, oldBoot, oldTarget, oldRPIBootPath
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

func TestAutomaticCommitIdentifiesFixedTargetWithoutPrompt(t *testing.T) {
	setTestBuildValues(t)
	var output bytes.Buffer
	announceAutomaticCommit(&output)
	if strings.Contains(output.String(), "Type exactly") || strings.Contains(output.String(), "> ") {
		t.Fatalf("automatic commit emitted an interactive prompt: %q", output.String())
	}
	if !strings.Contains(output.String(), expectedTargetFingerprint) {
		t.Fatalf("automatic commit did not identify the fixed target: %q", output.String())
	}
}

func TestUnattendedHardwareWaitsAdvanceFromObservedTopology(t *testing.T) {
	setTestBuildValues(t)
	oldObserve, oldWait := observeEligibleTargets, waitForInterval
	t.Cleanup(func() {
		observeEligibleTargets, waitForInterval = oldObserve, oldWait
	})

	observations := [][]string{
		{fixedRPIBootSysfsPath},
		{},
		{},
		{fixedRPIBootSysfsPath},
	}
	observeEligibleTargets = func() ([]string, error) {
		if len(observations) == 0 {
			t.Fatal("hardware wait read more topology observations than expected")
		}
		result := observations[0]
		observations = observations[1:]
		return result, nil
	}
	waitForInterval = func(context.Context, time.Duration) error { return nil }

	var output bytes.Buffer
	if err := prepareDisconnected(context.Background(), &output); err != nil {
		t.Fatalf("wait for disconnect: %v", err)
	}
	if err := waitExactTarget(context.Background()); err != nil {
		t.Fatalf("wait for exact target: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("hardware waits left %d observations unread", len(observations))
	}
	if strings.Contains(output.String(), "press Enter") {
		t.Fatalf("unattended hardware wait emitted an input prompt: %q", output.String())
	}
}

func TestUnattendedHardwareWaitRejectsWrongTopology(t *testing.T) {
	setTestBuildValues(t)
	oldObserve := observeEligibleTargets
	t.Cleanup(func() { observeEligibleTargets = oldObserve })
	observeEligibleTargets = func() ([]string, error) {
		return []string{"/sys/bus/usb/devices/9-9"}, nil
	}
	if err := waitExactTarget(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "unexpected RPIBOOT topology") {
		t.Fatalf("wrong topology error = %v", err)
	}
}

func TestUnattendedHardwareWaitStopsOnCancellation(t *testing.T) {
	setTestBuildValues(t)
	oldObserve, oldWait := observeEligibleTargets, waitForInterval
	t.Cleanup(func() {
		observeEligibleTargets, waitForInterval = oldObserve, oldWait
	})
	observeEligibleTargets = func() ([]string, error) { return nil, nil }
	waitForInterval = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitExactTarget(ctx); err == nil {
		t.Fatal("cancelled unattended wait succeeded")
	}
}
