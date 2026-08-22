package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
)

func TestSignAndFinalizeOwnedRecoveryReusesFreshSignatures(t *testing.T) {
	fixture := newWorkflowFixture(t)
	deps := fixture.dependencies()
	root := t.TempDir()
	freshSigned := filepath.Join(root, "fresh-signed")
	if err := signEEPROM(context.Background(), fixture.planDirectory, freshSigned, deps); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(freshSigned, 0o700) })
	ownedPlanDirectory := makeOwnedPlanDirectory(t, fixture, freshSigned)
	fixture.gateCalls = 0
	deps.updater = ownedTestUpdater(fixture, freshSigned, deps.updater, false)
	ownedSigned := filepath.Join(root, "owned-signed")
	if err := signOwnedRecovery(context.Background(), ownedPlanDirectory, ownedSigned, deps); err != nil {
		t.Fatalf("signOwnedRecovery() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ownedSigned, 0o700) })
	if fixture.gateCalls != 1 {
		t.Fatalf("owned-recovery gate calls = %d, want exactly 1", fixture.gateCalls)
	}
	wantSigned := []string{"bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "result.json"}
	if got := directoryNames(t, ownedSigned); !reflect.DeepEqual(got, wantSigned) {
		t.Fatalf("signed entries = %v, want %v", got, wantSigned)
	}
	assertPublishedModes(t, ownedSigned, wantSigned)
	if !sameFile(t, filepath.Join(freshSigned, "pieeprom.bin"), filepath.Join(ownedSigned, "pieeprom.bin")) ||
		!sameFile(t, filepath.Join(freshSigned, "pieeprom.sig"), filepath.Join(ownedSigned, "pieeprom.sig")) {
		t.Fatal("owned-recovery signing changed verified fresh EEPROM outputs")
	}

	finalDirectory := filepath.Join(root, "owned-final")
	if err := finalizeOwnedRecovery(context.Background(), ownedPlanDirectory, ownedSigned, finalDirectory, deps); err != nil {
		t.Fatalf("finalizeOwnedRecovery() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(finalDirectory, 0o700) })
	if fixture.gateCalls != 1 {
		t.Fatalf("offline finalization contacted gate; calls = %d", fixture.gateCalls)
	}
	wantFinal := []string{"bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "plan.json", "public.pem", "recovery.original.bin", "release-intent.json", "result.json"}
	if got := directoryNames(t, finalDirectory); !reflect.DeepEqual(got, wantFinal) {
		t.Fatalf("final entries = %v, want %v", got, wantFinal)
	}
	assertPublishedModes(t, finalDirectory, wantFinal)
}

func TestOwnedRecoveryRejectsChangedFreshEEPROM(t *testing.T) {
	fixture := newWorkflowFixture(t)
	deps := fixture.dependencies()
	root := t.TempDir()
	freshSigned := filepath.Join(root, "fresh-signed")
	if err := signEEPROM(context.Background(), fixture.planDirectory, freshSigned, deps); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(freshSigned, 0o700) })
	ownedPlanDirectory := makeOwnedPlanDirectory(t, fixture, freshSigned)
	fixture.gateCalls = 0
	deps.updater = ownedTestUpdater(fixture, freshSigned, deps.updater, true)
	err := signOwnedRecovery(context.Background(), ownedPlanDirectory, filepath.Join(root, "owned-signed"), deps)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("changed the verified fresh EEPROM")) {
		t.Fatalf("error = %v", err)
	}
	if fixture.gateCalls != 1 {
		t.Fatalf("gate calls = %d, want 1", fixture.gateCalls)
	}
}

func makeOwnedPlanDirectory(t *testing.T, fixture *workflowFixture, freshSignedDirectory string) string {
	t.Helper()
	fresh, err := loadResultDirectory(freshSignedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	input, err := eepromsigning.NewOwnedRecoverySigningInput(fixture.originalRecovery)
	if err != nil {
		t.Fatal(err)
	}
	plan := eepromsigning.OwnedRecoveryPlan{
		SchemaVersion: eepromsigning.OwnedRecoveryPlanSchemaV1Alpha1,
		PlanID:        "owned-recovery:test", UpdaterMode: eepromsigning.UpdaterModeOwnedRecovery,
		UpdaterFlags: []string{"-f", "-r"}, FreshEEPROMPlan: fixture.plan,
		FreshEEPROMResult: fresh.Result, OwnedRecoverySigningInput: input,
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "owned-plan")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for destination, source := range map[string]string{
		"release-intent.json":   filepath.Join(fixture.planDirectory, "release-intent.json"),
		"pieeprom.original.bin": filepath.Join(fixture.planDirectory, "pieeprom.original.bin"),
		"recovery.original.bin": filepath.Join(fixture.planDirectory, "recovery.original.bin"),
		"bootcode.original.bin": filepath.Join(fixture.planDirectory, "bootcode.original.bin"),
		"bootsys.original":      filepath.Join(fixture.planDirectory, "bootsys.original"),
		"boot.conf":             filepath.Join(fixture.planDirectory, "boot.conf"),
		"public.pem":            filepath.Join(fixture.planDirectory, "public.pem"),
		"pieeprom.expected.bin": filepath.Join(freshSignedDirectory, "pieeprom.bin"),
		"pieeprom.expected.sig": filepath.Join(freshSignedDirectory, "pieeprom.sig"),
		"bootcode5.fresh.bin":   filepath.Join(freshSignedDirectory, "bootcode5.bin"),
	} {
		contents, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, destination), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "plan.json"), jsonFile(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func ownedTestUpdater(fixture *workflowFixture, freshSignedDirectory string, freshUpdater updaterRunner, changeEEPROM bool) updaterRunner {
	return func(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
		if !invocation.SignRecovery {
			return freshUpdater(ctx, invocation, callback)
		}
		recovery, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalRecovery)
		bootcode, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootcode)
		bootsys, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootsys)
		artifacts := [][]byte{recovery, bootcode, bootsys, fixture.bootConfig}
		signatures := make([][]byte, 0, len(artifacts))
		for _, artifact := range artifacts {
			encoded, err := callback(ctx, artifact)
			if err != nil {
				return err
			}
			signature, err := hex.DecodeString(encoded)
			if err != nil {
				return err
			}
			signatures = append(signatures, signature)
		}
		eeprom, err := os.ReadFile(filepath.Join(freshSignedDirectory, "pieeprom.bin"))
		if err != nil {
			return err
		}
		metadata, err := os.ReadFile(filepath.Join(freshSignedDirectory, "pieeprom.sig"))
		if err != nil {
			return err
		}
		if changeEEPROM {
			eeprom = append([]byte(nil), eeprom...)
			eeprom[0] ^= 0x80
		}
		signedRecovery := append(append(append([]byte(nil), recovery...), signatures[0]...), fixture.publicBinary...)
		for name, contents := range map[string][]byte{"pieeprom.bin": eeprom, "pieeprom.sig": metadata, "bootcode5.bin": signedRecovery} {
			if err := os.WriteFile(filepath.Join(invocation.WorkDir, name), contents, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
}

func sameFile(t *testing.T, left, right string) bool {
	t.Helper()
	a, err := os.ReadFile(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(right)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(a, b)
}
