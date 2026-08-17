package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5"
)

type commandHardware struct {
	observation laneguard.Observation
	executions  int
	poststate   laneguard.DirectState
}

func (hardware *commandHardware) Observe(context.Context, laneguard.Config) (laneguard.Observation, error) {
	return hardware.observation, nil
}

func (hardware *commandHardware) Execute(_ context.Context, _ laneguard.Config, _ laneguard.Operation) (laneguard.OperationResult, error) {
	hardware.executions++
	hardware.observation.State = hardware.poststate
	return laneguard.OperationResult{OutputDigest: commandDigest("f"), Detail: "fake physical execution"}, nil
}

func TestDisabledCommandValidatesLaneWithoutMutationInputs(t *testing.T) {
	if err := run(context.Background(), nil); err != nil {
		t.Fatalf("disabled run: %v", err)
	}
}

func TestEnabledCommandRequiresRootAndImmutableBuildPaths(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 1000 }
	if err := run(context.Background(), []string{"--enable-mutations"}); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("non-root error = %v", err)
	}

	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	directory := t.TempDir()
	planPath := writeJSON(t, directory, "plan.json", plan)
	requestPath := writeJSON(t, directory, "request.json", request)
	err := run(context.Background(), []string{
		"--enable-mutations", "--plan", planPath, "--request", requestPath,
		"--journal", filepath.Join(directory, "journal.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "immutable") || !strings.Contains(err.Error(), "path") {
		t.Fatalf("missing immutable-path error = %v", err)
	}
}

func TestOneShotCommandUsesDurableJournalAndNoCallerArtifactPaths(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals()
	plan, request := commandPlanAndRequest()
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate: plan.Operations[0].ExpectedPoststate,
	}
	buildHardware = func(config physicalrpi5.Config) (laneguard.Hardware, error) {
		if config.Paths.RPIBootBinary != rpibootBinary || config.Paths.FreshCommitBundle != freshCommitBundle || !config.Paths.RequireNixStorePaths {
			t.Fatalf("physical config = %#v", config)
		}
		return hardware, nil
	}
	directory := t.TempDir()
	planPath := writeJSON(t, directory, "plan.json", plan)
	requestPath := writeJSON(t, directory, "request.json", request)
	journalPath := filepath.Join(directory, "journal.json")
	if err := run(context.Background(), []string{
		"--enable-mutations", "--plan", planPath, "--request", requestPath,
		"--journal", journalPath,
	}); err != nil {
		t.Fatalf("one-shot run: %v", err)
	}
	if hardware.executions != 1 {
		t.Fatalf("hardware executions = %d", hardware.executions)
	}
	store, err := laneguard.NewFileStore(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	key := plan.TransactionID + "/" + plan.PlanDigest + "/1/1"
	attempt, ok, err := store.Get(key)
	if err != nil || !ok || attempt.Status != laneguard.AttemptVerified {
		t.Fatalf("durable attempt = %#v, %t, %v", attempt, ok, err)
	}

	if err := run(context.Background(), []string{"--rpiboot-binary", "/tmp/evil"}); err == nil {
		t.Fatal("caller-selectable rpiboot path flag was accepted")
	}
}

func TestCommandRejectsMismatchedRequestBeforeConstructingHardware(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	request.OperationDigest = commandDigest("9")
	buildHardware = func(physicalrpi5.Config) (laneguard.Hardware, error) {
		t.Fatal("mismatched request reached hardware construction")
		return nil, nil
	}
	directory := t.TempDir()
	err := run(context.Background(), []string{
		"--enable-mutations",
		"--plan", writeJSON(t, directory, "plan.json", plan),
		"--request", writeJSON(t, directory, "request.json", request),
		"--journal", filepath.Join(directory, "journal.json"),
	})
	if !errors.Is(err, laneguard.ErrPlanMismatch) {
		t.Fatalf("error = %v, want plan mismatch", err)
	}
}

func TestStrictInputRejectsDuplicateFieldsAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	duplicatePath := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"sequence":1,"sequence":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var request laneguard.ExecuteRequest
	if err := loadStrictJSON(duplicatePath, 1024, &request); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	symlinkPath := filepath.Join(directory, "link.json")
	if err := os.Symlink(duplicatePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := loadStrictJSON(symlinkPath, 1024, &request); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

func commandPlanAndRequest() (laneguard.Plan, laneguard.ExecuteRequest) {
	prestate := laneguard.DirectState{CustomerKeyHash: zeroHash, EEPROMHash: strings.Repeat("f", 64), SecurityState: "fresh", PowerState: "rpiboot"}
	poststate := laneguard.DirectState{CustomerKeyHash: strings.Repeat("1", 64), EEPROMHash: strings.Repeat("e", 64), SecurityState: "owned", PowerState: "rpiboot"}
	plan := laneguard.Plan{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: "development-station", LaneID: "lane-1",
		TransactionID: "transaction-1", TargetFingerprint: "target-1",
		FenceEpoch: 1, ApprovalID: "approval-1", IntentReceipt: "intent-1",
		Operations: []laneguard.OperationSpec{
			{
				Sequence: 1, Operation: laneguard.OperationProgramCustomerKeyAndEEPROM,
				Classification:  laneguard.ClassIrreversible,
				AuthorizationID: "authorization-1", ExpectedPrestate: prestate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 2, Operation: laneguard.OperationColdPowerCycle,
				Classification:  laneguard.ClassReversible,
				AuthorizationID: "authorization-2", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 3, Operation: laneguard.OperationOwnedReadback,
				Classification:  laneguard.ClassReadOnly,
				AuthorizationID: "authorization-3", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 4, Operation: laneguard.OperationTestOwnedRecovery,
				Classification:  laneguard.ClassReversible,
				AuthorizationID: "authorization-4", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 5, Operation: laneguard.OperationPostRecoveryReadback,
				Classification:  laneguard.ClassReadOnly,
				AuthorizationID: "authorization-5", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 6, Operation: laneguard.OperationTestNegativeBoot,
				Classification:  laneguard.ClassReversible,
				AuthorizationID: "authorization-6", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 7, Operation: laneguard.OperationTestRootIntegrity,
				Classification:  laneguard.ClassReversible,
				AuthorizationID: "authorization-7", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
		},
	}
	derived, err := plan.WithDerivedDigests()
	if err != nil {
		panic(err)
	}
	plan = derived
	request := laneguard.ExecuteRequest{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest, TargetFingerprint: plan.TargetFingerprint,
		FenceEpoch: plan.FenceEpoch, ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt,
		Sequence: 1, OperationDigest: plan.Operations[0].OperationDigest,
		AuthorizationID: plan.Operations[0].AuthorizationID, ExpectedPrestate: prestate,
		ClaimExpiresAt: time.Now().Add(10 * time.Minute),
	}
	return plan, request
}

func writeJSON(t *testing.T, directory, name string, value any) string {
	t.Helper()
	path := filepath.Join(directory, name)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setImmutableTestGlobals() {
	rpibootBinary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-rpiboot/bin/rpiboot"
	gpioSetBinary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-gpio/bin/gpioset"
	freshReadbackBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fresh-readback"
	freshCommitBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fresh-commit"
	ownedReadbackBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-owned-readback"
	ownedRecoveryBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-owned-recovery"
	negativeBootBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-negative"
	rootIntegrityBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-integrity"
	expectedCustomerKeyHash = strings.Repeat("1", 64)
	expectedEEPROMHash = strings.Repeat("e", 64)
	expectedBootImageDigest = "sha256:" + strings.Repeat("b", 64)
}

func restoreCommandGlobals(t *testing.T) {
	t.Helper()
	savedUID, savedFactory := effectiveUID, buildHardware
	values := []string{
		rpibootBinary, gpioSetBinary, freshReadbackBundle, freshCommitBundle,
		ownedReadbackBundle, ownedRecoveryBundle, negativeBootBundle, rootIntegrityBundle,
		expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest,
	}
	t.Cleanup(func() {
		effectiveUID, buildHardware = savedUID, savedFactory
		rpibootBinary, gpioSetBinary = values[0], values[1]
		freshReadbackBundle, freshCommitBundle = values[2], values[3]
		ownedReadbackBundle, ownedRecoveryBundle = values[4], values[5]
		negativeBootBundle, rootIntegrityBundle = values[6], values[7]
		expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest = values[8], values[9], values[10]
	})
}

func commandDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
