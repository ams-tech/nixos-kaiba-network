package laneguard

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReconcileSchemaTracksBootModeBoundRequest(t *testing.T) {
	if ReconcileRequestSchemaVersion != "provisioning.kaiba.network/lane-guard-reconcile-request/v1alpha3" {
		t.Fatalf("reconcile request schema = %q", ReconcileRequestSchemaVersion)
	}
}

func TestContractSchemaTracksAuthorizedPowerControlMode(t *testing.T) {
	if ContractSchemaVersion != "provisioning.kaiba.network/lane-guard/v1alpha6" {
		t.Fatalf("contract schema = %q", ContractSchemaVersion)
	}
}

func TestConfigRequiresClosedPowerControlMode(t *testing.T) {
	for _, mode := range []PowerControlMode{PowerControlRelay, PowerControlManual} {
		config := testConfig()
		config.PowerControlMode = mode
		if err := config.Validate(); err != nil {
			t.Fatalf("valid power control mode %q rejected: %v", mode, err)
		}
	}
	for _, mode := range []PowerControlMode{"", "automatic"} {
		config := testConfig()
		config.PowerControlMode = mode
		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "power control mode") {
			t.Fatalf("invalid power control mode %q error = %v", mode, err)
		}
	}
}

func TestPlanValidateRejectsPowerControlModeDifferentFromLane(t *testing.T) {
	plan := testPlan()
	config := testConfig()
	config.PowerControlMode = PowerControlManual
	if err := plan.Validate(config); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("mode-mismatched plan error = %v, want plan mismatch", err)
	}
}

func TestDirectStateValidateDistinguishesObservedAndUnavailableEEPROM(t *testing.T) {
	observed := DirectState{
		CustomerKeyHash: unownedCustomerKeyHash, EEPROMHash: digest("a"), EEPROMHashStatus: EEPROMHashObserved,
		SecurityState: "fresh", PowerState: "powered_off",
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("valid observed state: %v", err)
	}
	unavailable := observed
	unavailable.EEPROMHash = ""
	unavailable.EEPROMHashStatus = EEPROMHashUnavailable
	if err := unavailable.Validate(); err != nil {
		t.Fatalf("valid unavailable state: %v", err)
	}
	ownedUnavailable := unavailable
	ownedUnavailable.CustomerKeyHash = digest("b")
	ownedUnavailable.SecurityState = "owned"
	if err := ownedUnavailable.Validate(); err != nil {
		t.Fatalf("valid owned state with unavailable EEPROM hash: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DirectState)
	}{
		{"missing status", func(state *DirectState) { state.EEPROMHashStatus = "" }},
		{"observed empty hash", func(state *DirectState) { state.EEPROMHash = "" }},
		{"observed noncanonical hash", func(state *DirectState) { state.EEPROMHash = "sha256:factory" }},
		{"unavailable populated hash", func(state *DirectState) { state.EEPROMHashStatus = EEPROMHashUnavailable }},
		{"fresh owned key", func(state *DirectState) { state.CustomerKeyHash = digest("b") }},
		{"unowned key marked owned", func(state *DirectState) { state.SecurityState = "owned" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := observed
			test.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatalf("invalid direct state was accepted: %#v", state)
			}
		})
	}
}

func TestPlanValidateRequiresCommitAttestedThenObservedEEPROMProof(t *testing.T) {
	initialUnavailable := testPlanBody()
	initialUnavailable.Operations[0].ExpectedPrestate.EEPROMHash = ""
	initialUnavailable.Operations[0].ExpectedPrestate.EEPROMHashStatus = EEPROMHashUnavailable
	initialUnavailable = deriveTestPlan(initialUnavailable)
	if err := initialUnavailable.Validate(testConfig()); err != nil {
		t.Fatalf("unavailable initial EEPROM state was rejected: %v", err)
	}

	poststateUnavailable := testPlanBody()
	poststateUnavailable.Operations[0].ExpectedPoststate.EEPROMHash = ""
	poststateUnavailable.Operations[0].ExpectedPoststate.EEPROMHashStatus = EEPROMHashUnavailable
	poststateUnavailable = deriveTestPlan(poststateUnavailable)
	if err := poststateUnavailable.Validate(testConfig()); err == nil || !strings.Contains(err.Error(), "commit-attested-to-observed") {
		t.Fatalf("unavailable poststate error = %v", err)
	}

	missingObservedReadback := testPlanBody()
	missingObservedReadback.Operations[2].ExpectedPoststate = missingObservedReadback.Operations[2].ExpectedPrestate
	for index := 3; index < len(missingObservedReadback.Operations); index++ {
		missingObservedReadback.Operations[index].ExpectedPrestate = missingObservedReadback.Operations[2].ExpectedPoststate
		missingObservedReadback.Operations[index].ExpectedPoststate = missingObservedReadback.Operations[2].ExpectedPoststate
	}
	missingObservedReadback = deriveTestPlan(missingObservedReadback)
	if err := missingObservedReadback.Validate(testConfig()); err == nil || !strings.Contains(err.Error(), "commit-attested-to-observed") {
		t.Fatalf("missing observed readback error = %v", err)
	}
}

func TestRequiredBootModeForOperationUsesClosedPolicy(t *testing.T) {
	tests := []struct {
		operation Operation
		want      BootMode
	}{
		{OperationProgramCustomerKeyAndEEPROM, BootModeRPIBoot},
		{OperationColdPowerCycle, BootModeNormal},
		{OperationOwnedReadback, BootModeRPIBoot},
		{OperationTestOwnedRecovery, BootModeRPIBoot},
		{OperationPostRecoveryReadback, BootModeRPIBoot},
		{OperationTestNegativeBoot, BootModeRPIBoot},
		{OperationTestRootIntegrity, BootModeRPIBoot},
	}
	for _, test := range tests {
		t.Run(string(test.operation), func(t *testing.T) {
			got, ok := RequiredBootModeForOperation(test.operation)
			if !ok || got != test.want {
				t.Fatalf("required boot mode = %q, %t, want %q, true", got, ok, test.want)
			}
		})
	}
	for _, operation := range []Operation{OperationVerifySignedBoot, "unknown"} {
		t.Run("unsupported "+string(operation), func(t *testing.T) {
			if got, ok := RequiredBootModeForOperation(operation); ok || got != "" {
				t.Fatalf("unsupported operation mode = %q, %t, want empty, false", got, ok)
			}
		})
	}
}

func TestPlanValidateRejectsBootModeOutsideOperationPolicy(t *testing.T) {
	for index, operation := range testPlanBody().Operations {
		t.Run(string(operation.Operation), func(t *testing.T) {
			plan := testPlanBody()
			if plan.Operations[index].RequiredBootMode == BootModeNormal {
				plan.Operations[index].RequiredBootMode = BootModeRPIBoot
			} else {
				plan.Operations[index].RequiredBootMode = BootModeNormal
			}
			plan, err := plan.WithDerivedDigests()
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Validate(testConfig()); err == nil || !strings.Contains(err.Error(), "required boot mode") {
				t.Fatalf("plan with policy-inconsistent boot mode was accepted: %v", err)
			}
		})
	}
}

func TestValidatePlanRequestRejectsRequiredBootModeMismatch(t *testing.T) {
	plan := testPlan()
	request := requestFor(plan, 1, time.Now().UTC().Add(time.Minute))
	request.RequiredBootMode = BootModeNormal
	if err := ValidatePlanRequest(testConfig(), plan, request); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("request error = %v, want plan mismatch", err)
	}
}
