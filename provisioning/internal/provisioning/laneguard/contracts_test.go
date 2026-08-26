package laneguard

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReconcileSchemaTracksBootModeBoundRequest(t *testing.T) {
	if ReconcileRequestSchemaVersion != "provisioning.kaiba.network/lane-guard-reconcile-request/v1alpha2" {
		t.Fatalf("reconcile request schema = %q", ReconcileRequestSchemaVersion)
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
