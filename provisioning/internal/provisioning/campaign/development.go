// Package campaign defines provisioning campaigns shared by the control plane
// and the privileged lane guard.
package campaign

import (
	"errors"
	"fmt"
)

// Operation is a stable wire identifier for one provisioning operation.
type Operation string

const (
	OperationProgramCustomerKeyAndEEPROM Operation = "program_customer_key_and_eeprom"
	OperationColdPowerCycle              Operation = "cold_power_cycle"
	OperationOwnedReadback               Operation = "owned_readback"
	OperationTestOwnedRecovery           Operation = "test_owned_recovery"
	OperationPostRecoveryReadback        Operation = "post_recovery_readback"
	OperationTestNegativeBoot            Operation = "test_negative_boot"
	OperationTestRootIntegrity           Operation = "test_root_integrity"

	DevelopmentOperationCount = 7
)

var (
	ErrInvalidDevelopmentCampaign = errors.New("invalid development secure-boot campaign")

	developmentOperations = [DevelopmentOperationCount]Operation{
		OperationProgramCustomerKeyAndEEPROM,
		OperationColdPowerCycle,
		OperationOwnedReadback,
		OperationTestOwnedRecovery,
		OperationPostRecoveryReadback,
		OperationTestNegativeBoot,
		OperationTestRootIntegrity,
	}
)

// DevelopmentOperations returns a copy of the complete initial secure-boot
// campaign. Callers cannot mutate the canonical policy.
func DevelopmentOperations() []Operation {
	operations := make([]Operation, len(developmentOperations))
	copy(operations, developmentOperations[:])
	return operations
}

// ValidateDevelopmentOperations requires the complete campaign, in order,
// without omitted, duplicated, inserted, or renamed operations.
func ValidateDevelopmentOperations(operations []Operation) error {
	if len(operations) != len(developmentOperations) {
		return fmt.Errorf("%w: operation count is %d, want %d", ErrInvalidDevelopmentCampaign, len(operations), len(developmentOperations))
	}
	for index, expected := range developmentOperations {
		if operations[index] != expected {
			return fmt.Errorf("%w: operation %d is %q, want %q", ErrInvalidDevelopmentCampaign, index+1, operations[index], expected)
		}
	}
	return nil
}
