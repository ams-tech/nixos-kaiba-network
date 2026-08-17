package campaign

import (
	"errors"
	"testing"
)

func TestDevelopmentOperationsReturnsDefensiveCopy(t *testing.T) {
	first := DevelopmentOperations()
	first[0] = "changed"
	second := DevelopmentOperations()
	if second[0] != OperationProgramCustomerKeyAndEEPROM {
		t.Fatalf("canonical campaign was mutated: %q", second[0])
	}
}

func TestValidateDevelopmentOperationsRequiresExactCampaign(t *testing.T) {
	canonical := DevelopmentOperations()
	if err := ValidateDevelopmentOperations(canonical); err != nil {
		t.Fatalf("canonical campaign rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]Operation) []Operation
	}{
		{
			name: "truncated",
			mutate: func(operations []Operation) []Operation {
				return operations[:len(operations)-1]
			},
		},
		{
			name: "reordered",
			mutate: func(operations []Operation) []Operation {
				operations[2], operations[3] = operations[3], operations[2]
				return operations
			},
		},
		{
			name: "duplicated",
			mutate: func(operations []Operation) []Operation {
				operations[3] = operations[2]
				return operations
			},
		},
		{
			name: "inserted",
			mutate: func(operations []Operation) []Operation {
				return append(operations, Operation("inserted_operation"))
			},
		},
		{
			name: "renamed",
			mutate: func(operations []Operation) []Operation {
				operations[4] = "renamed_operation"
				return operations
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := append([]Operation(nil), canonical...)
			if err := ValidateDevelopmentOperations(test.mutate(operations)); !errors.Is(err, ErrInvalidDevelopmentCampaign) {
				t.Fatalf("error = %v, want invalid development campaign", err)
			}
		})
	}
}
