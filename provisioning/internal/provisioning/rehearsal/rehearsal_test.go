package rehearsal

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestContractRequiresExactSevenOperationCampaign(t *testing.T) {
	contract := NewContract("campaign-contract-test")
	if err := contract.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []Operation{
		OperationProgramCustomerKeyAndEEPROM,
		OperationColdPowerCycle,
		OperationOwnedReadback,
		OperationTestOwnedRecovery,
		OperationPostRecoveryReadback,
		OperationTestNegativeBoot,
		OperationTestRootIntegrity,
	}
	if !reflect.DeepEqual(contract.Operations, want) {
		t.Fatalf("operations = %#v", contract.Operations)
	}

	tests := map[string]func(*Contract){
		"schema":     func(value *Contract) { value.SchemaVersion = "production" },
		"identifier": func(value *Contract) { value.RehearsalID = "Bad ID" },
		"mode":       func(value *Contract) { value.SafetyMode = "hardware" },
		"authority":  func(value *Contract) { value.Authority = "production" },
		"omission":   func(value *Contract) { value.Operations = value.Operations[:6] },
		"reorder": func(value *Contract) {
			value.Operations[0], value.Operations[1] = value.Operations[1], value.Operations[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := NewContract("campaign-contract-test")
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestSimulatorCompletesDeterministicNonAuthoritativeCampaign(t *testing.T) {
	firstSimulator, err := NewSimulator(SimulatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	secondSimulator, err := NewSimulator(SimulatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	contract := NewContract("deterministic-campaign")
	first, err := Run(context.Background(), contract, firstSimulator)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), contract, secondSimulator)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated reports differ:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if first.Outcome != OutcomeRehearsalPassed || first.State.Phase != PhaseRehearsalPassed {
		t.Fatalf("outcome/phase = %q/%q", first.Outcome, first.State.Phase)
	}
	if first.State.CompletedOperations != OperationCount || len(first.Evidence) != OperationCount {
		t.Fatalf("completed/evidence = %d/%d", first.State.CompletedOperations, len(first.Evidence))
	}
	if first.Authority != AuthorityRehearsalOnly || first.State.PhysicalMutationPerformed || first.State.OTPWriteCount != 0 {
		t.Fatalf("unsafe authority/state = %q/%#v", first.Authority, first.State)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenProductionOutcome := "security" + "_applied"
	if strings.Contains(string(encoded), forbiddenProductionOutcome) {
		t.Fatalf("report contains forbidden production outcome: %s", encoded)
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSimulatorFailureInjectionStopsWithoutAdvancingModel(t *testing.T) {
	tests := []struct {
		name        string
		sequence    int
		disposition StepDisposition
		outcome     Outcome
		phase       Phase
	}{
		{"failed", 4, StepFailed, OutcomeRehearsalFailed, PhaseRehearsalFailed},
		{"uncertain", 6, StepUncertain, OutcomeRehearsalUncertain, PhaseRehearsalUncertain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			simulator, err := NewSimulator(SimulatorConfig{Failure: &FailureInjection{
				Sequence: test.sequence, Disposition: test.disposition,
			}})
			if err != nil {
				t.Fatal(err)
			}
			report, err := Run(context.Background(), NewContract("failure-campaign"), simulator)
			if err != nil {
				t.Fatal(err)
			}
			if report.Outcome != test.outcome || report.State.Phase != test.phase {
				t.Fatalf("outcome/phase = %q/%q", report.Outcome, report.State.Phase)
			}
			if report.State.CompletedOperations != test.sequence-1 || report.State.NextSequence != test.sequence {
				t.Fatalf("completed/next = %d/%d", report.State.CompletedOperations, report.State.NextSequence)
			}
			if len(report.Evidence) != test.sequence {
				t.Fatalf("evidence count = %d", len(report.Evidence))
			}
			last := report.Evidence[len(report.Evidence)-1]
			if last.Disposition != test.disposition || last.After != last.Before {
				t.Fatalf("last evidence = %#v", last)
			}
			if err := report.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSimulatorRejectsInvalidFailureInjection(t *testing.T) {
	for _, failure := range []FailureInjection{
		{Sequence: 0, Disposition: StepFailed},
		{Sequence: OperationCount + 1, Disposition: StepFailed},
		{Sequence: 1, Disposition: StepSucceeded},
		{Sequence: 1, Disposition: StepFailed, Detail: strings.Repeat("x", 257)},
	} {
		if _, err := NewSimulator(SimulatorConfig{Failure: &failure}); !errors.Is(err, ErrInvalidFailureInjection) {
			t.Fatalf("NewSimulator(%#v) error = %v", failure, err)
		}
	}
}

func TestCancelledCampaignIsRehearsalUncertain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	simulator, err := NewSimulator(SimulatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(ctx, NewContract("cancelled-campaign"), simulator)
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != OutcomeRehearsalUncertain || report.State.CompletedOperations != 0 || len(report.Evidence) != 1 {
		t.Fatalf("report = %#v", report)
	}
}

type invalidExecutor struct{}

func (invalidExecutor) Execute(context.Context, Step) StepResult {
	return StepResult{
		Disposition: StepSucceeded,
		After:       ModelStateUnfusedFixtureReady,
		Observation: "invalid",
		Detail:      "invalid",
	}
}

func TestRunnerRejectsExecutorThatSkipsModelTransition(t *testing.T) {
	_, err := Run(context.Background(), NewContract("invalid-executor"), invalidExecutor{})
	if !errors.Is(err, ErrInvalidStepResult) {
		t.Fatalf("Run() error = %v", err)
	}
}
