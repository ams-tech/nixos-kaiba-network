package rehearsal

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidStepResult = errors.New("invalid software rehearsal step result")

// Step is the complete, side-effect-free input supplied to a rehearsal
// executor.
type Step struct {
	RehearsalID string
	Sequence    int
	Operation   Operation
	Before      ModelState
}

// StepResult is one synthetic observation. A failed or uncertain step must
// leave the model state unchanged.
type StepResult struct {
	Disposition StepDisposition
	After       ModelState
	Observation string
	Detail      string
}

// Executor is intentionally incompatible with the production hardware
// adapter interface. Implementations receive no paths, bundles, approvals, or
// physical configuration.
type Executor interface {
	Execute(context.Context, Step) StepResult
}

// Run executes the exact rehearsal campaign and returns a non-authoritative
// terminal report. Expected simulated failures are represented in Report and
// are not Go errors.
func Run(ctx context.Context, contract Contract, executor Executor) (Report, error) {
	if err := contract.Validate(); err != nil {
		return Report{}, err
	}
	if executor == nil {
		return Report{}, fmt.Errorf("%w: executor is nil", ErrInvalidStepResult)
	}
	report := Report{
		SchemaVersion: contract.SchemaVersion,
		RehearsalID:   contract.RehearsalID,
		SafetyMode:    contract.SafetyMode,
		Authority:     contract.Authority,
		State: State{
			Phase:        PhaseReady,
			ModelState:   ModelStateUnfusedFixtureReady,
			NextSequence: 1,
		},
		Evidence: make([]Evidence, 0, OperationCount),
	}

	for index, operation := range contract.Operations {
		sequence := index + 1
		report.State.Phase = PhaseRunning
		step := Step{
			RehearsalID: contract.RehearsalID,
			Sequence:    sequence,
			Operation:   operation,
			Before:      report.State.ModelState,
		}
		var result StepResult
		if err := ctx.Err(); err != nil {
			result = StepResult{
				Disposition: StepUncertain,
				After:       step.Before,
				Observation: "software_rehearsal_context_cancelled",
				Detail:      err.Error(),
			}
		} else {
			result = executor.Execute(ctx, step)
		}
		if err := validateStepResult(step, result); err != nil {
			return Report{}, err
		}
		evidence := Evidence{
			Kind: EvidenceKindSyntheticModel, Sequence: sequence, Operation: operation,
			Disposition: result.Disposition, Before: step.Before, After: result.After,
			Observation: result.Observation, Detail: result.Detail,
		}
		evidence.Digest = evidenceDigest(evidence)
		report.Evidence = append(report.Evidence, evidence)

		switch result.Disposition {
		case StepSucceeded:
			report.State.CompletedOperations = sequence
			report.State.NextSequence = sequence + 1
			report.State.ModelState = result.After
		case StepFailed:
			report.Outcome = OutcomeRehearsalFailed
			report.State.Phase = PhaseRehearsalFailed
			report.Detail = fmt.Sprintf("software-only rehearsal stopped at operation %d: %s", sequence, result.Detail)
			return validatedReport(report)
		case StepUncertain:
			report.Outcome = OutcomeRehearsalUncertain
			report.State.Phase = PhaseRehearsalUncertain
			report.Detail = fmt.Sprintf("software-only rehearsal became uncertain at operation %d: %s", sequence, result.Detail)
			return validatedReport(report)
		}
	}

	report.Outcome = OutcomeRehearsalPassed
	report.State.Phase = PhaseRehearsalPassed
	report.Detail = "software-only rehearsal completed; no physical or OTP action was attempted"
	return validatedReport(report)
}

func validateStepResult(step Step, result StepResult) error {
	if result.Observation == "" || result.Detail == "" {
		return fmt.Errorf("%w: operation %d returned incomplete evidence", ErrInvalidStepResult, step.Sequence)
	}
	switch result.Disposition {
	case StepSucceeded:
		if result.After != modelStates[step.Sequence] {
			return fmt.Errorf("%w: operation %d returned model state %q, want %q", ErrInvalidStepResult, step.Sequence, result.After, modelStates[step.Sequence])
		}
	case StepFailed, StepUncertain:
		if result.After != step.Before {
			return fmt.Errorf("%w: non-success operation %d changed model state", ErrInvalidStepResult, step.Sequence)
		}
	default:
		return fmt.Errorf("%w: operation %d returned disposition %q", ErrInvalidStepResult, step.Sequence, result.Disposition)
	}
	return nil
}

func validatedReport(report Report) (Report, error) {
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}
