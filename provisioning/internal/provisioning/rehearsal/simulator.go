package rehearsal

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidFailureInjection = errors.New("invalid software rehearsal failure injection")

// FailureInjection deterministically stops the synthetic campaign at one
// operation. Only failed and uncertain dispositions are supported.
type FailureInjection struct {
	Sequence    int
	Disposition StepDisposition
	Detail      string
}

// SimulatorConfig configures the side-effect-free model. A nil injection runs
// the full happy path.
type SimulatorConfig struct {
	Failure *FailureInjection
}

// Simulator is stateless and deterministic. It imports no physical adapter,
// RPIBOOT, artifact-bundle, or production control package.
type Simulator struct {
	failure *FailureInjection
}

// NewSimulator validates and copies configuration so callers cannot mutate a
// running simulator.
func NewSimulator(config SimulatorConfig) (*Simulator, error) {
	simulator := &Simulator{}
	if config.Failure == nil {
		return simulator, nil
	}
	failure := *config.Failure
	if failure.Sequence < 1 || failure.Sequence > OperationCount {
		return nil, fmt.Errorf("%w: sequence must be between 1 and %d", ErrInvalidFailureInjection, OperationCount)
	}
	if failure.Disposition != StepFailed && failure.Disposition != StepUncertain {
		return nil, fmt.Errorf("%w: disposition must be %q or %q", ErrInvalidFailureInjection, StepFailed, StepUncertain)
	}
	if failure.Detail == "" {
		failure.Detail = fmt.Sprintf("injected %s at operation %d", failure.Disposition, failure.Sequence)
	}
	if strings.TrimSpace(failure.Detail) == "" || len(failure.Detail) > 256 {
		return nil, fmt.Errorf("%w: detail must contain between 1 and 256 bytes", ErrInvalidFailureInjection)
	}
	simulator.failure = &failure
	return simulator, nil
}

var successfulObservations = [OperationCount]string{
	"model_commit_path_completed_without_hardware_access",
	"model_cold_power_cycle_completed_without_power_control",
	"model_owned_readback_matched_synthetic_fixture",
	"model_owned_recovery_path_matched_synthetic_fixture",
	"model_post_recovery_readback_matched_synthetic_fixture",
	"model_negative_boot_rejection_matched_synthetic_fixture",
	"model_root_integrity_rejection_matched_synthetic_fixture",
}

// Execute returns synthetic evidence and performs no I/O.
func (simulator *Simulator) Execute(ctx context.Context, step Step) StepResult {
	if err := ctx.Err(); err != nil {
		return StepResult{
			Disposition: StepUncertain,
			After:       step.Before,
			Observation: "software_rehearsal_context_cancelled",
			Detail:      err.Error(),
		}
	}
	if simulator.failure != nil && simulator.failure.Sequence == step.Sequence {
		return StepResult{
			Disposition: simulator.failure.Disposition,
			After:       step.Before,
			Observation: fmt.Sprintf("synthetic_failure_injected_at_%s", step.Operation),
			Detail:      simulator.failure.Detail,
		}
	}
	return StepResult{
		Disposition: StepSucceeded,
		After:       modelStates[step.Sequence],
		Observation: successfulObservations[step.Sequence-1],
		Detail:      fmt.Sprintf("synthetic operation %d (%s) completed", step.Sequence, step.Operation),
	}
}
