package provisioning

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const (
	FullUnprovisionedStateNotEstablished = "not_established"
	AssessmentDisclaimer                 = "This observation is correlation and partial preflight evidence; it is not device authentication or attestation and does not authorize irreversible provisioning."
)

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusIndeterminate Status = "indeterminate"
)

// TargetObservation is the normalized input to policy evaluation. Facts are
// adapter-defined, string-valued facts. UnknownFields contains upstream fields
// which the adapter deliberately preserved but does not understand.
type TargetObservation struct {
	AdapterID      string            `json:"adapter_id"`
	AdapterVersion string            `json:"adapter_version"`
	Facts          map[string]string `json:"facts"`
	UnknownFields  []string          `json:"unknown_fields,omitempty"`
	// Native carries the adapter's typed observation for orchestration and is
	// deliberately excluded from the policy contract and JSON encoding.
	Native any `json:"-"`
}

type Finding struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Fact     string `json:"fact,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Message  string `json:"message"`
}

type EvaluationResult struct {
	Status   Status    `json:"status"`
	Findings []Finding `json:"findings"`
}

type Assessment struct {
	Class                              EvaluationResult `json:"device_class"`
	ObservableBaseline                 EvaluationResult `json:"observable_baseline"`
	DeferredChecks                     []DeferredCheck  `json:"deferred_checks"`
	EligibleForReversibleQualification bool             `json:"eligible_for_reversible_qualification"`
	MutationEligible                   bool             `json:"mutation_eligible"`
	FullUnprovisionedState             string           `json:"full_unprovisioned_state"`
	Disclaimer                         string           `json:"disclaimer"`
}

// Evaluate applies a validated device profile to normalized evidence. Invalid
// or mismatched adapter contracts are represented conservatively as an
// indeterminate assessment rather than a successful match.
func Evaluate(profile DeviceProfile, observation TargetObservation) Assessment {
	assessment := Assessment{
		Class:                  EvaluationResult{Status: StatusPass, Findings: []Finding{}},
		ObservableBaseline:     EvaluationResult{Status: StatusIndeterminate, Findings: []Finding{}},
		DeferredChecks:         append([]DeferredCheck(nil), profile.Spec.DeferredChecks...),
		MutationEligible:       false,
		FullUnprovisionedState: FullUnprovisionedStateNotEstablished,
		Disclaimer:             AssessmentDisclaimer,
	}

	if observation.AdapterID != profile.Spec.Adapter.ID {
		assessment.Class = EvaluationResult{
			Status: StatusIndeterminate,
			Findings: []Finding{{
				ID:       "adapter-id",
				Code:     "adapter_mismatch",
				Expected: profile.Spec.Adapter.ID,
				Actual:   observation.AdapterID,
				Message:  "observation adapter does not match the profile",
			}},
		}
		assessment.ObservableBaseline.Findings = classNotEstablishedFinding()
		return assessment
	}
	if observation.AdapterVersion != profile.Spec.Adapter.Version {
		assessment.Class = EvaluationResult{
			Status: StatusIndeterminate,
			Findings: []Finding{{
				ID:       "adapter-version",
				Code:     "adapter_version_mismatch",
				Expected: profile.Spec.Adapter.Version,
				Actual:   observation.AdapterVersion,
				Message:  "observation adapter version does not match the profile",
			}},
		}
		assessment.ObservableBaseline.Findings = classNotEstablishedFinding()
		return assessment
	}

	assessment.Class = evaluateConditions(profile.Spec.ClassConditions, observation.Facts)
	if assessment.Class.Status != StatusPass {
		assessment.ObservableBaseline.Findings = classNotEstablishedFinding()
		return assessment
	}

	baseline := evaluateConditions(profile.Spec.BaselineConditions, observation.Facts)
	for _, fact := range profile.SortedRequiredFacts() {
		if _, present := observation.Facts[fact]; present {
			continue
		}
		baseline.Findings = append(baseline.Findings, Finding{
			ID:      "required-fact-" + strings.ReplaceAll(fact, ".", "-"),
			Code:    "required_fact_missing",
			Fact:    fact,
			Message: "required observation fact is absent",
		})
		baseline.Status = aggregateStatus(baseline.Status, StatusIndeterminate)
	}

	unknown := uniqueSorted(observation.UnknownFields)
	for _, field := range unknown {
		baseline.Findings = append(baseline.Findings, Finding{
			ID:      "unknown-field-" + stableFindingSuffix(field),
			Code:    "unknown_observation_field",
			Fact:    field,
			Message: "upstream evidence field is not understood by this adapter version",
		})
	}
	// The profile cannot make a passing observable-baseline determination
	// while upstream evidence remains uninterpreted. Preserve a known failure:
	// added uncertainty must not hide a violated condition.
	if len(unknown) > 0 {
		baseline.Status = aggregateStatus(baseline.Status, StatusIndeterminate)
	}

	sortFindings(baseline.Findings)
	assessment.ObservableBaseline = baseline
	assessment.EligibleForReversibleQualification = baseline.Status == StatusPass
	return assessment
}

func evaluateConditions(conditions []Condition, facts map[string]string) EvaluationResult {
	result := EvaluationResult{Status: StatusPass, Findings: []Finding{}}
	for _, condition := range conditions {
		actual, present := facts[condition.Fact]
		switch condition.Operator {
		case OperatorPresent:
			if !present {
				result.Status = aggregateStatus(result.Status, StatusIndeterminate)
				result.Findings = append(result.Findings, conditionFinding(condition, "condition_fact_missing", "", "condition fact is absent"))
			}
		case OperatorEquals:
			if !present {
				result.Status = aggregateStatus(result.Status, StatusIndeterminate)
				result.Findings = append(result.Findings, conditionFinding(condition, "condition_fact_missing", "", "condition fact is absent"))
			} else if actual != *condition.Value {
				result.Status = aggregateStatus(result.Status, StatusFail)
				result.Findings = append(result.Findings, conditionFinding(condition, "condition_not_satisfied", actual, "observed value does not equal the required value"))
			}
		case OperatorNotEquals:
			if !present {
				result.Status = aggregateStatus(result.Status, StatusIndeterminate)
				result.Findings = append(result.Findings, conditionFinding(condition, "condition_fact_missing", "", "condition fact is absent"))
			} else if actual == *condition.Value {
				result.Status = aggregateStatus(result.Status, StatusFail)
				result.Findings = append(result.Findings, conditionFinding(condition, "condition_not_satisfied", actual, "observed value equals a forbidden value"))
			}
		default:
			result.Status = aggregateStatus(result.Status, StatusIndeterminate)
			result.Findings = append(result.Findings, conditionFinding(condition, "unsupported_operator", actual, "condition operator is unsupported"))
		}
	}
	sortFindings(result.Findings)
	return result
}

func conditionFinding(condition Condition, code, actual, message string) Finding {
	expected := "present"
	if condition.Value != nil {
		expected = string(condition.Operator) + ":" + *condition.Value
	}
	return Finding{
		ID:       condition.ID,
		Code:     code,
		Fact:     condition.Fact,
		Expected: expected,
		Actual:   actual,
		Message:  message,
	}
}

func classNotEstablishedFinding() []Finding {
	return []Finding{{
		ID:      "device-class",
		Code:    "class_not_established",
		Message: "observable baseline was not evaluated because device class did not pass",
	}}
}

func aggregateStatus(current, candidate Status) Status {
	if current == StatusFail || candidate == StatusFail {
		return StatusFail
	}
	if current == StatusIndeterminate || candidate == StatusIndeterminate {
		return StatusIndeterminate
	}
	return StatusPass
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left := findings[i].ID + "\x00" + findings[i].Code + "\x00" + findings[i].Fact
		right := findings[j].ID + "\x00" + findings[j].Code + "\x00" + findings[j].Fact
		return left < right
	})
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stableFindingSuffix(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}
