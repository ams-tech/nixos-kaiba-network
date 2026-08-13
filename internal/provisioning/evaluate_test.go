package provisioning

import (
	"reflect"
	"strings"
	"testing"
)

func TestEvaluatePass(t *testing.T) {
	profile := mustTestProfile(t)
	assessment := Evaluate(profile, matchingObservation())

	if got, want := assessment.Class.Status, StatusPass; got != want {
		t.Fatalf("class status = %q, want %q", got, want)
	}
	if got, want := assessment.ObservableBaseline.Status, StatusPass; got != want {
		t.Fatalf("baseline status = %q, want %q", got, want)
	}
	if !assessment.EligibleForReversibleQualification {
		t.Fatal("eligible_for_reversible_qualification = false, want true")
	}
	if assessment.MutationEligible {
		t.Fatal("mutation_eligible = true, want false")
	}
	if assessment.FullUnprovisionedState != FullUnprovisionedStateNotEstablished {
		t.Fatalf("full state = %q", assessment.FullUnprovisionedState)
	}
	if assessment.Disclaimer != AssessmentDisclaimer {
		t.Fatalf("disclaimer = %q", assessment.Disclaimer)
	}
	if got, want := len(assessment.DeferredChecks), 1; got != want {
		t.Fatalf("deferred checks = %d, want %d", got, want)
	}
}

func TestEvaluateClassFailureSkipsBaseline(t *testing.T) {
	profile := mustTestProfile(t)
	observation := matchingObservation()
	observation.Facts["board.revision.model"] = "24"

	assessment := Evaluate(profile, observation)
	if got, want := assessment.Class.Status, StatusFail; got != want {
		t.Fatalf("class status = %q, want %q", got, want)
	}
	if got, want := assessment.ObservableBaseline.Status, StatusIndeterminate; got != want {
		t.Fatalf("baseline status = %q, want %q", got, want)
	}
	if got, want := assessment.ObservableBaseline.Findings[0].Code, "class_not_established"; got != want {
		t.Fatalf("baseline finding = %q, want %q", got, want)
	}
}

func TestEvaluateBaselineFailure(t *testing.T) {
	profile := mustTestProfile(t)
	observation := matchingObservation()
	observation.Facts["security.customer_key_unprogrammed"] = "false"

	assessment := Evaluate(profile, observation)
	if got, want := assessment.ObservableBaseline.Status, StatusFail; got != want {
		t.Fatalf("baseline status = %q, want %q", got, want)
	}
	if assessment.EligibleForReversibleQualification {
		t.Fatal("eligible = true, want false")
	}
}

func TestEvaluateNotEquals(t *testing.T) {
	profileJSON := strings.Replace(
		validProfileJSON,
		`"operator": "equals", "value": "true"`,
		`"operator": "not_equals", "value": "false"`,
		1,
	)
	profile, err := ParseProfile([]byte(profileJSON))
	if err != nil {
		t.Fatalf("ParseProfile() error = %v", err)
	}

	if got := Evaluate(profile, matchingObservation()).ObservableBaseline.Status; got != StatusPass {
		t.Fatalf("not_equals satisfied status = %q, want pass", got)
	}

	observation := matchingObservation()
	observation.Facts["security.customer_key_unprogrammed"] = "false"
	if got := Evaluate(profile, observation).ObservableBaseline.Status; got != StatusFail {
		t.Fatalf("not_equals violated status = %q, want fail", got)
	}
}

func TestEvaluateMissingFactIsIndeterminate(t *testing.T) {
	profile := mustTestProfile(t)
	observation := matchingObservation()
	delete(observation.Facts, "firmware.eeprom_hash")

	assessment := Evaluate(profile, observation)
	if got, want := assessment.ObservableBaseline.Status, StatusIndeterminate; got != want {
		t.Fatalf("baseline status = %q, want %q", got, want)
	}
	if len(assessment.ObservableBaseline.Findings) != 2 {
		t.Fatalf("findings = %#v, want condition and required-fact findings", assessment.ObservableBaseline.Findings)
	}
}

func TestEvaluateUnknownFieldsPreventPassAndAreDeterministic(t *testing.T) {
	profile := mustTestProfile(t)
	first := matchingObservation()
	first.UnknownFields = []string{"Z_FUTURE", "A_FUTURE", "Z_FUTURE"}
	second := matchingObservation()
	second.UnknownFields = []string{"A_FUTURE", "Z_FUTURE"}

	got := Evaluate(profile, first)
	want := Evaluate(profile, second)
	if got.ObservableBaseline.Status != StatusIndeterminate {
		t.Fatalf("baseline status = %q, want indeterminate", got.ObservableBaseline.Status)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assessment depends on unknown-field input order:\n got %#v\nwant %#v", got, want)
	}
}

func TestEvaluateUnknownFieldsPreserveKnownFailure(t *testing.T) {
	profile := mustTestProfile(t)
	observation := matchingObservation()
	observation.Facts["security.customer_key_unprogrammed"] = "false"
	observation.UnknownFields = []string{"FUTURE_SECURITY_STATE"}

	assessment := Evaluate(profile, observation)
	if got, want := assessment.ObservableBaseline.Status, StatusFail; got != want {
		t.Fatalf("baseline status = %q, want %q", got, want)
	}
	if len(assessment.ObservableBaseline.Findings) != 2 {
		t.Fatalf("findings = %#v, want known violation plus unknown-field finding", assessment.ObservableBaseline.Findings)
	}
}

func TestEvaluateAdapterMismatch(t *testing.T) {
	profile := mustTestProfile(t)
	observation := matchingObservation()
	observation.AdapterVersion = "v2"

	assessment := Evaluate(profile, observation)
	if got, want := assessment.Class.Status, StatusIndeterminate; got != want {
		t.Fatalf("class status = %q, want %q", got, want)
	}
	if got, want := assessment.Class.Findings[0].Code, "adapter_version_mismatch"; got != want {
		t.Fatalf("finding code = %q, want %q", got, want)
	}
}

func mustTestProfile(t *testing.T) DeviceProfile {
	t.Helper()
	profile, err := ParseProfile([]byte(validProfileJSON))
	if err != nil {
		t.Fatalf("ParseProfile() error = %v", err)
	}
	return profile
}

func matchingObservation() TargetObservation {
	return TargetObservation{
		AdapterID:      "rpi5",
		AdapterVersion: "v1alpha1",
		Facts: map[string]string{
			"board.revision.model":               "23",
			"security.customer_key_unprogrammed": "true",
			"firmware.eeprom_hash":               "0123456789abcdef",
		},
	}
}
