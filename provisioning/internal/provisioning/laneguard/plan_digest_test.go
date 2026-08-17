package laneguard

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	goldenOperationMaterial  = `{"sequence":3,"operation":"owned_readback","classification":"read_only","authorization_id":"authorization-golden","expected_prestate":{"customer_key_hash":"customer-before","eeprom_hash":"eeprom-before","security_state":"owned","power_state":"signed_os"},"expected_poststate":{"customer_key_hash":"customer-after","eeprom_hash":"eeprom-after","security_state":"owned_verified","power_state":"signed_os"},"maximum_duration_nanoseconds":90000000000}`
	goldenOperationDigest    = "sha256:dd2c209f0d68640b74ea1be1cb6ce1efa7990751d443fcf950db37bb0c6e33a7"
	goldenPlanMaterial       = `{"schema_version":"provisioning.kaiba.network/lane-guard/v1alpha1","station_id":"golden-station","lane_id":"golden-lane","transaction_id":"golden-transaction","target_fingerprint":"golden-target","fence_epoch":42,"operation_digests":["sha256:dd2c209f0d68640b74ea1be1cb6ce1efa7990751d443fcf950db37bb0c6e33a7"]}`
	goldenPlanDigest         = "sha256:3f773c7f1cf8dc70230e981a162a7aa2b441ec3814e671e73a2c1dea95752187"
	escapedOperationMaterial = `{"sequence":4,"operation":"test_owned_recovery","classification":"reversible","authorization_id":"auth\u003c\u003e\u0026\"\\雪\u2028","expected_prestate":{"customer_key_hash":"line\nbreak","eeprom_hash":"tab\tvalue","security_state":"café","power_state":"slash/ok"},"expected_poststate":{"customer_key_hash":"quote\"value","eeprom_hash":"backslash\\value","security_state":"owned","power_state":"signed_os"},"maximum_duration_nanoseconds":1}`
	escapedOperationDigest   = "sha256:9d485c7d3d4354208165b143dfaac57a56afb35550a6e1bdfd44600269b76942"
)

func TestOperationDigestGoldenVector(t *testing.T) {
	operation := goldenOperation()
	material, err := operation.CanonicalDigestMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if string(material) != goldenOperationMaterial {
		t.Fatalf("canonical operation material = %s", material)
	}
	digest, err := operation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != goldenOperationDigest {
		t.Fatalf("operation digest = %q, want %q", digest, goldenOperationDigest)
	}
}

func TestOperationDigestEscapingGoldenVector(t *testing.T) {
	operation := OperationSpec{
		Sequence: 4, Operation: OperationTestOwnedRecovery, Classification: ClassReversible,
		AuthorizationID: "auth<>&\"\\雪\u2028",
		ExpectedPrestate: DirectState{
			CustomerKeyHash: "line\nbreak", EEPROMHash: "tab\tvalue",
			SecurityState: "café", PowerState: "slash/ok",
		},
		ExpectedPoststate: DirectState{
			CustomerKeyHash: "quote\"value", EEPROMHash: "backslash\\value",
			SecurityState: "owned", PowerState: "signed_os",
		},
		MaximumDuration: time.Nanosecond,
	}
	material, err := operation.CanonicalDigestMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if string(material) != escapedOperationMaterial {
		t.Fatalf("canonical escaped operation material = %s", material)
	}
	actual, err := operation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if actual != escapedOperationDigest {
		t.Fatalf("escaped operation digest = %q, want %q", actual, escapedOperationDigest)
	}
}

func TestOperationDigestCoversEveryBodyField(t *testing.T) {
	operation := goldenOperation()
	baseline, err := operation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*OperationSpec)
	}{
		{"sequence", func(value *OperationSpec) { value.Sequence++ }},
		{"operation", func(value *OperationSpec) { value.Operation = OperationPostRecoveryReadback }},
		{"classification", func(value *OperationSpec) { value.Classification = ClassReversible }},
		{"authorization ID", func(value *OperationSpec) { value.AuthorizationID = "authorization-changed" }},
		{"prestate customer key", func(value *OperationSpec) { value.ExpectedPrestate.CustomerKeyHash = "changed" }},
		{"prestate EEPROM", func(value *OperationSpec) { value.ExpectedPrestate.EEPROMHash = "changed" }},
		{"prestate security", func(value *OperationSpec) { value.ExpectedPrestate.SecurityState = "changed" }},
		{"prestate power", func(value *OperationSpec) { value.ExpectedPrestate.PowerState = "changed" }},
		{"poststate customer key", func(value *OperationSpec) { value.ExpectedPoststate.CustomerKeyHash = "changed" }},
		{"poststate EEPROM", func(value *OperationSpec) { value.ExpectedPoststate.EEPROMHash = "changed" }},
		{"poststate security", func(value *OperationSpec) { value.ExpectedPoststate.SecurityState = "changed" }},
		{"poststate power", func(value *OperationSpec) { value.ExpectedPoststate.PowerState = "changed" }},
		{"maximum duration", func(value *OperationSpec) { value.MaximumDuration++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := operation
			test.mutate(&changed)
			digest, err := changed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatalf("digest did not change after mutating %s", test.name)
			}
		})
	}

	operation.OperationDigest = digest("f")
	actual, err := operation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if actual != baseline {
		t.Fatal("operation_digest was included in its own digest material")
	}
}

func TestPlanDigestGoldenVector(t *testing.T) {
	plan := goldenPlan()
	material, err := plan.CanonicalDigestMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if string(material) != goldenPlanMaterial {
		t.Fatalf("canonical plan material = %s", material)
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != goldenPlanDigest {
		t.Fatalf("plan digest = %q, want %q", digest, goldenPlanDigest)
	}
}

func TestPlanDigestCoversEveryBodyField(t *testing.T) {
	plan := goldenPlan()
	baseline, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"schema", func(value *Plan) { value.SchemaVersion = "changed-schema" }},
		{"station", func(value *Plan) { value.StationID = "changed-station" }},
		{"lane", func(value *Plan) { value.LaneID = "changed-lane" }},
		{"transaction", func(value *Plan) { value.TransactionID = "changed-transaction" }},
		{"target", func(value *Plan) { value.TargetFingerprint = "changed-target" }},
		{"fence", func(value *Plan) { value.FenceEpoch++ }},
		{"operation body", func(value *Plan) { value.Operations[0].AuthorizationID = "changed-authorization" }},
		{"operation appended", func(value *Plan) { value.Operations = append(value.Operations, goldenOperation()) }},
		{"operation removed", func(value *Plan) { value.Operations = value.Operations[:0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := clonePlan(plan)
			test.mutate(&changed)
			digest, err := changed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatalf("digest did not change after mutating %s", test.name)
			}
		})
	}

	for _, test := range []struct {
		name   string
		mutate func(*Plan)
	}{
		{"plan digest", func(value *Plan) { value.PlanDigest = digest("a") }},
		{"approval ID", func(value *Plan) { value.ApprovalID = "changed-approval" }},
		{"intent receipt", func(value *Plan) { value.IntentReceipt = "changed-intent" }},
		{"supplied operation digest", func(value *Plan) { value.Operations[0].OperationDigest = digest("b") }},
	} {
		t.Run("excluded "+test.name, func(t *testing.T) {
			changed := clonePlan(plan)
			test.mutate(&changed)
			actual, err := changed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if actual != baseline {
				t.Fatalf("%s changed the canonical plan digest", test.name)
			}
		})
	}
}

func TestPlanDigestBindsOperationOrder(t *testing.T) {
	first := goldenOperation()
	second := goldenOperation()
	second.Sequence++
	second.Operation = OperationPostRecoveryReadback
	plan := goldenPlan()
	plan.Operations = []OperationSpec{first, second}
	baseline, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Operations[0], plan.Operations[1] = plan.Operations[1], plan.Operations[0]
	reordered, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if reordered == baseline {
		t.Fatal("operation reordering did not change the plan digest")
	}
}

func TestWithDerivedDigestsReturnsValidatedCopy(t *testing.T) {
	original := testPlanBody()
	derived, err := original.WithDerivedDigests()
	if err != nil {
		t.Fatal(err)
	}
	if original.PlanDigest != "" || original.Operations[0].OperationDigest != "" {
		t.Fatal("digest derivation mutated the source plan")
	}
	if err := derived.Validate(testConfig()); err != nil {
		t.Fatalf("derived plan rejected: %v", err)
	}
	derived.Operations[0].AuthorizationID = "changed"
	if original.Operations[0].AuthorizationID == "changed" {
		t.Fatal("digest derivation did not deep-copy operations")
	}
}

func TestPlanValidateRejectsStaleAndForgedDigests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Plan)
	}{
		{
			name: "changed body with stale operation digest",
			mutate: func(_ *testing.T, plan *Plan) {
				plan.Operations[2].AuthorizationID = "changed-authorization"
			},
		},
		{
			name: "rederived operation with stale plan digest",
			mutate: func(t *testing.T, plan *Plan) {
				plan.Operations[2].AuthorizationID = "changed-authorization"
				digest, err := plan.Operations[2].Digest()
				if err != nil {
					t.Fatal(err)
				}
				plan.Operations[2].OperationDigest = digest
			},
		},
		{
			name: "forged operation digest",
			mutate: func(_ *testing.T, plan *Plan) {
				plan.Operations[2].OperationDigest = digest("8")
			},
		},
		{
			name: "forged plan digest",
			mutate: func(_ *testing.T, plan *Plan) {
				plan.PlanDigest = digest("9")
			},
		},
		{
			name: "coherent-looking arbitrary digests",
			mutate: func(_ *testing.T, plan *Plan) {
				plan.Operations[2].AuthorizationID = "changed-authorization"
				plan.Operations[2].OperationDigest = digest("8")
				plan.PlanDigest = digest("9")
			},
		},
		{
			name: "changed chained state",
			mutate: func(_ *testing.T, plan *Plan) {
				state := plan.Operations[2].ExpectedPoststate
				state.SecurityState = "changed-owned-state"
				plan.Operations[2].ExpectedPoststate = state
				plan.Operations[3].ExpectedPrestate = state
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testPlan()
			test.mutate(t, &plan)
			if err := plan.Validate(testConfig()); !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("error = %v, want digest mismatch", err)
			}
		})
	}
}

func TestLoadPlanRejectsDigestMismatchBeforeTargetObservation(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	plan.Operations[0].MaximumDuration += time.Second
	hardware := &fakeHardware{observation: Observation{
		EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
		TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
	}}
	guard, err := New(config, hardware, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("load error = %v, want digest mismatch", err)
	}
	if hardware.observeCount != 0 {
		t.Fatalf("digest-mismatched plan reached target observation %d times", hardware.observeCount)
	}
}

func TestLoadPlanRetainsTheValidatedPlanSnapshot(t *testing.T) {
	config := testConfig()
	plan := testPlan()
	validated := clonePlan(plan)
	hardware := &fakeHardware{
		observation: Observation{
			EligibleTargets: 1, RPIBootSysfsPath: config.RPIBootSysfsPath,
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		beforeObserve: func() {
			plan.Operations[0].AuthorizationID = "changed-after-validation"
		},
	}
	guard, err := New(config, hardware, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(context.Background(), plan); err != nil {
		t.Fatalf("load validated plan: %v", err)
	}
	if !samePlan(*guard.plan, validated) {
		t.Fatal("loaded plan changed after trusted-boundary validation")
	}
	if err := guard.plan.Validate(config); err != nil {
		t.Fatalf("retained plan is no longer valid: %v", err)
	}
}

func goldenOperation() OperationSpec {
	return OperationSpec{
		Sequence: 3, Operation: OperationOwnedReadback, Classification: ClassReadOnly,
		OperationDigest: digest("e"), AuthorizationID: "authorization-golden",
		ExpectedPrestate: DirectState{
			CustomerKeyHash: "customer-before", EEPROMHash: "eeprom-before",
			SecurityState: "owned", PowerState: "signed_os",
		},
		ExpectedPoststate: DirectState{
			CustomerKeyHash: "customer-after", EEPROMHash: "eeprom-after",
			SecurityState: "owned_verified", PowerState: "signed_os",
		},
		MaximumDuration: 90 * time.Second,
	}
}

func goldenPlan() Plan {
	return Plan{
		SchemaVersion: ContractSchemaVersion, StationID: "golden-station", LaneID: "golden-lane",
		TransactionID: "golden-transaction", PlanDigest: digest("f"), TargetFingerprint: "golden-target",
		FenceEpoch: 42, ApprovalID: "golden-approval", IntentReceipt: "golden-intent",
		Operations: []OperationSpec{goldenOperation()},
	}
}
