package releasebinding

import (
	"strings"
	"testing"
)

func TestBindingValidate(t *testing.T) {
	binding := validBinding()
	if err := binding.Validate(); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}

	// Binding must remain directly comparable so callers cannot accidentally
	// omit a field while repeating an approved release across a boundary.
	if binding != validBinding() {
		t.Fatal("equal release bindings did not compare equal")
	}
}

func TestBindingValidateChecksEveryField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"signed release manifest", func(value *Binding) { value.SignedReleaseManifestDigest = "" }},
		{"lane guard package", func(value *Binding) { value.LaneGuardPackageDigest = "" }},
		{"compiled artifact set", func(value *Binding) { value.CompiledArtifactSetDigest = "" }},
		{"customer key", func(value *Binding) { value.ExpectedCustomerKeyHash = "" }},
		{"EEPROM", func(value *Binding) { value.ExpectedEEPROMDigest = "" }},
		{"boot image", func(value *Binding) { value.ExpectedBootImageDigest = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := validBinding()
			test.mutate(&binding)
			if err := binding.Validate(); err == nil {
				t.Fatal("invalid release binding was accepted")
			}
		})
	}
}

func TestBindingValidateRejectsNonCanonicalDigests(t *testing.T) {
	for _, value := range []string{
		strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha512:" + strings.Repeat("a", 64),
	} {
		t.Run(value[:min(len(value), 12)], func(t *testing.T) {
			binding := validBinding()
			binding.SignedReleaseManifestDigest = value
			if err := binding.Validate(); err == nil {
				t.Fatalf("non-canonical digest %q was accepted", value)
			}
		})
	}
}

func validBinding() Binding {
	return Binding{
		SignedReleaseManifestDigest: digest("1"),
		LaneGuardPackageDigest:      digest("2"),
		CompiledArtifactSetDigest:   digest("3"),
		ExpectedCustomerKeyHash:     digest("4"),
		ExpectedEEPROMDigest:        digest("5"),
		ExpectedBootImageDigest:     digest("6"),
	}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
