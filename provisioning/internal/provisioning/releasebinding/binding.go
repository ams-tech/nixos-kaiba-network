// Package releasebinding defines the immutable release inputs that an
// approved provisioning plan must bind before it can reach a physical lane.
package releasebinding

import (
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// Binding identifies the exact signed release, lane-guard implementation,
// compiled artifacts, and target state approved for one provisioning plan.
// It is deliberately comparable so trusted boundaries can require exact
// equality without omitting an individual field.
type Binding struct {
	SignedReleaseManifestDigest string `json:"signed_release_manifest_digest"`
	LaneGuardPackageDigest      string `json:"lane_guard_package_digest"`
	CompiledArtifactSetDigest   string `json:"compiled_artifact_set_digest"`
	ExpectedCustomerKeyHash     string `json:"expected_customer_key_hash"`
	ExpectedEEPROMDigest        string `json:"expected_eeprom_digest"`
	ExpectedBootImageDigest     string `json:"expected_boot_image_digest"`
}

// Validate requires every release binding to use the canonical textual
// sha256:<64 lowercase hexadecimal characters> representation.
func (binding Binding) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"signed_release_manifest_digest", binding.SignedReleaseManifestDigest},
		{"lane_guard_package_digest", binding.LaneGuardPackageDigest},
		{"compiled_artifact_set_digest", binding.CompiledArtifactSetDigest},
		{"expected_customer_key_hash", binding.ExpectedCustomerKeyHash},
		{"expected_eeprom_digest", binding.ExpectedEEPROMDigest},
		{"expected_boot_image_digest", binding.ExpectedBootImageDigest},
	} {
		if _, err := bundle.ParseDigest(field.value); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
	}
	return nil
}
