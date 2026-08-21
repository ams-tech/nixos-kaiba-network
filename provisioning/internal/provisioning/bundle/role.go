package bundle

import (
	"fmt"
	"sort"
)

// ArtifactRole identifies the semantic use of immutable artifact bytes. It is
// deliberately a closed vocabulary so a signing request cannot introduce a
// new key use by supplying an arbitrary string.
type ArtifactRole string

const (
	RoleDeviceProfile     ArtifactRole = "device_profile"
	RolePlatformAdapter   ArtifactRole = "platform_adapter"
	RoleBootPublicKey     ArtifactRole = "boot_public_key"
	RoleEEPROMConfig      ArtifactRole = "rpi5.eeprom_config"
	RoleEEPROMBootsys     ArtifactRole = "rpi5.eeprom_bootsys"
	RoleSignedEEPROMImage ArtifactRole = "rpi5.signed_eeprom_image"
	RoleBootImage         ArtifactRole = "rpi5.boot_image"
	RoleBootSignature     ArtifactRole = "rpi5.boot_signature"
	// RoleRootIntegrity is persistent-root integrity metadata. The distinct
	// RoleRootIntegrityTestBundle contains the RPIBOOT acceptance-test payload.
	RoleRootIntegrity           ArtifactRole = "root_integrity"
	RoleFreshCommitBundle       ArtifactRole = "rpi5.fresh_commit_bundle"
	RoleFreshReadbackBundle     ArtifactRole = "rpi5.fresh_readback_bundle"
	RoleNegativeBootBundle      ArtifactRole = "rpi5.negative_boot_bundle"
	RoleOwnedReadbackBundle     ArtifactRole = "rpi5.owned_readback_bundle"
	RoleOwnedRecoveryBootcode   ArtifactRole = "rpi5.owned_recovery_bootcode"
	RoleOwnedRecoveryBundle     ArtifactRole = "rpi5.owned_recovery_bundle"
	RoleRootDataImage           ArtifactRole = "rpi5.root_data_image"
	RoleRootHashTreeImage       ArtifactRole = "rpi5.root_hash_tree_image"
	RoleRootIntegrityTestBundle ArtifactRole = "rpi5.root_integrity_test_bundle"
)

var artifactRoles = map[ArtifactRole]struct{}{
	RoleDeviceProfile: {}, RolePlatformAdapter: {}, RoleBootPublicKey: {},
	RoleEEPROMConfig: {}, RoleEEPROMBootsys: {}, RoleSignedEEPROMImage: {},
	RoleBootImage: {}, RoleBootSignature: {}, RoleRootIntegrity: {},
	RoleFreshCommitBundle: {}, RoleFreshReadbackBundle: {}, RoleNegativeBootBundle: {},
	RoleOwnedReadbackBundle: {}, RoleOwnedRecoveryBootcode: {}, RoleOwnedRecoveryBundle: {},
	RoleRootDataImage: {}, RoleRootHashTreeImage: {}, RoleRootIntegrityTestBundle: {},
}

var signableRoles = map[ArtifactRole]struct{}{
	RoleEEPROMConfig:          {},
	RoleEEPROMBootsys:         {},
	RoleBootImage:             {},
	RoleOwnedRecoveryBootcode: {},
}

// Validate reports whether role belongs to the versioned artifact vocabulary.
func (r ArtifactRole) Validate() error {
	if _, ok := artifactRoles[r]; !ok {
		return fmt.Errorf("artifact role %q is not supported", r)
	}
	return nil
}

// Signable reports whether the development boot key may sign bytes in this
// role. Output bundles, public keys, profiles, and adapters are never direct
// signing inputs.
func (r ArtifactRole) Signable() bool {
	_, ok := signableRoles[r]
	return ok
}

// Roles returns the complete role vocabulary in canonical order.
func Roles() []ArtifactRole {
	roles := make([]ArtifactRole, 0, len(artifactRoles))
	for role := range artifactRoles {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}
