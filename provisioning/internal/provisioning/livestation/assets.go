package livestation

import "embed"

const RuntimeConfigSchemaVersion = "provisioning.kaiba.network/station-live-runtime/v1alpha1"

//go:embed web/index.html web/app.js web/styles.css
var liveAssets embed.FS

type runtimeConfig struct {
	SchemaVersion      string `json:"schema_version"`
	StateSchemaVersion string `json:"state_schema_version"`
	ExpectedOrigin     string `json:"expected_origin"`
	StateEndpoint      string `json:"state_endpoint"`
	ActionEndpoint     string `json:"action_endpoint"`
	Simulation         bool   `json:"simulation"`
	SecretFree         bool   `json:"secret_free"`
	RollbackStatus     string `json:"rollback_status"`
	EnrollmentCapable  bool   `json:"enrollment_capable"`
}

func embeddedAsset(name string) ([]byte, error) {
	return liveAssets.ReadFile("web/" + name)
}

func liveRuntimeConfig(expectedOrigin string) runtimeConfig {
	return runtimeConfig{
		SchemaVersion:      RuntimeConfigSchemaVersion,
		StateSchemaVersion: StateSchemaVersion,
		ExpectedOrigin:     expectedOrigin,
		StateEndpoint:      "/api/v1/state",
		ActionEndpoint:     "/api/v1/actions",
		Simulation:         false,
		SecretFree:         true,
		RollbackStatus:     RollbackStatus,
		EnrollmentCapable:  false,
	}
}
