package provisioning

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const validProfileJSON = `{
  "apiVersion": "provisioning.kaiba.network/v1alpha1",
  "kind": "DeviceClassProfile",
  "metadata": {"id": "rpi5-model-b", "status": "experimental"},
  "spec": {
    "adapter": {"id": "rpi5", "version": "v1alpha1"},
    "requiredFacts": ["board.revision.model", "security.customer_key_unprogrammed", "firmware.eeprom_hash"],
    "classConditions": [
      {"id": "model", "fact": "board.revision.model", "operator": "equals", "value": "23"}
    ],
    "baselineConditions": [
      {"id": "customer-key", "fact": "security.customer_key_unprogrammed", "operator": "equals", "value": "true"},
      {"id": "eeprom", "fact": "firmware.eeprom_hash", "operator": "present"}
    ],
    "deferredChecks": [
      {"id": "storage-contents", "description": "Storage inspection requires a later phase."}
    ]
  }
}`

func TestParseProfile(t *testing.T) {
	profile, err := ParseProfile([]byte(validProfileJSON))
	if err != nil {
		t.Fatalf("ParseProfile() error = %v", err)
	}

	wantDigest := sha256.Sum256([]byte(validProfileJSON))
	if got, want := profile.Digest, "sha256:"+hex.EncodeToString(wantDigest[:]); got != want {
		t.Fatalf("Digest = %q, want %q", got, want)
	}
	if !strings.HasPrefix(profile.PolicyDigest, "sha256:") || len(profile.PolicyDigest) != len("sha256:")+64 {
		t.Fatalf("PolicyDigest = %q", profile.PolicyDigest)
	}
	if got, want := profile.Metadata.ID, "rpi5-model-b"; got != want {
		t.Fatalf("Metadata.ID = %q, want %q", got, want)
	}
	if got, want := profile.Spec.BaselineConditions[1].Operator, OperatorPresent; got != want {
		t.Fatalf("operator = %q, want %q", got, want)
	}
}

func TestPolicyDigestIgnoresFormattingAndStatusButNotPolicy(t *testing.T) {
	experimental, err := ParseProfile([]byte(validProfileJSON))
	if err != nil {
		t.Fatal(err)
	}
	stableJSON := strings.Replace(validProfileJSON, `"status": "experimental"`, `"status": "stable"`, 1)
	stable, err := ParseProfile([]byte(" \n" + stableJSON + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if experimental.Digest == stable.Digest {
		t.Fatal("exact profile digest did not change")
	}
	if experimental.PolicyDigest != stable.PolicyDigest {
		t.Fatalf("status-only promotion changed policy digest: %q != %q", experimental.PolicyDigest, stable.PolicyDigest)
	}
	changedJSON := strings.Replace(validProfileJSON, `"value": "23"`, `"value": "24"`, 1)
	changed, err := ParseProfile([]byte(changedJSON))
	if err != nil {
		t.Fatal(err)
	}
	if experimental.PolicyDigest == changed.PolicyDigest {
		t.Fatal("substantive policy change did not change policy digest")
	}
}

func TestParseProfileRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr string
	}{
		{
			name:    "duplicate root key",
			profile: strings.Replace(validProfileJSON, `"kind": "DeviceClassProfile",`, `"kind": "DeviceClassProfile", "kind": "DeviceClassProfile",`, 1),
			wantErr: "duplicate key",
		},
		{
			name:    "duplicate nested key",
			profile: strings.Replace(validProfileJSON, `"id": "rpi5"`, `"id": "rpi5", "id": "other"`, 1),
			wantErr: "duplicate key",
		},
		{
			name:    "unknown field",
			profile: strings.Replace(validProfileJSON, `"status": "experimental"`, `"status": "experimental", "owner": "lab"`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "wrong case is unknown",
			profile: strings.Replace(validProfileJSON, `"apiVersion"`, `"ApiVersion"`, 1),
			wantErr: "missing field \"apiVersion\"",
		},
		{
			name:    "trailing value",
			profile: validProfileJSON + `{}`,
			wantErr: "trailing JSON value",
		},
		{
			name:    "unsupported operator",
			profile: strings.Replace(validProfileJSON, `"operator": "equals"`, `"operator": "contains"`, 1),
			wantErr: "operator \"contains\" is unsupported",
		},
		{
			name:    "equals lacks value",
			profile: strings.Replace(validProfileJSON, `, "value": "23"`, ``, 1),
			wantErr: "equals condition requires a non-null value",
		},
		{
			name:    "equals null value",
			profile: strings.Replace(validProfileJSON, `"value": "23"`, `"value": null`, 1),
			wantErr: "equals condition requires a non-null value",
		},
		{
			name:    "present has value",
			profile: strings.Replace(validProfileJSON, `"operator": "present"`, `"operator": "present", "value": "anything"`, 1),
			wantErr: "present condition must omit value",
		},
		{
			name:    "condition fact not declared",
			profile: strings.Replace(validProfileJSON, `"fact": "board.revision.model"`, `"fact": "board.revision.processor"`, 1),
			wantErr: "absent from requiredFacts",
		},
		{
			name:    "duplicate semantic condition id",
			profile: strings.Replace(validProfileJSON, `"id": "customer-key"`, `"id": "model"`, 1),
			wantErr: "condition id \"model\" is duplicated",
		},
		{
			name:    "no deferred checks",
			profile: strings.Replace(validProfileJSON, `{"id": "storage-contents", "description": "Storage inspection requires a later phase."}`, ``, 1),
			wantErr: "deferredChecks must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProfile([]byte(tt.profile))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseProfile() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadProfileRejectsOversize(t *testing.T) {
	_, err := LoadProfile(strings.NewReader(strings.Repeat(" ", MaxProfileSize+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadProfile() error = %v, want size error", err)
	}
}
