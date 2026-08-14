package rpi5

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning"
)

const qualificationMetadata = `{
  "USER_SERIAL_NUM": "A7EB274C",
  "MAC_ADDR": "2C:CF:67:70:76:F3",
  "CUSTOMER_KEY_HASH": "0000000000000000000000000000000000000000000000000000000000000000",
  "BOOT_ROM": "0000000A",
  "BOARD_ATTR": "00000000",
  "USER_BOARDREV": "B04170",
  "JTAG_LOCKED": "0",
  "MAC_WIFI_ADDR": "2C:CF:67:70:76:F4",
  "MAC_BT_ADDR": "2C:CF:67:70:76:F5",
  "FACTORY_UUID": "001000911006186073",
  "SIGNATURE_MODE": "0",
  "ADVANCED_BOOT": "00000000"
}`

func TestBuildQualificationRecordPassesAndRedactsInventory(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC))
	second := qualificationProbeResult(t, profile, time.Date(2026, 8, 13, 12, 5, 0, 0, time.UTC))

	context := validQualificationContext()
	record, err := BuildQualificationRecord(profile, first, second, context)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != QualificationStatusPassed || record.QuarantineRequired {
		t.Fatalf("outcome = %q, quarantine = %v", record.Status, record.QuarantineRequired)
	}
	if len(record.Probes) != 2 || len(record.Comparisons) != 15 || len(record.Findings) != 0 {
		t.Fatalf("record shape = %#v", record)
	}
	for _, comparison := range record.Comparisons {
		want := "match"
		if comparison.Field == "eeprom_hash" && first.Observation.EEPROMHash == "" {
			want = "not_observed"
		}
		if comparison.Status != want {
			t.Fatalf("comparison = %#v", comparison)
		}
	}

	firstJSON := qualificationJSON(t, record)
	secondJSON := qualificationJSON(t, record)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("qualification record encoding is not deterministic")
	}
	if !bytes.Contains(firstJSON, []byte(`"findings": []`)) {
		t.Fatalf("successful qualification must encode findings as an empty array:\n%s", firstJSON)
	}
	for _, privateValue := range []string{
		first.ObservedAt.Format(time.RFC3339),
		first.Observation.UserSerial,
		first.Observation.FactoryUUID,
		first.Observation.EthernetMAC,
		first.Observation.WiFiMAC,
		first.Observation.BluetoothMAC,
		first.Source.LaneID,
		first.Source.USBPath,
	} {
		if strings.Contains(string(firstJSON), privateValue) {
			t.Fatalf("public record leaked private value %q", privateValue)
		}
	}
	if strings.Contains(string(firstJSON), "observed_at") || strings.Contains(string(firstJSON), `"user_serial":`) || strings.Contains(string(firstJSON), `"factory_uuid":`) {
		t.Fatalf("public record contains a forbidden private field:\n%s", firstJSON)
	}
	if strings.Contains(string(firstJSON), context.NixSystemClosure) || strings.Contains(string(firstJSON), "kaiba-station") {
		t.Fatalf("public record leaked the private NixOS closure path:\n%s", firstJSON)
	}
	if !canonicalDigest(record.NixSystemClosureDigest) {
		t.Fatalf("NixOS closure digest = %q", record.NixSystemClosureDigest)
	}
}

func TestBuildQualificationRecordAcceptsAnUnobservedEEPROMHash(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
	first.Observation.EEPROMHash = ""
	second.Observation.EEPROMHash = ""
	first.Assessment = qualificationAssessment(profile, first.Observation)
	second.Assessment = qualificationAssessment(profile, second.Observation)

	record, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != QualificationStatusPassed || record.QuarantineRequired || len(record.Findings) != 0 {
		t.Fatalf("outcome = %#v", record)
	}
	comparison := qualificationComparison(t, record, "eeprom_hash")
	if comparison.Status != "not_observed" {
		t.Fatalf("EEPROM comparison = %#v", comparison)
	}
	for _, probe := range record.Probes {
		if probe.EEPROMHash != nil {
			t.Fatalf("redacted EEPROM hash = %#v, want nil", probe.EEPROMHash)
		}
	}
	if count := bytes.Count(qualificationJSON(t, record), []byte(`"eeprom_hash": null`)); count != 2 {
		t.Fatalf("null EEPROM hash count = %d, want 2", count)
	}
}

func TestBuildQualificationRecordDetectsChangedEEPROMHash(t *testing.T) {
	profile := qualificationProfile(t)
	firstHash := strings.Repeat("d", 64)
	tests := []struct {
		name       string
		firstHash  string
		secondHash string
	}{
		{name: "present then absent", firstHash: firstHash},
		{name: "absent then present", secondHash: firstHash},
		{name: "unequal present hashes", firstHash: firstHash, secondHash: strings.Repeat("a", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
			second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
			first.Observation.EEPROMHash = tt.firstHash
			second.Observation.EEPROMHash = tt.secondHash
			first.Assessment = qualificationAssessment(profile, first.Observation)
			second.Assessment = qualificationAssessment(profile, second.Observation)

			record, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
			if err != nil {
				t.Fatal(err)
			}
			if record.Status != QualificationStatusFailed || !record.QuarantineRequired {
				t.Fatalf("outcome = %#v", record)
			}
			if strings.Join(record.Findings, ",") != "eeprom-hash-changed" {
				t.Fatalf("findings = %#v", record.Findings)
			}
			if comparison := qualificationComparison(t, record, "eeprom_hash"); comparison.Status != "changed" {
				t.Fatalf("EEPROM comparison = %#v", comparison)
			}
		})
	}
}

func TestBuildQualificationRecordMatchesAnObservedEEPROMHash(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
	hash := strings.Repeat("d", 64)
	first.Observation.EEPROMHash = hash
	second.Observation.EEPROMHash = hash
	first.Assessment = qualificationAssessment(profile, first.Observation)
	second.Assessment = qualificationAssessment(profile, second.Observation)

	record, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
	if err != nil {
		t.Fatal(err)
	}
	if comparison := qualificationComparison(t, record, "eeprom_hash"); comparison.Status != "match" {
		t.Fatalf("EEPROM comparison = %#v", comparison)
	}
	for _, probe := range record.Probes {
		if probe.EEPROMHash == nil || *probe.EEPROMHash != hash {
			t.Fatalf("redacted EEPROM hash = %#v", probe.EEPROMHash)
		}
	}
}

func TestBuildQualificationRecordRequiresEveryComparedSignal(t *testing.T) {
	profile := qualificationProfile(t)
	baseFirst := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	baseSecond := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())

	tests := []struct {
		name   string
		mutate func(*Observation)
		match  string
	}{
		{"Wi-Fi MAC", func(observation *Observation) { observation.WiFiMAC = "" }, "Wi-Fi MAC is required"},
		{"Bluetooth MAC", func(observation *Observation) { observation.BluetoothMAC = "" }, "Bluetooth MAC is required"},
		{"signature mode", func(observation *Observation) { delete(observation.UpstreamFields, "SIGNATURE_MODE") }, "SIGNATURE_MODE is required"},
		{"advanced boot", func(observation *Observation) { delete(observation.UpstreamFields, "ADVANCED_BOOT") }, "ADVANCED_BOOT is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := cloneProbeResult(t, baseFirst)
			second := cloneProbeResult(t, baseSecond)
			tt.mutate(&first.Observation)
			_, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
			if err == nil || !strings.Contains(err.Error(), tt.match) {
				t.Fatalf("error = %v, want containing %q", err, tt.match)
			}
		})
	}
}

func TestBuildQualificationRecordRejectsAnUnsupportedProfileID(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
	profile.Metadata.ID = "alternate-raspberry-pi-5-policy"

	_, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
	if err == nil || !strings.Contains(err.Error(), QualificationProfileID) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildQualificationRecordReportsChangedTargetAndBootFailure(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
	second.Observation.UserSerial = "a7eb274d"
	second.Observation.TargetFingerprint = targetFingerprint(
		second.Observation.FactoryUUID,
		second.Observation.UserSerial,
		second.Observation.BoardRevision.Raw,
	)
	second.Assessment = qualificationAssessment(profile, second.Observation)
	context := validQualificationContext()
	context.NormalBootConfirmation = NormalBootFailed

	record, err := BuildQualificationRecord(profile, first, second, context)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != QualificationStatusFailed || !record.QuarantineRequired {
		t.Fatalf("outcome = %#v", record)
	}
	if strings.Join(record.Findings, ",") != "normal-boot-failed,target-fingerprint-changed,user-serial-changed" {
		t.Fatalf("findings = %#v", record.Findings)
	}
	encoded := string(qualificationJSON(t, record))
	if strings.Contains(encoded, second.Observation.UserSerial) {
		t.Fatal("failed record leaked the changed serial")
	}
}

func TestBuildQualificationRecordCanPreflightComparisonsBeforeNormalBoot(t *testing.T) {
	profile := qualificationProfile(t)
	first := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	second := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())
	context := validQualificationContext()
	context.NormalBootConfirmation = NormalBootPending

	record, err := BuildQualificationRecord(profile, first, second, context)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != QualificationStatusIncomplete || record.QuarantineRequired || len(record.Findings) != 0 {
		t.Fatalf("preflight outcome = %#v", record)
	}
}

func TestBuildQualificationRecordRejectsInvalidOrIncomparableInputs(t *testing.T) {
	profile := qualificationProfile(t)
	baseFirst := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	baseSecond := qualificationProbeResult(t, profile, time.Unix(20, 0).UTC())

	tests := []struct {
		name   string
		mutate func(*ProbeResult, *ProbeResult)
		match  string
	}{
		{
			name: "provenance changed",
			mutate: func(_, second *ProbeResult) {
				second.Source.BundleDigest = "sha256:" + strings.Repeat("b", 64)
			},
			match: "identical live acquisition provenance",
		},
		{
			name: "assessment tampered",
			mutate: func(_, second *ProbeResult) {
				second.Assessment.MutationEligible = true
			},
			match: "fresh profile evaluation",
		},
		{
			name: "fingerprint tampered",
			mutate: func(_, second *ProbeResult) {
				second.Observation.TargetFingerprint = "sha256:" + strings.Repeat("f", 64)
			},
			match: "fingerprint is internally inconsistent",
		},
		{
			name: "malformed EEPROM hash",
			mutate: func(_, second *ProbeResult) {
				second.Observation.EEPROMHash = strings.Repeat("g", 64)
			},
			match: "EEPROM hash must be canonical when present",
		},
		{
			name: "uppercase EEPROM hash",
			mutate: func(_, second *ProbeResult) {
				second.Observation.EEPROMHash = strings.Repeat("A", 64)
			},
			match: "EEPROM hash must be canonical when present",
		},
		{
			name: "mutation success",
			mutate: func(_, second *ProbeResult) {
				second.Observation.UpstreamFields["EEPROM_UPDATE"] = "success"
				second.Observation.MutationSuccess = []string{"EEPROM_UPDATE"}
			},
			match: "successful mutation operation",
		},
		{
			name: "reversed observation order",
			mutate: func(first, second *ProbeResult) {
				second.ObservedAt = first.ObservedAt
			},
			match: "later than the first",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := cloneProbeResult(t, baseFirst)
			second := cloneProbeResult(t, baseSecond)
			tt.mutate(&first, &second)
			_, err := BuildQualificationRecord(profile, first, second, validQualificationContext())
			if err == nil || !strings.Contains(err.Error(), tt.match) {
				t.Fatalf("error = %v, want containing %q", err, tt.match)
			}
		})
	}
}

func TestParseProbeResultIsStrictAndBounded(t *testing.T) {
	profile := qualificationProfile(t)
	result := qualificationProbeResult(t, profile, time.Unix(10, 0).UTC())
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProbeResult(raw); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{"duplicate key", []byte(strings.Replace(string(raw), `"schema_version":`, `"schema_version":"duplicate","schema_version":`, 1))},
		{"unknown key", []byte(strings.Replace(string(raw), `"observed_at":`, `"unexpected":true,"observed_at":`, 1))},
		{"trailing value", append(append([]byte(nil), raw...), []byte(` {}`)...)},
		{"oversized", bytes.Repeat([]byte(" "), MaxProbeResultSize+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseProbeResult(tt.raw); err == nil {
				t.Fatal("malformed result was accepted")
			}
		})
	}
}

func TestValidateQualificationContext(t *testing.T) {
	valid := validQualificationContext()
	if err := ValidateQualificationContext(valid); err != nil {
		t.Fatal(err)
	}
	tests := []QualificationContext{
		{SourceRevision: strings.Repeat("A", 40), StationSystem: valid.StationSystem, NixSystemClosure: valid.NixSystemClosure, PowerCycleConfirmation: valid.PowerCycleConfirmation, PreProbeBootConfirmation: valid.PreProbeBootConfirmation, NormalBootConfirmation: valid.NormalBootConfirmation},
		{SourceRevision: valid.SourceRevision, StationSystem: "riscv64-linux", NixSystemClosure: valid.NixSystemClosure, PowerCycleConfirmation: valid.PowerCycleConfirmation, PreProbeBootConfirmation: valid.PreProbeBootConfirmation, NormalBootConfirmation: valid.NormalBootConfirmation},
		{SourceRevision: valid.SourceRevision, StationSystem: valid.StationSystem, NixSystemClosure: "/run/current-system", PowerCycleConfirmation: valid.PowerCycleConfirmation, PreProbeBootConfirmation: valid.PreProbeBootConfirmation, NormalBootConfirmation: valid.NormalBootConfirmation},
		{SourceRevision: valid.SourceRevision, StationSystem: valid.StationSystem, NixSystemClosure: valid.NixSystemClosure, PowerCycleConfirmation: "", PreProbeBootConfirmation: valid.PreProbeBootConfirmation, NormalBootConfirmation: valid.NormalBootConfirmation},
		{SourceRevision: valid.SourceRevision, StationSystem: valid.StationSystem, NixSystemClosure: valid.NixSystemClosure, PowerCycleConfirmation: valid.PowerCycleConfirmation, PreProbeBootConfirmation: "", NormalBootConfirmation: valid.NormalBootConfirmation},
		{SourceRevision: valid.SourceRevision, StationSystem: valid.StationSystem, NixSystemClosure: valid.NixSystemClosure, PowerCycleConfirmation: valid.PowerCycleConfirmation, PreProbeBootConfirmation: valid.PreProbeBootConfirmation, NormalBootConfirmation: "unknown"},
	}
	for index, context := range tests {
		if err := ValidateQualificationContext(context); err == nil {
			t.Fatalf("invalid context %d was accepted", index)
		}
	}
}

func qualificationProfile(t *testing.T) provisioning.DeviceProfile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "profiles", "device-classes", "raspberry-pi-5-model-b-v1alpha1.json")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	profile, err := provisioning.LoadProfile(file)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func qualificationProbeResult(t *testing.T, profile provisioning.DeviceProfile, observedAt time.Time) ProbeResult {
	t.Helper()
	observation, err := ParseMetadata([]byte(qualificationMetadata))
	if err != nil {
		t.Fatal(err)
	}
	return ProbeResult{
		SchemaVersion: ProbeResultSchemaVersion,
		ObservedAt:    observedAt,
		Profile: ProfileReference{
			ID: profile.Metadata.ID, Status: profile.Metadata.Status,
			Digest: profile.Digest, PolicyDigest: profile.PolicyDigest,
		},
		Adapter: AdapterReference{ID: AdapterID, Version: AdapterVersion},
		Source: Provenance{
			Source:         "live-rpiboot",
			LaneID:         "lane-1",
			USBPath:        "1-2.3",
			ToolVersion:    "20260227",
			ToolDigest:     "sha256:" + strings.Repeat("1", 64),
			BundleDigest:   "sha256:" + strings.Repeat("2", 64),
			FirmwareDigest: "sha256:" + strings.Repeat("3", 64),
			ConfigDigest:   "sha256:" + strings.Repeat("4", 64),
		},
		Observation: observation,
		Assessment:  qualificationAssessment(profile, observation),
	}
}

func qualificationAssessment(profile provisioning.DeviceProfile, observation Observation) provisioning.Assessment {
	return provisioning.Evaluate(profile, provisioning.TargetObservation{
		AdapterID:      observation.AdapterID,
		AdapterVersion: observation.AdapterVersion,
		Facts:          observation.Facts(),
		UnknownFields:  append([]string(nil), observation.UnknownFields...),
	})
}

func validQualificationContext() QualificationContext {
	return QualificationContext{
		SourceRevision:           strings.Repeat("a", 40),
		StationSystem:            "x86_64-linux",
		NixSystemClosure:         "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-kaiba-station-1",
		PowerCycleConfirmation:   PowerCycleOperatorConfirmed,
		PreProbeBootConfirmation: PreProbeBootOperatorConfirmed,
		NormalBootConfirmation:   NormalBootUnchanged,
	}
}

func qualificationJSON(t *testing.T, record QualificationRecord) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func qualificationComparison(t *testing.T, record QualificationRecord, field string) QualificationComparison {
	t.Helper()
	for _, comparison := range record.Comparisons {
		if comparison.Field == field {
			return comparison
		}
	}
	t.Fatalf("comparison %q was not emitted", field)
	return QualificationComparison{}
}

func cloneProbeResult(t *testing.T, input ProbeResult) ProbeResult {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseProbeResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
