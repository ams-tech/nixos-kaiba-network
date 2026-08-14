package rpi5

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning"
)

const (
	ProbeResultSchemaVersion         = "provisioning.kaiba.network/target-observation/v1alpha1"
	QualificationRecordSchemaVersion = "provisioning.kaiba.network/rpi5-hardware-qualification/v1alpha1"
	QualificationProfileID           = "raspberry-pi-5-model-b-v1alpha1"
	MaxProbeResultSize               = 256 * 1024

	PowerCycleOperatorConfirmed   = "operator_confirmed_complete"
	PreProbeBootOperatorConfirmed = "operator_confirmed_normal"
	NormalBootPending             = "not_yet_observed"
	NormalBootUnchanged           = "operator_confirmed_unchanged"
	NormalBootFailed              = "operator_confirmed_failed"

	QualificationStatusIncomplete = "incomplete"
	QualificationStatusPassed     = "passed"
	QualificationStatusFailed     = "failed"
)

var (
	sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	nixStorePathPattern   = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+$`)
)

// ProfileReference binds a probe result to the exact profile bytes used for
// evaluation and to status-independent policy semantics. Both digests are
// calculated by LoadProfile.
type ProfileReference struct {
	ID           string                     `json:"id"`
	Status       provisioning.ProfileStatus `json:"status"`
	Digest       string                     `json:"digest"`
	PolicyDigest string                     `json:"policy_digest"`
}

// AdapterReference identifies the normalization contract used by a probe.
type AdapterReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ProbeResult is the complete private result produced by kaiba-provision
// probe. Qualification consumes this type but never copies it into public
// evidence because it contains inventory identifiers and a timestamp.
type ProbeResult struct {
	SchemaVersion string                  `json:"schema_version"`
	ObservedAt    time.Time               `json:"observed_at"`
	Profile       ProfileReference        `json:"profile"`
	Adapter       AdapterReference        `json:"adapter"`
	Source        Provenance              `json:"source"`
	Observation   Observation             `json:"observation"`
	Assessment    provisioning.Assessment `json:"assessment"`
}

// QualificationContext contains operator-supplied facts which cannot be
// established from two metadata observations alone.
type QualificationContext struct {
	SourceRevision           string
	StationSystem            string
	NixSystemClosure         string
	PowerCycleConfirmation   string
	PreProbeBootConfirmation string
	NormalBootConfirmation   string
}

// QualificationRecord is safe to publish only because it is assembled from a
// fixed whitelist. It deliberately has no raw observation maps, timestamps,
// serials, UUIDs, MAC values, station identity, lane label, or USB path.
type QualificationRecord struct {
	SchemaVersion            string                    `json:"schema_version"`
	SourceRevision           string                    `json:"source_revision"`
	StationSystem            string                    `json:"station_system"`
	NixSystemClosureDigest   string                    `json:"nix_system_closure_digest"`
	Profile                  ProfileReference          `json:"profile"`
	Adapter                  AdapterReference          `json:"adapter"`
	Source                   QualificationSource       `json:"source"`
	Probes                   []RedactedProbe           `json:"probes"`
	Comparisons              []QualificationComparison `json:"comparisons"`
	PowerCycleConfirmation   string                    `json:"power_cycle_confirmation"`
	PreProbeBootConfirmation string                    `json:"pre_probe_normal_boot_confirmation"`
	NormalBootConfirmation   string                    `json:"normal_boot_confirmation"`
	Status                   string                    `json:"status"`
	QuarantineRequired       bool                      `json:"quarantine_required"`
	Findings                 []string                  `json:"findings"`
	MutationEligible         bool                      `json:"mutation_eligible"`
	FullUnprovisionedState   string                    `json:"full_unprovisioned_state"`
	Disclaimer               string                    `json:"disclaimer"`
}

type QualificationSource struct {
	Kind              string `json:"kind"`
	ToolVersion       string `json:"tool_version"`
	ToolDigest        string `json:"tool_digest"`
	BundleDigest      string `json:"bundle_digest"`
	FirmwareDigest    string `json:"firmware_digest"`
	ConfigDigest      string `json:"config_digest"`
	LaneContinuity    string `json:"lane_continuity"`
	USBPathContinuity string `json:"usb_path_continuity"`
}

type RedactedProbe struct {
	Sequence            int                     `json:"sequence"`
	EvidenceDigest      string                  `json:"evidence_digest"`
	TargetFingerprint   string                  `json:"target_fingerprint"`
	BoardRevision       Revision                `json:"board_revision"`
	BoardAttributes     string                  `json:"board_attributes"`
	BootROM             string                  `json:"boot_rom"`
	EEPROMHash          string                  `json:"eeprom_hash"`
	CustomerKeyHash     string                  `json:"customer_key_hash"`
	CustomerKeyState    string                  `json:"customer_key_state"`
	VideoCoreJTAGLocked bool                    `json:"videocore_jtag_locked"`
	Assessment          QualificationAssessment `json:"assessment"`
	MutationAudit       MutationAudit           `json:"mutation_audit"`
}

type QualificationAssessment struct {
	DeviceClassStatus                  provisioning.Status `json:"device_class_status"`
	ObservableBaselineStatus           provisioning.Status `json:"observable_baseline_status"`
	EligibleForReversibleQualification bool                `json:"eligible_for_reversible_qualification"`
	MutationEligible                   bool                `json:"mutation_eligible"`
	FullUnprovisionedState             string              `json:"full_unprovisioned_state"`
}

type MutationAudit struct {
	SuccessReported bool `json:"success_reported"`
}

type QualificationComparison struct {
	Field  string `json:"field"`
	Status string `json:"status"`
}

// LoadProbeResult reads one regular, non-symlink private result and applies a
// strict JSON contract before it is considered for qualification.
func LoadProbeResult(path string) (ProbeResult, error) {
	raw, err := readRegularFile(path, MaxProbeResultSize, false)
	if err != nil {
		return ProbeResult{}, err
	}
	return ParseProbeResult(raw)
}

// ParseProbeResult rejects duplicate and unknown fields, trailing JSON, and
// malformed timestamps. Deeper semantic validation is profile-dependent and
// is performed by BuildQualificationRecord.
func ParseProbeResult(raw []byte) (ProbeResult, error) {
	if len(raw) == 0 {
		return ProbeResult{}, errors.New("probe result is empty")
	}
	if len(raw) > MaxProbeResultSize {
		return ProbeResult{}, fmt.Errorf("probe result exceeds %d bytes", MaxProbeResultSize)
	}
	if err := validateNoDuplicateJSON(raw); err != nil {
		return ProbeResult{}, fmt.Errorf("decode probe result: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var result ProbeResult
	if err := dec.Decode(&result); err != nil {
		return ProbeResult{}, fmt.Errorf("decode probe result: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return ProbeResult{}, fmt.Errorf("decode probe result: %w", err)
	}
	return result, nil
}

// ValidateQualificationContext validates the explicit ceremony facts before
// any private probe result is opened.
func ValidateQualificationContext(context QualificationContext) error {
	if !sourceRevisionPattern.MatchString(context.SourceRevision) {
		return errors.New("source revision must be a lowercase 40- or 64-hex Git revision")
	}
	if context.StationSystem != "x86_64-linux" && context.StationSystem != "aarch64-linux" {
		return errors.New("station system must be x86_64-linux or aarch64-linux")
	}
	if !nixStorePathPattern.MatchString(context.NixSystemClosure) {
		return errors.New("Nix system closure must be one canonical /nix/store path")
	}
	if context.PowerCycleConfirmation != PowerCycleOperatorConfirmed {
		return fmt.Errorf("power-cycle confirmation must be %q", PowerCycleOperatorConfirmed)
	}
	if context.PreProbeBootConfirmation != PreProbeBootOperatorConfirmed {
		return fmt.Errorf("pre-probe normal-boot confirmation must be %q", PreProbeBootOperatorConfirmed)
	}
	if context.NormalBootConfirmation != NormalBootPending && context.NormalBootConfirmation != NormalBootUnchanged && context.NormalBootConfirmation != NormalBootFailed {
		return fmt.Errorf("normal-boot confirmation must be %q, %q, or %q", NormalBootPending, NormalBootUnchanged, NormalBootFailed)
	}
	return nil
}

// BuildQualificationRecord validates two complete live observations, checks
// that they share one immutable acquisition context, compares all stable
// target fields, and emits a deterministic redacted aggregate.
func BuildQualificationRecord(
	profile provisioning.DeviceProfile,
	first ProbeResult,
	second ProbeResult,
	context QualificationContext,
) (QualificationRecord, error) {
	if err := ValidateQualificationContext(context); err != nil {
		return QualificationRecord{}, err
	}
	if profile.Metadata.ID != QualificationProfileID {
		return QualificationRecord{}, fmt.Errorf("hardware qualification only supports profile %q", QualificationProfileID)
	}
	if profile.Metadata.Status != provisioning.ProfileStatusExperimental && profile.Metadata.Status != provisioning.ProfileStatusStable {
		return QualificationRecord{}, errors.New("hardware qualification requires an experimental or stable profile")
	}
	if profile.Spec.Adapter.ID != AdapterID || profile.Spec.Adapter.Version != AdapterVersion {
		return QualificationRecord{}, errors.New("hardware qualification profile requires the Raspberry Pi 5 metadata adapter")
	}
	if err := validateQualificationCandidate(profile, first, 1); err != nil {
		return QualificationRecord{}, fmt.Errorf("first probe result: %w", err)
	}
	if err := validateQualificationCandidate(profile, second, 2); err != nil {
		return QualificationRecord{}, fmt.Errorf("second probe result: %w", err)
	}
	if !first.ObservedAt.Before(second.ObservedAt) {
		return QualificationRecord{}, errors.New("second probe observation must be later than the first")
	}
	if err := validateSharedProbeContext(first, second); err != nil {
		return QualificationRecord{}, err
	}

	comparisons, findings := compareQualificationObservations(first.Observation, second.Observation)
	if context.NormalBootConfirmation == NormalBootFailed {
		findings = append(findings, "normal-boot-failed")
	}
	sort.Strings(findings)
	status := QualificationStatusIncomplete
	if len(findings) != 0 {
		status = QualificationStatusFailed
	} else if context.NormalBootConfirmation == NormalBootUnchanged {
		status = QualificationStatusPassed
	}

	record := QualificationRecord{
		SchemaVersion:          QualificationRecordSchemaVersion,
		SourceRevision:         context.SourceRevision,
		StationSystem:          context.StationSystem,
		NixSystemClosureDigest: digestBytes([]byte("kaiba.nix-system-closure.v1\x00" + context.NixSystemClosure)),
		Profile:                first.Profile,
		Adapter:                first.Adapter,
		Source: QualificationSource{
			Kind:              first.Source.Source,
			ToolVersion:       first.Source.ToolVersion,
			ToolDigest:        first.Source.ToolDigest,
			BundleDigest:      first.Source.BundleDigest,
			FirmwareDigest:    first.Source.FirmwareDigest,
			ConfigDigest:      first.Source.ConfigDigest,
			LaneContinuity:    "match",
			USBPathContinuity: "match",
		},
		Probes: []RedactedProbe{
			redactedProbe(1, first),
			redactedProbe(2, second),
		},
		Comparisons:              comparisons,
		PowerCycleConfirmation:   context.PowerCycleConfirmation,
		PreProbeBootConfirmation: context.PreProbeBootConfirmation,
		NormalBootConfirmation:   context.NormalBootConfirmation,
		Status:                   status,
		QuarantineRequired:       status == QualificationStatusFailed,
		Findings:                 findings,
		MutationEligible:         false,
		FullUnprovisionedState:   provisioning.FullUnprovisionedStateNotEstablished,
		Disclaimer:               provisioning.AssessmentDisclaimer,
	}
	return record, nil
}

func validateQualificationCandidate(profile provisioning.DeviceProfile, result ProbeResult, sequence int) error {
	if result.SchemaVersion != ProbeResultSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", result.SchemaVersion)
	}
	if result.ObservedAt.IsZero() || result.ObservedAt.Location() != time.UTC {
		return errors.New("observed_at is required and must be UTC")
	}
	wantProfile := ProfileReference{
		ID: profile.Metadata.ID, Status: profile.Metadata.Status,
		Digest: profile.Digest, PolicyDigest: profile.PolicyDigest,
	}
	if result.Profile != wantProfile {
		return errors.New("profile reference does not match the supplied profile")
	}
	wantAdapter := AdapterReference{ID: AdapterID, Version: AdapterVersion}
	if result.Adapter != wantAdapter {
		return errors.New("adapter reference is not the Raspberry Pi 5 metadata adapter")
	}
	if result.Observation.AdapterID != AdapterID || result.Observation.AdapterVersion != AdapterVersion {
		return errors.New("observation adapter does not match the result adapter")
	}
	if err := validateLiveProvenance(result.Source); err != nil {
		return err
	}
	if err := validateQualificationObservation(result.Observation); err != nil {
		return err
	}
	normalized := provisioning.TargetObservation{
		AdapterID:      result.Observation.AdapterID,
		AdapterVersion: result.Observation.AdapterVersion,
		Facts:          result.Observation.Facts(),
		UnknownFields:  append([]string(nil), result.Observation.UnknownFields...),
	}
	wantAssessment := provisioning.Evaluate(profile, normalized)
	if !reflect.DeepEqual(result.Assessment, wantAssessment) {
		return errors.New("recorded assessment does not match a fresh profile evaluation")
	}
	if result.Assessment.Class.Status != provisioning.StatusPass {
		return fmt.Errorf("probe %d device class did not pass", sequence)
	}
	if result.Assessment.ObservableBaseline.Status != provisioning.StatusPass || !result.Assessment.EligibleForReversibleQualification {
		return fmt.Errorf("probe %d observable baseline did not pass", sequence)
	}
	if result.Assessment.MutationEligible || result.Assessment.FullUnprovisionedState != provisioning.FullUnprovisionedStateNotEstablished {
		return errors.New("probe assessment violates the non-mutation safety boundary")
	}
	return nil
}

func validateLiveProvenance(source Provenance) error {
	if source.Source != "live-rpiboot" {
		return errors.New("qualification requires live-rpiboot provenance")
	}
	if !laneIDPattern.MatchString(source.LaneID) || !usbPathPattern.MatchString(source.USBPath) {
		return errors.New("live provenance has an invalid lane or USB path")
	}
	if source.ToolVersion == "" || len(source.ToolVersion) > 256 || strings.ContainsAny(source.ToolVersion, "\r\n\x00") {
		return errors.New("live provenance has an invalid tool version")
	}
	for _, item := range []struct{ name, value string }{
		{"tool", source.ToolDigest},
		{"bundle", source.BundleDigest},
		{"firmware", source.FirmwareDigest},
		{"config", source.ConfigDigest},
	} {
		if !canonicalDigest(item.value) {
			return fmt.Errorf("live provenance %s digest is not canonical SHA-256", item.name)
		}
	}
	return nil
}

func validateQualificationObservation(observation Observation) error {
	if !canonicalDigest(observation.EvidenceDigest) || !canonicalDigest(observation.TargetFingerprint) {
		return errors.New("observation digests are not canonical SHA-256")
	}
	if !hex8Pattern.MatchString(observation.UserSerial) || observation.UserSerial != strings.ToLower(observation.UserSerial) || isZeroHex(observation.UserSerial) {
		return errors.New("observation user serial is not canonical")
	}
	if !factoryUUIDPattern.MatchString(observation.FactoryUUID) || observation.FactoryUUID != strings.ToLower(observation.FactoryUUID) || isZeroHex(observation.FactoryUUID) {
		return errors.New("observation factory UUID is not canonical")
	}
	revision, err := DecodeRevision(observation.BoardRevision.Raw)
	if err != nil || !reflect.DeepEqual(revision, observation.BoardRevision) {
		return errors.New("observation board revision is internally inconsistent")
	}
	if !revision.NewStyle || revision.Processor != 4 || revision.Model != 23 {
		return errors.New("observation is not a Raspberry Pi 5 Model B revision")
	}
	for _, item := range []struct{ name, value string }{
		{"board attributes", observation.BoardAttributes},
		{"boot ROM", observation.BootROM},
	} {
		if !hex8Pattern.MatchString(item.value) || item.value != strings.ToLower(item.value) {
			return fmt.Errorf("observation %s is not canonical", item.name)
		}
	}
	if !hex64Pattern.MatchString(observation.EEPROMHash) || observation.EEPROMHash != strings.ToLower(observation.EEPROMHash) {
		return errors.New("observation EEPROM hash is required and must be canonical")
	}
	if !hex64Pattern.MatchString(observation.CustomerKeyHash) || observation.CustomerKeyHash != strings.ToLower(observation.CustomerKeyHash) {
		return errors.New("observation customer-key hash is not canonical")
	}
	wantKeyState := "set"
	if isZeroHex(observation.CustomerKeyHash) {
		wantKeyState = "unset"
	}
	if observation.CustomerKeyState != wantKeyState || wantKeyState != "unset" {
		return errors.New("observation customer secure-boot key is not unset")
	}
	if observation.VideoCoreJTAGLocked {
		return errors.New("observation VideoCore JTAG is locked")
	}

	macs := []struct {
		name  string
		value string
	}{
		{"Ethernet MAC", observation.EthernetMAC},
		{"Wi-Fi MAC", observation.WiFiMAC},
		{"Bluetooth MAC", observation.BluetoothMAC},
	}
	seenMACs := map[string]string{}
	for _, item := range macs {
		if item.value == "" {
			return fmt.Errorf("observation %s is required for qualification", item.name)
		}
		normalized, err := normalizeMAC(item.name, item.value)
		if err != nil || normalized != item.value {
			return fmt.Errorf("observation %s is not canonical", item.name)
		}
		if previous, ok := seenMACs[item.value]; ok {
			return fmt.Errorf("observation %s duplicates %s", item.name, previous)
		}
		seenMACs[item.value] = item.name
	}

	unknown := append([]string(nil), observation.UnknownFields...)
	sort.Strings(unknown)
	if len(unknown) != len(observation.Extensions) {
		return errors.New("observation extension and unknown-field sets differ")
	}
	for index, name := range unknown {
		if index > 0 && unknown[index-1] == name {
			return errors.New("observation unknown fields are duplicated")
		}
		if _, ok := observation.Extensions[name]; !ok {
			return errors.New("observation extension and unknown-field sets differ")
		}
	}
	if len(unknown) != 0 {
		return errors.New("qualification does not accept unknown upstream fields")
	}
	for _, name := range []string{"SIGNATURE_MODE", "ADVANCED_BOOT"} {
		if observation.UpstreamFields[name] == "" {
			return fmt.Errorf("observation upstream field %s is required for qualification", name)
		}
	}
	for name, value := range observation.UpstreamFields {
		switch name {
		case "SIGNATURE_MODE":
			if value != "0" && value != "1" {
				return errors.New("observation signature mode is invalid")
			}
		case "ADVANCED_BOOT":
			if !hex8Pattern.MatchString(value) || value != strings.ToLower(value) {
				return errors.New("observation advanced-boot value is invalid")
			}
		case "EEPROM_UPDATE", "SECURE_BOOT_PROVISION":
			if !validOperationResult(value) {
				return errors.New("observation operation result is invalid")
			}
		default:
			return fmt.Errorf("observation contains unexpected upstream field %q", name)
		}
	}
	mutationFields := mutationSuccessFromObservation(observation)
	if !reflect.DeepEqual(observation.MutationSuccess, mutationFields) {
		return errors.New("observation mutation-success audit is inconsistent")
	}
	if len(mutationFields) != 0 {
		return errors.New("observation reports a successful mutation operation")
	}
	wantFingerprint := targetFingerprint(observation.FactoryUUID, observation.UserSerial, observation.BoardRevision.Raw)
	if observation.TargetFingerprint != wantFingerprint {
		return errors.New("observation target fingerprint is internally inconsistent")
	}
	return nil
}

func mutationSuccessFromObservation(observation Observation) []string {
	var result []string
	for name, value := range observation.UpstreamFields {
		if strings.EqualFold(strings.TrimSpace(value), "success") {
			result = append(result, name)
		}
	}
	for name, value := range observation.Extensions {
		if strings.EqualFold(strings.TrimSpace(value), "success") {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func validateSharedProbeContext(first, second ProbeResult) error {
	if first.Profile != second.Profile || first.Adapter != second.Adapter {
		return errors.New("probe results use different profile or adapter references")
	}
	if first.Source != second.Source {
		return errors.New("probe results do not share identical live acquisition provenance")
	}
	return nil
}

func redactedProbe(sequence int, result ProbeResult) RedactedProbe {
	return RedactedProbe{
		Sequence:            sequence,
		EvidenceDigest:      result.Observation.EvidenceDigest,
		TargetFingerprint:   result.Observation.TargetFingerprint,
		BoardRevision:       result.Observation.BoardRevision,
		BoardAttributes:     result.Observation.BoardAttributes,
		BootROM:             result.Observation.BootROM,
		EEPROMHash:          result.Observation.EEPROMHash,
		CustomerKeyHash:     result.Observation.CustomerKeyHash,
		CustomerKeyState:    result.Observation.CustomerKeyState,
		VideoCoreJTAGLocked: result.Observation.VideoCoreJTAGLocked,
		Assessment: QualificationAssessment{
			DeviceClassStatus:                  result.Assessment.Class.Status,
			ObservableBaselineStatus:           result.Assessment.ObservableBaseline.Status,
			EligibleForReversibleQualification: result.Assessment.EligibleForReversibleQualification,
			MutationEligible:                   false,
			FullUnprovisionedState:             provisioning.FullUnprovisionedStateNotEstablished,
		},
		MutationAudit: MutationAudit{SuccessReported: false},
	}
}

func compareQualificationObservations(first, second Observation) ([]QualificationComparison, []string) {
	type candidate struct {
		field  string
		first  any
		second any
	}
	candidates := []candidate{
		{"target_fingerprint", first.TargetFingerprint, second.TargetFingerprint},
		{"user_serial", first.UserSerial, second.UserSerial},
		{"factory_uuid", first.FactoryUUID, second.FactoryUUID},
		{"board_revision", first.BoardRevision, second.BoardRevision},
		{"board_attributes", first.BoardAttributes, second.BoardAttributes},
		{"ethernet_mac", first.EthernetMAC, second.EthernetMAC},
		{"wifi_mac", first.WiFiMAC, second.WiFiMAC},
		{"bluetooth_mac", first.BluetoothMAC, second.BluetoothMAC},
		{"boot_rom", first.BootROM, second.BootROM},
		{"eeprom_hash", first.EEPROMHash, second.EEPROMHash},
		{"customer_key_hash", first.CustomerKeyHash, second.CustomerKeyHash},
		{"customer_key_state", first.CustomerKeyState, second.CustomerKeyState},
		{"videocore_jtag_locked", first.VideoCoreJTAGLocked, second.VideoCoreJTAGLocked},
		{"signature_mode", first.UpstreamFields["SIGNATURE_MODE"], second.UpstreamFields["SIGNATURE_MODE"]},
		{"advanced_boot", first.UpstreamFields["ADVANCED_BOOT"], second.UpstreamFields["ADVANCED_BOOT"]},
	}
	comparisons := make([]QualificationComparison, 0, len(candidates))
	findings := make([]string, 0)
	for _, item := range candidates {
		status := "match"
		if !reflect.DeepEqual(item.first, item.second) {
			status = "changed"
			findings = append(findings, strings.ReplaceAll(item.field, "_", "-")+"-changed")
		}
		comparisons = append(comparisons, QualificationComparison{Field: item.field, Status: status})
	}
	return comparisons, findings
}

func canonicalDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") &&
		hex64Pattern.MatchString(value[len("sha256:"):]) && value == strings.ToLower(value)
}
