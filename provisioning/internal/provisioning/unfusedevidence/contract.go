// Package unfusedevidence validates operator-recorded, non-enforcement
// hardware evidence for an already verified unfused compatibility capsule.
// It contains no live hardware or process-execution boundary.
package unfusedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
)

const (
	ObservationSchemaVersion = "provisioning.kaiba.network/rpi5-unfused-hardware-observation/v1alpha1"
	OutcomeSchemaVersion     = "provisioning.kaiba.network/rpi5-unfused-hardware-evidence/v1alpha1"

	EvidenceModeOperatorHardware = "operator_hardware_observation"
	StatusCompatibilityPassed    = "compatibility_passed"

	ManualBOOTSELConfirmation    = "manual_bootsel_rpiboot_observed"
	ManualNormalBootConfirmation = "manual_normal_boot_observed"
	CompletePowerRemoval         = "complete_power_removal_observed"

	CompatibilityMarkerPrefix = "KAIBA_UNFUSED_COMPATIBILITY=pass"
	DMVerityMarkerPrefix      = "KAIBA_DM_VERITY=active"
	ZeroCustomerKeyHash       = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// TargetObservation is the continuity and public key state recorded on the
// same fixed lane before and after the unfused compatibility boot.
type TargetObservation struct {
	LaneID            string `json:"lane_id"`
	TargetFingerprint string `json:"target_fingerprint"`
	CustomerKeyHash   string `json:"customer_key_hash"`
}

// HardwareObservation is a strict operator record. Confirmations are closed
// constants so free-form prose cannot accidentally satisfy the ceremony.
type HardwareObservation struct {
	SchemaVersion                string `json:"schema_version"`
	ObservationID                string `json:"observation_id"`
	CompatibilityOutcomeDigest   string `json:"compatibility_outcome_digest"`
	CapsuleID                    string `json:"capsule_id"`
	CapsuleDigest                string `json:"capsule_digest"`
	BootImageDigest              string `json:"boot_image_digest"`
	BootSignatureDigest          string `json:"boot_signature_digest"`
	BootPublicKeyFingerprint     string `json:"boot_public_key_fingerprint"`
	SignatureVerificationReceipt string `json:"signature_verification_receipt"`
	RootDataDigest               string `json:"root_data_digest"`
	RootHashDigest               string `json:"root_hash_digest"`
	UARTCaptureDigest            string `json:"uart_capture_digest"`

	ManualBOOTSELConfirmation          string `json:"manual_bootsel_confirmation"`
	PreBOOTSELPowerRemovalConfirmation string `json:"pre_bootsel_power_removal_confirmation"`
	ModeChangePowerRemovalConfirmation string `json:"rpiboot_to_normal_power_removal_confirmation"`
	ManualNormalBootConfirmation       string `json:"manual_normal_boot_confirmation"`
	PostBootPowerRemovalConfirmation   string `json:"post_normal_boot_power_removal_confirmation"`

	Before TargetObservation `json:"before"`
	After  TargetObservation `json:"after"`
}

// Outcome is emitted only after the prior capsule result, operator record, and
// UART capture all agree. Its policy booleans are fixed by the verifier.
type Outcome struct {
	SchemaVersion                string `json:"schema_version"`
	Status                       string `json:"status"`
	EvidenceMode                 string `json:"evidence_mode"`
	ObservationID                string `json:"observation_id"`
	ObservationDigest            string `json:"observation_digest"`
	CompatibilityOutcomeDigest   string `json:"compatibility_outcome_digest"`
	LaneID                       string `json:"lane_id"`
	TargetFingerprint            string `json:"target_fingerprint"`
	CustomerKeyHashBefore        string `json:"customer_key_hash_before"`
	CustomerKeyHashAfter         string `json:"customer_key_hash_after"`
	CapsuleID                    string `json:"capsule_id"`
	CapsuleDigest                string `json:"capsule_digest"`
	BootImageDigest              string `json:"boot_image_digest"`
	BootSignatureDigest          string `json:"boot_signature_digest"`
	BootPublicKeyFingerprint     string `json:"boot_public_key_fingerprint"`
	SignatureVerificationReceipt string `json:"signature_verification_receipt"`
	SignatureVerified            bool   `json:"signature_verified"`
	RootDataDigest               string `json:"root_data_digest"`
	RootHashDigest               string `json:"root_hash_digest"`
	UARTCaptureDigest            string `json:"uart_capture_digest"`
	HardwareObserved             bool   `json:"hardware_observed"`
	SecurityEnforced             bool   `json:"security_enforced"`
	MutationEligible             bool   `json:"mutation_eligible"`
}

// CompatibilityOutcomeDigest derives the binding that an operator observation
// must repeat. It accepts only a successful, offline, non-enforcement result.
func CompatibilityOutcomeDigest(outcome unfusedcompat.Outcome) (string, error) {
	if err := validateCompatibilityOutcome(outcome); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(outcome)
	if err != nil {
		return "", fmt.Errorf("encode canonical compatibility outcome: %w", err)
	}
	return domainDigest("kaiba.rpi5.unfused-compatibility-result.v1", canonical), nil
}

// ExpectedUARTMarkers returns the two exact records required in a bounded UART
// capture for the supplied capsule result.
func ExpectedUARTMarkers(outcome unfusedcompat.Outcome) ([]string, error) {
	if err := validateCompatibilityOutcome(outcome); err != nil {
		return nil, err
	}
	return []string{
		CompatibilityMarkerPrefix + " boot_img_sha256=" + outcome.BootImageDigest + " capsule_sha256=" + outcome.CapsuleDigest,
		DMVerityMarkerPrefix + " root_data_sha256=" + outcome.RootDataDigest + " root_hash_sha256=" + outcome.RootHashDigest,
	}, nil
}
func validateCompatibilityOutcome(outcome unfusedcompat.Outcome) error {
	if outcome.SchemaVersion != unfusedcompat.OutcomeSchemaVersion ||
		outcome.Status != unfusedcompat.StatusCompatibilityPassed ||
		outcome.EvidenceMode != unfusedcompat.EvidenceModeOfflineFixture {
		return errors.New("compatibility outcome is not a successful offline fixture result")
	}
	if !identifierPattern.MatchString(outcome.FixtureID) || !identifierPattern.MatchString(outcome.CapsuleID) {
		return errors.New("compatibility outcome fixture or capsule identity is invalid")
	}
	for label, value := range map[string]string{
		"manifest_digest":                outcome.ManifestDigest,
		"capsule_digest":                 outcome.CapsuleDigest,
		"boot_image_digest":              outcome.BootImageDigest,
		"boot_signature_digest":          outcome.BootSignatureDigest,
		"boot_public_key_fingerprint":    outcome.BootPublicKeyFingerprint,
		"signature_verification_receipt": outcome.SignatureVerificationReceipt,
		"root_data_digest":               outcome.RootDataDigest,
		"root_hash_digest":               outcome.RootHashDigest,
		"fixture_digest":                 outcome.FixtureDigest,
	} {
		if !validDigest(value) {
			return fmt.Errorf("compatibility outcome %s is not a canonical lowercase SHA-256 digest", label)
		}
	}
	if outcome.FilesVerified < 4 {
		return errors.New("compatibility outcome did not verify all required capsule roles")
	}
	if !outcome.SignatureVerified {
		return errors.New("compatibility outcome did not verify the detached boot signature")
	}
	if outcome.HardwareObserved || outcome.SecurityEnforced || outcome.MutationEligible {
		return errors.New("compatibility outcome contains a prohibited hardware or policy claim")
	}
	return nil
}

func (observation HardwareObservation) validate(outcome unfusedcompat.Outcome, outcomeDigest, uartDigest string) error {
	if observation.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("unsupported hardware observation schema %q", observation.SchemaVersion)
	}
	if !identifierPattern.MatchString(observation.ObservationID) {
		return errors.New("observation_id is invalid")
	}
	if observation.CompatibilityOutcomeDigest != outcomeDigest {
		return errors.New("hardware observation does not match the verified compatibility outcome")
	}
	if observation.CapsuleID != outcome.CapsuleID || observation.CapsuleDigest != outcome.CapsuleDigest ||
		observation.BootImageDigest != outcome.BootImageDigest ||
		observation.BootSignatureDigest != outcome.BootSignatureDigest ||
		observation.BootPublicKeyFingerprint != outcome.BootPublicKeyFingerprint ||
		observation.SignatureVerificationReceipt != outcome.SignatureVerificationReceipt ||
		observation.RootDataDigest != outcome.RootDataDigest || observation.RootHashDigest != outcome.RootHashDigest {
		return errors.New("hardware observation capsule binding differs from the compatibility outcome")
	}
	if observation.UARTCaptureDigest != uartDigest {
		return errors.New("hardware observation UART digest differs from the supplied capture")
	}
	if observation.ManualBOOTSELConfirmation != ManualBOOTSELConfirmation ||
		observation.ManualNormalBootConfirmation != ManualNormalBootConfirmation {
		return errors.New("manual BOOTSEL and normal-boot confirmations are required")
	}
	if observation.PreBOOTSELPowerRemovalConfirmation != CompletePowerRemoval ||
		observation.ModeChangePowerRemovalConfirmation != CompletePowerRemoval ||
		observation.PostBootPowerRemovalConfirmation != CompletePowerRemoval {
		return errors.New("complete power removal must be confirmed at every mode boundary")
	}
	if err := validateTargetObservation("before", observation.Before); err != nil {
		return err
	}
	if err := validateTargetObservation("after", observation.After); err != nil {
		return err
	}
	if observation.Before.LaneID != observation.After.LaneID || observation.Before.TargetFingerprint != observation.After.TargetFingerprint {
		return errors.New("target or lane continuity changed between observations")
	}
	return nil
}

func validateTargetObservation(label string, observation TargetObservation) error {
	if !identifierPattern.MatchString(observation.LaneID) {
		return fmt.Errorf("%s lane_id is invalid", label)
	}
	if !validDigest(observation.TargetFingerprint) {
		return fmt.Errorf("%s target_fingerprint is not a canonical lowercase SHA-256 digest", label)
	}
	if observation.CustomerKeyHash != ZeroCustomerKeyHash {
		return fmt.Errorf("%s customer_key_hash is not the all-zero unfused value", label)
	}
	return nil
}

func observationDigest(observation HardwareObservation) (string, error) {
	canonical, err := json.Marshal(observation)
	if err != nil {
		return "", fmt.Errorf("encode canonical hardware observation: %w", err)
	}
	return domainDigest("kaiba.rpi5.unfused-hardware-observation.v1", canonical), nil
}

func domainDigest(domain string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}
