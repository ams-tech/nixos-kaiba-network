package eepromsigning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	OwnedRecoveryPlanSchemaV1Alpha1   = "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1"
	OwnedRecoveryResultSchemaV1Alpha1 = "kaiba.provisioning.rpi5-owned-recovery-signing-result/v1alpha1"

	UpdaterModeOwnedRecovery          = "owned-recovery"
	RecoveryModeCustomerCounterSigned = "customer-counter-signed"

	maxOwnedRecoveryPlanBytes   = 512 * 1024
	maxOwnedRecoveryResultBytes = 128 * 1024
)

// OwnedRecoveryPlan adds exactly one signing authorization to an already
// verified fresh-board EEPROM result. The pinned vendor updater still invokes
// four callbacks for -fr; callbacks two through four are replayed from the
// embedded, verified fresh result and are never new gate requests.
type OwnedRecoveryPlan struct {
	SchemaVersion             string       `json:"schema_version"`
	PlanID                    string       `json:"plan_id"`
	UpdaterMode               string       `json:"updater_mode"`
	UpdaterFlags              []string     `json:"updater_flags"`
	FreshEEPROMPlan           Plan         `json:"fresh_eeprom_plan"`
	FreshEEPROMResult         Result       `json:"fresh_eeprom_result"`
	OwnedRecoverySigningInput SigningInput `json:"owned_recovery_signing_input"`
}

// OwnedRecoveryResult records the one newly approved signature and the three
// vendor outputs. The EEPROM outputs must remain byte-identical to the verified
// fresh-board result; only bootcode5.bin changes to customer-signed recovery.
type OwnedRecoveryResult struct {
	SchemaVersion               string          `json:"schema_version"`
	PlanID                      string          `json:"plan_id"`
	PlanDigest                  bundle.Digest   `json:"plan_digest"`
	ReleaseIntentDigest         bundle.Digest   `json:"release_intent_digest"`
	EEPROMReleaseManifestDigest bundle.Digest   `json:"eeprom_release_manifest_digest"`
	SignerPolicyDigest          bundle.Digest   `json:"signer_policy_digest"`
	PublicKeyFingerprint        bundle.Digest   `json:"public_key_fingerprint"`
	CustomerKeyHash             bundle.Digest   `json:"customer_key_hash"`
	SourceDateEpoch             uint64          `json:"source_date_epoch"`
	UpdaterMode                 string          `json:"updater_mode"`
	RecoveryMode                string          `json:"recovery_mode"`
	Signature                   SignatureResult `json:"signature"`
	OwnedRecoveryBootcode       File            `json:"owned_recovery_bootcode"`
	ReplayedSignedEEPROM        File            `json:"replayed_signed_eeprom"`
	ReplayedEEPROMMetadata      File            `json:"replayed_eeprom_update_metadata"`
}

func (p OwnedRecoveryPlan) Validate() error {
	if p.SchemaVersion != OwnedRecoveryPlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported owned-recovery signing plan schema_version %q", p.SchemaVersion)
	}
	if !identifierPattern.MatchString(p.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	if p.UpdaterMode != UpdaterModeOwnedRecovery || len(p.UpdaterFlags) != 2 || p.UpdaterFlags[0] != "-f" || p.UpdaterFlags[1] != "-r" {
		return errors.New("owned-recovery updater must use exactly the -f and -r flags")
	}
	if err := VerifyBindings(p.FreshEEPROMPlan, p.FreshEEPROMResult); err != nil {
		return fmt.Errorf("verified fresh EEPROM lineage: %w", err)
	}
	input := p.OwnedRecoverySigningInput
	if input.Role != RoleOwnedRecovery {
		return fmt.Errorf("owned_recovery_signing_input.role must be %q", RoleOwnedRecovery)
	}
	if err := input.Digest.Validate(); err != nil {
		return fmt.Errorf("owned_recovery_signing_input.digest: %w", err)
	}
	if input.SizeBytes == 0 || input.SizeBytes > maxFirmwareSigningInputBytes {
		return errors.New("owned_recovery_signing_input.size_bytes is invalid")
	}
	if input.SizeBytes != p.FreshEEPROMPlan.OriginalRecovery.SizeBytes+12 {
		return errors.New("owned-recovery signing-input size must equal original recovery size plus 12")
	}
	return nil
}

func (p OwnedRecoveryPlan) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode canonical owned-recovery signing plan: %w", err)
	}
	if len(encoded) > maxOwnedRecoveryPlanBytes {
		return nil, fmt.Errorf("canonical owned-recovery signing plan exceeds %d bytes", maxOwnedRecoveryPlanBytes)
	}
	return encoded, nil
}

func (p OwnedRecoveryPlan) Digest() (bundle.Digest, error) {
	encoded, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-owned-recovery-signing-plan.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func (r OwnedRecoveryResult) Validate() error {
	if r.SchemaVersion != OwnedRecoveryResultSchemaV1Alpha1 {
		return fmt.Errorf("unsupported owned-recovery signing result schema_version %q", r.SchemaVersion)
	}
	if !identifierPattern.MatchString(r.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	for name, digest := range map[string]bundle.Digest{
		"plan_digest": r.PlanDigest, "release_intent_digest": r.ReleaseIntentDigest,
		"eeprom_release_manifest_digest": r.EEPROMReleaseManifestDigest,
		"signer_policy_digest":           r.SignerPolicyDigest, "public_key_fingerprint": r.PublicKeyFingerprint,
		"customer_key_hash": r.CustomerKeyHash, "signature.input_digest": r.Signature.InputDigest,
		"signature.signature_digest":    r.Signature.SignatureDigest,
		"signature.gate_receipt_digest": r.Signature.GateReceiptDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if r.SourceDateEpoch == 0 || r.SourceDateEpoch > maxSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must be between 1 and %d", maxSourceDateEpoch)
	}
	if r.UpdaterMode != UpdaterModeOwnedRecovery || r.RecoveryMode != RecoveryModeCustomerCounterSigned {
		return errors.New("result must describe customer-counter-signed owned recovery")
	}
	if r.Signature.Role != RoleOwnedRecovery || r.Signature.InputSizeBytes == 0 || r.Signature.InputSizeBytes > maxFirmwareSigningInputBytes || r.Signature.SignatureSizeBytes != rsaSignatureBytes {
		return errors.New("signature must describe exactly one RSA-2048 owned-recovery input")
	}
	for _, item := range []struct {
		label string
		file  File
		max   uint64
	}{
		{"owned_recovery_bootcode", r.OwnedRecoveryBootcode, maxRecoveryImageBytes},
		{"replayed_signed_eeprom", r.ReplayedSignedEEPROM, maxEEPROMImageBytes},
		{"replayed_eeprom_update_metadata", r.ReplayedEEPROMMetadata, maxUpdateMetadataBytes},
	} {
		if err := item.file.validate(item.label, item.max); err != nil {
			return err
		}
	}
	return nil
}

func (r OwnedRecoveryResult) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode canonical owned-recovery signing result: %w", err)
	}
	if len(encoded) > maxOwnedRecoveryResultBytes {
		return nil, fmt.Errorf("canonical owned-recovery signing result exceeds %d bytes", maxOwnedRecoveryResultBytes)
	}
	return encoded, nil
}

func (r OwnedRecoveryResult) Digest() (bundle.Digest, error) {
	encoded, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-owned-recovery-signing-result.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// VerifyOwnedRecoveryBindings proves that the result adds only the authorized
// recovery signature and leaves both fresh EEPROM outputs unchanged.
func VerifyOwnedRecoveryBindings(plan OwnedRecoveryPlan, result OwnedRecoveryResult) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate owned-recovery signing plan: %w", err)
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate owned-recovery signing result: %w", err)
	}
	digest, err := plan.Digest()
	if err != nil {
		return err
	}
	freshPlan, freshResult := plan.FreshEEPROMPlan, plan.FreshEEPROMResult
	if result.PlanID != plan.PlanID || result.PlanDigest != digest {
		return errors.New("owned-recovery result does not bind the exact plan")
	}
	if result.ReleaseIntentDigest != freshPlan.ReleaseIntentDigest || result.EEPROMReleaseManifestDigest != freshPlan.EEPROMReleaseManifestDigest ||
		result.SignerPolicyDigest != freshPlan.SignerPolicyDigest || result.PublicKeyFingerprint != freshPlan.PublicKeyFingerprint || result.CustomerKeyHash != freshPlan.CustomerKeyHash ||
		result.SourceDateEpoch != freshPlan.SourceDateEpoch {
		return errors.New("owned-recovery result does not preserve fresh EEPROM lineage")
	}
	if result.Signature.Role != plan.OwnedRecoverySigningInput.Role || result.Signature.InputDigest != plan.OwnedRecoverySigningInput.Digest || result.Signature.InputSizeBytes != plan.OwnedRecoverySigningInput.SizeBytes {
		return errors.New("owned-recovery result signature does not bind the approved recovery input")
	}
	if result.ReplayedSignedEEPROM != freshResult.SignedEEPROM || result.ReplayedEEPROMMetadata != freshResult.EEPROMUpdateMetadata {
		return errors.New("owned-recovery updater changed the verified fresh EEPROM outputs")
	}
	return nil
}

// ParseOwnedRecoveryPlan applies the strict canonical JSON boundary.
func ParseOwnedRecoveryPlan(encoded []byte) (OwnedRecoveryPlan, error) {
	if len(encoded) == 0 || len(encoded) > maxOwnedRecoveryPlanBytes {
		return OwnedRecoveryPlan{}, fmt.Errorf("owned-recovery plan size must be between 1 and %d bytes", maxOwnedRecoveryPlanBytes)
	}
	var plan OwnedRecoveryPlan
	if err := strictDecode(encoded, &plan); err != nil {
		return OwnedRecoveryPlan{}, fmt.Errorf("decode owned-recovery signing plan: %w", err)
	}
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		return OwnedRecoveryPlan{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return OwnedRecoveryPlan{}, errors.New("owned-recovery signing plan is not canonical JSON")
	}
	return plan, nil
}

// ParseOwnedRecoveryResult applies the strict canonical JSON boundary.
func ParseOwnedRecoveryResult(encoded []byte) (OwnedRecoveryResult, error) {
	if len(encoded) == 0 || len(encoded) > maxOwnedRecoveryResultBytes {
		return OwnedRecoveryResult{}, fmt.Errorf("owned-recovery result size must be between 1 and %d bytes", maxOwnedRecoveryResultBytes)
	}
	var result OwnedRecoveryResult
	if err := strictDecode(encoded, &result); err != nil {
		return OwnedRecoveryResult{}, fmt.Errorf("decode owned-recovery signing result: %w", err)
	}
	canonical, err := result.CanonicalJSON()
	if err != nil {
		return OwnedRecoveryResult{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return OwnedRecoveryResult{}, errors.New("owned-recovery signing result is not canonical JSON")
	}
	return result, nil
}
