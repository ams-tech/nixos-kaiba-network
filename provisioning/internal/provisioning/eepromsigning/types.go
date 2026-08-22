// Package eepromsigning defines the public, non-mutating contract around the
// pinned Raspberry Pi 5 EEPROM signing workflow. It contains no private-key,
// device, recovery, OTP, or EEPROM-programming authority.
package eepromsigning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	PlanSchemaV1Alpha1   = "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1"
	ResultSchemaV1Alpha1 = "kaiba.provisioning.rpi5-eeprom-signing-result/v1alpha1"

	UpdaterModeFreshBoard = "fresh-board"
	RecoveryModeUnsigned  = "unsigned-copy"

	RoleEEPROMBootcode SigningInputRole = "rpi5.eeprom_bootcode"
	RoleEEPROMBootsys  SigningInputRole = "rpi5.eeprom_bootsys"
	RoleEEPROMConfig   SigningInputRole = "rpi5.eeprom_config"

	maxPlanBytes                        = 128 * 1024
	maxResultBytes                      = 128 * 1024
	maxEEPROMImageBytes                 = 2 * 1024 * 1024
	maxRecoveryImageBytes               = 110 * 1024
	maxFirmwareComponentBytes           = 110 * 1024
	maxBootConfigBytes                  = 4096 - 20
	maxPublicKeyPEMBytes                = 16 * 1024
	maxUpdateMetadataBytes              = 4096
	maxSourceDateEpoch           uint64 = 253402300799
	rsaSignatureBytes                   = 256
	maxUnsignedFirmwareBytes            = maxFirmwareComponentBytes - firmwareSigningTrailerBytes
	maxFirmwareSigningInputBytes        = maxUnsignedFirmwareBytes + 12
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// SigningInputRole is deliberately narrower than bundle.ArtifactRole. The
// pinned -f updater signs exactly these three byte strings in this order. In
// particular, EEPROM bootcode is a signing-only intermediate and does not add
// another required role to the final signed-release manifest.
type SigningInputRole string

// File records one immutable regular file. Paths are deliberately absent.
type File struct {
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// SigningInput is the exact byte string presented to the approval gate. For
// bootcode and bootsys this is the vendor signing preimage, not just the
// original extracted component.
type SigningInput struct {
	Role      SigningInputRole `json:"role"`
	Digest    bundle.Digest    `json:"digest"`
	SizeBytes uint64           `json:"size_bytes"`
}

// Plan binds all public inputs to one deterministic invocation of the pinned
// updater. SourceDateEpoch and FirmwareBuildEpoch are independently pinned:
// the former is the release source commit epoch used for deterministic output,
// while the latter identifies the reviewed upstream firmware. There is no
// wall-clock fallback. UpdaterMode and UpdaterFlags fix the fresh-board -f
// workflow and expressly exclude recovery counter-signing.
type Plan struct {
	SchemaVersion               string         `json:"schema_version"`
	PlanID                      string         `json:"plan_id"`
	ReleaseIntentDigest         bundle.Digest  `json:"release_intent_digest"`
	EEPROMReleaseManifestDigest bundle.Digest  `json:"eeprom_release_manifest_digest"`
	SignerPolicyDigest          bundle.Digest  `json:"signer_policy_digest"`
	PublicKeyFingerprint        bundle.Digest  `json:"public_key_fingerprint"`
	CustomerKeyHash             bundle.Digest  `json:"customer_key_hash"`
	FirmwareBuildEpoch          uint64         `json:"firmware_build_epoch"`
	SourceDateEpoch             uint64         `json:"source_date_epoch"`
	UpdaterMode                 string         `json:"updater_mode"`
	UpdaterFlags                []string       `json:"updater_flags"`
	OriginalEEPROM              File           `json:"original_eeprom"`
	OriginalRecovery            File           `json:"original_recovery"`
	OriginalBootcode            File           `json:"original_bootcode"`
	OriginalBootsys             File           `json:"original_bootsys"`
	BootConfig                  File           `json:"boot_config"`
	PublicKeyPEM                File           `json:"public_key_pem"`
	SigningInputs               []SigningInput `json:"signing_inputs"`
}

// SignatureResult correlates one embedded customer signature with the public
// digest of its durable signing-gate receipt. A receipt digest is correlation
// evidence only; authenticating the private gate receipt is a separate
// control-host operation.
type SignatureResult struct {
	Role               SigningInputRole `json:"role"`
	InputDigest        bundle.Digest    `json:"input_digest"`
	InputSizeBytes     uint64           `json:"input_size_bytes"`
	SignatureDigest    bundle.Digest    `json:"signature_digest"`
	SignatureSizeBytes uint64           `json:"signature_size_bytes"`
	GateReceiptDigest  bundle.Digest    `json:"gate_receipt_digest"`
}

// Result is the complete public output of one fresh-board updater execution.
// EEPROMUpdateMetadata is pieeprom.sig: an outer digest/timestamp document, not
// a customer signature. The customer signatures are embedded in SignedEEPROM.
type Result struct {
	SchemaVersion               string            `json:"schema_version"`
	PlanID                      string            `json:"plan_id"`
	PlanDigest                  bundle.Digest     `json:"plan_digest"`
	ReleaseIntentDigest         bundle.Digest     `json:"release_intent_digest"`
	EEPROMReleaseManifestDigest bundle.Digest     `json:"eeprom_release_manifest_digest"`
	SignerPolicyDigest          bundle.Digest     `json:"signer_policy_digest"`
	PublicKeyFingerprint        bundle.Digest     `json:"public_key_fingerprint"`
	CustomerKeyHash             bundle.Digest     `json:"customer_key_hash"`
	SourceDateEpoch             uint64            `json:"source_date_epoch"`
	UpdaterMode                 string            `json:"updater_mode"`
	RecoveryMode                string            `json:"recovery_mode"`
	Signatures                  []SignatureResult `json:"signatures"`
	SignedEEPROM                File              `json:"signed_eeprom"`
	EEPROMUpdateMetadata        File              `json:"eeprom_update_metadata"`
	FreshRecoveryBootcode       File              `json:"fresh_recovery_bootcode"`
}

func (f File) validate(label string, maximum uint64) error {
	if err := f.Digest.Validate(); err != nil {
		return fmt.Errorf("%s.digest: %w", label, err)
	}
	if f.SizeBytes == 0 || f.SizeBytes > maximum {
		return fmt.Errorf("%s.size_bytes must be between 1 and %d", label, maximum)
	}
	return nil
}

// Match verifies bytes against a public file record.
func (f File) Match(label string, contents []byte) error {
	if err := f.validate(label, ^uint64(0)); err != nil {
		return err
	}
	if uint64(len(contents)) != f.SizeBytes {
		return fmt.Errorf("%s size does not match its record", label)
	}
	if bundle.Sum(contents) != f.Digest {
		return fmt.Errorf("%s digest does not match its record", label)
	}
	return nil
}

func signingRoles() []SigningInputRole {
	return []SigningInputRole{RoleEEPROMBootcode, RoleEEPROMBootsys, RoleEEPROMConfig}
}

func (p Plan) Validate() error {
	if p.SchemaVersion != PlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported EEPROM signing plan schema_version %q", p.SchemaVersion)
	}
	if !identifierPattern.MatchString(p.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	for name, digest := range map[string]bundle.Digest{
		"release_intent_digest":          p.ReleaseIntentDigest,
		"eeprom_release_manifest_digest": p.EEPROMReleaseManifestDigest,
		"signer_policy_digest":           p.SignerPolicyDigest,
		"public_key_fingerprint":         p.PublicKeyFingerprint,
		"customer_key_hash":              p.CustomerKeyHash,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if p.FirmwareBuildEpoch == 0 || p.FirmwareBuildEpoch > maxSourceDateEpoch {
		return fmt.Errorf("firmware_build_epoch must be between 1 and %d", maxSourceDateEpoch)
	}
	if p.SourceDateEpoch == 0 || p.SourceDateEpoch > maxSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must be between 1 and %d", maxSourceDateEpoch)
	}
	if p.UpdaterMode != UpdaterModeFreshBoard || len(p.UpdaterFlags) != 1 || p.UpdaterFlags[0] != "-f" {
		return errors.New("updater must use exactly fresh-board mode with the -f flag")
	}
	for _, item := range []struct {
		label   string
		file    File
		maximum uint64
	}{
		{"original_eeprom", p.OriginalEEPROM, maxEEPROMImageBytes},
		{"original_recovery", p.OriginalRecovery, maxUnsignedFirmwareBytes},
		{"original_bootcode", p.OriginalBootcode, maxUnsignedFirmwareBytes},
		{"original_bootsys", p.OriginalBootsys, maxUnsignedFirmwareBytes},
		{"boot_config", p.BootConfig, maxBootConfigBytes},
		{"public_key_pem", p.PublicKeyPEM, maxPublicKeyPEMBytes},
	} {
		if err := item.file.validate(item.label, item.maximum); err != nil {
			return err
		}
	}
	roles := signingRoles()
	if len(p.SigningInputs) != len(roles) {
		return fmt.Errorf("signing_inputs must contain exactly %d entries", len(roles))
	}
	for index, input := range p.SigningInputs {
		if input.Role != roles[index] {
			return fmt.Errorf("signing_inputs[%d].role must be %q", index, roles[index])
		}
		if err := input.Digest.Validate(); err != nil {
			return fmt.Errorf("signing_inputs[%d].digest: %w", index, err)
		}
		if input.SizeBytes == 0 || input.SizeBytes > maxFirmwareSigningInputBytes {
			return fmt.Errorf("signing_inputs[%d].size_bytes is invalid", index)
		}
	}
	if p.SigningInputs[0].SizeBytes != p.OriginalBootcode.SizeBytes+12 {
		return errors.New("bootcode signing-input size must equal original_bootcode.size_bytes plus 12")
	}
	if p.SigningInputs[1].SizeBytes != p.OriginalBootsys.SizeBytes+12 {
		return errors.New("bootsys signing-input size must equal original_bootsys.size_bytes plus 12")
	}
	if p.SigningInputs[2].SizeBytes != p.BootConfig.SizeBytes {
		return errors.New("config signing-input size must equal boot_config.size_bytes")
	}
	return nil
}

func (p Plan) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode canonical EEPROM signing plan: %w", err)
	}
	return encoded, nil
}

func (p Plan) Digest() (bundle.Digest, error) {
	encoded, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func (r Result) Validate() error {
	if r.SchemaVersion != ResultSchemaV1Alpha1 {
		return fmt.Errorf("unsupported EEPROM signing result schema_version %q", r.SchemaVersion)
	}
	if !identifierPattern.MatchString(r.PlanID) {
		return errors.New("plan_id must be a canonical lower-case identifier")
	}
	for name, digest := range map[string]bundle.Digest{
		"plan_digest":                    r.PlanDigest,
		"release_intent_digest":          r.ReleaseIntentDigest,
		"eeprom_release_manifest_digest": r.EEPROMReleaseManifestDigest,
		"signer_policy_digest":           r.SignerPolicyDigest,
		"public_key_fingerprint":         r.PublicKeyFingerprint,
		"customer_key_hash":              r.CustomerKeyHash,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if r.SourceDateEpoch == 0 || r.SourceDateEpoch > maxSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must be between 1 and %d", maxSourceDateEpoch)
	}
	if r.UpdaterMode != UpdaterModeFreshBoard || r.RecoveryMode != RecoveryModeUnsigned {
		return errors.New("result must describe the fresh-board updater with unsigned recovery")
	}
	roles := signingRoles()
	if len(r.Signatures) != len(roles) {
		return fmt.Errorf("signatures must contain exactly %d entries", len(roles))
	}
	for index, signature := range r.Signatures {
		if signature.Role != roles[index] {
			return fmt.Errorf("signatures[%d].role must be %q", index, roles[index])
		}
		for name, digest := range map[string]bundle.Digest{
			"input_digest":        signature.InputDigest,
			"signature_digest":    signature.SignatureDigest,
			"gate_receipt_digest": signature.GateReceiptDigest,
		} {
			if err := digest.Validate(); err != nil {
				return fmt.Errorf("signatures[%d].%s: %w", index, name, err)
			}
		}
		if signature.InputSizeBytes == 0 || signature.InputSizeBytes > maxFirmwareSigningInputBytes {
			return fmt.Errorf("signatures[%d].input_size_bytes is invalid", index)
		}
		if signature.SignatureSizeBytes != rsaSignatureBytes {
			return fmt.Errorf("signatures[%d].signature_size_bytes must be %d", index, rsaSignatureBytes)
		}
	}
	for _, item := range []struct {
		label   string
		file    File
		maximum uint64
	}{
		{"signed_eeprom", r.SignedEEPROM, maxEEPROMImageBytes},
		{"eeprom_update_metadata", r.EEPROMUpdateMetadata, maxUpdateMetadataBytes},
		{"fresh_recovery_bootcode", r.FreshRecoveryBootcode, maxUnsignedFirmwareBytes},
	} {
		if err := item.file.validate(item.label, item.maximum); err != nil {
			return err
		}
	}
	return nil
}

func (r Result) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode canonical EEPROM signing result: %w", err)
	}
	return encoded, nil
}

func (r Result) Digest() (bundle.Digest, error) {
	encoded, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kaiba.provisioning.rpi5-eeprom-signing-result.v1alpha1\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
