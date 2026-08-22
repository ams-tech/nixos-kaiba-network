package main

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
)

var ownedPlanFileLimits = map[string]int64{
	"plan.json":             512 * 1024,
	"release-intent.json":   releaseintent.MaxBytes,
	"pieeprom.original.bin": maxEEPROMBytes,
	"recovery.original.bin": maxRecoveryBytes,
	"bootcode.original.bin": maxComponentBytes,
	"bootsys.original":      maxComponentBytes,
	"boot.conf":             maxBootConfigBytes,
	"public.pem":            maxPublicKeyBytes,
	"pieeprom.expected.bin": maxEEPROMBytes,
	"pieeprom.expected.sig": maxUpdateMetadataBytes,
	"bootcode5.fresh.bin":   maxRecoveryBytes,
}

var ownedResultFileLimits = map[string]int64{
	"pieeprom.bin":  maxEEPROMBytes,
	"pieeprom.sig":  maxUpdateMetadataBytes,
	"bootcode5.bin": maxRecoveryBytes,
	"result.json":   maxResultJSONBytes,
}

type loadedOwnedPlan struct {
	Plan                   eepromsigning.OwnedRecoveryPlan
	PlanJSON               []byte
	ReleaseIntentJSON      []byte
	OriginalEEPROM         []byte
	OriginalRecovery       []byte
	OriginalBootcode       []byte
	OriginalBootsys        []byte
	BootConfig             []byte
	PublicPEM              []byte
	ExpectedSignedEEPROM   []byte
	ExpectedEEPROMMetadata []byte
	FreshRecovery          []byte
}

type loadedOwnedResult struct {
	Result         eepromsigning.OwnedRecoveryResult
	ResultJSON     []byte
	SignedEEPROM   []byte
	EEPROMMetadata []byte
	SignedRecovery []byte
}

func loadOwnedPlanDirectory(path string) (loadedOwnedPlan, error) {
	files, err := readExactDirectory(path, ownedPlanFileLimits)
	if err != nil {
		return loadedOwnedPlan{}, fmt.Errorf("load owned-recovery signing plan directory: %w", err)
	}
	plan, err := eepromsigning.ParseOwnedRecoveryPlan(files["plan.json"])
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	intent, err := releaseintent.Parse(files["release-intent.json"])
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	if !canonicalJSONFile(files["release-intent.json"], intentJSON) {
		return loadedOwnedPlan{}, errors.New("release-intent.json is not canonical JSON")
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	freshPlan, freshResult := plan.FreshEEPROMPlan, plan.FreshEEPROMResult
	if intentDigest != freshPlan.ReleaseIntentDigest {
		return loadedOwnedPlan{}, errors.New("release-intent.json digest does not match the owned-recovery plan")
	}
	if intent.SourceDateEpoch != freshPlan.SourceDateEpoch || intent.EEPROMReleaseManifestDigest != freshPlan.EEPROMReleaseManifestDigest ||
		intent.PublicKeyFingerprint != freshPlan.PublicKeyFingerprint || intent.SigningPolicyDigest != freshPlan.SignerPolicyDigest ||
		intent.ExpectedCustomerKeyHash != freshPlan.CustomerKeyHash {
		return loadedOwnedPlan{}, errors.New("release intent does not bind the owned-recovery plan lineage")
	}
	approved, found := intent.SigningInput(bundle.RoleOwnedRecoveryBootcode)
	if !found || approved.Digest != plan.OwnedRecoverySigningInput.Digest || approved.SizeBytes != plan.OwnedRecoverySigningInput.SizeBytes {
		return loadedOwnedPlan{}, errors.New("release intent does not approve the exact owned-recovery signing input")
	}
	for _, item := range []struct {
		label    string
		record   eepromsigning.File
		contents []byte
	}{
		{"original EEPROM", freshPlan.OriginalEEPROM, files["pieeprom.original.bin"]},
		{"original recovery", freshPlan.OriginalRecovery, files["recovery.original.bin"]},
		{"original bootcode", freshPlan.OriginalBootcode, files["bootcode.original.bin"]},
		{"original bootsys", freshPlan.OriginalBootsys, files["bootsys.original"]},
		{"boot config", freshPlan.BootConfig, files["boot.conf"]},
		{"public key", freshPlan.PublicKeyPEM, files["public.pem"]},
		{"verified signed EEPROM", freshResult.SignedEEPROM, files["pieeprom.expected.bin"]},
		{"verified EEPROM metadata", freshResult.EEPROMUpdateMetadata, files["pieeprom.expected.sig"]},
		{"fresh recovery", freshResult.FreshRecoveryBootcode, files["bootcode5.fresh.bin"]},
	} {
		if err := item.record.Match(item.label, item.contents); err != nil {
			return loadedOwnedPlan{}, err
		}
	}
	derived, err := eepromsigning.NewOwnedRecoverySigningInput(files["recovery.original.bin"])
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	if derived != plan.OwnedRecoverySigningInput {
		return loadedOwnedPlan{}, errors.New("owned-recovery signing input does not match recovery.original.bin")
	}
	_, fingerprint, customerKey, err := eepromsigning.ParsePublicKey(files["public.pem"])
	if err != nil {
		return loadedOwnedPlan{}, err
	}
	if fingerprint != freshPlan.PublicKeyFingerprint || bundle.Sum(customerKey) != freshPlan.CustomerKeyHash {
		return loadedOwnedPlan{}, errors.New("public.pem does not match the planned customer key")
	}
	return loadedOwnedPlan{
		Plan: plan, PlanJSON: planJSON, ReleaseIntentJSON: intentJSON,
		OriginalEEPROM: files["pieeprom.original.bin"], OriginalRecovery: files["recovery.original.bin"],
		OriginalBootcode: files["bootcode.original.bin"], OriginalBootsys: files["bootsys.original"],
		BootConfig: files["boot.conf"], PublicPEM: files["public.pem"],
		ExpectedSignedEEPROM: files["pieeprom.expected.bin"], ExpectedEEPROMMetadata: files["pieeprom.expected.sig"],
		FreshRecovery: files["bootcode5.fresh.bin"],
	}, nil
}

func loadOwnedResultDirectory(path string) (loadedOwnedResult, error) {
	files, err := readExactDirectory(path, ownedResultFileLimits)
	if err != nil {
		return loadedOwnedResult{}, fmt.Errorf("load owned-recovery signing result directory: %w", err)
	}
	result, err := eepromsigning.ParseOwnedRecoveryResult(files["result.json"])
	if err != nil {
		return loadedOwnedResult{}, err
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		return loadedOwnedResult{}, err
	}
	for _, item := range []struct {
		label    string
		record   eepromsigning.File
		contents []byte
	}{
		{"replayed signed EEPROM", result.ReplayedSignedEEPROM, files["pieeprom.bin"]},
		{"replayed EEPROM metadata", result.ReplayedEEPROMMetadata, files["pieeprom.sig"]},
		{"owned recovery", result.OwnedRecoveryBootcode, files["bootcode5.bin"]},
	} {
		if err := item.record.Match(item.label, item.contents); err != nil {
			return loadedOwnedResult{}, err
		}
	}
	return loadedOwnedResult{Result: result, ResultJSON: resultJSON, SignedEEPROM: files["pieeprom.bin"], EEPROMMetadata: files["pieeprom.sig"], SignedRecovery: files["bootcode5.bin"]}, nil
}

func sameOwnedPlan(left, right loadedOwnedPlan) bool {
	return bytes.Equal(left.PlanJSON, right.PlanJSON) && bytes.Equal(left.ReleaseIntentJSON, right.ReleaseIntentJSON) &&
		bytes.Equal(left.OriginalEEPROM, right.OriginalEEPROM) && bytes.Equal(left.OriginalRecovery, right.OriginalRecovery) &&
		bytes.Equal(left.OriginalBootcode, right.OriginalBootcode) && bytes.Equal(left.OriginalBootsys, right.OriginalBootsys) &&
		bytes.Equal(left.BootConfig, right.BootConfig) && bytes.Equal(left.PublicPEM, right.PublicPEM) &&
		bytes.Equal(left.ExpectedSignedEEPROM, right.ExpectedSignedEEPROM) && bytes.Equal(left.ExpectedEEPROMMetadata, right.ExpectedEEPROMMetadata) &&
		bytes.Equal(left.FreshRecovery, right.FreshRecovery)
}

func sameOwnedResult(left, right loadedOwnedResult) bool {
	return bytes.Equal(left.ResultJSON, right.ResultJSON) && bytes.Equal(left.SignedEEPROM, right.SignedEEPROM) &&
		bytes.Equal(left.EEPROMMetadata, right.EEPROMMetadata) && bytes.Equal(left.SignedRecovery, right.SignedRecovery)
}
