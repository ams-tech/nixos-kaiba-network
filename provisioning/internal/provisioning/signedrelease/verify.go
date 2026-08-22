package signedrelease

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpibootbundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
)

var signedBootLimits = map[string]int64{
	"boot.img": 128 * 1024 * 1024, "boot.sig": 4096, "manifest.json": 256 * 1024,
	"public.pem": 16 * 1024, "release-intent.json": releaseintent.MaxBytes,
	"signing-plan.json": 64 * 1024, "signing-result.json": 64 * 1024,
}

var signedEEPROMLimits = map[string]int64{
	"boot.conf": 4096, "bootcode.original.bin": 110 * 1024, "bootcode.signed.bin": 110 * 1024,
	"bootcode5.bin": 110 * 1024, "bootconf.sig": 4096, "bootconf.signed.txt": 4096,
	"bootsys.original": 110 * 1024, "bootsys.signed": 110 * 1024, "cacert.der": 64 * 1024,
	"pieeprom.bin": 2 * 1024 * 1024, "pieeprom.original.bin": 2 * 1024 * 1024, "pieeprom.sig": 4096,
	"plan.json": 128 * 1024, "pubkey.bin": 264, "public.pem": 16 * 1024,
	"recovery.original.bin": 110 * 1024, "release-intent.json": releaseintent.MaxBytes,
	"result.json": 128 * 1024, "updatetime": 4096,
}

var replayPlanLimits = map[string]int64{
	"plan.json": 128 * 1024, "release-intent.json": releaseintent.MaxBytes,
	"pieeprom.original.bin": 2 * 1024 * 1024, "recovery.original.bin": 110 * 1024,
	"bootcode.original.bin": 110 * 1024, "bootsys.original": 110 * 1024,
	"boot.conf": 4096, "public.pem": 16 * 1024,
}

var replaySignedLimits = map[string]int64{
	"pieeprom.bin": 2 * 1024 * 1024, "pieeprom.sig": 4096,
	"bootcode5.bin": 110 * 1024, "result.json": 128 * 1024,
}

var ownedRecoveryLimits = map[string]int64{
	"bootcode5.bin": 110 * 1024, "pieeprom.bin": 2 * 1024 * 1024, "pieeprom.sig": 4096,
	"plan.json": 512 * 1024, "public.pem": 16 * 1024, "recovery.original.bin": 110 * 1024,
	"release-intent.json": releaseintent.MaxBytes, "result.json": 128 * 1024,
}

// Resolve verifies every public boundary and constructs the exact final
// manifest and publication index without writing output.
func Resolve(ctx context.Context, inputs Inputs, options Options) (ResolvedRelease, error) {
	if ctx == nil {
		return ResolvedRelease{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedRelease{}, err
	}
	if options.EEPROMReplayVerifier == nil {
		return ResolvedRelease{}, errors.New("a linker-pinned deterministic EEPROM replay verifier is required")
	}

	intentSource, err := inspectRegular(inputs.ReleaseIntentPath, releaseintent.MaxBytes, true)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("release intent: %w", err)
	}
	intent, err := releaseintent.Parse(intentSource.contents)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("release intent: %w", err)
	}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		return ResolvedRelease{}, err
	}
	if !canonicalJSONFile(intentSource.contents, intentJSON) {
		return ResolvedRelease{}, errors.New("release intent is not canonical JSON")
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return ResolvedRelease{}, err
	}

	unsignedSource, err := inspectRegular(inputs.UnsignedArtifactsManifestPath, maxMetadataBytes, true)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("unsigned artifact set: %w", err)
	}
	unsigned, err := parseUnsignedArtifactSet(unsignedSource.contents)
	if err != nil {
		return ResolvedRelease{}, err
	}
	if unsigned.BundleDigest != intent.UnsignedArtifactSetDigest || unsigned.SourceRevision != intent.SourceRevision ||
		unsigned.ExpectedCustomerKeyHash != intent.ExpectedCustomerKeyHash {
		return ResolvedRelease{}, errors.New("unsigned artifact set does not bind the release intent lineage")
	}

	eepromReleaseSource, err := inspectRegular(inputs.EEPROMReleaseManifestPath, maxMetadataBytes, true)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("EEPROM release manifest: %w", err)
	}
	if err := validateEEPROMRelease(eepromReleaseSource.contents); err != nil {
		return ResolvedRelease{}, err
	}
	if eepromReleaseSource.digest != intent.EEPROMReleaseManifestDigest {
		return ResolvedRelease{}, errors.New("EEPROM release manifest digest does not match the release intent")
	}

	bootFiles, err := readExactDirectory(inputs.SignedBootDirectory, signedBootLimits)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("signed boot bundle: %w", err)
	}
	bootPlan, bootResult, publicKey, err := verifySignedBoot(bootFiles, intent, intentDigest)
	if err != nil {
		return ResolvedRelease{}, err
	}

	eepromFiles, err := readExactDirectory(inputs.SignedEEPROMDirectory, signedEEPROMLimits)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("signed EEPROM bundle: %w", err)
	}
	eepromPlan, eepromResult, err := verifySignedEEPROM(eepromFiles, intent, intentJSON, intentDigest)
	if err != nil {
		return ResolvedRelease{}, err
	}

	ownedFiles, err := readExactDirectory(inputs.OwnedRecoveryDirectory, ownedRecoveryLimits)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("owned-recovery bundle: %w", err)
	}
	ownedPlan, ownedResult, err := verifyOwnedRecovery(ownedFiles, eepromFiles, eepromPlan, eepromResult, intent, intentJSON, publicKey)
	if err != nil {
		return ResolvedRelease{}, err
	}

	if !bytes.Equal(bootFiles["public.pem"].contents, eepromFiles["public.pem"].contents) ||
		!bytes.Equal(bootFiles["public.pem"].contents, ownedFiles["public.pem"].contents) {
		return ResolvedRelease{}, errors.New("boot, EEPROM, and owned-recovery bundles use different public keys")
	}
	if bootPlan.PublicKeyFingerprint != eepromPlan.PublicKeyFingerprint ||
		bootResult.PublicKeyFingerprint != ownedResult.PublicKeyFingerprint {
		return ResolvedRelease{}, errors.New("signing records do not preserve one public-key fingerprint")
	}

	if err := verifyReplayInputs(inputs, eepromFiles); err != nil {
		return ResolvedRelease{}, err
	}
	if err := options.EEPROMReplayVerifier.VerifyEEPROMReplay(
		ctx, inputs.EEPROMReplayPlanDirectory, inputs.EEPROMReplaySignedDirectory, inputs.SignedEEPROMDirectory,
	); err != nil {
		return ResolvedRelease{}, fmt.Errorf("deterministic EEPROM replay: %w", err)
	}
	if err := options.EEPROMReplayVerifier.VerifyOwnedRecoveryReplay(
		ctx, inputs.OwnedReplayPlanDirectory, inputs.OwnedReplaySignedDirectory, inputs.OwnedRecoveryDirectory,
	); err != nil {
		return ResolvedRelease{}, fmt.Errorf("deterministic owned-recovery replay: %w", err)
	}

	profileSource, err := inspectRegular(inputs.DeviceProfilePath, provisioning.MaxProfileSize, true)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("device profile: %w", err)
	}
	profile, err := provisioning.LoadProfile(bytes.NewReader(profileSource.contents))
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("device profile: %w", err)
	}
	if profile.Metadata.ID != intent.DeviceClass {
		return ResolvedRelease{}, errors.New("device profile does not describe the release-intent device class")
	}
	adapterSource, err := inspectRegular(inputs.PlatformAdapterPath, maxRegularFileSize, false)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("platform adapter: %w", err)
	}
	rootIntegritySource, err := inspectRegular(inputs.RootIntegrityPath, maxMetadataBytes, true)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("root-integrity metadata: %w", err)
	}
	if _, err := parseRootIntegrity(rootIntegritySource.contents, unsigned); err != nil {
		return ResolvedRelease{}, err
	}

	rootData, err := inspectRegular(inputs.RootDataImagePath, maxRegularFileSize, false)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("root data image: %w", err)
	}
	rootHash, err := inspectRegular(inputs.RootHashTreeImagePath, maxRegularFileSize, false)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("root hash-tree image: %w", err)
	}
	if rootData.digest != unsigned.Artifacts.RootData.Digest || rootHash.digest != unsigned.Artifacts.RootHashTree.Digest {
		return ResolvedRelease{}, errors.New("root images do not match the unsigned artifact set")
	}
	if bootFiles["boot.img"].digest != unsigned.Artifacts.BootImage.Digest || bootFiles["boot.img"].size != unsigned.BootImageSizeBytes {
		return ResolvedRelease{}, errors.New("signed boot image does not match the unsigned artifact set")
	}

	trees, err := verifyRPIBootBundleSet(inputs, intentDigest, bootFiles, eepromFiles, ownedFiles, rootData, rootHash)
	if err != nil {
		return ResolvedRelease{}, err
	}

	files := map[bundle.ArtifactRole]regularSource{
		bundle.RoleBootPublicKey:         bootFiles["public.pem"],
		bundle.RoleDeviceProfile:         profileSource,
		bundle.RolePlatformAdapter:       adapterSource,
		bundle.RoleRootIntegrity:         rootIntegritySource,
		bundle.RoleBootImage:             bootFiles["boot.img"],
		bundle.RoleBootSignature:         bootFiles["boot.sig"],
		bundle.RoleEEPROMBootsys:         eepromFiles["bootsys.signed"],
		bundle.RoleEEPROMConfig:          eepromFiles["boot.conf"],
		bundle.RoleOwnedRecoveryBootcode: ownedFiles["bootcode5.bin"],
		bundle.RoleRootDataImage:         rootData,
		bundle.RoleRootHashTreeImage:     rootHash,
		bundle.RoleSignedEEPROMImage:     eepromFiles["pieeprom.bin"],
	}
	artifacts := make([]bundle.ReleaseArtifact, 0, len(bundle.SignedReleaseRoles()))
	for _, role := range bundle.SignedReleaseRoles() {
		if file, exists := files[role]; exists {
			artifacts = append(artifacts, bundle.ReleaseArtifact{Role: role, Kind: bundle.ArtifactKindRegularFile, Digest: file.digest, SizeBytes: file.size})
			continue
		}
		tree := trees[role].tree
		digest, err := tree.Digest()
		if err != nil {
			return ResolvedRelease{}, err
		}
		size, err := tree.SizeBytes()
		if err != nil {
			return ResolvedRelease{}, err
		}
		artifacts = append(artifacts, bundle.ReleaseArtifact{Role: role, Kind: bundle.ArtifactKindDirectoryTree, Digest: digest, SizeBytes: size, Tree: &tree})
	}
	manifest, err := bundle.NewSignedReleaseManifest(
		intent.ReleaseID, intent.SourceRevision, intentDigest, intent.SigningPolicyDigest, intent.ExpectedCustomerKeyHash, artifacts,
	)
	if err != nil {
		return ResolvedRelease{}, fmt.Errorf("construct signed-release manifest: %w", err)
	}

	records := map[string]regularSource{
		"boot_signing_plan":       memorySource(jsonFile(mustCanonicalBootPlan(bootPlan))),
		"boot_signing_result":     memorySource(jsonFile(mustCanonicalBootResult(bootResult))),
		"eeprom_release_manifest": eepromReleaseSource,
		"eeprom_signing_plan":     memorySource(jsonFile(mustCanonicalEEPROMPlan(eepromPlan))),
		"eeprom_signing_result":   memorySource(jsonFile(mustCanonicalEEPROMResult(eepromResult))),
		"owned_recovery_plan":     memorySource(jsonFile(mustCanonicalOwnedPlan(ownedPlan))),
		"owned_recovery_result":   memorySource(jsonFile(mustCanonicalOwnedResult(ownedResult))),
		"release_intent":          memorySource(jsonFile(intentJSON)),
		"unsigned_artifact_set":   unsignedSource,
	}
	publication, err := newPublication(manifest, records)
	if err != nil {
		return ResolvedRelease{}, err
	}
	return ResolvedRelease{Manifest: manifest, Publication: publication, files: files, trees: trees, records: records}, nil
}

func verifyRPIBootBundleSet(
	inputs Inputs,
	intentDigest bundle.Digest,
	bootFiles, eepromFiles, ownedFiles map[string]regularSource,
	rootData, rootHash regularSource,
) (map[bundle.ArtifactRole]treeSource, error) {
	specifications := []struct {
		role bundle.ArtifactRole
		path string
		leaf string
	}{
		{bundle.RoleFreshCommitBundle, inputs.FreshCommitBundle, "fresh-commit"},
		{bundle.RoleFreshReadbackBundle, inputs.FreshReadbackBundle, "fresh-readback"},
		{bundle.RoleNegativeBootBundle, inputs.NegativeBootBundle, "negative-boot"},
		{bundle.RoleOwnedReadbackBundle, inputs.OwnedReadbackBundle, "owned-readback"},
		{bundle.RoleOwnedRecoveryBundle, inputs.OwnedRecoveryBundle, "owned-recovery"},
		{bundle.RoleRootIntegrityTestBundle, inputs.RootIntegrityTestBundle, "root-integrity-test"},
	}
	root := filepath.Dir(inputs.FreshCommitBundle)
	for _, specification := range specifications {
		if specification.path != filepath.Join(root, specification.leaf) {
			return nil, errors.New("RPIBOOT trees must be the six canonical paths under one bundle-set root")
		}
	}
	set, err := rpibootbundle.Verify(root)
	if err != nil {
		return nil, fmt.Errorf("canonical RPIBOOT bundle set: %w", err)
	}
	if set.ReleaseIntentDigest != intentDigest {
		return nil, errors.New("RPIBOOT bundle set does not bind the selected release intent")
	}
	wantInputs := map[string]regularSource{
		"boot_image":              bootFiles["boot.img"],
		"boot_public_key":         bootFiles["public.pem"],
		"boot_signature":          bootFiles["boot.sig"],
		"eeprom_update_metadata":  eepromFiles["pieeprom.sig"],
		"fresh_recovery_bootcode": eepromFiles["bootcode5.bin"],
		"owned_recovery_bootcode": ownedFiles["bootcode5.bin"],
		"root_data_image":         rootData,
		"root_hash_tree_image":    rootHash,
		"signed_eeprom_image":     eepromFiles["pieeprom.bin"],
	}
	for _, input := range set.Inputs {
		expected, exists := wantInputs[input.Name]
		if !exists || input.File.Digest != expected.digest || input.File.SizeBytes != expected.size {
			return nil, fmt.Errorf("RPIBOOT bundle-set input %q does not match the verified release component", input.Name)
		}
	}

	recordedTrees := make(map[bundle.ArtifactRole]bundle.DirectoryTree, len(set.Bundles))
	for _, record := range set.Bundles {
		recordedTrees[bundle.ArtifactRole(record.Role)] = record.Tree
	}
	trees := make(map[bundle.ArtifactRole]treeSource, len(specifications))
	for _, specification := range specifications {
		tree, err := inspectTree(specification.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", specification.role, err)
		}
		actualJSON, _ := tree.tree.CanonicalJSON()
		expectedJSON, _ := recordedTrees[specification.role].CanonicalJSON()
		if !bytes.Equal(actualJSON, expectedJSON) {
			return nil, fmt.Errorf("%s differs from the canonical RPIBOOT bundle-set record", specification.role)
		}
		trees[specification.role] = tree
	}
	return trees, nil
}

func verifySignedBoot(files map[string]regularSource, intent releaseintent.Intent, intentDigest bundle.Digest) (signedboot.Plan, signedboot.Result, *rsa.PublicKey, error) {
	var plan signedboot.Plan
	if err := strictDecode(files["signing-plan.json"].contents, &plan); err != nil {
		return plan, signedboot.Result{}, nil, fmt.Errorf("decode boot signing plan: %w", err)
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil || !canonicalJSONFile(files["signing-plan.json"].contents, planJSON) {
		return plan, signedboot.Result{}, nil, errors.New("boot signing plan is not canonical JSON")
	}
	var result signedboot.Result
	if err := strictDecode(files["signing-result.json"].contents, &result); err != nil {
		return plan, result, nil, fmt.Errorf("decode boot signing result: %w", err)
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil || !canonicalJSONFile(files["signing-result.json"].contents, resultJSON) {
		return plan, result, nil, errors.New("boot signing result is not canonical JSON")
	}
	if !canonicalJSONFile(files["release-intent.json"].contents, mustCanonicalIntent(intent)) {
		return plan, result, nil, errors.New("boot bundle release intent differs from the selected release intent")
	}
	planDigest, _ := plan.Digest()
	if plan.ReleaseIntentDigest != intentDigest || result.PlanID != plan.PlanID || result.PlanDigest != planDigest ||
		result.ReleaseIntentDigest != intentDigest || result.BootImageDigest != plan.BootImageDigest || result.BootImageSizeBytes != plan.BootImageSizeBytes ||
		result.BootSignatureDigest != files["boot.sig"].digest || result.BootSignatureSizeBytes != files["boot.sig"].size ||
		result.PublicKeyFingerprint != plan.PublicKeyFingerprint || result.SignerPolicyDigest != plan.SignerPolicyDigest ||
		result.SourceDateEpoch != plan.SourceDateEpoch || plan.SignerPolicyDigest != intent.SigningPolicyDigest || plan.SourceDateEpoch != intent.SourceDateEpoch {
		return plan, result, nil, errors.New("boot signing plan/result lineage is inconsistent")
	}
	approved, found := intent.SigningInput(bundle.RoleBootImage)
	if !found || approved.Digest != plan.BootImageDigest || approved.SizeBytes != plan.BootImageSizeBytes ||
		files["boot.img"].digest != plan.BootImageDigest || files["boot.img"].size != plan.BootImageSizeBytes {
		return plan, result, nil, errors.New("boot image does not match the authorized signing input")
	}
	key, fingerprint, customerBinary, err := eepromsigning.ParsePublicKey(files["public.pem"].contents)
	if err != nil {
		return plan, result, nil, fmt.Errorf("boot public key: %w", err)
	}
	if fingerprint != intent.PublicKeyFingerprint || fingerprint != plan.PublicKeyFingerprint || bundle.Sum(customerBinary) != intent.ExpectedCustomerKeyHash {
		return plan, result, nil, errors.New("boot public key does not match the release intent")
	}
	document, err := rpi5bootsig.Parse(files["boot.sig"].contents)
	if err != nil {
		return plan, result, nil, fmt.Errorf("boot signature: %w", err)
	}
	if document.ImageDigest != plan.BootImageDigest || document.Timestamp != plan.SourceDateEpoch {
		return plan, result, nil, errors.New("boot signature does not bind the planned image and epoch")
	}
	if err := document.Verify(key); err != nil {
		return plan, result, nil, err
	}
	manifest, err := bundle.ParseManifest(files["manifest.json"].contents)
	if err != nil {
		return plan, result, nil, fmt.Errorf("boot manifest: %w", err)
	}
	canonicalManifest, _ := manifest.CanonicalJSON()
	if !canonicalJSONFile(files["manifest.json"].contents, canonicalManifest) || manifest.ManifestID != plan.PlanID ||
		manifest.DeviceClass != "raspberry-pi-5" || manifest.SigningPolicyDigest != intent.SigningPolicyDigest || len(manifest.Artifacts) != 3 {
		return plan, result, nil, errors.New("boot manifest does not bind the exact signed boot bundle")
	}
	want := map[bundle.ArtifactRole]regularSource{
		bundle.RoleBootImage: files["boot.img"], bundle.RoleBootPublicKey: files["public.pem"], bundle.RoleBootSignature: files["boot.sig"],
	}
	for _, artifact := range manifest.Artifacts {
		expected, exists := want[artifact.Role]
		if !exists || artifact.Digest != expected.digest || artifact.SizeBytes != expected.size {
			return plan, result, nil, errors.New("boot manifest artifact records do not match bundle bytes")
		}
	}
	return plan, result, key, nil
}

func verifySignedEEPROM(files map[string]regularSource, intent releaseintent.Intent, intentJSON []byte, intentDigest bundle.Digest) (eepromsigning.Plan, eepromsigning.Result, error) {
	plan, err := eepromsigning.ParsePlan(files["plan.json"].contents)
	if err != nil {
		return plan, eepromsigning.Result{}, fmt.Errorf("EEPROM plan: %w", err)
	}
	result, err := eepromsigning.ParseResult(files["result.json"].contents)
	if err != nil {
		return plan, result, fmt.Errorf("EEPROM result: %w", err)
	}
	if !canonicalJSONFile(files["release-intent.json"].contents, intentJSON) {
		return plan, result, errors.New("EEPROM bundle release intent differs from the selected release intent")
	}
	if plan.ReleaseIntentDigest != intentDigest || plan.EEPROMReleaseManifestDigest != intent.EEPROMReleaseManifestDigest ||
		plan.SignerPolicyDigest != intent.SigningPolicyDigest || plan.PublicKeyFingerprint != intent.PublicKeyFingerprint ||
		plan.CustomerKeyHash != intent.ExpectedCustomerKeyHash || plan.SourceDateEpoch != intent.SourceDateEpoch {
		return plan, result, errors.New("EEPROM plan does not bind the release intent")
	}
	for index, input := range plan.SigningInputs {
		approved, found := intent.SigningInput(bundle.ArtifactRole(input.Role))
		if !found || approved.Digest != input.Digest || approved.SizeBytes != input.SizeBytes {
			return plan, result, fmt.Errorf("EEPROM signing input %d was not authorized", index)
		}
	}
	if !bytes.Equal(files["bootconf.signed.txt"].contents, files["boot.conf"].contents) {
		return plan, result, errors.New("signed EEPROM extracted boot config differs from boot.conf")
	}
	input := eepromsigning.FinalizationInput{
		Plan: plan, Result: result,
		OriginalEEPROM: files["pieeprom.original.bin"].contents, OriginalRecovery: files["recovery.original.bin"].contents,
		OriginalBootcode: files["bootcode.original.bin"].contents, OriginalBootsys: files["bootsys.original"].contents,
		BootConfig: files["boot.conf"].contents, PublicKeyPEM: files["public.pem"].contents,
		SignedEEPROM: files["pieeprom.bin"].contents, EEPROMUpdateMetadata: files["pieeprom.sig"].contents,
		FreshRecoveryBootcode: files["bootcode5.bin"].contents, ExtractedBootcode: files["bootcode.signed.bin"].contents,
		ExtractedBootsys: files["bootsys.signed"].contents, ExtractedBootConfig: files["bootconf.signed.txt"].contents,
		ExtractedBootConfigSig: files["bootconf.sig"].contents, ExtractedPublicKeyBinary: files["pubkey.bin"].contents,
		OriginalCACertDER: files["cacert.der"].contents, ExtractedCACertDER: files["cacert.der"].contents,
		OriginalUpdateTime: files["updatetime"].contents, ExtractedUpdateTime: files["updatetime"].contents,
	}
	if err := eepromsigning.VerifyFinalization(input); err != nil {
		return plan, result, fmt.Errorf("signed EEPROM finalization: %w", err)
	}
	return plan, result, nil
}

func verifyOwnedRecovery(files, eepromFiles map[string]regularSource, freshPlan eepromsigning.Plan, freshResult eepromsigning.Result, intent releaseintent.Intent, intentJSON []byte, publicKey *rsa.PublicKey) (eepromsigning.OwnedRecoveryPlan, eepromsigning.OwnedRecoveryResult, error) {
	plan, err := eepromsigning.ParseOwnedRecoveryPlan(files["plan.json"].contents)
	if err != nil {
		return plan, eepromsigning.OwnedRecoveryResult{}, fmt.Errorf("owned-recovery plan: %w", err)
	}
	result, err := eepromsigning.ParseOwnedRecoveryResult(files["result.json"].contents)
	if err != nil {
		return plan, result, fmt.Errorf("owned-recovery result: %w", err)
	}
	if err := eepromsigning.VerifyOwnedRecoveryBindings(plan, result); err != nil {
		return plan, result, err
	}
	derivedInput, err := eepromsigning.NewOwnedRecoverySigningInput(files["recovery.original.bin"].contents)
	if err != nil || derivedInput != plan.OwnedRecoverySigningInput {
		return plan, result, errors.New("owned-recovery signing input does not match the pinned recovery image")
	}
	approved, found := intent.SigningInput(bundle.RoleOwnedRecoveryBootcode)
	if !found || approved.Digest != derivedInput.Digest || approved.SizeBytes != derivedInput.SizeBytes {
		return plan, result, errors.New("release intent does not authorize the owned-recovery signing input")
	}
	freshPlanJSON, _ := freshPlan.CanonicalJSON()
	embeddedPlanJSON, _ := plan.FreshEEPROMPlan.CanonicalJSON()
	freshResultJSON, _ := freshResult.CanonicalJSON()
	embeddedResultJSON, _ := plan.FreshEEPROMResult.CanonicalJSON()
	if !bytes.Equal(freshPlanJSON, embeddedPlanJSON) || !bytes.Equal(freshResultJSON, embeddedResultJSON) {
		return plan, result, errors.New("owned-recovery plan does not embed the verified fresh EEPROM plan and result")
	}
	if !canonicalJSONFile(files["release-intent.json"].contents, intentJSON) ||
		!bytes.Equal(files["public.pem"].contents, eepromFiles["public.pem"].contents) ||
		!bytes.Equal(files["recovery.original.bin"].contents, eepromFiles["recovery.original.bin"].contents) ||
		!bytes.Equal(files["pieeprom.bin"].contents, eepromFiles["pieeprom.bin"].contents) ||
		!bytes.Equal(files["pieeprom.sig"].contents, eepromFiles["pieeprom.sig"].contents) {
		return plan, result, errors.New("owned-recovery bundle does not preserve fresh EEPROM bytes and lineage")
	}
	_, _, binaryKey, err := eepromsigning.ParsePublicKey(files["public.pem"].contents)
	if err != nil {
		return plan, result, err
	}
	signature, err := eepromsigning.VerifySignedFirmware(files["recovery.original.bin"].contents, files["bootcode5.bin"].contents, binaryKey, publicKey)
	if err != nil {
		return plan, result, fmt.Errorf("owned-recovery bootcode: %w", err)
	}
	if result.OwnedRecoveryBootcode.Digest != files["bootcode5.bin"].digest || result.OwnedRecoveryBootcode.SizeBytes != files["bootcode5.bin"].size ||
		result.Signature.SignatureDigest != bundle.Sum(signature) || result.Signature.SignatureSizeBytes != uint64(len(signature)) ||
		result.ReplayedSignedEEPROM.Digest != files["pieeprom.bin"].digest || result.ReplayedEEPROMMetadata.Digest != files["pieeprom.sig"].digest {
		return plan, result, errors.New("owned-recovery result records do not match final bytes")
	}
	return plan, result, nil
}

func verifyReplayInputs(inputs Inputs, finalized map[string]regularSource) error {
	plan, err := readExactDirectory(inputs.EEPROMReplayPlanDirectory, replayPlanLimits)
	if err != nil {
		return fmt.Errorf("EEPROM replay plan: %w", err)
	}
	signed, err := readExactDirectory(inputs.EEPROMReplaySignedDirectory, replaySignedLimits)
	if err != nil {
		return fmt.Errorf("EEPROM replay signed output: %w", err)
	}
	for name := range replayPlanLimits {
		if !bytes.Equal(plan[name].contents, finalized[name].contents) {
			return fmt.Errorf("EEPROM replay plan %s differs from the finalized bundle", name)
		}
	}
	for name := range replaySignedLimits {
		if !bytes.Equal(signed[name].contents, finalized[name].contents) {
			return fmt.Errorf("EEPROM replay signed output %s differs from the finalized bundle", name)
		}
	}
	return nil
}

func memorySource(contents []byte) regularSource {
	copy := append([]byte(nil), contents...)
	return regularSource{contents: copy, digest: bundle.Sum(copy), size: uint64(len(copy))}
}

func mustCanonicalIntent(intent releaseintent.Intent) []byte {
	encoded, _ := intent.CanonicalJSON()
	return encoded
}
func mustCanonicalBootPlan(value signedboot.Plan) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}
func mustCanonicalBootResult(value signedboot.Result) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}
func mustCanonicalEEPROMPlan(value eepromsigning.Plan) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}
func mustCanonicalEEPROMResult(value eepromsigning.Result) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}
func mustCanonicalOwnedPlan(value eepromsigning.OwnedRecoveryPlan) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}
func mustCanonicalOwnedResult(value eepromsigning.OwnedRecoveryResult) []byte {
	encoded, _ := value.CanonicalJSON()
	return encoded
}

func digestPath(prefix string, digest bundle.Digest, suffix string) string {
	return filepath.ToSlash(filepath.Join(prefix, "sha256", strings.TrimPrefix(string(digest), "sha256:")+suffix))
}

func newPublication(manifest bundle.SignedReleaseManifest, records map[string]regularSource) (Publication, error) {
	manifestDigest, err := manifest.Digest()
	if err != nil {
		return Publication{}, err
	}
	publication := Publication{
		SchemaVersion: PublicationSchemaV1Alpha1, SignedReleaseManifestDigest: manifestDigest,
		ManifestPath:        digestPath("manifests", manifestDigest, ".json"),
		ReleaseIntentDigest: manifest.ReleaseIntentDigest, SourceRevision: manifest.SourceRevision,
		Artifacts: make([]PublicationArtifact, 0, len(manifest.Artifacts)),
		Records:   make([]PublicationRecord, 0, len(records)),
	}
	for _, artifact := range manifest.Artifacts {
		item := PublicationArtifact{Role: artifact.Role, Kind: artifact.Kind, Digest: artifact.Digest, SizeBytes: artifact.SizeBytes}
		if artifact.Kind == bundle.ArtifactKindRegularFile {
			item.Path = digestPath("objects", artifact.Digest, "")
		} else {
			item.Path = digestPath("trees", artifact.Digest, "")
			item.TreeRecordPath = digestPath("tree-records", artifact.Digest, ".json")
		}
		publication.Artifacts = append(publication.Artifacts, item)
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		record := records[id]
		publication.Records = append(publication.Records, PublicationRecord{
			ID: id, Digest: record.digest, SizeBytes: record.size, Path: digestPath("records", record.digest, ""),
		})
	}
	if err := publication.Validate(); err != nil {
		return Publication{}, err
	}
	return publication, nil
}

func (p Publication) Validate() error {
	if p.SchemaVersion != PublicationSchemaV1Alpha1 {
		return fmt.Errorf("unsupported publication schema_version %q", p.SchemaVersion)
	}
	for name, digest := range map[string]bundle.Digest{"signed_release_manifest_digest": p.SignedReleaseManifestDigest, "release_intent_digest": p.ReleaseIntentDigest} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if !sourceRevisionPattern.MatchString(p.SourceRevision) {
		return errors.New("publication source_revision is not canonical")
	}
	if p.ManifestPath != digestPath("manifests", p.SignedReleaseManifestDigest, ".json") {
		return errors.New("publication manifest_path is not content addressed")
	}
	roles := bundle.SignedReleaseRoles()
	if len(p.Artifacts) != len(roles) {
		return fmt.Errorf("publication artifacts must contain exactly %d entries", len(roles))
	}
	for index, item := range p.Artifacts {
		if item.Role != roles[index] || item.SizeBytes == 0 || item.Digest.Validate() != nil {
			return fmt.Errorf("publication artifact %d is invalid", index)
		}
		if item.Kind == bundle.ArtifactKindRegularFile {
			if item.Path != digestPath("objects", item.Digest, "") || item.TreeRecordPath != "" {
				return fmt.Errorf("publication artifact %d regular-file path is invalid", index)
			}
		} else if item.Kind == bundle.ArtifactKindDirectoryTree {
			if item.Path != digestPath("trees", item.Digest, "") || item.TreeRecordPath != digestPath("tree-records", item.Digest, ".json") {
				return fmt.Errorf("publication artifact %d tree paths are invalid", index)
			}
		} else {
			return fmt.Errorf("publication artifact %d kind is invalid", index)
		}
	}
	wantIDs := []string{"boot_signing_plan", "boot_signing_result", "eeprom_release_manifest", "eeprom_signing_plan", "eeprom_signing_result", "owned_recovery_plan", "owned_recovery_result", "release_intent", "unsigned_artifact_set"}
	if len(p.Records) != len(wantIDs) {
		return fmt.Errorf("publication records must contain exactly %d entries", len(wantIDs))
	}
	for index, record := range p.Records {
		if record.ID != wantIDs[index] || record.SizeBytes == 0 || record.Digest.Validate() != nil || record.Path != digestPath("records", record.Digest, "") {
			return fmt.Errorf("publication record %d is invalid", index)
		}
	}
	return nil
}
