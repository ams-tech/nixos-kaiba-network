package signedboot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const signedBootDeviceClass = "raspberry-pi-5"

// SignatureRequester is injectable for tests. Production callers use
// signinggate.RequestSignature and a linker-fixed socket path.
type SignatureRequester func(context.Context, string, []byte) (signinggate.Result, error)

// SignConfig contains public, immutable production configuration. It contains
// no PIN, private-key path, module path, or runtime-selectable provider.
type SignConfig struct {
	GateSocketPath               string
	SignerID                     string
	CohortID                     string
	PKCS11URI                    string
	ExpectedPublicKeyPath        string
	ExpectedPublicKeyFingerprint bundle.Digest
	RequestSignature             SignatureRequester
}

// Sign revalidates an exact signing plan, requests one gate-authorized
// signature, emits canonical Raspberry Pi boot.sig text, and atomically
// publishes the public signing result directory.
func Sign(ctx context.Context, planDirectory, outputDirectory string, config SignConfig) error {
	if ctx == nil {
		return errors.New("signing context is required")
	}
	if pathsOverlap(planDirectory, outputDirectory) {
		return errors.New("signing output must not overlap the plan directory")
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("validate signing output: %w", err)
	}
	if err := validateSocketPath(config.GateSocketPath); err != nil {
		return err
	}
	if err := config.ExpectedPublicKeyFingerprint.Validate(); err != nil {
		return fmt.Errorf("configured public-key fingerprint: %w", err)
	}
	policy, err := signing.NewDevelopmentYubiKeyPolicy(
		config.SignerID, config.CohortID, config.PKCS11URI, config.ExpectedPublicKeyFingerprint,
	)
	if err != nil {
		return fmt.Errorf("configured signer policy: %w", err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return fmt.Errorf("digest configured signer policy: %w", err)
	}

	loaded, err := LoadPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	expectedPEM, expectedFingerprint, err := readExpectedPublicKey(config.ExpectedPublicKeyPath)
	if err != nil {
		return err
	}
	if expectedFingerprint != config.ExpectedPublicKeyFingerprint {
		return errors.New("configured public key does not match the linker-fixed fingerprint")
	}
	if loaded.Plan.PublicKeyFingerprint != config.ExpectedPublicKeyFingerprint || !bytes.Equal(loaded.PublicPEM, expectedPEM) {
		return errors.New("signing plan public key is not the linker-fixed expected public key")
	}
	if loaded.Plan.SignerPolicyDigest != policyDigest {
		return errors.New("signing plan does not bind the linker-fixed signer policy")
	}

	request := config.RequestSignature
	if request == nil {
		request = signinggate.RequestSignature
	}
	gateResult, err := request(ctx, config.GateSocketPath, append([]byte(nil), loaded.BootImage...))
	if err != nil {
		return fmt.Errorf("request boot-image signature: %w", err)
	}
	if err := gateResult.ReceiptDigest.Validate(); err != nil {
		return fmt.Errorf("signing-gate receipt digest: %w", err)
	}
	if gateResult.ReleaseIntentDigest != loaded.Plan.ReleaseIntentDigest {
		return errors.New("signing-gate release intent does not match the signing plan")
	}
	rawSignature, err := signing.ParseSignatureHex([]byte(gateResult.SignatureHex))
	if err != nil {
		return fmt.Errorf("signing-gate signature: %w", err)
	}
	document, err := rpi5bootsig.New(loaded.Plan.BootImageDigest, loaded.Plan.SourceDateEpoch, rawSignature)
	if err != nil {
		return fmt.Errorf("construct Raspberry Pi boot signature: %w", err)
	}
	if err := document.Verify(loaded.PublicKey); err != nil {
		return fmt.Errorf("verify signing-gate signature: %w", err)
	}
	bootSignature, err := document.MarshalText()
	if err != nil {
		return fmt.Errorf("encode Raspberry Pi boot signature: %w", err)
	}

	// The signing gate may wait for operator touch. Re-open every public input
	// after that wait so an artifact or key substitution cannot be published.
	revalidated, err := LoadPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("revalidate signing plan: %w", err)
	}
	if !sameLoadedPlan(loaded, revalidated) {
		return errors.New("signing plan changed while the signing gate was active")
	}
	revalidatedExpectedPEM, revalidatedExpectedFingerprint, err := readExpectedPublicKey(config.ExpectedPublicKeyPath)
	if err != nil {
		return fmt.Errorf("revalidate configured public key: %w", err)
	}
	if revalidatedExpectedFingerprint != expectedFingerprint || !bytes.Equal(revalidatedExpectedPEM, expectedPEM) {
		return errors.New("configured public key changed while the signing gate was active")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	result := Result{
		SchemaVersion: ResultSchemaV1Alpha2, PlanID: loaded.Plan.PlanID,
		PlanDigest: loaded.PlanDigest, ReleaseIntentDigest: loaded.Plan.ReleaseIntentDigest,
		BootImageDigest:     loaded.Plan.BootImageDigest,
		BootImageSizeBytes:  loaded.Plan.BootImageSizeBytes,
		BootSignatureDigest: bundle.Sum(bootSignature), BootSignatureSizeBytes: uint64(len(bootSignature)),
		PublicKeyFingerprint: loaded.Plan.PublicKeyFingerprint,
		SignerPolicyDigest:   loaded.Plan.SignerPolicyDigest, GateReceiptDigest: gateResult.ReceiptDigest,
		SourceDateEpoch: loaded.Plan.SourceDateEpoch,
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		return err
	}
	if err := createAtomicDirectory(outputDirectory, map[string][]byte{
		"boot.sig": bootSignature, "signing-result.json": jsonFile(resultJSON),
	}); err != nil {
		return fmt.Errorf("publish signing result: %w", err)
	}
	return nil
}

// Finalize validates a plan and signing result without contacting any signer,
// then atomically publishes a self-contained, public signed-boot bundle.
func Finalize(planDirectory, signedDirectory, outputDirectory string) error {
	if pathsOverlap(planDirectory, signedDirectory) || pathsOverlap(planDirectory, outputDirectory) || pathsOverlap(signedDirectory, outputDirectory) {
		return errors.New("plan, signing result, and final output paths must not overlap")
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("validate final output: %w", err)
	}
	loadedPlan, err := LoadPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	loadedResult, err := LoadResultDirectory(signedDirectory)
	if err != nil {
		return err
	}
	if err := verifyBindings(loadedPlan, loadedResult); err != nil {
		return err
	}

	// Re-open both public boundaries before publishing their snapshots.
	revalidatedPlan, err := LoadPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("revalidate signing plan: %w", err)
	}
	revalidatedResult, err := LoadResultDirectory(signedDirectory)
	if err != nil {
		return fmt.Errorf("revalidate signing result: %w", err)
	}
	if !sameLoadedPlan(loadedPlan, revalidatedPlan) || !sameLoadedResult(loadedResult, revalidatedResult) {
		return errors.New("signing inputs changed while finalizing")
	}
	if err := verifyBindings(revalidatedPlan, revalidatedResult); err != nil {
		return fmt.Errorf("revalidate signing bindings: %w", err)
	}

	manifest, err := bundle.NewManifest(
		loadedPlan.Plan.PlanID,
		signedBootDeviceClass,
		loadedPlan.Plan.SignerPolicyDigest,
		[]bundle.Artifact{
			{Role: bundle.RoleBootImage, Digest: loadedPlan.Plan.BootImageDigest, SizeBytes: loadedPlan.Plan.BootImageSizeBytes},
			{Role: bundle.RoleBootPublicKey, Digest: bundle.Sum(loadedPlan.PublicPEM), SizeBytes: uint64(len(loadedPlan.PublicPEM))},
			{Role: bundle.RoleBootSignature, Digest: loadedResult.Result.BootSignatureDigest, SizeBytes: loadedResult.Result.BootSignatureSizeBytes},
		},
	)
	if err != nil {
		return fmt.Errorf("construct signed-boot manifest: %w", err)
	}
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		return err
	}
	if err := createAtomicDirectory(outputDirectory, map[string][]byte{
		"boot.img": loadedPlan.BootImage, "boot.sig": loadedResult.BootSig,
		"public.pem": loadedPlan.PublicPEM, "signing-plan.json": jsonFile(loadedPlan.PlanJSON),
		"release-intent.json": jsonFile(loadedPlan.ReleaseIntentJSON),
		"signing-result.json": jsonFile(loadedResult.ResultJSON), "manifest.json": jsonFile(manifestJSON),
	}); err != nil {
		return fmt.Errorf("publish signed-boot bundle: %w", err)
	}
	return nil
}

func verifyBindings(plan LoadedPlan, signed LoadedResult) error {
	result := signed.Result
	if result.PlanID != plan.Plan.PlanID || result.PlanDigest != plan.PlanDigest {
		return errors.New("signing result does not bind the exact signing plan")
	}
	if result.ReleaseIntentDigest != plan.Plan.ReleaseIntentDigest {
		return errors.New("signing result does not bind the release intent")
	}
	if result.BootImageDigest != plan.Plan.BootImageDigest || result.BootImageSizeBytes != plan.Plan.BootImageSizeBytes {
		return errors.New("signing result boot image does not match the signing plan")
	}
	if result.PublicKeyFingerprint != plan.Plan.PublicKeyFingerprint || result.SourceDateEpoch != plan.Plan.SourceDateEpoch {
		return errors.New("signing result signer or timestamp does not match the signing plan")
	}
	if result.SignerPolicyDigest != plan.Plan.SignerPolicyDigest {
		return errors.New("signing result signer policy does not match the signing plan")
	}
	if result.BootSignatureDigest != bundle.Sum(signed.BootSig) || result.BootSignatureSizeBytes != uint64(len(signed.BootSig)) {
		return errors.New("boot.sig does not match the signing result")
	}
	document, err := rpi5bootsig.Parse(signed.BootSig)
	if err != nil {
		return fmt.Errorf("parse canonical Raspberry Pi boot signature: %w", err)
	}
	canonical, err := document.MarshalText()
	if err != nil {
		return fmt.Errorf("canonicalize Raspberry Pi boot signature: %w", err)
	}
	if !bytes.Equal(canonical, signed.BootSig) {
		return errors.New("boot.sig is not canonical")
	}
	if document.ImageDigest != plan.Plan.BootImageDigest || document.Timestamp != plan.Plan.SourceDateEpoch {
		return errors.New("boot.sig does not bind the planned image digest and timestamp")
	}
	if err := document.Verify(plan.PublicKey); err != nil {
		return fmt.Errorf("verify Raspberry Pi boot signature: %w", err)
	}
	return nil
}

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || strings.IndexByte(path, 0) >= 0 {
		return errors.New("signing gate socket path must be absolute and clean")
	}
	return nil
}
