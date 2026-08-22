package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

func signOwnedRecovery(ctx context.Context, planDirectory, outputDirectory string, deps dependencies) error {
	if ctx == nil {
		return errors.New("owned-recovery signing requires a context")
	}
	if deps.request == nil || deps.updater == nil || deps.extractor == nil {
		return errors.New("owned-recovery signing dependencies are incomplete")
	}
	if err := validateRuntimeConfig(deps.config); err != nil {
		return err
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("owned-recovery signed output: %w", err)
	}
	if pathsOverlap(planDirectory, outputDirectory) {
		return errors.New("owned-recovery plan and signed output directories must not overlap")
	}
	plan, err := loadOwnedPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	if err := validatePinnedOwnedPlan(plan, deps.config); err != nil {
		return err
	}
	publicKey, _, publicKeyBinary, err := eepromsigning.ParsePublicKey(plan.PublicPEM)
	if err != nil {
		return err
	}

	workDirectory, err := makePrivateWorkDirectory("owned-recovery-sign")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDirectory)
	reused, err := extractFreshVerifiedSignatures(ctx, deps, workDirectory, plan)
	if err != nil {
		return fmt.Errorf("verify reusable fresh EEPROM signatures: %w", err)
	}
	if err := stageUpdaterInputs(workDirectory, ownedAsFreshPlan(plan)); err != nil {
		return err
	}
	callbacks := newOwnedCallbackState(plan.Plan, publicKey, deps.config.GateSocketPath, deps.request, reused)
	updaterErr := deps.updater(ctx, updateInvocation{
		WorkDir: workDirectory, SourceDateEpoch: plan.Plan.FreshEEPROMPlan.SourceDateEpoch,
		SignRecovery: true, Config: deps.config,
	}, callbacks.sign)
	if callbackErr := callbacks.finalError(); callbackErr != nil {
		return callbackErr
	}
	if updaterErr != nil {
		return updaterErr
	}
	signatureResult, recoverySignature, err := callbacks.result()
	if err != nil {
		return err
	}
	outputs, err := readOwnedUpdaterOutputs(workDirectory)
	if err != nil {
		return err
	}
	if !bytes.Equal(outputs.SignedEEPROM, plan.ExpectedSignedEEPROM) || !bytes.Equal(outputs.EEPROMMetadata, plan.ExpectedEEPROMMetadata) {
		return errors.New("owned-recovery updater changed the verified fresh EEPROM or metadata")
	}
	embeddedSignature, err := eepromsigning.VerifySignedFirmware(plan.OriginalRecovery, outputs.SignedRecovery, publicKeyBinary, publicKey)
	if err != nil {
		return fmt.Errorf("verify owned recovery bootcode5.bin: %w", err)
	}
	if !bytes.Equal(embeddedSignature, recoverySignature) {
		return errors.New("owned recovery embeds a signature different from the one approved by the gate")
	}
	result, err := newOwnedResult(plan.Plan, signatureResult, outputs)
	if err != nil {
		return err
	}
	current, err := loadOwnedPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("re-read owned-recovery plan: %w", err)
	}
	if !sameOwnedPlan(plan, current) {
		return errors.New("owned-recovery plan changed while signing")
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		return err
	}
	return createAtomicDirectory(outputDirectory, map[string][]byte{
		"pieeprom.bin": outputs.SignedEEPROM, "pieeprom.sig": outputs.EEPROMMetadata,
		"bootcode5.bin": outputs.SignedRecovery, "result.json": jsonFile(resultJSON),
	})
}

func finalizeOwnedRecovery(ctx context.Context, planDirectory, signedDirectory, outputDirectory string, deps dependencies) error {
	if ctx == nil {
		return errors.New("owned-recovery finalization requires a context")
	}
	if deps.updater == nil || deps.extractor == nil {
		return errors.New("owned-recovery finalization dependencies are incomplete")
	}
	if err := validateRuntimeConfig(deps.config); err != nil {
		return err
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("owned-recovery final output: %w", err)
	}
	if pathsOverlap(planDirectory, signedDirectory) || pathsOverlap(planDirectory, outputDirectory) || pathsOverlap(signedDirectory, outputDirectory) {
		return errors.New("owned-recovery plan, signed result, and final output must not overlap")
	}
	plan, err := loadOwnedPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	if err := validatePinnedOwnedPlan(plan, deps.config); err != nil {
		return err
	}
	signed, err := loadOwnedResultDirectory(signedDirectory)
	if err != nil {
		return err
	}
	if err := eepromsigning.VerifyOwnedRecoveryBindings(plan.Plan, signed.Result); err != nil {
		return err
	}
	if !bytes.Equal(signed.SignedEEPROM, plan.ExpectedSignedEEPROM) || !bytes.Equal(signed.EEPROMMetadata, plan.ExpectedEEPROMMetadata) {
		return errors.New("owned-recovery result changed the verified fresh EEPROM outputs")
	}

	workDirectory, err := makePrivateWorkDirectory("owned-recovery-finalize")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDirectory)
	reused, err := extractFreshVerifiedSignatures(ctx, deps, workDirectory, plan)
	if err != nil {
		return fmt.Errorf("verify reusable fresh EEPROM signatures: %w", err)
	}
	publicKey, _, publicKeyBinary, err := eepromsigning.ParsePublicKey(plan.PublicPEM)
	if err != nil {
		return err
	}
	recoverySignature, err := eepromsigning.VerifySignedFirmware(plan.OriginalRecovery, signed.SignedRecovery, publicKeyBinary, publicKey)
	if err != nil {
		return fmt.Errorf("verify owned recovery bootcode5.bin: %w", err)
	}
	if bundle.Sum(recoverySignature) != signed.Result.Signature.SignatureDigest {
		return errors.New("owned recovery embedded signature digest differs from result.json")
	}
	if err := replayOwnedUpdater(ctx, deps, workDirectory, plan, signed, recoverySignature, reused); err != nil {
		return fmt.Errorf("offline deterministic owned-recovery replay: %w", err)
	}
	currentPlan, err := loadOwnedPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("re-read owned-recovery plan: %w", err)
	}
	currentResult, err := loadOwnedResultDirectory(signedDirectory)
	if err != nil {
		return fmt.Errorf("re-read owned-recovery result: %w", err)
	}
	if !sameOwnedPlan(plan, currentPlan) || !sameOwnedResult(signed, currentResult) {
		return errors.New("owned-recovery plan or result changed while finalizing")
	}
	return createAtomicDirectory(outputDirectory, map[string][]byte{
		"plan.json": jsonFile(plan.PlanJSON), "result.json": jsonFile(signed.ResultJSON),
		"release-intent.json": jsonFile(plan.ReleaseIntentJSON), "public.pem": plan.PublicPEM,
		"recovery.original.bin": plan.OriginalRecovery, "bootcode5.bin": signed.SignedRecovery,
		"pieeprom.bin": signed.SignedEEPROM, "pieeprom.sig": signed.EEPROMMetadata,
	})
}

type ownedUpdaterOutputs struct {
	SignedEEPROM, EEPROMMetadata, SignedRecovery []byte
}

func readOwnedUpdaterOutputs(workDirectory string) (ownedUpdaterOutputs, error) {
	eeprom, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "pieeprom.bin"), maxEEPROMBytes)
	if err != nil {
		return ownedUpdaterOutputs{}, fmt.Errorf("read replayed signed EEPROM: %w", err)
	}
	metadata, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "pieeprom.sig"), maxUpdateMetadataBytes)
	if err != nil {
		return ownedUpdaterOutputs{}, fmt.Errorf("read replayed EEPROM metadata: %w", err)
	}
	recovery, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "bootcode5.bin"), maxRecoveryBytes)
	if err != nil {
		return ownedUpdaterOutputs{}, fmt.Errorf("read signed owned recovery: %w", err)
	}
	return ownedUpdaterOutputs{SignedEEPROM: eeprom, EEPROMMetadata: metadata, SignedRecovery: recovery}, nil
}

func newOwnedResult(plan eepromsigning.OwnedRecoveryPlan, signature eepromsigning.SignatureResult, outputs ownedUpdaterOutputs) (eepromsigning.OwnedRecoveryResult, error) {
	digest, err := plan.Digest()
	if err != nil {
		return eepromsigning.OwnedRecoveryResult{}, err
	}
	fresh := plan.FreshEEPROMPlan
	result := eepromsigning.OwnedRecoveryResult{
		SchemaVersion: eepromsigning.OwnedRecoveryResultSchemaV1Alpha1,
		PlanID:        plan.PlanID, PlanDigest: digest, ReleaseIntentDigest: fresh.ReleaseIntentDigest,
		EEPROMReleaseManifestDigest: fresh.EEPROMReleaseManifestDigest,
		SignerPolicyDigest:          fresh.SignerPolicyDigest, PublicKeyFingerprint: fresh.PublicKeyFingerprint,
		CustomerKeyHash: fresh.CustomerKeyHash, SourceDateEpoch: fresh.SourceDateEpoch,
		UpdaterMode:  eepromsigning.UpdaterModeOwnedRecovery,
		RecoveryMode: eepromsigning.RecoveryModeCustomerCounterSigned, Signature: signature,
		OwnedRecoveryBootcode: fileRecord(outputs.SignedRecovery), ReplayedSignedEEPROM: fileRecord(outputs.SignedEEPROM),
		ReplayedEEPROMMetadata: fileRecord(outputs.EEPROMMetadata),
	}
	if err := eepromsigning.VerifyOwnedRecoveryBindings(plan, result); err != nil {
		return eepromsigning.OwnedRecoveryResult{}, err
	}
	return result, nil
}

func ownedAsFreshPlan(plan loadedOwnedPlan) loadedPlan {
	return loadedPlan{
		Plan: plan.Plan.FreshEEPROMPlan, ReleaseIntentJSON: plan.ReleaseIntentJSON,
		OriginalEEPROM: plan.OriginalEEPROM, OriginalRecovery: plan.OriginalRecovery,
		OriginalBootcode: plan.OriginalBootcode, OriginalBootsys: plan.OriginalBootsys,
		BootConfig: plan.BootConfig, PublicPEM: plan.PublicPEM,
	}
}

func validatePinnedOwnedPlan(plan loadedOwnedPlan, config runtimeConfig) error {
	return validatePinnedRelease(ownedAsFreshPlan(plan), config)
}

func extractFreshVerifiedSignatures(ctx context.Context, deps dependencies, workDirectory string, plan loadedOwnedPlan) (eepromsigning.VerifiedSignatures, error) {
	freshWorkDirectory := filepath.Join(workDirectory, "fresh-verification")
	if err := os.Mkdir(freshWorkDirectory, 0o700); err != nil {
		return eepromsigning.VerifiedSignatures{}, fmt.Errorf("create fresh-verification work directory: %w", err)
	}
	original, err := extractEEPROM(ctx, deps, freshWorkDirectory, "original", plan.OriginalEEPROM)
	if err != nil {
		return eepromsigning.VerifiedSignatures{}, err
	}
	signed, err := extractEEPROM(ctx, deps, freshWorkDirectory, "signed", plan.ExpectedSignedEEPROM)
	if err != nil {
		return eepromsigning.VerifiedSignatures{}, err
	}
	freshPlan := ownedAsFreshPlan(plan)
	freshResult := loadedResult{
		Result: plan.Plan.FreshEEPROMResult, SignedEEPROM: plan.ExpectedSignedEEPROM,
		EEPROMUpdateMetadata: plan.ExpectedEEPROMMetadata, FreshRecovery: plan.FreshRecovery,
	}
	verified, err := verifyFinalization(freshPlan, freshResult, original, signed)
	if err != nil {
		return eepromsigning.VerifiedSignatures{}, err
	}
	// Do not trust a nested result record or extracted signed sections alone.
	// Replay the fresh -f updater with the verified signatures so ancillary
	// EEPROM bytes are covered by the same deterministic boundary as the
	// original fresh-board finalizer.
	if err := replayAndCompareUpdater(ctx, deps, freshWorkDirectory, freshPlan, freshResult, verified); err != nil {
		return eepromsigning.VerifiedSignatures{}, fmt.Errorf("replay verified fresh EEPROM: %w", err)
	}
	return verified, nil
}

type ownedCallbackState struct {
	mu             sync.Mutex
	plan           eepromsigning.OwnedRecoveryPlan
	publicKey      *rsa.PublicKey
	gateSocketPath string
	request        signatureRequester
	reused         [][]byte
	index          int
	approved       eepromsigning.SignatureResult
	approvedBytes  []byte
	err            error
}

func newOwnedCallbackState(plan eepromsigning.OwnedRecoveryPlan, publicKey *rsa.PublicKey, socket string, request signatureRequester, reused eepromsigning.VerifiedSignatures) *ownedCallbackState {
	return &ownedCallbackState{plan: plan, publicKey: publicKey, gateSocketPath: socket, request: request,
		reused: [][]byte{append([]byte(nil), reused.Bootcode...), append([]byte(nil), reused.Bootsys...), append([]byte(nil), reused.BootConfig...)}}
}

func (state *ownedCallbackState) expected() []eepromsigning.SigningInput {
	return append([]eepromsigning.SigningInput{state.plan.OwnedRecoverySigningInput}, state.plan.FreshEEPROMPlan.SigningInputs...)
}

func (state *ownedCallbackState) sign(ctx context.Context, artifact []byte) (string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return "", state.err
	}
	expected := state.expected()
	if state.index >= len(expected) {
		state.err = errors.New("pinned -fr updater made an extra signing callback")
		return "", state.err
	}
	planned := expected[state.index]
	if uint64(len(artifact)) != planned.SizeBytes || bundle.Sum(artifact) != planned.Digest {
		state.err = fmt.Errorf("pinned -fr updater callback %d does not match planned %s bytes", state.index+1, planned.Role)
		return "", state.err
	}
	if state.index > 0 {
		signature := state.reused[state.index-1]
		if err := eepromsigning.VerifySignature(state.publicKey, artifact, signature); err != nil {
			state.err = fmt.Errorf("reused %s signature is invalid: %w", planned.Role, err)
			return "", state.err
		}
		state.index++
		return hex.EncodeToString(signature), nil
	}
	gate, err := state.request(ctx, state.gateSocketPath, append([]byte(nil), artifact...))
	if err != nil {
		state.err = fmt.Errorf("signing gate rejected owned recovery: %w", err)
		return "", state.err
	}
	if gate.ReleaseIntentDigest != state.plan.FreshEEPROMPlan.ReleaseIntentDigest {
		state.err = errors.New("signing gate returned a different release intent for owned recovery")
		return "", state.err
	}
	if err := gate.ReceiptDigest.Validate(); err != nil {
		state.err = fmt.Errorf("owned-recovery gate receipt: %w", err)
		return "", state.err
	}
	signature, err := signing.ParseSignatureHex([]byte(gate.SignatureHex))
	if err != nil || hex.EncodeToString(signature) != gate.SignatureHex {
		state.err = errors.New("owned-recovery gate signature is not canonical RSA-2048")
		return "", state.err
	}
	if err := eepromsigning.VerifySignature(state.publicKey, artifact, signature); err != nil {
		state.err = fmt.Errorf("owned-recovery gate signature does not match the planned customer key: %w", err)
		return "", state.err
	}
	state.approved = eepromsigning.SignatureResult{Role: planned.Role, InputDigest: planned.Digest, InputSizeBytes: planned.SizeBytes,
		SignatureDigest: bundle.Sum(signature), SignatureSizeBytes: uint64(len(signature)), GateReceiptDigest: gate.ReceiptDigest}
	state.approvedBytes = append([]byte(nil), signature...)
	state.index++
	return gate.SignatureHex, nil
}

func (state *ownedCallbackState) finalError() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.err
}
func (state *ownedCallbackState) result() (eepromsigning.SignatureResult, []byte, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return eepromsigning.SignatureResult{}, nil, state.err
	}
	if state.index != 4 {
		return eepromsigning.SignatureResult{}, nil, fmt.Errorf("pinned -fr updater made %d callbacks, want exactly 4", state.index)
	}
	return state.approved, append([]byte(nil), state.approvedBytes...), nil
}

func replayOwnedUpdater(ctx context.Context, deps dependencies, workDirectory string, plan loadedOwnedPlan, signed loadedOwnedResult, recovery []byte, reused eepromsigning.VerifiedSignatures) error {
	if err := stageUpdaterInputs(workDirectory, ownedAsFreshPlan(plan)); err != nil {
		return err
	}
	state := &replayCallbackState{expected: append([]eepromsigning.SigningInput{plan.Plan.OwnedRecoverySigningInput}, plan.Plan.FreshEEPROMPlan.SigningInputs...),
		signatures: [][]byte{append([]byte(nil), recovery...), append([]byte(nil), reused.Bootcode...), append([]byte(nil), reused.Bootsys...), append([]byte(nil), reused.BootConfig...)}}
	err := deps.updater(ctx, updateInvocation{WorkDir: workDirectory, SourceDateEpoch: plan.Plan.FreshEEPROMPlan.SourceDateEpoch, SignRecovery: true, Config: deps.config}, state.sign)
	if callbackErr := state.finalError(); callbackErr != nil {
		return callbackErr
	}
	if err != nil {
		return err
	}
	if err := state.complete(); err != nil {
		return err
	}
	outputs, err := readOwnedUpdaterOutputs(workDirectory)
	if err != nil {
		return err
	}
	if !bytes.Equal(outputs.SignedEEPROM, signed.SignedEEPROM) || !bytes.Equal(outputs.EEPROMMetadata, signed.EEPROMMetadata) || !bytes.Equal(outputs.SignedRecovery, signed.SignedRecovery) {
		return errors.New("offline -fr replay differs from the supplied owned-recovery result")
	}
	return nil
}
