package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

var extractedFileLimits = map[string]int64{
	"bootcode.bin": maxComponentBytes,
	"bootsys":      maxComponentBytes,
	"bootconf.txt": maxBootConfigBytes,
	"bootconf.sig": maxUpdateMetadataBytes,
	"pubkey.bin":   512,
	"cacert.der":   16 * 1024,
	"updatetime":   8,
}

type extractedEEPROM struct {
	Bootcode        []byte
	Bootsys         []byte
	BootConfig      []byte
	BootConfigSig   []byte
	PublicKeyBinary []byte
	CACertDER       []byte
	UpdateTime      []byte
}

type extractorRunner func(context.Context, runtimeConfig, string, string) error

func signEEPROM(ctx context.Context, planDirectory, outputDirectory string, deps dependencies) error {
	if ctx == nil {
		return errors.New("signing requires a context")
	}
	if deps.request == nil || deps.updater == nil || deps.extractor == nil {
		return errors.New("signing dependencies are incomplete")
	}
	if err := validateRuntimeConfig(deps.config); err != nil {
		return err
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("signed output: %w", err)
	}
	if pathsOverlap(planDirectory, outputDirectory) {
		return errors.New("plan and signed output directories must not overlap")
	}
	plan, err := loadPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	if err := validatePinnedRelease(plan, deps.config); err != nil {
		return err
	}
	publicKey, _, _, err := eepromsigning.ParsePublicKey(plan.PublicPEM)
	if err != nil {
		return err
	}

	workDirectory, err := makePrivateWorkDirectory("sign")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDirectory)
	if err := stageUpdaterInputs(workDirectory, plan); err != nil {
		return err
	}

	callbacks := newCallbackState(plan.Plan, publicKey, deps.config.GateSocketPath, deps.request)
	err = deps.updater(ctx, updateInvocation{
		WorkDir: workDirectory, SourceDateEpoch: plan.Plan.SourceDateEpoch, Config: deps.config,
	}, callbacks.sign)
	if callbackError := callbacks.finalError(); callbackError != nil {
		return callbackError
	}
	if err != nil {
		return err
	}
	signatures, err := callbacks.results()
	if err != nil {
		return err
	}

	signedEEPROM, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "pieeprom.bin"), maxEEPROMBytes)
	if err != nil {
		return fmt.Errorf("read signed EEPROM: %w", err)
	}
	metadata, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "pieeprom.sig"), maxUpdateMetadataBytes)
	if err != nil {
		return fmt.Errorf("read EEPROM update metadata: %w", err)
	}
	freshRecovery, err := readAbsoluteRegularFile(filepath.Join(workDirectory, "bootcode5.bin"), maxRecoveryBytes)
	if err != nil {
		return fmt.Errorf("read fresh-board recovery: %w", err)
	}
	result, err := newResult(plan.Plan, signatures, signedEEPROM, metadata, freshRecovery)
	if err != nil {
		return err
	}

	originalExtracted, err := extractEEPROM(ctx, deps, workDirectory, "original", plan.OriginalEEPROM)
	if err != nil {
		return err
	}
	extracted, err := extractEEPROM(ctx, deps, workDirectory, "signed", signedEEPROM)
	if err != nil {
		return err
	}
	if _, err := verifyFinalization(plan, loadedResult{
		Result: result, SignedEEPROM: signedEEPROM, EEPROMUpdateMetadata: metadata, FreshRecovery: freshRecovery,
	}, originalExtracted, extracted); err != nil {
		return fmt.Errorf("verify pinned updater result: %w", err)
	}

	currentPlan, err := loadPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("re-read EEPROM signing plan: %w", err)
	}
	if !samePlan(plan, currentPlan) {
		return errors.New("EEPROM signing plan changed while signing")
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		return err
	}
	return createAtomicDirectory(outputDirectory, map[string][]byte{
		"pieeprom.bin":  signedEEPROM,
		"pieeprom.sig":  metadata,
		"bootcode5.bin": freshRecovery,
		"result.json":   jsonFile(resultJSON),
	})
}

func finalizeEEPROM(ctx context.Context, planDirectory, signedDirectory, outputDirectory string, deps dependencies) error {
	if ctx == nil {
		return errors.New("finalization requires a context")
	}
	if deps.extractor == nil || deps.updater == nil {
		return errors.New("finalization dependencies are incomplete")
	}
	if err := validateRuntimeConfig(deps.config); err != nil {
		return err
	}
	if err := validateNewOutputPath(outputDirectory); err != nil {
		return fmt.Errorf("final bundle output: %w", err)
	}
	if pathsOverlap(planDirectory, signedDirectory) || pathsOverlap(planDirectory, outputDirectory) || pathsOverlap(signedDirectory, outputDirectory) {
		return errors.New("plan, signed result, and final bundle directories must not overlap")
	}
	plan, err := loadPlanDirectory(planDirectory)
	if err != nil {
		return err
	}
	if err := validatePinnedRelease(plan, deps.config); err != nil {
		return err
	}
	signed, err := loadResultDirectory(signedDirectory)
	if err != nil {
		return err
	}
	if err := eepromsigning.VerifyBindings(plan.Plan, signed.Result); err != nil {
		return err
	}

	workDirectory, err := makePrivateWorkDirectory("finalize")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDirectory)
	originalExtracted, err := extractEEPROM(ctx, deps, workDirectory, "original", plan.OriginalEEPROM)
	if err != nil {
		return err
	}
	extracted, err := extractEEPROM(ctx, deps, workDirectory, "signed", signed.SignedEEPROM)
	if err != nil {
		return err
	}
	verifiedSignatures, err := verifyFinalization(plan, signed, originalExtracted, extracted)
	if err != nil {
		return fmt.Errorf("offline EEPROM finalization: %w", err)
	}
	if err := replayAndCompareUpdater(ctx, deps, workDirectory, plan, signed, verifiedSignatures); err != nil {
		return fmt.Errorf("offline deterministic EEPROM replay: %w", err)
	}

	currentPlan, err := loadPlanDirectory(planDirectory)
	if err != nil {
		return fmt.Errorf("re-read EEPROM signing plan: %w", err)
	}
	currentSigned, err := loadResultDirectory(signedDirectory)
	if err != nil {
		return fmt.Errorf("re-read EEPROM signing result: %w", err)
	}
	if !samePlan(plan, currentPlan) || !sameResult(signed, currentSigned) {
		return errors.New("EEPROM plan or signed result changed while finalizing")
	}

	return createAtomicDirectory(outputDirectory, map[string][]byte{
		"plan.json":             jsonFile(plan.PlanJSON),
		"release-intent.json":   jsonFile(plan.ReleaseIntentJSON),
		"pieeprom.original.bin": plan.OriginalEEPROM,
		"recovery.original.bin": plan.OriginalRecovery,
		"bootcode.original.bin": plan.OriginalBootcode,
		"bootsys.original":      plan.OriginalBootsys,
		"boot.conf":             plan.BootConfig,
		"public.pem":            plan.PublicPEM,
		"pieeprom.bin":          signed.SignedEEPROM,
		"pieeprom.sig":          signed.EEPROMUpdateMetadata,
		"bootcode5.bin":         signed.FreshRecovery,
		"result.json":           jsonFile(signed.ResultJSON),
		"bootcode.signed.bin":   extracted.Bootcode,
		"bootsys.signed":        extracted.Bootsys,
		"bootconf.signed.txt":   extracted.BootConfig,
		"bootconf.sig":          extracted.BootConfigSig,
		"pubkey.bin":            extracted.PublicKeyBinary,
		"cacert.der":            extracted.CACertDER,
		"updatetime":            extracted.UpdateTime,
	})
}

type callbackState struct {
	mu             sync.Mutex
	plan           eepromsigning.Plan
	publicKey      *rsa.PublicKey
	gateSocketPath string
	request        signatureRequester
	index          int
	signatures     []eepromsigning.SignatureResult
	stickyError    error
}

type replayCallbackState struct {
	mu         sync.Mutex
	expected   []eepromsigning.SigningInput
	signatures [][]byte
	index      int
	err        error
}

func replayAndCompareUpdater(
	ctx context.Context,
	deps dependencies,
	workDirectory string,
	plan loadedPlan,
	signed loadedResult,
	verified eepromsigning.VerifiedSignatures,
) error {
	if err := stageUpdaterInputs(workDirectory, plan); err != nil {
		return err
	}
	state := &replayCallbackState{
		expected: append([]eepromsigning.SigningInput(nil), plan.Plan.SigningInputs...),
		signatures: [][]byte{
			append([]byte(nil), verified.Bootcode...),
			append([]byte(nil), verified.Bootsys...),
			append([]byte(nil), verified.BootConfig...),
		},
	}
	updaterError := deps.updater(ctx, updateInvocation{
		WorkDir: workDirectory, SourceDateEpoch: plan.Plan.SourceDateEpoch, Config: deps.config,
	}, state.sign)
	if callbackError := state.finalError(); callbackError != nil {
		return callbackError
	}
	if updaterError != nil {
		return updaterError
	}
	if err := state.complete(); err != nil {
		return err
	}
	for _, output := range []struct {
		name     string
		expected []byte
		maximum  int64
	}{
		{name: "pieeprom.bin", expected: signed.SignedEEPROM, maximum: maxEEPROMBytes},
		{name: "pieeprom.sig", expected: signed.EEPROMUpdateMetadata, maximum: maxUpdateMetadataBytes},
		{name: "bootcode5.bin", expected: signed.FreshRecovery, maximum: maxRecoveryBytes},
	} {
		actual, err := readAbsoluteRegularFile(filepath.Join(workDirectory, output.name), output.maximum)
		if err != nil {
			return fmt.Errorf("read replayed %s: %w", output.name, err)
		}
		if !bytes.Equal(actual, output.expected) {
			return fmt.Errorf("replayed %s differs from the supplied signed result", output.name)
		}
	}
	return nil
}

func (state *replayCallbackState) sign(_ context.Context, artifact []byte) (string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return "", state.err
	}
	if state.index >= len(state.expected) || state.index >= len(state.signatures) {
		state.err = errors.New("pinned updater made an extra signing callback during offline replay")
		return "", state.err
	}
	expected := state.expected[state.index]
	if uint64(len(artifact)) != expected.SizeBytes || bundle.Sum(artifact) != expected.Digest {
		state.err = fmt.Errorf("pinned updater replay callback %d does not match planned %s bytes", state.index+1, expected.Role)
		return "", state.err
	}
	signature := state.signatures[state.index]
	if len(signature) != signing.RSASignatureBytes {
		state.err = fmt.Errorf("verified %s signature has the wrong size", expected.Role)
		return "", state.err
	}
	state.index++
	return hex.EncodeToString(signature), nil
}

func (state *replayCallbackState) finalError() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.err
}

func (state *replayCallbackState) complete() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return state.err
	}
	if state.index != len(state.expected) || state.index != len(state.signatures) {
		return fmt.Errorf("pinned updater made %d replay callbacks, want exactly %d", state.index, len(state.expected))
	}
	return nil
}

func newCallbackState(plan eepromsigning.Plan, publicKey *rsa.PublicKey, socketPath string, request signatureRequester) *callbackState {
	return &callbackState{plan: plan, publicKey: publicKey, gateSocketPath: socketPath, request: request}
}

func (state *callbackState) sign(ctx context.Context, artifact []byte) (string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.stickyError != nil {
		return "", state.stickyError
	}
	if state.index >= len(state.plan.SigningInputs) {
		state.stickyError = errors.New("pinned updater made an extra signing callback")
		return "", state.stickyError
	}
	planned := state.plan.SigningInputs[state.index]
	if uint64(len(artifact)) != planned.SizeBytes || bundle.Sum(artifact) != planned.Digest {
		state.stickyError = fmt.Errorf("pinned updater signing callback %d does not match planned %s bytes", state.index+1, planned.Role)
		return "", state.stickyError
	}
	gateResult, err := state.request(ctx, state.gateSocketPath, append([]byte(nil), artifact...))
	if err != nil {
		state.stickyError = fmt.Errorf("signing gate rejected %s: %w", planned.Role, err)
		return "", state.stickyError
	}
	if gateResult.ReleaseIntentDigest != state.plan.ReleaseIntentDigest {
		state.stickyError = fmt.Errorf("signing gate returned a different release intent for %s", planned.Role)
		return "", state.stickyError
	}
	if err := gateResult.ReceiptDigest.Validate(); err != nil {
		state.stickyError = fmt.Errorf("signing gate receipt for %s: %w", planned.Role, err)
		return "", state.stickyError
	}
	signature, err := signing.ParseSignatureHex([]byte(gateResult.SignatureHex))
	if err != nil {
		state.stickyError = fmt.Errorf("signing gate signature for %s: %w", planned.Role, err)
		return "", state.stickyError
	}
	if hex.EncodeToString(signature) != gateResult.SignatureHex {
		state.stickyError = fmt.Errorf("signing gate signature for %s is not canonical", planned.Role)
		return "", state.stickyError
	}
	if err := eepromsigning.VerifySignature(state.publicKey, artifact, signature); err != nil {
		state.stickyError = fmt.Errorf("signing gate signature for %s does not match the planned customer key: %w", planned.Role, err)
		return "", state.stickyError
	}
	state.signatures = append(state.signatures, eepromsigning.SignatureResult{
		Role: planned.Role, InputDigest: planned.Digest, InputSizeBytes: planned.SizeBytes,
		SignatureDigest: bundle.Sum(signature), SignatureSizeBytes: uint64(len(signature)),
		GateReceiptDigest: gateResult.ReceiptDigest,
	})
	state.index++
	return gateResult.SignatureHex, nil
}

func (state *callbackState) finalError() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.stickyError
}

func (state *callbackState) results() ([]eepromsigning.SignatureResult, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.stickyError != nil {
		return nil, state.stickyError
	}
	if state.index != len(state.plan.SigningInputs) {
		return nil, fmt.Errorf("pinned updater made %d signing callbacks, want exactly %d", state.index, len(state.plan.SigningInputs))
	}
	return append([]eepromsigning.SignatureResult(nil), state.signatures...), nil
}

func newResult(
	plan eepromsigning.Plan,
	signatures []eepromsigning.SignatureResult,
	signedEEPROM, updateMetadata, freshRecovery []byte,
) (eepromsigning.Result, error) {
	planDigest, err := plan.Digest()
	if err != nil {
		return eepromsigning.Result{}, err
	}
	result := eepromsigning.Result{
		SchemaVersion: eepromsigning.ResultSchemaV1Alpha1,
		PlanID:        plan.PlanID, PlanDigest: planDigest,
		ReleaseIntentDigest:         plan.ReleaseIntentDigest,
		EEPROMReleaseManifestDigest: plan.EEPROMReleaseManifestDigest,
		SignerPolicyDigest:          plan.SignerPolicyDigest,
		PublicKeyFingerprint:        plan.PublicKeyFingerprint,
		CustomerKeyHash:             plan.CustomerKeyHash,
		SourceDateEpoch:             plan.SourceDateEpoch,
		UpdaterMode:                 eepromsigning.UpdaterModeFreshBoard,
		RecoveryMode:                eepromsigning.RecoveryModeUnsigned,
		Signatures:                  append([]eepromsigning.SignatureResult(nil), signatures...),
		SignedEEPROM:                fileRecord(signedEEPROM),
		EEPROMUpdateMetadata:        fileRecord(updateMetadata),
		FreshRecoveryBootcode:       fileRecord(freshRecovery),
	}
	if err := eepromsigning.VerifyBindings(plan, result); err != nil {
		return eepromsigning.Result{}, err
	}
	return result, nil
}

func fileRecord(contents []byte) eepromsigning.File {
	return eepromsigning.File{Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents))}
}

func validatePinnedRelease(plan loadedPlan, config runtimeConfig) error {
	if plan.Plan.EEPROMReleaseManifestDigest != config.ExpectedEEPROMReleaseDigest {
		return errors.New("EEPROM signing plan does not use the linker-fixed EEPROM release")
	}
	if plan.Plan.FirmwareBuildEpoch != config.ExpectedFirmwareBuildEpoch {
		return errors.New("EEPROM signing plan does not use the linker-fixed firmware build epoch")
	}
	for label, pair := range map[string]struct {
		planned  bundle.Digest
		expected bundle.Digest
	}{
		"original EEPROM":   {plan.Plan.OriginalEEPROM.Digest, config.ExpectedOriginalEEPROMDigest},
		"original recovery": {plan.Plan.OriginalRecovery.Digest, config.ExpectedOriginalRecoveryDigest},
		"original bootcode": {plan.Plan.OriginalBootcode.Digest, config.ExpectedOriginalBootcodeDigest},
		"original bootsys":  {plan.Plan.OriginalBootsys.Digest, config.ExpectedOriginalBootsysDigest},
	} {
		if pair.planned != pair.expected {
			return fmt.Errorf("EEPROM signing plan %s does not match the linker-fixed EEPROM release", label)
		}
	}
	return nil
}

func makePrivateWorkDirectory(label string) (string, error) {
	directory, err := os.MkdirTemp("/tmp", ".kaiba-eeprom-"+label+"-*")
	if err != nil {
		return "", fmt.Errorf("create private EEPROM work directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}
	return directory, nil
}

func stageUpdaterInputs(workDirectory string, plan loadedPlan) error {
	for name, contents := range map[string][]byte{
		"pieeprom.original.bin": plan.OriginalEEPROM,
		"recovery.original.bin": plan.OriginalRecovery,
		"boot.conf":             plan.BootConfig,
		"public.pem":            plan.PublicPEM,
	} {
		path := filepath.Join(workDirectory, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o400)
		if err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
		if _, err := file.Write(contents); err != nil {
			_ = file.Close()
			return fmt.Errorf("stage %s: %w", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("stage %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
	}
	directory, err := os.Open(workDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func extractEEPROM(ctx context.Context, deps dependencies, workDirectory, label string, image []byte) (extractedEEPROM, error) {
	if label != "original" && label != "signed" {
		return extractedEEPROM{}, errors.New("invalid fixed EEPROM extraction label")
	}
	imagePath := filepath.Join(workDirectory, "verify-"+label+"-pieeprom.bin")
	file, err := os.OpenFile(imagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return extractedEEPROM{}, err
	}
	if _, err := file.Write(image); err != nil {
		_ = file.Close()
		return extractedEEPROM{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return extractedEEPROM{}, err
	}
	if err := file.Close(); err != nil {
		return extractedEEPROM{}, err
	}
	extractDirectory := filepath.Join(workDirectory, "extracted-"+label)
	if err := os.Mkdir(extractDirectory, 0o700); err != nil {
		return extractedEEPROM{}, err
	}
	if err := deps.extractor(ctx, deps.config, imagePath, extractDirectory); err != nil {
		return extractedEEPROM{}, fmt.Errorf("extract signed EEPROM: %w", err)
	}
	files, err := readExactDirectory(extractDirectory, extractedFileLimits)
	if err != nil {
		return extractedEEPROM{}, fmt.Errorf("load extracted signed EEPROM: %w", err)
	}
	return extractedEEPROM{
		Bootcode: files["bootcode.bin"], Bootsys: files["bootsys"],
		BootConfig: files["bootconf.txt"], BootConfigSig: files["bootconf.sig"],
		PublicKeyBinary: files["pubkey.bin"],
		CACertDER:       files["cacert.der"], UpdateTime: files["updatetime"],
	}, nil
}

func verifyFinalization(plan loadedPlan, signed loadedResult, original, extracted extractedEEPROM) (eepromsigning.VerifiedSignatures, error) {
	return eepromsigning.ExtractVerifiedSignatures(eepromsigning.FinalizationInput{
		Plan: plan.Plan, Result: signed.Result,
		OriginalEEPROM: plan.OriginalEEPROM, OriginalRecovery: plan.OriginalRecovery,
		OriginalBootcode: plan.OriginalBootcode, OriginalBootsys: plan.OriginalBootsys,
		BootConfig: plan.BootConfig, PublicKeyPEM: plan.PublicPEM,
		SignedEEPROM: signed.SignedEEPROM, EEPROMUpdateMetadata: signed.EEPROMUpdateMetadata,
		FreshRecoveryBootcode: signed.FreshRecovery,
		ExtractedBootcode:     extracted.Bootcode, ExtractedBootsys: extracted.Bootsys,
		ExtractedBootConfig: extracted.BootConfig, ExtractedBootConfigSig: extracted.BootConfigSig,
		ExtractedPublicKeyBinary: extracted.PublicKeyBinary,
		OriginalCACertDER:        original.CACertDER, ExtractedCACertDER: extracted.CACertDER,
		OriginalUpdateTime: original.UpdateTime, ExtractedUpdateTime: extracted.UpdateTime,
	})
}

func productionExtractor(ctx context.Context, config runtimeConfig, imagePath, outputDirectory string) error {
	if ctx == nil {
		return errors.New("extractor requires a context")
	}
	if err := validateRuntimeConfig(config); err != nil {
		return err
	}
	if err := validateExistingAbsolutePath(imagePath); err != nil {
		return fmt.Errorf("signed EEPROM image: %w", err)
	}
	if err := validateExistingAbsolutePath(outputDirectory); err != nil {
		return fmt.Errorf("EEPROM extraction directory: %w", err)
	}
	info, err := os.Lstat(outputDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("EEPROM extraction output must be a non-symlink directory")
	}
	temporaryDirectory, err := os.MkdirTemp(filepath.Dir(outputDirectory), ".extractor-tmp-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporaryDirectory)
	command := exec.CommandContext(ctx, config.ExtractorExecutablePath, "-x", imagePath)
	command.Dir = outputDirectory
	command.WaitDelay = 2 * time.Second
	command.Env = []string{
		"LANG=C", "LC_ALL=C", "TZ=UTC", "PATH=" + config.FixedToolPATH,
		"TMPDIR=" + temporaryDirectory,
	}
	var stdout, stderr cappedBuffer
	stdout.maximum = maxCommandOutputBytes
	stderr.maximum = maxCommandOutputBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("pinned rpi-eeprom-config failed: %w (stdout %q, stderr %q)", err, stdout.String(), stderr.String())
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("pinned rpi-eeprom-config output exceeded %d bytes", maxCommandOutputBytes)
	}
	return nil
}
