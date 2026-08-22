package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	cliTestFirmwareEpoch = uint64(1779807685)
	cliTestSourceEpoch   = uint64(1779700000)
)

type workflowFixture struct {
	privateKey       *rsa.PrivateKey
	planDirectory    string
	plan             eepromsigning.Plan
	releaseDigest    bundle.Digest
	originalEEPROM   []byte
	originalRecovery []byte
	originalBootcode []byte
	originalBootsys  []byte
	bootConfig       []byte
	publicPEM        []byte
	publicBinary     []byte
	caCertDER        []byte
	updateTime       []byte
	extracted        extractedEEPROM
	signedEEPROM     []byte
	gateCalls        int
}

func TestSignAndFinalizeEEPROMWithMockedPinnedCommands(t *testing.T) {
	fixture := newWorkflowFixture(t)
	deps := fixture.dependencies()
	root := t.TempDir()
	signedDirectory := filepath.Join(root, "signed")
	if err := signEEPROM(context.Background(), fixture.planDirectory, signedDirectory, deps); err != nil {
		t.Fatalf("signEEPROM() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(signedDirectory, 0o700) })
	if fixture.gateCalls != 3 {
		t.Fatalf("signing gate calls = %d, want 3", fixture.gateCalls)
	}
	wantSigned := []string{"bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "result.json"}
	if got := directoryNames(t, signedDirectory); !reflect.DeepEqual(got, wantSigned) {
		t.Fatalf("signed output entries = %v, want %v", got, wantSigned)
	}
	assertPublishedModes(t, signedDirectory, wantSigned)
	result, err := loadResultDirectory(signedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Signatures) != 3 {
		t.Fatalf("result signature rows = %d", len(result.Result.Signatures))
	}
	for index, row := range result.Result.Signatures {
		if row.GateReceiptDigest == "" || row.SignatureDigest == "" || row.Role != fixture.plan.SigningInputs[index].Role {
			t.Fatalf("signature row %d = %#v", index, row)
		}
	}

	finalDirectory := filepath.Join(root, "final")
	if err := finalizeEEPROM(context.Background(), fixture.planDirectory, signedDirectory, finalDirectory, deps); err != nil {
		t.Fatalf("finalizeEEPROM() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(finalDirectory, 0o700) })
	wantFinal := []string{
		"boot.conf", "bootcode.original.bin", "bootcode.signed.bin", "bootcode5.bin",
		"bootconf.sig", "bootconf.signed.txt", "bootsys.original", "bootsys.signed", "cacert.der",
		"pieeprom.bin", "pieeprom.original.bin", "pieeprom.sig", "plan.json", "public.pem",
		"pubkey.bin", "recovery.original.bin", "release-intent.json", "result.json", "updatetime",
	}
	sort.Strings(wantFinal)
	if got := directoryNames(t, finalDirectory); !reflect.DeepEqual(got, wantFinal) {
		t.Fatalf("final output entries = %v, want %v", got, wantFinal)
	}
	assertPublishedModes(t, finalDirectory, wantFinal)
	if got, err := os.ReadFile(filepath.Join(finalDirectory, "bootcode5.bin")); err != nil || !bytes.Equal(got, fixture.originalRecovery) {
		t.Fatalf("final unsigned recovery = %x, error %v", got, err)
	}
}

func TestSignEEPROMRejectsUpdaterCallbackDeviations(t *testing.T) {
	tests := []struct {
		name    string
		updater func(*workflowFixture) updaterRunner
		match   string
	}{
		{
			name: "reordered",
			updater: func(fixture *workflowFixture) updaterRunner {
				return func(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
					preimage, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootsys)
					_, err := callback(ctx, preimage)
					return err
				}
			},
			match: "callback 1",
		},
		{
			name: "missing",
			updater: func(fixture *workflowFixture) updaterRunner {
				return func(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
					preimage, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootcode)
					_, err := callback(ctx, preimage)
					return err
				}
			},
			match: "made 1 signing callbacks",
		},
		{
			name: "extra",
			updater: func(fixture *workflowFixture) updaterRunner {
				return func(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
					first, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootcode)
					second, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootsys)
					for _, artifact := range [][]byte{first, second, fixture.bootConfig, fixture.bootConfig} {
						if _, err := callback(ctx, artifact); err != nil {
							return err
						}
					}
					return nil
				}
			},
			match: "extra signing callback",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			deps := fixture.dependencies()
			deps.updater = test.updater(fixture)
			err := signEEPROM(context.Background(), fixture.planDirectory, filepath.Join(t.TempDir(), "signed"), deps)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("signEEPROM() error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestSignEEPROMRejectsGateReleaseIntentAndSignature(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*signinggate.Result)
		match  string
	}{
		{
			name: "release intent",
			mutate: func(result *signinggate.Result) {
				result.ReleaseIntentDigest = bundle.Sum([]byte("another release intent"))
			},
			match: "different release intent",
		},
		{
			name: "invalid signature",
			mutate: func(result *signinggate.Result) {
				result.SignatureHex = strings.Repeat("00", 256)
			},
			match: "planned customer key",
		},
		{
			name: "noncanonical signature",
			mutate: func(result *signinggate.Result) {
				result.SignatureHex += "\n"
			},
			match: "not canonical",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkflowFixture(t)
			deps := fixture.dependencies()
			validRequest := deps.request
			deps.request = func(ctx context.Context, socket string, artifact []byte) (signinggate.Result, error) {
				result, err := validRequest(ctx, socket, artifact)
				if err == nil {
					test.mutate(&result)
				}
				return result, err
			}
			err := signEEPROM(context.Background(), fixture.planDirectory, filepath.Join(t.TempDir(), "signed"), deps)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("signEEPROM() error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestFinalizeEEPROMRejectsTamperedSignedOutput(t *testing.T) {
	fixture := newWorkflowFixture(t)
	deps := fixture.dependencies()
	root := t.TempDir()
	signedDirectory := filepath.Join(root, "signed")
	if err := signEEPROM(context.Background(), fixture.planDirectory, signedDirectory, deps); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(signedDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(signedDirectory, "pieeprom.bin")
	if err := os.Chmod(imagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	image[0] ^= 0x80
	if err := os.WriteFile(imagePath, image, 0o644); err != nil {
		t.Fatal(err)
	}
	err = finalizeEEPROM(context.Background(), fixture.planDirectory, signedDirectory, filepath.Join(root, "final"), deps)
	if err == nil || !strings.Contains(err.Error(), "signed EEPROM digest") {
		t.Fatalf("finalizeEEPROM() error = %v", err)
	}
}

func TestFinalizeEEPROMReplayRejectsRecomputedResultForAlteredUnsignedSection(t *testing.T) {
	fixture := newWorkflowFixture(t)
	deps := fixture.dependencies()
	root := t.TempDir()
	signedDirectory := filepath.Join(root, "signed")
	if err := signEEPROM(context.Background(), fixture.planDirectory, signedDirectory, deps); err != nil {
		t.Fatal(err)
	}
	signed, err := loadResultDirectory(signedDirectory)
	if err != nil {
		t.Fatal(err)
	}

	// Model an attacker changing an EEPROM byte outside every extracted signed
	// section, then honestly recomputing all public file records and update
	// metadata. The extracted signatures still verify, so deterministic updater
	// replay is the check that must reject the transformed image.
	tamperedEEPROM := append([]byte(nil), signed.SignedEEPROM...)
	tamperedEEPROM[0] ^= 0x80
	tamperedMetadata := []byte(strings.TrimPrefix(string(bundle.Sum(tamperedEEPROM)), "sha256:") +
		"\nts: " + strconv.FormatUint(fixture.plan.SourceDateEpoch, 10) + "\n")
	signed.Result.SignedEEPROM = fileRecord(tamperedEEPROM)
	signed.Result.EEPROMUpdateMetadata = fileRecord(tamperedMetadata)
	resultJSON, err := signed.Result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(signedDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"pieeprom.bin": tamperedEEPROM,
		"pieeprom.sig": tamperedMetadata,
		"result.json":  jsonFile(resultJSON),
	} {
		path := filepath.Join(signedDirectory, name)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	baseExtractor := deps.extractor
	deps.extractor = func(ctx context.Context, config runtimeConfig, imagePath, outputDirectory string) error {
		image, err := os.ReadFile(imagePath)
		if err != nil {
			return err
		}
		if !bytes.Equal(image, tamperedEEPROM) {
			return baseExtractor(ctx, config, imagePath, outputDirectory)
		}
		for name, contents := range map[string][]byte{
			"bootcode.bin": fixture.extracted.Bootcode,
			"bootsys":      fixture.extracted.Bootsys,
			"bootconf.txt": fixture.extracted.BootConfig,
			"bootconf.sig": fixture.extracted.BootConfigSig,
			"pubkey.bin":   fixture.extracted.PublicKeyBinary,
			"cacert.der":   fixture.caCertDER,
			"updatetime":   fixture.updateTime,
		} {
			if err := os.WriteFile(filepath.Join(outputDirectory, name), contents, 0o600); err != nil {
				return err
			}
		}
		return nil
	}

	err = finalizeEEPROM(
		context.Background(), fixture.planDirectory, signedDirectory, filepath.Join(root, "final"), deps,
	)
	if err == nil || !strings.Contains(err.Error(), "replayed pieeprom.bin differs from the supplied signed result") {
		t.Fatalf("finalizeEEPROM() error = %v, want deterministic replay rejection", err)
	}
}

func TestSignEEPROMRejectsRecoveryNotApprovedByReleaseIntent(t *testing.T) {
	fixture := newWorkflowFixture(t)
	maliciousRecovery := []byte("unapproved replacement recovery")
	fixture.plan.OriginalRecovery = cliFileRecord(maliciousRecovery)
	planJSON, err := fixture.plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.planDirectory, "recovery.original.bin"), maliciousRecovery, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.planDirectory, "plan.json"), jsonFile(planJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	err = signEEPROM(context.Background(), fixture.planDirectory, filepath.Join(t.TempDir(), "signed"), fixture.dependencies())
	if err == nil || !strings.Contains(err.Error(), "does not approve the exact pinned unsigned recovery") {
		t.Fatalf("signEEPROM() error = %v", err)
	}
}

func TestUpdaterCommandIsClosedAndEnvironmentIsScrubbed(t *testing.T) {
	config := testRuntimeConfig(bundle.Sum([]byte("EEPROM release")))
	wantArgs := []string{
		"-f", "-c", "boot.conf", "-i", "pieeprom.original.bin", "-o", "pieeprom.bin",
		"-p", "public.pem", "-H", config.WrapperExecutablePath,
	}
	if got := updaterArguments(config, false); !reflect.DeepEqual(got, wantArgs) {
		t.Fatalf("updater arguments = %v, want %v", got, wantArgs)
	}
	for _, argument := range updaterArguments(config, false) {
		if argument == "-r" || argument == "-fr" {
			t.Fatalf("updater arguments enable recovery signing: %v", updaterArguments(config, false))
		}
	}
	owned := updaterArguments(config, true)
	if len(owned) == 0 || owned[0] != "-fr" {
		t.Fatalf("owned-recovery updater arguments = %v", owned)
	}
	wantEnvironment := []string{
		"LANG=C", "LC_ALL=C", "TZ=UTC", "PATH=/fixed/tools:/fixed/runtime",
		"SOURCE_DATE_EPOCH=" + strconv.FormatUint(cliTestSourceEpoch, 10),
		"TMPDIR=/private/tmp", sessionSocketEnvironment + "=/private/signing.sock",
	}
	if got := updaterEnvironment(config, cliTestSourceEpoch, "/private/tmp", "/private/signing.sock"); !reflect.DeepEqual(got, wantEnvironment) {
		t.Fatalf("updater environment = %v, want %v", got, wantEnvironment)
	}
}

func (fixture *workflowFixture) dependencies() dependencies {
	gate := func(ctx context.Context, socketPath string, artifact []byte) (signinggate.Result, error) {
		if socketPath != "/fixed/signing-gate.sock" {
			return signinggate.Result{}, fmt.Errorf("unexpected gate socket %q", socketPath)
		}
		fixture.gateCalls++
		digest := sha256.Sum256(artifact)
		signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.privateKey, crypto.SHA256, digest[:])
		if err != nil {
			return signinggate.Result{}, err
		}
		return signinggate.Result{
			SignatureHex:        hex.EncodeToString(signature),
			ReceiptDigest:       bundle.Sum([]byte(fmt.Sprintf("receipt-%d", fixture.gateCalls))),
			ReleaseIntentDigest: fixture.plan.ReleaseIntentDigest,
		}, nil
	}
	updater := func(ctx context.Context, invocation updateInvocation, callback hsmCallback) error {
		if invocation.SourceDateEpoch != fixture.plan.SourceDateEpoch || invocation.Config.ExpectedEEPROMReleaseDigest != fixture.releaseDigest {
			return errors.New("mock updater received the wrong fixed invocation")
		}
		bootcodePreimage, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootcode)
		bootsysPreimage, _ := eepromsigning.FirmwareSigningPreimage(fixture.originalBootsys)
		artifacts := [][]byte{bootcodePreimage, bootsysPreimage, fixture.bootConfig}
		signatures := make([][]byte, 0, 3)
		for _, artifact := range artifacts {
			signatureHex, err := callback(ctx, artifact)
			if err != nil {
				return err
			}
			signature, err := hex.DecodeString(signatureHex)
			if err != nil {
				return err
			}
			signatures = append(signatures, signature)
		}
		fixture.extracted = extractedEEPROM{
			Bootcode:   append(append(append([]byte(nil), bootcodePreimage...), signatures[0]...), fixture.publicBinary...),
			Bootsys:    append(append(append([]byte(nil), bootsysPreimage...), signatures[1]...), fixture.publicBinary...),
			BootConfig: append([]byte(nil), fixture.bootConfig...),
			BootConfigSig: []byte(strings.TrimPrefix(string(bundle.Sum(fixture.bootConfig)), "sha256:") +
				"\nts: " + strconv.FormatUint(fixture.plan.SourceDateEpoch, 10) +
				"\nrsa2048: " + hex.EncodeToString(signatures[2]) + "\n"),
			PublicKeyBinary: append([]byte(nil), fixture.publicBinary...),
		}
		fixture.signedEEPROM = bytes.Repeat([]byte{0xa5}, len(fixture.originalEEPROM))
		metadata := []byte(strings.TrimPrefix(string(bundle.Sum(fixture.signedEEPROM)), "sha256:") +
			"\nts: " + strconv.FormatUint(fixture.plan.SourceDateEpoch, 10) + "\n")
		for name, contents := range map[string][]byte{
			"pieeprom.bin":  fixture.signedEEPROM,
			"pieeprom.sig":  metadata,
			"bootcode5.bin": fixture.originalRecovery,
		} {
			if err := os.WriteFile(filepath.Join(invocation.WorkDir, name), contents, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	extractor := func(ctx context.Context, config runtimeConfig, imagePath, outputDirectory string) error {
		image, err := os.ReadFile(imagePath)
		if err != nil {
			return err
		}
		extracted := fixture.extracted
		if bytes.Equal(image, fixture.originalEEPROM) {
			extracted = extractedEEPROM{
				Bootcode: fixture.originalBootcode, Bootsys: fixture.originalBootsys,
				BootConfig: fixture.bootConfig, BootConfigSig: []byte("original config signature field"),
				PublicKeyBinary: bytes.Repeat([]byte{0xff}, 512),
			}
		} else if !bytes.Equal(image, fixture.signedEEPROM) {
			return errors.New("mock extractor received an unknown EEPROM")
		}
		for name, contents := range map[string][]byte{
			"bootcode.bin": extracted.Bootcode,
			"bootsys":      extracted.Bootsys,
			"bootconf.txt": extracted.BootConfig,
			"bootconf.sig": extracted.BootConfigSig,
			"pubkey.bin":   extracted.PublicKeyBinary,
			"cacert.der":   fixture.caCertDER,
			"updatetime":   fixture.updateTime,
		} {
			if err := os.WriteFile(filepath.Join(outputDirectory, name), contents, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	config := testRuntimeConfig(fixture.releaseDigest)
	config.ExpectedOriginalEEPROMDigest = bundle.Sum(fixture.originalEEPROM)
	config.ExpectedOriginalRecoveryDigest = bundle.Sum(fixture.originalRecovery)
	config.ExpectedOriginalBootcodeDigest = bundle.Sum(fixture.originalBootcode)
	config.ExpectedOriginalBootsysDigest = bundle.Sum(fixture.originalBootsys)
	config.ExpectedFirmwareBuildEpoch = fixture.plan.FirmwareBuildEpoch
	return dependencies{config: config, request: gate, updater: updater, extractor: extractor}
}

func newWorkflowFixture(t *testing.T) *workflowFixture {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	publicBinary, err := eepromsigning.CustomerPublicKeyBinary(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	originalEEPROM := bytes.Repeat([]byte{0x5a}, 4096)
	originalRecovery := []byte("pinned unsigned synthetic recovery")
	originalBootcode := []byte("pinned synthetic bootcode")
	originalBootsys := []byte("pinned synthetic bootsys")
	bootConfig := []byte("BOOT_ORDER=0xf6\nBOOT_UART=1\n")
	signingInputs, err := eepromsigning.NewSigningInputs(originalBootcode, originalBootsys, bootConfig)
	if err != nil {
		t.Fatal(err)
	}
	recoverySigningInput, err := eepromsigning.FirmwareSigningPreimage(originalRecovery)
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest := bundle.Sum([]byte("pinned EEPROM release manifest"))
	signerPolicyDigest := bundle.Sum([]byte("fixed signing policy"))
	intentInputs := []bundle.Artifact{
		{Role: bundle.RoleBootImage, Digest: bundle.Sum([]byte("boot image")), SizeBytes: 10},
		{Role: bundle.RoleEEPROMBootcode, Digest: signingInputs[0].Digest, SizeBytes: signingInputs[0].SizeBytes},
		{Role: bundle.RoleEEPROMBootsys, Digest: signingInputs[1].Digest, SizeBytes: signingInputs[1].SizeBytes},
		{Role: bundle.RoleEEPROMConfig, Digest: signingInputs[2].Digest, SizeBytes: signingInputs[2].SizeBytes},
		{Role: bundle.RoleOwnedRecoveryBootcode, Digest: bundle.Sum(recoverySigningInput), SizeBytes: uint64(len(recoverySigningInput))},
	}
	intent, err := releaseintent.New(releaseintent.Parameters{
		ReleaseID: "release:test", SourceRevision: strings.Repeat("a", 40),
		SourceDateEpoch:             cliTestSourceEpoch,
		UnsignedArtifactSetDigest:   bundle.Sum([]byte("unsigned artifact set")),
		EEPROMReleaseManifestDigest: releaseDigest,
		PublicKeyFingerprint:        bundle.Sum(publicDER), SigningPolicyDigest: signerPolicyDigest,
		ExpectedCustomerKeyHash: bundle.Sum(publicBinary), SigningInputs: intentInputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := eepromsigning.Plan{
		SchemaVersion: eepromsigning.PlanSchemaV1Alpha1, PlanID: "eeprom-plan:test",
		ReleaseIntentDigest: intentDigest, EEPROMReleaseManifestDigest: releaseDigest,
		SignerPolicyDigest: signerPolicyDigest, PublicKeyFingerprint: bundle.Sum(publicDER),
		CustomerKeyHash: bundle.Sum(publicBinary), FirmwareBuildEpoch: cliTestFirmwareEpoch,
		SourceDateEpoch: cliTestSourceEpoch, UpdaterMode: eepromsigning.UpdaterModeFreshBoard,
		UpdaterFlags: []string{"-f"}, OriginalEEPROM: cliFileRecord(originalEEPROM),
		OriginalRecovery: cliFileRecord(originalRecovery), OriginalBootcode: cliFileRecord(originalBootcode),
		OriginalBootsys: cliFileRecord(originalBootsys), BootConfig: cliFileRecord(bootConfig),
		PublicKeyPEM: cliFileRecord(publicPEM), SigningInputs: signingInputs,
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	planDirectory := filepath.Join(t.TempDir(), "plan")
	if err := os.Mkdir(planDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"plan.json": jsonFile(planJSON), "release-intent.json": jsonFile(intentJSON),
		"pieeprom.original.bin": originalEEPROM, "recovery.original.bin": originalRecovery,
		"bootcode.original.bin": originalBootcode, "bootsys.original": originalBootsys,
		"boot.conf": bootConfig, "public.pem": publicPEM,
	} {
		if err := os.WriteFile(filepath.Join(planDirectory, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &workflowFixture{
		privateKey: privateKey, planDirectory: planDirectory, plan: plan, releaseDigest: releaseDigest,
		originalEEPROM: originalEEPROM, originalRecovery: originalRecovery,
		originalBootcode: originalBootcode, originalBootsys: originalBootsys,
		bootConfig: bootConfig, publicPEM: publicPEM, publicBinary: publicBinary,
		caCertDER: []byte("synthetic CA certificate"), updateTime: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
}

func testRuntimeConfig(releaseDigest bundle.Digest) runtimeConfig {
	return runtimeConfig{
		GateSocketPath:                 "/fixed/signing-gate.sock",
		UpdaterExecutablePath:          "/fixed/update-pieeprom",
		ExtractorExecutablePath:        "/fixed/rpi-eeprom-config",
		FixedToolPATH:                  "/fixed/tools:/fixed/runtime",
		WrapperExecutablePath:          "/fixed/kaiba-provision-sign-eeprom",
		ExpectedEEPROMReleaseDigest:    releaseDigest,
		ExpectedOriginalEEPROMDigest:   bundle.Sum([]byte("original EEPROM")),
		ExpectedOriginalRecoveryDigest: bundle.Sum([]byte("original recovery")),
		ExpectedOriginalBootcodeDigest: bundle.Sum([]byte("original bootcode")),
		ExpectedOriginalBootsysDigest:  bundle.Sum([]byte("original bootsys")),
		ExpectedFirmwareBuildEpoch:     cliTestFirmwareEpoch,
	}
}

func cliFileRecord(contents []byte) eepromsigning.File {
	return eepromsigning.File{Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents))}
}

func directoryNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func assertPublishedModes(t *testing.T, directory string, names []string) {
	t.Helper()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("published directory mode = %o, want 555", info.Mode().Perm())
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("published %s mode = %o, want 444", name, info.Mode().Perm())
		}
	}
}
