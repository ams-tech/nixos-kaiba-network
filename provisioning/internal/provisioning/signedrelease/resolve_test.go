package signedrelease

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpibootbundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
)

func TestFinalizeVerifiesCompleteCrossBundleLineage(t *testing.T) {
	fixture := newResolveFixture(t)
	replays := 0
	options := Options{EEPROMReplayVerifier: EEPROMReplayVerifierFunc(func(_ context.Context, plan, signed, finalized string) error {
		replays++
		fresh := plan == fixture.inputs.EEPROMReplayPlanDirectory && signed == fixture.inputs.EEPROMReplaySignedDirectory && finalized == fixture.inputs.SignedEEPROMDirectory
		owned := plan == fixture.inputs.OwnedReplayPlanDirectory && signed == fixture.inputs.OwnedReplaySignedDirectory && finalized == fixture.inputs.OwnedRecoveryDirectory
		if !fresh && !owned {
			return fmt.Errorf("unexpected replay inputs")
		}
		return nil
	})}
	output := filepath.Join(t.TempDir(), "release")
	t.Cleanup(func() { removeTemporaryTree(output) })
	if err := Finalize(context.Background(), fixture.inputs, output, options); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if replays != 2 {
		t.Fatalf("component replay calls = %d, want 2", replays)
	}
	manifest, err := VerifyPublication(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 18 {
		t.Fatalf("artifact count = %d, want 18", len(manifest.Artifacts))
	}
	if capture := os.Getenv("KAIBA_SIGNED_RELEASE_TEST_PUBLICATION"); capture != "" {
		encoded, err := os.ReadFile(filepath.Join(output, "publication.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(capture, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Role == bundle.RoleEEPROMBootcode {
			t.Fatal("signing-only EEPROM bootcode leaked into final role set")
		}
	}

	bootSignature := filepath.Join(fixture.inputs.SignedBootDirectory, "boot.sig")
	encoded, err := os.ReadFile(bootSignature)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-2] ^= 1
	if err := os.WriteFile(bootSignature, encoded, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), fixture.inputs, options); err == nil {
		t.Fatal("Resolve() accepted a mutated boot signature")
	}
	if replays != 2 {
		t.Fatalf("replay ran before boot-signature rejection; calls=%d", replays)
	}
}

func TestResolveRejectsTreesOutsideCanonicalRPIBootBundleSet(t *testing.T) {
	fixture := newResolveFixture(t)
	fixture.inputs.FreshCommitBundle = fixture.inputs.FreshReadbackBundle
	options := Options{EEPROMReplayVerifier: EEPROMReplayVerifierFunc(func(context.Context, string, string, string) error {
		return nil
	})}
	if _, err := Resolve(context.Background(), fixture.inputs, options); err == nil || !strings.Contains(err.Error(), "six canonical paths") {
		t.Fatalf("Resolve() error = %v, want canonical RPIBOOT path rejection", err)
	}
}

func TestResolveRequiresOwnedRecoveryUpdaterReplay(t *testing.T) {
	fixture := newResolveFixture(t)
	options := Options{EEPROMReplayVerifier: EEPROMReplayVerifierFunc(func(_ context.Context, plan, _ string, _ string) error {
		if plan == fixture.inputs.OwnedReplayPlanDirectory {
			return fmt.Errorf("owned updater replay rejected")
		}
		return nil
	})}
	if _, err := Resolve(context.Background(), fixture.inputs, options); err == nil || !strings.Contains(err.Error(), "deterministic owned-recovery replay") {
		t.Fatalf("Resolve() error = %v, want mandatory owned-recovery replay rejection", err)
	}
}

type resolveFixture struct{ inputs Inputs }

func newResolveFixture(t *testing.T) resolveFixture {
	t.Helper()
	root := t.TempDir()
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
	fingerprint, customerHash := bundle.Sum(publicDER), bundle.Sum(publicBinary)

	bootImage := make([]byte, 32*1024*1024)
	for index := 0; index < len(bootImage); index += 4096 {
		bootImage[index] = byte(index / 4096)
	}
	rootData, rootHashImage := []byte("synthetic verified root data"), []byte("synthetic dm-verity hash tree")
	originalEEPROM := bytes.Repeat([]byte{0x5a}, 4096)
	originalRecovery := []byte("pinned unsigned synthetic recovery")
	originalBootcode := []byte("pinned synthetic bootcode")
	originalBootsys := []byte("pinned synthetic bootsys")
	bootConfig := []byte("BOOT_ORDER=0xf6\nBOOT_UART=1\n")
	eepromInputs, err := eepromsigning.NewSigningInputs(originalBootcode, originalBootsys, bootConfig)
	if err != nil {
		t.Fatal(err)
	}
	ownedInput, err := eepromsigning.NewOwnedRecoverySigningInput(originalRecovery)
	if err != nil {
		t.Fatal(err)
	}

	eepromRelease := []byte(`{"schema_version":"kaiba.provisioning.rpi5-eeprom-release/v1alpha1","device_class":"raspberry-pi-5-model-b-v1alpha1","source":{},"firmware":{},"provenance":[],"toolchain":{},"required_capability":{},"authority":{}}`)
	eepromReleasePath := writeFixtureFile(t, root, "eeprom-release.json", eepromRelease)
	unsignedPath, unsignedDigest, rootIntegrityDigest := writeUnsignedFixture(t, root, bootImage, rootData, rootHashImage, customerHash)

	const sourceEpoch = uint64(1786968000)
	policyDigest := bundle.Sum([]byte("fixed signing policy"))
	intent, err := releaseintent.New(releaseintent.Parameters{
		ReleaseID: "release:rpi5:test", SourceRevision: strings.Repeat("a", 40), SourceDateEpoch: sourceEpoch,
		UnsignedArtifactSetDigest: unsignedDigest, EEPROMReleaseManifestDigest: bundle.Sum(eepromRelease),
		PublicKeyFingerprint: fingerprint, SigningPolicyDigest: policyDigest, ExpectedCustomerKeyHash: customerHash,
		SigningInputs: []bundle.Artifact{
			{Role: bundle.RoleBootImage, Digest: bundle.Sum(bootImage), SizeBytes: uint64(len(bootImage))},
			{Role: bundle.RoleEEPROMBootcode, Digest: eepromInputs[0].Digest, SizeBytes: eepromInputs[0].SizeBytes},
			{Role: bundle.RoleEEPROMBootsys, Digest: eepromInputs[1].Digest, SizeBytes: eepromInputs[1].SizeBytes},
			{Role: bundle.RoleEEPROMConfig, Digest: eepromInputs[2].Digest, SizeBytes: eepromInputs[2].SizeBytes},
			{Role: bundle.RoleOwnedRecoveryBootcode, Digest: ownedInput.Digest, SizeBytes: ownedInput.SizeBytes},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, _ := intent.CanonicalJSON()
	intentDigest, _ := intent.Digest()
	intentPath := writeFixtureFile(t, root, "release-intent.json", jsonFile(intentJSON))

	bootPlan := signedboot.Plan{
		SchemaVersion: signedboot.PlanSchemaV1Alpha2, PlanID: "boot-plan:test", ReleaseIntentDigest: intentDigest,
		BootImageDigest: bundle.Sum(bootImage), BootImageSizeBytes: uint64(len(bootImage)), PublicKeyFingerprint: fingerprint,
		SignerPolicyDigest: policyDigest, SourceDateEpoch: sourceEpoch,
	}
	bootPlanJSON, _ := bootPlan.CanonicalJSON()
	bootPlanDigest, _ := bootPlan.Digest()
	bootRawSignature := signFixture(t, privateKey, bootImage)
	bootDocument, err := rpi5bootsig.New(bundle.Sum(bootImage), sourceEpoch, bootRawSignature)
	if err != nil {
		t.Fatal(err)
	}
	bootSignature, _ := bootDocument.MarshalText()
	bootResult := signedboot.Result{
		SchemaVersion: signedboot.ResultSchemaV1Alpha2, PlanID: bootPlan.PlanID, PlanDigest: bootPlanDigest,
		ReleaseIntentDigest: intentDigest, BootImageDigest: bundle.Sum(bootImage), BootImageSizeBytes: uint64(len(bootImage)),
		BootSignatureDigest: bundle.Sum(bootSignature), BootSignatureSizeBytes: uint64(len(bootSignature)),
		PublicKeyFingerprint: fingerprint, SignerPolicyDigest: policyDigest, GateReceiptDigest: bundle.Sum([]byte("boot receipt")), SourceDateEpoch: sourceEpoch,
	}
	bootResultJSON, _ := bootResult.CanonicalJSON()
	bootManifest, err := bundle.NewManifest(bootPlan.PlanID, "raspberry-pi-5", policyDigest, []bundle.Artifact{
		{Role: bundle.RoleBootImage, Digest: bundle.Sum(bootImage), SizeBytes: uint64(len(bootImage))},
		{Role: bundle.RoleBootPublicKey, Digest: bundle.Sum(publicPEM), SizeBytes: uint64(len(publicPEM))},
		{Role: bundle.RoleBootSignature, Digest: bundle.Sum(bootSignature), SizeBytes: uint64(len(bootSignature))},
	})
	if err != nil {
		t.Fatal(err)
	}
	bootManifestJSON, _ := bootManifest.CanonicalJSON()
	signedBoot := writeFixtureDirectory(t, root, "signed-boot", map[string][]byte{
		"boot.img": bootImage, "boot.sig": bootSignature, "manifest.json": jsonFile(bootManifestJSON), "public.pem": publicPEM,
		"release-intent.json": jsonFile(intentJSON), "signing-plan.json": jsonFile(bootPlanJSON), "signing-result.json": jsonFile(bootResultJSON),
	})

	eepromPlan := eepromsigning.Plan{
		SchemaVersion: eepromsigning.PlanSchemaV1Alpha1, PlanID: "eeprom-plan:test", ReleaseIntentDigest: intentDigest,
		EEPROMReleaseManifestDigest: bundle.Sum(eepromRelease), SignerPolicyDigest: policyDigest, PublicKeyFingerprint: fingerprint,
		CustomerKeyHash: customerHash, FirmwareBuildEpoch: 1779807685, SourceDateEpoch: sourceEpoch,
		UpdaterMode: eepromsigning.UpdaterModeFreshBoard, UpdaterFlags: []string{"-f"},
		OriginalEEPROM: fileRecord(originalEEPROM), OriginalRecovery: fileRecord(originalRecovery), OriginalBootcode: fileRecord(originalBootcode),
		OriginalBootsys: fileRecord(originalBootsys), BootConfig: fileRecord(bootConfig), PublicKeyPEM: fileRecord(publicPEM), SigningInputs: eepromInputs,
	}
	eepromPlanJSON, _ := eepromPlan.CanonicalJSON()
	eepromPlanDigest, _ := eepromPlan.Digest()
	bootcodePreimage, _ := eepromsigning.FirmwareSigningPreimage(originalBootcode)
	bootsysPreimage, _ := eepromsigning.FirmwareSigningPreimage(originalBootsys)
	bootcodeSignature := signFixtureInput(t, privateKey, bootcodePreimage)
	bootsysSignature := signFixtureInput(t, privateKey, bootsysPreimage)
	configSignature := signFixtureInput(t, privateKey, bootConfig)
	signedBootcode := append(append(append([]byte(nil), bootcodePreimage...), bootcodeSignature...), publicBinary...)
	signedBootsys := append(append(append([]byte(nil), bootsysPreimage...), bootsysSignature...), publicBinary...)
	bootConfigSignature := []byte(strings.TrimPrefix(string(bundle.Sum(bootConfig)), "sha256:") + "\nts: " + strconv.FormatUint(sourceEpoch, 10) + "\nrsa2048: " + hex.EncodeToString(configSignature) + "\n")
	signedEEPROM := bytes.Repeat([]byte{0xa5}, len(originalEEPROM))
	eepromMetadata := []byte(strings.TrimPrefix(string(bundle.Sum(signedEEPROM)), "sha256:") + "\nts: " + strconv.FormatUint(sourceEpoch, 10) + "\n")
	eepromResult := eepromsigning.Result{
		SchemaVersion: eepromsigning.ResultSchemaV1Alpha1, PlanID: eepromPlan.PlanID, PlanDigest: eepromPlanDigest,
		ReleaseIntentDigest: intentDigest, EEPROMReleaseManifestDigest: bundle.Sum(eepromRelease), SignerPolicyDigest: policyDigest,
		PublicKeyFingerprint: fingerprint, CustomerKeyHash: customerHash, SourceDateEpoch: sourceEpoch,
		UpdaterMode: eepromsigning.UpdaterModeFreshBoard, RecoveryMode: eepromsigning.RecoveryModeUnsigned,
		Signatures: []eepromsigning.SignatureResult{
			signatureRecord(eepromsigning.RoleEEPROMBootcode, eepromInputs[0], bootcodeSignature, "bootcode receipt"),
			signatureRecord(eepromsigning.RoleEEPROMBootsys, eepromInputs[1], bootsysSignature, "bootsys receipt"),
			signatureRecord(eepromsigning.RoleEEPROMConfig, eepromInputs[2], configSignature, "config receipt"),
		},
		SignedEEPROM: fileRecord(signedEEPROM), EEPROMUpdateMetadata: fileRecord(eepromMetadata), FreshRecoveryBootcode: fileRecord(originalRecovery),
	}
	eepromResultJSON, _ := eepromResult.CanonicalJSON()
	eepromFinalFiles := map[string][]byte{
		"boot.conf": bootConfig, "bootcode.original.bin": originalBootcode, "bootcode.signed.bin": signedBootcode,
		"bootcode5.bin": originalRecovery, "bootconf.sig": bootConfigSignature, "bootconf.signed.txt": bootConfig,
		"bootsys.original": originalBootsys, "bootsys.signed": signedBootsys, "cacert.der": []byte("synthetic CA certificate"),
		"pieeprom.bin": signedEEPROM, "pieeprom.original.bin": originalEEPROM, "pieeprom.sig": eepromMetadata,
		"plan.json": jsonFile(eepromPlanJSON), "pubkey.bin": publicBinary, "public.pem": publicPEM,
		"recovery.original.bin": originalRecovery, "release-intent.json": jsonFile(intentJSON), "result.json": jsonFile(eepromResultJSON),
		"updatetime": []byte("synthetic update time"),
	}
	signedEEPROMDirectory := writeFixtureDirectory(t, root, "signed-eeprom-final", eepromFinalFiles)
	replayPlan := writeFixtureDirectory(t, root, "eeprom-replay-plan", selectFiles(eepromFinalFiles, replayPlanLimits))
	replaySigned := writeFixtureDirectory(t, root, "eeprom-replay-signed", selectFiles(eepromFinalFiles, replaySignedLimits))

	ownedPlan := eepromsigning.OwnedRecoveryPlan{
		SchemaVersion: eepromsigning.OwnedRecoveryPlanSchemaV1Alpha1, PlanID: "owned-recovery:test",
		UpdaterMode: eepromsigning.UpdaterModeOwnedRecovery, UpdaterFlags: []string{"-f", "-r"},
		FreshEEPROMPlan: eepromPlan, FreshEEPROMResult: eepromResult, OwnedRecoverySigningInput: ownedInput,
	}
	ownedPlanJSON, _ := ownedPlan.CanonicalJSON()
	ownedPlanDigest, _ := ownedPlan.Digest()
	recoveryPreimage, _ := eepromsigning.FirmwareSigningPreimage(originalRecovery)
	recoverySignature := signFixtureInput(t, privateKey, recoveryPreimage)
	signedRecovery := append(append(append([]byte(nil), recoveryPreimage...), recoverySignature...), publicBinary...)
	ownedResult := eepromsigning.OwnedRecoveryResult{
		SchemaVersion: eepromsigning.OwnedRecoveryResultSchemaV1Alpha1, PlanID: ownedPlan.PlanID, PlanDigest: ownedPlanDigest,
		ReleaseIntentDigest: intentDigest, EEPROMReleaseManifestDigest: bundle.Sum(eepromRelease), SignerPolicyDigest: policyDigest,
		PublicKeyFingerprint: fingerprint, CustomerKeyHash: customerHash, SourceDateEpoch: sourceEpoch,
		UpdaterMode: eepromsigning.UpdaterModeOwnedRecovery, RecoveryMode: eepromsigning.RecoveryModeCustomerCounterSigned,
		Signature:             signatureRecord(eepromsigning.RoleOwnedRecovery, ownedInput, recoverySignature, "recovery receipt"),
		OwnedRecoveryBootcode: fileRecord(signedRecovery), ReplayedSignedEEPROM: fileRecord(signedEEPROM), ReplayedEEPROMMetadata: fileRecord(eepromMetadata),
	}
	ownedResultJSON, _ := ownedResult.CanonicalJSON()
	ownedPlanDirectory := writeFixtureDirectory(t, root, "owned-recovery-plan", map[string][]byte{
		"plan.json": jsonFile(ownedPlanJSON), "release-intent.json": jsonFile(intentJSON),
		"pieeprom.original.bin": originalEEPROM, "recovery.original.bin": originalRecovery,
		"bootcode.original.bin": originalBootcode, "bootsys.original": originalBootsys,
		"boot.conf": bootConfig, "public.pem": publicPEM, "pieeprom.expected.bin": signedEEPROM,
		"pieeprom.expected.sig": eepromMetadata, "bootcode5.fresh.bin": originalRecovery,
	})
	ownedSignedDirectory := writeFixtureDirectory(t, root, "owned-recovery-signed", map[string][]byte{
		"bootcode5.bin": signedRecovery, "pieeprom.bin": signedEEPROM, "pieeprom.sig": eepromMetadata,
		"result.json": jsonFile(ownedResultJSON),
	})
	ownedDirectory := writeFixtureDirectory(t, root, "owned-recovery-final", map[string][]byte{
		"bootcode5.bin": signedRecovery, "pieeprom.bin": signedEEPROM, "pieeprom.sig": eepromMetadata,
		"plan.json": jsonFile(ownedPlanJSON), "public.pem": publicPEM, "recovery.original.bin": originalRecovery,
		"release-intent.json": jsonFile(intentJSON), "result.json": jsonFile(ownedResultJSON),
	})

	profileSource := filepath.Join("..", "..", "..", "profiles", "device-classes", "raspberry-pi-5-model-b-v1alpha1.json")
	profile, err := os.ReadFile(profileSource)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := writeFixtureFile(t, root, "device-profile.json", profile)
	adapterPath := writeFixtureFile(t, root, "platform-adapter", []byte("immutable platform adapter"))
	rootHashText := strings.TrimPrefix(string(rootIntegrityDigest), "sha256:")
	rootIntegrityPath := writeFixtureFile(t, root, "root-integrity.json", []byte(fmt.Sprintf(
		`{"schema":"provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1","algorithm":"sha256","data_block_size":4096,"hash_block_size":4096,"no_superblock":false,"root_hash":"%s","data_device":"/dev/nvme0n1p2","hash_device":"/dev/nvme0n1p3"}`,
		rootHashText,
	)))
	rootDataPath := writeFixtureFile(t, root, "root-data.img", rootData)
	rootHashPath := writeFixtureFile(t, root, "root-hash.img", rootHashImage)
	rpibootRoot := filepath.Join(root, "rpiboot-bundles")
	if _, err := rpibootbundle.Build(rpibootbundle.BuildConfig{
		ReleaseIntentDigest: intentDigest,
		FreshRecovery:       filepath.Join(signedEEPROMDirectory, "bootcode5.bin"),
		OwnedRecovery:       filepath.Join(ownedDirectory, "bootcode5.bin"),
		SignedEEPROM:        filepath.Join(signedEEPROMDirectory, "pieeprom.bin"),
		EEPROMMetadata:      filepath.Join(signedEEPROMDirectory, "pieeprom.sig"),
		BootImage:           filepath.Join(signedBoot, "boot.img"),
		BootSignature:       filepath.Join(signedBoot, "boot.sig"),
		BootPublicKey:       filepath.Join(signedBoot, "public.pem"),
		RootDataImage:       rootDataPath,
		RootHashTreeImage:   rootHashPath,
		Output:              rpibootRoot,
	}); err != nil {
		t.Fatalf("build canonical RPIBOOT fixture: %v", err)
	}
	t.Cleanup(func() { removeTemporaryTree(rpibootRoot) })

	return resolveFixture{inputs: Inputs{
		ReleaseIntentPath: intentPath, UnsignedArtifactsManifestPath: unsignedPath, EEPROMReleaseManifestPath: eepromReleasePath,
		SignedBootDirectory: signedBoot, SignedEEPROMDirectory: signedEEPROMDirectory, EEPROMReplayPlanDirectory: replayPlan,
		EEPROMReplaySignedDirectory: replaySigned, OwnedReplayPlanDirectory: ownedPlanDirectory,
		OwnedReplaySignedDirectory: ownedSignedDirectory, OwnedRecoveryDirectory: ownedDirectory, DeviceProfilePath: profilePath,
		PlatformAdapterPath: adapterPath, RootIntegrityPath: rootIntegrityPath, FreshCommitBundle: filepath.Join(rpibootRoot, "fresh-commit"),
		FreshReadbackBundle: filepath.Join(rpibootRoot, "fresh-readback"), NegativeBootBundle: filepath.Join(rpibootRoot, "negative-boot"),
		OwnedReadbackBundle: filepath.Join(rpibootRoot, "owned-readback"), OwnedRecoveryBundle: filepath.Join(rpibootRoot, "owned-recovery"),
		RootIntegrityTestBundle: filepath.Join(rpibootRoot, "root-integrity-test"), RootDataImagePath: rootDataPath, RootHashTreeImagePath: rootHashPath,
	}}
}

func writeUnsignedFixture(t *testing.T, root string, boot, rootData, rootHash []byte, customerHash bundle.Digest) (string, bundle.Digest, bundle.Digest) {
	t.Helper()
	rootIntegrityDigest := bundle.Sum([]byte("verity root hash"))
	value := unsignedArtifactSet{
		Schema: unsignedArtifactSchema, SourceRevision: strings.Repeat("a", 40), ExpectedCustomerKeyHash: customerHash,
		BootOrderPolicy: "nvme-only", BootCommandLinePath: "nixos/default/cmdline.txt",
		FirmwareAllowlist:  []string{"config.txt", "kaiba-root-integrity.json", "nixos/default/bcm2712-rpi-5-b.dtb", "nixos/default/cmdline.txt", "nixos/default/initrd", "nixos/default/kernel.img"},
		BootImageSizeBytes: uint64(len(boot)), PersistentMutableState: "tmpfs-only", RollbackPolicy: "unimplemented-block-enrollment-ready",
		DebugPolicy: "videocore-jtag-unlocked-development", EEPROMWriteProtectionPolicy: "unlocked-development",
		Toolchain: unsignedToolchain{Cryptsetup: "2.7", Dosfstools: "4.2", Mtools: "4.0"},
		Artifacts: unsignedArtifacts{
			BootImage:    unsignedArtifact{Path: "unsigned/boot.img", Digest: bundle.Sum(boot)},
			RootData:     unsignedArtifact{Path: "nvme/root-data.img", Digest: bundle.Sum(rootData)},
			RootHashTree: unsignedArtifact{Path: "nvme/root-hash.img", Digest: bundle.Sum(rootHash)},
		},
		Verity:              unsignedVerity{Algorithm: "sha256", DataBlockSize: 4096, HashBlockSize: 4096, UUID: "12345678-1234-1234-1234-123456789abc", DataDevice: "/dev/nvme0n1p2", HashDevice: "/dev/nvme0n1p3", Mapper: "/dev/mapper/root"},
		RootIntegrityDigest: rootIntegrityDigest, SigningStatus: "unsigned",
	}
	without, _ := json.Marshal(value)
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(without))
	decoder.UseNumber()
	_ = decoder.Decode(&object)
	delete(object, "bundle_digest")
	canonical, _ := json.Marshal(object)
	value.BundleDigest = domainDigest("kaiba.rpi5.unsigned-artifacts.v1", canonical)
	encoded, _ := json.MarshalIndent(value, "", "  ")
	encoded = append(encoded, '\n')
	return writeFixtureFile(t, root, "unsigned-artifacts.json", encoded), value.BundleDigest, rootIntegrityDigest
}

func signFixture(t *testing.T, key *rsa.PrivateKey, contents []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(contents)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func signFixtureInput(t *testing.T, key *rsa.PrivateKey, input []byte) []byte {
	return signFixture(t, key, input)
}

func fileRecord(contents []byte) eepromsigning.File {
	return eepromsigning.File{Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents))}
}

func signatureRecord(role eepromsigning.SigningInputRole, input eepromsigning.SigningInput, signature []byte, receipt string) eepromsigning.SignatureResult {
	return eepromsigning.SignatureResult{Role: role, InputDigest: input.Digest, InputSizeBytes: input.SizeBytes, SignatureDigest: bundle.Sum(signature), SignatureSizeBytes: uint64(len(signature)), GateReceiptDigest: bundle.Sum([]byte(receipt))}
}

func writeFixtureDirectory(t *testing.T, root, name string, files map[string][]byte) string {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	for filename, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, filename), contents, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func writeFixtureFile(t *testing.T, root, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, contents, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func selectFiles(files map[string][]byte, limits map[string]int64) map[string][]byte {
	selected := make(map[string][]byte, len(limits))
	for name := range limits {
		selected[name] = files[name]
	}
	return selected
}
