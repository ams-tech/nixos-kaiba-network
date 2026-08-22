package eepromsigning

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const testEpoch = uint64(1779807685)

type testFixture struct {
	privateKey *rsa.PrivateKey
	plan       Plan
	result     Result
	final      FinalizationInput
}

func TestFirmwareSigningPreimageAndOrder(t *testing.T) {
	bootcode := []byte("bootcode")
	bootsys := []byte("bootsys")
	config := []byte("BOOT_ORDER=0xf6\n")
	preimage, err := FirmwareSigningPreimage(bootcode)
	if err != nil {
		t.Fatal(err)
	}
	wantTail := []byte{
		8, 0, 0, 0, // original length
		16, 0, 0, 0, // customer key number
		0, 0, 0, 0, // private version
	}
	if !bytes.Equal(preimage[:len(bootcode)], bootcode) || !bytes.Equal(preimage[len(bootcode):], wantTail) {
		t.Fatalf("firmware preimage = %x", preimage)
	}
	inputs, err := NewSigningInputs(bootcode, bootsys, config)
	if err != nil {
		t.Fatal(err)
	}
	wantRoles := []SigningInputRole{RoleEEPROMBootcode, RoleEEPROMBootsys, RoleEEPROMConfig}
	for index, role := range wantRoles {
		if inputs[index].Role != role {
			t.Fatalf("input %d role = %q, want %q", index, inputs[index].Role, role)
		}
	}
	if inputs[2].Digest != bundle.Sum(config) || inputs[2].SizeBytes != uint64(len(config)) {
		t.Fatalf("config input = %#v", inputs[2])
	}
}

func TestVerifyFinalization(t *testing.T) {
	fixture := newFixture(t)
	if err := VerifyFinalization(fixture.final); err != nil {
		t.Fatalf("VerifyFinalization() error = %v", err)
	}
	if _, err := fixture.plan.Digest(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.result.Digest(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFinalizationRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*FinalizationInput)
		match  string
	}{
		{
			name: "plan binding",
			mutate: func(value *FinalizationInput) {
				value.Result.PlanDigest = bundle.Sum([]byte("other plan"))
			},
			match: "exact plan",
		},
		{
			name: "release intent",
			mutate: func(value *FinalizationInput) {
				value.Result.ReleaseIntentDigest = bundle.Sum([]byte("other intent"))
			},
			match: "release intent",
		},
		{
			name: "signing order",
			mutate: func(value *FinalizationInput) {
				value.Result.Signatures[0], value.Result.Signatures[1] = value.Result.Signatures[1], value.Result.Signatures[0]
			},
			match: "role",
		},
		{
			name: "signed EEPROM",
			mutate: func(value *FinalizationInput) {
				value.SignedEEPROM[0] ^= 0x80
			},
			match: "signed EEPROM digest",
		},
		{
			name: "unsigned recovery",
			mutate: func(value *FinalizationInput) {
				value.FreshRecoveryBootcode[0] ^= 0x80
			},
			match: "fresh recovery bootcode digest",
		},
		{
			name: "extracted config",
			mutate: func(value *FinalizationInput) {
				value.ExtractedBootConfig = []byte("BOOT_ORDER=0x1\n")
			},
			match: "different boot config",
		},
		{
			name: "CA certificate section",
			mutate: func(value *FinalizationInput) {
				value.ExtractedCACertDER[0] ^= 0x80
			},
			match: "CA certificate",
		},
		{
			name: "update-time section",
			mutate: func(value *FinalizationInput) {
				value.ExtractedUpdateTime[0] ^= 0x80
			},
			match: "update-time",
		},
		{
			name: "bootcode customer signature",
			mutate: func(value *FinalizationInput) {
				value.ExtractedBootcode[len(value.OriginalBootcode)+12] ^= 0x80
			},
			match: "signature is invalid",
		},
		{
			name: "bootsys customer key",
			mutate: func(value *FinalizationInput) {
				value.ExtractedBootsys[len(value.ExtractedBootsys)-1] ^= 0x80
			},
			match: "different customer public key",
		},
		{
			name: "config customer signature",
			mutate: func(value *FinalizationInput) {
				value.ExtractedBootConfigSig = bytes.Replace(value.ExtractedBootConfigSig, []byte("rsa2048: "), []byte("rsa2048: 0"), 1)
			},
			match: "wrong size",
		},
		{
			name: "outer metadata timestamp",
			mutate: func(value *FinalizationInput) {
				value.EEPROMUpdateMetadata = bytes.Replace(value.EEPROMUpdateMetadata, []byte("ts: 1779807685"), []byte("ts: 1779807684"), 1)
				value.Result.EEPROMUpdateMetadata = file(value.EEPROMUpdateMetadata)
			},
			match: "SOURCE_DATE_EPOCH",
		},
		{
			name: "outer metadata must not contain RSA",
			mutate: func(value *FinalizationInput) {
				value.EEPROMUpdateMetadata = append(value.EEPROMUpdateMetadata, []byte("rsa2048: "+strings.Repeat("0", 512)+"\n")...)
				value.Result.EEPROMUpdateMetadata = file(value.EEPROMUpdateMetadata)
			},
			match: "canonical",
		},
		{
			name: "signature result digest",
			mutate: func(value *FinalizationInput) {
				value.Result.Signatures[2].SignatureDigest = bundle.Sum([]byte("other signature"))
			},
			match: "does not match the signing result",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			test.mutate(&fixture.final)
			err := VerifyFinalization(fixture.final)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("VerifyFinalization() error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestPlanValidationRejectsUnsafeModesAndInputs(t *testing.T) {
	fixture := newFixture(t)
	tests := []struct {
		name   string
		mutate func(*Plan)
		match  string
	}{
		{"recovery signing", func(value *Plan) { value.UpdaterFlags = []string{"-f", "-r"} }, "-f flag"},
		{"wall clock fallback", func(value *Plan) { value.SourceDateEpoch = 0 }, "source_date_epoch"},
		{"wrong order", func(value *Plan) {
			value.SigningInputs[0], value.SigningInputs[1] = value.SigningInputs[1], value.SigningInputs[0]
		}, "role"},
		{"missing call", func(value *Plan) { value.SigningInputs = value.SigningInputs[:2] }, "exactly 3"},
		{"unknown call", func(value *Plan) { value.SigningInputs[0].Role = "rpi5.arbitrary" }, "role"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := fixture.plan
			plan.UpdaterFlags = append([]string(nil), fixture.plan.UpdaterFlags...)
			plan.SigningInputs = append([]SigningInput(nil), fixture.plan.SigningInputs...)
			test.mutate(&plan)
			if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Plan.Validate() error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestPlanAllowsDistinctPinnedSourceAndFirmwareEpochs(t *testing.T) {
	plan := newFixture(t).plan
	plan.SourceDateEpoch--
	if plan.SourceDateEpoch == plan.FirmwareBuildEpoch {
		t.Fatal("test setup did not produce distinct epochs")
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("Plan.Validate() rejected distinct fixed epochs: %v", err)
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SourceDateEpoch != plan.SourceDateEpoch || parsed.FirmwareBuildEpoch != plan.FirmwareBuildEpoch {
		t.Fatalf("parsed epochs = source %d, firmware %d", parsed.SourceDateEpoch, parsed.FirmwareBuildEpoch)
	}
	baselineDigest, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	sourceChanged := parsed
	sourceChanged.SourceDateEpoch--
	sourceDigest, err := sourceChanged.Digest()
	if err != nil {
		t.Fatal(err)
	}
	firmwareChanged := parsed
	firmwareChanged.FirmwareBuildEpoch--
	firmwareDigest, err := firmwareChanged.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if baselineDigest == sourceDigest || baselineDigest == firmwareDigest || sourceDigest == firmwareDigest {
		t.Fatal("plan digest does not independently bind both fixed epochs")
	}
}

func TestStrictCanonicalPlanAndResultParsing(t *testing.T) {
	fixture := newFixture(t)
	planJSON, err := fixture.plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	resultJSON, err := fixture.result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for label, encoded := range map[string][]byte{
		"plan":   planJSON,
		"result": append(append([]byte(nil), resultJSON...), '\n'),
	} {
		var err error
		if label == "plan" {
			_, err = ParsePlan(encoded)
		} else {
			_, err = ParseResult(encoded)
		}
		if err != nil {
			t.Fatalf("parse canonical %s: %v", label, err)
		}
	}

	var planFields map[string]any
	if err := json.Unmarshal(planJSON, &planFields); err != nil {
		t.Fatal(err)
	}
	planFields["unknown"] = true
	unknown, _ := json.Marshal(planFields)
	if _, err := ParsePlan(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ParsePlan(unknown) error = %v", err)
	}
	duplicate := bytes.Replace(planJSON, []byte(`{"schema_version":`), []byte(`{"schema_version":"duplicate","schema_version":`), 1)
	if _, err := ParsePlan(duplicate); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("ParsePlan(duplicate) error = %v", err)
	}
	noncanonical := append([]byte(" "), planJSON...)
	if _, err := ParsePlan(noncanonical); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("ParsePlan(noncanonical) error = %v", err)
	}
	if _, err := ParseResult(append(resultJSON, []byte("\n{}")...)); err == nil {
		t.Fatal("ParseResult accepted a trailing JSON value")
	}
}

func TestCustomerPublicKeyBinaryAndFirmwareRejections(t *testing.T) {
	fixture := newFixture(t)
	publicBinary, err := CustomerPublicKeyBinary(&fixture.privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicBinary) != 264 || bundle.Sum(publicBinary) != fixture.plan.CustomerKeyHash {
		t.Fatalf("customer public key binary is not the planned 264-byte value")
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedFirmware(fixture.final.OriginalBootcode, fixture.final.ExtractedBootcode, publicBinary, &wrongKey.PublicKey); err == nil {
		t.Fatal("VerifySignedFirmware accepted a different public key")
	}
	tooLarge := make([]byte, maxFirmwareComponentBytes)
	if _, err := FirmwareSigningPreimage(tooLarge); err == nil {
		t.Fatal("FirmwareSigningPreimage accepted an oversized component")
	}
}

func newFixture(t *testing.T) testFixture {
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
	publicBinary, err := CustomerPublicKeyBinary(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	originalEEPROM := bytes.Repeat([]byte{0x5a}, 4096)
	originalRecovery := []byte("pinned unsigned recovery")
	originalBootcode := []byte("pinned bootcode")
	originalBootsys := []byte("pinned bootsys")
	bootConfig := []byte("BOOT_ORDER=0xf6\nBOOT_UART=1\n")
	signingInputs, err := NewSigningInputs(originalBootcode, originalBootsys, bootConfig)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		SchemaVersion: PlanSchemaV1Alpha1, PlanID: "eeprom-plan:test",
		ReleaseIntentDigest:         bundle.Sum([]byte("release intent")),
		EEPROMReleaseManifestDigest: bundle.Sum([]byte("EEPROM release manifest")),
		SignerPolicyDigest:          bundle.Sum([]byte("signer policy")),
		PublicKeyFingerprint:        bundle.Sum(publicDER), CustomerKeyHash: bundle.Sum(publicBinary),
		FirmwareBuildEpoch: testEpoch, SourceDateEpoch: testEpoch,
		UpdaterMode: UpdaterModeFreshBoard, UpdaterFlags: []string{"-f"},
		OriginalEEPROM: file(originalEEPROM), OriginalRecovery: file(originalRecovery),
		OriginalBootcode: file(originalBootcode), OriginalBootsys: file(originalBootsys),
		BootConfig: file(bootConfig), PublicKeyPEM: file(publicPEM), SigningInputs: signingInputs,
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	bootcodeSigned, bootcodeSignature := signFirmware(t, privateKey, publicBinary, originalBootcode)
	bootsysSigned, bootsysSignature := signFirmware(t, privateKey, publicBinary, originalBootsys)
	configSignature := sign(t, privateKey, bootConfig)
	configSig := []byte(hex.EncodeToString(sha256Bytes(bootConfig)) + "\nts: " + "1779807685" + "\nrsa2048: " + hex.EncodeToString(configSignature) + "\n")
	signedEEPROM := bytes.Repeat([]byte{0xa5}, len(originalEEPROM))
	updateMetadata := []byte(hex.EncodeToString(sha256Bytes(signedEEPROM)) + "\nts: 1779807685\n")
	signatures := []SignatureResult{
		signatureResult(RoleEEPROMBootcode, signingInputs[0], bootcodeSignature, "bootcode receipt"),
		signatureResult(RoleEEPROMBootsys, signingInputs[1], bootsysSignature, "bootsys receipt"),
		signatureResult(RoleEEPROMConfig, signingInputs[2], configSignature, "config receipt"),
	}
	result := Result{
		SchemaVersion: ResultSchemaV1Alpha1, PlanID: plan.PlanID, PlanDigest: planDigest,
		ReleaseIntentDigest: plan.ReleaseIntentDigest, EEPROMReleaseManifestDigest: plan.EEPROMReleaseManifestDigest,
		SignerPolicyDigest: plan.SignerPolicyDigest, PublicKeyFingerprint: plan.PublicKeyFingerprint,
		CustomerKeyHash: plan.CustomerKeyHash, SourceDateEpoch: plan.SourceDateEpoch,
		UpdaterMode: UpdaterModeFreshBoard, RecoveryMode: RecoveryModeUnsigned,
		Signatures: signatures, SignedEEPROM: file(signedEEPROM), EEPROMUpdateMetadata: file(updateMetadata),
		FreshRecoveryBootcode: file(originalRecovery),
	}
	final := FinalizationInput{
		Plan: plan, Result: result, OriginalEEPROM: originalEEPROM, OriginalRecovery: originalRecovery,
		OriginalBootcode: originalBootcode, OriginalBootsys: originalBootsys, BootConfig: bootConfig,
		PublicKeyPEM: publicPEM, SignedEEPROM: signedEEPROM, EEPROMUpdateMetadata: updateMetadata,
		FreshRecoveryBootcode: originalRecovery, ExtractedBootcode: bootcodeSigned,
		ExtractedBootsys: bootsysSigned, ExtractedBootConfig: bootConfig,
		ExtractedBootConfigSig: configSig, ExtractedPublicKeyBinary: publicBinary,
		OriginalCACertDER: []byte("pinned CA certificate"), ExtractedCACertDER: []byte("pinned CA certificate"),
		OriginalUpdateTime: []byte{1, 2, 3, 4, 5, 6, 7, 8}, ExtractedUpdateTime: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	return testFixture{privateKey: privateKey, plan: plan, result: result, final: cloneFinal(final)}
}

func file(contents []byte) File {
	return File{Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents))}
}

func signFirmware(t *testing.T, privateKey *rsa.PrivateKey, publicBinary, original []byte) ([]byte, []byte) {
	t.Helper()
	preimage, err := FirmwareSigningPreimage(original)
	if err != nil {
		t.Fatal(err)
	}
	signature := sign(t, privateKey, preimage)
	signed := append(append(append([]byte(nil), preimage...), signature...), publicBinary...)
	return signed, signature
}

func sign(t *testing.T, privateKey *rsa.PrivateKey, input []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(input)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func signatureResult(role SigningInputRole, input SigningInput, signature []byte, receipt string) SignatureResult {
	return SignatureResult{
		Role: role, InputDigest: input.Digest, InputSizeBytes: input.SizeBytes,
		SignatureDigest: bundle.Sum(signature), SignatureSizeBytes: uint64(len(signature)),
		GateReceiptDigest: bundle.Sum([]byte(receipt)),
	}
}

func sha256Bytes(input []byte) []byte {
	digest := sha256.Sum256(input)
	return digest[:]
}

func cloneFinal(input FinalizationInput) FinalizationInput {
	clone := input
	clone.Plan.UpdaterFlags = append([]string(nil), input.Plan.UpdaterFlags...)
	clone.Plan.SigningInputs = append([]SigningInput(nil), input.Plan.SigningInputs...)
	clone.Result.Signatures = append([]SignatureResult(nil), input.Result.Signatures...)
	for _, pair := range []struct {
		destination *[]byte
		source      []byte
	}{
		{&clone.OriginalEEPROM, input.OriginalEEPROM}, {&clone.OriginalRecovery, input.OriginalRecovery},
		{&clone.OriginalBootcode, input.OriginalBootcode}, {&clone.OriginalBootsys, input.OriginalBootsys},
		{&clone.BootConfig, input.BootConfig}, {&clone.PublicKeyPEM, input.PublicKeyPEM},
		{&clone.SignedEEPROM, input.SignedEEPROM}, {&clone.EEPROMUpdateMetadata, input.EEPROMUpdateMetadata},
		{&clone.FreshRecoveryBootcode, input.FreshRecoveryBootcode}, {&clone.ExtractedBootcode, input.ExtractedBootcode},
		{&clone.ExtractedBootsys, input.ExtractedBootsys}, {&clone.ExtractedBootConfig, input.ExtractedBootConfig},
		{&clone.ExtractedBootConfigSig, input.ExtractedBootConfigSig}, {&clone.ExtractedPublicKeyBinary, input.ExtractedPublicKeyBinary},
		{&clone.OriginalCACertDER, input.OriginalCACertDER}, {&clone.ExtractedCACertDER, input.ExtractedCACertDER},
		{&clone.OriginalUpdateTime, input.OriginalUpdateTime}, {&clone.ExtractedUpdateTime, input.ExtractedUpdateTime},
	} {
		*pair.destination = append([]byte(nil), pair.source...)
	}
	return clone
}
