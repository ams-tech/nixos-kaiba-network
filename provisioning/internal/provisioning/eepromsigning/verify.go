package eepromsigning

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const firmwareSigningTrailerBytes = 4 + 4 + 4 + rsaSignatureBytes + 264

// FirmwareSigningPreimage constructs the exact bytes presented to Raspberry
// Pi's HSM wrapper by rpi-sign-bootcode for BCM2712 customer signing: original
// bytes, original length, customer key number 16, and private version zero.
func FirmwareSigningPreimage(original []byte) ([]byte, error) {
	if len(original) == 0 || len(original)+firmwareSigningTrailerBytes > maxFirmwareComponentBytes {
		return nil, fmt.Errorf("firmware component size must leave room below %d bytes", maxFirmwareComponentBytes)
	}
	preimage := make([]byte, len(original)+12)
	copy(preimage, original)
	binary.LittleEndian.PutUint32(preimage[len(original):], uint32(len(original)))
	binary.LittleEndian.PutUint32(preimage[len(original)+4:], 16)
	binary.LittleEndian.PutUint32(preimage[len(original)+8:], 0)
	return preimage, nil
}

// NewSigningInputs derives the only accepted -f callback order.
func NewSigningInputs(bootcode, bootsys, bootConfig []byte) ([]SigningInput, error) {
	bootcodePreimage, err := FirmwareSigningPreimage(bootcode)
	if err != nil {
		return nil, fmt.Errorf("bootcode signing input: %w", err)
	}
	bootsysPreimage, err := FirmwareSigningPreimage(bootsys)
	if err != nil {
		return nil, fmt.Errorf("bootsys signing input: %w", err)
	}
	if len(bootConfig) == 0 || len(bootConfig) > maxBootConfigBytes {
		return nil, fmt.Errorf("boot config size must be between 1 and %d", maxBootConfigBytes)
	}
	return []SigningInput{
		{Role: RoleEEPROMBootcode, Digest: bundle.Sum(bootcodePreimage), SizeBytes: uint64(len(bootcodePreimage))},
		{Role: RoleEEPROMBootsys, Digest: bundle.Sum(bootsysPreimage), SizeBytes: uint64(len(bootsysPreimage))},
		{Role: RoleEEPROMConfig, Digest: bundle.Sum(bootConfig), SizeBytes: uint64(len(bootConfig))},
	}, nil
}

// CustomerPublicKeyBinary emits Raspberry Pi's irreversible 264-byte N,e
// representation (little-endian 2048-bit modulus followed by little-endian
// uint64 exponent).
func CustomerPublicKeyBinary(publicKey *rsa.PublicKey) ([]byte, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	modulusBigEndian := publicKey.N.FillBytes(make([]byte, rsaSignatureBytes))
	encoded := make([]byte, 264)
	for index := range modulusBigEndian {
		encoded[index] = modulusBigEndian[len(modulusBigEndian)-1-index]
	}
	binary.LittleEndian.PutUint64(encoded[rsaSignatureBytes:], uint64(publicKey.E))
	return encoded, nil
}

func parsePublicKey(encoded []byte) (*rsa.PublicKey, bundle.Digest, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maxPublicKeyPEMBytes {
		return nil, "", nil, fmt.Errorf("public key size must be between 1 and %d bytes", maxPublicKeyPEMBytes)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, "", nil, errors.New("public key must contain exactly one headerless PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", nil, errors.New("public key is not valid PKIX DER")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, "", nil, errors.New("public key is not RSA")
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, "", nil, err
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", nil, err
	}
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: canonicalDER})
	if !bytes.Equal(encoded, canonicalPEM) {
		return nil, "", nil, errors.New("public key is not canonical PKIX PEM")
	}
	publicBinary, err := CustomerPublicKeyBinary(publicKey)
	if err != nil {
		return nil, "", nil, err
	}
	return publicKey, bundle.Sum(canonicalDER), publicBinary, nil
}

// ParsePublicKey validates one canonical RSA-2048 PKIX PEM public key and
// returns its SPKI fingerprint plus Raspberry Pi's 264-byte N,e encoding.
func ParsePublicKey(encoded []byte) (*rsa.PublicKey, bundle.Digest, []byte, error) {
	return parsePublicKey(encoded)
}

// VerifySignature verifies one raw 256-byte RSA-2048/SHA-256/PKCS#1 v1.5
// signature. Runtime adapters use this immediately after each gate response,
// before allowing the pinned updater to consume the signature.
func VerifySignature(publicKey *rsa.PublicKey, input, signature []byte) error {
	if err := validatePublicKey(publicKey); err != nil {
		return err
	}
	if len(input) == 0 {
		return errors.New("signature input must not be empty")
	}
	if len(signature) != rsaSignatureBytes {
		return fmt.Errorf("signature is %d bytes, want %d", len(signature), rsaSignatureBytes)
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return errors.New("RSA-2048/SHA-256 signature is invalid")
	}
	return nil
}

func validatePublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() != 2048 || publicKey.Size() != rsaSignatureBytes || publicKey.E != 65537 {
		return errors.New("public key must be RSA-2048 with exponent 65537")
	}
	return nil
}

// VerifySignedFirmware verifies one complete rpi-sign-bootcode BCM2712 output
// and returns the embedded raw customer signature.
func VerifySignedFirmware(original, signed, expectedPublicKeyBinary []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	preimage, err := FirmwareSigningPreimage(original)
	if err != nil {
		return nil, err
	}
	expectedSize := len(original) + firmwareSigningTrailerBytes
	if len(signed) != expectedSize {
		return nil, fmt.Errorf("signed firmware size is %d, want %d", len(signed), expectedSize)
	}
	if !bytes.Equal(signed[:len(preimage)], preimage) {
		return nil, errors.New("signed firmware preimage differs from the planned component, key number, or version")
	}
	signatureStart := len(preimage)
	publicKeyStart := signatureStart + rsaSignatureBytes
	if len(expectedPublicKeyBinary) != 264 || !bytes.Equal(signed[publicKeyStart:], expectedPublicKeyBinary) {
		return nil, errors.New("signed firmware embeds a different customer public key")
	}
	signature := append([]byte(nil), signed[signatureStart:publicKeyStart]...)
	if err := VerifySignature(publicKey, preimage, signature); err != nil {
		return nil, errors.New("signed firmware customer signature is invalid")
	}
	return signature, nil
}

type signatureDocument struct {
	digest    bundle.Digest
	epoch     uint64
	signature []byte
}

func parseSignatureDocument(encoded []byte, signatureRequired bool) (signatureDocument, error) {
	lines := strings.Split(string(encoded), "\n")
	expectedLines := 3
	if signatureRequired {
		expectedLines = 4
	}
	if len(lines) != expectedLines || lines[len(lines)-1] != "" {
		return signatureDocument{}, errors.New("signature metadata is not canonical newline-terminated text")
	}
	if len(lines[0]) != 64 {
		return signatureDocument{}, errors.New("signature metadata image digest is malformed")
	}
	for _, char := range lines[0] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return signatureDocument{}, errors.New("signature metadata image digest is not lowercase hexadecimal")
		}
	}
	if !strings.HasPrefix(lines[1], "ts: ") {
		return signatureDocument{}, errors.New("signature metadata timestamp is malformed")
	}
	epochText := strings.TrimPrefix(lines[1], "ts: ")
	epoch, err := strconv.ParseUint(epochText, 10, 64)
	if err != nil || strconv.FormatUint(epoch, 10) != epochText || epoch > maxSourceDateEpoch {
		return signatureDocument{}, errors.New("signature metadata timestamp is not canonical")
	}
	document := signatureDocument{digest: bundle.Digest("sha256:" + lines[0]), epoch: epoch}
	if !signatureRequired {
		return document, nil
	}
	if !strings.HasPrefix(lines[2], "rsa2048: ") {
		return signatureDocument{}, errors.New("customer signature line is missing")
	}
	hexSignature := strings.TrimPrefix(lines[2], "rsa2048: ")
	if len(hexSignature) != rsaSignatureBytes*2 {
		return signatureDocument{}, errors.New("customer signature has the wrong size")
	}
	signature, err := hex.DecodeString(hexSignature)
	if err != nil || hex.EncodeToString(signature) != hexSignature {
		return signatureDocument{}, errors.New("customer signature is not canonical lowercase hexadecimal")
	}
	document.signature = signature
	return document, nil
}

func verifyBootConfigSignature(config, encoded []byte, epoch uint64, publicKey *rsa.PublicKey) ([]byte, error) {
	document, err := parseSignatureDocument(encoded, true)
	if err != nil {
		return nil, fmt.Errorf("boot config signature: %w", err)
	}
	if document.digest != bundle.Sum(config) {
		return nil, errors.New("boot config signature digest does not match boot.conf")
	}
	if document.epoch != epoch {
		return nil, errors.New("boot config signature timestamp does not match SOURCE_DATE_EPOCH")
	}
	digest := sha256.Sum256(config)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], document.signature); err != nil {
		return nil, errors.New("boot config customer signature is invalid")
	}
	return document.signature, nil
}

func verifyUpdateMetadata(signedEEPROM, encoded []byte, epoch uint64) error {
	document, err := parseSignatureDocument(encoded, false)
	if err != nil {
		return fmt.Errorf("EEPROM update metadata: %w", err)
	}
	if document.digest != bundle.Sum(signedEEPROM) {
		return errors.New("EEPROM update metadata digest does not match pieeprom.bin")
	}
	if document.epoch != epoch {
		return errors.New("EEPROM update metadata timestamp does not match SOURCE_DATE_EPOCH")
	}
	return nil
}

// VerifyBindings checks that a public result is a response to the exact plan.
func VerifyBindings(plan Plan, result Result) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate EEPROM signing plan: %w", err)
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate EEPROM signing result: %w", err)
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return err
	}
	if result.PlanID != plan.PlanID || result.PlanDigest != planDigest {
		return errors.New("EEPROM signing result does not bind the exact plan")
	}
	if result.ReleaseIntentDigest != plan.ReleaseIntentDigest || result.EEPROMReleaseManifestDigest != plan.EEPROMReleaseManifestDigest {
		return errors.New("EEPROM signing result does not bind the planned release intent and EEPROM release")
	}
	if result.SignerPolicyDigest != plan.SignerPolicyDigest || result.PublicKeyFingerprint != plan.PublicKeyFingerprint || result.CustomerKeyHash != plan.CustomerKeyHash {
		return errors.New("EEPROM signing result does not bind the planned signer and customer key")
	}
	if result.SourceDateEpoch != plan.SourceDateEpoch || result.UpdaterMode != plan.UpdaterMode || result.RecoveryMode != RecoveryModeUnsigned {
		return errors.New("EEPROM signing result does not bind the planned deterministic updater mode")
	}
	for index, signature := range result.Signatures {
		planned := plan.SigningInputs[index]
		if signature.Role != planned.Role || signature.InputDigest != planned.Digest || signature.InputSizeBytes != planned.SizeBytes {
			return fmt.Errorf("signature result %d does not bind the planned signing input", index)
		}
	}
	if result.SignedEEPROM.SizeBytes != plan.OriginalEEPROM.SizeBytes {
		return errors.New("signed EEPROM size differs from the original EEPROM size")
	}
	if result.FreshRecoveryBootcode != plan.OriginalRecovery {
		return errors.New("fresh-board recovery record must equal the unsigned original recovery record")
	}
	return nil
}

// FinalizationInput is a snapshot of public files. Extracted* must be obtained
// from SignedEEPROM by the separately pinned rpi-eeprom-config boundary. This
// verifier checks every extracted byte and embedded signature but intentionally
// makes no claim about a hardware write, OTP, or authentic gate receipt.
type FinalizationInput struct {
	Plan                     Plan
	Result                   Result
	OriginalEEPROM           []byte
	OriginalRecovery         []byte
	OriginalBootcode         []byte
	OriginalBootsys          []byte
	BootConfig               []byte
	PublicKeyPEM             []byte
	SignedEEPROM             []byte
	EEPROMUpdateMetadata     []byte
	FreshRecoveryBootcode    []byte
	ExtractedBootcode        []byte
	ExtractedBootsys         []byte
	ExtractedBootConfig      []byte
	ExtractedBootConfigSig   []byte
	ExtractedPublicKeyBinary []byte
	OriginalCACertDER        []byte
	ExtractedCACertDER       []byte
	OriginalUpdateTime       []byte
	ExtractedUpdateTime      []byte
}

// VerifyFinalization performs pure offline verification of the complete
// fresh-board EEPROM output and the three customer signatures.
func VerifyFinalization(input FinalizationInput) error {
	if err := VerifyBindings(input.Plan, input.Result); err != nil {
		return err
	}
	for _, item := range []struct {
		label    string
		record   File
		contents []byte
	}{
		{"original EEPROM", input.Plan.OriginalEEPROM, input.OriginalEEPROM},
		{"original recovery", input.Plan.OriginalRecovery, input.OriginalRecovery},
		{"original bootcode", input.Plan.OriginalBootcode, input.OriginalBootcode},
		{"original bootsys", input.Plan.OriginalBootsys, input.OriginalBootsys},
		{"boot config", input.Plan.BootConfig, input.BootConfig},
		{"public key PEM", input.Plan.PublicKeyPEM, input.PublicKeyPEM},
		{"signed EEPROM", input.Result.SignedEEPROM, input.SignedEEPROM},
		{"EEPROM update metadata", input.Result.EEPROMUpdateMetadata, input.EEPROMUpdateMetadata},
		{"fresh recovery bootcode", input.Result.FreshRecoveryBootcode, input.FreshRecoveryBootcode},
	} {
		if err := item.record.Match(item.label, item.contents); err != nil {
			return err
		}
	}
	if !bytes.Equal(input.FreshRecoveryBootcode, input.OriginalRecovery) {
		return errors.New("fresh-board bootcode5.bin is not the unsigned pinned recovery image")
	}
	if !bytes.Equal(input.ExtractedBootConfig, input.BootConfig) {
		return errors.New("signed EEPROM embeds a different boot config")
	}
	if len(input.OriginalCACertDER) == 0 || !bytes.Equal(input.ExtractedCACertDER, input.OriginalCACertDER) {
		return errors.New("signed EEPROM changes the pinned CA certificate section")
	}
	if len(input.OriginalUpdateTime) == 0 || !bytes.Equal(input.ExtractedUpdateTime, input.OriginalUpdateTime) {
		return errors.New("signed EEPROM changes the pinned update-time section")
	}
	publicKey, fingerprint, publicBinary, err := parsePublicKey(input.PublicKeyPEM)
	if err != nil {
		return err
	}
	if fingerprint != input.Plan.PublicKeyFingerprint {
		return errors.New("public key fingerprint does not match the signing plan")
	}
	if bundle.Sum(publicBinary) != input.Plan.CustomerKeyHash {
		return errors.New("Raspberry Pi customer-key hash does not match the signing plan")
	}
	if !bytes.Equal(input.ExtractedPublicKeyBinary, publicBinary) {
		return errors.New("signed EEPROM embeds a different customer public key")
	}
	derivedInputs, err := NewSigningInputs(input.OriginalBootcode, input.OriginalBootsys, input.BootConfig)
	if err != nil {
		return err
	}
	for index := range derivedInputs {
		if derivedInputs[index] != input.Plan.SigningInputs[index] {
			return fmt.Errorf("planned signing input %d does not match the public input bytes", index)
		}
	}
	bootcodeSignature, err := VerifySignedFirmware(input.OriginalBootcode, input.ExtractedBootcode, publicBinary, publicKey)
	if err != nil {
		return fmt.Errorf("verify embedded bootcode: %w", err)
	}
	bootsysSignature, err := VerifySignedFirmware(input.OriginalBootsys, input.ExtractedBootsys, publicBinary, publicKey)
	if err != nil {
		return fmt.Errorf("verify embedded bootsys: %w", err)
	}
	configSignature, err := verifyBootConfigSignature(input.BootConfig, input.ExtractedBootConfigSig, input.Plan.SourceDateEpoch, publicKey)
	if err != nil {
		return err
	}
	actualSignatures := [][]byte{bootcodeSignature, bootsysSignature, configSignature}
	for index, signature := range actualSignatures {
		result := input.Result.Signatures[index]
		if result.SignatureSizeBytes != uint64(len(signature)) || result.SignatureDigest != bundle.Sum(signature) {
			return fmt.Errorf("embedded %s signature does not match the signing result", result.Role)
		}
	}
	if err := verifyUpdateMetadata(input.SignedEEPROM, input.EEPROMUpdateMetadata, input.Plan.SourceDateEpoch); err != nil {
		return err
	}
	return nil
}

// VerifiedSignatures contains the three raw customer signatures recovered
// from an EEPROM that passed the complete public finalization verifier.
type VerifiedSignatures struct {
	Bootcode   []byte
	Bootsys    []byte
	BootConfig []byte
}

// ExtractVerifiedSignatures first performs complete offline verification and
// then returns signature bytes suitable only for deterministic public replay
// of the same pinned updater invocation. It grants no signing authority.
func ExtractVerifiedSignatures(input FinalizationInput) (VerifiedSignatures, error) {
	if err := VerifyFinalization(input); err != nil {
		return VerifiedSignatures{}, err
	}
	publicKey, _, publicBinary, err := parsePublicKey(input.PublicKeyPEM)
	if err != nil {
		return VerifiedSignatures{}, err
	}
	bootcode, err := VerifySignedFirmware(input.OriginalBootcode, input.ExtractedBootcode, publicBinary, publicKey)
	if err != nil {
		return VerifiedSignatures{}, err
	}
	bootsys, err := VerifySignedFirmware(input.OriginalBootsys, input.ExtractedBootsys, publicBinary, publicKey)
	if err != nil {
		return VerifiedSignatures{}, err
	}
	bootConfig, err := verifyBootConfigSignature(input.BootConfig, input.ExtractedBootConfigSig, input.Plan.SourceDateEpoch, publicKey)
	if err != nil {
		return VerifiedSignatures{}, err
	}
	return VerifiedSignatures{
		Bootcode: append([]byte(nil), bootcode...), Bootsys: append([]byte(nil), bootsys...),
		BootConfig: append([]byte(nil), bootConfig...),
	}, nil
}
