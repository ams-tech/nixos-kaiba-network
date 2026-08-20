package yubikeysigner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

var fixedEnvironmentLocale = []string{"LANG=C", "LC_ALL=C"}

// Sign snapshots one runtime-owned gate input, invokes the fixed provider-backed
// RSA/SHA-256 operation, and independently verifies the 256-byte result before
// returning it. The PIN is never read by this process; OpenSSL's immutable
// provider configuration reads it directly from the protected credential.
func (s *Signer) Sign(ctx context.Context, inputPath string) ([]byte, error) {
	if err := cleanAbsolutePath("input", inputPath); err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := validatePrivateDirectory(s.temporaryRoot, s.runtimeOwnerUID); err != nil {
		return nil, fmt.Errorf("validate private temporary root: %w", err)
	}
	temporaryDirectory, err := os.MkdirTemp(s.temporaryRoot, "kaiba-yubikey-sign-")
	if err != nil {
		return nil, fmt.Errorf("create private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	if err := os.Chmod(temporaryDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("protect private temporary directory: %w", err)
	}

	snapshotPath := filepath.Join(temporaryDirectory, "approved-input.bin")
	inputIdentity, snapshotIdentity, err := snapshotInput(inputPath, snapshotPath, s.runtimeOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("snapshot approved input: %w", err)
	}
	publicKeyPath := filepath.Join(temporaryDirectory, "expected-public-key.pem")
	publicKeyIdentity, err := writePrivateFile(publicKeyPath, s.publicKeyPEM, 0o400)
	if err != nil {
		return nil, fmt.Errorf("prepare public key: %w", err)
	}
	signaturePath := filepath.Join(temporaryDirectory, "signature.bin")
	output, err := os.OpenFile(signaturePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("prepare signature output: %w", err)
	}
	if err := output.Close(); err != nil {
		return nil, fmt.Errorf("prepare signature output: %w", err)
	}
	outputInfo, err := os.Lstat(signaturePath)
	if err != nil {
		return nil, fmt.Errorf("prepare signature output: %w", err)
	}
	outputIdentity, err := statIdentity(outputInfo)
	if err != nil {
		return nil, fmt.Errorf("prepare signature output: %w", err)
	}

	credentialIdentity, err := s.credentialValidator(s.pinPath, s.trustedOwnerUID, s.runtimeOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("PIN credential: %w", err)
	}
	environment := append(append([]string(nil), fixedEnvironmentLocale...), "OPENSSL_CONF="+s.opensslConfigPath)
	signInvocation := Invocation{
		Path: s.opensslPath,
		Args: []string{
			"dgst", "-sha256", "-sign", s.pkcs11URI,
			"-sigopt", "rsa_padding_mode:pkcs1",
			"-out", signaturePath, snapshotPath,
		},
		Env: environment,
	}
	result, err := s.runner.Run(operationContext, signInvocation)
	if err != nil {
		if operationContext.Err() != nil {
			return nil, fmt.Errorf("YubiKey signing timed out or was cancelled: %w", operationContext.Err())
		}
		return nil, errors.New("YubiKey signing command failed")
	}
	if len(result.Stdout) > maxDiagnosticBytes || len(result.Stderr) > maxDiagnosticBytes || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		return nil, errors.New("YubiKey signing command produced unexpected output")
	}
	if err := validateUnchanged(snapshotPath, snapshotIdentity); err != nil {
		return nil, fmt.Errorf("approved input snapshot: %w", err)
	}
	if err := validateUnchanged(s.pinPath, credentialIdentity); err != nil {
		return nil, fmt.Errorf("PIN credential: %w", err)
	}
	signature, _, err := readSignature(signaturePath, s.runtimeOwnerUID, outputIdentity)
	if err != nil {
		return nil, fmt.Errorf("read YubiKey signature: %w", err)
	}
	if err := os.Chmod(signaturePath, 0o400); err != nil {
		return nil, fmt.Errorf("protect YubiKey signature: %w", err)
	}
	protectedSignatureInfo, err := os.Lstat(signaturePath)
	if err != nil {
		return nil, fmt.Errorf("protect YubiKey signature: %w", err)
	}
	protectedSignatureIdentity, err := statIdentity(protectedSignatureInfo)
	if err != nil {
		return nil, fmt.Errorf("protect YubiKey signature: %w", err)
	}

	verifyInvocation := Invocation{
		Path: s.opensslPath,
		Args: []string{
			"dgst", "-sha256", "-verify", publicKeyPath,
			"-signature", signaturePath,
			"-sigopt", "rsa_padding_mode:pkcs1",
			snapshotPath,
		},
		Env: environment,
	}
	verification, err := s.runner.Run(operationContext, verifyInvocation)
	if err != nil {
		if operationContext.Err() != nil {
			return nil, fmt.Errorf("signature verification timed out or was cancelled: %w", operationContext.Err())
		}
		return nil, errors.New("signature verification command failed")
	}
	if len(verification.Stdout) > maxDiagnosticBytes || len(verification.Stderr) > maxDiagnosticBytes ||
		!bytes.Equal(verification.Stdout, []byte("Verified OK\n")) || len(verification.Stderr) != 0 {
		return nil, errors.New("signature verification output was not the expected success response")
	}
	if err := validateUnchanged(inputPath, inputIdentity); err != nil {
		return nil, fmt.Errorf("approved input: %w", err)
	}
	if err := validateUnchanged(snapshotPath, snapshotIdentity); err != nil {
		return nil, fmt.Errorf("approved input snapshot: %w", err)
	}
	if err := validateUnchanged(publicKeyPath, publicKeyIdentity); err != nil {
		return nil, fmt.Errorf("expected public key: %w", err)
	}
	if err := validateUnchanged(s.pinPath, credentialIdentity); err != nil {
		return nil, fmt.Errorf("PIN credential: %w", err)
	}
	if err := validateUnchanged(signaturePath, protectedSignatureIdentity); err != nil {
		return nil, fmt.Errorf("verified signature: %w", err)
	}
	verifiedSignature, _, err := readSignatureFile(signaturePath, s.runtimeOwnerUID, protectedSignatureIdentity)
	if err != nil || !bytes.Equal(verifiedSignature, signature) {
		return nil, errors.New("signature changed after verification")
	}
	return bytes.Clone(signature), nil
}

func readSignatureFile(path string, runtimeOwnerUID uint32, expected fileIdentity) ([]byte, fileIdentity, error) {
	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	defer file.Close()
	identity, err := statIdentity(info)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if identity != expected || identity.uid != runtimeOwnerUID || info.Mode().Perm() != 0o400 || info.Size() != int64(signing.RSASignatureBytes) {
		return nil, fileIdentity{}, errors.New("verified signature file changed")
	}
	data := make([]byte, signing.RSASignatureBytes)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fileIdentity{}, err
	}
	return data, identity, nil
}
