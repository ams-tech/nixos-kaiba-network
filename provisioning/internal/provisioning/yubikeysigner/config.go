// Package yubikeysigner implements the immutable YubiKey PKCS#11 backend used
// behind the approval gate. It uses a pinned OpenSSL 3 PKCS#11 provider whose
// configuration fixes YKCS11 and a credential-file PIN source.
package yubikeysigner

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	DefaultOperationTimeout = 2 * time.Minute
	canonicalURIPrefix      = "pkcs11:serial="
	canonicalURISuffix      = ";id=%02;type=private"
)

var yubiKeySerialPattern = regexp.MustCompile(`^[0-9]{1,16}$`)

// Config is populated only by immutable build settings. None of its fields is
// selected by an approval request, browser action, environment variable, or
// wrapper flag.
type Config struct {
	OpenSSLPath                  string
	OpenSSLConfigPath            string
	PKCS11ProviderModulePath     string
	YKCS11ModulePath             string
	PKCS11URI                    string
	PINCredentialPath            string
	PrivateTemporaryRootPath     string
	PublicKeyPEMPath             string
	ExpectedPublicKeyFingerprint bundle.Digest
	TrustedOwnerUID              uint32
	RuntimeOwnerUID              uint32
	OperationTimeout             time.Duration
	Runner                       Runner
}

// Signer signs exactly one file snapshot through the fixed YubiKey object and
// verifies the returned RSA signature against the fixed public key.
type Signer struct {
	opensslPath         string
	opensslConfigPath   string
	pkcs11URI           string
	pinPath             string
	temporaryRoot       string
	publicKeyPEM        []byte
	trustedOwnerUID     uint32
	runtimeOwnerUID     uint32
	credentialValidator func(string, uint32, uint32) (fileIdentity, error)
	timeout             time.Duration
	runner              Runner
}

func New(config Config) (*Signer, error) {
	paths := []struct {
		name string
		path string
	}{
		{name: "OpenSSL executable", path: config.OpenSSLPath},
		{name: "OpenSSL configuration", path: config.OpenSSLConfigPath},
		{name: "PKCS#11 provider module", path: config.PKCS11ProviderModulePath},
		{name: "YKCS11 module", path: config.YKCS11ModulePath},
		{name: "PIN credential", path: config.PINCredentialPath},
		{name: "private temporary root", path: config.PrivateTemporaryRootPath},
		{name: "public-key PEM", path: config.PublicKeyPEMPath},
	}
	for _, configuredPath := range paths {
		if err := cleanAbsolutePath(configuredPath.name, configuredPath.path); err != nil {
			return nil, err
		}
	}
	if _, err := parseCanonicalPKCS11URI(config.PKCS11URI); err != nil {
		return nil, err
	}
	if err := config.ExpectedPublicKeyFingerprint.Validate(); err != nil {
		return nil, fmt.Errorf("expected public-key fingerprint: %w", err)
	}
	if config.OperationTimeout <= 0 || config.OperationTimeout > 5*time.Minute {
		return nil, errors.New("operation timeout must be positive and at most five minutes")
	}
	if config.Runner == nil {
		return nil, errors.New("process runner is unavailable")
	}
	if _, err := trustedFile(config.OpenSSLPath, config.TrustedOwnerUID, true, 256*1024*1024); err != nil {
		return nil, fmt.Errorf("OpenSSL executable: %w", err)
	}
	if _, err := trustedFile(config.PKCS11ProviderModulePath, config.TrustedOwnerUID, false, 32*1024*1024); err != nil {
		return nil, fmt.Errorf("PKCS#11 provider module: %w", err)
	}
	if _, err := trustedFile(config.YKCS11ModulePath, config.TrustedOwnerUID, false, 32*1024*1024); err != nil {
		return nil, fmt.Errorf("YKCS11 module: %w", err)
	}
	opensslConfig, err := trustedFile(config.OpenSSLConfigPath, config.TrustedOwnerUID, false, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("OpenSSL configuration: %w", err)
	}
	expectedOpenSSLConfig := canonicalOpenSSLConfig(
		config.PKCS11ProviderModulePath,
		config.YKCS11ModulePath,
		config.PINCredentialPath,
	)
	if !bytes.Equal(opensslConfig, expectedOpenSSLConfig) {
		return nil, errors.New("OpenSSL configuration does not match the canonical provider configuration")
	}
	publicKeyPEM, err := trustedFile(config.PublicKeyPEMPath, config.TrustedOwnerUID, false, maxPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("public-key PEM: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("public-key PEM: %w", err)
	}
	if fingerprint != config.ExpectedPublicKeyFingerprint {
		return nil, fmt.Errorf("public-key fingerprint is %s, want %s", fingerprint, config.ExpectedPublicKeyFingerprint)
	}
	return &Signer{
		opensslPath: config.OpenSSLPath, opensslConfigPath: config.OpenSSLConfigPath,
		pkcs11URI: config.PKCS11URI, pinPath: config.PINCredentialPath,
		temporaryRoot: config.PrivateTemporaryRootPath,
		publicKeyPEM:  bytes.Clone(publicKeyPEM), trustedOwnerUID: config.TrustedOwnerUID,
		runtimeOwnerUID:     config.RuntimeOwnerUID,
		credentialValidator: validateCredential,
		timeout:             config.OperationTimeout, runner: config.Runner,
	}, nil
}

func canonicalOpenSSLConfig(providerModulePath, ykcs11ModulePath, pinCredentialPath string) []byte {
	return []byte(fmt.Sprintf(`config_diagnostics = 1
openssl_conf = kaiba_openssl_init

[kaiba_openssl_init]
providers = kaiba_provider_sect

[kaiba_provider_sect]
default = kaiba_default_sect
pkcs11 = kaiba_pkcs11_sect

[kaiba_default_sect]
activate = 1

[kaiba_pkcs11_sect]
module = %s
pkcs11-module-path = %s
pkcs11-module-token-pin = file:%s
pkcs11-module-cache-keys = false
pkcs11-module-cache-sessions = 0
pkcs11-module-login-behavior = always
activate = 1
`, providerModulePath, ykcs11ModulePath, pinCredentialPath))
}

func parseCanonicalPKCS11URI(uri string) (string, error) {
	if len(uri) <= len(canonicalURIPrefix)+len(canonicalURISuffix) ||
		!bytes.HasPrefix([]byte(uri), []byte(canonicalURIPrefix)) ||
		!bytes.HasSuffix([]byte(uri), []byte(canonicalURISuffix)) {
		return "", errors.New("PKCS#11 URI must use canonical pkcs11:serial=<serial>;id=%02;type=private form")
	}
	serial := uri[len(canonicalURIPrefix) : len(uri)-len(canonicalURISuffix)]
	if !yubiKeySerialPattern.MatchString(serial) {
		return "", errors.New("PKCS#11 URI serial must contain 1 to 16 decimal digits")
	}
	return serial, nil
}

// publicKeyFingerprint is SHA-256 over canonical SubjectPublicKeyInfo DER, not
// over PEM text and not over Raspberry Pi's separately defined OTP key hash.
func publicKeyFingerprint(encoded []byte) (bundle.Digest, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("expected exactly one header-free PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New("invalid SubjectPublicKeyInfo")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.Size() != 256 || publicKey.N.BitLen() != 2048 || publicKey.E != 65537 {
		return "", errors.New("public key must be RSA-2048 with exponent 65537")
	}
	canonical, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(canonical, block.Bytes) {
		return "", errors.New("public key is not canonical SubjectPublicKeyInfo DER")
	}
	return bundle.Sum(canonical), nil
}
