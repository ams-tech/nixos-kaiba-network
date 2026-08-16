package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/yubikeysigner"
)

const (
	exitOK                   = 0
	exitInternal             = 1
	exitUsage                = 2
	exitSigner               = 3
	privateTemporaryRootPath = "/run/kaiba-provision-signing"
)

// These paths and public selectors are supplied only by the immutable Nix
// build. There are intentionally no flag or environment overrides.
var (
	opensslExecutablePath               string
	opensslConfigurationPath            string
	pkcs11ProviderModulePath            string
	ykcs11ModulePath                    string
	yubiKeyPKCS11URI                    string
	yubiKeyPINCredentialPath            string
	yubiKeyPublicKeyPEMPath             string
	yubiKeyExpectedPublicKeyFingerprint string
)

type fileSigner interface {
	Sign(context.Context, string) ([]byte, error)
}

type dependencies struct {
	signer fileSigner
	err    error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func productionDependencies() dependencies {
	fingerprint, err := bundle.ParseDigest(yubiKeyExpectedPublicKeyFingerprint)
	if err != nil {
		return dependencies{err: fmt.Errorf("expected public-key fingerprint: %w", err)}
	}
	signer, err := yubikeysigner.New(yubikeysigner.Config{
		OpenSSLPath: opensslExecutablePath, OpenSSLConfigPath: opensslConfigurationPath,
		PKCS11ProviderModulePath: pkcs11ProviderModulePath, YKCS11ModulePath: ykcs11ModulePath,
		PKCS11URI: yubiKeyPKCS11URI, PINCredentialPath: yubiKeyPINCredentialPath,
		PrivateTemporaryRootPath:     privateTemporaryRootPath,
		PublicKeyPEMPath:             yubiKeyPublicKeyPEMPath,
		ExpectedPublicKeyFingerprint: fingerprint,
		TrustedOwnerUID:              0, RuntimeOwnerUID: uint32(os.Geteuid()),
		OperationTimeout: yubikeysigner.DefaultOperationTimeout,
		Runner:           yubikeysigner.ExecRunner{},
	})
	return dependencies{signer: signer, err: err}
}

// run implements Raspberry Pi's complete external HSM-wrapper protocol and
// accepts no other operation or selection surface.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) != 3 || args[0] != "-a" || args[1] != string(signing.AlgorithmRSA2048SHA256) || args[2] == "" {
		fmt.Fprintln(stderr, "usage: kaiba-provision-yubikey-wrapper -a rsa2048-sha256 INPUT_FILE")
		return exitUsage
	}
	if deps.err != nil {
		fmt.Fprintf(stderr, "YubiKey wrapper configuration: %v\n", deps.err)
		return exitInternal
	}
	if deps.signer == nil {
		fmt.Fprintln(stderr, "YubiKey wrapper configuration: signer is unavailable")
		return exitInternal
	}
	signature, err := deps.signer.Sign(ctx, args[2])
	if err != nil {
		fmt.Fprintf(stderr, "YubiKey signing failed: %v\n", err)
		return exitSigner
	}
	if len(signature) != signing.RSASignatureBytes {
		fmt.Fprintf(stderr, "YubiKey signing failed: signature is %d bytes, want %d\n", len(signature), signing.RSASignatureBytes)
		return exitSigner
	}
	if _, err := fmt.Fprintln(stdout, hex.EncodeToString(signature)); err != nil {
		fmt.Fprintf(stderr, "write signature: %v\n", err)
		return exitInternal
	}
	return exitOK
}
