package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInput    = 3
	exitSigner   = 4
)

// These values are intentionally supplied by the immutable production build.
// They have no flag or environment-variable override. The executable must be
// the control-host approval gate, not a general PKCS#11 command.
var (
	approvalGatedSignerPath          string
	approvalGatedSignerArgumentsJSON string
	developmentSignerID              string
	developmentCohortID              string
	developmentPKCS11URI             string
	developmentPublicKeyFingerprint  string
)

type dependencies struct {
	backend signing.Backend
	policy  signing.YubiKeyPolicy
	err     error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func productionDependencies() dependencies {
	fingerprint, err := bundle.ParseDigest(developmentPublicKeyFingerprint)
	if err != nil {
		return dependencies{err: fmt.Errorf("development public-key fingerprint: %w", err)}
	}
	policy, err := signing.NewDevelopmentYubiKeyPolicy(
		developmentSignerID,
		developmentCohortID,
		developmentPKCS11URI,
		fingerprint,
	)
	if err != nil {
		return dependencies{err: err}
	}
	arguments, err := parseFixedArguments(approvalGatedSignerArgumentsJSON)
	if err != nil {
		return dependencies{err: err}
	}
	backend, err := signing.NewExternalCommandBackend(signing.ExternalCommandConfig{
		ExecutablePath: approvalGatedSignerPath,
		FixedArguments: arguments,
	})
	if err != nil {
		return dependencies{err: err}
	}
	return dependencies{backend: backend, policy: policy}
}

// run implements Raspberry Pi's exact external HSM-wrapper protocol:
//
//	kaiba-provision-signer -a rsa2048-sha256 INPUT_FILE
//
// It intentionally has no other command, flag, role, key, executable, or
// module selection surface.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) != 3 || args[0] != "-a" || args[1] != string(signing.AlgorithmRSA2048SHA256) || args[2] == "" {
		printUsage(stderr)
		return exitUsage
	}
	if deps.err != nil {
		fmt.Fprintf(stderr, "signer configuration: %v\n", deps.err)
		return exitInternal
	}
	if deps.backend == nil {
		fmt.Fprintln(stderr, "signer configuration: backend is unavailable")
		return exitInternal
	}
	if err := deps.policy.Validate(); err != nil {
		fmt.Fprintf(stderr, "signer configuration: %v\n", err)
		return exitInternal
	}
	artifact, err := readSigningInput(args[2])
	if err != nil {
		fmt.Fprintf(stderr, "read signing input: %v\n", err)
		return exitInput
	}
	signature, err := deps.backend.Sign(ctx, signing.AlgorithmRSA2048SHA256, artifact)
	if err != nil {
		fmt.Fprintf(stderr, "sign approved input: %v\n", err)
		return exitSigner
	}
	if len(signature) != signing.RSASignatureBytes {
		fmt.Fprintf(stderr, "sign approved input: signer returned %d bytes, want %d\n", len(signature), signing.RSASignatureBytes)
		return exitSigner
	}
	if _, err := fmt.Fprintln(stdout, hex.EncodeToString(signature)); err != nil {
		fmt.Fprintf(stderr, "write signature: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-signer -a rsa2048-sha256 INPUT_FILE")
}

func parseFixedArguments(encoded string) ([]string, error) {
	if len(encoded) == 0 || len(encoded) > 16*1024 {
		return nil, errors.New("approval-gated signer fixed arguments are not configured")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	var arguments []string
	if err := decoder.Decode(&arguments); err != nil {
		return nil, fmt.Errorf("decode approval-gated signer fixed arguments: %w", err)
	}
	if arguments == nil {
		return nil, errors.New("approval-gated signer fixed arguments must be a JSON array")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decode approval-gated signer fixed arguments: %w", err)
		}
		return nil, fmt.Errorf("decode approval-gated signer fixed arguments: trailing JSON value %v", token)
	}
	return arguments, nil
}

func readSigningInput(path string) ([]byte, error) {
	if path == "" || filepath.Clean(path) != path {
		return nil, errors.New("input path must be non-empty and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > int64(signing.MaxArtifactBytes) {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", signing.MaxArtifactBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	artifact, err := io.ReadAll(io.LimitReader(file, int64(signing.MaxArtifactBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(artifact) == 0 || len(artifact) > signing.MaxArtifactBytes {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", signing.MaxArtifactBytes)
	}
	return artifact, nil
}
