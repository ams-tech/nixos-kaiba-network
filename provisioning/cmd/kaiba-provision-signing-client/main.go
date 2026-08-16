package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInput    = 3
	exitDenied   = 4
)

// Populated by the immutable build. There is deliberately no flag or
// environment override for the control-host socket.
var signingGateSocketPath string

type signatureRequester func(context.Context, []byte) (signinggate.Result, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionRequester()))
}

func productionRequester() signatureRequester {
	return func(ctx context.Context, artifact []byte) (signinggate.Result, error) {
		return signinggate.RequestSignature(ctx, signingGateSocketPath, artifact)
	}
}

// run implements the complete Raspberry Pi HSM-wrapper CLI and no other
// runtime selection surface.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, request signatureRequester) int {
	if len(args) != 3 || args[0] != "-a" || args[1] != string(signing.AlgorithmRSA2048SHA256) || args[2] == "" {
		fmt.Fprintln(stderr, "usage: kaiba-provision-signing-client -a rsa2048-sha256 INPUT_FILE")
		return exitUsage
	}
	if request == nil {
		fmt.Fprintln(stderr, "signing client configuration is unavailable")
		return exitInternal
	}
	artifact, err := readSigningInput(args[2])
	if err != nil {
		fmt.Fprintf(stderr, "read signing input: %v\n", err)
		return exitInput
	}
	result, err := request(ctx, artifact)
	if err != nil {
		fmt.Fprintf(stderr, "signing gate: %v\n", err)
		return exitDenied
	}
	if _, err := fmt.Fprintln(stdout, result.SignatureHex); err != nil {
		fmt.Fprintf(stderr, "write signature: %v\n", err)
		return exitInternal
	}
	return exitOK
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
