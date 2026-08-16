package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
)

// All production authority and path values are injected by the immutable
// build. The daemon intentionally has no flags or environment overrides.
var (
	signingGateSocketPath        string
	signingGrantRegistryPath     string
	signingStateDirectoryPath    string
	signingBackendID             string
	signingBackendExecutablePath string
	signingBackendArgumentsJSON  string
)

type serverFactory func(io.Writer) (func(context.Context) error, io.Closer, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr, productionFactory))
}

func run(ctx context.Context, args []string, stderr io.Writer, factory serverFactory) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: kaiba-provision-signing-gate")
		return exitUsage
	}
	if factory == nil {
		fmt.Fprintln(stderr, "signing gate configuration is unavailable")
		return exitInternal
	}
	serve, closer, err := factory(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "configure signing gate: %v\n", err)
		return exitInternal
	}
	if closer != nil {
		defer closer.Close()
	}
	if err := serve(ctx); err != nil {
		fmt.Fprintf(stderr, "serve signing gate: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func productionFactory(errorLog io.Writer) (func(context.Context) error, io.Closer, error) {
	registry, err := signinggate.LoadRegistry(signinggate.RegistryConfig{
		Path: signingGrantRegistryPath, OwnerUID: 0,
	})
	if err != nil {
		return nil, nil, err
	}
	store, err := signinggate.OpenStateStore(signingStateDirectoryPath, uint32(os.Geteuid()))
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (func(context.Context) error, io.Closer, error) {
		_ = store.Close()
		return nil, nil, err
	}
	arguments, err := parseFixedArguments(signingBackendArgumentsJSON)
	if err != nil {
		return fail(err)
	}
	backend, err := signing.NewExternalCommandBackend(signing.ExternalCommandConfig{
		ExecutablePath: signingBackendExecutablePath,
		FixedArguments: arguments,
	})
	if err != nil {
		return fail(err)
	}
	gate, err := signinggate.NewGate(signinggate.GateConfig{
		Registry: registry, Store: store, Backend: backend,
		BackendID: signingBackendID, Now: time.Now,
	})
	if err != nil {
		return fail(err)
	}
	serve := func(ctx context.Context) error {
		return signinggate.Serve(ctx, signinggate.ServerConfig{
			SocketPath: signingGateSocketPath,
			OwnerUID:   uint32(os.Geteuid()),
			Gate:       gate,
			ErrorLog:   errorLog,
		})
	}
	return serve, store, nil
}

func parseFixedArguments(encoded string) ([]string, error) {
	if len(encoded) == 0 || len(encoded) > 16*1024 {
		return nil, errors.New("signing backend fixed arguments are not configured")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	var arguments []string
	if err := decoder.Decode(&arguments); err != nil {
		return nil, fmt.Errorf("decode signing backend fixed arguments: %w", err)
	}
	if arguments == nil {
		return nil, errors.New("signing backend fixed arguments must be a JSON array")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("trailing signing backend argument value %v", token)
	}
	return arguments, nil
}
