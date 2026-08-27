package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
)

const (
	exitOK           = 0
	exitInternal     = 1
	exitUsage        = 2
	exitVerification = 3
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	// Match the gate boundary: the reviewed registry is root-owned, while the
	// process runs as the dedicated service identity that owns durable state.
	return runWithOwners(ctx, arguments, stdout, stderr, 0, uint32(os.Geteuid()))
}

func runWithOwners(ctx context.Context, arguments []string, stdout, stderr io.Writer, registryOwnerUID, stateOwnerUID uint32) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "export":
		return runExport(ctx, arguments[1:], stdout, stderr, registryOwnerUID, stateOwnerUID)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func runExport(ctx context.Context, arguments []string, stdout, stderr io.Writer, registryOwnerUID, stateOwnerUID uint32) int {
	flags := flag.NewFlagSet("kaiba-provision-signing-receipts export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	registryPath := flags.String("registry", "", "absolute root-managed v1alpha2 grant registry path")
	stateDirectory := flags.String("state-directory", "", "absolute root-managed signing-gate state directory")
	publicKeyPath := flags.String("public-key", "", "absolute reviewed RSA-2048 public key PEM path")
	outputPath := flags.String("output", "", "absolute new canonical receipt-export path")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *registryPath == "" || *stateDirectory == "" || *publicKeyPath == "" || *outputPath == "" {
		flags.Usage()
		return exitUsage
	}
	if pathWithinDirectory(*outputPath, *stateDirectory) {
		fmt.Fprintln(stderr, "export signing receipts: output must be outside the signing-gate state directory")
		return exitVerification
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		fmt.Fprintf(stderr, "export signing receipts: output: %v\n", err)
		return exitVerification
	}
	registry, err := signinggate.LoadRegistry(signinggate.RegistryConfig{Path: *registryPath, OwnerUID: registryOwnerUID})
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: registry: %v\n", err)
		return exitVerification
	}
	publicKeyPEM, err := readRegularFile(*publicKeyPath, signingreceipts.MaxPublicKeyBytes)
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: public key: %v\n", err)
		return exitVerification
	}
	states, err := signinggate.ReadCompleteStateSnapshot(ctx, *stateDirectory, stateOwnerUID, registry)
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: %v\n", err)
		return exitVerification
	}
	exported, err := signingreceipts.New(registry, states, publicKeyPEM)
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: authenticate snapshot: %v\n", err)
		return exitVerification
	}
	canonical, err := exported.CanonicalJSON(registry, publicKeyPEM)
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: encode: %v\n", err)
		return exitInternal
	}
	_, verification, err := signingreceipts.ParseAndVerify(canonical, registry, publicKeyPEM, exported.ReceiptDigests())
	if err != nil {
		fmt.Fprintf(stderr, "export signing receipts: self-verify: %v\n", err)
		return exitInternal
	}
	if err := evidencefile.WriteCanonicalNew(*outputPath, canonical); err != nil {
		fmt.Fprintf(stderr, "export signing receipts: publish: %v\n", err)
		return exitInternal
	}
	return writeVerification(stdout, stderr, verification)
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-provision-signing-receipts verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	exportPath := flags.String("export", "", "absolute canonical receipt-export path")
	registryPath := flags.String("registry", "", "absolute independently reviewed v1alpha2 registry path")
	publicKeyPath := flags.String("public-key", "", "absolute independently reviewed RSA-2048 public key PEM path")
	var expectedReceiptDigests digestValues
	flags.Var(&expectedReceiptDigests, "expected-receipt-digest", "digest captured from one live signing result; repeat exactly once per registry grant")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *exportPath == "" || *registryPath == "" || *publicKeyPath == "" || len(expectedReceiptDigests) == 0 {
		flags.Usage()
		return exitUsage
	}
	registryJSON, err := readRegularFile(*registryPath, signinggate.MaxRegistryBytes)
	if err != nil {
		fmt.Fprintf(stderr, "verify signing receipts: registry: %v\n", err)
		return exitVerification
	}
	registry, err := signingreceipts.ParseRegistry(registryJSON)
	if err != nil {
		fmt.Fprintf(stderr, "verify signing receipts: registry: %v\n", err)
		return exitVerification
	}
	publicKeyPEM, err := readRegularFile(*publicKeyPath, signingreceipts.MaxPublicKeyBytes)
	if err != nil {
		fmt.Fprintf(stderr, "verify signing receipts: public key: %v\n", err)
		return exitVerification
	}
	exportJSON, err := readRegularFile(*exportPath, signingreceipts.MaxExportBytes)
	if err != nil {
		fmt.Fprintf(stderr, "verify signing receipts: export: %v\n", err)
		return exitVerification
	}
	_, verification, err := signingreceipts.ParseAndVerify(exportJSON, registry, publicKeyPEM, expectedReceiptDigests)
	if err != nil {
		fmt.Fprintf(stderr, "verify signing receipts: %v\n", err)
		return exitVerification
	}
	return writeVerification(stdout, stderr, verification)
}

type digestValues []bundle.Digest

func (values *digestValues) String() string {
	if values == nil {
		return ""
	}
	encoded := make([]string, len(*values))
	for index, digest := range *values {
		encoded[index] = string(digest)
	}
	return strings.Join(encoded, ",")
}

func (values *digestValues) Set(value string) error {
	digest, err := bundle.ParseDigest(value)
	if err != nil {
		return err
	}
	*values = append(*values, digest)
	return nil
}

func writeVerification(stdout, stderr io.Writer, verification signingreceipts.Verification) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verification); err != nil {
		fmt.Fprintf(stderr, "encode signing receipt verification: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func readRegularFile(path string, maximum int) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("input must not be group- or world-writable")
	}
	if info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", maximum)
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
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maximum || int64(len(data)) != info.Size() {
		return nil, errors.New("input size changed while reading or exceeds its fixed bound")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() || opened.Mode() != after.Mode() {
		return nil, errors.New("input identity, size, or mode changed while reading")
	}
	return data, nil
}

func pathWithinDirectory(path, directory string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return false
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  kaiba-provision-signing-receipts export --registry ABSOLUTE_PATH --state-directory ABSOLUTE_PATH --public-key ABSOLUTE_PATH --output ABSOLUTE_NEW_PATH")
	fmt.Fprintln(output, "  kaiba-provision-signing-receipts verify --export ABSOLUTE_PATH --registry ABSOLUTE_PATH --public-key ABSOLUTE_PATH --expected-receipt-digest SHA256_DIGEST [--expected-receipt-digest SHA256_DIGEST ...]")
}
