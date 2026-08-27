package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3

	approvalFilename = "approval.json"
	registryFilename = "signing-grants.json"
)

var (
	lstatFile = os.Lstat
	openInput = os.Open
	makeDir   = os.Mkdir
	openFile  = os.OpenFile
	openDir   = os.Open
	newAuthor = signingapproval.New
	clockNow  = time.Now
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "author":
		return authorCommand(arguments[1:], stdout, stderr)
	case "validate":
		return validateCommand(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func authorCommand(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("author", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	intentPath := flags.String("release-intent", "", "absolute canonical release-intent JSON path")
	reviewerID := flags.String("reviewer-id", "", "canonical reviewer attribution identifier")
	approvedAt := flags.String("approved-at", "", "canonical UTC RFC3339 approval time")
	expiresAt := flags.String("expires-at", "", "canonical UTC RFC3339 expiry, at most 24 hours later")
	outputPath := flags.String("output", "", "absolute new output directory")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *intentPath == "" || *reviewerID == "" || *approvedAt == "" || *expiresAt == "" || *outputPath == "" {
		flags.Usage()
		return exitUsage
	}
	if err := requireAbsoluteClean(*outputPath, "output"); err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInvalid
	}
	intent, err := loadCanonicalIntent(*intentPath)
	if err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInvalid
	}
	authorization, err := newAuthor(intent, *reviewerID, *approvedAt, *expiresAt)
	if err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInvalid
	}
	if err := requireCurrentlyActive(authorization.Approval); err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInvalid
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInternal
	}
	registryJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInternal
	}
	if err := writeOutputDirectory(*outputPath, approvalJSON, registryJSON); err != nil {
		fmt.Fprintf(stderr, "author signing approval: %v\n", err)
		return exitInternal
	}
	return encodeResult(stdout, stderr, map[string]any{
		"status":                "authored",
		"approval_id":           authorization.Approval.ApprovalID,
		"approval_digest":       authorization.Approval.ApprovalDigest,
		"release_intent_digest": authorization.Approval.ReleaseIntentDigest,
		"grant_count":           len(authorization.Registry.Grants),
	})
}

func requireCurrentlyActive(approval signingapproval.Approval) error {
	approvedAt, err := time.Parse(time.RFC3339, approval.ApprovedAt)
	if err != nil {
		return errors.New("approved_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, approval.ExpiresAt)
	if err != nil {
		return errors.New("expires_at is invalid")
	}
	now := clockNow().UTC()
	if now.Before(approvedAt) {
		return errors.New("approved_at is in the future according to the authoring host clock")
	}
	if !now.Before(expiresAt) {
		return errors.New("the approval is already expired according to the authoring host clock")
	}
	return nil
}

func validateCommand(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	intentPath := flags.String("release-intent", "", "absolute canonical release-intent JSON path")
	approvalPath := flags.String("approval", "", "absolute canonical signing approval JSON path")
	registryPath := flags.String("registry", "", "absolute canonical v1alpha2 grant registry JSON path")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *intentPath == "" || *approvalPath == "" || *registryPath == "" {
		flags.Usage()
		return exitUsage
	}
	intent, err := loadCanonicalIntent(*intentPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	approvalData, err := readCanonicalFile(*approvalPath, signingapproval.MaxApprovalBytes+1, "approval")
	if err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	approval, err := signingapproval.ParseApproval(approvalData)
	if err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	registryData, err := readCanonicalFile(*registryPath, signinggate.MaxRegistryBytes+1, "registry")
	if err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	registry, err := signingapproval.ParseRegistry(registryData)
	if err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	if err := (signingapproval.Authorization{Approval: approval, Registry: registry}).Validate(intent); err != nil {
		fmt.Fprintf(stderr, "validate signing authorization: %v\n", err)
		return exitInvalid
	}
	return encodeResult(stdout, stderr, map[string]any{
		"status":                "valid",
		"approval_id":           approval.ApprovalID,
		"approval_digest":       approval.ApprovalDigest,
		"release_intent_digest": approval.ReleaseIntentDigest,
		"grant_count":           len(registry.Grants),
	})
}

func loadCanonicalIntent(path string) (releaseintent.Intent, error) {
	data, err := readCanonicalFile(path, releaseintent.MaxBytes+1, "release intent")
	if err != nil {
		return releaseintent.Intent{}, err
	}
	payload := data
	if payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
	}
	intent, err := releaseintent.Parse(payload)
	if err != nil {
		return releaseintent.Intent{}, fmt.Errorf("release intent: %w", err)
	}
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		return releaseintent.Intent{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return releaseintent.Intent{}, errors.New("release intent must use its exact canonical JSON representation")
	}
	return intent, nil
}

func readCanonicalFile(path string, maximum int, label string) ([]byte, error) {
	if err := requireAbsoluteClean(path, label); err != nil {
		return nil, err
	}
	info, err := lstatFile(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	if info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", label, maximum)
	}
	file, err := openInput(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened %s: %w", label, err)
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if len(data) == 0 || len(data) > maximum {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", label, maximum)
	}
	return data, nil
}

func writeOutputDirectory(path string, approvalJSON, registryJSON []byte) error {
	if err := makeDir(path, 0o700); err != nil {
		return fmt.Errorf("create new output directory: %w", err)
	}
	for _, output := range []struct {
		name string
		data []byte
	}{
		{approvalFilename, approvalJSON},
		{registryFilename, registryJSON},
	} {
		if err := writeExclusive(filepath.Join(path, output.name), append(output.data, '\n')); err != nil {
			return err
		}
	}
	directory, err := openDir(path)
	if err != nil {
		return fmt.Errorf("open output directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}

func writeExclusive(path string, data []byte) error {
	file, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func requireAbsoluteClean(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be absolute and clean", label)
	}
	return nil
}

func encodeResult(stdout, stderr io.Writer, result any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-signing-approval author --release-intent ABSOLUTE_PATH --reviewer-id IDENTIFIER --approved-at UTC_RFC3339_SECONDS --expires-at UTC_RFC3339_SECONDS --output ABSOLUTE_NEW_DIRECTORY")
	fmt.Fprintln(output, "       kaiba-provision-signing-approval validate --release-intent ABSOLUTE_PATH --approval ABSOLUTE_PATH --registry ABSOLUTE_PATH")
}
