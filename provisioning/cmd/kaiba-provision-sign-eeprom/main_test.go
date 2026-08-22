package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func TestParseArgumentsIsClosedAndRequiresAbsolutePaths(t *testing.T) {
	if command, plan, signed, output, err := parseArguments([]string{
		"sign", "--plan", "/public/plan", "--output", "/public/signed",
	}); err != nil || command != "sign" || plan != "/public/plan" || signed != "" || output != "/public/signed" {
		t.Fatalf("parse sign = %q %q %q %q, %v", command, plan, signed, output, err)
	}
	if command, plan, signed, output, err := parseArguments([]string{
		"finalize", "--plan", "/public/plan", "--signed", "/public/signed", "--output", "/public/final",
	}); err != nil || command != "finalize" || plan != "/public/plan" || signed != "/public/signed" || output != "/public/final" {
		t.Fatalf("parse finalize = %q %q %q %q, %v", command, plan, signed, output, err)
	}
	for _, arguments := range [][]string{
		{"sign", "--plan", "relative", "--output", "/public/signed"},
		{"sign", "--output", "/public/signed", "--plan", "/public/plan"},
		{"sign", "--plan", "/public/plan", "--output", "/public/signed", "--extra"},
		{"finalize", "--plan", "/public/plan", "--signed", "relative", "--output", "/public/final"},
		{"-a", "rsa2048-sha256", "/tmp/input"},
	} {
		if _, _, _, _, err := parseArguments(arguments); err == nil {
			t.Fatalf("parseArguments(%v) succeeded", arguments)
		}
	}
}

func TestRunHiddenWrapperExactMode(t *testing.T) {
	input := []byte("synthetic updater signing input")
	inputPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	signatureHex := strings.Repeat("ab", 256)
	var received []byte
	client := func(ctx context.Context, socketPath string, artifact []byte) (string, error) {
		if socketPath != "/private/eeprom-signing.sock" {
			t.Fatalf("socket path = %q", socketPath)
		}
		received = append([]byte(nil), artifact...)
		return signatureHex, nil
	}
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"-a", "rsa2048-sha256", inputPath}, &stdout, &stderr,
		dependencies{err: errors.New("public configuration must not be consulted")},
		func(name string) string {
			if name == sessionSocketEnvironment {
				return "/private/eeprom-signing.sock"
			}
			return ""
		}, client)
	if exitCode != exitOK || stderr.Len() != 0 {
		t.Fatalf("run hidden exit = %d, stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != signatureHex+"\n" || !bytes.Equal(received, input) {
		t.Fatalf("hidden wrapper output/received mismatch")
	}
}

func TestRunHiddenWrapperRequiresPrivateSession(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(inputPath, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"-a", "rsa2048-sha256", inputPath}, &stdout, &stderr,
		dependencies{}, func(string) string { return "" },
		func(context.Context, string, []byte) (string, error) {
			t.Fatal("wrapper client called without a private session")
			return "", nil
		})
	if exitCode != exitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "private signing-session socket") {
		t.Fatalf("run hidden exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestProductionDependenciesResolvesSelfWrapperWithoutLinkerCycle(t *testing.T) {
	savedDigest := expectedEEPROMReleaseManifestDigest
	savedGate := signingGateSocketPath
	savedUpdater := pinnedUpdatePieepromExecutablePath
	savedExtractor := pinnedRpiEEPROMConfigExecutablePath
	savedPATH := pinnedToolRuntimePath
	savedWrapper := eepromSigningWrapperExecutablePath
	savedOriginalEEPROM := expectedOriginalEEPROMDigest
	savedOriginalRecovery := expectedOriginalRecoveryDigest
	savedOriginalBootcode := expectedOriginalBootcodeDigest
	savedOriginalBootsys := expectedOriginalBootsysDigest
	savedFirmwareEpoch := expectedEEPROMFirmwareBuildEpoch
	t.Cleanup(func() {
		expectedEEPROMReleaseManifestDigest = savedDigest
		signingGateSocketPath = savedGate
		pinnedUpdatePieepromExecutablePath = savedUpdater
		pinnedRpiEEPROMConfigExecutablePath = savedExtractor
		pinnedToolRuntimePath = savedPATH
		eepromSigningWrapperExecutablePath = savedWrapper
		expectedOriginalEEPROMDigest = savedOriginalEEPROM
		expectedOriginalRecoveryDigest = savedOriginalRecovery
		expectedOriginalBootcodeDigest = savedOriginalBootcode
		expectedOriginalBootsysDigest = savedOriginalBootsys
		expectedEEPROMFirmwareBuildEpoch = savedFirmwareEpoch
	})
	expectedEEPROMReleaseManifestDigest = string(bundle.Sum([]byte("release")))
	signingGateSocketPath = "/fixed/gate.sock"
	pinnedUpdatePieepromExecutablePath = "/fixed/updater"
	pinnedRpiEEPROMConfigExecutablePath = "/fixed/extractor"
	pinnedToolRuntimePath = "/fixed/tools"
	eepromSigningWrapperExecutablePath = ""
	expectedOriginalEEPROMDigest = string(bundle.Sum([]byte("original EEPROM")))
	expectedOriginalRecoveryDigest = string(bundle.Sum([]byte("original recovery")))
	expectedOriginalBootcodeDigest = string(bundle.Sum([]byte("original bootcode")))
	expectedOriginalBootsysDigest = string(bundle.Sum([]byte("original bootsys")))
	expectedEEPROMFirmwareBuildEpoch = "1779807685"
	deps := productionDependencies()
	if deps.err != nil {
		t.Fatal(deps.err)
	}
	if !filepath.IsAbs(deps.config.WrapperExecutablePath) || filepath.Clean(deps.config.WrapperExecutablePath) != deps.config.WrapperExecutablePath {
		t.Fatalf("resolved self wrapper = %q", deps.config.WrapperExecutablePath)
	}
}
