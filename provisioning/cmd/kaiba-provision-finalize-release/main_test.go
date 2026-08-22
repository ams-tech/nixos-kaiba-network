package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedrelease"
)

func TestRunPassesTheExactFixedInputSet(t *testing.T) {
	args := validArguments()
	called := false
	deps := dependencies{
		finalize: func(_ context.Context, inputs signedrelease.Inputs, output string, options signedrelease.Options) error {
			called = true
			if inputs.ReleaseIntentPath != "/input/0" || inputs.RootHashTreeImagePath != "/input/20" || output != "/input/21" {
				t.Fatalf("unexpected parsed paths: %#v output=%q", inputs, output)
			}
			if options.EEPROMReplayVerifier == nil {
				t.Fatal("replay verifier was not passed to finalizer")
			}
			return nil
		},
		options: signedrelease.Options{EEPROMReplayVerifier: signedrelease.EEPROMReplayVerifierFunc(func(context.Context, string, string, string) error { return nil })},
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr, deps); code != exitOK {
		t.Fatalf("run() = %d, stderr=%s", code, stderr.String())
	}
	if !called || stdout.String() != "published signed release: /input/21\n" {
		t.Fatalf("called=%v stdout=%q", called, stdout.String())
	}
}

func TestRunRejectsMissingReorderedAndRelativeArguments(t *testing.T) {
	base := validArguments()
	mutations := [][]string{
		base[:len(base)-2],
		append([]string(nil), base...),
		append([]string(nil), base...),
	}
	mutations[1][1], mutations[1][3] = mutations[1][3], mutations[1][1]
	mutations[2][2] = "relative"
	for index, args := range mutations {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, dependencies{}); code != exitUsage {
				t.Fatalf("run() = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr.String(), "usage:") {
				t.Fatalf("stderr=%q", stderr.String())
			}
		})
	}
}

func TestRunReportsConfigurationAndFinalizationFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		deps dependencies
		want string
	}{
		{"configuration", dependencies{err: errors.New("not linked")}, "not linked"},
		{"finalization", dependencies{finalize: func(context.Context, signedrelease.Inputs, string, signedrelease.Options) error {
			return errors.New("tampered")
		}}, "tampered"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), validArguments(), &stdout, &stderr, test.deps); code != exitFailure {
				t.Fatalf("run()=%d", code)
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr=%q", stderr.String())
			}
		})
	}
}

func TestProductionDependenciesFailClosedWithoutLinkerPath(t *testing.T) {
	previous := eepromFinalizerExecutablePath
	t.Cleanup(func() { eepromFinalizerExecutablePath = previous })
	eepromFinalizerExecutablePath = ""
	if deps := productionDependencies(); deps.err == nil || !strings.Contains(deps.err.Error(), "linker-fixed") {
		t.Fatalf("productionDependencies() err=%v", deps.err)
	}
}

func validArguments() []string {
	names := []string{
		"--release-intent", "--unsigned-artifacts-manifest", "--eeprom-release-manifest", "--signed-boot", "--signed-eeprom",
		"--eeprom-replay-plan", "--eeprom-replay-signed", "--owned-recovery", "--owned-replay-plan", "--owned-replay-signed", "--device-profile", "--platform-adapter",
		"--root-integrity", "--fresh-commit-bundle", "--fresh-readback-bundle", "--negative-boot-bundle", "--owned-readback-bundle",
		"--owned-recovery-bundle", "--root-integrity-test-bundle", "--root-data-image", "--root-hash-tree-image", "--output",
	}
	args := []string{"finalize"}
	for index, name := range names {
		args = append(args, name, fmt.Sprintf("/input/%d", index))
	}
	return args
}
