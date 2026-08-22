package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// TestMain also lets a synthetic pinned updater invoke this test executable as
// the exact hidden HSM wrapper. No key material, test-only mode, or alternate
// public command is compiled into the production binary.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "-a" && os.Args[2] == "rsa2048-sha256" {
		os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, dependencies{}, os.Getenv, productionWrapperClient))
	}
	os.Exit(m.Run())
}

func TestProductionUpdaterUsesPrivateSessionAndExactInvocation(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "kaiba-eeprom-session-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	updaterPath := filepath.Join(root, "synthetic-pinned-updater")
	script := `#!/bin/sh
set -eu
[ "$#" -eq 11 ]
[ "$1" = "-f" ]
[ "$2" = "-c" ] && [ "$3" = "boot.conf" ]
[ "$4" = "-i" ] && [ "$5" = "pieeprom.original.bin" ]
[ "$6" = "-o" ] && [ "$7" = "pieeprom.bin" ]
[ "$8" = "-p" ] && [ "$9" = "public.pem" ]
[ "${10}" = "-H" ]
[ "$LANG" = "C" ] && [ "$LC_ALL" = "C" ] && [ "$TZ" = "UTC" ]
[ "$PATH" = "/fixed/tools" ]
[ "$SOURCE_DATE_EPOCH" = "1779700000" ]
[ "$TMPDIR" = "$PWD/tmp" ]
[ -n "$KAIBA_EEPROM_SIGNING_SESSION_SOCKET" ]
[ -z "${HOME+x}" ]
wrapper="${11}"
"$wrapper" -a rsa2048-sha256 "$PWD/first.bin" >/dev/null
"$wrapper" -a rsa2048-sha256 "$PWD/second.bin" >/dev/null
"$wrapper" -a rsa2048-sha256 config.bin >/dev/null
`
	if err := os.WriteFile(updaterPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	workDirectory := filepath.Join(root, "work")
	if err := os.Mkdir(workDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	wantArtifacts := [][]byte{[]byte("first preimage"), []byte("second preimage"), []byte("config")}
	for index, name := range []string{"first.bin", "second.bin", "config.bin"} {
		if err := os.WriteFile(filepath.Join(workDirectory, name), wantArtifacts[index], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	self, err := resolvedSelfExecutable()
	if err != nil {
		t.Fatal(err)
	}
	config := testRuntimeConfig(bundle.Sum([]byte("release")))
	config.GateSocketPath = "/fixed/gate.sock"
	config.UpdaterExecutablePath = updaterPath
	config.ExtractorExecutablePath = "/fixed/extractor"
	config.FixedToolPATH = "/fixed/tools"
	config.WrapperExecutablePath = self
	var gotArtifacts [][]byte
	callback := func(ctx context.Context, artifact []byte) (string, error) {
		gotArtifacts = append(gotArtifacts, append([]byte(nil), artifact...))
		return strings.Repeat("ab", 256), nil
	}
	if err := productionUpdater(context.Background(), updateInvocation{
		WorkDir: workDirectory, SourceDateEpoch: cliTestSourceEpoch, Config: config,
	}, callback); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("Unix sockets are blocked by this test sandbox")
		}
		t.Fatalf("productionUpdater() error = %v", err)
	}
	if !reflect.DeepEqual(gotArtifacts, wantArtifacts) {
		t.Fatalf("private-session artifacts = %q, want %q", gotArtifacts, wantArtifacts)
	}
	if _, err := os.Lstat(filepath.Join(workDirectory, "signing.sock")); !os.IsNotExist(err) {
		t.Fatalf("private socket remains after updater: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(workDirectory, "config.bin")); err != nil || !bytes.Equal(contents, wantArtifacts[2]) {
		t.Fatalf("relative wrapper input changed: %q, %v", contents, err)
	}
}
