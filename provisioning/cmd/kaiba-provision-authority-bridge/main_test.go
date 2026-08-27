package main

import (
	"context"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authoritybridge"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

type fakeControlReader struct{}

func (fakeControlReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return controlplane.Transaction{}, nil
}

func (fakeControlReader) PreflightCurrentClaim(context.Context, controlplane.CurrentClaimPreflightRequest) (controlplane.Transaction, error) {
	return controlplane.Transaction{}, nil
}

type fakeAuditReader struct{}

func (fakeAuditReader) GetRecordsByReceiptIDs(context.Context, string, []string) ([]auditlog.Record, error) {
	return nil, nil
}

func TestParseConfigRequiresClosedConfiguration(t *testing.T) {
	arguments := validArguments()
	config, err := parseConfig(arguments, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if config.socketPath != "/run/kaiba-authority/bridge.sock" || config.controlURL != "https://control.example:8443" ||
		config.auditURL != "https://audit.example:8443" || config.leaseSafetyMargin != 45*time.Second {
		t.Fatalf("config = %#v", config)
	}

	for _, test := range []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "missing", arguments: nil, want: "required"},
		{name: "relative socket", arguments: replaceArgument(arguments, "--socket", "bridge.sock"), want: "--socket"},
		{name: "relative credential", arguments: replaceArgument(arguments, "--tls-cert", "station.pem"), want: "--tls-cert"},
		{name: "unclean credential", arguments: replaceArgument(arguments, "--audit-server-ca", "/run/credentials/../audit-ca.pem"), want: "clean absolute path"},
		{name: "store root credential", arguments: replaceArgument(arguments, "--control-server-ca", "/nix/store"), want: "outside the Nix store"},
		{name: "store credential", arguments: replaceArgument(arguments, "--tls-key", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-client-key"), want: "outside the Nix store"},
		{name: "same authority", arguments: replaceArgument(arguments, "--audit-url", "https://CONTROL.example:8443/"), want: "must be distinct"},
		{name: "same default-port authority", arguments: replaceArgument(replaceArgument(arguments, "--control-url", "https://control.example"), "--audit-url", "https://CONTROL.example:443"), want: "must be distinct"},
		{name: "same IPv6 authority", arguments: replaceArgument(replaceArgument(arguments, "--control-url", "https://[::1]:8443"), "--audit-url", "https://[0:0:0:0:0:0:0:1]:8443"), want: "must be distinct"},
		{name: "same CA path", arguments: replaceArgument(arguments, "--audit-server-ca", "/run/credentials/control-ca.pem"), want: "CA paths must be distinct"},
		{name: "negative margin", arguments: replaceArgument(arguments, "--lease-safety-margin", "-1s"), want: "must not be negative"},
		{name: "positionals", arguments: append(append([]string(nil), arguments...), "unexpected"), want: "positional"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseConfig(test.arguments, io.Discard); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunConstructsIndependentReadersAndServes(t *testing.T) {
	restoreCommandGlobals(t)
	control := fakeControlReader{}
	audit := fakeAuditReader{}
	buildAuthorityReaders = func(
		controlBaseURL string,
		controlFiles mtls.ClientFiles,
		auditBaseURL string,
		auditFiles mtls.ClientFiles,
	) (authoritybridge.ControlReader, authoritybridge.AuditReader, error) {
		if controlBaseURL != "https://control.example:8443" || controlFiles.Certificate != "/run/credentials/station.pem" ||
			controlFiles.PrivateKey != "/run/credentials/station-key.pem" || controlFiles.ServerCA != "/run/credentials/control-ca.pem" {
			t.Fatalf("control configuration = %q, %#v", controlBaseURL, controlFiles)
		}
		if auditBaseURL != "https://audit.example:8443" || auditFiles.Certificate != "/run/credentials/station.pem" ||
			auditFiles.PrivateKey != "/run/credentials/station-key.pem" || auditFiles.ServerCA != "/run/credentials/audit-ca.pem" {
			t.Fatalf("audit configuration = %q, %#v", auditBaseURL, auditFiles)
		}
		return control, audit, nil
	}
	effectiveUID = func() int { return 1234 }
	effectiveGID = func() int { return 5678 }
	sentinel := errors.New("serve sentinel")
	serveBridge = func(_ context.Context, config authoritybridge.ServerConfig) error {
		if config.SocketPath != "/run/kaiba-authority/bridge.sock" || config.OwnerUID != 1234 || config.OwnerGID != 5678 ||
			config.DirectoryMode != 0o750 || config.SocketMode != 0o660 || config.ErrorLog == nil || config.Binder == nil {
			t.Fatalf("server config = %#v", config)
		}
		if config.Binder.Control != control || config.Binder.Audit != audit || config.Binder.LeaseSafetyMargin != 45*time.Second {
			t.Fatalf("binder = %#v", config.Binder)
		}
		return sentinel
	}
	if err := run(context.Background(), validArguments()); !errors.Is(err, sentinel) {
		t.Fatalf("run error = %v", err)
	}
}

func TestRunFailsClosedBeforeServingWhenReaderConfigurationFails(t *testing.T) {
	restoreCommandGlobals(t)
	sentinel := errors.New("invalid control trust")
	buildAuthorityReaders = func(string, mtls.ClientFiles, string, mtls.ClientFiles) (authoritybridge.ControlReader, authoritybridge.AuditReader, error) {
		return nil, nil, sentinel
	}
	serveBridge = func(context.Context, authoritybridge.ServerConfig) error {
		t.Fatal("bridge served after reader configuration failed")
		return nil
	}
	if err := run(context.Background(), validArguments()); !errors.Is(err, sentinel) {
		t.Fatalf("run error = %v", err)
	}
}

func TestRunRejectsInvalidEffectiveIdentityBeforeServing(t *testing.T) {
	type identityTest struct {
		name string
		uid  int
		gid  int
		want string
	}
	tests := []identityTest{
		{name: "uid", uid: -1, gid: 1, want: "UID"},
		{name: "gid", uid: 1, gid: -1, want: "GID"},
	}
	if strconv.IntSize > 32 {
		outOfRange := uint64(math.MaxUint32) + 1
		tests = append(tests,
			identityTest{name: "uid overflow", uid: int(outOfRange), gid: 1, want: "UID"},
			identityTest{name: "gid overflow", uid: 1, gid: int(outOfRange), want: "GID"},
		)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restoreCommandGlobals(t)
			buildAuthorityReaders = func(string, mtls.ClientFiles, string, mtls.ClientFiles) (authoritybridge.ControlReader, authoritybridge.AuditReader, error) {
				return fakeControlReader{}, fakeAuditReader{}, nil
			}
			effectiveUID = func() int { return test.uid }
			effectiveGID = func() int { return test.gid }
			serveBridge = func(context.Context, authoritybridge.ServerConfig) error {
				t.Fatal("bridge served with an invalid effective identity")
				return nil
			}
			if err := run(context.Background(), validArguments()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("run error = %v, want %q", err, test.want)
			}
		})
	}
}

func validArguments() []string {
	return []string{
		"--socket", "/run/kaiba-authority/bridge.sock",
		"--control-url", "https://control.example:8443",
		"--audit-url", "https://audit.example:8443",
		"--tls-cert", "/run/credentials/station.pem",
		"--tls-key", "/run/credentials/station-key.pem",
		"--control-server-ca", "/run/credentials/control-ca.pem",
		"--audit-server-ca", "/run/credentials/audit-ca.pem",
		"--lease-safety-margin", "45s",
	}
}

func replaceArgument(arguments []string, name, value string) []string {
	result := append([]string(nil), arguments...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == name {
			result[index+1] = value
			return result
		}
	}
	return result
}

func restoreCommandGlobals(t *testing.T) {
	t.Helper()
	originalReaders := buildAuthorityReaders
	originalServe := serveBridge
	originalUID := effectiveUID
	originalGID := effectiveGID
	t.Cleanup(func() {
		buildAuthorityReaders = originalReaders
		serveBridge = originalServe
		effectiveUID = originalUID
		effectiveGID = originalGID
	})
}
