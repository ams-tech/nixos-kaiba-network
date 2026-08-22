package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authoritybridge"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

type serverConfig struct {
	socketPath        string
	controlURL        string
	auditURL          string
	tlsCertificate    string
	tlsPrivateKey     string
	controlServerCA   string
	auditServerCA     string
	leaseSafetyMargin time.Duration
}

var (
	buildAuthorityReaders = func(
		controlBaseURL string,
		controlFiles mtls.ClientFiles,
		auditBaseURL string,
		auditFiles mtls.ClientFiles,
	) (authoritybridge.ControlReader, authoritybridge.AuditReader, error) {
		control, audit, err := authorityhttp.NewIndependentReaders(controlBaseURL, controlFiles, auditBaseURL, auditFiles)
		return control, audit, err
	}
	serveBridge  = authoritybridge.Serve
	effectiveUID = os.Geteuid
	effectiveGID = os.Getegid
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatalf("kaiba-provision-authority-bridge: %v", err)
	}
}

func parseConfig(arguments []string, output io.Writer) (serverConfig, error) {
	flags := flag.NewFlagSet("kaiba-provision-authority-bridge", flag.ContinueOnError)
	flags.SetOutput(output)
	var config serverConfig
	flags.StringVar(&config.socketPath, "socket", "", "private Unix socket path")
	flags.StringVar(&config.controlURL, "control-url", "", "control-service HTTPS origin")
	flags.StringVar(&config.auditURL, "audit-url", "", "audit-service HTTPS origin")
	flags.StringVar(&config.tlsCertificate, "tls-cert", "", "station client certificate PEM path")
	flags.StringVar(&config.tlsPrivateKey, "tls-key", "", "station client private-key PEM path")
	flags.StringVar(&config.controlServerCA, "control-server-ca", "", "exclusive control-service CA PEM path")
	flags.StringVar(&config.auditServerCA, "audit-server-ca", "", "exclusive audit-service CA PEM path")
	flags.DurationVar(&config.leaseSafetyMargin, "lease-safety-margin", 30*time.Second, "lease lifetime reserved after the worst-case operation duration")
	if err := flags.Parse(arguments); err != nil {
		return serverConfig{}, err
	}
	if flags.NArg() != 0 {
		return serverConfig{}, errors.New("unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"--socket": config.socketPath, "--control-url": config.controlURL, "--audit-url": config.auditURL,
		"--tls-cert": config.tlsCertificate, "--tls-key": config.tlsPrivateKey,
		"--control-server-ca": config.controlServerCA, "--audit-server-ca": config.auditServerCA,
	} {
		if value == "" {
			return serverConfig{}, fmt.Errorf("%s is required", name)
		}
	}
	if !validAbsolutePath(config.socketPath, 100) {
		return serverConfig{}, errors.New("--socket must be a clean, short absolute path")
	}
	if sameAuthorityOrigin(config.controlURL, config.auditURL) {
		return serverConfig{}, errors.New("control and audit authority origins must be distinct")
	}
	for name, path := range map[string]string{
		"--tls-cert": config.tlsCertificate, "--tls-key": config.tlsPrivateKey,
		"--control-server-ca": config.controlServerCA, "--audit-server-ca": config.auditServerCA,
	} {
		if !validAbsolutePath(path, 4096) {
			return serverConfig{}, fmt.Errorf("%s must be a clean absolute path", name)
		}
		if path == "/nix/store" || strings.HasPrefix(path, "/nix/store/") {
			return serverConfig{}, fmt.Errorf("%s must be a runtime credential outside the Nix store", name)
		}
	}
	if config.controlServerCA == config.auditServerCA {
		return serverConfig{}, errors.New("control and audit server CA paths must be distinct")
	}
	if config.leaseSafetyMargin < 0 {
		return serverConfig{}, errors.New("--lease-safety-margin must not be negative")
	}
	return config, nil
}

func sameAuthorityOrigin(left, right string) bool {
	return authorityhttp.SameAuthorityOrigin(left, right)
}

func validAbsolutePath(path string, maximumLength int) bool {
	return path != "" && len(path) <= maximumLength && strings.IndexByte(path, 0) < 0 && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func run(ctx context.Context, arguments []string) error {
	config, err := parseConfig(arguments, os.Stderr)
	if err != nil {
		return err
	}
	controlReader, auditReader, err := buildAuthorityReaders(config.controlURL, mtls.ClientFiles{
		Certificate: config.tlsCertificate,
		PrivateKey:  config.tlsPrivateKey,
		ServerCA:    config.controlServerCA,
	}, config.auditURL, mtls.ClientFiles{
		Certificate: config.tlsCertificate,
		PrivateKey:  config.tlsPrivateKey,
		ServerCA:    config.auditServerCA,
	})
	if err != nil {
		return fmt.Errorf("configure independent authority readers: %w", err)
	}
	uid := effectiveUID()
	if uid < 0 || uint64(uid) > math.MaxUint32 {
		return errors.New("effective UID is outside the supported range")
	}
	gid := effectiveGID()
	if gid < 0 || uint64(gid) > math.MaxUint32 {
		return errors.New("effective GID is outside the supported range")
	}
	binder := &authoritybridge.Binder{
		Control:           controlReader,
		Audit:             auditReader,
		LeaseSafetyMargin: config.leaseSafetyMargin,
	}
	if err := serveBridge(ctx, authoritybridge.ServerConfig{
		SocketPath:    config.socketPath,
		OwnerUID:      uint32(uid),
		OwnerGID:      uint32(gid),
		DirectoryMode: 0o750,
		SocketMode:    0o660,
		Binder:        binder,
		ErrorLog:      os.Stderr,
	}); err != nil {
		return fmt.Errorf("serve authenticated authority bridge: %w", err)
	}
	return nil
}
