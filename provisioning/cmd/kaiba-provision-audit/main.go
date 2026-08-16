package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

type serverConfig struct {
	listen    string
	statePath string
	tlsFiles  mtls.Files
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatalf("kaiba-provision-audit: %v", err)
	}
}

func parseConfig(arguments []string, output io.Writer) (serverConfig, error) {
	flags := flag.NewFlagSet("kaiba-provision-audit", flag.ContinueOnError)
	flags.SetOutput(output)
	var config serverConfig
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8092", "explicit IP address and port")
	flags.StringVar(&config.statePath, "state", "kaiba-provision-audit.json", "durable append-only audit state path")
	flags.StringVar(&config.tlsFiles.Certificate, "tls-cert", "", "server certificate PEM path")
	flags.StringVar(&config.tlsFiles.PrivateKey, "tls-key", "", "server private-key PEM path")
	flags.StringVar(&config.tlsFiles.ClientCA, "client-ca", "", "exclusive client CA PEM path")
	if err := flags.Parse(arguments); err != nil {
		return serverConfig{}, err
	}
	if flags.NArg() != 0 {
		return serverConfig{}, errors.New("unexpected positional arguments")
	}
	if config.statePath == "" {
		return serverConfig{}, errors.New("state path must not be empty")
	}
	if err := config.tlsFiles.Validate(); err != nil {
		return serverConfig{}, err
	}
	if err := mtls.ValidateListenAddress(config.listen, config.tlsFiles.Enabled()); err != nil {
		return serverConfig{}, err
	}
	return config, nil
}

func run(ctx context.Context, arguments []string) error {
	config, err := parseConfig(arguments, os.Stderr)
	if err != nil {
		return err
	}
	service, err := auditlog.NewService(auditlog.FileStore{Path: config.statePath})
	if err != nil {
		return fmt.Errorf("open audit state: %w", err)
	}
	var tlsConfig *tls.Config
	identityPolicy := mtls.LoopbackPlaintextIdentityPolicy()
	if config.tlsFiles.Enabled() {
		tlsConfig, err = mtls.LoadServerConfig(config.tlsFiles)
		if err != nil {
			return fmt.Errorf("configure mutual TLS: %w", err)
		}
		identityPolicy = mtls.MutualTLSIdentityPolicy()
	}
	listener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{
		Addr: config.listen, Handler: auditlog.Handler(service, identityPolicy), TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		if err := <-result; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
