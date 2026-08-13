package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/cliutil"
	clocksource "github.com/ams-tech/nixos-kaiba-network/dns/internal/clock"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/controller"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/identity"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

func main() {
	log.SetFlags(0)
	leaseDefault := mustDuration("KAIBA_CONTROLLER_LEASE_DURATION", 24*time.Hour)
	renewDefault := mustDuration("KAIBA_CONTROLLER_RENEW_AFTER", 6*time.Hour)
	allowDefault := mustBool("KAIBA_CONTROLLER_ALLOW_NON_GLOBAL_ADDRESSES", false)
	listen := flag.String("listen", cliutil.Env("KAIBA_CONTROLLER_LISTEN", ":8443"), "HTTPS listen address")
	database := flag.String("db", cliutil.Env("KAIBA_CONTROLLER_DB", "/var/lib/kaiba-controller/controller.db"), "SQLite desired-state database")
	certFile := flag.String("tls-cert", cliutil.Env("KAIBA_CONTROLLER_TLS_CERT", ""), "server certificate file")
	keyFile := flag.String("tls-key", cliutil.Env("KAIBA_CONTROLLER_TLS_KEY", ""), "server private-key file")
	clientCAFile := flag.String("client-ca", cliutil.Env("KAIBA_CONTROLLER_CLIENT_CA", ""), "trusted device CA bundle")
	zone := flag.String("zone", cliutil.Env("KAIBA_CONTROLLER_ZONE", "kaiba.network"), "device DNS zone")
	clockFile := flag.String("clock-file", cliutil.Env("KAIBA_CONTROLLER_CLOCK_FILE", ""), "RFC3339 clock file for controlled tests (empty uses wall clock)")
	leaseDuration := flag.Duration("lease-duration", leaseDefault, "device address lease duration")
	renewAfter := flag.Duration("renew-after", renewDefault, "recommended device renewal interval")
	allowNonGlobal := flag.Bool("allow-non-global-addresses", allowDefault, "allow test-only non-public addresses")
	flag.Parse()
	if *certFile == "" || *keyFile == "" || *clientCAFile == "" {
		log.Fatal("--tls-cert, --tls-key, and --client-ca are required")
	}
	if err := run(*listen, *database, *certFile, *keyFile, *clientCAFile, *zone, *clockFile, *leaseDuration, *renewAfter, *allowNonGlobal); err != nil {
		log.Fatal(err)
	}
}

func run(listen, database, certFile, keyFile, clientCAFile, zone, clockFile string, leaseDuration, renewAfter time.Duration, allowNonGlobal bool) error {
	now, err := clocksource.New(clockFile, func(err error) {
		if err == nil {
			log.Printf("clock file recovered")
			return
		}
		log.Printf("clock file error: %v", err)
	})
	if err != nil {
		return err
	}
	desiredState, err := store.OpenSQLite(database)
	if err != nil {
		return err
	}
	defer desiredState.Close()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load controller certificate: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return fmt.Errorf("read device CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return errors.New("device CA file contains no certificates")
	}
	handler, err := controller.New(controller.Config{
		Identity: identity.SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: zone},
		Store:    desiredState, LeaseDuration: leaseDuration, RenewAfter: renewAfter,
		AllowNonGlobalAddresses: allowNonGlobal,
		Now:                     now,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: listen, Handler: handler, TLSConfig: controller.TLSConfig(cert, clientCAs),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	log.Printf("kaiba-controller listening on %s", listen)
	return server.ListenAndServeTLS("", "")
}

func mustDuration(name string, fallback time.Duration) time.Duration {
	value, err := cliutil.EnvDuration(name, fallback)
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func mustBool(name string, fallback bool) bool {
	value, err := cliutil.EnvBool(name, fallback)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
