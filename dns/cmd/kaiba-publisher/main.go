package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/cliutil"
	clocksource "github.com/ams-tech/nixos-kaiba-network/dns/internal/clock"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/dnswriter"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/publisher"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

func main() {
	log.SetFlags(0)
	pollDefault := mustDuration("KAIBA_PUBLISHER_POLL_INTERVAL", 5*time.Second)
	ttlDefault := mustUint32("KAIBA_PUBLISHER_TTL", 300)
	onceDefault := mustBool("KAIBA_PUBLISHER_ONCE", false)
	database := flag.String("db", cliutil.Env("KAIBA_PUBLISHER_DB", "/var/lib/kaiba-controller/controller.db"), "SQLite desired-state database")
	clockFile := flag.String("clock-file", cliutil.Env("KAIBA_PUBLISHER_CLOCK_FILE", ""), "RFC3339 clock file for controlled tests (empty uses wall clock)")
	dnsServer := flag.String("dns-server", cliutil.Env("KAIBA_PUBLISHER_DNS_SERVER", ""), "writable origin address")
	zone := flag.String("zone", cliutil.Env("KAIBA_PUBLISHER_ZONE", "kaiba.network"), "DNS update zone")
	tsigName := flag.String("tsig-name", cliutil.Env("KAIBA_PUBLISHER_TSIG_NAME", ""), "RFC 2136 TSIG key name")
	tsigAlgorithm := flag.String("tsig-algorithm", cliutil.Env("KAIBA_PUBLISHER_TSIG_ALGORITHM", "hmac-sha256."), "RFC 2136 TSIG algorithm")
	tsigSecretFile := flag.String("tsig-secret-file", cliutil.Env("KAIBA_PUBLISHER_TSIG_SECRET_FILE", ""), "file containing the base64 TSIG secret")
	ttl := flag.Uint("ttl", uint(ttlDefault), "published address TTL in seconds")
	pollInterval := flag.Duration("poll-interval", pollDefault, "desired-state polling interval")
	observeServers := cliutil.CSVEnv("KAIBA_PUBLISHER_OBSERVE_SERVERS")
	flag.Var(&observeServers, "observe-server", "public authoritative DNS server to observe (repeatable)")
	once := flag.Bool("once", onceDefault, "run one reconciliation pass and exit")
	flag.Parse()
	if *dnsServer == "" || *tsigName == "" || *tsigSecretFile == "" {
		log.Fatal("--dns-server, --tsig-name, and --tsig-secret-file are required")
	}
	if *ttl == 0 || uint64(*ttl) > uint64(^uint32(0)) {
		log.Fatal("--ttl must be between 1 and 4294967295")
	}
	secret, err := os.ReadFile(*tsigSecretFile)
	if err != nil {
		log.Fatalf("read TSIG secret: %v", err)
	}
	now, err := clocksource.New(*clockFile, func(err error) {
		if err == nil {
			log.Printf("clock file recovered")
			return
		}
		log.Printf("clock file error: %v", err)
	})
	if err != nil {
		log.Fatal(err)
	}
	desiredState, err := store.OpenSQLite(*database)
	if err != nil {
		log.Fatal(err)
	}
	defer desiredState.Close()
	var observer dnswriter.Observer
	if len(observeServers) > 0 {
		observer = dnswriter.DNSObserver{Servers: observeServers}
	}
	service := &publisher.Service{
		Store:    desiredState,
		DNS:      dnswriter.RFC2136{Server: *dnsServer, Zone: *zone, TSIGName: *tsigName, TSIGSecret: strings.TrimSpace(string(secret)), Algorithm: *tsigAlgorithm},
		Observer: observer, Leadership: publisher.StaticLeadership{}, TTL: uint32(*ttl),
		Now:     now,
		OnError: func(err error) { log.Printf("publication pass failed: %v", err) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := service.RunOnce(ctx); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := service.Run(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(fmt.Errorf("publisher stopped: %w", err))
	}
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

func mustUint32(name string, fallback uint32) uint32 {
	value, err := cliutil.EnvUint32(name, fallback)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
