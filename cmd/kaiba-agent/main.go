package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/agent"
	"github.com/kaiba-network/dns-pilot/internal/cliutil"
)

func main() {
	log.SetFlags(0)
	renewDefault := mustDuration("KAIBA_AGENT_RENEW_INTERVAL", 6*time.Hour)
	timeoutDefault := mustDuration("KAIBA_AGENT_REQUEST_TIMEOUT", 30*time.Second)
	onceDefault := mustBool("KAIBA_AGENT_ONCE", false)
	endpoint := flag.String("endpoint", cliutil.Env("KAIBA_AGENT_ENDPOINT", ""), "controller base HTTPS URL")
	certFile := flag.String("client-cert", cliutil.Env("KAIBA_AGENT_CLIENT_CERT", ""), "device certificate file")
	keyFile := flag.String("client-key", cliutil.Env("KAIBA_AGENT_CLIENT_KEY", ""), "device private-key file")
	caFile := flag.String("ca", cliutil.Env("KAIBA_AGENT_CA", ""), "controller CA bundle")
	addresses := cliutil.CSVEnv("KAIBA_AGENT_ADDRESSES")
	flag.Var(&addresses, "address", "explicit endpoint IP address (repeatable)")
	interfaces := cliutil.CSVEnv("KAIBA_AGENT_INTERFACES")
	flag.Var(&interfaces, "interface", "interface eligible for address discovery (repeatable)")
	statePath := flag.String("idempotency-state", cliutil.Env("KAIBA_AGENT_IDEMPOTENCY_STATE", "/var/lib/kaiba-agent/idempotency.json"), "pending request state file")
	renewInterval := flag.Duration("renew-interval", renewDefault, "lease-renewal interval")
	requestTimeout := flag.Duration("request-timeout", timeoutDefault, "one HTTP request timeout")
	once := flag.Bool("once", onceDefault, "submit once and exit")
	flag.Parse()
	if *endpoint == "" || *certFile == "" || *keyFile == "" || *caFile == "" {
		log.Fatal("--endpoint, --client-cert, --client-key, and --ca are required")
	}
	parsedAddresses := make([]netip.Addr, 0, len(addresses))
	for _, value := range addresses {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Is4In6() {
			log.Fatalf("invalid --address %q", value)
		}
		parsedAddresses = append(parsedAddresses, addr)
	}
	httpClient, err := agent.NewHTTPClient(*certFile, *keyFile, *caFile, *requestTimeout)
	if err != nil {
		log.Fatal(err)
	}
	service, err := agent.New(agent.Config{
		Endpoint: *endpoint, Addresses: parsedAddresses, Interfaces: interfaces,
		StatePath: *statePath, HTTPClient: httpClient, RenewInterval: *renewInterval,
		RequestTimeout: *requestTimeout, Once: *once,
		OnError: func(err error) { log.Printf("endpoint update failed: %v", err) },
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
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
