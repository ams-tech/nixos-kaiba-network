package main

import (
	"io"
	"testing"
)

func TestParseConfigEnforcesMutualTLSAndListenerBoundary(t *testing.T) {
	tlsFlags := []string{"--tls-cert", "server.crt", "--tls-key", "server.key", "--client-ca", "client-ca.crt"}
	for _, test := range []struct {
		name      string
		arguments []string
		valid     bool
		tls       bool
	}{
		{name: "default loopback plaintext", valid: true},
		{name: "IPv6 loopback plaintext", arguments: []string{"--listen", "[::1]:8092"}, valid: true},
		{name: "non-loopback plaintext", arguments: []string{"--listen", "192.0.2.10:8092"}},
		{name: "complete TLS on concrete IP", arguments: append([]string{"--listen", "192.0.2.10:8092"}, tlsFlags...), valid: true, tls: true},
		{name: "TLS wildcard IPv4", arguments: append([]string{"--listen", "0.0.0.0:8092"}, tlsFlags...)},
		{name: "TLS wildcard IPv6", arguments: append([]string{"--listen", "[::]:8092"}, tlsFlags...)},
		{name: "TLS hostname", arguments: append([]string{"--listen", "audit.example:8092"}, tlsFlags...)},
		{name: "partial TLS", arguments: []string{"--tls-cert", "server.crt", "--client-ca", "client-ca.crt"}},
		{name: "empty state", arguments: []string{"--state", ""}},
		{name: "positional argument", arguments: []string{"extra"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseConfig(test.arguments, io.Discard)
			if (err == nil) != test.valid {
				t.Fatalf("parseConfig() error = %v, valid=%t", err, test.valid)
			}
			if err == nil && config.tlsFiles.Enabled() != test.tls {
				t.Fatalf("TLS enabled = %t, want %t", config.tlsFiles.Enabled(), test.tls)
			}
		})
	}
}

func TestParseConfigDefaultsRemainBoundedLoopbackPlaintext(t *testing.T) {
	config, err := parseConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if config.listen != "127.0.0.1:8092" || config.statePath != "kaiba-provision-audit.json" || config.tlsFiles.Enabled() {
		t.Fatalf("default config = %#v", config)
	}
}
