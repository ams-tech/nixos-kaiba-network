// Package mtls defines the narrow mutually authenticated TLS transport used by
// the provisioning control and audit reference services.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

type Files struct {
	Certificate string
	PrivateKey  string
	ClientCA    string
}

func (files Files) Enabled() bool {
	return files.Certificate != "" && files.PrivateKey != "" && files.ClientCA != ""
}

// Validate requires a complete TLS credential tuple or no TLS fields at all.
func (files Files) Validate() error {
	configured := 0
	for _, path := range []string{files.Certificate, files.PrivateKey, files.ClientCA} {
		if path != "" {
			configured++
		}
	}
	if configured != 0 && configured != 3 {
		return errors.New("--tls-cert, --tls-key, and --client-ca must be set together")
	}
	return nil
}

// ValidateListenAddress forbids hostnames and wildcard listeners. Plain HTTP
// is permitted only on an explicit loopback IP; authenticated TLS may use any
// concrete, non-unspecified IP address.
func ValidateListenAddress(address string, tlsEnabled bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listen address must contain an explicit IP address and port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("listen address must use an IP literal, not a hostname")
	}
	if ip.IsUnspecified() {
		return errors.New("listen address must not be an unspecified or wildcard IP")
	}
	if !tlsEnabled && !ip.IsLoopback() {
		return errors.New("plain HTTP may listen only on an explicit loopback IP")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (portNumber == 0 && port != "0") {
		return errors.New("listen port is invalid")
	}
	return nil
}

// LoadServerConfig constructs a TLS 1.3-only-floor server configuration. Its
// client trust pool starts empty and contains only certificates supplied via
// ClientCA; the host's system roots are never consulted.
func LoadServerConfig(files Files) (*tls.Config, error) {
	if err := files.Validate(); err != nil {
		return nil, err
	}
	if !files.Enabled() {
		return nil, errors.New("TLS credentials are not configured")
	}
	certificate, err := tls.LoadX509KeyPair(files.Certificate, files.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	clientCAPEM, err := os.ReadFile(files.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("client CA file contains no parseable certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}
