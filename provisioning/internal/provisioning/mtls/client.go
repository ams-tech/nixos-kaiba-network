package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ClientFiles contains the station credential and the exclusive trust anchor
// used by an authenticated provisioning client. The host's system roots are
// deliberately never consulted.
type ClientFiles struct {
	Certificate string
	PrivateKey  string
	ServerCA    string
}

func (files ClientFiles) Validate() error {
	configured := 0
	for _, path := range []string{files.Certificate, files.PrivateKey, files.ServerCA} {
		if path != "" {
			configured++
		}
	}
	if configured != 3 {
		return errors.New("client --tls-cert, --tls-key, and --server-ca must all be set")
	}
	return nil
}

// LoadClientConfig constructs a TLS 1.3 client configuration with one fixed
// client certificate and an otherwise empty server trust pool. ServerName is
// intentionally left unset so net/http derives and verifies it from the
// configured HTTPS authority.
func LoadClientConfig(files ClientFiles) (*tls.Config, error) {
	if err := files.Validate(); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(files.Certificate, files.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load TLS client certificate and key: %w", err)
	}
	serverCAPEM, err := os.ReadFile(files.ServerCA)
	if err != nil {
		return nil, fmt.Errorf("read server CA: %w", err)
	}
	serverRoots := x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("server CA file contains no parseable certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      serverRoots,
	}, nil
}
