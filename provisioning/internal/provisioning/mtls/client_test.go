package mtls

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestClientFilesRequireCompleteCredentialAndExclusiveServerCA(t *testing.T) {
	for _, files := range []ClientFiles{
		{},
		{Certificate: "cert"},
		{Certificate: "cert", PrivateKey: "key"},
		{Certificate: "cert", ServerCA: "ca"},
	} {
		if err := files.Validate(); err == nil {
			t.Fatalf("incomplete client TLS files accepted: %#v", files)
		}
	}
	if err := (ClientFiles{Certificate: "cert", PrivateKey: "key", ServerCA: "ca"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadClientConfigUsesTLS13AndOnlySuppliedServerCA(t *testing.T) {
	now := time.Now().UTC()
	trustedCA := newTestCA(t, "trusted-client-ca", now)
	clientCertificate := trustedCA.issue(t, "station-client", now, false)
	directory := t.TempDir()
	config, err := LoadClientConfig(ClientFiles{
		Certificate: writePEM(t, directory, "client.crt", "CERTIFICATE", clientCertificate.der),
		PrivateKey:  writeECKey(t, directory, "client.key", clientCertificate.key),
		ServerCA:    writePEM(t, directory, "server-ca.crt", "CERTIFICATE", trustedCA.der),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || len(config.Certificates) != 1 || config.RootCAs == nil || config.ServerName != "" {
		t.Fatalf("client TLS config = %#v", config)
	}
}

func TestLoadClientConfigRejectsUnparseableServerCA(t *testing.T) {
	now := time.Now().UTC()
	ca := newTestCA(t, "client-ca", now)
	clientCertificate := ca.issue(t, "station-client", now, false)
	directory := t.TempDir()
	badCA := writePEM(t, directory, "server-ca.crt", "NOT A CERTIFICATE", []byte("bad"))
	_, err := LoadClientConfig(ClientFiles{
		Certificate: writePEM(t, directory, "client.crt", "CERTIFICATE", clientCertificate.der),
		PrivateKey:  writeECKey(t, directory, "client.key", clientCertificate.key),
		ServerCA:    badCA,
	})
	if err == nil {
		t.Fatal("unparseable server CA was accepted")
	}
}
