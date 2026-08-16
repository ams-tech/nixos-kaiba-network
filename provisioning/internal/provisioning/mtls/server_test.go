package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMutualTLSIdentityPolicyBindsExactStationAndLaneURI(t *testing.T) {
	policy := MutualTLSIdentityPolicy()
	matching := requestWithVerifiedIdentity(t, "ignored-common-name", "spiffe://kaiba.network/station/station-1/lane/lane-1")
	if err := policy.Authorize(matching, "station-1", "lane-1"); err != nil {
		t.Fatalf("matching identity failed: %v", err)
	}
	identity, err := policy.Authenticate(matching)
	if err != nil {
		t.Fatal(err)
	}
	if identity != (StationLaneIdentity{StationID: "station-1", LaneID: "lane-1"}) {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestMutualTLSIdentityPolicyRejectsMissingMismatchAndAmbiguousSAN(t *testing.T) {
	policy := MutualTLSIdentityPolicy()
	tests := []struct {
		name    string
		request *http.Request
		want    error
	}{
		{
			name:    "missing verified certificate",
			request: httptest.NewRequest(http.MethodPost, "https://control.test/api/v1/commands", nil),
			want:    ErrClientIdentity,
		},
		{
			name:    "matching common name is not a fallback",
			request: requestWithVerifiedIdentity(t, "station-1/lane-1"),
			want:    ErrClientIdentity,
		},
		{
			name:    "mismatched station",
			request: requestWithVerifiedIdentity(t, "ignored", "spiffe://kaiba.network/station/station-2/lane/lane-1"),
			want:    ErrClientIdentityMismatch,
		},
		{
			name: "ambiguous URI SANs",
			request: requestWithVerifiedIdentity(t, "ignored",
				"spiffe://kaiba.network/station/station-1/lane/lane-1",
				"spiffe://kaiba.network/station/station-1/lane/lane-2"),
			want: ErrClientIdentity,
		},
		{
			name:    "noncanonical URI SAN",
			request: requestWithVerifiedIdentity(t, "ignored", "spiffe://kaiba.network/station/station-1/lane/lane-1?role=admin"),
			want:    ErrClientIdentity,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := policy.Authorize(test.request, "station-1", "lane-1"); !errors.Is(err, test.want) {
				t.Fatalf("Authorize error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLoopbackPlaintextPolicyPreservesDevelopmentMode(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/commands", nil)
	if err := LoopbackPlaintextIdentityPolicy().Authorize(request, "station-1", "lane-1"); err != nil {
		t.Fatalf("loopback development authorization failed: %v", err)
	}
	if err := (IdentityPolicy{}).Authorize(request, "station-1", "lane-1"); !errors.Is(err, ErrClientIdentity) {
		t.Fatalf("zero-value identity policy error = %v", err)
	}
}

func requestWithVerifiedIdentity(t *testing.T, commonName string, identityURIs ...string) *http.Request {
	t.Helper()
	certificate := &x509.Certificate{Raw: []byte("test-client-leaf"), Subject: pkix.Name{CommonName: commonName}}
	for _, rawURI := range identityURIs {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatal(err)
		}
		certificate.URIs = append(certificate.URIs, parsed)
	}
	request := httptest.NewRequest(http.MethodPost, "https://control.test/api/v1/commands", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return request
}

func TestFilesAndListenAddressValidation(t *testing.T) {
	for _, files := range []Files{
		{Certificate: "cert"},
		{PrivateKey: "key", ClientCA: "ca"},
	} {
		if err := files.Validate(); err == nil {
			t.Fatalf("incomplete TLS files accepted: %#v", files)
		}
	}
	if err := (Files{}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Files{Certificate: "cert", PrivateKey: "key", ClientCA: "ca"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		tls     bool
		valid   bool
	}{
		{"127.0.0.1:8091", false, true},
		{"[::1]:8091", false, true},
		{"192.0.2.10:8091", true, true},
		{"[2001:db8::10]:8091", true, true},
		{"192.0.2.10:8091", false, false},
		{"0.0.0.0:8091", true, false},
		{"[::]:8091", true, false},
		{"localhost:8091", true, false},
		{"127.0.0.1", true, false},
	} {
		if err := ValidateListenAddress(test.address, test.tls); (err == nil) != test.valid {
			t.Errorf("ValidateListenAddress(%q, %t) error = %v, valid=%t", test.address, test.tls, err, test.valid)
		}
	}
}

func TestTLS13MutualAuthenticationUsesOnlySuppliedClientCA(t *testing.T) {
	now := time.Now().UTC()
	trustedCA := newTestCA(t, "trusted-ca", now)
	rogueCA := newTestCA(t, "rogue-ca", now)
	serverCertificate := trustedCA.issue(t, "server", now, true)
	trustedClient := trustedCA.issue(t, "trusted-client", now, false)
	rogueClient := rogueCA.issue(t, "rogue-client", now, false)
	directory := t.TempDir()
	files := Files{
		Certificate: writePEM(t, directory, "server.crt", "CERTIFICATE", serverCertificate.der),
		PrivateKey:  writeECKey(t, directory, "server.key", serverCertificate.key),
		ClientCA:    writePEM(t, directory, "client-ca.crt", "CERTIFICATE", trustedCA.der),
	}
	serverTLS, err := LoadServerConfig(files)
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.MinVersion != tls.VersionTLS13 || serverTLS.ClientAuth != tls.RequireAndVerifyClientCert || serverTLS.ClientCAs == nil {
		t.Fatalf("TLS config = %#v", serverTLS)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.VerifiedChains) != 1 {
			t.Error("request did not contain one verified client chain")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(trustedCA.certificate)
	request := func(certificate *issuedCertificate) error {
		var certificates []tls.Certificate
		if certificate != nil {
			certificates = []tls.Certificate{{
				Certificate: [][]byte{certificate.der},
				PrivateKey:  certificate.key,
			}}
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      trustedRoots,
			Certificates: certificates,
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("response status = %d", response.StatusCode)
		}
		return nil
	}
	if err := request(trustedClient); err != nil {
		t.Fatalf("trusted client failed: %v", err)
	}
	if err := request(rogueClient); err == nil {
		t.Fatal("client signed by an unsupplied CA authenticated")
	}
	if err := request(nil); err == nil {
		t.Fatal("client without a certificate authenticated")
	}
}

type testCA struct {
	certificate *x509.Certificate
	der         []byte
	key         *ecdsa.PrivateKey
}

type issuedCertificate struct {
	der []byte
	key *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string, now time.Time) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certificate: certificate, der: der, key: key}
}

func (ca testCA) issue(t *testing.T, name string, now time.Time, server bool) *issuedCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &issuedCertificate{der: der, key: key}
}

func writePEM(t *testing.T, directory, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeECKey(t *testing.T, directory, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, directory, name, "PRIVATE KEY", der)
}
