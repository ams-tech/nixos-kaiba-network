package authorityhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func TestReadersUseMTLSStrictRoutesAndSeparateRoots(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	controlServer, controlCA := startMTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
		assertClientCertificate(t, request)
		if request.Method != http.MethodGet || request.URL.EscapedPath() != "/api/v1/transactions/transaction-1" || request.URL.RawQuery != "" {
			t.Errorf("control request = %s %s", request.Method, request.URL.String())
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(writer).Encode(controlplane.Transaction{
			SchemaVersion: controlplane.TransactionSchemaVersion,
			ID:            "transaction-1",
		})
	})
	auditServer, auditCA := startMTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
		assertClientCertificate(t, request)
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/events" || request.URL.Query().Get("transaction_id") != "transaction-1" {
			t.Errorf("audit request = %s %s", request.Method, request.URL.String())
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(struct {
			SchemaVersion string            `json:"schema_version"`
			Records       []auditlog.Record `json:"records"`
		}{
			SchemaVersion: auditlog.StoreSchemaVersion,
			Records: []auditlog.Record{{
				Sequence: 1,
				Event:    auditlog.Event{TransactionID: "transaction-1"},
			}},
		})
	})

	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	control, audit, err := NewIndependentReaders(controlServer.URL, mtls.ClientFiles{
		Certificate: certificatePath,
		PrivateKey:  keyPath,
		ServerCA:    controlCA,
	}, auditServer.URL, mtls.ClientFiles{
		Certificate: certificatePath,
		PrivateKey:  keyPath,
		ServerCA:    auditCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := control.GetTransaction(context.Background(), "transaction-1")
	if err != nil || transaction.ID != "transaction-1" {
		t.Fatalf("control transaction = %#v, %v", transaction, err)
	}
	records, err := audit.GetRecords(context.Background(), "transaction-1")
	if err != nil || len(records) != 1 || records[0].Event.TransactionID != "transaction-1" {
		t.Fatalf("audit records = %#v, %v", records, err)
	}

	controlTransport := control.client.Transport.(*http.Transport)
	auditTransport := audit.client.Transport.(*http.Transport)
	if controlTransport.Proxy != nil || auditTransport.Proxy != nil ||
		controlTransport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		auditTransport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		controlTransport.TLSClientConfig.RootCAs == auditTransport.TLSClientConfig.RootCAs {
		t.Fatal("readers did not receive independent, no-proxy TLS 1.3 transports")
	}

	wrongRoot, err := NewControlReader(controlServer.URL, mtls.ClientFiles{
		Certificate: certificatePath,
		PrivateKey:  keyPath,
		ServerCA:    auditCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongRoot.GetTransaction(context.Background(), "transaction-1"); err == nil {
		t.Fatal("control service was accepted under the audit service trust root")
	}
}

func TestAuditReaderUsesExactReceiptSelection(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	receiptID := "sha256:" + strings.Repeat("a", 64)
	server, serverCA := startMTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if values := request.URL.Query()["receipt_id"]; len(values) != 1 || values[0] != receiptID {
			t.Errorf("receipt query = %#v", values)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(struct {
			SchemaVersion string            `json:"schema_version"`
			Records       []auditlog.Record `json:"records"`
		}{auditlog.StoreSchemaVersion, []auditlog.Record{{
			Sequence: 1, Event: auditlog.Event{TransactionID: "transaction-1"},
		}}})
	})
	reader, err := NewAuditReader(server.URL, mtls.ClientFiles{
		Certificate: certificatePath, PrivateKey: keyPath, ServerCA: serverCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := reader.GetRecordsByReceiptIDs(context.Background(), "transaction-1", []string{receiptID})
	if err != nil || len(records) != 1 {
		t.Fatalf("exact audit records = %#v, %v", records, err)
	}
	for _, receiptIDs := range [][]string{nil, {"bad"}, {receiptID, receiptID}} {
		if _, err := reader.GetRecordsByReceiptIDs(context.Background(), "transaction-1", receiptIDs); err == nil {
			t.Fatalf("invalid receipt selection accepted: %#v", receiptIDs)
		}
	}
}

func TestIndependentReadersRejectSharedServerTrustRoot(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	_, sharedCA := startMTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	sharedContents, err := os.ReadFile(sharedCA)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	sharedCopy := filepath.Join(directory, "shared-copy.pem")
	if err := os.WriteFile(sharedCopy, sharedContents, 0o600); err != nil {
		t.Fatal(err)
	}
	reencodedCopy := filepath.Join(directory, "shared-reencoded.pem")
	if err := os.WriteFile(reencodedCopy, append([]byte("# same root with distinct PEM bytes\n"), sharedContents...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, additionalCA := startMTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	additionalContents, err := os.ReadFile(additionalCA)
	if err != nil {
		t.Fatal(err)
	}
	overlappingPool := filepath.Join(directory, "overlapping-pool.pem")
	combined := append(append([]byte(nil), sharedContents...), additionalContents...)
	if err := os.WriteFile(overlappingPool, combined, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		auditCA string
	}{
		{name: "same path", auditCA: sharedCA},
		{name: "identical contents", auditCA: sharedCopy},
		{name: "same parsed root", auditCA: reencodedCopy},
		{name: "partially overlapping pool", auditCA: overlappingPool},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := mtls.ClientFiles{Certificate: certificatePath, PrivateKey: keyPath, ServerCA: sharedCA}
			auditFiles := files
			auditFiles.ServerCA = test.auditCA
			if _, _, err := NewIndependentReaders(
				"https://control.example:8443", files,
				"https://audit.example:8443", auditFiles,
			); err == nil || !strings.Contains(err.Error(), "must be distinct") {
				t.Fatalf("NewIndependentReaders error = %v", err)
			}
		})
	}

	t.Run("reissued root with the same signing key", func(t *testing.T) {
		controlCA, auditCA := writeReissuedTrustAnchors(t)
		controlFiles := mtls.ClientFiles{Certificate: certificatePath, PrivateKey: keyPath, ServerCA: controlCA}
		auditFiles := mtls.ClientFiles{Certificate: certificatePath, PrivateKey: keyPath, ServerCA: auditCA}
		if _, _, err := NewIndependentReaders(
			"https://control.example:8443", controlFiles,
			"https://audit.example:8443", auditFiles,
		); err == nil || !strings.Contains(err.Error(), "must be distinct") {
			t.Fatalf("NewIndependentReaders error = %v", err)
		}
	})
}

func TestIndependentReadersRejectSemanticOriginAliases(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	_, controlCA := startMTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	_, auditCA := startMTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	controlFiles := mtls.ClientFiles{Certificate: certificatePath, PrivateKey: keyPath, ServerCA: controlCA}
	auditFiles := mtls.ClientFiles{Certificate: certificatePath, PrivateKey: keyPath, ServerCA: auditCA}

	for _, origins := range [][2]string{
		{"https://[::1]:8443", "https://[0:0:0:0:0:0:0:1]:8443"},
		{"https://192.0.2.1:8443", "https://[::ffff:192.0.2.1]:8443"},
		{"https://control.example", "https://CONTROL.example:443"},
		{"https://control.example", "https://CONTROL.example:0443"},
	} {
		if _, _, err := NewIndependentReaders(origins[0], controlFiles, origins[1], auditFiles); err == nil ||
			!strings.Contains(err.Error(), "origins must be distinct") {
			t.Fatalf("NewIndependentReaders(%q, %q) error = %v", origins[0], origins[1], err)
		}
	}
}

func TestReaderRejectsNonOriginAndNonHTTPSBaseURLs(t *testing.T) {
	for _, raw := range []string{
		"", "http://authority.example", "https://user@authority.example", "https://authority.example/api",
		"https://authority.example?x=1", "https://authority.example#fragment", " https://authority.example",
		"https://authority.example:0", "https://authority.example:65536",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewControlReader(raw, mtls.ClientFiles{}); err == nil || !strings.Contains(err.Error(), "base URL") {
				t.Fatalf("NewControlReader(%q) error = %v", raw, err)
			}
		})
	}
}

func TestControlReaderRejectsRedirectsAndMalformedResponses(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	for _, test := range []struct {
		name        string
		contentType string
		status      int
		body        string
		want        string
	}{
		{name: "redirect", status: http.StatusFound, contentType: "application/json", body: `{}`, want: "302"},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: `{}`, want: "Content-Type"},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: `{"schema_version":"` + controlplane.TransactionSchemaVersion + `","id":"transaction-1","surprise":true}`, want: "unknown field"},
		{name: "duplicate field", status: http.StatusOK, contentType: "application/json", body: `{"schema_version":"` + controlplane.TransactionSchemaVersion + `","id":"transaction-1","id":"transaction-1"}`, want: "duplicate"},
		{name: "trailing value", status: http.StatusOK, contentType: "application/json", body: `{"schema_version":"` + controlplane.TransactionSchemaVersion + `","id":"transaction-1"}{}`, want: "trailing"},
		{name: "wrong identity", status: http.StatusOK, contentType: "application/json", body: `{"schema_version":"` + controlplane.TransactionSchemaVersion + `","id":"transaction-2"}`, want: "identity"},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("x", maxResponseBytes+1), want: "size"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, serverCA := startMTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
				assertClientCertificate(t, request)
				if test.name == "redirect" {
					writer.Header().Set("Location", "https://redirect.invalid/api/v1/transactions/transaction-1")
				}
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			})
			reader, err := NewControlReader(server.URL, mtls.ClientFiles{
				Certificate: certificatePath,
				PrivateKey:  keyPath,
				ServerCA:    serverCA,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.GetTransaction(context.Background(), "transaction-1"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAuditReaderRejectsMalformedEnvelopeAndCrossTransactionRecords(t *testing.T) {
	certificatePath, keyPath := writeClientCredential(t)
	for _, body := range []string{
		`{"schema_version":"` + auditlog.StoreSchemaVersion + `","records":null}`,
		`{"schema_version":"wrong","records":[]}`,
		`{"schema_version":"` + auditlog.StoreSchemaVersion + `","records":[{"sequence":1,"event":{"transaction_id":"transaction-2"}}]}`,
	} {
		server, serverCA := startMTLSServer(t, func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(body))
		})
		reader, err := NewAuditReader(server.URL, mtls.ClientFiles{
			Certificate: certificatePath,
			PrivateKey:  keyPath,
			ServerCA:    serverCA,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.GetRecords(context.Background(), "transaction-1"); err == nil {
			t.Fatalf("malformed audit response was accepted: %s", body)
		}
		server.Close()
	}
}

func TestReadersRejectInvalidTransactionIDWithoutNetworkAccess(t *testing.T) {
	if _, err := (&ControlReader{}).GetTransaction(context.Background(), "transaction/escape"); err == nil {
		t.Fatal("invalid control transaction ID was accepted")
	}
	if _, err := (&AuditReader{}).GetRecords(context.Background(), "transaction/escape"); err == nil {
		t.Fatal("invalid audit transaction ID was accepted")
	}
	if _, err := (&AuditReader{}).GetRecordsByReceiptIDs(context.Background(), "transaction/escape", []string{"sha256:" + strings.Repeat("a", 64)}); err == nil {
		t.Fatal("invalid exact audit transaction ID was accepted")
	}
}

func assertClientCertificate(t *testing.T, request *http.Request) {
	t.Helper()
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		t.Fatal("request did not present exactly one client certificate")
	}
}

func startMTLSServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "authority-service"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverCA := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return server, serverCA
}

func writeClientCredential(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "station-client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "station.pem")
	keyPath := filepath.Join(directory, "station-key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}

func writeReissuedTrustAnchors(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	directory := t.TempDir()
	paths := [2]string{filepath.Join(directory, "control-ca.pem"), filepath.Join(directory, "audit-ca.pem")}
	for index, path := range paths {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(index + 1)),
			Subject:               pkix.Name{CommonName: "reissued-authority-" + string(rune('a'+index))},
			NotBefore:             now.Add(-time.Duration(index+1) * time.Hour),
			NotAfter:              now.Add(time.Duration(index+1) * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1]
}
