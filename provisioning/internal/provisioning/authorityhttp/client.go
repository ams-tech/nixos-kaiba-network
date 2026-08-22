// Package authorityhttp provides the authenticated, read-only network side of
// the provisioning authority bridge.
package authorityhttp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authoritybridge"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

const (
	maxResponseBytes = 1 << 20
	requestTimeout   = authoritybridge.AuthorityReadTimeout
)

var transactionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ControlReader reads authenticated transaction snapshots from the control
// service. Its transport has an exclusive server trust pool and never consults
// proxy environment variables.
type ControlReader struct {
	client  *http.Client
	baseURL url.URL
}

// AuditReader reads authenticated transaction records from the append-only
// audit service. It owns a transport independent of the control reader so the
// two services can have distinct trust anchors.
type AuditReader struct {
	client  *http.Client
	baseURL url.URL
}

var (
	_ authoritybridge.ControlReader = (*ControlReader)(nil)
	_ authoritybridge.AuditReader   = (*AuditReader)(nil)
)

// NewControlReader creates a control reader for an origin-only HTTPS base URL.
func NewControlReader(baseURL string, files mtls.ClientFiles) (*ControlReader, error) {
	client, parsed, err := newClient(baseURL, files)
	if err != nil {
		return nil, err
	}
	return &ControlReader{client: client, baseURL: parsed}, nil
}

// NewAuditReader creates an audit reader for an origin-only HTTPS base URL.
func NewAuditReader(baseURL string, files mtls.ClientFiles) (*AuditReader, error) {
	client, parsed, err := newClient(baseURL, files)
	if err != nil {
		return nil, err
	}
	return &AuditReader{client: client, baseURL: parsed}, nil
}

// NewIndependentReaders creates the paired readers used by the authority
// bridge and rejects a shared server trust root. Distinct filenames and
// certificate encodings are not a sufficient separation boundary: reissued or
// cross-certified roots can still delegate both services to the same key.
func NewIndependentReaders(
	controlBaseURL string,
	controlFiles mtls.ClientFiles,
	auditBaseURL string,
	auditFiles mtls.ClientFiles,
) (*ControlReader, *AuditReader, error) {
	if SameAuthorityOrigin(controlBaseURL, auditBaseURL) {
		return nil, nil, errors.New("control and audit authority origins must be distinct")
	}
	if controlFiles.ServerCA == auditFiles.ServerCA {
		return nil, nil, errors.New("control and audit server CA paths must be distinct")
	}
	controlRoots, err := loadTrustKeyFingerprints(controlFiles.ServerCA)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect control server CA roots: %w", err)
	}
	auditRoots, err := loadTrustKeyFingerprints(auditFiles.ServerCA)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect audit server CA roots: %w", err)
	}
	if trustKeyFingerprintsOverlap(controlRoots, auditRoots) {
		return nil, nil, errors.New("control and audit server CA contents must be distinct and disjoint")
	}
	control, err := NewControlReader(controlBaseURL, controlFiles)
	if err != nil {
		return nil, nil, fmt.Errorf("configure control authority reader: %w", err)
	}
	audit, err := NewAuditReader(auditBaseURL, auditFiles)
	if err != nil {
		return nil, nil, fmt.Errorf("configure audit authority reader: %w", err)
	}
	return control, audit, nil
}

// SameAuthorityOrigin compares two valid HTTPS origins by their effective
// port and semantic IP address (or case-folded DNS name). IPv6 spelling and
// IPv4-mapped aliases therefore cannot bypass the independent-origin gate.
func SameAuthorityOrigin(left, right string) bool {
	leftURL, leftErr := parseBaseURL(left)
	rightURL, rightErr := parseBaseURL(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return canonicalOriginHost(leftURL.Hostname()) == canonicalOriginHost(rightURL.Hostname()) &&
		effectiveHTTPSPort(leftURL) == effectiveHTTPSPort(rightURL)
}

func canonicalOriginHost(host string) string {
	address, err := netip.ParseAddr(host)
	if err == nil {
		return address.Unmap().String()
	}
	return strings.ToLower(host)
}

func effectiveHTTPSPort(origin url.URL) string {
	if port := origin.Port(); port != "" {
		parsed, _ := strconv.ParseUint(port, 10, 16)
		return strconv.FormatUint(parsed, 10)
	}
	return "443"
}

func loadTrustKeyFingerprints(path string) (map[[sha256.Size]byte]struct{}, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fingerprints := make(map[[sha256.Size]byte]struct{})
	for len(encoded) > 0 {
		block, remaining := pem.Decode(encoded)
		if block == nil {
			break
		}
		encoded = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA certificate: %w", err)
		}
		canonicalKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("canonicalize CA public key: %w", err)
		}
		fingerprints[sha256.Sum256(canonicalKey)] = struct{}{}
	}
	if len(fingerprints) == 0 {
		return nil, errors.New("server CA file contains no certificates")
	}
	return fingerprints, nil
}

func trustKeyFingerprintsOverlap(left, right map[[sha256.Size]byte]struct{}) bool {
	for fingerprint := range left {
		if _, exists := right[fingerprint]; exists {
			return true
		}
	}
	return false
}

func newClient(baseURL string, files mtls.ClientFiles) (*http.Client, url.URL, error) {
	parsed, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, url.URL{}, err
	}
	tlsConfig, err := mtls.LoadClientConfig(files)
	if err != nil {
		return nil, url.URL{}, fmt.Errorf("configure mutual TLS client: %w", err)
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
		DisableCompression:     true,
		TLSClientConfig:        cloneTLSConfig(tlsConfig),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, parsed, nil
}

func parseBaseURL(raw string) (url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return url.URL{}, errors.New("authority base URL is required without surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return url.URL{}, fmt.Errorf("parse authority base URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return url.URL{}, errors.New("authority base URL must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return url.URL{}, errors.New("authority base URL must use a TCP port from 1 through 65535")
		}
	}
	return url.URL{Scheme: "https", Host: parsed.Host}, nil
}

// GetTransaction returns exactly one strict control transaction.
func (reader *ControlReader) GetTransaction(ctx context.Context, transactionID string) (controlplane.Transaction, error) {
	if reader == nil || reader.client == nil || !transactionIDPattern.MatchString(transactionID) {
		return controlplane.Transaction{}, errors.New("control transaction ID is invalid")
	}
	endpoint := reader.baseURL
	endpoint.Path = "/api/v1/transactions/" + transactionID
	var transaction controlplane.Transaction
	if err := getJSON(ctx, reader.client, endpoint.String(), func(data []byte) error {
		return controlplane.DecodeStrict(data, &transaction)
	}); err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read control transaction: %w", err)
	}
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ID != transactionID {
		return controlplane.Transaction{}, errors.New("read control transaction: response identity is invalid")
	}
	return transaction, nil
}

// GetRecords returns the strict audit record set for one transaction.
func (reader *AuditReader) GetRecords(ctx context.Context, transactionID string) ([]auditlog.Record, error) {
	if reader == nil || reader.client == nil || !transactionIDPattern.MatchString(transactionID) {
		return nil, errors.New("audit transaction ID is invalid")
	}
	endpoint := reader.baseURL
	endpoint.Path = "/api/v1/events"
	query := endpoint.Query()
	query.Set("transaction_id", transactionID)
	endpoint.RawQuery = query.Encode()
	response := struct {
		SchemaVersion string            `json:"schema_version"`
		Records       []auditlog.Record `json:"records"`
	}{}
	if err := getJSON(ctx, reader.client, endpoint.String(), func(data []byte) error {
		return auditlog.DecodeStrict(data, &response)
	}); err != nil {
		return nil, fmt.Errorf("read audit records: %w", err)
	}
	if response.SchemaVersion != auditlog.StoreSchemaVersion || response.Records == nil {
		return nil, errors.New("read audit records: response envelope is invalid")
	}
	for _, record := range response.Records {
		if record.Event.TransactionID != transactionID {
			return nil, errors.New("read audit records: response contains another transaction")
		}
	}
	return response.Records, nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, decode func([]byte) error) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("construct request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %s", response.Status)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		return errors.New("response Content-Type is not application/json")
	}
	if response.ContentLength > maxResponseBytes {
		return errors.New("response exceeds the fixed size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(data) == 0 || len(data) > maxResponseBytes {
		return errors.New("response has an invalid size")
	}
	if err := decode(data); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// cloneTLSConfig keeps the transport's configuration private and preserves the
// bridge's TLS 1.3 floor even if shared client defaults later change.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	clone := config.Clone()
	clone.MinVersion = tls.VersionTLS13
	return clone
}
