package operatorworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

const authorityResponseLimit = 1 << 20

// HTTPControlClient is the narrow typed writer used by the operator CLI. Its
// methods correspond to explicit workflow transitions; it exposes no raw
// command method to callers.
type HTTPControlClient struct {
	client *http.Client
	origin url.URL
}

// HTTPAuditClient appends only typed audit events.
type HTTPAuditClient struct {
	client *http.Client
	origin url.URL
}

func NewHTTPControlClient(origin string, files mtls.ClientFiles) (*HTTPControlClient, error) {
	client, parsed, err := newAuthorityHTTPClient(origin, files)
	if err != nil {
		return nil, err
	}
	return &HTTPControlClient{client: client, origin: parsed}, nil
}

func NewHTTPAuditClient(origin string, files mtls.ClientFiles) (*HTTPAuditClient, error) {
	client, parsed, err := newAuthorityHTTPClient(origin, files)
	if err != nil {
		return nil, err
	}
	return &HTTPAuditClient{client: client, origin: parsed}, nil
}

func newAuthorityHTTPClient(rawOrigin string, files mtls.ClientFiles) (*http.Client, url.URL, error) {
	parsed, err := parseAuthorityOrigin(rawOrigin)
	if err != nil {
		return nil, url.URL{}, err
	}
	tlsConfig, err := mtls.LoadClientConfig(files)
	if err != nil {
		return nil, url.URL{}, fmt.Errorf("configure authority mutual TLS: %w", err)
	}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 16 * 1024, DisableCompression: true,
		TLSClientConfig: tlsConfig.Clone(),
	}
	return &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, parsed, nil
}

func parseAuthorityOrigin(raw string) (url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return url.URL{}, errors.New("authority URL is required without surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return url.URL{}, fmt.Errorf("parse authority URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return url.URL{}, errors.New("authority URL must be an HTTPS origin without credentials, path, query, or fragment")
	}
	return url.URL{Scheme: "https", Host: parsed.Host}, nil
}

func (client *HTTPControlClient) GetTransaction(ctx context.Context, transactionID string) (controlplane.Transaction, error) {
	if client == nil || client.client == nil || !identifierPattern.MatchString(transactionID) {
		return controlplane.Transaction{}, errors.New("control transaction ID is invalid")
	}
	endpoint := client.origin
	endpoint.Path = "/api/v1/transactions/" + transactionID
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return controlplane.Transaction{}, err
	}
	var transaction controlplane.Transaction
	if err := doAuthorityJSON(client.client, request, http.StatusOK, &transaction); err != nil {
		return controlplane.Transaction{}, fmt.Errorf("read control transaction: %w", err)
	}
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion || transaction.ID != transactionID {
		return controlplane.Transaction{}, errors.New("control transaction response identity is invalid")
	}
	return transaction, nil
}

func (client *HTTPControlClient) CreateTransaction(ctx context.Context, request controlplane.CreateTransactionRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "create_transaction", request.TransactionID, request)
}

func (client *HTTPControlClient) AcquireClaim(ctx context.Context, request controlplane.AcquireClaimRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "acquire_claim", request.TransactionID, request)
}

func (client *HTTPControlClient) RenewClaim(ctx context.Context, request controlplane.RenewClaimRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "renew_claim", request.TransactionID, request)
}

func (client *HTTPControlClient) TransferClaim(ctx context.Context, request controlplane.TransferClaimRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "transfer_claim", request.TransactionID, request)
}

func (client *HTTPControlClient) BindTarget(ctx context.Context, request controlplane.BindTargetRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "bind_target", request.TransactionID, request)
}

func (client *HTTPControlClient) RecordApproval(ctx context.Context, request controlplane.RecordApprovalRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "record_approval", request.TransactionID, request)
}

func (client *HTTPControlClient) RecordIntent(ctx context.Context, request controlplane.RecordIntentRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "record_intent", request.TransactionID, request)
}

func (client *HTTPControlClient) RecordEvidence(ctx context.Context, request controlplane.RecordEvidenceRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "record_evidence", request.TransactionID, request)
}

func (client *HTTPControlClient) MarkSecurityApplied(ctx context.Context, request controlplane.SecurityAppliedRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "mark_security_applied", request.TransactionID, request)
}

func (client *HTTPControlClient) RecordReconciliation(ctx context.Context, request controlplane.RecordReconciliationRequest) (controlplane.Transaction, error) {
	return client.command(ctx, "record_reconciliation", request.TransactionID, request)
}

func (client *HTTPControlClient) command(ctx context.Context, operation, transactionID string, value any) (controlplane.Transaction, error) {
	if client == nil || client.client == nil {
		return controlplane.Transaction{}, errors.New("control client is unavailable")
	}
	if !identifierPattern.MatchString(transactionID) {
		return controlplane.Transaction{}, errors.New("control transaction ID is invalid")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("encode typed control request: %w", err)
	}
	body, err := json.Marshal(controlplane.Command{
		SchemaVersion: controlplane.CommandSchemaVersion, Operation: operation, Request: raw,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("encode control command envelope: %w", err)
	}
	endpoint := client.origin
	endpoint.Path = "/api/v1/commands"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return controlplane.Transaction{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	var transaction controlplane.Transaction
	if err := doAuthorityJSON(client.client, httpRequest, http.StatusOK, &transaction); err != nil {
		return controlplane.Transaction{}, err
	}
	if transaction.SchemaVersion != controlplane.TransactionSchemaVersion ||
		transaction.ID != transactionID || transaction.ResourceVersion == 0 {
		return controlplane.Transaction{}, errors.New("control transaction response identity is invalid")
	}
	return transaction, nil
}

func (client *HTTPAuditClient) Append(ctx context.Context, appendRequest auditlog.AppendRequest) (auditlog.Receipt, error) {
	if client == nil || client.client == nil {
		return auditlog.Receipt{}, errors.New("audit client is unavailable")
	}
	body, err := json.Marshal(appendRequest)
	if err != nil {
		return auditlog.Receipt{}, fmt.Errorf("encode typed audit append: %w", err)
	}
	endpoint := client.origin
	endpoint.Path = "/api/v1/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return auditlog.Receipt{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	var receipt auditlog.Receipt
	if err := doAuthorityJSON(client.client, request, http.StatusCreated, &receipt); err != nil {
		return auditlog.Receipt{}, err
	}
	if receipt.SchemaVersion != auditlog.ReceiptSchemaVersion || !digestPattern.MatchString(receipt.ReceiptID) {
		return auditlog.Receipt{}, errors.New("audit receipt response identity is invalid")
	}
	return receipt, nil
}

func doAuthorityJSON(client *http.Client, request *http.Request, expectedStatus int, target any) error {
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	reader := io.LimitReader(response.Body, authorityResponseLimit+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > authorityResponseLimit {
		return errors.New("authority response has invalid size")
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("authority returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("authority response is not application/json")
	}
	if err := controlplane.DecodeStrict(body, target); err != nil {
		return fmt.Errorf("decode authority response: %w", err)
	}
	return nil
}
