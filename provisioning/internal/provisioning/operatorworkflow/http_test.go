package operatorworkflow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

func TestParseAuthorityOriginAcceptsOnlyAnHTTPSOrigin(t *testing.T) {
	accepted, err := parseAuthorityOrigin("https://control.example.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	if accepted.String() != "https://control.example.test:8443" {
		t.Fatalf("origin = %q", accepted.String())
	}
	for _, value := range []string{
		"", " https://control.example.test", "http://control.example.test", "https://",
		"https://user@control.example.test", "https://control.example.test/api",
		"https://control.example.test?query=1", "https://control.example.test/#fragment",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseAuthorityOrigin(value); err == nil {
				t.Fatalf("accepted unsafe origin %q", value)
			}
		})
	}
}

func TestAuthorityResponseUsesBoundedStrictJSON(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantError   bool
	}{
		{name: "valid", status: http.StatusOK, contentType: "application/json; charset=utf-8", body: `{"value":"ok"}`},
		{name: "duplicate", status: http.StatusOK, contentType: "application/json", body: `{"value":"one","value":"two"}`, wantError: true},
		{name: "unknown", status: http.StatusOK, contentType: "application/json", body: `{"value":"ok","extra":true}`, wantError: true},
		{name: "trailing", status: http.StatusOK, contentType: "application/json", body: `{"value":"ok"}{}`, wantError: true},
		{name: "wrong media", status: http.StatusOK, contentType: "text/plain", body: `{"value":"ok"}`, wantError: true},
		{name: "wrong status", status: http.StatusForbidden, contentType: "application/json", body: `{"value":"ok"}`, wantError: true},
		{name: "empty", status: http.StatusOK, contentType: "application/json", body: "", wantError: true},
		{name: "oversize", status: http.StatusOK, contentType: "application/json", body: strings.Repeat(" ", authorityResponseLimit+1), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Header:     http.Header{"Content-Type": []string{test.contentType}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://control.example.test/api", nil)
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Value string `json:"value"`
			}
			err = doAuthorityJSON(client, request, http.StatusOK, &response)
			if (err != nil) != test.wantError {
				t.Fatalf("doAuthorityJSON() error = %v", err)
			}
			if err == nil && response.Value != "ok" {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestControlCommandValidatesReturnedTransactionIdentity(t *testing.T) {
	tests := []struct {
		name        string
		transaction controlplane.Transaction
		wantError   bool
	}{
		{
			name: "valid",
			transaction: controlplane.Transaction{
				SchemaVersion: controlplane.TransactionSchemaVersion, ID: "transaction-1", ResourceVersion: 1,
			},
		},
		{
			name: "wrong schema", wantError: true,
			transaction: controlplane.Transaction{SchemaVersion: "wrong", ID: "transaction-1", ResourceVersion: 1},
		},
		{
			name: "wrong transaction", wantError: true,
			transaction: controlplane.Transaction{
				SchemaVersion: controlplane.TransactionSchemaVersion, ID: "transaction-2", ResourceVersion: 1,
			},
		},
		{
			name: "zero resource version", wantError: true,
			transaction: controlplane.Transaction{SchemaVersion: controlplane.TransactionSchemaVersion, ID: "transaction-1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.transaction)
			if err != nil {
				t.Fatal(err)
			}
			httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
					Body: io.NopCloser(strings.NewReader(string(body))),
				}, nil
			})}
			client := &HTTPControlClient{
				client: httpClient, origin: url.URL{Scheme: "https", Host: "control.example.test"},
			}
			_, err = client.CreateTransaction(context.Background(), controlplane.CreateTransactionRequest{TransactionID: "transaction-1"})
			if (err != nil) != test.wantError {
				t.Fatalf("CreateTransaction() error = %v", err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
