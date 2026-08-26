package operatorworkflow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
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

func TestHTTPControlClientMarkSecurityAppliedUsesFixedTypedOperation(t *testing.T) {
	want := controlplane.SecurityAppliedRequest{
		SchemaVersion:  controlplane.SecurityAppliedRequestSchemaVersion,
		IdempotencyKey: "security-applied-1",
		MutationContext: controlplane.MutationContext{
			TransactionID: "transaction-1", ExpectedResourceVersion: 7,
			ClaimID: "claim-1", FenceEpoch: 3,
		},
		PlanDigest:     "sha256:" + strings.Repeat("a", 64),
		EvidenceDigest: "sha256:" + strings.Repeat("b", 64),
		AuditReceiptID: "sha256:" + strings.Repeat("c", 64),
		RollbackStatus: "rollback_unimplemented", ReleaseClassification: "development_asset",
	}
	responseBody, err := json.Marshal(controlplane.Transaction{
		SchemaVersion: controlplane.TransactionSchemaVersion, ID: want.TransactionID, ResourceVersion: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var command controlplane.Command
		if err := json.NewDecoder(request.Body).Decode(&command); err != nil {
			t.Fatal(err)
		}
		if command.SchemaVersion != controlplane.CommandSchemaVersion || command.Operation != "mark_security_applied" {
			t.Fatalf("control command = %#v", command)
		}
		var got controlplane.SecurityAppliedRequest
		if err := controlplane.DecodeStrict(command.Request, &got); err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != want.SchemaVersion || got.IdempotencyKey != want.IdempotencyKey ||
			got.MutationContext != want.MutationContext || got.PlanDigest != want.PlanDigest ||
			got.EvidenceDigest != want.EvidenceDigest || got.AuditReceiptID != want.AuditReceiptID ||
			got.RollbackStatus != want.RollbackStatus || got.ReleaseClassification != want.ReleaseClassification {
			t.Fatalf("typed security-applied request = %#v, want %#v", got, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(string(responseBody))),
		}, nil
	})}
	client := &HTTPControlClient{
		client: httpClient, origin: url.URL{Scheme: "https", Host: "control.example.test"},
	}
	if _, err := client.MarkSecurityApplied(context.Background(), want); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPControlClientApprovalPreflightUsesFixedTypedOperation(t *testing.T) {
	want := controlplane.ApprovalPreflightRequest{
		SchemaVersion: controlplane.ApprovalPreflightRequestSchemaVersion,
		MutationContext: controlplane.MutationContext{
			TransactionID: "transaction-1", ExpectedResourceVersion: 3,
			ClaimID: "claim-1", FenceEpoch: 2,
		},
		ApprovalID: "approval-1", ApproverID: "approver-1",
		TransactionDigest: testDigest("a"), PlanDigest: testDigest("b"),
		StationID: "station-1", LaneID: "lane-1", TargetFingerprint: testDigest("c"),
		Release: releasebinding.Binding{
			SignedReleaseManifestDigest: testDigest("d"), LaneGuardPackageDigest: testDigest("e"),
			CompiledArtifactSetDigest: testDigest("f"), ExpectedCustomerKeyHash: testDigest("1"),
			ExpectedEEPROMDigest: testDigest("2"), ExpectedBootImageDigest: testDigest("3"),
		},
		AllowedOperations: []string{"stage-1", "stage-2"},
		ApprovedAt:        time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		ExpiresAt:         time.Date(2026, 8, 15, 12, 30, 0, 0, time.UTC),
	}
	responseBody, err := json.Marshal(controlplane.Transaction{
		SchemaVersion: controlplane.TransactionSchemaVersion, ID: want.TransactionID, ResourceVersion: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var command controlplane.Command
		if err := json.NewDecoder(request.Body).Decode(&command); err != nil {
			t.Fatal(err)
		}
		if command.SchemaVersion != controlplane.CommandSchemaVersion || command.Operation != "preflight_approval" {
			t.Fatalf("control command = %#v", command)
		}
		var got controlplane.ApprovalPreflightRequest
		if err := controlplane.DecodeStrict(command.Request, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("typed approval preflight = %#v, want %#v", got, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(string(responseBody))),
		}, nil
	})}
	client := &HTTPControlClient{
		client: httpClient, origin: url.URL{Scheme: "https", Host: "control.example.test"},
	}
	if _, err := client.PreflightApproval(context.Background(), want); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
