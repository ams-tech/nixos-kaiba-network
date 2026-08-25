package auditlog

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func TestMutualTLSHandlerBindsAuditEventStationAndLane(t *testing.T) {
	tests := []struct {
		name         string
		identityURIs []string
		wantStatus   int
		wantRecords  int
	}{
		{
			name:         "matching",
			identityURIs: []string{"spiffe://kaiba.network/station/station-1/lane/lane-1"},
			wantStatus:   http.StatusCreated,
			wantRecords:  1,
		},
		{
			name:        "missing URI SAN",
			wantStatus:  http.StatusUnauthorized,
			wantRecords: 0,
		},
		{
			name:         "mismatched lane",
			identityURIs: []string{"spiffe://kaiba.network/station/station-1/lane/lane-2"},
			wantStatus:   http.StatusForbidden,
			wantRecords:  0,
		},
		{
			name:         "approver identity",
			identityURIs: []string{"spiffe://kaiba.network/approver/approver-1"},
			wantStatus:   http.StatusUnauthorized,
			wantRecords:  0,
		},
		{
			name: "ambiguous URI SANs",
			identityURIs: []string{
				"spiffe://kaiba.network/station/station-1/lane/lane-1",
				"spiffe://kaiba.network/station/station-1/lane/lane-2",
			},
			wantStatus:  http.StatusUnauthorized,
			wantRecords: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(testAppendRequest("event-1", "idem-1", ResultIntentRecorded))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.TLS = auditVerifiedTLSState(t, "station-1/lane-1", test.identityURIs...)
			response := httptest.NewRecorder()

			Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if got := len(service.Records("")); got != test.wantRecords {
				t.Fatalf("stored records = %d, want %d", got, test.wantRecords)
			}
		})
	}
}

func TestMutualTLSHandlerRequiresIndependentApproverForPlanApproval(t *testing.T) {
	tests := []struct {
		name         string
		identityURIs []string
		wantStatus   int
		wantRecords  int
	}{
		{
			name:         "matching approver",
			identityURIs: []string{"spiffe://kaiba.network/approver/approver-1"},
			wantStatus:   http.StatusCreated,
			wantRecords:  1,
		},
		{
			name:         "station claimant cannot approve",
			identityURIs: []string{"spiffe://kaiba.network/station/station-1/lane/lane-1"},
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "different approver cannot approve",
			identityURIs: []string{"spiffe://kaiba.network/approver/approver-2"},
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "missing approver URI SAN",
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
			if err != nil {
				t.Fatal(err)
			}
			appendRequest := testAppendRequest("approval-1", "approval-idem-1", ResultIntentRecorded)
			appendRequest.Event.Stage = "plan_approval"
			appendRequest.Event.Actors = []Actor{{ID: "approver-1", Role: "approver"}}
			body, err := json.Marshal(appendRequest)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.TLS = auditVerifiedTLSState(t, "ignored", test.identityURIs...)
			response := httptest.NewRecorder()

			Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if got := len(service.Records("")); got != test.wantRecords {
				t.Fatalf("stored records = %d, want %d", got, test.wantRecords)
			}
		})
	}
}

func TestPlanApprovalRequiresExactlyOneApproverActor(t *testing.T) {
	service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	appendRequest := testAppendRequest("approval-1", "approval-idem-1", ResultIntentRecorded)
	appendRequest.Event.Stage = "plan_approval"
	appendRequest.Event.Actors = []Actor{
		{ID: "approver-1", Role: "approver"},
		{ID: "station-1", Role: "provisioning_station"},
	}
	body, err := json.Marshal(appendRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = auditVerifiedTLSState(t, "ignored", "spiffe://kaiba.network/approver/approver-1")
	response := httptest.NewRecorder()

	Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if got := len(service.Records("")); got != 0 {
		t.Fatalf("stored records = %d, want 0", got)
	}
}

func TestLoopbackPlaintextAuditHandlerPreservesDevelopmentMode(t *testing.T) {
	service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(testAppendRequest("event-1", "idem-1", ResultIntentRecorded))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/events", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	Handler(service, mtls.LoopbackPlaintextIdentityPolicy()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
}

func TestMutualTLSExactReceiptReadDoesNotGrantTransactionWideVisibility(t *testing.T) {
	service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	first := testAppendRequest("event-1", "idem-1", ResultIntentRecorded)
	first.Event.TransactionID = "transaction-1"
	first.Event.StationID = "station-1"
	first.Event.LaneID = "lane-1"
	firstReceipt, err := service.Append(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := testAppendRequest("event-2", "idem-2", ResultIntentRecorded)
	second.Event.TransactionID = "transaction-1"
	second.Event.StationID = "station-1"
	second.Event.LaneID = "lane-1"
	if _, err := service.Append(t.Context(), second); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/events?transaction_id=transaction-1&receipt_id="+url.QueryEscape(firstReceipt.ReceiptID), nil)
	request.TLS = auditVerifiedTLSState(t, "station-2/lane-2", "spiffe://kaiba.network/station/station-2/lane/lane-2")
	response := httptest.NewRecorder()
	Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion string   `json:"schema_version"`
		Records       []Record `json:"records"`
	}
	if err := DecodeStrict(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Records) != 1 || envelope.Records[0].Event.EventID != "event-1" {
		t.Fatalf("exact records = %#v", envelope.Records)
	}

	broad := httptest.NewRequest(http.MethodGet, "/api/v1/events?transaction_id=transaction-1", nil)
	broad.TLS = request.TLS
	broadResponse := httptest.NewRecorder()
	Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(broadResponse, broad)
	if err := DecodeStrict(broadResponse.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Records) != 0 {
		t.Fatalf("cross-lane broad read exposed %d records", len(envelope.Records))
	}

	missingTransaction := httptest.NewRequest(http.MethodGet,
		"/api/v1/events?receipt_id="+url.QueryEscape(firstReceipt.ReceiptID), nil)
	missingTransaction.TLS = request.TLS
	missingTransactionResponse := httptest.NewRecorder()
	Handler(service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(missingTransactionResponse, missingTransaction)
	if missingTransactionResponse.Code != http.StatusBadRequest {
		t.Fatalf("unscoped exact read status = %d, want %d; body=%s",
			missingTransactionResponse.Code, http.StatusBadRequest, missingTransactionResponse.Body.String())
	}
}

func auditVerifiedTLSState(t *testing.T, commonName string, identityURIs ...string) *tls.ConnectionState {
	t.Helper()
	certificate := &x509.Certificate{Raw: []byte("audit-client-leaf"), Subject: pkix.Name{CommonName: commonName}}
	for _, rawURI := range identityURIs {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatal(err)
		}
		certificate.URIs = append(certificate.URIs, parsed)
	}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}
