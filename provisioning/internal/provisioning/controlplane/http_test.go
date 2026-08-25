package controlplane

import (
	"bytes"
	"context"
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

func TestMutualTLSHandlerBindsAcquireClaimStationAndLane(t *testing.T) {
	tests := []struct {
		name         string
		identityURIs []string
		wantStatus   int
		wantClaim    bool
	}{
		{
			name:         "matching",
			identityURIs: []string{"spiffe://kaiba.network/station/station-1/lane/lane-1"},
			wantStatus:   http.StatusOK,
			wantClaim:    true,
		},
		{
			name:       "missing URI SAN",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:         "mismatched station",
			identityURIs: []string{"spiffe://kaiba.network/station/station-2/lane/lane-1"},
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "approver identity",
			identityURIs: []string{"spiffe://kaiba.network/approver/approver-1"},
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name: "ambiguous URI SANs",
			identityURIs: []string{
				"spiffe://kaiba.network/station/station-1/lane/lane-1",
				"spiffe://kaiba.network/station/station-1/lane/lane-2",
			},
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t, &MemoryStore{})
			transaction := fixture.create()
			claim := AcquireClaimRequest{
				SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-http-1",
				TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
				StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
				AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
			}
			request := controlCommandRequest(t, "acquire_claim", claim)
			request.TLS = controlVerifiedTLSState(t, "station-1/lane-1", test.identityURIs...)
			response := httptest.NewRecorder()

			Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			stored, err := fixture.service.GetTransaction(request.Context(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if (stored.ActiveClaim != nil) != test.wantClaim {
				t.Fatalf("active claim = %#v, want present=%t", stored.ActiveClaim, test.wantClaim)
			}
		})
	}
}

func TestMutualTLSControlReadRemainsScopedAfterClaimRelease(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	neverClaimed, err := fixture.service.CreateTransaction(context.Background(), CreateTransactionRequest{
		SchemaVersion: CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-never-claimed",
		TransactionID: "transaction-never-claimed", AssetID: "asset-never-claimed", IntendedLogicalID: "device-never-claimed",
		ProfileID: "rpi5-v1", BundleDigest: digest("0"), PolicyDigest: digest("1"),
		ExpectedPrestateCustomerKeyHash: UnownedCustomerKeyHash, ExpectedCustomerKeyHash: digest("2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction := fixture.create()
	transaction, err = fixture.service.AcquireClaim(context.Background(), AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-read-owner",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = fixture.service.AbortTransaction(context.Background(), AbortRequest{
		SchemaVersion: AbortRequestSchemaVersion, IdempotencyKey: "abort-read-owner",
		MutationContext: contextFor(transaction), ReusableBaselineDigest: digest("a"), AuditReceiptID: digest("b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = fixture.service.ReleaseClaim(context.Background(), ReleaseClaimRequest{
		SchemaVersion: ReleaseClaimRequestSchemaVersion, IdempotencyKey: "release-read-owner",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		transactionID string
		identity      string
		want          int
	}{
		{name: "latest historical claimant", transactionID: transaction.ID, identity: "spiffe://kaiba.network/station/station-1/lane/lane-1", want: http.StatusOK},
		{name: "other station after release", transactionID: transaction.ID, identity: "spiffe://kaiba.network/station/station-2/lane/lane-2", want: http.StatusForbidden},
		{name: "never-claimed transaction", transactionID: neverClaimed.ID, identity: "spiffe://kaiba.network/station/station-1/lane/lane-1", want: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/transactions/"+test.transactionID, nil)
			request.TLS = controlVerifiedTLSState(t, "ignored", test.identity)
			response := httptest.NewRecorder()
			Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestMutualTLSHandlerRequiresIndependentApproverForRecordApproval(t *testing.T) {
	tests := []struct {
		name         string
		identityURIs []string
		wantStatus   int
		wantApproval bool
	}{
		{
			name:         "matching approver",
			identityURIs: []string{"spiffe://kaiba.network/approver/approver-1"},
			wantStatus:   http.StatusOK,
			wantApproval: true,
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
			fixture := newTestFixture(t, &MemoryStore{})
			operations := developmentCampaignNames()
			transaction := fixture.createClaimBind(operations)
			request := controlCommandRequest(t, "record_approval", fixture.approvalRequest(transaction, operations, "approval-1"))
			request.TLS = controlVerifiedTLSState(t, "ignored", test.identityURIs...)
			response := httptest.NewRecorder()

			Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			stored, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
			if err != nil {
				t.Fatal(err)
			}
			if (stored.Approval != nil) != test.wantApproval {
				t.Fatalf("stored approval = %#v, want present=%t", stored.Approval, test.wantApproval)
			}
		})
	}
}

func TestMutualTLSHandlerBindsClaimScopedRequestsAndTransferHandoff(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.create()
	var err error
	transaction, err = fixture.service.AcquireClaim(context.Background(), AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-direct-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	renew := RenewClaimRequest{
		SchemaVersion: RenewClaimRequestSchemaVersion, IdempotencyKey: "renew-http-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch, LeaseDurationSeconds: 300,
	}
	renewRequest := controlCommandRequest(t, "renew_claim", renew)
	renewRequest.TLS = controlVerifiedTLSState(t, "ignored", "spiffe://kaiba.network/station/station-2/lane/lane-2")
	renewResponse := httptest.NewRecorder()
	Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(renewResponse, renewRequest)
	if renewResponse.Code != http.StatusForbidden {
		t.Fatalf("mismatched claim renewal status = %d; body=%s", renewResponse.Code, renewResponse.Body.String())
	}

	transfer := TransferClaimRequest{
		SchemaVersion: TransferClaimRequestSchemaVersion, IdempotencyKey: "transfer-http-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
		NewStationID: "station-2", NewLaneID: "lane-2", Mode: ClaimModeMutation,
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
	}
	transferRequest := controlCommandRequest(t, "transfer_claim", transfer)
	transferRequest.TLS = controlVerifiedTLSState(t, "ignored", "spiffe://kaiba.network/station/station-1/lane/lane-1")
	transferResponse := httptest.NewRecorder()
	Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(transferResponse, transferRequest)
	if transferResponse.Code != http.StatusOK {
		t.Fatalf("current claimant transfer status = %d; body=%s", transferResponse.Code, transferResponse.Body.String())
	}

	transferred, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.ResourceVersion != transaction.ResourceVersion+1 ||
		transferred.FenceEpoch != transaction.FenceEpoch+1 ||
		transferred.ActiveClaim.StationID != "station-2" || transferred.ActiveClaim.LaneID != "lane-2" {
		t.Fatalf("transferred transaction = %#v", transferred)
	}

	renewAfterTransfer := RenewClaimRequest{
		SchemaVersion: RenewClaimRequestSchemaVersion, IdempotencyKey: "renew-after-transfer",
		TransactionID: transferred.ID, ExpectedResourceVersion: transferred.ResourceVersion,
		ClaimID: transferred.ActiveClaim.ID, FenceEpoch: transferred.FenceEpoch, LeaseDurationSeconds: 300,
	}
	oldIdentityRequest := controlCommandRequest(t, "renew_claim", renewAfterTransfer)
	oldIdentityRequest.TLS = controlVerifiedTLSState(t, "ignored", "spiffe://kaiba.network/station/station-1/lane/lane-1")
	oldIdentityResponse := httptest.NewRecorder()
	Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(oldIdentityResponse, oldIdentityRequest)
	if oldIdentityResponse.Code != http.StatusForbidden {
		t.Fatalf("old claimant after transfer status = %d; body=%s", oldIdentityResponse.Code, oldIdentityResponse.Body.String())
	}

	newIdentityRequest := controlCommandRequest(t, "renew_claim", renewAfterTransfer)
	newIdentityRequest.TLS = controlVerifiedTLSState(t, "ignored", "spiffe://kaiba.network/station/station-2/lane/lane-2")
	newIdentityResponse := httptest.NewRecorder()
	Handler(fixture.service, mtls.MutualTLSIdentityPolicy()).ServeHTTP(newIdentityResponse, newIdentityRequest)
	if newIdentityResponse.Code != http.StatusOK {
		t.Fatalf("new claimant after transfer status = %d; body=%s", newIdentityResponse.Code, newIdentityResponse.Body.String())
	}

	renewed, err := fixture.service.GetTransaction(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ResourceVersion != transferred.ResourceVersion+1 || renewed.ActiveClaim.StationID != "station-2" || renewed.ActiveClaim.LaneID != "lane-2" {
		t.Fatalf("new claimant renewal = %#v", renewed)
	}
}

func TestLoopbackPlaintextControlHandlerPreservesDevelopmentMode(t *testing.T) {
	fixture := newTestFixture(t, &MemoryStore{})
	transaction := fixture.create()
	request := controlCommandRequest(t, "acquire_claim", AcquireClaimRequest{
		SchemaVersion: AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-http-1",
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: "station-1", LaneID: "lane-1", Mode: ClaimModeMutation,
		AllowedStages: developmentCampaignNames(), LeaseDurationSeconds: 300,
	})
	response := httptest.NewRecorder()

	Handler(fixture.service, mtls.LoopbackPlaintextIdentityPolicy()).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
}

func controlCommandRequest(t *testing.T, operation string, commandRequest any) *http.Request {
	t.Helper()
	encodedRequest, err := json.Marshal(commandRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(Command{
		SchemaVersion: CommandSchemaVersion,
		Operation:     operation,
		Request:       encodedRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/commands", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func controlVerifiedTLSState(t *testing.T, commonName string, identityURIs ...string) *tls.ConnectionState {
	t.Helper()
	certificate := &x509.Certificate{Raw: []byte("control-client-leaf"), Subject: pkix.Name{CommonName: commonName}}
	for _, rawURI := range identityURIs {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatal(err)
		}
		certificate.URIs = append(certificate.URIs, parsed)
	}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}
