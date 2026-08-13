package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/api"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/identity"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/model"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

func testHandler(t *testing.T, allowNonGlobal bool) (*Handler, *store.SQLite) {
	t.Helper()
	return testHandlerWithClock(t, allowNonGlobal, func() time.Time {
		return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	})
}

func testHandlerWithClock(t *testing.T, allowNonGlobal bool, now func() time.Time) (*Handler, *store.SQLite) {
	t.Helper()
	database, err := store.OpenSQLite(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	handler, err := New(Config{
		Identity: identity.SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: "kaiba.network"},
		Store:    database, LeaseDuration: 24 * time.Hour, RenewAfter: 6 * time.Hour,
		AllowNonGlobalAddresses: allowNonGlobal,
		Now:                     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, database
}

func verifiedRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	identityURI, _ := url.Parse("spiffe://kaiba.network/device/001")
	leaf := &x509.Certificate{URIs: []*url.URL{identityURI}}
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if method == http.MethodPut {
		request.Header.Set("If-None-Match", "*")
	}
	return request
}

func TestPutEndpointsAndStatus(t *testing.T) {
	t.Parallel()
	handler, database := testHandler(t, true)
	body := `{"addresses":[{"family":"ipv6","address":"2001:db8::42"},{"family":"ipv4","address":"203.0.113.42"}]}`
	request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", body)
	request.Header.Set("Idempotency-Key", "update-001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("PUT returned %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"g-1"` {
		t.Fatalf("PUT ETag = %q, want \"g-1\"", response.Header().Get("ETag"))
	}
	var state api.DeviceState
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.DeviceID != "001" || state.Hostname != "pi-001.kaiba.network" || state.Status != model.StatusAccepted || state.Generation != 1 || state.RenewAfterSeconds != 21600 {
		t.Fatalf("unexpected response: %+v", state)
	}
	if len(state.Addresses) != 2 || state.Addresses[0].Family != "ipv4" {
		t.Fatalf("addresses are not canonical: %+v", state.Addresses)
	}
	if err := database.MarkOriginApplied(request.Context(), "001", 1); err != nil {
		t.Fatal(err)
	}
	statusRequest := verifiedRequest(t, http.MethodGet, "/v1/devices/self/status", "")
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	if statusResponse.Header().Get("ETag") != `"g-1"` {
		t.Fatalf("status ETag = %q, want \"g-1\"", statusResponse.Header().Get("ETag"))
	}
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != model.StatusOriginApplied {
		t.Fatalf("status = %s, want origin-applied", state.Status)
	}
}

func TestPutEndpointsIdempotency(t *testing.T) {
	t.Parallel()
	handler, database := testHandler(t, true)
	put := func(body string) *httptest.ResponseRecorder {
		request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", body)
		request.Header.Set("Idempotency-Key", "same-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := put(`{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`)
	if first.Code != http.StatusAccepted {
		t.Fatal(first.Body.String())
	}
	replay := put(`{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`)
	if replay.Code != http.StatusAccepted || replay.Body.String() != first.Body.String() {
		t.Fatalf("unexpected replay: %d %s", replay.Code, replay.Body.String())
	}
	reconfigured, err := New(Config{
		Identity: identity.SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: "kaiba.network"},
		Store:    database, LeaseDuration: 24 * time.Hour, RenewAfter: 3 * time.Hour,
		AllowNonGlobalAddresses: true,
		Now: func() time.Time {
			return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconfiguredRequest := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", `{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`)
	reconfiguredRequest.Header.Set("Idempotency-Key", "same-key")
	reconfiguredReplay := httptest.NewRecorder()
	reconfigured.ServeHTTP(reconfiguredReplay, reconfiguredRequest)
	if reconfiguredReplay.Code != http.StatusAccepted || reconfiguredReplay.Body.String() != first.Body.String() || reconfiguredReplay.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatalf("reconfigured replay changed original response: %d %q %s", reconfiguredReplay.Code, reconfiguredReplay.Header().Get("ETag"), reconfiguredReplay.Body.String())
	}
	conflict := put(`{"addresses":[{"family":"ipv4","address":"203.0.113.43"}]}`)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict returned %d: %s", conflict.Code, conflict.Body.String())
	}
	changedPrecondition := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", `{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`)
	changedPrecondition.Header.Set("Idempotency-Key", "same-key")
	changedPrecondition.Header.Del("If-None-Match")
	changedPrecondition.Header.Set("If-Match", `"g-1"`)
	changedPreconditionResponse := httptest.NewRecorder()
	handler.ServeHTTP(changedPreconditionResponse, changedPrecondition)
	if changedPreconditionResponse.Code != http.StatusConflict {
		t.Fatalf("changed precondition returned %d: %s", changedPreconditionResponse.Code, changedPreconditionResponse.Body.String())
	}
}

func TestWritePreconditionsRejectDistinctStaleRequest(t *testing.T) {
	t.Parallel()
	currentTime := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	handler, database := testHandlerWithClock(t, true, func() time.Time { return currentTime })
	put := func(key, precondition, address string) *httptest.ResponseRecorder {
		request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", fmt.Sprintf(`{"addresses":[{"family":"ipv4","address":%q}]}`, address))
		request.Header.Set("Idempotency-Key", key)
		request.Header.Del("If-None-Match")
		if precondition == "absent" {
			request.Header.Set("If-None-Match", "*")
		} else {
			request.Header.Set("If-Match", precondition)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := put("first", "absent", "203.0.113.41")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first update returned %d: %s", first.Code, first.Body.String())
	}
	second := put("second", `"g-1"`, "203.0.113.42")
	if second.Code != http.StatusAccepted || second.Header().Get("ETag") != `"g-2"` {
		t.Fatalf("second update returned %d ETag %q: %s", second.Code, second.Header().Get("ETag"), second.Body.String())
	}
	stale := put("distinct-stale", `"g-1"`, "203.0.113.43")
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale update returned %d: %s", stale.Code, stale.Body.String())
	}
	intent, err := database.GetIntent(t.Context(), "001")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Generation != 2 || len(intent.Addresses) != 1 || intent.Addresses[0].String() != "203.0.113.42" {
		t.Fatalf("stale update mutated desired state: %+v", intent)
	}
	if _, err := database.ExpireLeases(t.Context(), currentTime.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	currentTime = currentTime.Add(365 * 24 * time.Hour)
	replay := put("first", "absent", "203.0.113.41")
	if replay.Code != http.StatusAccepted || replay.Body.String() != first.Body.String() || replay.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatalf("old idempotent replay changed: %d %q %s", replay.Code, replay.Header().Get("ETag"), replay.Body.String())
	}
	intent, err = database.GetIntent(t.Context(), "001")
	if err != nil || intent.Generation != 3 || len(intent.Addresses) != 0 {
		t.Fatalf("arbitrarily late replay mutated current state: %+v, %v", intent, err)
	}
}

func TestWritePreconditionHeaderValidation(t *testing.T) {
	t.Parallel()
	handler, _ := testHandler(t, true)
	body := `{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`
	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{name: "missing", mutate: func(request *http.Request) { request.Header.Del("If-None-Match") }, want: http.StatusPreconditionRequired},
		{name: "both", mutate: func(request *http.Request) { request.Header.Set("If-Match", `"g-1"`) }, want: http.StatusPreconditionRequired},
		{name: "malformed match", mutate: func(request *http.Request) {
			request.Header.Del("If-None-Match")
			request.Header.Set("If-Match", `W/"g-1"`)
		}, want: http.StatusBadRequest},
		{name: "malformed none match", mutate: func(request *http.Request) { request.Header.Set("If-None-Match", `"g-1"`) }, want: http.StatusBadRequest},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", body)
			request.Header.Set("Idempotency-Key", fmt.Sprintf("precondition-%d", index))
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("got %d (%s), want %d", response.Code, response.Body.String(), test.want)
			}
		})
	}
}

func TestPutEndpointsRejectsUnauthorizedInput(t *testing.T) {
	t.Parallel()
	handler, _ := testHandler(t, true)
	validBody := `{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`
	tests := []struct {
		name       string
		body       string
		key        string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing idempotency key", body: validBody, wantStatus: http.StatusBadRequest},
		{name: "unknown hostname field", body: `{"hostname":"victim.kaiba.network","addresses":[{"family":"ipv4","address":"203.0.113.42"}]}`, key: "key", wantStatus: http.StatusBadRequest},
		{name: "unknown record type", body: `{"addresses":[{"family":"TXT","address":"203.0.113.42"}]}`, key: "key", wantStatus: http.StatusBadRequest},
		{name: "mismatched family", body: `{"addresses":[{"family":"ipv6","address":"203.0.113.42"}]}`, key: "key", wantStatus: http.StatusBadRequest},
		{name: "duplicate", body: `{"addresses":[{"family":"ipv4","address":"203.0.113.42"},{"family":"ipv4","address":"203.0.113.42"}]}`, key: "key", wantStatus: http.StatusBadRequest},
		{name: "empty set", body: `{"addresses":[]}`, key: "key", wantStatus: http.StatusBadRequest},
		{name: "unverified certificate", body: validBody, key: "key", mutate: func(request *http.Request) { request.TLS.VerifiedChains = nil }, wantStatus: http.StatusUnauthorized},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", test.body)
			request.Header.Set("Idempotency-Key", fmt.Sprintf("%s-%d", test.key, index))
			if test.key == "" {
				request.Header.Del("Idempotency-Key")
			}
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("got %d (%s), want %d", response.Code, response.Body.String(), test.wantStatus)
			}
		})
	}
}

func TestProductionAddressPolicyRequiresPublicAddress(t *testing.T) {
	t.Parallel()
	handler, _ := testHandler(t, false)
	for _, value := range []string{"10.0.0.1", "203.0.113.42", "2001:db8::42"} {
		family := "ipv4"
		if strings.Contains(value, ":") {
			family = "ipv6"
		}
		request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", fmt.Sprintf(`{"addresses":[{"family":%q,"address":%q}]}`, family, value))
		request.Header.Set("Idempotency-Key", "reject-"+strings.ReplaceAll(value, ":", "-"))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d: %s", value, response.Code, response.Body.String())
		}
	}
	request := verifiedRequest(t, http.MethodPut, "/v1/devices/self/endpoints", `{"addresses":[{"family":"ipv4","address":"8.8.8.8"}]}`)
	request.Header.Set("Idempotency-Key", "accept-public")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("public address returned %d: %s", response.Code, response.Body.String())
	}
}
