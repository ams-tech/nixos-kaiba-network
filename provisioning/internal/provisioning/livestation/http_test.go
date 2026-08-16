package livestation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testHost = "127.0.0.1:8081"

type stubOrchestrator struct {
	state State
	err   error
	calls int
}

func (stub *stubOrchestrator) Current(context.Context) (State, error) { return stub.state, stub.err }

func (stub *stubOrchestrator) Apply(_ context.Context, request ActionRequest) (State, error) {
	stub.calls++
	if stub.err != nil {
		return stub.state, stub.err
	}
	stub.state.Revision = request.ExpectedRevision + 1
	return stub.state, nil
}

func TestHTTPHandlerServesAuthoritativeStateAndActions(t *testing.T) {
	stub := &stubOrchestrator{state: State{SchemaVersion: StateSchemaVersion, Revision: 4, Simulation: false}}
	handler, err := NewHandler(stub, testHost)
	if err != nil {
		t.Fatal(err)
	}
	response := doRequest(handler, http.MethodGet, "/api/v1/state", "", "", "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("state response = %d, headers %#v", response.Code, response.Header())
	}
	var state State
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.Revision != 4 || state.Simulation {
		t.Fatalf("state body = %#v, %v", state, err)
	}

	response = doRequest(handler, http.MethodPost, "/api/v1/actions", `{"action":"run_station_admission","expected_revision":4}`, "http://"+testHost, "application/json")
	if response.Code != http.StatusOK || stub.calls != 1 {
		t.Fatalf("action response = %d, calls %d, body %s", response.Code, stub.calls, response.Body.String())
	}
}

func TestHTTPHandlerServesOnlyTheLiveKioskAssetsAndRuntimeContract(t *testing.T) {
	stub := &stubOrchestrator{state: State{SchemaVersion: StateSchemaVersion, Revision: 1}}
	handler, err := NewHandler(stub, testHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path        string
		contentType string
		contains    string
	}{
		{"/", "text/html; charset=utf-8", "Kaiba Live Provisioning"},
		{"/app.js", "text/javascript; charset=utf-8", StateSchemaVersion},
		{"/styles.css", "text/css; charset=utf-8", ".action-card.irreversible"},
	} {
		response := doRequest(handler, http.MethodGet, test.path, "", "", "")
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != test.contentType || !strings.Contains(response.Body.String(), test.contains) {
			t.Fatalf("asset %s = %d, %q, body %q", test.path, response.Code, response.Header().Get("Content-Type"), response.Body.String())
		}
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") || response.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
			t.Fatalf("asset %s security headers = %#v", test.path, response.Header())
		}
	}
	if strings.Contains(string(mustAsset(t, "app.js")), "happy-path") || strings.Contains(string(mustAsset(t, "index.html")), "scenario") {
		t.Fatal("live kiosk contains simulation scenario logic")
	}

	runtimeResponse := doRequest(handler, http.MethodGet, "/runtime-config.json", "", "", "")
	if runtimeResponse.Code != http.StatusOK || runtimeResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("runtime response = %d, %q, %s", runtimeResponse.Code, runtimeResponse.Header().Get("Content-Type"), runtimeResponse.Body.String())
	}
	var runtime runtimeConfig
	if err := json.Unmarshal(runtimeResponse.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.SchemaVersion != RuntimeConfigSchemaVersion || runtime.StateSchemaVersion != StateSchemaVersion ||
		runtime.ExpectedOrigin != "http://"+testHost || runtime.Simulation || !runtime.SecretFree ||
		runtime.RollbackStatus != RollbackStatus || runtime.EnrollmentCapable ||
		runtime.StateEndpoint != "/api/v1/state" || runtime.ActionEndpoint != "/api/v1/actions" {
		t.Fatalf("runtime config = %#v", runtime)
	}
	if stub.calls != 0 {
		t.Fatal("static kiosk request reached the orchestrator action backend")
	}
}

func TestHTTPHandlerKeepsStaticSurfaceExact(t *testing.T) {
	stub := &stubOrchestrator{state: State{Revision: 1}}
	handler, err := NewHandler(stub, testHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodHead, "/app.js", http.StatusMethodNotAllowed},
		{http.MethodPost, "/runtime-config.json", http.StatusMethodNotAllowed},
		{http.MethodGet, "/index.html", http.StatusNotFound},
		{http.MethodGet, "/runtime-config.json?debug=true", http.StatusBadRequest},
	} {
		response := doRequest(handler, test.method, test.path, "", "", "")
		if response.Code != test.want {
			t.Fatalf("%s %s = %d, want %d", test.method, test.path, response.Code, test.want)
		}
	}
}

func TestHTTPHandlerRejectsCrossOriginAndMalformedRequestsBeforeBackend(t *testing.T) {
	tests := []struct {
		name, method, path, body, origin, contentType, host string
		want                                                int
	}{
		{"host", http.MethodGet, "/api/v1/state", "", "", "", "evil.example", http.StatusMisdirectedRequest},
		{"query", http.MethodGet, "/api/v1/state?debug=1", "", "", "", testHost, http.StatusBadRequest},
		{"origin absent", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1}`, "", "application/json", testHost, http.StatusForbidden},
		{"origin foreign", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1}`, "https://evil.example", "application/json", testHost, http.StatusForbidden},
		{"content type", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1}`, "http://" + testHost, "application/json; charset=utf-8", testHost, http.StatusUnsupportedMediaType},
		{"duplicate", http.MethodPost, "/api/v1/actions", `{"action":"reset","action":"execute_commit","expected_revision":1}`, "http://" + testHost, "application/json", testHost, http.StatusBadRequest},
		{"unknown", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1,"extra":true}`, "http://" + testHost, "application/json", testHost, http.StatusBadRequest},
		{"fractional", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1.0}`, "http://" + testHost, "application/json", testHost, http.StatusBadRequest},
		{"trailing", http.MethodPost, "/api/v1/actions", `{"action":"reset","expected_revision":1}{}`, "http://" + testHost, "application/json", testHost, http.StatusBadRequest},
		{"wrong method", http.MethodPut, "/api/v1/actions", `{}`, "http://" + testHost, "application/json", testHost, http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &stubOrchestrator{state: State{Revision: 1}}
			handler, err := NewHandler(stub, testHost)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, "http://"+testHost+test.path, strings.NewReader(test.body))
			request.Host = test.host
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body %s", response.Code, test.want, response.Body.String())
			}
			if stub.calls != 0 {
				t.Fatal("rejected request reached orchestrator")
			}
		})
	}
}

func TestHTTPHandlerMapsOptimisticConcurrencyAndSafetyErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"stale", ErrStaleRevision, http.StatusConflict},
		{"not allowed", ErrActionNotAllowed, http.StatusConflict},
		{"reconciliation", ErrReconciliationRequired, http.StatusConflict},
		{"quarantine", ErrQuarantined, http.StatusLocked},
		{"backend", ErrBackendUnavailable, http.StatusServiceUnavailable},
		{"invalid backend", ErrInvalidBackendResult, http.StatusBadGateway},
		{"other", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &stubOrchestrator{state: State{Revision: 9}, err: test.err}
			handler, err := NewHandler(stub, testHost)
			if err != nil {
				t.Fatal(err)
			}
			response := doRequest(handler, http.MethodPost, "/api/v1/actions", `{"action":"execute_commit","expected_revision":9}`, "http://"+testHost, "application/json")
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestValidateListenAddressIsLoopbackOnly(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:8081"} {
		if err := ValidateListenAddress(address); err != nil {
			t.Errorf("valid address %q: %v", address, err)
		}
	}
	for _, address := range []string{"localhost:8081", "0.0.0.0:8081", "192.0.2.1:8081", "127.0.0.1", "127.0.0.1:not-a-port"} {
		if err := ValidateListenAddress(address); err == nil {
			t.Errorf("invalid address %q accepted", address)
		}
	}
}

func doRequest(handler http.Handler, method, path, body, origin, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://"+testHost+path, strings.NewReader(body))
	request.Host = testHost
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func mustAsset(t *testing.T, name string) []byte {
	t.Helper()
	asset, err := embeddedAsset(name)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}
