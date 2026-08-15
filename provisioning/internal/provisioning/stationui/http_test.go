package stationui

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const testHost = "127.0.0.1:8080"

func TestHTTPStateAndAction(t *testing.T) {
	machine := newTestMachine(t, ScenarioHappyPath)
	handler := newTestHandler(t, machine)

	stateResponse := request(t, handler, http.MethodGet, "/api/v1/state", "", "", testHost)
	if stateResponse.Code != http.StatusOK || stateResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET state = %d %s", stateResponse.Code, stateResponse.Body.String())
	}
	var state State
	if err := json.Unmarshal(stateResponse.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.SchemaVersion != "provisioning.kaiba.network/station-demo-state/v1alpha2" || state.Phase != PhaseStationAdmission || state.Revision != 1 {
		t.Fatalf("initial state = %#v", state)
	}

	body := `{"action":"run_station_admission","expected_revision":1}`
	actionResponse := request(t, handler, http.MethodPost, "/api/v1/actions", body, "http://"+testHost, testHost)
	if actionResponse.Code != http.StatusOK {
		t.Fatalf("POST action = %d %s", actionResponse.Code, actionResponse.Body.String())
	}
	if err := json.Unmarshal(actionResponse.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != PhaseTransactionCreation || state.Revision != 2 {
		t.Fatalf("state = %#v", state)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control", "Permissions-Policy"} {
		if actionResponse.Header().Get(header) == "" {
			t.Fatalf("missing security header %s", header)
		}
	}
}

func TestHTTPRejectsHostOriginMethodAndContentType(t *testing.T) {
	handler := newTestHandler(t, newTestMachine(t, ScenarioHappyPath))
	tests := []struct {
		name, method, path, body, origin, host, contentType string
		status                                              int
	}{
		{"host", http.MethodGet, "/api/v1/state", "", "", "evil.example", "", http.StatusMisdirectedRequest},
		{"origin absent", http.MethodPost, "/api/v1/actions", `{"action":"run_station_admission","expected_revision":1}`, "", testHost, "application/json", http.StatusForbidden},
		{"origin foreign", http.MethodPost, "/api/v1/actions", `{"action":"run_station_admission","expected_revision":1}`, "https://evil.example", testHost, "application/json", http.StatusForbidden},
		{"content type", http.MethodPost, "/api/v1/actions", `{}`, "http://" + testHost, testHost, "text/plain", http.StatusUnsupportedMediaType},
		{"content type parameter", http.MethodPost, "/api/v1/actions", `{}`, "http://" + testHost, testHost, "application/json; charset=utf-8", http.StatusUnsupportedMediaType},
		{"state method", http.MethodPost, "/api/v1/state", `{}`, "http://" + testHost, testHost, "application/json", http.StatusMethodNotAllowed},
		{"action method", http.MethodGet, "/api/v1/actions", "", "", testHost, "", http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := requestWithContentType(t, handler, test.method, test.path, test.body, test.origin, test.host, test.contentType)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
			}
		})
	}
}

func TestHTTPRejectsMalformedNonCanonicalAndConflictingActions(t *testing.T) {
	tests := []struct {
		name, body string
		status     int
	}{
		{"empty", "", http.StatusBadRequest},
		{"malformed", `{`, http.StatusBadRequest},
		{"duplicate", `{"action":"run_station_admission","action":"reset","expected_revision":1}`, http.StatusBadRequest},
		{"unknown", `{"action":"run_station_admission","expected_revision":1,"extra":true}`, http.StatusBadRequest},
		{"missing", `{"action":"run_station_admission"}`, http.StatusBadRequest},
		{"trailing", `{"action":"run_station_admission","expected_revision":1}{}`, http.StatusBadRequest},
		{"nested revision", `{"action":"run_station_admission","expected_revision":{"value":1}}`, http.StatusBadRequest},
		{"fractional revision", `{"action":"run_station_admission","expected_revision":1.0}`, http.StatusBadRequest},
		{"zero revision", `{"action":"run_station_admission","expected_revision":0}`, http.StatusBadRequest},
		{"oversized", strings.Repeat("x", maxActionBody+1), http.StatusBadRequest},
		{"illegal transition", `{"action":"create_transaction","expected_revision":1}`, http.StatusConflict},
		{"stale revision", `{"action":"run_station_admission","expected_revision":2}`, http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, newTestMachine(t, ScenarioHappyPath))
			response := request(t, handler, http.MethodPost, "/api/v1/actions", test.body, "http://"+testHost, testHost)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if state := handlerState(t, handler); state.Revision != 1 {
				t.Fatalf("rejected request changed revision to %d", state.Revision)
			}
		})
	}
}

func TestHTTPServesOnlyExactEmbeddedPaths(t *testing.T) {
	handler := newTestHandler(t, newTestMachine(t, ScenarioHappyPath))
	tests := []struct {
		path, contentType, body string
		status                  int
	}{
		{"/", "text/html; charset=utf-8", "INDEX", http.StatusOK},
		{"/app.js", "text/javascript; charset=utf-8", "SCRIPT", http.StatusOK},
		{"/transport.js", "text/javascript; charset=utf-8", "TRANSPORT", http.StatusOK},
		{"/styles.css", "text/css; charset=utf-8", "STYLE", http.StatusOK},
		{"/runtime-config.json", "application/json", `"mode":"http"`, http.StatusOK},
		{"/missing", "application/problem+json", "", http.StatusNotFound},
		{"/../index.html", "application/problem+json", "", http.StatusNotFound},
	}
	for _, test := range tests {
		response := request(t, handler, http.MethodGet, test.path, "", "", testHost)
		if response.Code != test.status || response.Header().Get("Content-Type") != test.contentType {
			t.Fatalf("GET %s = %d %q", test.path, response.Code, response.Header().Get("Content-Type"))
		}
		if test.body != "" && !strings.Contains(response.Body.String(), test.body) {
			t.Fatalf("GET %s body = %q, want content %q", test.path, response.Body.String(), test.body)
		}
	}
}

func TestValidateListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "127.0.0.1:0"} {
		if err := ValidateListenAddress(address); err != nil {
			t.Errorf("ValidateListenAddress(%q): %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "localhost:8080", "127.0.0.1", "127.0.0.1:not-a-port"} {
		if err := ValidateListenAddress(address); err == nil {
			t.Errorf("ValidateListenAddress(%q) succeeded", address)
		}
	}
}

func newTestHandler(t *testing.T, machine *Machine) http.Handler {
	t.Helper()
	assets := fstest.MapFS{
		"index.html":   &fstest.MapFile{Data: []byte("INDEX")},
		"app.js":       &fstest.MapFile{Data: []byte("SCRIPT")},
		"transport.js": &fstest.MapFile{Data: []byte("TRANSPORT")},
		"styles.css":   &fstest.MapFile{Data: []byte("STYLE")},
	}
	var filesystem fs.FS = assets
	handler, err := NewHandler(machine, testHost, filesystem)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func request(t *testing.T, handler http.Handler, method, path, body, origin, host string) *httptest.ResponseRecorder {
	t.Helper()
	return requestWithContentType(t, handler, method, path, body, origin, host, "application/json")
}

func requestWithContentType(t *testing.T, handler http.Handler, method, path, body, origin, host, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+testHost+path, bytes.NewBufferString(body))
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func handlerState(t *testing.T, handler http.Handler) State {
	t.Helper()
	response := request(t, handler, http.MethodGet, "/api/v1/state", "", "", testHost)
	var state State
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	return state
}
