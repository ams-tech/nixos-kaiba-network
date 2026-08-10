package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/api"
	"github.com/kaiba-network/dns-pilot/internal/model"
)

func TestUpdateOnceReusesPendingIdempotencyKeyAcrossRetry(t *testing.T) {
	t.Parallel()
	var mutex sync.Mutex
	var keys []string
	var preconditions []string
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/v1/devices/self/status" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		requests++
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		preconditions = append(preconditions, request.Header.Get("If-None-Match"))
		if request.Method != http.MethodPut || request.URL.Path != "/v1/devices/self/endpoints" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		var payload api.EndpointRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if len(payload.Addresses) != 2 || payload.Addresses[0].Family != "ipv4" {
			t.Errorf("addresses were not canonical: %+v", payload.Addresses)
		}
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(api.Error{Code: "origin_unavailable", Message: "retry later"})
			return
		}
		response.Header().Set("ETag", `"g-1"`)
		response.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(response).Encode(api.DeviceState{
			DeviceID: "001", Hostname: "pi-001.kaiba.network", Generation: 1,
			Status: model.StatusAccepted, LeaseExpiresAt: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		})
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "state", "idempotency.json")
	keyNumber := 0
	service, err := New(Config{
		Endpoint:  server.URL,
		Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::42"), netip.MustParseAddr("203.0.113.42")},
		StatePath: statePath, HTTPClient: server.Client(), RenewInterval: time.Hour,
		RequestTimeout: time.Second, Now: func() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) },
		NewIdempotencyKey: func() (string, error) { keyNumber++; return "key-" + string(rune('0'+keyNumber)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateOnce(context.Background()); err == nil {
		t.Fatal("503 response was accepted")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("pending request was not durable: %v", err)
	}
	pendingPayload, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var pending pendingState
	if err := json.Unmarshal(pendingPayload, &pending); err != nil || !pending.IfNoneMatch {
		t.Fatalf("pending precondition was not durable: %+v, %v", pending, err)
	}
	state, err := service.UpdateOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.DeviceID != "001" {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("completed pending state still exists: %v", err)
	}
	if _, err := service.UpdateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(keys) != 3 || keys[0] != keys[1] || keys[2] == keys[1] || keyNumber != 2 || preconditions[0] != "*" || preconditions[1] != "*" {
		t.Fatalf("unexpected durable requests: keys=%v preconditions=%v (generated %d)", keys, preconditions, keyNumber)
	}
}

func TestRunOnceReturnsPermanentControllerError(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(response).Encode(api.Error{Code: "invalid_addresses", Message: "bad address"})
	}))
	defer server.Close()
	service, err := New(Config{
		Endpoint: server.URL, Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		StatePath: filepath.Join(t.TempDir(), "pending.json"), HTTPClient: server.Client(),
		RenewInterval: time.Hour, RequestTimeout: time.Second, Once: true,
		NewIdempotencyKey: func() (string, error) { return "request-1", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Run(context.Background()); err == nil {
		t.Fatal("permanent controller error was not returned")
	}
}

func TestUpdateOnceRefreshesAnExpiredIdempotentReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	var keys []string
	var preconditions []string
	statusRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			statusRequests++
			if statusRequests == 1 {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			response.Header().Set("ETag", `"g-2"`)
			_ = json.NewEncoder(response).Encode(api.DeviceState{Generation: 2, LeaseExpiresAt: now.Add(24 * time.Hour)})
			return
		}
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		if value := request.Header.Get("If-Match"); value != "" {
			preconditions = append(preconditions, "If-Match:"+value)
		} else {
			preconditions = append(preconditions, "If-None-Match:"+request.Header.Get("If-None-Match"))
		}
		expires := now.Add(-time.Minute)
		if len(keys) == 2 {
			expires = now.Add(24 * time.Hour)
		}
		response.Header().Set("ETag", api.GenerationETag(int64(len(keys))))
		response.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(response).Encode(api.DeviceState{
			DeviceID: "001", Hostname: "pi-001.kaiba.network", Generation: int64(len(keys)),
			Status: model.StatusAccepted, LeaseExpiresAt: expires,
		})
	}))
	defer server.Close()
	keyNumber := 0
	service, err := New(Config{
		Endpoint: server.URL, Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		StatePath: filepath.Join(t.TempDir(), "pending.json"), HTTPClient: server.Client(),
		RenewInterval: time.Hour, RequestTimeout: time.Second, Now: func() time.Time { return now },
		NewIdempotencyKey: func() (string, error) {
			keyNumber++
			return "request-" + string(rune('0'+keyNumber)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.UpdateOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 2 || len(keys) != 2 || keys[0] == keys[1] || preconditions[0] != "If-None-Match:*" || preconditions[1] != `If-Match:"g-2"` {
		t.Fatalf("expired replay was not refreshed: state=%+v keys=%v preconditions=%v", state, keys, preconditions)
	}
}

func TestUpdateOnceRefreshesFailedPrecondition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	statusGeneration := int64(1)
	var keys, preconditions []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			response.Header().Set("ETag", api.GenerationETag(statusGeneration))
			_ = json.NewEncoder(response).Encode(api.DeviceState{Generation: statusGeneration, LeaseExpiresAt: now.Add(24 * time.Hour)})
			return
		}
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		preconditions = append(preconditions, request.Header.Get("If-Match"))
		if len(keys) == 1 {
			statusGeneration = 2
			response.WriteHeader(http.StatusPreconditionFailed)
			_ = json.NewEncoder(response).Encode(api.Error{Code: "precondition_failed", Message: "stale"})
			return
		}
		response.Header().Set("ETag", `"g-3"`)
		response.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(response).Encode(api.DeviceState{Generation: 3, LeaseExpiresAt: now.Add(24 * time.Hour)})
	}))
	defer server.Close()
	keyNumber := 0
	service, err := New(Config{
		Endpoint: server.URL, Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		StatePath: filepath.Join(t.TempDir(), "pending.json"), HTTPClient: server.Client(),
		RenewInterval: time.Hour, RequestTimeout: time.Second, Now: func() time.Time { return now },
		NewIdempotencyKey: func() (string, error) {
			keyNumber++
			return "request-" + string(rune('0'+keyNumber)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.UpdateOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 3 || len(keys) != 2 || keys[0] == keys[1] || preconditions[0] != `"g-1"` || preconditions[1] != `"g-2"` {
		t.Fatalf("412 was not refreshed safely: state=%+v keys=%v preconditions=%v", state, keys, preconditions)
	}
}

func TestNewRejectsInsecureControllerURL(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Endpoint: "http://controller.test", StatePath: "state", HTTPClient: http.DefaultClient,
		RenewInterval: time.Hour,
	})
	if err == nil {
		t.Fatal("HTTP controller URL was accepted")
	}
}
