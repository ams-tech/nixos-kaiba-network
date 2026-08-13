package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	addresspolicy "github.com/ams-tech/nixos-kaiba-network/dns/internal/address"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/api"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/model"
)

type Config struct {
	Endpoint          string
	Addresses         []netip.Addr
	Interfaces        []string
	StatePath         string
	HTTPClient        *http.Client
	RenewInterval     time.Duration
	RequestTimeout    time.Duration
	Once              bool
	NewIdempotencyKey func() (string, error)
	Now               func() time.Time
	OnError           func(error)
}

type Agent struct {
	config Config
}

type HTTPError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("controller returned HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
}

func (e *HTTPError) Retryable() bool {
	return e.StatusCode == http.StatusPreconditionFailed || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

func New(config Config) (*Agent, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return nil, errors.New("endpoint must be an absolute HTTPS URL")
	}
	if config.HTTPClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	if config.StatePath == "" {
		return nil, errors.New("idempotency state path is required")
	}
	if config.RenewInterval <= 0 {
		return nil, errors.New("renew interval must be positive")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.NewIdempotencyKey == nil {
		config.NewIdempotencyKey = randomID
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Agent{config: config}, nil
}

func NewHTTPClient(certFile, keyFile, caFile string, timeout time.Duration) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load device certificate: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read controller CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("controller CA file contains no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots,
	}}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func (a *Agent) addresses() ([]netip.Addr, error) {
	if len(a.config.Addresses) > 0 {
		return model.CanonicalAddresses(a.config.Addresses), nil
	}
	return DiscoverAddresses(a.config.Interfaces)
}

func (a *Agent) UpdateOnce(ctx context.Context) (api.DeviceState, error) {
	return a.updateOnce(ctx, true)
}

func (a *Agent) updateOnce(ctx context.Context, refreshStaleState bool) (api.DeviceState, error) {
	addresses, err := a.addresses()
	if err != nil {
		return api.DeviceState{}, err
	}
	if len(addresses) == 0 {
		return api.DeviceState{}, errors.New("no endpoint addresses were discovered")
	}
	payload := api.EndpointRequest{Addresses: api.AddressesFromNetIP(addresses)}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return api.DeviceState{}, err
	}
	hash := model.AddressesHash(addresses)
	pending, err := a.loadOrCreatePending(ctx, hash)
	if err != nil {
		return api.DeviceState{}, err
	}
	endpoint, _ := url.Parse(a.config.Endpoint)
	endpoint.Path = "/v1/devices/self/endpoints"
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	requestContext, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPut, endpoint.String(), bytes.NewReader(payloadJSON))
	if err != nil {
		return api.DeviceState{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", pending.Key)
	request.Header.Set("User-Agent", "kaiba-agent/1")
	pending.apply(request)
	response, err := a.config.HTTPClient.Do(request)
	if err != nil {
		return api.DeviceState{}, fmt.Errorf("submit endpoint update: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return api.DeviceState{}, err
	}
	if response.StatusCode != http.StatusAccepted {
		httpError := responseError(response.StatusCode, responseBody)
		if response.StatusCode == http.StatusConflict {
			_ = a.clearPending()
		}
		if response.StatusCode == http.StatusPreconditionFailed {
			if err := a.clearPending(); err != nil {
				return api.DeviceState{}, err
			}
			if refreshStaleState {
				return a.updateOnce(ctx, false)
			}
		}
		return api.DeviceState{}, httpError
	}
	var state api.DeviceState
	if err := json.Unmarshal(responseBody, &state); err != nil {
		return api.DeviceState{}, fmt.Errorf("decode controller response: %w", err)
	}
	responseGeneration, err := api.ParseGenerationETag(response.Header.Get("ETag"))
	if err != nil || responseGeneration != state.Generation {
		return api.DeviceState{}, errors.New("controller response has a missing or inconsistent generation ETag")
	}
	if err := a.clearPending(); err != nil {
		return api.DeviceState{}, err
	}
	// An idempotency replay deliberately returns the original durable result.
	// If that response was lost long enough for its lease to expire, clear the
	// completed key and immediately create one fresh renewal instead of sleeping
	// with a deleted public record.
	if state.LeaseExpiresAt.IsZero() || !state.LeaseExpiresAt.After(a.config.Now()) {
		if refreshStaleState {
			return a.updateOnce(ctx, false)
		}
		return api.DeviceState{}, errors.New("controller acknowledged an already-expired lease")
	}
	return state, nil
}

func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		_, err := a.UpdateOnce(ctx)
		if err == nil {
			backoff = time.Second
			if a.config.Once {
				return nil
			}
			if err := wait(ctx, jitter(a.config.RenewInterval)); err != nil {
				return err
			}
			continue
		}
		if a.config.OnError != nil {
			a.config.OnError(err)
		}
		if a.config.Once || !isRetryable(err) {
			return err
		}
		if err := wait(ctx, jitter(backoff)); err != nil {
			return err
		}
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}
}

func isRetryable(err error) bool {
	var httpError *HTTPError
	if errors.As(err, &httpError) {
		return httpError.Retryable()
	}
	return true
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// jitter returns a cryptographically random delay in the 90%-110% range. It
// prevents a fleet lease-renewal wave without requiring persistent RNG state.
func jitter(duration time.Duration) time.Duration {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return duration
	}
	number := uint64(0)
	for _, octet := range value {
		number = number<<8 | uint64(octet)
	}
	fraction := float64(number) / float64(^uint64(0))
	return time.Duration(float64(duration) * (0.9 + 0.2*fraction))
}

type pendingState struct {
	PayloadHash string `json:"payload_hash"`
	Key         string `json:"idempotency_key"`
	IfMatch     string `json:"if_match,omitempty"`
	IfNoneMatch bool   `json:"if_none_match,omitempty"`
}

func (state pendingState) validPrecondition() bool {
	if state.IfNoneMatch {
		return state.IfMatch == ""
	}
	if state.IfMatch == "" {
		return false
	}
	_, err := api.ParseGenerationETag(state.IfMatch)
	return err == nil
}

func (state pendingState) apply(request *http.Request) {
	if state.IfNoneMatch {
		request.Header.Set("If-None-Match", "*")
		return
	}
	request.Header.Set("If-Match", state.IfMatch)
}

func (a *Agent) loadOrCreatePending(ctx context.Context, hash string) (pendingState, error) {
	payload, err := os.ReadFile(a.config.StatePath)
	if err == nil {
		var state pendingState
		if json.Unmarshal(payload, &state) == nil && state.PayloadHash == hash && state.Key != "" && state.validPrecondition() {
			return state, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingState{}, fmt.Errorf("read idempotency state: %w", err)
	}
	precondition, err := a.fetchPrecondition(ctx)
	if err != nil {
		return pendingState{}, err
	}
	key, err := a.config.NewIdempotencyKey()
	if err != nil {
		return pendingState{}, err
	}
	state := pendingState{
		PayloadHash: hash, Key: key, IfMatch: precondition.IfMatch,
		IfNoneMatch: precondition.IfNoneMatch,
	}
	if err := writePending(a.config.StatePath, state); err != nil {
		return pendingState{}, err
	}
	return state, nil
}

func (a *Agent) fetchPrecondition(ctx context.Context) (pendingState, error) {
	endpoint, _ := url.Parse(a.config.Endpoint)
	endpoint.Path = "/v1/devices/self/status"
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	requestContext, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return pendingState{}, err
	}
	request.Header.Set("User-Agent", "kaiba-agent/1")
	response, err := a.config.HTTPClient.Do(request)
	if err != nil {
		return pendingState{}, fmt.Errorf("read controller status: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return pendingState{}, err
	}
	if response.StatusCode == http.StatusNotFound {
		return pendingState{IfNoneMatch: true}, nil
	}
	if response.StatusCode != http.StatusOK {
		return pendingState{}, responseError(response.StatusCode, responseBody)
	}
	etag := response.Header.Get("ETag")
	generation, err := api.ParseGenerationETag(etag)
	if err != nil {
		return pendingState{}, fmt.Errorf("controller status has an invalid ETag: %w", err)
	}
	var state api.DeviceState
	if err := json.Unmarshal(responseBody, &state); err != nil {
		return pendingState{}, fmt.Errorf("decode controller status: %w", err)
	}
	if state.Generation != generation {
		return pendingState{}, errors.New("controller status body and ETag generations differ")
	}
	return pendingState{IfMatch: etag}, nil
}

func responseError(statusCode int, responseBody []byte) *HTTPError {
	var apiError api.Error
	_ = json.Unmarshal(responseBody, &apiError)
	if apiError.Code == "" {
		apiError.Code = "unexpected_response"
	}
	if apiError.Message == "" {
		apiError.Message = strings.TrimSpace(string(responseBody))
	}
	return &HTTPError{StatusCode: statusCode, Code: apiError.Code, Message: apiError.Message}
}

func writePending(path string, state pendingState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create idempotency state directory: %w", err)
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, payload, 0o600); err != nil {
		return fmt.Errorf("write idempotency state: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("commit idempotency state: %w", err)
	}
	return nil
}

func (a *Agent) clearPending() error {
	err := os.Remove(a.config.StatePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove completed idempotency state: %w", err)
	}
	return nil
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate idempotency key: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func DiscoverAddresses(interfaceNames []string) ([]netip.Addr, error) {
	allowed := make(map[string]struct{}, len(interfaceNames))
	for _, name := range interfaceNames {
		allowed[name] = struct{}{}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	var result []netip.Addr
	for _, networkInterface := range interfaces {
		if len(allowed) > 0 {
			if _, ok := allowed[networkInterface.Name]; !ok {
				continue
			}
		}
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read addresses for %s: %w", networkInterface.Name, err)
		}
		for _, item := range assigned {
			value := item.String()
			if prefix, err := netip.ParsePrefix(value); err == nil {
				if addresspolicy.IsPubliclyRoutable(prefix.Addr()) {
					result = append(result, prefix.Addr())
				}
				continue
			}
			if addr, err := netip.ParseAddr(value); err == nil && addresspolicy.IsPubliclyRoutable(addr) {
				result = append(result, addr)
			}
		}
	}
	result = model.CanonicalAddresses(result)
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}
