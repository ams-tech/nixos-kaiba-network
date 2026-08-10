package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	addresspolicy "github.com/kaiba-network/dns-pilot/internal/address"
	"github.com/kaiba-network/dns-pilot/internal/api"
	"github.com/kaiba-network/dns-pilot/internal/identity"
	"github.com/kaiba-network/dns-pilot/internal/model"
	"github.com/kaiba-network/dns-pilot/internal/store"
)

const maxRequestBytes = 64 << 10

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Config struct {
	Identity                identity.Policy
	Store                   store.DesiredState
	LeaseDuration           time.Duration
	RenewAfter              time.Duration
	AllowNonGlobalAddresses bool
	Now                     func() time.Time
}

type Handler struct {
	identity                identity.Policy
	store                   store.DesiredState
	leaseDuration           time.Duration
	renewAfter              time.Duration
	allowNonGlobalAddresses bool
	now                     func() time.Time
	mux                     *http.ServeMux
}

func New(config Config) (*Handler, error) {
	if config.Identity == nil || config.Store == nil {
		return nil, errors.New("identity policy and desired-state store are required")
	}
	if config.LeaseDuration <= 0 || config.RenewAfter <= 0 || config.RenewAfter >= config.LeaseDuration {
		return nil, errors.New("renew-after must be positive and shorter than lease-duration")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	h := &Handler{
		identity: config.Identity, store: config.Store, leaseDuration: config.LeaseDuration,
		renewAfter: config.RenewAfter, allowNonGlobalAddresses: config.AllowNonGlobalAddresses,
		now: config.Now, mux: http.NewServeMux(),
	}
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("PUT /v1/devices/self/endpoints", h.putEndpoints)
	h.mux.HandleFunc("GET /v1/devices/self/status", h.getStatus)
	return h, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	h.mux.ServeHTTP(response, request)
}

func (h *Handler) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) authenticate(request *http.Request) (identity.Device, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return identity.Device{}, errors.New("a verified client certificate is required")
	}
	return h.identity.Resolve(request.TLS.VerifiedChains[0][0])
}

func (h *Handler) putEndpoints(response http.ResponseWriter, request *http.Request) {
	device, err := h.authenticate(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "unauthenticated", "a valid device certificate is required")
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if !idempotencyKeyPattern.MatchString(idempotencyKey) {
		writeError(response, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key is required and must contain 1-128 safe characters")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload api.EndpointRequest
	if err := decoder.Decode(&payload); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_json", "request must be one JSON endpoint document")
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_json", "request must contain exactly one JSON document")
		return
	}
	addresses, err := h.validateAddresses(payload.Addresses)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_addresses", err.Error())
		return
	}
	precondition, status, err := parseWritePrecondition(request)
	if err != nil {
		code := "invalid_precondition"
		if status == http.StatusPreconditionRequired {
			code = "precondition_required"
		}
		writeError(response, status, code, err.Error())
		return
	}
	result, err := h.store.UpsertIntent(request.Context(), store.UpsertRequest{
		DeviceID: device.ID, Hostname: device.Hostname, Addresses: addresses,
		IdempotencyKey: idempotencyKey, Precondition: precondition,
		Now: h.now(), LeaseDuration: h.leaseDuration,
		RenewAfterSeconds: int64(h.renewAfter / time.Second),
	})
	if errors.Is(err, store.ErrIdempotencyConflict) {
		writeError(response, http.StatusConflict, "idempotency_conflict", err.Error())
		return
	}
	if errors.Is(err, store.ErrPreconditionRequired) {
		writeError(response, http.StatusPreconditionRequired, "precondition_required", err.Error())
		return
	}
	if errors.Is(err, store.ErrPreconditionFailed) {
		writeError(response, http.StatusPreconditionFailed, "precondition_failed", err.Error())
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "storage_error", "desired state could not be persisted")
		return
	}
	response.Header().Set("ETag", api.GenerationETag(result.Intent.Generation))
	writeJSON(response, http.StatusAccepted, h.deviceState(result.Intent, result.RenewAfterSeconds))
}

func parseWritePrecondition(request *http.Request) (store.IntentPrecondition, int, error) {
	ifMatch := request.Header.Values("If-Match")
	ifNoneMatch := request.Header.Values("If-None-Match")
	if (len(ifMatch) == 0 && len(ifNoneMatch) == 0) || (len(ifMatch) > 0 && len(ifNoneMatch) > 0) {
		return store.IntentPrecondition{}, http.StatusPreconditionRequired, errors.New("exactly one of If-Match or If-None-Match is required")
	}
	if len(ifMatch) > 0 {
		if len(ifMatch) != 1 {
			return store.IntentPrecondition{}, http.StatusBadRequest, errors.New("If-Match must contain exactly one generation ETag")
		}
		generation, err := api.ParseGenerationETag(strings.TrimSpace(ifMatch[0]))
		if err != nil {
			return store.IntentPrecondition{}, http.StatusBadRequest, fmt.Errorf("invalid If-Match: %w", err)
		}
		return store.MatchGeneration(generation), 0, nil
	}
	if len(ifNoneMatch) != 1 || strings.TrimSpace(ifNoneMatch[0]) != "*" {
		return store.IntentPrecondition{}, http.StatusBadRequest, errors.New("If-None-Match must be exactly *")
	}
	return store.RequireAbsent(), 0, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON document")
	}
	return err
}

func (h *Handler) validateAddresses(input []api.Address) ([]netip.Addr, error) {
	if len(input) == 0 {
		return nil, errors.New("addresses must contain at least one address")
	}
	if len(input) > 32 {
		return nil, errors.New("addresses may contain at most 32 addresses")
	}
	addresses := make([]netip.Addr, 0, len(input))
	seen := make(map[netip.Addr]struct{}, len(input))
	for _, item := range input {
		addr, err := netip.ParseAddr(item.Address)
		if err != nil || addr.Is4In6() {
			return nil, fmt.Errorf("%q is not a canonical IP address", item.Address)
		}
		expectedFamily := "ipv6"
		if addr.Is4() {
			expectedFamily = "ipv4"
		}
		if item.Family != expectedFamily {
			return nil, fmt.Errorf("address %q does not match family %q", item.Address, item.Family)
		}
		if !h.allowNonGlobalAddresses && !addresspolicy.IsPubliclyRoutable(addr) {
			return nil, fmt.Errorf("address %q is not publicly routable", item.Address)
		}
		if _, duplicate := seen[addr]; duplicate {
			return nil, fmt.Errorf("address %q is duplicated", item.Address)
		}
		seen[addr] = struct{}{}
		addresses = append(addresses, addr)
	}
	return model.CanonicalAddresses(addresses), nil
}

func (h *Handler) getStatus(response http.ResponseWriter, request *http.Request) {
	device, err := h.authenticate(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "unauthenticated", "a valid device certificate is required")
		return
	}
	intent, err := h.store.GetIntent(request.Context(), device.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(response, http.StatusNotFound, "not_found", "this device has no desired state")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "storage_error", "desired state could not be read")
		return
	}
	now := h.now().UTC()
	if len(intent.Addresses) > 0 && !now.Before(intent.LeaseExpiresAt) {
		if _, err := h.store.ExpireLeases(request.Context(), now); err != nil {
			writeError(response, http.StatusInternalServerError, "storage_error", "expired desired state could not be reconciled")
			return
		}
		intent, err = h.store.GetIntent(request.Context(), device.ID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, "storage_error", "desired state could not be read")
			return
		}
	}
	response.Header().Set("ETag", api.GenerationETag(intent.Generation))
	writeJSON(response, http.StatusOK, h.deviceState(intent, int64(h.renewAfter/time.Second)))
}

func (h *Handler) deviceState(intent model.Intent, renewAfterSeconds int64) api.DeviceState {
	return api.DeviceState{
		DeviceID: intent.DeviceID, Hostname: intent.Hostname,
		Addresses: api.AddressesFromNetIP(intent.Addresses), Generation: intent.Generation,
		Status: intent.Status(), LeaseExpiresAt: intent.LeaseExpiresAt,
		RenewAfterSeconds: renewAfterSeconds,
	}
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, api.Error{Code: code, Message: message})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

// TLSConfig is kept here so modules and tests share the server's required mTLS
// policy rather than accidentally configuring request-client certificates.
func TLSConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs,
	}
}
