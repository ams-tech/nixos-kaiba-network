package auditlog

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

const maxRequestBytes = 1 << 20

// Handler exposes the reference JSON/HTTP surface. The supplied identity
// policy is selected by the server deployment: mutual TLS binds station/lane
// fields to the verified URI SAN, while loopback plaintext is an explicit
// development-only exception.
func Handler(service *Service, identityPolicy mtls.IdentityPolicy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/v1/events", func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBody(writer, request)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		var appendRequest AppendRequest
		if err := DecodeStrict(body, &appendRequest); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		if err := authorizeAppend(request, identityPolicy, appendRequest.Event); err != nil {
			status := authorizationStatus(err)
			if errors.Is(err, ErrInvalid) {
				status = http.StatusBadRequest
			}
			writeError(writer, status, err)
			return
		}
		receipt, err := service.Append(request.Context(), appendRequest)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrInvalid) {
				status = http.StatusBadRequest
			} else if errors.Is(err, ErrIdempotencyConflict) {
				status = http.StatusConflict
			}
			writeError(writer, status, err)
			return
		}
		writeJSON(writer, http.StatusCreated, receipt)
	})
	mux.HandleFunc("GET /api/v1/events", func(writer http.ResponseWriter, request *http.Request) {
		var identity mtls.StationLaneIdentity
		if identityPolicy.RequiresClientIdentity() {
			var err error
			identity, err = identityPolicy.Authenticate(request)
			if err != nil {
				writeError(writer, authorizationStatus(err), err)
				return
			}
		}
		records := service.Records(request.URL.Query().Get("transaction_id"))
		if identityPolicy.RequiresClientIdentity() {
			visible := make([]Record, 0, len(records))
			for _, record := range records {
				if record.Event.StationID == identity.StationID && record.Event.LaneID == identity.LaneID {
					visible = append(visible, record)
				}
			}
			records = visible
		}
		writeJSON(writer, http.StatusOK, struct {
			SchemaVersion string   `json:"schema_version"`
			Records       []Record `json:"records"`
		}{StoreSchemaVersion, records})
	})
	return mux
}

func authorizeAppend(request *http.Request, identityPolicy mtls.IdentityPolicy, event Event) error {
	if event.Stage != "plan_approval" {
		return identityPolicy.Authorize(request, event.StationID, event.LaneID)
	}
	if len(event.Actors) != 1 || event.Actors[0].Role != "approver" || event.Actors[0].ID == "" {
		return invalid("plan_approval requires exactly one approver actor")
	}
	return identityPolicy.AuthorizeApprover(request, event.Actors[0].ID)
}

func authorizationStatus(err error) int {
	if errors.Is(err, mtls.ErrClientIdentityMismatch) {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func readBody(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	if mediaType := request.Header.Get("Content-Type"); mediaType != "" && !strings.HasPrefix(strings.ToLower(mediaType), "application/json") {
		return nil, invalid("Content-Type must be application/json")
	}
	reader := http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return data, nil
}
