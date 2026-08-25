package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

const maxRequestBytes = 1 << 20

type Command struct {
	SchemaVersion string          `json:"schema_version"`
	Operation     string          `json:"operation"`
	Request       json.RawMessage `json:"request"`
}

func Handler(service *Service, identityPolicy mtls.IdentityPolicy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/transactions/{transaction_id}", func(writer http.ResponseWriter, request *http.Request) {
		if _, err := identityPolicy.Authenticate(request); err != nil {
			writeError(writer, statusForError(err), err)
			return
		}
		transaction, err := service.GetTransaction(request.Context(), request.PathValue("transaction_id"))
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(writer, status, err)
			return
		}
		stationID, laneID, authorized := transactionReadOwner(transaction)
		if !authorized && identityPolicy.RequiresClientIdentity() {
			writeError(writer, http.StatusForbidden, mtls.ErrClientIdentityMismatch)
			return
		}
		if authorized {
			if err := identityPolicy.Authorize(request, stationID, laneID); err != nil {
				writeError(writer, statusForError(err), err)
				return
			}
		}
		writeJSON(writer, http.StatusOK, transaction)
	})
	mux.HandleFunc("POST /api/v1/commands", func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBody(writer, request)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		var command Command
		if err := DecodeStrict(body, &command); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		if command.SchemaVersion != CommandSchemaVersion || !validIdentifier(command.Operation) || len(command.Request) == 0 {
			writeError(writer, http.StatusBadRequest, invalid("invalid command envelope"))
			return
		}
		transaction, err := dispatchCommand(request, service, identityPolicy, command)
		if err != nil {
			writeError(writer, statusForError(err), err)
			return
		}
		writeJSON(writer, http.StatusOK, transaction)
	})
	return mux
}

// transactionReadOwner keeps durable authority, including capability-like
// audit receipt IDs, scoped to the active claimant or the most recently
// fenced historical claimant after release. A never-claimed transaction has
// no station/lane reader under mutual TLS.
func transactionReadOwner(transaction Transaction) (string, string, bool) {
	if transaction.ActiveClaim != nil {
		return transaction.ActiveClaim.StationID, transaction.ActiveClaim.LaneID, true
	}
	if len(transaction.ClaimHistory) == 0 {
		return "", "", false
	}
	latest := transaction.ClaimHistory[0]
	for _, claim := range transaction.ClaimHistory[1:] {
		if claim.FenceEpoch > latest.FenceEpoch {
			latest = claim
		}
	}
	return latest.StationID, latest.LaneID, true
}

func dispatchCommand(httpRequest *http.Request, service *Service, identityPolicy mtls.IdentityPolicy, command Command) (Transaction, error) {
	ctx := httpRequest.Context()
	switch command.Operation {
	case "create_transaction":
		var request CreateTransactionRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if _, err := identityPolicy.Authenticate(httpRequest); err != nil {
			return Transaction{}, err
		}
		return service.CreateTransaction(ctx, request)
	case "acquire_claim":
		var request AcquireClaimRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := identityPolicy.Authorize(httpRequest, request.StationID, request.LaneID); err != nil {
			return Transaction{}, err
		}
		return service.AcquireClaim(ctx, request)
	case "renew_claim":
		var request RenewClaimRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.RenewClaim(ctx, request)
	case "transfer_claim":
		var request TransferClaimRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.TransferClaim(ctx, request)
	case "release_claim":
		var request ReleaseClaimRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.ReleaseClaim(ctx, request)
	case "bind_target":
		var request BindTargetRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.BindTarget(ctx, request)
	case "record_approval":
		var request RecordApprovalRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := identityPolicy.AuthorizeApprover(httpRequest, request.ApproverID); err != nil {
			return Transaction{}, err
		}
		return service.RecordApproval(ctx, request)
	case "record_intent":
		var request RecordIntentRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.RecordIntent(ctx, request)
	case "record_evidence":
		var request RecordEvidenceRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.RecordEvidence(ctx, request)
	case "record_reconciliation":
		var request RecordReconciliationRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.RecordReconciliation(ctx, request)
	case "quarantine_device":
		var request QuarantineRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.QuarantineDevice(ctx, request)
	case "abort_transaction":
		var request AbortRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.AbortTransaction(ctx, request)
	case "mark_security_applied":
		var request SecurityAppliedRequest
		if err := DecodeStrict(command.Request, &request); err != nil {
			return Transaction{}, err
		}
		if err := authorizeCurrentClaim(httpRequest, service, identityPolicy, request.TransactionID); err != nil {
			return Transaction{}, err
		}
		return service.MarkSecurityApplied(ctx, request)
	default:
		return Transaction{}, invalid("unsupported command operation")
	}
}

func authorizeCurrentClaim(request *http.Request, service *Service, identityPolicy mtls.IdentityPolicy, transactionID string) error {
	if _, err := identityPolicy.Authenticate(request); err != nil {
		return err
	}
	transaction, err := service.GetTransaction(request.Context(), transactionID)
	if err != nil {
		return err
	}
	if transaction.ActiveClaim == nil {
		return mtls.ErrClientIdentityMismatch
	}
	return identityPolicy.Authorize(request, transaction.ActiveClaim.StationID, transaction.ActiveClaim.LaneID)
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, mtls.ErrClientIdentityMismatch):
		return http.StatusForbidden
	case errors.Is(err, mtls.ErrClientIdentity):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrConflict),
		errors.Is(err, ErrStaleFence), errors.Is(err, ErrLeaseExpired), errors.Is(err, ErrIllegalTransition):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
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

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writeJSON(writer, status, struct {
		Error string `json:"error"`
	}{err.Error()})
}
