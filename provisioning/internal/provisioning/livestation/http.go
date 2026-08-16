package livestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"
)

const maxActionBody = 16 * 1024

type HTTPHandler struct {
	orchestrator   Orchestrator
	expectedHost   string
	expectedOrigin string
}

func NewHandler(orchestrator Orchestrator, expectedHost string) (http.Handler, error) {
	if orchestrator == nil {
		return nil, errors.New("live orchestrator is required")
	}
	if err := ValidateListenAddress(expectedHost); err != nil {
		return nil, fmt.Errorf("expected Host: %w", err)
	}
	return &HTTPHandler{
		orchestrator: orchestrator, expectedHost: expectedHost,
		expectedOrigin: "http://" + expectedHost,
	}, nil
}

func (handler *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if request.Host != handler.expectedHost {
		writeProblem(response, http.StatusMisdirectedRequest, "invalid_host", "Invalid Host", "The request Host does not identify this loopback station.", 0)
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "query_not_allowed", "Query not allowed", "Live station endpoints do not accept query parameters.", 0)
		return
	}
	switch request.URL.Path {
	case "/":
		handler.serveAsset(response, request, "index.html", "text/html; charset=utf-8")
	case "/app.js":
		handler.serveAsset(response, request, "app.js", "text/javascript; charset=utf-8")
	case "/styles.css":
		handler.serveAsset(response, request, "styles.css", "text/css; charset=utf-8")
	case "/runtime-config.json":
		if request.Method != http.MethodGet {
			methodNotAllowed(response, http.MethodGet)
			return
		}
		writeJSON(response, http.StatusOK, liveRuntimeConfig(handler.expectedOrigin))
	case "/api/v1/state":
		if request.Method != http.MethodGet {
			methodNotAllowed(response, http.MethodGet)
			return
		}
		state, err := handler.orchestrator.Current(request.Context())
		if err != nil {
			writeProblem(response, http.StatusServiceUnavailable, "state_unavailable", "State unavailable", "Authoritative state could not be read.", 0)
			return
		}
		writeJSON(response, http.StatusOK, state)
	case "/api/v1/actions":
		if request.Method != http.MethodPost {
			methodNotAllowed(response, http.MethodPost)
			return
		}
		if len(request.Header.Values("Origin")) != 1 || request.Header.Get("Origin") != handler.expectedOrigin {
			writeProblem(response, http.StatusForbidden, "invalid_origin", "Invalid Origin", "State-changing requests require the kiosk's exact same origin.", 0)
			return
		}
		if len(request.Header.Values("Content-Type")) != 1 {
			writeProblem(response, http.StatusUnsupportedMediaType, "invalid_content_type", "Invalid content type", "Use one Content-Type: application/json header with no parameters.", 0)
			return
		}
		mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || len(parameters) != 0 {
			writeProblem(response, http.StatusUnsupportedMediaType, "invalid_content_type", "Invalid content type", "Use Content-Type: application/json with no parameters.", 0)
			return
		}
		action, err := decodeAction(request.Body)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_action", "Invalid action", err.Error(), 0)
			return
		}
		state, err := handler.orchestrator.Apply(request.Context(), action)
		switch {
		case errors.Is(err, ErrStaleRevision):
			writeProblem(response, http.StatusConflict, "stale_revision", "Stale state revision", "Reload authoritative state before attempting another action.", state.Revision)
		case errors.Is(err, ErrActionNotAllowed):
			writeProblem(response, http.StatusConflict, "action_not_allowed", "Action not allowed", "The action is not allowed in the authoritative workflow phase.", state.Revision)
		case errors.Is(err, ErrReconciliationRequired):
			writeProblem(response, http.StatusConflict, "reconciliation_required", "Reconciliation required", "Do not repeat the one-shot operation; reconcile direct target state.", state.Revision)
		case errors.Is(err, ErrQuarantined):
			writeProblem(response, http.StatusLocked, "target_quarantined", "Target quarantined", "The owned target is quarantined and no further lane mutations are allowed.", state.Revision)
		case errors.Is(err, ErrBackendUnavailable):
			writeProblem(response, http.StatusServiceUnavailable, "backend_unavailable", "Backend unavailable", "No live orchestration backend is configured.", state.Revision)
		case errors.Is(err, ErrInvalidBackendResult):
			writeProblem(response, http.StatusBadGateway, "invalid_backend_result", "Invalid backend result", "The backend result failed authoritative contract validation.", state.Revision)
		case err != nil:
			writeProblem(response, http.StatusInternalServerError, "orchestration_error", "Orchestration error", "The authoritative action could not be completed.", state.Revision)
		default:
			writeJSON(response, http.StatusOK, state)
		}
	default:
		writeProblem(response, http.StatusNotFound, "not_found", "Not found", "The requested resource does not exist.", 0)
	}
}

func (handler *HTTPHandler) serveAsset(response http.ResponseWriter, request *http.Request, name, contentType string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	asset, err := embeddedAsset(name)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "asset_unavailable", "Asset unavailable", "The embedded live-station interface is incomplete.", 0)
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(asset)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(asset)
}

func decodeAction(reader io.Reader) (ActionRequest, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxActionBody+1))
	if err != nil {
		return ActionRequest{}, errors.New("could not read request body")
	}
	if len(raw) == 0 {
		return ActionRequest{}, errors.New("request body is empty")
	}
	if len(raw) > maxActionBody {
		return ActionRequest{}, fmt.Errorf("request body exceeds %d bytes", maxActionBody)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeUniqueValue(decoder, "$", nil)
	if err != nil {
		return ActionRequest{}, fmt.Errorf("decode JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ActionRequest{}, fmt.Errorf("decode JSON: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		return ActionRequest{}, errors.New("request must contain exactly action and expected_revision")
	}
	actionValue, actionPresent := object["action"]
	revisionValue, revisionPresent := object["expected_revision"]
	if !actionPresent || !revisionPresent {
		return ActionRequest{}, errors.New("request must contain exactly action and expected_revision")
	}
	action, ok := actionValue.(string)
	if !ok || action == "" || len(action) > 128 {
		return ActionRequest{}, errors.New("action must be a non-empty string of at most 128 bytes")
	}
	revisionNumber, ok := revisionValue.(json.Number)
	if !ok {
		return ActionRequest{}, errors.New("expected_revision must be an unsigned integer")
	}
	revision, err := strconv.ParseUint(string(revisionNumber), 10, 64)
	if err != nil || revision == 0 {
		return ActionRequest{}, errors.New("expected_revision must be a positive unsigned integer")
	}
	return ActionRequest{Action: Action(action), ExpectedRevision: revision}, nil
}

func decodeUniqueValue(decoder *json.Decoder, path string, first json.Token) (any, error) {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("%s: object key is not a string", path)
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("%s: duplicate key %q", path, key)
			}
			value, err := decodeUniqueValue(decoder, path+"."+key, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		values := []any{}
		for index := 0; decoder.More(); index++ {
			value, err := decodeUniqueValue(decoder, fmt.Sprintf("%s[%d]", path, index), nil)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return values, nil
	default:
		return nil, fmt.Errorf("%s: unexpected JSON delimiter", path)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return fmt.Errorf("trailing data: %w", err)
}

type problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Revision uint64 `json:"revision,omitempty"`
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func methodNotAllowed(response http.ResponseWriter, methods ...string) {
	for _, method := range methods {
		response.Header().Add("Allow", method)
	}
	writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", "The resource does not accept this HTTP method.", 0)
}

func writeProblem(response http.ResponseWriter, status int, problemType, title, detail string, revision uint64) {
	response.Header().Set("Content-Type", "application/problem+json")
	writeJSONWithContentType(response, status, problem{problemType, title, status, detail, revision})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	writeJSONWithContentType(response, status, value)
}

func writeJSONWithContentType(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	encoder := json.NewEncoder(response)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func ValidateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listen address must include an IP address and port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || !ip.IsLoopback() {
		return errors.New("listen address must use an explicit loopback IP address")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (portNumber == 0 && port != "0") {
		return errors.New("listen port is invalid")
	}
	return nil
}

func ListenAndServe(ctx context.Context, address string, orchestrator Orchestrator) error {
	if err := ValidateListenAddress(address); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	handler, err := NewHandler(orchestrator, listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
