package auditlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid             = errors.New("invalid audit request")
	ErrIdempotencyConflict = errors.New("idempotency key was reused with different input")
	ErrCorruptStore        = errors.New("audit store integrity check failed")
)

const (
	ResultIntentRecorded = "intent_recorded"
	ResultSucceeded      = "succeeded"
	ResultFailed         = "failed"
	ResultUncertain      = "uncertain"
	ResultQuarantined    = "quarantined"
	ResultReconciled     = "reconciled"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type Option func(*Service)

func WithClock(clock func() time.Time) Option {
	return func(service *Service) {
		service.clock = clock
	}
}

// Service serializes appends and persists each accepted event before returning
// its receipt. A Service instance must be the sole writer for its Store.
type Service struct {
	mu    sync.Mutex
	store Store
	state persistedState
	clock func() time.Time
}

func NewService(store Store, options ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	service := &Service{
		store: store,
		state: persistedState{
			SchemaVersion: StoreSchemaVersion,
			Idempotency:   make(map[string]uint64),
		},
		clock: time.Now,
	}
	for _, option := range options {
		option(service)
	}
	if service.clock == nil {
		return nil, fmt.Errorf("%w: clock is required", ErrInvalid)
	}
	data, err := store.Load()
	if errors.Is(err, ErrStoreNotFound) {
		return service, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedState
	if err := DecodeStrict(data, &state); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptStore, err)
	}
	if err := validateState(state); err != nil {
		return nil, err
	}
	service.state = state
	return service, nil
}

// Append is idempotent by IdempotencyKey. A replay with byte-equivalent typed
// input returns the original durable receipt; reuse for another event fails.
func (s *Service) Append(_ context.Context, request AppendRequest) (Receipt, error) {
	if err := validateAppendRequest(request); err != nil {
		return Receipt{}, err
	}
	requestDigest, err := digestJSON(request)
	if err != nil {
		return Receipt{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if sequence, exists := s.state.Idempotency[request.IdempotencyKey]; exists {
		record := s.state.Records[sequence-1]
		if record.RequestDigest != requestDigest {
			return Receipt{}, ErrIdempotencyConflict
		}
		return receiptFor(record), nil
	}
	for _, existing := range s.state.Records {
		if existing.Event.EventID == request.Event.EventID {
			return Receipt{}, fmt.Errorf("%w: event_id already exists", ErrIdempotencyConflict)
		}
	}

	sequence := uint64(len(s.state.Records) + 1)
	previous := ""
	if len(s.state.Records) > 0 {
		previous = s.state.Records[len(s.state.Records)-1].EventHash
	}
	record := Record{
		Sequence:          sequence,
		PreviousEventHash: previous,
		RequestDigest:     requestDigest,
		RecordedAt:        s.clock().UTC(),
		Event:             request.Event,
	}
	record.EventHash, err = digestJSON(recordHashMaterial(record))
	if err != nil {
		return Receipt{}, err
	}
	candidate := cloneState(s.state)
	candidate.Records = append(candidate.Records, record)
	candidate.Idempotency[request.IdempotencyKey] = sequence
	if err := validateState(candidate); err != nil {
		return Receipt{}, err
	}
	data, err := marshalState(candidate)
	if err != nil {
		return Receipt{}, err
	}
	if err := s.store.Save(data); err != nil {
		return Receipt{}, err
	}
	s.state = candidate
	return receiptFor(record), nil
}

// Records returns a defensive copy in authoritative service sequence order.
// An empty transactionID returns all records.
func (s *Service) Records(transactionID string) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Record, 0, len(s.state.Records))
	for _, record := range s.state.Records {
		if transactionID == "" || record.Event.TransactionID == transactionID {
			result = append(result, cloneRecord(record))
		}
	}
	return result
}

func validateAppendRequest(request AppendRequest) error {
	if request.SchemaVersion != AppendRequestSchemaVersion {
		return invalid("unsupported append request schema_version")
	}
	if !validIdentifier(request.IdempotencyKey) {
		return invalid("idempotency_key is invalid")
	}
	return validateEvent(request.Event)
}

func validateEvent(event Event) error {
	if event.SchemaVersion != EventSchemaVersion {
		return invalid("unsupported event schema_version")
	}
	if event.PolicyVersion == "" || len(event.PolicyVersion) > 128 {
		return invalid("policy_version is required and must be at most 128 characters")
	}
	for name, value := range map[string]string{
		"event_id": event.EventID, "transaction_id": event.TransactionID,
		"station_id": event.StationID, "lane_id": event.LaneID, "stage": event.Stage,
	} {
		if !validIdentifier(value) {
			return invalid(name + " is invalid")
		}
	}
	if event.FenceEpoch == 0 {
		return invalid("fence_epoch must be non-zero")
	}
	if !validDigest(event.InputDigest) {
		return invalid("input_digest must be a lowercase sha256 digest")
	}
	if event.OutputDigest != "" && !validDigest(event.OutputDigest) {
		return invalid("output_digest must be empty or a lowercase sha256 digest")
	}
	switch event.Result {
	case ResultIntentRecorded, ResultSucceeded, ResultFailed, ResultUncertain, ResultQuarantined, ResultReconciled:
	default:
		return invalid("result is unsupported")
	}
	if event.TimeEvidence.StationTime.IsZero() {
		return invalid("time_evidence.station_time is required")
	}
	switch event.TimeEvidence.ClockStatus {
	case "synchronized", "degraded", "unknown":
	default:
		return invalid("time_evidence.clock_status is unsupported")
	}
	if len(event.Actors) == 0 || len(event.Actors) > 8 {
		return invalid("actors must contain between one and eight entries")
	}
	actorKeys := make(map[string]struct{}, len(event.Actors))
	for _, actor := range event.Actors {
		if !validIdentifier(actor.ID) || !validIdentifier(actor.Role) {
			return invalid("actor identity or role is invalid")
		}
		key := actor.Role + "\x00" + actor.ID
		if _, duplicate := actorKeys[key]; duplicate {
			return invalid("actors contains a duplicate role and identity")
		}
		actorKeys[key] = struct{}{}
	}
	if len(event.ObservationReferences) > 64 {
		return invalid("observation_references exceeds 64 entries")
	}
	for _, reference := range event.ObservationReferences {
		if !validIdentifier(reference.Kind) || !validDigest(reference.Digest) {
			return invalid("observation reference kind or digest is invalid")
		}
		if reference.URI != "" {
			parsed, err := url.Parse(reference.URI)
			if err != nil || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "kaiba-evidence") {
				return invalid("observation reference URI must be an https or kaiba-evidence URI without credentials or fragment")
			}
		}
	}
	return nil
}

func validateState(state persistedState) error {
	if state.SchemaVersion != StoreSchemaVersion {
		return fmt.Errorf("%w: unsupported store schema_version", ErrCorruptStore)
	}
	if state.Idempotency == nil {
		return fmt.Errorf("%w: idempotency index is missing", ErrCorruptStore)
	}
	seenEvents := make(map[string]struct{}, len(state.Records))
	indexedSequences := make(map[uint64]string, len(state.Idempotency))
	for key, sequence := range state.Idempotency {
		if !validIdentifier(key) || sequence == 0 || sequence > uint64(len(state.Records)) {
			return fmt.Errorf("%w: invalid idempotency index", ErrCorruptStore)
		}
		if _, duplicate := indexedSequences[sequence]; duplicate {
			return fmt.Errorf("%w: multiple idempotency keys reference one record", ErrCorruptStore)
		}
		indexedSequences[sequence] = key
	}
	previous := ""
	for index, record := range state.Records {
		wantSequence := uint64(index + 1)
		if record.Sequence != wantSequence || record.PreviousEventHash != previous || record.RecordedAt.IsZero() || !validDigest(record.RequestDigest) {
			return fmt.Errorf("%w: invalid record metadata at sequence %d", ErrCorruptStore, wantSequence)
		}
		if err := validateEvent(record.Event); err != nil {
			return fmt.Errorf("%w: invalid record at sequence %d: %v", ErrCorruptStore, wantSequence, err)
		}
		if _, duplicate := seenEvents[record.Event.EventID]; duplicate {
			return fmt.Errorf("%w: duplicate event_id %q", ErrCorruptStore, record.Event.EventID)
		}
		seenEvents[record.Event.EventID] = struct{}{}
		wantHash, err := digestJSON(recordHashMaterial(record))
		if err != nil || record.EventHash != wantHash {
			return fmt.Errorf("%w: hash mismatch at sequence %d", ErrCorruptStore, wantSequence)
		}
		if _, indexed := indexedSequences[wantSequence]; !indexed {
			return fmt.Errorf("%w: record %d is absent from idempotency index", ErrCorruptStore, wantSequence)
		}
		idempotencyKey := indexedSequences[wantSequence]
		wantRequestDigest, err := digestJSON(AppendRequest{
			SchemaVersion:  AppendRequestSchemaVersion,
			IdempotencyKey: idempotencyKey,
			Event:          record.Event,
		})
		if err != nil || record.RequestDigest != wantRequestDigest {
			return fmt.Errorf("%w: request digest mismatch at sequence %d", ErrCorruptStore, wantSequence)
		}
		previous = record.EventHash
	}
	return nil
}

type hashMaterial struct {
	Sequence          uint64    `json:"sequence"`
	PreviousEventHash string    `json:"previous_event_hash,omitempty"`
	RequestDigest     string    `json:"request_digest"`
	RecordedAt        time.Time `json:"recorded_at"`
	Event             Event     `json:"event"`
}

func recordHashMaterial(record Record) hashMaterial {
	return hashMaterial{
		Sequence: record.Sequence, PreviousEventHash: record.PreviousEventHash,
		RequestDigest: record.RequestDigest, RecordedAt: record.RecordedAt, Event: record.Event,
	}
}

func receiptFor(record Record) Receipt {
	receiptID := digestBytes([]byte("kaiba-audit-receipt\x00" + record.EventHash))
	return Receipt{
		SchemaVersion: ReceiptSchemaVersion, ReceiptID: receiptID,
		Sequence: record.Sequence, PreviousEventHash: record.PreviousEventHash,
		EventHash: record.EventHash, RecordedAt: record.RecordedAt,
	}
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical audit value: %w", err)
	}
	return digestBytes(data), nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, message)
}

func cloneState(state persistedState) persistedState {
	result := persistedState{
		SchemaVersion: state.SchemaVersion,
		Records:       make([]Record, len(state.Records)),
		Idempotency:   make(map[string]uint64, len(state.Idempotency)),
	}
	for index, record := range state.Records {
		result.Records[index] = cloneRecord(record)
	}
	for key, sequence := range state.Idempotency {
		result.Idempotency[key] = sequence
	}
	return result
}

func cloneRecord(record Record) Record {
	record.Event.Actors = append([]Actor(nil), record.Event.Actors...)
	record.Event.ObservationReferences = append([]ObservationReference(nil), record.Event.ObservationReferences...)
	return record
}

// SortRecords is provided for storage adapters that reconstruct records from
// ordered external media before passing them through Service validation.
func SortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
}
