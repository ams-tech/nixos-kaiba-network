// Package auditlog implements the reference append-only provisioning audit
// service. Its contracts intentionally contain references and digests rather
// than arbitrary payloads so secret-bearing data cannot enter the durable log.
package auditlog

import "time"

const (
	AppendRequestSchemaVersion = "provisioning.kaiba.network/audit-append-request/v1alpha1"
	EventSchemaVersion         = "provisioning.kaiba.network/audit-event/v1alpha1"
	ReceiptSchemaVersion       = "provisioning.kaiba.network/audit-receipt/v1alpha1"
	StoreSchemaVersion         = "provisioning.kaiba.network/audit-store/v1alpha1"
	DefaultPolicyVersion       = "provisioning-audit-policy/v1alpha1"
)

// Actor is a stable, non-secret identity reference. Authentication assertions,
// tokens, and credentials are deliberately absent from this contract.
type Actor struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

// TimeEvidence preserves the station's supporting clock observation. The audit
// service's RecordedAt and Sequence fields remain authoritative for ordering.
type TimeEvidence struct {
	StationTime time.Time `json:"station_time"`
	ClockStatus string    `json:"clock_status"`
}

// ObservationReference points at structured, separately retained evidence.
// The audit API never accepts raw command output or opaque diagnostic blobs.
type ObservationReference struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	URI    string `json:"uri,omitempty"`
}

// Event is the secret-free event supplied by a station or control service.
// PreviousEventHash, service time, and sequence are assigned by the service in
// Record, preventing a caller from choosing or skipping chain positions.
type Event struct {
	SchemaVersion         string                 `json:"schema_version"`
	PolicyVersion         string                 `json:"policy_version"`
	EventID               string                 `json:"event_id"`
	TransactionID         string                 `json:"transaction_id"`
	StationID             string                 `json:"station_id"`
	LaneID                string                 `json:"lane_id"`
	Stage                 string                 `json:"stage"`
	FenceEpoch            uint64                 `json:"fence_epoch"`
	InputDigest           string                 `json:"input_digest"`
	OutputDigest          string                 `json:"output_digest,omitempty"`
	Result                string                 `json:"result"`
	Actors                []Actor                `json:"actors"`
	TimeEvidence          TimeEvidence           `json:"time_evidence"`
	ObservationReferences []ObservationReference `json:"observation_references,omitempty"`
}

type AppendRequest struct {
	SchemaVersion  string `json:"schema_version"`
	IdempotencyKey string `json:"idempotency_key"`
	Event          Event  `json:"event"`
}

// Receipt is durable only after Append returns successfully.
type Receipt struct {
	SchemaVersion     string    `json:"schema_version"`
	ReceiptID         string    `json:"receipt_id"`
	Sequence          uint64    `json:"sequence"`
	PreviousEventHash string    `json:"previous_event_hash,omitempty"`
	EventHash         string    `json:"event_hash"`
	RecordedAt        time.Time `json:"recorded_at"`
}

// Record is the access-controlled representation retained by the audit
// service. RequestDigest binds an idempotency key to exactly one request.
type Record struct {
	Sequence          uint64    `json:"sequence"`
	PreviousEventHash string    `json:"previous_event_hash,omitempty"`
	EventHash         string    `json:"event_hash"`
	RequestDigest     string    `json:"request_digest"`
	RecordedAt        time.Time `json:"recorded_at"`
	Event             Event     `json:"event"`
}
