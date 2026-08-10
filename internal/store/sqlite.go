package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/model"
	_ "modernc.org/sqlite"
)

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("SQLite path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	// Each pilot service serializes its own connection pool. SQLite WAL and the
	// busy timeout coordinate the controller and publisher processes, while the
	// one-connection pools keep transaction behavior predictable.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
		`PRAGMA foreign_keys = ON`,
	} {
		if err := execStartupStatement(db, statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure SQLite (%s): %w", statement, err)
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db}, nil
}

func execStartupStatement(db *sql.DB, statement string) error {
	const retryWindow = 5 * time.Second
	deadline := time.Now().Add(retryWindow)
	for {
		_, err := db.Exec(statement)
		if err == nil {
			return nil
		}
		if !sqliteLockContention(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sqliteLockContention(err error) bool {
	var sqliteError interface{ Code() int }
	if !errors.As(err, &sqliteError) {
		return false
	}
	// Extended SQLite result codes retain the primary code in the low byte.
	primaryCode := sqliteError.Code() & 0xff
	return primaryCode == 5 || primaryCode == 6 // SQLITE_BUSY or SQLITE_LOCKED
}

func migrate(db *sql.DB) error {
	const desiredStateSchema = `
CREATE TABLE IF NOT EXISTS intents (
  device_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL UNIQUE,
  addresses_json TEXT NOT NULL,
  generation INTEGER NOT NULL,
  lease_expires_ns INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  origin_applied_generation INTEGER NOT NULL DEFAULT 0,
  public_observed_generation INTEGER NOT NULL DEFAULT 0,
  last_publication_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS intents_origin_pending
  ON intents(generation, origin_applied_generation);
CREATE INDEX IF NOT EXISTS intents_observation_pending
  ON intents(generation, public_observed_generation);
CREATE INDEX IF NOT EXISTS intents_lease_expiry
  ON intents(lease_expires_ns);
`
	if _, err := db.Exec(desiredStateSchema); err != nil {
		return fmt.Errorf("migrate SQLite: %w", err)
	}
	if err := migrateIdempotencyTable(db); err != nil {
		return err
	}
	return nil
}

// The pilot retains idempotency responses indefinitely so every duplicate key
// can return its exact original result. A future fleet-scale compaction policy
// requires an explicit API contract change and is deliberately deferred.
const idempotencyTableSchema = `
CREATE TABLE IF NOT EXISTS idempotency_requests (
  device_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  precondition_key TEXT NOT NULL,
  response_json TEXT NOT NULL,
  PRIMARY KEY (device_id, idempotency_key)
)`

func migrateIdempotencyTable(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(idempotency_requests)`)
	if err != nil {
		return fmt.Errorf("inspect idempotency schema: %w", err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("inspect idempotency column: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(columns) == 0 {
		if _, err := db.Exec(idempotencyTableSchema); err != nil {
			return fmt.Errorf("create idempotency table: %w", err)
		}
		return nil
	}
	targetColumns := []string{"device_id", "idempotency_key", "payload_hash", "precondition_key", "response_json"}
	if len(columns) == len(targetColumns) {
		complete := true
		for _, column := range targetColumns {
			complete = complete && columns[column]
		}
		if complete {
			return nil
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin idempotency migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DROP INDEX IF EXISTS idempotency_retention`); err != nil {
		return fmt.Errorf("drop legacy idempotency index: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE idempotency_requests RENAME TO idempotency_requests_legacy`); err != nil {
		return fmt.Errorf("rename legacy idempotency table: %w", err)
	}
	if _, err := tx.Exec(idempotencyTableSchema); err != nil {
		return fmt.Errorf("create current idempotency table: %w", err)
	}
	preconditionExpression := `''`
	if columns["precondition_key"] {
		preconditionExpression = "precondition_key"
	}
	copyStatement := fmt.Sprintf(`
INSERT INTO idempotency_requests(device_id, idempotency_key, payload_hash, precondition_key, response_json)
SELECT device_id, idempotency_key, payload_hash, %s, response_json
FROM idempotency_requests_legacy`, preconditionExpression)
	if _, err := tx.Exec(copyStatement); err != nil {
		return fmt.Errorf("copy legacy idempotency responses: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE idempotency_requests_legacy`); err != nil {
		return fmt.Errorf("drop legacy idempotency table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit idempotency migration: %w", err)
	}
	return nil
}

func (s *SQLite) Close() error { return s.db.Close() }

type persistedResult struct {
	DeviceID                 string   `json:"device_id"`
	Hostname                 string   `json:"hostname"`
	Addresses                []string `json:"addresses"`
	Generation               int64    `json:"generation"`
	LeaseExpiresNS           int64    `json:"lease_expires_ns"`
	UpdatedAtNS              int64    `json:"updated_at_ns"`
	RenewAfterSeconds        int64    `json:"renew_after_seconds,omitempty"`
	OriginAppliedGeneration  int64    `json:"origin_applied_generation"`
	PublicObservedGeneration int64    `json:"public_observed_generation"`
	LastPublicationError     string   `json:"last_publication_error"`
}

func persistIntent(intent model.Intent, renewAfterSeconds int64) persistedResult {
	addresses := make([]string, 0, len(intent.Addresses))
	for _, addr := range model.CanonicalAddresses(intent.Addresses) {
		addresses = append(addresses, addr.String())
	}
	return persistedResult{
		DeviceID: intent.DeviceID, Hostname: intent.Hostname, Addresses: addresses,
		Generation: intent.Generation, LeaseExpiresNS: intent.LeaseExpiresAt.UnixNano(),
		UpdatedAtNS: intent.UpdatedAt.UnixNano(), RenewAfterSeconds: renewAfterSeconds,
		OriginAppliedGeneration:  intent.OriginAppliedGeneration,
		PublicObservedGeneration: intent.PublicObservedGeneration,
		LastPublicationError:     intent.LastPublicationError,
	}
}

func (p persistedResult) intent() (model.Intent, error) {
	addresses := make([]netip.Addr, 0, len(p.Addresses))
	for _, value := range p.Addresses {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return model.Intent{}, fmt.Errorf("decode stored address %q: %w", value, err)
		}
		addresses = append(addresses, addr)
	}
	return model.Intent{
		DeviceID: p.DeviceID, Hostname: p.Hostname, Addresses: addresses,
		Generation: p.Generation, LeaseExpiresAt: time.Unix(0, p.LeaseExpiresNS).UTC(),
		UpdatedAt: time.Unix(0, p.UpdatedAtNS).UTC(), OriginAppliedGeneration: p.OriginAppliedGeneration,
		PublicObservedGeneration: p.PublicObservedGeneration,
		LastPublicationError:     p.LastPublicationError,
	}, nil
}

func encodeAddresses(addresses []netip.Addr) (string, error) {
	values := make([]string, 0, len(addresses))
	for _, addr := range model.CanonicalAddresses(addresses) {
		values = append(values, addr.String())
	}
	payload, err := json.Marshal(values)
	return string(payload), err
}

func decodeAddresses(payload string) ([]netip.Addr, error) {
	var values []string
	if err := json.Unmarshal([]byte(payload), &values); err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

func (s *SQLite) UpsertIntent(ctx context.Context, request UpsertRequest) (UpsertResult, error) {
	request.Now = request.Now.UTC()
	request.Addresses = model.CanonicalAddresses(request.Addresses)
	hash := model.AddressesHash(request.Addresses)
	preconditionKey := request.Precondition.key()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return UpsertResult{}, fmt.Errorf("begin desired-state transaction: %w", err)
	}
	defer tx.Rollback()

	var storedHash, storedPrecondition, responseJSON string
	err = tx.QueryRowContext(ctx, `SELECT payload_hash, precondition_key, response_json FROM idempotency_requests WHERE device_id = ? AND idempotency_key = ?`, request.DeviceID, request.IdempotencyKey).Scan(&storedHash, &storedPrecondition, &responseJSON)
	if err == nil {
		// A blank precondition identifies a response migrated from the original
		// pre-ETag pilot. Its body binding remains authoritative, while all newly
		// accepted keys bind both body and precondition.
		if storedHash != hash || (storedPrecondition != "" && storedPrecondition != preconditionKey) {
			return UpsertResult{}, ErrIdempotencyConflict
		}
		var persisted persistedResult
		if err := json.Unmarshal([]byte(responseJSON), &persisted); err != nil {
			return UpsertResult{}, fmt.Errorf("decode idempotent response: %w", err)
		}
		intent, err := persisted.intent()
		if err != nil {
			return UpsertResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return UpsertResult{}, err
		}
		renewAfterSeconds := persisted.RenewAfterSeconds
		if renewAfterSeconds <= 0 {
			// Legacy pilot rows predate persistence of response policy. They can
			// only use the request's current value; all newly accepted requests
			// retain the original response value indefinitely.
			renewAfterSeconds = request.RenewAfterSeconds
		}
		return UpsertResult{Intent: intent, RenewAfterSeconds: renewAfterSeconds, Replay: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return UpsertResult{}, fmt.Errorf("read idempotency key: %w", err)
	}
	if !request.Precondition.valid() {
		return UpsertResult{}, ErrPreconditionRequired
	}

	current, found, err := scanIntent(tx.QueryRowContext(ctx, `
SELECT device_id, hostname, addresses_json, generation, lease_expires_ns,
       updated_at_ns, origin_applied_generation, public_observed_generation,
       last_publication_error
FROM intents WHERE device_id = ?`, request.DeviceID))
	if err != nil {
		return UpsertResult{}, err
	}
	expiredDuringWrite := found && len(current.Addresses) > 0 && !request.Now.Before(current.LeaseExpiresAt)
	if expiredDuringWrite {
		current.Addresses = []netip.Addr{}
		current.Generation++
		current.UpdatedAt = request.Now
		current.LastPublicationError = ""
		if _, err := tx.ExecContext(ctx, `
UPDATE intents SET addresses_json = '[]', generation = ?, updated_at_ns = ?, last_publication_error = ''
WHERE device_id = ?`, current.Generation, current.UpdatedAt.UnixNano(), current.DeviceID); err != nil {
			return UpsertResult{}, fmt.Errorf("realize expired lease: %w", err)
		}
	}
	preconditionFailed := false
	if request.Precondition.RequireAbsent {
		if found {
			preconditionFailed = true
		}
	} else if !found || current.Generation != request.Precondition.ExpectedGeneration {
		preconditionFailed = true
	}
	if preconditionFailed {
		if expiredDuringWrite {
			if err := tx.Commit(); err != nil {
				return UpsertResult{}, fmt.Errorf("commit lease expiry: %w", err)
			}
		}
		return UpsertResult{}, ErrPreconditionFailed
	}
	addressesJSON, err := encodeAddresses(request.Addresses)
	if err != nil {
		return UpsertResult{}, err
	}
	leaseExpires := request.Now.Add(request.LeaseDuration)
	var next model.Intent
	if !found {
		next = model.Intent{DeviceID: request.DeviceID, Hostname: request.Hostname, Addresses: request.Addresses, Generation: 1, LeaseExpiresAt: leaseExpires, UpdatedAt: request.Now}
		_, err = tx.ExecContext(ctx, `
INSERT INTO intents(device_id, hostname, addresses_json, generation, lease_expires_ns, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?)`, next.DeviceID, next.Hostname, addressesJSON, next.Generation, next.LeaseExpiresAt.UnixNano(), next.UpdatedAt.UnixNano())
	} else {
		if current.Hostname != request.Hostname {
			return UpsertResult{}, fmt.Errorf("device identity mapped to a different hostname")
		}
		next = current
		next.Addresses = request.Addresses
		next.LeaseExpiresAt = leaseExpires
		next.UpdatedAt = request.Now
		changed := !model.AddressesEqual(current.Addresses, request.Addresses) || !request.Now.Before(current.LeaseExpiresAt)
		if changed {
			next.Generation++
			next.LastPublicationError = ""
		}
		_, err = tx.ExecContext(ctx, `
UPDATE intents SET addresses_json = ?, generation = ?, lease_expires_ns = ?, updated_at_ns = ?, last_publication_error = ?
WHERE device_id = ?`, addressesJSON, next.Generation, next.LeaseExpiresAt.UnixNano(), next.UpdatedAt.UnixNano(), next.LastPublicationError, next.DeviceID)
	}
	if err != nil {
		return UpsertResult{}, fmt.Errorf("write desired state: %w", err)
	}
	persistedPayload, err := json.Marshal(persistIntent(next, request.RenewAfterSeconds))
	if err != nil {
		return UpsertResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO idempotency_requests(device_id, idempotency_key, payload_hash, precondition_key, response_json)
VALUES (?, ?, ?, ?, ?)`, request.DeviceID, request.IdempotencyKey, hash, preconditionKey, string(persistedPayload)); err != nil {
		return UpsertResult{}, fmt.Errorf("store idempotent response: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return UpsertResult{}, fmt.Errorf("commit desired state: %w", err)
	}
	return UpsertResult{Intent: next, RenewAfterSeconds: request.RenewAfterSeconds}, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanIntent(row rowScanner) (model.Intent, bool, error) {
	var intent model.Intent
	var addressesJSON string
	var leaseExpiresNS, updatedAtNS int64
	err := row.Scan(&intent.DeviceID, &intent.Hostname, &addressesJSON, &intent.Generation,
		&leaseExpiresNS, &updatedAtNS, &intent.OriginAppliedGeneration,
		&intent.PublicObservedGeneration, &intent.LastPublicationError)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Intent{}, false, nil
	}
	if err != nil {
		return model.Intent{}, false, fmt.Errorf("scan desired state: %w", err)
	}
	addresses, err := decodeAddresses(addressesJSON)
	if err != nil {
		return model.Intent{}, false, fmt.Errorf("decode desired-state addresses: %w", err)
	}
	intent.Addresses = addresses
	intent.LeaseExpiresAt = time.Unix(0, leaseExpiresNS).UTC()
	intent.UpdatedAt = time.Unix(0, updatedAtNS).UTC()
	return intent, true, nil
}

func (s *SQLite) GetIntent(ctx context.Context, deviceID string) (model.Intent, error) {
	intent, found, err := scanIntent(s.db.QueryRowContext(ctx, `
SELECT device_id, hostname, addresses_json, generation, lease_expires_ns,
       updated_at_ns, origin_applied_generation, public_observed_generation,
       last_publication_error
FROM intents WHERE device_id = ?`, deviceID))
	if err != nil {
		return model.Intent{}, err
	}
	if !found {
		return model.Intent{}, ErrNotFound
	}
	return intent, nil
}

func (s *SQLite) ExpireLeases(ctx context.Context, now time.Time) ([]model.Intent, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
SELECT device_id, hostname, addresses_json, generation, lease_expires_ns,
       updated_at_ns, origin_applied_generation, public_observed_generation,
       last_publication_error
FROM intents WHERE lease_expires_ns <= ? AND addresses_json <> '[]' ORDER BY device_id`, now.UnixNano())
	if err != nil {
		return nil, err
	}
	var expired []model.Intent
	for rows.Next() {
		intent, _, err := scanIntent(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		intent.Addresses = []netip.Addr{}
		intent.Generation++
		intent.UpdatedAt = now.UTC()
		intent.LastPublicationError = ""
		expired = append(expired, intent)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, intent := range expired {
		if _, err := tx.ExecContext(ctx, `UPDATE intents SET addresses_json = '[]', generation = ?, updated_at_ns = ?, last_publication_error = '' WHERE device_id = ?`, intent.Generation, intent.UpdatedAt.UnixNano(), intent.DeviceID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return expired, nil
}

func (s *SQLite) list(ctx context.Context, where string, limit int) ([]model.Intent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT device_id, hostname, addresses_json, generation, lease_expires_ns,
       updated_at_ns, origin_applied_generation, public_observed_generation,
       last_publication_error FROM intents WHERE ` + where + ` ORDER BY device_id LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var intents []model.Intent
	for rows.Next() {
		intent, _, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}
	return intents, rows.Err()
}

func (s *SQLite) ListOriginPending(ctx context.Context, limit int) ([]model.Intent, error) {
	return s.list(ctx, `origin_applied_generation < generation`, limit)
}

func (s *SQLite) ListObservationPending(ctx context.Context, limit int) ([]model.Intent, error) {
	return s.list(ctx, `origin_applied_generation >= generation AND public_observed_generation < generation`, limit)
}

func (s *SQLite) mark(ctx context.Context, statement string, args ...any) error {
	if _, err := s.db.ExecContext(ctx, statement, args...); err != nil {
		return fmt.Errorf("update publication status: %w", err)
	}
	return nil
}

func (s *SQLite) MarkOriginApplied(ctx context.Context, deviceID string, generation int64) error {
	return s.mark(ctx, `UPDATE intents SET origin_applied_generation = ?, last_publication_error = '' WHERE device_id = ? AND generation = ?`, generation, deviceID, generation)
}

func (s *SQLite) MarkPubliclyObserved(ctx context.Context, deviceID string, generation int64) error {
	return s.mark(ctx, `UPDATE intents SET public_observed_generation = ? WHERE device_id = ? AND generation = ? AND origin_applied_generation >= ?`, generation, deviceID, generation, generation)
}

func (s *SQLite) MarkPublicationError(ctx context.Context, deviceID string, generation int64, message string) error {
	return s.mark(ctx, `UPDATE intents SET last_publication_error = ? WHERE device_id = ? AND generation = ?`, message, deviceID, generation)
}
