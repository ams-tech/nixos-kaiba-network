package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/model"
)

func testSQLite(t *testing.T) *SQLite {
	t.Helper()
	database, err := OpenSQLite(filepath.Join(t.TempDir(), "desired-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestSQLiteUsesWAL(t *testing.T) {
	t.Parallel()
	database := testSQLite(t)
	var mode string
	if err := database.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal mode = %q, want wal", mode)
	}
}

func TestSQLitePreservesPrecreatedSharedModeForSidecars(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "desired-state.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// The caller's umask may have removed group write during OpenFile. The
	// NixOS module's tmpfiles rule likewise repairs the main database to this
	// exact mode before either service opens it.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}

	database, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("stat SQLite file %q: %v", suffix, err)
		}
		if got := info.Mode().Perm(); got != 0o660 {
			t.Errorf("SQLite file %q mode = %04o, want 0660", suffix, got)
		}
	}
}

func TestSQLiteConcurrentOpenMigratesOnce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "desired-state.db")
	const openers = 8
	start := make(chan struct{})
	results := make(chan *SQLite, openers)
	errs := make(chan error, openers)
	var workers sync.WaitGroup
	workers.Add(openers)
	for range openers {
		go func() {
			defer workers.Done()
			<-start
			database, err := OpenSQLite(path)
			if err != nil {
				errs <- err
				return
			}
			results <- database
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent OpenSQLite: %v", err)
	}
	for database := range results {
		if err := database.Close(); err != nil {
			t.Errorf("close concurrent database: %v", err)
		}
	}
	if t.Failed() {
		return
	}
	database, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open migrated database: %v", err)
	}
	defer database.Close()
	var count int
	if err := database.db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'idempotency_requests'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("idempotency table count = %d, want 1", count)
	}
}

func TestSQLiteDesiredStateLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testSQLite(t)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	firstAddress := netip.MustParseAddr("203.0.113.42")
	request := UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network", Addresses: []netip.Addr{firstAddress},
		IdempotencyKey: "request-1", Precondition: RequireAbsent(),
		Now: now, LeaseDuration: 24 * time.Hour,
	}
	first, err := database.UpsertIntent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replay || first.Intent.Generation != 1 || first.Intent.Status() != model.StatusAccepted {
		t.Fatalf("unexpected initial result: %+v", first)
	}

	replay, err := database.UpsertIntent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || !replay.Intent.LeaseExpiresAt.Equal(first.Intent.LeaseExpiresAt) {
		t.Fatalf("idempotent response changed: %+v", replay)
	}
	conflict := request
	conflict.Addresses = []netip.Addr{netip.MustParseAddr("203.0.113.43")}
	if _, err := database.UpsertIntent(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("got %v, want ErrIdempotencyConflict", err)
	}
	changedPrecondition := request
	changedPrecondition.Precondition = MatchGeneration(1)
	if _, err := database.UpsertIntent(ctx, changedPrecondition); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed precondition got %v, want ErrIdempotencyConflict", err)
	}

	if err := database.MarkOriginApplied(ctx, "001", 1); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkPubliclyObserved(ctx, "001", 1); err != nil {
		t.Fatal(err)
	}
	renewal := request
	renewal.IdempotencyKey = "request-2"
	renewal.Precondition = MatchGeneration(1)
	renewal.Now = now.Add(6 * time.Hour)
	renewed, err := database.UpsertIntent(ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Intent.Generation != 1 || renewed.Intent.Status() != model.StatusPubliclyObserved {
		t.Fatalf("unchanged renewal caused publication: %+v", renewed.Intent)
	}
	if !renewed.Intent.LeaseExpiresAt.Equal(renewal.Now.Add(24 * time.Hour)) {
		t.Fatal("renewal did not extend lease")
	}
	pendingAfterRenewal, err := database.ListOriginPending(ctx, 10)
	if err != nil || len(pendingAfterRenewal) != 0 {
		t.Fatalf("unchanged renewal scheduled a DNS mutation: %+v, %v", pendingAfterRenewal, err)
	}

	changed := renewal
	changed.IdempotencyKey = "request-3"
	changed.Now = now.Add(7 * time.Hour)
	changed.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::42"), firstAddress}
	updated, err := database.UpsertIntent(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Intent.Generation != 2 || updated.Intent.Status() != model.StatusAccepted {
		t.Fatalf("changed update did not create a generation: %+v", updated.Intent)
	}
	staleReplay, err := database.UpsertIntent(ctx, request)
	if err != nil || !staleReplay.Replay || staleReplay.Intent.Generation != 1 {
		t.Fatalf("stale replay did not return its original result: %+v, %v", staleReplay, err)
	}
	current, err := database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation != 2 || !model.AddressesEqual(current.Addresses, changed.Addresses) {
		t.Fatalf("stale replay mutated current desired state: %+v", current)
	}
	staleDistinct := request
	staleDistinct.IdempotencyKey = "stale-distinct"
	staleDistinct.Precondition = MatchGeneration(1)
	if _, err := database.UpsertIntent(ctx, staleDistinct); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("distinct stale request got %v, want ErrPreconditionFailed", err)
	}
	current, err = database.GetIntent(ctx, "001")
	if err != nil || current.Generation != 2 || !model.AddressesEqual(current.Addresses, changed.Addresses) {
		t.Fatalf("distinct stale request mutated current desired state: %+v, %v", current, err)
	}
	pending, err := database.ListOriginPending(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Generation != 2 {
		t.Fatalf("unexpected pending publication: %+v, %v", pending, err)
	}

	expired, err := database.ExpireLeases(ctx, changed.Now.Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Generation != 3 || len(expired[0].Addresses) != 0 {
		t.Fatalf("unexpected expiry: %+v", expired)
	}
	preExpiryRequest := changed
	preExpiryRequest.IdempotencyKey = "pre-expiry"
	preExpiryRequest.Now = changed.Now.Add(25 * time.Hour)
	preExpiryRequest.Precondition = MatchGeneration(2)
	if _, err := database.UpsertIntent(ctx, preExpiryRequest); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("pre-expiry ETag got %v, want ErrPreconditionFailed", err)
	}
	again, err := database.ExpireLeases(ctx, changed.Now.Add(26*time.Hour))
	if err != nil || len(again) != 0 {
		t.Fatalf("expiry was not idempotent: %+v, %v", again, err)
	}
}

func TestSQLiteStalePublicationMarksCannotAdvanceNewGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testSQLite(t)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	base := UpsertRequest{DeviceID: "001", Hostname: "pi-001.kaiba.network", Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, IdempotencyKey: "one", Precondition: RequireAbsent(), Now: now, LeaseDuration: time.Hour}
	if _, err := database.UpsertIntent(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.Addresses = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	base.IdempotencyKey = "two"
	base.Precondition = MatchGeneration(1)
	base.Now = now.Add(time.Minute)
	if _, err := database.UpsertIntent(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkOriginApplied(ctx, "001", 1); err != nil {
		t.Fatal(err)
	}
	intent, err := database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status() != model.StatusAccepted {
		t.Fatalf("stale completion advanced status to %s", intent.Status())
	}
}

func TestSQLiteRetainsExactIdempotencyResponseIndefinitely(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testSQLite(t)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	request := UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network",
		Addresses:      []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		IdempotencyKey: "old", Precondition: RequireAbsent(),
		Now: now, LeaseDuration: 24 * time.Hour,
	}
	original := request
	first, err := database.UpsertIntent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExpireLeases(ctx, now.Add(2*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "new"
	request.Precondition = MatchGeneration(2)
	request.Addresses = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	request.Now = now.Add(365 * 24 * time.Hour)
	if _, err := database.UpsertIntent(ctx, request); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM idempotency_requests`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("retained idempotency rows = %d, want 2", count)
	}
	original.Now = now.Add(365*24*time.Hour + time.Hour)
	replay, err := database.UpsertIntent(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || !reflect.DeepEqual(replay.Intent, first.Intent) {
		t.Fatalf("late replay changed original result: first=%+v replay=%+v", first, replay)
	}
	current, err := database.GetIntent(ctx, "001")
	if err != nil || current.Generation != 3 || !model.AddressesEqual(current.Addresses, request.Addresses) {
		t.Fatalf("late replay mutated current intent: %+v, %v", current, err)
	}
}

func TestSQLiteRequiresWritePrecondition(t *testing.T) {
	t.Parallel()
	database := testSQLite(t)
	_, err := database.UpsertIntent(context.Background(), UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network",
		Addresses:      []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		IdempotencyKey: "missing", Now: time.Now(), LeaseDuration: time.Hour,
	})
	if !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("got %v, want ErrPreconditionRequired", err)
	}
}

func TestSQLiteExpiredLeaseInvalidatesOldGenerationBeforeSweep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testSQLite(t)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	base := UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network",
		Addresses:      []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		IdempotencyKey: "initial", Precondition: RequireAbsent(),
		Now: now, LeaseDuration: time.Hour,
	}
	if _, err := database.UpsertIntent(ctx, base); err != nil {
		t.Fatal(err)
	}
	delayed := base
	delayed.IdempotencyKey = "delayed"
	delayed.Precondition = MatchGeneration(1)
	delayed.Now = now.Add(2 * time.Hour)
	delayed.Addresses = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	if _, err := database.UpsertIntent(ctx, delayed); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("expired ETag got %v, want ErrPreconditionFailed", err)
	}
	expired, err := database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if expired.Generation != 2 || len(expired.Addresses) != 0 {
		t.Fatalf("lease expiry was not committed with stale rejection: %+v", expired)
	}
	fresh := delayed
	fresh.IdempotencyKey = "fresh"
	fresh.Precondition = MatchGeneration(2)
	result, err := database.UpsertIntent(ctx, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if result.Intent.Generation != 3 || !model.AddressesEqual(result.Intent.Addresses, fresh.Addresses) {
		t.Fatalf("fresh post-expiry request was not accepted: %+v", result.Intent)
	}
}

func TestSQLiteMigratesLegacyRetentionTableWithoutLosingResponses(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
CREATE TABLE idempotency_requests (
  device_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  precondition_key TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  retain_until_ns INTEGER NOT NULL,
  PRIMARY KEY (device_id, idempotency_key)
);
CREATE INDEX idempotency_retention ON idempotency_requests(retain_until_ns);`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	addresses := []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	originalIntent := model.Intent{
		DeviceID: "001", Hostname: "pi-001.kaiba.network", Addresses: addresses,
		Generation: 1, LeaseExpiresAt: now.Add(24 * time.Hour), UpdatedAt: now,
	}
	responseJSON, err := json.Marshal(persistIntent(originalIntent, 21600))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
INSERT INTO idempotency_requests(
  device_id, idempotency_key, payload_hash, precondition_key, response_json,
  created_at_ns, retain_until_ns
) VALUES (?, ?, ?, ?, ?, ?, ?)`, "001", "legacy", model.AddressesHash(addresses), "if-none-match:*", string(responseJSON), now.UnixNano(), now.Add(time.Hour).UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	result, err := database.UpsertIntent(context.Background(), UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network", Addresses: addresses,
		IdempotencyKey: "legacy", Precondition: RequireAbsent(),
		Now: now.Add(365 * 24 * time.Hour), LeaseDuration: 24 * time.Hour,
		RenewAfterSeconds: 10800,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Replay || !reflect.DeepEqual(result.Intent, originalIntent) || result.RenewAfterSeconds != 21600 {
		t.Fatalf("migration lost exact response: %+v", result)
	}
	rows, err := database.db.Query(`PRAGMA table_info(idempotency_requests)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == "created_at_ns" || name == "retain_until_ns" {
			t.Fatalf("legacy retention column %q remains", name)
		}
	}
}
