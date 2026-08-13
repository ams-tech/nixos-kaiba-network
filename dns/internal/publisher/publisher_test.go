package publisher

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/model"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

type writeCall struct {
	hostname  string
	addresses []netip.Addr
	ttl       uint32
}

type fakeWriter struct {
	calls []writeCall
	err   error
}

func (w *fakeWriter) ReplaceAddressRRsets(_ context.Context, hostname string, addresses []netip.Addr, ttl uint32) error {
	w.calls = append(w.calls, writeCall{hostname: hostname, addresses: append([]netip.Addr(nil), addresses...), ttl: ttl})
	return w.err
}

type fakeObserver struct {
	observed bool
	calls    int
}

func (o *fakeObserver) ObserveAddressRRsets(context.Context, string, []netip.Addr) (bool, error) {
	o.calls++
	return o.observed, nil
}

func publisherStore(t *testing.T) *store.SQLite {
	t.Helper()
	database, err := store.OpenSQLite(filepath.Join(t.TempDir(), "publisher.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func seedIntent(t *testing.T, database *store.SQLite, now time.Time) {
	t.Helper()
	_, err := database.UpsertIntent(context.Background(), store.UpsertRequest{
		DeviceID: "001", Hostname: "pi-001.kaiba.network",
		Addresses:      []netip.Addr{netip.MustParseAddr("203.0.113.42")},
		IdempotencyKey: "seed", Precondition: store.RequireAbsent(),
		Now: now, LeaseDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServicePublishesObservesAndExpires(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	database := publisherStore(t)
	seedIntent(t, database, now)
	writer := &fakeWriter{}
	observer := &fakeObserver{observed: true}
	service := &Service{Store: database, DNS: writer, Observer: observer, TTL: 300, Now: func() time.Time { return now }}
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(writer.calls) != 1 || writer.calls[0].hostname != "pi-001.kaiba.network" || writer.calls[0].ttl != 300 {
		t.Fatalf("unexpected write calls: %+v", writer.calls)
	}
	intent, err := database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status() != model.StatusPubliclyObserved || observer.calls != 1 {
		t.Fatalf("publication status = %s, observer calls = %d", intent.Status(), observer.calls)
	}

	service.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(writer.calls) != 2 || len(writer.calls[1].addresses) != 0 {
		t.Fatalf("lease expiry did not publish deletion: %+v", writer.calls)
	}
	intent, err = database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Generation != 2 || intent.Status() != model.StatusPubliclyObserved || len(intent.Addresses) != 0 {
		t.Fatalf("unexpected expired intent: %+v", intent)
	}
}

func TestServiceRetainsAcceptedStateWhenOriginFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	database := publisherStore(t)
	seedIntent(t, database, now)
	writer := &fakeWriter{err: errors.New("origin unavailable")}
	service := &Service{Store: database, DNS: writer, TTL: 300, Now: func() time.Time { return now }}
	if err := service.RunOnce(ctx); err == nil {
		t.Fatal("origin failure was not returned")
	}
	intent, err := database.GetIntent(ctx, "001")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status() != model.StatusAccepted || intent.LastPublicationError != "origin unavailable" {
		t.Fatalf("unexpected failed publication state: %+v", intent)
	}
	pending, err := database.ListOriginPending(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("failed publication was not retained for retry: %+v, %v", pending, err)
	}
}

type inactiveLeadership struct{}

func (inactiveLeadership) Acquire(context.Context) (func(), bool, error) {
	return func() {}, false, nil
}

func TestServiceDoesNothingWithoutLeadership(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	database := publisherStore(t)
	seedIntent(t, database, now)
	writer := &fakeWriter{}
	service := &Service{Store: database, DNS: writer, TTL: 300, Leadership: inactiveLeadership{}, Now: func() time.Time { return now }}
	if err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(writer.calls) != 0 {
		t.Fatal("non-leader mutated DNS")
	}
}
