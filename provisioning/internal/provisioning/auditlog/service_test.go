package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAppendPersistsHashChainAndReplaysIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	service, err := NewService(FileStore{Path: path}, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := testAppendRequest("event-1", "idem-1", ResultIntentRecorded)
	first, err := service.Append(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.PreviousEventHash != "" || !validDigest(first.EventHash) || !validDigest(first.ReceiptID) {
		t.Fatalf("first receipt = %#v", first)
	}
	now = now.Add(time.Second)
	secondRequest := testAppendRequest("event-2", "idem-2", ResultSucceeded)
	secondRequest.Event.OutputDigest = testDigest("b")
	second, err := service.Append(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 || second.PreviousEventHash != first.EventHash {
		t.Fatalf("second receipt = %#v", second)
	}

	reopened, err := NewService(FileStore{Path: path}, WithClock(func() time.Time { return now.Add(time.Hour) }))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := reopened.Append(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != first {
		t.Fatalf("replayed receipt = %#v, want %#v", replayed, first)
	}
	records := reopened.Records("transaction-1")
	if len(records) != 2 || records[1].PreviousEventHash != records[0].EventHash {
		t.Fatalf("records = %#v", records)
	}
	if mode := fileMode(t, path); mode.Perm() != 0o600 {
		t.Fatalf("audit file mode = %o", mode.Perm())
	}
}

func TestAppendRejectsChangedIdempotencyInputAndDuplicateEventID(t *testing.T) {
	service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	request := testAppendRequest("event-1", "idem-1", ResultIntentRecorded)
	if _, err := service.Append(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Event.Stage = "different-stage"
	if _, err := service.Append(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotency error = %v", err)
	}
	duplicateEvent := request
	duplicateEvent.IdempotencyKey = "idem-2"
	if _, err := service.Append(context.Background(), duplicateEvent); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("duplicate event error = %v", err)
	}
	if got := len(service.Records("")); got != 1 {
		t.Fatalf("record count after rejected appends = %d", got)
	}
}

func TestAuditStoreDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	service, err := NewService(FileStore{Path: path}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), testAppendRequest("event-1", "idem-1", ResultSucceeded)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state.Records[0].Event.Result = ResultFailed
	tampered, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(FileStore{Path: path}); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("tampered store error = %v", err)
	}
}

func TestAppendIsSerializedUnderConcurrency(t *testing.T) {
	service, err := NewService(&MemoryStore{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	const count = 24
	var wait sync.WaitGroup
	errorsCh := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := testAppendRequest("event-"+decimal(index), "idem-"+decimal(index), ResultSucceeded)
			_, err := service.Append(context.Background(), request)
			errorsCh <- err
		}(index)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	records := service.Records("")
	if len(records) != count {
		t.Fatalf("record count = %d", len(records))
	}
	for index, record := range records {
		if record.Sequence != uint64(index+1) {
			t.Fatalf("sequence %d = %d", index, record.Sequence)
		}
		if index > 0 && record.PreviousEventHash != records[index-1].EventHash {
			t.Fatalf("record %d does not link to predecessor", index)
		}
	}
}

func TestDecodeStrictRejectsDuplicateAndSecretBearingFields(t *testing.T) {
	var request AppendRequest
	duplicate := []byte(`{"schema_version":"a","schema_version":"b"}`)
	if err := DecodeStrict(duplicate, &request); err == nil {
		t.Fatal("duplicate field was accepted")
	}
	unknownSecret := []byte(`{"schema_version":"x","idempotency_key":"i","event":{},"private_key":"secret"}`)
	if err := DecodeStrict(unknownSecret, &request); err == nil {
		t.Fatal("unknown secret-bearing field was accepted")
	}
}

func testAppendRequest(eventID, idempotencyKey, result string) AppendRequest {
	return AppendRequest{
		SchemaVersion:  AppendRequestSchemaVersion,
		IdempotencyKey: idempotencyKey,
		Event: Event{
			SchemaVersion: EventSchemaVersion, PolicyVersion: DefaultPolicyVersion,
			EventID: eventID, TransactionID: "transaction-1", StationID: "station-1", LaneID: "lane-1",
			Stage: "ownership_commit", FenceEpoch: 1, InputDigest: testDigest("a"), Result: result,
			Actors:                []Actor{{ID: "operator-1", Role: "operator"}},
			TimeEvidence:          TimeEvidence{StationTime: fixedClock()(), ClockStatus: "synchronized"},
			ObservationReferences: []ObservationReference{{Kind: "probe", Digest: testDigest("c"), URI: "kaiba-evidence://transaction-1/probe"}},
		},
	}
}

func testDigest(character string) string {
	result := "sha256:"
	for len(result) < len("sha256:")+64 {
		result += character
	}
	return result
}

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) }
}

func decimal(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return string(digits[value/10]) + string(digits[value%10])
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
