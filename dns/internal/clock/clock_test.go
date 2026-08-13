package clock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileClockReloadsAndRetainsLastValidInstant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock")
	writeClock(t, path, "2099-01-01T00:00:00Z\n")

	var notifications []string
	file, err := Open(path, func(err error) {
		if err == nil {
			notifications = append(notifications, "recovered")
			return
		}
		notifications = append(notifications, err.Error())
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := file.Now(); !got.Equal(initial) {
		t.Fatalf("initial time = %s, want %s", got, initial)
	}

	writeClock(t, path, "not-a-timestamp\n")
	if got := file.Now(); !got.Equal(initial) {
		t.Fatalf("invalid update changed time to %s", got)
	}
	// Re-reading the same bad value must not flood the error callback.
	_ = file.Now()
	if len(notifications) != 1 || !strings.Contains(notifications[0], "as RFC3339 timestamp") {
		t.Fatalf("unexpected error notifications: %q", notifications)
	}

	advanced := initial.Add(time.Minute)
	writeClock(t, path, advanced.Format(time.RFC3339Nano)+"\n")
	if got := file.Now(); !got.Equal(advanced) {
		t.Fatalf("advanced time = %s, want %s", got, advanced)
	}
	if len(notifications) != 2 || notifications[1] != "recovered" {
		t.Fatalf("unexpected recovery notifications: %q", notifications)
	}
}

func TestOpenRejectsMissingAndMalformedClockFiles(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), nil); err == nil || !strings.Contains(err.Error(), "read clock file") {
		t.Fatalf("missing file error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "clock")
	writeClock(t, path, "tomorrow")
	if _, err := Open(path, nil); err == nil || !strings.Contains(err.Error(), "as RFC3339 timestamp") {
		t.Fatalf("malformed file error = %v", err)
	}
}

func TestNewWithoutPathUsesWallClock(t *testing.T) {
	before := time.Now()
	now, err := New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("wall-clock result %s outside [%s, %s]", got, before, after)
	}
}

func writeClock(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
