// Package clock provides the opt-in, file-backed clock used by integration
// tests. Production callers leave the clock path empty and use the wall clock.
package clock

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// File reloads an RFC3339 timestamp on every call to Now. A transient read or
// parse failure retains the last valid instant so a partial test-clock write
// cannot unexpectedly expire leases. The error callback is invoked once for
// each distinct failure and again with nil when the clock recovers.
type File struct {
	path    string
	onError func(error)

	mu          sync.Mutex
	last        time.Time
	lastProblem string
}

// New returns time.Now when path is empty. A non-empty path must contain one
// RFC3339 or RFC3339Nano timestamp and is intended only for controlled tests.
func New(path string, onError func(error)) (func() time.Time, error) {
	if strings.TrimSpace(path) == "" {
		return time.Now, nil
	}
	file, err := Open(path, onError)
	if err != nil {
		return nil, err
	}
	return file.Now, nil
}

// Open validates the clock file before returning a source.
func Open(path string, onError func(error)) (*File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("clock file path is required")
	}
	instant, err := read(path)
	if err != nil {
		return nil, err
	}
	return &File{path: path, onError: onError, last: instant}, nil
}

// Now returns the latest valid instant in UTC.
func (f *File) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	instant, err := read(f.path)
	if err != nil {
		problem := err.Error()
		if problem != f.lastProblem && f.onError != nil {
			f.onError(err)
		}
		f.lastProblem = problem
		return f.last
	}
	if f.lastProblem != "" && f.onError != nil {
		f.onError(nil)
	}
	f.lastProblem = ""
	f.last = instant
	return instant
}

func read(path string) (time.Time, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("read clock file %q: %w", path, err)
	}
	value := strings.TrimSpace(string(payload))
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse clock file %q as RFC3339 timestamp: %w", path, err)
	}
	return instant.UTC(), nil
}
