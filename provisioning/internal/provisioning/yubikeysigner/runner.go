package yubikeysigner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

const maxDiagnosticBytes = 4096

// Invocation is a complete, immutable process invocation. The signer builds
// every field itself; callers cannot add flags, providers, environment
// variables, key selectors, or credential values.
type Invocation struct {
	Path string
	Args []string
	Env  []string
}

// Result contains bounded process output. Signatures are exchanged only via
// private temporary files, never through these diagnostic streams.
type Result struct {
	Stdout []byte
	Stderr []byte
}

// Runner exists so the exact OpenSSL process contract can be tested without a
// YubiKey. Production uses ExecRunner.
type Runner interface {
	Run(context.Context, Invocation) (Result, error)
}

// ExecRunner executes an absolute command without a shell or inherited
// environment. stdin is /dev/null, so a broken provider configuration cannot
// fall back to an interactive PIN prompt.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, invocation Invocation) (Result, error) {
	command := exec.CommandContext(ctx, invocation.Path, invocation.Args...)
	command.Env = append([]string(nil), invocation.Env...)
	command.Dir = "/"
	command.WaitDelay = 2 * time.Second

	stdout := newBoundedBuffer(maxDiagnosticBytes)
	stderr := newBoundedBuffer(maxDiagnosticBytes)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
	}
	if stdout.Overflowed() || stderr.Overflowed() {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, errors.New("process output exceeded limit")
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

// boundedBuffer keeps draining after the limit is reached so a child cannot
// deadlock on a full pipe. Overflow is nevertheless a hard failure.
type boundedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = b.buffer.Write(data[:remaining])
	}
	if len(data) > remaining {
		b.overflow = true
	}
	return len(data), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func (b *boundedBuffer) Overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}
