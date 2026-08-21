package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRunDispatchesClosedCommands(t *testing.T) {
	t.Run("sign", func(t *testing.T) {
		called := false
		sign := func(_ context.Context, plan, output string) error {
			called = true
			if plan != "/plan" || output != "/signed" {
				t.Fatalf("sign paths = %q, %q", plan, output)
			}
			return nil
		}
		if code := run(context.Background(), []string{"sign", "--plan", "/plan", "--output", "/signed"}, &bytes.Buffer{}, sign, nil); code != exitOK {
			t.Fatalf("run() = %d, want %d", code, exitOK)
		}
		if !called {
			t.Fatal("sign operation was not called")
		}
	})

	t.Run("finalize", func(t *testing.T) {
		called := false
		finalize := func(plan, signed, output string) error {
			called = true
			if plan != "/plan" || signed != "/signed" || output != "/final" {
				t.Fatalf("finalize paths = %q, %q, %q", plan, signed, output)
			}
			return nil
		}
		args := []string{"finalize", "--plan", "/plan", "--signed", "/signed", "--output", "/final"}
		if code := run(context.Background(), args, &bytes.Buffer{}, nil, finalize); code != exitOK {
			t.Fatalf("run() = %d, want %d", code, exitOK)
		}
		if !called {
			t.Fatal("finalize operation was not called")
		}
	})
}

func TestRunRejectsRuntimeAuthorityArgumentsAndReportsFailures(t *testing.T) {
	for _, args := range [][]string{
		{"sign", "--plan", "/plan", "--output", "/signed", "--key", "/private.pem"},
		{"sign", "--socket", "/tmp/socket", "--plan", "/plan", "--output", "/signed"},
		{"finalize", "--plan", "/plan", "--signed", "/signed"},
	} {
		var diagnostic bytes.Buffer
		if code := run(context.Background(), args, &diagnostic, nil, nil); code != exitUsage {
			t.Fatalf("run(%v) = %d, want usage; diagnostic=%q", args, code, diagnostic.String())
		}
	}

	var diagnostic bytes.Buffer
	want := errors.New("gate denied")
	sign := func(context.Context, string, string) error { return want }
	code := run(context.Background(), []string{"sign", "--plan", "/plan", "--output", "/signed"}, &diagnostic, sign, nil)
	if code != exitFailure || !bytes.Contains(diagnostic.Bytes(), []byte(want.Error())) {
		t.Fatalf("run failure = %d, %q", code, diagnostic.String())
	}
}
