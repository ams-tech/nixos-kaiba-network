package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestRunRejectsRuntimeArguments(t *testing.T) {
	called := false
	factory := func(io.Writer) (func(context.Context) error, io.Closer, error) {
		called = true
		return nil, nil, nil
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"--socket", "/tmp/client-selected"}, &stderr, factory); code != exitUsage {
		t.Fatalf("run() = %d", code)
	}
	if called || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("factory/stderr = %v/%q", called, stderr.String())
	}
}

func TestRunServesAndClosesState(t *testing.T) {
	closed := false
	factory := func(io.Writer) (func(context.Context) error, io.Closer, error) {
		return func(context.Context) error { return nil }, closerFunc(func() error {
			closed = true
			return nil
		}), nil
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr, factory); code != exitOK || !closed || stderr.Len() != 0 {
		t.Fatalf("run/closed/stderr = %d/%v/%q", code, closed, stderr.String())
	}
}

func TestRunFailsClosedOnConfigurationAndServerErrors(t *testing.T) {
	tests := []serverFactory{
		func(io.Writer) (func(context.Context) error, io.Closer, error) {
			return nil, nil, errors.New("bad registry")
		},
		func(io.Writer) (func(context.Context) error, io.Closer, error) {
			return func(context.Context) error { return errors.New("socket failed") }, nil, nil
		},
	}
	for _, factory := range tests {
		var stderr bytes.Buffer
		if code := run(context.Background(), nil, &stderr, factory); code != exitInternal || stderr.Len() == 0 {
			t.Fatalf("run/stderr = %d/%q", code, stderr.String())
		}
	}
}

func TestParseFixedArgumentsIsStrict(t *testing.T) {
	arguments, err := parseFixedArguments(`["--module","/nix/store/fixed/libykcs11.so"]`)
	if err != nil || len(arguments) != 2 {
		t.Fatalf("arguments/error = %#v/%v", arguments, err)
	}
	for _, value := range []string{"", `null`, `{}`, `[] {}`} {
		if _, err := parseFixedArguments(value); err == nil {
			t.Fatalf("parseFixedArguments(%q) succeeded", value)
		}
	}
}
