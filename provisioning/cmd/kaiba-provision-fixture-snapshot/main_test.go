//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunRequiresExactFlagsAndCreatesSnapshot(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "snapshot.img")
	if err := os.WriteFile(sourcePath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"--source", sourcePath,
		"--destination", destinationPath,
		"--expected-size", "7",
	}); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "fixture" {
		t.Fatalf("snapshot = %q", actual)
	}
}

func TestRunRejectsMissingFlagsAndPositionalArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"--source", "/tmp/source", "--destination", "/tmp/destination"},
		{"--source", "/tmp/source", "--destination", "/tmp/destination", "--expected-size", "0"},
		{"--source", "/tmp/source", "--destination", "/tmp/destination", "--expected-size", "0", "extra"},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("run(%q) succeeded", arguments)
		}
	}
}
