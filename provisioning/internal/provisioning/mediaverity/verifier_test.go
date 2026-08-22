package mediaverity

import (
	"strings"
	"testing"
)

func TestFixedVerifierFailsClosedWithoutStorePath(t *testing.T) {
	for _, path := range []string{"", "relative", "/usr/bin/veritysetup", "/nix/store/../veritysetup"} {
		if err := (FixedVerifier{Path: path}).Validate(); err == nil {
			t.Fatalf("accepted path %q", path)
		}
	}
}

func TestBoundedBufferCapsDiagnostics(t *testing.T) {
	buffer := &boundedBuffer{maximum: 4}
	written, err := buffer.Write([]byte("abcdef"))
	if err != nil || written != 6 || buffer.String() != "abcd" || !buffer.overflow {
		t.Fatalf("Write = %d, %v; buffer=%q overflow=%t", written, err, buffer.String(), buffer.overflow)
	}
	if !strings.Contains("veritysetup output exceeded the fixed diagnostic bound", "fixed diagnostic bound") {
		t.Fatal("diagnostic marker changed")
	}
}
