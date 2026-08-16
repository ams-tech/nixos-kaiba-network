package signing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSignatureHexIsStrict(t *testing.T) {
	signature := strings.Repeat("ab", RSASignatureBytes)
	for _, input := range []string{signature, signature + "\n"} {
		decoded, err := ParseSignatureHex([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded) != RSASignatureBytes {
			t.Fatalf("decoded length = %d", len(decoded))
		}
	}
	for _, invalid := range []string{
		strings.ToUpper(signature), signature + "\r\n", signature + " ", signature[:len(signature)-1], "zz" + signature[2:],
	} {
		if _, err := ParseSignatureHex([]byte(invalid)); err == nil {
			t.Fatalf("ParseSignatureHex accepted %q", invalid[:min(len(invalid), 24)])
		}
	}
}

func TestExternalCommandBackendUsesFixedExecutableAndArguments(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "fake-hsm-wrapper")
	script := `#!/bin/sh
set -eu
[ "$1" = "--fixed-policy" ]
[ "$2" = "-a" ]
[ "$3" = "rsa2048-sha256" ]
[ "$#" -eq 4 ]
input=
IFS= read -r input < "$4" || true
[ "$input" = "approved bytes" ]
printf '%0512d\n' 0
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	backend, err := NewExternalCommandBackend(ExternalCommandConfig{
		ExecutablePath: executable,
		FixedArguments: []string{"--fixed-policy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := backend.Sign(context.Background(), AlgorithmRSA2048SHA256, []byte("approved bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != RSASignatureBytes {
		t.Fatalf("signature length = %d", len(signature))
	}
}

func TestExternalCommandBackendRejectsUntrustedConfiguration(t *testing.T) {
	for _, config := range []ExternalCommandConfig{
		{},
		{ExecutablePath: "relative/signer"},
		{ExecutablePath: "/clean/../unclean/signer"},
		{ExecutablePath: "/fixed/signer", FixedArguments: []string{"bad\nargument"}},
	} {
		if _, err := NewExternalCommandBackend(config); err == nil {
			t.Fatalf("NewExternalCommandBackend(%#v) succeeded", config)
		}
	}
}
