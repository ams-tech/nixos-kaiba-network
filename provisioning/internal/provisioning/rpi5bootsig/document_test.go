package rpi5bootsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func TestDocumentCanonicalRoundTripAndVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	image := []byte("immutable Raspberry Pi boot image")
	digestBytes := sha256.Sum256(image)
	digest := bundle.Sum(image)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digestBytes[:])
	if err != nil {
		t.Fatal(err)
	}

	document, err := New(digest, 1_725_000_123, signature)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := document.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(string(digest), "sha256:") + "\n" +
		"ts: 1725000123\n" +
		"rsa2048: " + hex.EncodeToString(signature) + "\n"
	if string(encoded) != want {
		t.Fatalf("MarshalText() = %q, want %q", encoded, want)
	}

	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ImageDigest != digest || parsed.Timestamp != document.Timestamp || !bytes.Equal(parsed.Signature, signature) {
		t.Fatalf("Parse() = %#v, want %#v", parsed, document)
	}
	if err := parsed.Verify(&privateKey.PublicKey); err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}

	signature[0] ^= 0xff
	if bytes.Equal(document.Signature, signature) {
		t.Fatal("New retained the caller's mutable signature slice")
	}
}

func TestParseRejectsNonCanonicalAndRawRepresentations(t *testing.T) {
	valid := validDocumentText(t)
	lines := strings.Split(string(valid), "\n")
	upperDigest := append([]string(nil), lines...)
	upperDigest[0] = strings.ToUpper(upperDigest[0])
	upperSignature := append([]string(nil), lines...)
	upperSignature[2] = strings.ToUpper(upperSignature[2])

	tests := map[string][]byte{
		"empty":                  {},
		"raw signature":          make([]byte, rsa2048SignatureBytes),
		"missing final newline":  valid[:len(valid)-1],
		"CRLF":                   []byte(strings.ReplaceAll(string(valid), "\n", "\r\n")),
		"extra blank line":       append(append([]byte(nil), valid...), '\n'),
		"extra data line":        append(append([]byte(nil), valid...), []byte("ignored\n")...),
		"uppercase digest":       []byte(strings.Join(upperDigest, "\n")),
		"uppercase signature":    []byte(strings.Join(upperSignature, "\n")),
		"digest prefix":          []byte("sha256:" + string(valid)),
		"leading-zero timestamp": replaceLine(valid, 1, "ts: 01"),
		"plus timestamp":         replaceLine(valid, 1, "ts: +1"),
		"negative timestamp":     replaceLine(valid, 1, "ts: -1"),
		"empty timestamp":        replaceLine(valid, 1, "ts: "),
		"overflow timestamp":     replaceLine(valid, 1, "ts: 18446744073709551616"),
		"timestamp whitespace":   replaceLine(valid, 1, "ts: 1 "),
		"wrong timestamp label":  replaceLine(valid, 1, "timestamp: 1"),
		"wrong algorithm":        replaceLine(valid, 2, "rsa4096: "+strings.Repeat("0", 512)),
		"short signature":        replaceLine(valid, 2, "rsa2048: "+strings.Repeat("0", 510)),
		"long signature":         replaceLine(valid, 2, "rsa2048: "+strings.Repeat("0", 514)),
		"non-hex signature":      replaceLine(valid, 2, "rsa2048: "+strings.Repeat("g", 512)),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(encoded); err == nil {
				t.Fatalf("Parse(%q) succeeded", encoded)
			}
		})
	}
}

func TestTimestampZeroIsCanonical(t *testing.T) {
	encoded := replaceLine(validDocumentText(t), 1, "ts: 0")
	document, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if document.Timestamp != 0 {
		t.Fatalf("Timestamp = %d, want 0", document.Timestamp)
	}
}

func TestVerifyRejectsWrongDigestSignatureAndKeySize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256([]byte("boot image"))
	digest := bundle.Digest("sha256:" + hex.EncodeToString(digestBytes[:]))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digestBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	document, err := New(digest, 42, signature)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong digest", func(t *testing.T) {
		changed := document
		changed.ImageDigest = bundle.Sum([]byte("different boot image"))
		if err := changed.Verify(&privateKey.PublicKey); err == nil {
			t.Fatal("signature verified for a different image digest")
		}
	})
	t.Run("altered signature", func(t *testing.T) {
		changed := document
		changed.Signature = append([]byte(nil), document.Signature...)
		changed.Signature[0] ^= 0xff
		if err := changed.Verify(&privateKey.PublicKey); err == nil {
			t.Fatal("altered signature verified")
		}
	})
	t.Run("wrong signer", func(t *testing.T) {
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := document.Verify(&wrong.PublicKey); err == nil {
			t.Fatal("signature verified with a different RSA-2048 key")
		}
	})
	t.Run("RSA-1024", func(t *testing.T) {
		short, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if err := document.Verify(&short.PublicKey); err == nil || !strings.Contains(err.Error(), "RSA-2048") {
			t.Fatalf("Verify() error = %v", err)
		}
	})
	t.Run("nil key", func(t *testing.T) {
		if err := document.Verify(nil); err == nil || !strings.Contains(err.Error(), "RSA-2048") {
			t.Fatalf("Verify() error = %v", err)
		}
	})
	t.Run("wrong exponent", func(t *testing.T) {
		changed := privateKey.PublicKey
		changed.E = 3
		if err := document.Verify(&changed); err == nil || !strings.Contains(err.Error(), "exponent 65537") {
			t.Fatalf("Verify() error = %v", err)
		}
	})
}

func validDocumentText(t *testing.T) []byte {
	t.Helper()
	document, err := New(bundle.Sum([]byte("boot image")), 1, make([]byte, rsa2048SignatureBytes))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := document.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func replaceLine(encoded []byte, index int, replacement string) []byte {
	lines := strings.Split(string(encoded), "\n")
	lines[index] = replacement
	return []byte(strings.Join(lines, "\n"))
}
