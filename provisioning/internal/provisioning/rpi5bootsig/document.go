// Package rpi5bootsig parses and verifies the canonical Raspberry Pi boot
// signature document emitted for a signed boot image.
package rpi5bootsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	rsa2048SignatureBytes = 256
	maximumDocumentBytes  = 64 + 1 + len("ts: ") + 20 + 1 + len("rsa2048: ") + rsa2048SignatureBytes*2 + 1
)

// Document is the canonical detached signature metadata for one boot image.
// ImageDigest is the SHA-256 digest signed by Signature. Timestamp is release
// metadata included in the document, but not in the RSA signature input.
type Document struct {
	ImageDigest bundle.Digest
	Timestamp   uint64
	Signature   []byte
}

// New validates and returns a detached boot signature document. Signature is
// defensively copied so subsequent caller mutation cannot change the result.
func New(imageDigest bundle.Digest, timestamp uint64, signature []byte) (Document, error) {
	document := Document{
		ImageDigest: imageDigest,
		Timestamp:   timestamp,
		Signature:   append([]byte(nil), signature...),
	}
	if err := document.validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Parse accepts only the canonical three-line boot signature representation:
//
//	<64 lowercase SHA-256 hex digits>\n
//	ts: <canonical uint64 decimal>\n
//	rsa2048: <512 lowercase signature hex digits>\n
func Parse(encoded []byte) (Document, error) {
	if len(encoded) == 0 || len(encoded) > maximumDocumentBytes {
		return Document{}, errors.New("boot signature document has an invalid size")
	}
	if encoded[len(encoded)-1] != '\n' {
		return Document{}, errors.New("boot signature document must end with a newline")
	}
	if strings.ContainsRune(string(encoded), '\r') {
		return Document{}, errors.New("boot signature document must use LF line endings")
	}
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return Document{}, errors.New("boot signature document must contain exactly three lines")
	}

	imageDigest, err := bundle.ParseDigest("sha256:" + lines[0])
	if err != nil || len(lines[0]) != sha256.Size*2 {
		return Document{}, errors.New("boot signature image digest must be 64 lowercase hexadecimal digits")
	}

	if !strings.HasPrefix(lines[1], "ts: ") {
		return Document{}, errors.New("boot signature timestamp line must start with \"ts: \"")
	}
	timestampText := strings.TrimPrefix(lines[1], "ts: ")
	timestamp, err := strconv.ParseUint(timestampText, 10, 64)
	if err != nil || strconv.FormatUint(timestamp, 10) != timestampText {
		return Document{}, errors.New("boot signature timestamp must be a canonical decimal uint64")
	}

	if !strings.HasPrefix(lines[2], "rsa2048: ") {
		return Document{}, errors.New("boot signature line must start with \"rsa2048: \"")
	}
	signatureText := strings.TrimPrefix(lines[2], "rsa2048: ")
	if len(signatureText) != rsa2048SignatureBytes*2 || !isLowerHex(signatureText) {
		return Document{}, errors.New("boot signature must be 512 lowercase hexadecimal digits")
	}
	signature, err := hex.DecodeString(signatureText)
	if err != nil {
		return Document{}, errors.New("boot signature is not valid hexadecimal")
	}

	document, err := New(imageDigest, timestamp, signature)
	if err != nil {
		return Document{}, err
	}
	canonical, err := document.MarshalText()
	if err != nil {
		return Document{}, err
	}
	if string(canonical) != string(encoded) {
		return Document{}, errors.New("boot signature document is not canonical")
	}
	return document, nil
}

// MarshalText emits the unique canonical representation accepted by Parse.
func (document Document) MarshalText() ([]byte, error) {
	if err := document.validate(); err != nil {
		return nil, err
	}
	digestText := strings.TrimPrefix(string(document.ImageDigest), "sha256:")
	encoded := fmt.Sprintf("%s\nts: %d\nrsa2048: %s\n", digestText, document.Timestamp, hex.EncodeToString(document.Signature))
	return []byte(encoded), nil
}

// Verify verifies the RSA-2048 PKCS#1 v1.5 SHA-256 signature over ImageDigest.
func (document Document) Verify(publicKey *rsa.PublicKey) error {
	if err := document.validate(); err != nil {
		return err
	}
	if publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() != 2048 || publicKey.Size() != rsa2048SignatureBytes || publicKey.E != 65537 {
		return errors.New("boot signature verification requires an RSA-2048 public key with exponent 65537")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(string(document.ImageDigest), "sha256:"))
	if err != nil || len(digest) != sha256.Size {
		return errors.New("boot signature image digest is invalid")
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, document.Signature); err != nil {
		return errors.New("boot signature does not verify")
	}
	return nil
}

func (document Document) validate() error {
	if err := document.ImageDigest.Validate(); err != nil {
		return fmt.Errorf("boot signature image digest: %w", err)
	}
	if len(document.Signature) != rsa2048SignatureBytes {
		return fmt.Errorf("boot signature must contain exactly %d bytes", rsa2048SignatureBytes)
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
