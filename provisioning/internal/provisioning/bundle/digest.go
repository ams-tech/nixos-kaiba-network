// Package bundle defines the content-addressed secure-boot artifact manifest.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const digestPrefix = "sha256:"

// Digest is the canonical textual representation of a SHA-256 digest.
// Canonical values always use the sha256: prefix and 64 lowercase hex digits.
type Digest string

// ParseDigest validates and returns a canonical SHA-256 digest.
func ParseDigest(value string) (Digest, error) {
	if len(value) != len(digestPrefix)+sha256.Size*2 || value[:min(len(value), len(digestPrefix))] != digestPrefix {
		return "", errors.New("digest must use the canonical sha256:<64 lowercase hex> form")
	}
	hexPart := value[len(digestPrefix):]
	for _, char := range hexPart {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return "", errors.New("digest must use the canonical sha256:<64 lowercase hex> form")
		}
	}
	return Digest(value), nil
}

// Validate reports whether the digest is canonical.
func (d Digest) Validate() error {
	parsed, err := ParseDigest(string(d))
	if err != nil {
		return err
	}
	if parsed != d {
		return fmt.Errorf("digest %q is not canonical", d)
	}
	return nil
}

// Sum returns the canonical SHA-256 digest of data.
func Sum(data []byte) Digest {
	digest := sha256.Sum256(data)
	return Digest(digestPrefix + hex.EncodeToString(digest[:]))
}
