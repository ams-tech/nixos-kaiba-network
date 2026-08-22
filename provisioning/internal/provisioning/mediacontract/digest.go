package mediacontract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// Digest is the only digest representation accepted by the media contract.
// The algorithm prefix is part of the value so callers cannot silently change
// algorithms at an integration boundary.
type Digest string

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (digest Digest) Validate() error {
	if !digestPattern.MatchString(string(digest)) {
		return errors.New("digest must use canonical sha256:<64 lowercase hex> form")
	}
	decoded, err := hex.DecodeString(string(digest)[len("sha256:"):])
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("digest must contain exactly one SHA-256 value")
	}
	return nil
}

func sumBytes(value []byte) Digest {
	sum := sha256.Sum256(value)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func domainDigest(domain string, value []byte) Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func validateDigest(label string, digest Digest) error {
	if err := digest.Validate(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}
