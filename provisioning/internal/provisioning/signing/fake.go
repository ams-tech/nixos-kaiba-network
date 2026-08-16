package signing

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// DeterministicFakeBackend provides stable non-cryptographic signatures for
// tests. It never accesses PKCS#11, a YubiKey, or the host key store.
type DeterministicFakeBackend struct {
	Domain string
	Calls  int
}

func (f *DeterministicFakeBackend) Sign(_ context.Context, algorithm Algorithm, artifact []byte) ([]byte, error) {
	if algorithm != AlgorithmRSA2048SHA256 {
		return nil, fmt.Errorf("unsupported fake signing algorithm %q", algorithm)
	}
	f.Calls++
	signature := make([]byte, RSASignatureBytes)
	for block := 0; block < RSASignatureBytes/sha256.Size; block++ {
		hash := sha256.New()
		_, _ = hash.Write([]byte("kaiba.provisioning.deterministic-fake-signer.v1\x00"))
		_, _ = hash.Write([]byte(f.Domain))
		_, _ = hash.Write([]byte{0})
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		_, _ = hash.Write(counter[:])
		_, _ = hash.Write(artifact)
		copy(signature[block*sha256.Size:], hash.Sum(nil))
	}
	return signature, nil
}
