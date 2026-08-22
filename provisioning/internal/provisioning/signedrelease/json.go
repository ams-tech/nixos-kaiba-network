package signedrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func domainDigest(domain string, encoded []byte) bundle.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func strictDecode(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxMetadataBytes {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", maxMetadataBytes)
	}
	if err := rejectDuplicateKeysAndNulls(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func decodeUniqueJSON(encoded []byte) (map[string]any, error) {
	if len(encoded) == 0 || len(encoded) > maxMetadataBytes {
		return nil, fmt.Errorf("JSON size must be between 1 and %d bytes", maxMetadataBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	value, err := decodeUniqueValue(decoder, nil)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("trailing JSON value %v", token)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("top-level JSON value must be an object")
	}
	return object, nil
}

func rejectDuplicateKeysAndNulls(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if _, err := decodeUniqueValue(decoder, nil); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func decodeUniqueValue(decoder *json.Decoder, first json.Token) (any, error) {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
	}
	if token == nil {
		return nil, errors.New("JSON null is not permitted")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("JSON object key %q is duplicated", key)
			}
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, errors.New("JSON object is not closed")
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, errors.New("JSON array is not closed")
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func canonicalJSONFile(encoded, canonical []byte) bool {
	return bytes.Equal(encoded, canonical) ||
		(len(encoded) == len(canonical)+1 && encoded[len(encoded)-1] == '\n' && bytes.Equal(encoded[:len(canonical)], canonical))
}

func jsonFile(encoded []byte) []byte {
	result := append([]byte(nil), encoded...)
	return append(result, '\n')
}
