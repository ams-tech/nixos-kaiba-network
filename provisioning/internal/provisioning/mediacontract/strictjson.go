package mediacontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maximumContractBytes = 4 * 1024 * 1024

// strictCanonicalDecode rejects the ambiguity classes that encoding/json
// otherwise accepts: duplicate keys, unknown fields, nulls, trailing values,
// and non-canonical whitespace or field ordering. One terminal newline is the
// sole transport decoration accepted for a canonical JSON file.
func strictCanonicalDecode(data []byte, target any, canonical func() ([]byte, error)) error {
	if len(data) == 0 || len(data) > maximumContractBytes {
		return fmt.Errorf("JSON contract size must be between 1 and %d bytes", maximumContractBytes)
	}
	if err := inspectJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contract contains a trailing value")
		}
		return fmt.Errorf("decode trailing JSON contract: %w", err)
	}
	expected, err := canonical()
	if err != nil {
		return err
	}
	actual := data
	if bytes.HasSuffix(actual, []byte{'\n'}) {
		actual = actual[:len(actual)-1]
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("JSON contract is not in canonical form")
	}
	return nil
}

func inspectJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	if err := inspectJSONToken(decoder, token, "$"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contract contains trailing data")
	}
	return nil
}

func inspectJSONToken(decoder *json.Decoder, token json.Token, location string) error {
	if token == nil {
		return fmt.Errorf("JSON null is not allowed at %s", location)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object at %s: %w", location, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key at %s is not a string", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON value at %s.%s: %w", location, key, err)
			}
			if err := inspectJSONToken(decoder, value, location+"."+key); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("decode JSON object end at %s", location)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON array at %s: %w", location, err)
			}
			if err := inspectJSONToken(decoder, value, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("decode JSON array end at %s", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}
