package eepromsigning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ParsePlan accepts exactly canonical JSON with an optional final LF. Unknown
// fields, duplicate keys, trailing values, and alternate whitespace fail.
func ParsePlan(encoded []byte) (Plan, error) {
	if len(encoded) == 0 || len(encoded) > maxPlanBytes {
		return Plan{}, fmt.Errorf("EEPROM signing plan size must be between 1 and %d bytes", maxPlanBytes)
	}
	var plan Plan
	if err := strictDecode(encoded, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode EEPROM signing plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		return Plan{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return Plan{}, errors.New("EEPROM signing plan is not canonical JSON")
	}
	return plan, nil
}

// ParseResult applies the same strict canonical boundary to a signing result.
func ParseResult(encoded []byte) (Result, error) {
	if len(encoded) == 0 || len(encoded) > maxResultBytes {
		return Result{}, fmt.Errorf("EEPROM signing result size must be between 1 and %d bytes", maxResultBytes)
	}
	var result Result
	if err := strictDecode(encoded, &result); err != nil {
		return Result{}, fmt.Errorf("decode EEPROM signing result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	canonical, err := result.CanonicalJSON()
	if err != nil {
		return Result{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return Result{}, errors.New("EEPROM signing result is not canonical JSON")
	}
	return result, nil
}

func canonicalJSONFile(encoded, canonical []byte) bool {
	return bytes.Equal(encoded, canonical) || (len(encoded) == len(canonical)+1 && encoded[len(encoded)-1] == '\n' && bytes.Equal(encoded[:len(canonical)], canonical))
}

func strictDecode(encoded []byte, destination any) error {
	if err := rejectDuplicateKeys(encoded); err != nil {
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

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectValue(decoder, token); err != nil {
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

func inspectValue(decoder *json.Decoder, token json.Token) error {
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
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("JSON object key %q is duplicated", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
