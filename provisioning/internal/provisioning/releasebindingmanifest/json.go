package releasebindingmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ParseCompiledArtifactSet accepts only bounded canonical JSON, with one
// optional final LF for a conventional manifest file.
func ParseCompiledArtifactSet(encoded []byte, mode ValidationMode) (CompiledArtifactSet, error) {
	if err := validateEncodedSize(encoded); err != nil {
		return CompiledArtifactSet{}, fmt.Errorf("compiled artifact set: %w", err)
	}
	var manifest CompiledArtifactSet
	if err := strictDecode(encoded, &manifest); err != nil {
		return CompiledArtifactSet{}, fmt.Errorf("decode compiled artifact set: %w", err)
	}
	canonical, err := manifest.CanonicalJSON(mode)
	if err != nil {
		return CompiledArtifactSet{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return CompiledArtifactSet{}, errors.New("compiled artifact set is not canonical JSON")
	}
	return manifest, nil
}

// ParseLaneGuardPackage applies the same strict canonical boundary to package
// digest material.
func ParseLaneGuardPackage(encoded []byte, mode ValidationMode) (LaneGuardPackage, error) {
	if err := validateEncodedSize(encoded); err != nil {
		return LaneGuardPackage{}, fmt.Errorf("lane-guard package: %w", err)
	}
	var manifest LaneGuardPackage
	if err := strictDecode(encoded, &manifest); err != nil {
		return LaneGuardPackage{}, fmt.Errorf("decode lane-guard package: %w", err)
	}
	canonical, err := manifest.CanonicalJSON(mode)
	if err != nil {
		return LaneGuardPackage{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return LaneGuardPackage{}, errors.New("lane-guard package is not canonical JSON")
	}
	return manifest, nil
}

func validateEncodedSize(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > MaxManifestBytes {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", MaxManifestBytes)
	}
	return nil
}

func canonicalJSONFile(encoded, canonical []byte) bool {
	return bytes.Equal(encoded, canonical) ||
		(len(encoded) == len(canonical)+1 && encoded[len(encoded)-1] == '\n' && bytes.Equal(encoded[:len(canonical)], canonical))
}

func strictDecode(encoded []byte, destination any) error {
	if err := rejectDuplicateKeysAndNulls(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func rejectDuplicateKeysAndNulls(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, first); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func inspectJSONValue(decoder *json.Decoder, token json.Token) error {
	if token == nil {
		return errors.New("JSON null is not permitted")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
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
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON object key %q is duplicated", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value); err != nil {
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
			if err := inspectJSONValue(decoder, value); err != nil {
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

func requireJSONEOF(decoder *json.Decoder) error {
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}
