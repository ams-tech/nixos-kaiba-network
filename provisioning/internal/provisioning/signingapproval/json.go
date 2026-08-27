package signingapproval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

// ParseApproval strictly decodes one approval and requires its exact canonical
// representation, optionally followed by one LF transport newline.
func ParseApproval(data []byte) (Approval, error) {
	payload, err := canonicalPayload(data, MaxApprovalBytes, "signing approval")
	if err != nil {
		return Approval{}, err
	}
	var approval Approval
	if err := strictDecode(payload, &approval); err != nil {
		return Approval{}, fmt.Errorf("decode signing approval: %w", err)
	}
	canonical, err := approval.CanonicalJSON()
	if err != nil {
		return Approval{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return Approval{}, errors.New("signing approval must use its exact canonical JSON representation")
	}
	return approval, nil
}

// ParseRegistry strictly decodes a v1alpha2 gate registry and requires the
// same deterministic representation emitted by CanonicalRegistryJSON.
func ParseRegistry(data []byte) (signinggate.Registry, error) {
	payload, err := canonicalPayload(data, signinggate.MaxRegistryBytes, "signing grant registry")
	if err != nil {
		return signinggate.Registry{}, err
	}
	var registry signinggate.Registry
	if err := strictDecode(payload, &registry); err != nil {
		return signinggate.Registry{}, fmt.Errorf("decode signing grant registry: %w", err)
	}
	canonical, err := CanonicalRegistryJSON(registry)
	if err != nil {
		return signinggate.Registry{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return signinggate.Registry{}, errors.New("signing grant registry must use its exact canonical JSON representation")
	}
	return registry, nil
}

// CanonicalRegistryJSON returns the fixed-order, whitespace-free v1alpha2
// registry representation used by the authoring CLI.
func CanonicalRegistryJSON(registry signinggate.Registry) ([]byte, error) {
	if err := registry.Validate(); err != nil {
		return nil, fmt.Errorf("grant registry: %w", err)
	}
	encoded, err := json.Marshal(registry)
	if err != nil {
		return nil, fmt.Errorf("encode canonical signing grant registry: %w", err)
	}
	if len(encoded) > signinggate.MaxRegistryBytes {
		return nil, fmt.Errorf("canonical signing grant registry exceeds %d bytes", signinggate.MaxRegistryBytes)
	}
	return encoded, nil
}

func canonicalPayload(data []byte, maximum int, label string) ([]byte, error) {
	if len(data) == 0 || len(data) > maximum+1 {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes plus an optional LF", label, maximum)
	}
	payload := data
	if payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
	}
	if len(payload) == 0 || len(payload) > maximum {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", label, maximum)
	}
	return payload, nil
}

func strictDecode(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	if err := rejectJSONNulls(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func inspectJSONValue(decoder *json.Decoder, token json.Token) error {
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

func rejectJSONNulls(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("JSON null is not permitted")
		}
	}
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
