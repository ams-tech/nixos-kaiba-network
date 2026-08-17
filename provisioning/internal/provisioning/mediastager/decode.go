package mediastager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const MaximumPlanBytes = 1024 * 1024

func LoadPlan(path string, mode Mode) (Plan, error) {
	if !cleanAbsolutePath(path) {
		return Plan{}, invalidPlan("plan path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Plan{}, fmt.Errorf("open staging plan: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Plan{}, fmt.Errorf("stat staging plan: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumPlanBytes {
		return Plan{}, invalidPlan("plan must be a regular file between 1 and %d bytes", MaximumPlanBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumPlanBytes+1))
	if err != nil {
		return Plan{}, fmt.Errorf("read staging plan: %w", err)
	}
	return DecodePlan(data, mode)
}

func DecodePlan(data []byte, mode Mode) (Plan, error) {
	if len(data) == 0 || len(data) > MaximumPlanBytes {
		return Plan{}, invalidPlan("plan must be between 1 and %d bytes", MaximumPlanBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Plan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if err := requireExactPlanShape(data); err != nil {
		return Plan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidPlan, err)
	}
	if err := requireEOF(decoder); err != nil {
		return Plan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if err := plan.Validate(mode); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func requireExactPlanShape(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	if err := requireExactKeys(root, "schema_version", "target", "images"); err != nil {
		return fmt.Errorf("plan object: %w", err)
	}
	var target map[string]json.RawMessage
	if err := json.Unmarshal(root["target"], &target); err != nil {
		return fmt.Errorf("target object: %w", err)
	}
	if err := requireExactKeys(target, "path", "expected_identity", "expected_size_bytes"); err != nil {
		return fmt.Errorf("target object: %w", err)
	}
	var images []json.RawMessage
	if err := json.Unmarshal(root["images"], &images); err != nil {
		return fmt.Errorf("images array: %w", err)
	}
	for index, raw := range images {
		var image map[string]json.RawMessage
		if err := json.Unmarshal(raw, &image); err != nil {
			return fmt.Errorf("image %d object: %w", index+1, err)
		}
		if err := requireExactKeys(image, "role", "path", "digest", "size_bytes", "offset_bytes"); err != nil {
			return fmt.Errorf("image %d object: %w", index+1, err)
		}
	}
	return nil
}

func requireExactKeys(object map[string]json.RawMessage, expected ...string) error {
	if object == nil {
		return errors.New("must be a JSON object")
	}
	want := make(map[string]struct{}, len(expected))
	for _, key := range expected {
		want[key] = struct{}{}
	}
	for key := range object {
		if _, ok := want[key]; !ok {
			return fmt.Errorf("unexpected key %q", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		for _, key := range expected {
			if _, missing := want[key]; missing {
				return fmt.Errorf("missing key %q", key)
			}
		}
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token); err != nil {
		return err
	}
	return requireEOF(decoder)
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

func requireEOF(decoder *json.Decoder) error {
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}
