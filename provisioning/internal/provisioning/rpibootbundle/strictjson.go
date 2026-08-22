package rpibootbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
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
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not permitted")
		}
		return err
	}
	return nil
}

func rejectDuplicateKeysAndNulls(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	frames := make([]jsonFrame, 0, 8)
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
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				frames = append(frames, jsonFrame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				frames = append(frames, jsonFrame{})
			case '}', ']':
				if len(frames) == 0 {
					return errors.New("unexpected JSON delimiter")
				}
				frames = frames[:len(frames)-1]
				markValueConsumed(frames)
			}
			continue
		}
		if len(frames) > 0 && frames[len(frames)-1].object && frames[len(frames)-1].expectKey {
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			current := &frames[len(frames)-1]
			if _, duplicate := current.keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			current.keys[key] = struct{}{}
			current.expectKey = false
			continue
		}
		markValueConsumed(frames)
	}
}

func markValueConsumed(frames []jsonFrame) {
	if len(frames) > 0 && frames[len(frames)-1].object && !frames[len(frames)-1].expectKey {
		frames[len(frames)-1].expectKey = true
	}
}
