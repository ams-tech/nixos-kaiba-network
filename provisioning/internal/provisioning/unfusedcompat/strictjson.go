package unfusedcompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	maximumManifestBytes = 256 * 1024
	maximumFixtureBytes  = 64 * 1024
)

func loadStrictJSONFile(filePath string, maximum int64, target any) error {
	if filePath == "" || !filepath.IsAbs(filePath) || filepath.Clean(filePath) != filePath {
		return errors.New("JSON input path must be clean and absolute")
	}
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open regular non-symlink JSON input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect JSON input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("JSON input must be a regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return fmt.Errorf("read JSON input: %w", err)
	}
	if int64(len(data)) > maximum {
		return fmt.Errorf("JSON input exceeds %d bytes", maximum)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input has a trailing value")
		}
		return fmt.Errorf("decode trailing JSON input: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON input: %w", err)
	}
	if err := rejectDuplicateJSONToken(decoder, token, "$"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}

func rejectDuplicateJSONToken(decoder *json.Decoder, token json.Token, location string) error {
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
				return fmt.Errorf("decode JSON input: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s contains duplicate key %q", location, key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON input: %w", err)
			}
			if err := rejectDuplicateJSONToken(decoder, value, location+"."+key); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON input: %w", err)
			}
			if err := rejectDuplicateJSONToken(decoder, value, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("JSON input contains an unexpected delimiter")
	}
}
