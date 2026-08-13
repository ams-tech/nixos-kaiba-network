package api

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const generationETagPrefix = `"g-`

// GenerationETag is the strong validator for one device's desired address
// generation. Publication progress and unchanged lease renewals do not change
// it because neither changes the DNS projection.
func GenerationETag(generation int64) string {
	return fmt.Sprintf(`"g-%d"`, generation)
}

func ParseGenerationETag(value string) (int64, error) {
	if !strings.HasPrefix(value, generationETagPrefix) || !strings.HasSuffix(value, `"`) {
		return 0, errors.New("ETag must have the form \"g-<positive generation>\"")
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(value, generationETagPrefix), `"`)
	if digits == "" || digits[0] == '0' {
		return 0, errors.New("ETag generation must be a positive canonical integer")
	}
	for _, character := range digits {
		if character < '0' || character > '9' {
			return 0, errors.New("ETag generation must be a positive canonical integer")
		}
	}
	generation, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || generation <= 0 {
		return 0, errors.New("ETag generation is out of range")
	}
	return generation, nil
}
