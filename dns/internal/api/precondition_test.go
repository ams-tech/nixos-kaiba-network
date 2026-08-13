package api

import "testing"

func TestGenerationETagRoundTrip(t *testing.T) {
	t.Parallel()
	for _, generation := range []int64{1, 42, 1<<62 - 1} {
		value := GenerationETag(generation)
		parsed, err := ParseGenerationETag(value)
		if err != nil || parsed != generation {
			t.Fatalf("round trip %d through %q = %d, %v", generation, value, parsed, err)
		}
	}
}

func TestParseGenerationETagRejectsNonCanonicalValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "g-1", `W/"g-1"`, `"g-0"`, `"g-01"`, `"g--1"`, `"g-1","g-2"`, `"other-1"`} {
		if _, err := ParseGenerationETag(value); err == nil {
			t.Fatalf("accepted invalid generation ETag %q", value)
		}
	}
}
