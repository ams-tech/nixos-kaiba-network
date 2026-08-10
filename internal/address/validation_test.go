package address

import (
	"net/netip"
	"testing"
)

func TestIsPubliclyRoutable(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"8.8.8.8":              true,
		"1.1.1.1":              true,
		"2606:4700:4700::1111": true,
		"10.0.0.1":             false,
		"100.64.0.1":           false,
		"127.0.0.1":            false,
		"169.254.1.1":          false,
		"192.0.2.1":            false,
		"198.18.0.1":           false,
		"203.0.113.42":         false,
		"240.0.0.1":            false,
		"::1":                  false,
		"fd00::1":              false,
		"fe80::1":              false,
		"fec0::1":              false,
		"2001:db8::42":         false,
	}
	for value, expected := range tests {
		value, expected := value, expected
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if actual := IsPubliclyRoutable(netip.MustParseAddr(value)); actual != expected {
				t.Fatalf("IsPubliclyRoutable(%s) = %t, want %t", value, actual, expected)
			}
		})
	}
}
