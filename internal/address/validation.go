package address

import "net/netip"

var nonPublicPrefixes = mustPrefixes(
	// IPv4 special-purpose ranges which netip may classify as global unicast.
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	// IPv6 discard, benchmarking, documentation, ORCHID, and deprecated
	// site-local ranges.
	"100::/64", "2001:2::/48", "2001:10::/28", "2001:20::/28",
	"2001:db8::/32", "fec0::/10",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

// IsPubliclyRoutable is intentionally stricter than netip.IsGlobalUnicast:
// private and IANA special-purpose addresses cannot identify an Internet
// endpoint in production. Tests can explicitly disable this policy.
func IsPubliclyRoutable(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Is4In6() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
