package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"time"
)

// PublicationStatus describes how far the current desired-state generation has
// progressed through the DNS publication pipeline.
type PublicationStatus string

const (
	StatusAccepted         PublicationStatus = "accepted"
	StatusOriginApplied    PublicationStatus = "origin-applied"
	StatusPubliclyObserved PublicationStatus = "publicly-observed"
)

// Intent is the durable desired state for one device.
type Intent struct {
	DeviceID                 string
	Hostname                 string
	Addresses                []netip.Addr
	Generation               int64
	LeaseExpiresAt           time.Time
	UpdatedAt                time.Time
	OriginAppliedGeneration  int64
	PublicObservedGeneration int64
	LastPublicationError     string
}

func (i Intent) Status() PublicationStatus {
	if i.PublicObservedGeneration >= i.Generation {
		return StatusPubliclyObserved
	}
	if i.OriginAppliedGeneration >= i.Generation {
		return StatusOriginApplied
	}
	return StatusAccepted
}

// CanonicalAddresses returns a sorted, duplicate-free copy. IPv4-mapped IPv6
// addresses are normalized to IPv4.
func CanonicalAddresses(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	seen := make(map[netip.Addr]struct{}, len(in))
	for _, addr := range in {
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Compare(out[b]) < 0 })
	return out
}

func AddressesEqual(a, b []netip.Addr) bool {
	a = CanonicalAddresses(a)
	b = CanonicalAddresses(b)
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// AddressesHash is used to bind an idempotency key to one canonical request.
func AddressesHash(addresses []netip.Addr) string {
	values := make([]string, 0, len(addresses))
	for _, addr := range CanonicalAddresses(addresses) {
		values = append(values, addr.String())
	}
	payload, _ := json.Marshal(values)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
