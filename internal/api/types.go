package api

import (
	"net/netip"
	"time"

	"github.com/kaiba-network/dns-pilot/internal/model"
)

type Address struct {
	Family  string `json:"family"`
	Address string `json:"address"`
}

type EndpointRequest struct {
	Addresses []Address `json:"addresses"`
}

type DeviceState struct {
	DeviceID          string                  `json:"device_id"`
	Hostname          string                  `json:"hostname"`
	Addresses         []Address               `json:"addresses"`
	Generation        int64                   `json:"generation"`
	Status            model.PublicationStatus `json:"status"`
	LeaseExpiresAt    time.Time               `json:"lease_expires_at"`
	RenewAfterSeconds int64                   `json:"renew_after_seconds"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func AddressesFromNetIP(addresses []netip.Addr) []Address {
	result := make([]Address, 0, len(addresses))
	for _, addr := range model.CanonicalAddresses(addresses) {
		family := "ipv6"
		if addr.Is4() {
			family = "ipv4"
		}
		result = append(result, Address{Family: family, Address: addr.String()})
	}
	return result
}
