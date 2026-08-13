package identity

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
)

func uri(value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestSPIFFEPolicyResolve(t *testing.T) {
	t.Parallel()
	policy := SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: "kaiba.network."}
	device, err := policy.Resolve(&x509.Certificate{URIs: []*url.URL{uri("spiffe://kaiba.network/device/001")}})
	if err != nil {
		t.Fatal(err)
	}
	if device.ID != "001" || device.Hostname != "pi-001.kaiba.network" {
		t.Fatalf("unexpected device: %+v", device)
	}
}

func TestSPIFFEPolicyRejectsInvalidAndAmbiguousIdentities(t *testing.T) {
	t.Parallel()
	policy := SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: "kaiba.test"}
	for name, cert := range map[string]*x509.Certificate{
		"wrong trust domain": {URIs: []*url.URL{uri("spiffe://elsewhere.test/device/001")}},
		"too short":          {URIs: []*url.URL{uri("spiffe://kaiba.network/device/01")}},
		"non-numeric":        {URIs: []*url.URL{uri("spiffe://kaiba.network/device/admin")}},
		"extra path":         {URIs: []*url.URL{uri("spiffe://kaiba.network/device/001/admin")}},
		"query":              {URIs: []*url.URL{uri("spiffe://kaiba.network/device/001?role=admin")}},
		"userinfo":           {URIs: []*url.URL{uri("spiffe://user@kaiba.network/device/001")}},
		"port":               {URIs: []*url.URL{uri("spiffe://kaiba.network:443/device/001")}},
		"leading slash":      {URIs: []*url.URL{uri("spiffe://kaiba.network//device/001")}},
		"trailing slash":     {URIs: []*url.URL{uri("spiffe://kaiba.network/device/001/")}},
		"encoded identifier": {URIs: []*url.URL{uri("spiffe://kaiba.network/device/%30%30%31")}},
		"uppercase host":     {URIs: []*url.URL{uri("spiffe://KAIBA.NETWORK/device/001")}},
	} {
		name, cert := name, cert
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := policy.Resolve(cert); !errors.Is(err, ErrNoIdentity) {
				t.Fatalf("got %v, want ErrNoIdentity", err)
			}
		})
	}
	_, err := policy.Resolve(&x509.Certificate{URIs: []*url.URL{
		uri("spiffe://kaiba.network/device/001"), uri("spiffe://kaiba.network/device/002"),
	}})
	if !errors.Is(err, ErrAmbiguousIdentity) {
		t.Fatalf("got %v, want ErrAmbiguousIdentity", err)
	}
}
