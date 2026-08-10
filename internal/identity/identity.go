package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var deviceIDPattern = regexp.MustCompile(`^[0-9]{3,}$`)
var devicePathPattern = regexp.MustCompile(`^/device/([0-9]{3,})$`)

var (
	ErrNoIdentity        = errors.New("certificate has no Kaiba device identity")
	ErrAmbiguousIdentity = errors.New("certificate has multiple Kaiba device identities")
)

type Device struct {
	ID       string
	Hostname string
}

// Policy is the replaceable boundary between transport authentication and
// device naming authorization.
type Policy interface {
	Resolve(cert *x509.Certificate) (Device, error)
}

type SPIFFEPolicy struct {
	TrustDomain string
	Zone        string
}

func (p SPIFFEPolicy) Resolve(cert *x509.Certificate) (Device, error) {
	if cert == nil {
		return Device{}, ErrNoIdentity
	}
	trustDomain := strings.TrimSuffix(strings.ToLower(p.TrustDomain), ".")
	zone := strings.TrimSuffix(strings.ToLower(p.Zone), ".")
	var matchedID string
	for _, candidate := range cert.URIs {
		if candidate == nil || candidate.Scheme != "spiffe" || candidate.Host != trustDomain || candidate.User != nil || candidate.Opaque != "" || candidate.RawQuery != "" || candidate.ForceQuery || candidate.Fragment != "" {
			continue
		}
		parts := devicePathPattern.FindStringSubmatch(candidate.EscapedPath())
		if len(parts) != 2 || !deviceIDPattern.MatchString(parts[1]) {
			continue
		}
		if matchedID != "" {
			return Device{}, ErrAmbiguousIdentity
		}
		matchedID = parts[1]
	}
	if matchedID == "" {
		return Device{}, ErrNoIdentity
	}
	return Device{ID: matchedID, Hostname: fmt.Sprintf("pi-%s.%s", matchedID, zone)}, nil
}
