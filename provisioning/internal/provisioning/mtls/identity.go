package mtls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	stationLaneURIPrefix = "spiffe://kaiba.network/station/"
	approverURIPrefix    = "spiffe://kaiba.network/approver/"
)

var (
	identityComponentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

	// ErrClientIdentity classifies a missing, unverified, ambiguous, or
	// non-canonical provisioning identity as an authentication failure.
	ErrClientIdentity = errors.New("verified client certificate provisioning identity is required")
	// ErrClientIdentityMismatch classifies a valid identity that does not own
	// the provisioning authority named by a request as an authorization failure.
	ErrClientIdentityMismatch = errors.New("client certificate identity does not authorize the requested provisioning authority")
)

// StationLaneIdentity is the station capability understood by the provisioning
// reference services. It is encoded as exactly one canonical URI SAN:
// spiffe://kaiba.network/station/<station-id>/lane/<lane-id>.
type StationLaneIdentity struct {
	StationID string
	LaneID    string
}

// ApproverIdentity is an independent plan-approval principal. It is encoded as
// exactly one canonical URI SAN:
// spiffe://kaiba.network/approver/<approver-id>.
type ApproverIdentity struct {
	ApproverID string
}

type identityPolicyMode uint8

const (
	identityPolicyLoopbackPlaintext identityPolicyMode = iota + 1
	identityPolicyMutualTLS
)

// IdentityPolicy makes the development plaintext exception explicit while
// keeping its zero value fail-closed.
type IdentityPolicy struct {
	mode identityPolicyMode
}

// LoopbackPlaintextIdentityPolicy disables certificate authorization only for
// the loopback-only plaintext development deployment accepted by
// ValidateListenAddress.
func LoopbackPlaintextIdentityPolicy() IdentityPolicy {
	return IdentityPolicy{mode: identityPolicyLoopbackPlaintext}
}

// MutualTLSIdentityPolicy requires one verified, canonical station/lane URI
// SAN and binds it to station- and lane-scoped requests.
func MutualTLSIdentityPolicy() IdentityPolicy {
	return IdentityPolicy{mode: identityPolicyMutualTLS}
}

func (policy IdentityPolicy) RequiresClientIdentity() bool {
	return policy.mode != identityPolicyLoopbackPlaintext
}

// Authenticate returns the verified client identity. The loopback plaintext
// policy deliberately returns an empty identity because no certificate is
// available in that development mode.
func (policy IdentityPolicy) Authenticate(request *http.Request) (StationLaneIdentity, error) {
	switch policy.mode {
	case identityPolicyLoopbackPlaintext:
		return StationLaneIdentity{}, nil
	case identityPolicyMutualTLS:
		return verifiedStationLaneIdentity(request)
	default:
		return StationLaneIdentity{}, fmt.Errorf("%w: identity policy is not configured", ErrClientIdentity)
	}
}

// Authorize requires the verified URI SAN to name the exact station/lane pair.
func (policy IdentityPolicy) Authorize(request *http.Request, stationID, laneID string) error {
	if policy.mode == identityPolicyLoopbackPlaintext {
		return nil
	}
	identity, err := policy.Authenticate(request)
	if err != nil {
		return err
	}
	if identity.StationID != stationID || identity.LaneID != laneID {
		return ErrClientIdentityMismatch
	}
	return nil
}

// AuthenticateApprover returns the verified independent approver identity. A
// station/lane URI SAN is not an approver identity and fails authentication.
func (policy IdentityPolicy) AuthenticateApprover(request *http.Request) (ApproverIdentity, error) {
	switch policy.mode {
	case identityPolicyLoopbackPlaintext:
		return ApproverIdentity{}, nil
	case identityPolicyMutualTLS:
		return verifiedApproverIdentity(request)
	default:
		return ApproverIdentity{}, fmt.Errorf("%w: identity policy is not configured", ErrClientIdentity)
	}
}

// AuthorizeApprover requires the verified approver URI SAN to name the exact
// approver recorded by an approval request or approval audit event.
func (policy IdentityPolicy) AuthorizeApprover(request *http.Request, approverID string) error {
	if policy.mode == identityPolicyLoopbackPlaintext {
		return nil
	}
	identity, err := policy.AuthenticateApprover(request)
	if err != nil {
		return err
	}
	if identity.ApproverID != approverID {
		return ErrClientIdentityMismatch
	}
	return nil
}

func verifiedStationLaneIdentity(request *http.Request) (StationLaneIdentity, error) {
	identityURI, err := verifiedIdentityURI(request)
	if err != nil {
		return StationLaneIdentity{}, err
	}
	identity, err := parseStationLaneURI(identityURI)
	if err != nil {
		return StationLaneIdentity{}, fmt.Errorf("%w: %v", ErrClientIdentity, err)
	}
	return identity, nil
}

func verifiedApproverIdentity(request *http.Request) (ApproverIdentity, error) {
	identityURI, err := verifiedIdentityURI(request)
	if err != nil {
		return ApproverIdentity{}, err
	}
	identity, err := parseApproverURI(identityURI)
	if err != nil {
		return ApproverIdentity{}, fmt.Errorf("%w: %v", ErrClientIdentity, err)
	}
	return identity, nil
}

func verifiedIdentityURI(request *http.Request) (*url.URL, error) {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 {
		return nil, fmt.Errorf("%w: no verified client certificate", ErrClientIdentity)
	}
	var leaf *x509.Certificate
	for _, chain := range request.TLS.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil {
			return nil, fmt.Errorf("%w: verified client chain has no leaf certificate", ErrClientIdentity)
		}
		if leaf == nil {
			leaf = chain[0]
			continue
		}
		if !bytes.Equal(leaf.Raw, chain[0].Raw) {
			return nil, fmt.Errorf("%w: verified chains contain different leaf certificates", ErrClientIdentity)
		}
	}
	if len(leaf.URIs) == 0 {
		return nil, fmt.Errorf("%w: client certificate has no URI SAN", ErrClientIdentity)
	}
	if len(leaf.URIs) != 1 {
		return nil, fmt.Errorf("%w: client certificate must contain exactly one URI SAN", ErrClientIdentity)
	}
	return leaf.URIs[0], nil
}

func parseStationLaneURI(identityURI *url.URL) (StationLaneIdentity, error) {
	if identityURI == nil {
		return StationLaneIdentity{}, errors.New("URI SAN is empty")
	}
	parts := strings.Split(identityURI.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "station" || parts[3] != "lane" ||
		!identityComponentPattern.MatchString(parts[2]) || !identityComponentPattern.MatchString(parts[4]) {
		return StationLaneIdentity{}, errors.New("URI SAN must use spiffe://kaiba.network/station/<station-id>/lane/<lane-id>")
	}
	identity := StationLaneIdentity{StationID: parts[2], LaneID: parts[4]}
	expected := stationLaneURIPrefix + identity.StationID + "/lane/" + identity.LaneID
	if identityURI.String() != expected {
		return StationLaneIdentity{}, errors.New("URI SAN is not canonical")
	}
	return identity, nil
}

func parseApproverURI(identityURI *url.URL) (ApproverIdentity, error) {
	if identityURI == nil {
		return ApproverIdentity{}, errors.New("URI SAN is empty")
	}
	parts := strings.Split(identityURI.Path, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "approver" ||
		!identityComponentPattern.MatchString(parts[2]) {
		return ApproverIdentity{}, errors.New("URI SAN must use spiffe://kaiba.network/approver/<approver-id>")
	}
	identity := ApproverIdentity{ApproverID: parts[2]}
	expected := approverURIPrefix + identity.ApproverID
	if identityURI.String() != expected {
		return ApproverIdentity{}, errors.New("URI SAN is not canonical")
	}
	return identity, nil
}
