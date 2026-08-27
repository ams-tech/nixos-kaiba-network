// Package signingapproval constructs a canonical, reviewer-attributed public
// approval record and exact five-grant registry for one Raspberry Pi 5 release
// intent.
//
// It deliberately has no private-key, token, PIN, filesystem-path, or signing
// authority. Every signing role and artifact digest comes from the validated
// release intent; callers cannot add, remove, or substitute a signing input.
package signingapproval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	SchemaV1Alpha1          = "kaiba.provisioning.rpi5-signing-approval/v1alpha1"
	DecisionApproved        = "approved"
	MaxApprovalBytes        = 64 * 1024
	MaximumApprovalLifetime = 24 * time.Hour

	approvalDigestDomain = "kaiba.provisioning.rpi5-signing-approval.v1alpha1"
)

var (
	identifierPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	timePattern           = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// Approval is the canonical, secret-free statement attributed to a reviewer.
// Reviewer authentication and file handoff are procedural: this record has no
// reviewer signature, and the signing-host root remains a trusted authority.
// ApprovalID is derived from ApprovalDigest, rather than supplied by an
// operator, so two approvals with identical review inputs have one identity.
type Approval struct {
	SchemaVersion       string            `json:"schema_version"`
	ApprovalID          string            `json:"approval_id"`
	ApprovalDigest      bundle.Digest     `json:"approval_digest"`
	Decision            string            `json:"decision"`
	ReviewerID          string            `json:"reviewer_id"`
	ApprovedAt          string            `json:"approved_at"`
	ExpiresAt           string            `json:"expires_at"`
	ReleaseID           string            `json:"release_id"`
	SourceRevision      string            `json:"source_revision"`
	ReleaseIntentDigest bundle.Digest     `json:"release_intent_digest"`
	SigningInputs       []bundle.Artifact `json:"signing_inputs"`
}

// Authorization is the complete public authoring result. Registry is directly
// consumable by the existing v1alpha2 signing gate after a privileged operator
// installs it with the gate's required ownership and permissions.
type Authorization struct {
	Approval Approval
	Registry signinggate.Registry
}

type approvalDigestMaterial struct {
	SchemaVersion       string            `json:"schema_version"`
	Decision            string            `json:"decision"`
	ReviewerID          string            `json:"reviewer_id"`
	ApprovedAt          string            `json:"approved_at"`
	ExpiresAt           string            `json:"expires_at"`
	ReleaseID           string            `json:"release_id"`
	SourceRevision      string            `json:"source_revision"`
	ReleaseIntentDigest bundle.Digest     `json:"release_intent_digest"`
	SigningInputs       []bundle.Artifact `json:"signing_inputs"`
}

// New derives one approval and the exact five grants authorized by intent.
// reviewerID and both times are public ceremony inputs. Times must already use
// canonical UTC RFC3339 seconds; New never silently rounds or changes them.
func New(intent releaseintent.Intent, reviewerID, approvedAt, expiresAt string) (Authorization, error) {
	if err := intent.Validate(); err != nil {
		return Authorization{}, fmt.Errorf("release intent: %w", err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return Authorization{}, fmt.Errorf("release intent digest: %w", err)
	}
	approval := Approval{
		SchemaVersion:       SchemaV1Alpha1,
		Decision:            DecisionApproved,
		ReviewerID:          reviewerID,
		ApprovedAt:          approvedAt,
		ExpiresAt:           expiresAt,
		ReleaseID:           intent.ReleaseID,
		SourceRevision:      intent.SourceRevision,
		ReleaseIntentDigest: intentDigest,
		SigningInputs:       append([]bundle.Artifact(nil), intent.SigningInputs...),
	}
	digest, err := approval.calculateDigest()
	if err != nil {
		return Authorization{}, err
	}
	approval.ApprovalDigest = digest
	approval.ApprovalID = approvalID(digest)
	if err := approval.Validate(); err != nil {
		return Authorization{}, err
	}
	registry, err := registryFor(approval)
	if err != nil {
		return Authorization{}, err
	}
	authorization := Authorization{Approval: approval, Registry: registry}
	if err := authorization.Validate(intent); err != nil {
		return Authorization{}, err
	}
	return authorization, nil
}

// Validate independently reconstructs every approval and grant binding from
// intent. Exact equality is required; extra grants and hand-authored IDs fail.
func (authorization Authorization) Validate(intent releaseintent.Intent) error {
	if err := intent.Validate(); err != nil {
		return fmt.Errorf("release intent: %w", err)
	}
	if err := authorization.Approval.Validate(); err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return err
	}
	approval := authorization.Approval
	if approval.ReleaseID != intent.ReleaseID || approval.SourceRevision != intent.SourceRevision || approval.ReleaseIntentDigest != intentDigest {
		return errors.New("approval does not identify the supplied release intent")
	}
	if !artifactsEqual(approval.SigningInputs, intent.SigningInputs) {
		return errors.New("approval signing inputs do not exactly match the release intent")
	}
	approvedAt, _ := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	if approvedAt.Unix() < int64(intent.SourceDateEpoch) {
		return errors.New("approved_at precedes the release intent source_date_epoch")
	}
	if err := authorization.Registry.Validate(); err != nil {
		return fmt.Errorf("grant registry: %w", err)
	}
	expected, err := registryFor(approval)
	if err != nil {
		return err
	}
	actualJSON, err := CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		return err
	}
	expectedJSON, err := CanonicalRegistryJSON(expected)
	if err != nil {
		return err
	}
	if string(actualJSON) != string(expectedJSON) {
		return errors.New("grant registry is not the exact deterministic five-grant registry for the approval")
	}
	return nil
}

// Validate checks the closed approval vocabulary, canonical times and exact
// digest-derived identity without consulting an external clock.
func (approval Approval) Validate() error {
	if err := approval.validateMaterial(); err != nil {
		return err
	}
	digest, err := approval.calculateDigest()
	if err != nil {
		return err
	}
	if approval.ApprovalDigest != digest {
		return errors.New("approval_digest does not match the canonical approval material")
	}
	if approval.ApprovalID != approvalID(digest) {
		return errors.New("approval_id is not derived from approval_digest")
	}
	return nil
}

// CanonicalJSON returns the unique fixed-order JSON covered by the approval's
// digest-derived identity. Transport newlines are not included.
func (approval Approval) CanonicalJSON() ([]byte, error) {
	if err := approval.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(approval)
	if err != nil {
		return nil, fmt.Errorf("encode canonical signing approval: %w", err)
	}
	if len(encoded) > MaxApprovalBytes {
		return nil, fmt.Errorf("canonical signing approval exceeds %d bytes", MaxApprovalBytes)
	}
	return encoded, nil
}

func (approval Approval) validateMaterial() error {
	if approval.SchemaVersion != SchemaV1Alpha1 {
		return fmt.Errorf("unsupported signing approval schema_version %q", approval.SchemaVersion)
	}
	if approval.Decision != DecisionApproved {
		return fmt.Errorf("decision must be %q", DecisionApproved)
	}
	if !identifierPattern.MatchString(approval.ReviewerID) {
		return errors.New("reviewer_id must be a canonical lower-case identifier")
	}
	approvedAt, err := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseCanonicalTime(approval.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(approvedAt) || expiresAt.After(approvedAt.Add(MaximumApprovalLifetime)) {
		return errors.New("expires_at must be after approved_at and no more than 24 hours later")
	}
	if !identifierPattern.MatchString(approval.ReleaseID) {
		return errors.New("release_id must be a canonical lower-case identifier")
	}
	if !sourceRevisionPattern.MatchString(approval.SourceRevision) {
		return errors.New("source_revision must contain exactly 40 or 64 lower-case hexadecimal characters")
	}
	if err := approval.ReleaseIntentDigest.Validate(); err != nil {
		return fmt.Errorf("release_intent_digest: %w", err)
	}
	roles := releaseintent.SigningInputRoles()
	if len(approval.SigningInputs) != len(roles) {
		return fmt.Errorf("signing_inputs must contain exactly %d entries", len(roles))
	}
	seenDigests := make(map[bundle.Digest]struct{}, len(approval.SigningInputs))
	for index, input := range approval.SigningInputs {
		if input.Role != roles[index] {
			return fmt.Errorf("signing_inputs[%d].role must be %q", index, roles[index])
		}
		if err := input.Digest.Validate(); err != nil {
			return fmt.Errorf("signing_inputs[%d].digest: %w", index, err)
		}
		if _, exists := seenDigests[input.Digest]; exists {
			return errors.New("signing input artifact digests must be unique for unambiguous gate resolution")
		}
		seenDigests[input.Digest] = struct{}{}
		if input.SizeBytes == 0 || input.SizeBytes > releaseintent.MaxSigningInputBytes {
			return fmt.Errorf("signing_inputs[%d].size_bytes must be between 1 and %d", index, releaseintent.MaxSigningInputBytes)
		}
	}
	return nil
}

func (approval Approval) calculateDigest() (bundle.Digest, error) {
	if err := approval.validateMaterial(); err != nil {
		return "", err
	}
	material := approvalDigestMaterial{
		SchemaVersion: approval.SchemaVersion, Decision: approval.Decision,
		ReviewerID: approval.ReviewerID, ApprovedAt: approval.ApprovedAt, ExpiresAt: approval.ExpiresAt,
		ReleaseID: approval.ReleaseID, SourceRevision: approval.SourceRevision,
		ReleaseIntentDigest: approval.ReleaseIntentDigest,
		SigningInputs:       append([]bundle.Artifact(nil), approval.SigningInputs...),
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode signing approval digest material: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(approvalDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func registryFor(approval Approval) (signinggate.Registry, error) {
	if err := approval.Validate(); err != nil {
		return signinggate.Registry{}, fmt.Errorf("approval: %w", err)
	}
	grants := make([]signinggate.Grant, 0, len(approval.SigningInputs))
	digestHex := strings.TrimPrefix(string(approval.ApprovalDigest), "sha256:")
	for _, input := range approval.SigningInputs {
		role := string(input.Role)
		grants = append(grants, signinggate.Grant{
			SchemaVersion: signinggate.GrantSchemaV1Alpha2,
			GrantID:       "grant:" + digestHex + ":" + role,
			ExpiresAt:     approval.ExpiresAt,
			Request: signing.Request{
				SchemaVersion:  signing.RequestSchemaV1Alpha2,
				RequestID:      "request:" + digestHex + ":" + role,
				Algorithm:      signing.AlgorithmRSA2048SHA256,
				Role:           input.Role,
				ArtifactDigest: input.Digest,
				Approval: signing.ApprovalBinding{
					ApprovalID:          approval.ApprovalID,
					ApprovalDigest:      approval.ApprovalDigest,
					ReleaseIntentDigest: approval.ReleaseIntentDigest,
					Role:                input.Role,
					ArtifactDigest:      input.Digest,
				},
			},
		})
	}
	registry, err := signinggate.NewRegistry(grants)
	if err != nil {
		return signinggate.Registry{}, fmt.Errorf("construct five-grant registry: %w", err)
	}
	return registry, nil
}

func approvalID(digest bundle.Digest) string {
	return "approval:" + strings.TrimPrefix(string(digest), "sha256:")
}

func parseCanonicalTime(value, field string) (time.Time, error) {
	if !timePattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("%s must use canonical UTC RFC3339 seconds", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must use canonical UTC RFC3339 seconds", field)
	}
	return parsed, nil
}

func artifactsEqual(left, right []bundle.Artifact) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
