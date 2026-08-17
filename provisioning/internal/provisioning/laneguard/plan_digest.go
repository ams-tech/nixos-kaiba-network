package laneguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	operationDigestDomain = "kaiba.provisioning.lane-guard.operation-digest.v1alpha2"
	planDigestDomain      = "kaiba.provisioning.lane-guard.plan-digest.v1alpha2"
)

type operationDigestMaterial struct {
	Sequence                   uint32         `json:"sequence"`
	Operation                  Operation      `json:"operation"`
	Classification             OperationClass `json:"classification"`
	AuthorizationID            string         `json:"authorization_id"`
	ExpectedPrestate           DirectState    `json:"expected_prestate"`
	ExpectedPoststate          DirectState    `json:"expected_poststate"`
	MaximumDurationNanoseconds int64          `json:"maximum_duration_nanoseconds"`
}

type planDigestMaterial struct {
	SchemaVersion     string                 `json:"schema_version"`
	StationID         string                 `json:"station_id"`
	LaneID            string                 `json:"lane_id"`
	TransactionID     string                 `json:"transaction_id"`
	Release           releasebinding.Binding `json:"release"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	FenceEpoch        uint64                 `json:"fence_epoch"`
	ApprovalExpiresAt string                 `json:"approval_expires_at"`
	OperationDigests  []string               `json:"operation_digests"`
}

// CanonicalDigestMaterial returns the deterministic operation representation
// used for digest derivation. OperationDigest is deliberately excluded.
func (operation OperationSpec) CanonicalDigestMaterial() ([]byte, error) {
	encoded, err := json.Marshal(operationDigestMaterial{
		Sequence:                   operation.Sequence,
		Operation:                  operation.Operation,
		Classification:             operation.Classification,
		AuthorizationID:            operation.AuthorizationID,
		ExpectedPrestate:           operation.ExpectedPrestate,
		ExpectedPoststate:          operation.ExpectedPoststate,
		MaximumDurationNanoseconds: operation.MaximumDuration.Nanoseconds(),
	})
	if err != nil {
		return nil, fmt.Errorf("encode canonical operation digest material: %w", err)
	}
	return encoded, nil
}

// Digest returns the domain-separated digest of the canonical operation body.
func (operation OperationSpec) Digest() (string, error) {
	material, err := operation.CanonicalDigestMaterial()
	if err != nil {
		return "", err
	}
	return deriveDigest(operationDigestDomain, material), nil
}

// CanonicalDigestMaterial returns the deterministic plan representation used
// for digest derivation. The release binding and canonical UTC approval expiry
// are included, and operation digests are independently recomputed in order.
// PlanDigest, ApprovalID, and IntentReceipt are deliberately excluded.
func (plan Plan) CanonicalDigestMaterial() ([]byte, error) {
	approvalExpiresAt, err := canonicalApprovalExpiry(plan.ApprovalExpiresAt)
	if err != nil {
		return nil, err
	}
	operationDigests := make([]string, len(plan.Operations))
	for index, operation := range plan.Operations {
		digest, err := operation.Digest()
		if err != nil {
			return nil, fmt.Errorf("derive operation %d digest: %w", index+1, err)
		}
		operationDigests[index] = digest
	}
	encoded, err := json.Marshal(planDigestMaterial{
		SchemaVersion:     plan.SchemaVersion,
		StationID:         plan.StationID,
		LaneID:            plan.LaneID,
		TransactionID:     plan.TransactionID,
		Release:           plan.Release,
		TargetFingerprint: plan.TargetFingerprint,
		FenceEpoch:        plan.FenceEpoch,
		ApprovalExpiresAt: approvalExpiresAt,
		OperationDigests:  operationDigests,
	})
	if err != nil {
		return nil, fmt.Errorf("encode canonical plan digest material: %w", err)
	}
	return encoded, nil
}

func canonicalApprovalExpiry(value time.Time) (string, error) {
	if value.IsZero() {
		return "", errors.New("plan requires an approval expiry")
	}
	canonical := value.UTC().Format(time.RFC3339Nano)
	parsed, err := time.Parse(time.RFC3339Nano, canonical)
	if err != nil || !parsed.Equal(value) {
		return "", errors.New("plan approval expiry must be representable as canonical UTC RFC3339Nano")
	}
	return canonical, nil
}

// Digest returns the domain-separated digest of the canonical plan body and
// its ordered, independently derived operation digests.
func (plan Plan) Digest() (string, error) {
	material, err := plan.CanonicalDigestMaterial()
	if err != nil {
		return "", err
	}
	return deriveDigest(planDigestDomain, material), nil
}

// WithDerivedDigests returns a deep copy populated with canonical operation and
// plan digests. It is for trusted plan construction. Validation of untrusted
// plans compares supplied digests and never normalizes them with this method.
func (plan Plan) WithDerivedDigests() (Plan, error) {
	derived := plan
	derived.Operations = append([]OperationSpec(nil), plan.Operations...)
	for index := range derived.Operations {
		digest, err := derived.Operations[index].Digest()
		if err != nil {
			return Plan{}, fmt.Errorf("derive operation %d digest: %w", index+1, err)
		}
		derived.Operations[index].OperationDigest = digest
	}
	digest, err := derived.Digest()
	if err != nil {
		return Plan{}, err
	}
	derived.PlanDigest = digest
	return derived, nil
}

func deriveDigest(domain string, material []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(material)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
