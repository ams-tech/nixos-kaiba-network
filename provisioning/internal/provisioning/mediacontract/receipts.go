package mediacontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

const (
	StageStatusReadbackRequired = "staged_readback_required"
	VerificationStatusVerified  = "full_media_verified"
	FinalStatusVerified         = "media_staging_verified"
)

type VerificationMode string

const (
	VerificationIndependentDevice VerificationMode = "independent_read_only_device"
	VerificationRegularFixture    VerificationMode = "regular_file_fixture"
)

type ColdObservationMode string

const (
	ColdObservationManual ColdObservationMode = "manual_operator_confirmation"
)

type RegionVerification struct {
	Role     RegionRole `json:"role"`
	Digest   Digest     `json:"digest"`
	Verified bool       `json:"verified"`
}

type StageReceipt struct {
	SchemaVersion               string        `json:"schema_version"`
	Status                      string        `json:"status"`
	TransactionID               string        `json:"transaction_id"`
	PlanDigest                  Digest        `json:"plan_digest"`
	SignedReleaseManifestDigest Digest        `json:"signed_release_manifest_digest"`
	LayoutDigest                Digest        `json:"layout_digest"`
	Target                      TargetBinding `json:"target"`
	AttachmentBootID            string        `json:"attachment_boot_id"`
	AttachmentSequence          uint64        `json:"attachment_sequence"`
	InitialMediaDigest          Digest        `json:"initial_media_digest"`
	ExpectedMediaDigest         Digest        `json:"expected_media_digest"`
	ObservedMediaDigest         Digest        `json:"observed_media_digest"`
	BytesWritten                uint64        `json:"bytes_written"`
	FSyncComplete               bool          `json:"fsync_complete"`
	ReopenedTarget              bool          `json:"reopened_target"`
	IndependentReadbackRequired bool          `json:"independent_readback_required"`
	ColdPowerCycleObserved      bool          `json:"cold_power_cycle_observed"`
	OneTimeSettingsChanged      bool          `json:"one_time_settings_changed"`
	ReceiptDigest               Digest        `json:"receipt_digest"`
}

func NewStageReceipt(plan Plan, attachmentBootID string, attachmentSequence uint64, observedMediaDigest Digest) (StageReceipt, error) {
	if err := plan.Validate(); err != nil {
		return StageReceipt{}, err
	}
	bytesWritten, err := stageBytesWritten(plan)
	if err != nil {
		return StageReceipt{}, err
	}
	receipt := StageReceipt{
		SchemaVersion:               StageReceiptSchemaVersion,
		Status:                      StageStatusReadbackRequired,
		TransactionID:               plan.TransactionID,
		PlanDigest:                  plan.PlanDigest,
		SignedReleaseManifestDigest: plan.Release.SignedReleaseManifestDigest,
		LayoutDigest:                plan.Layout.LayoutDigest,
		Target:                      plan.Target,
		AttachmentBootID:            attachmentBootID,
		AttachmentSequence:          attachmentSequence,
		InitialMediaDigest:          plan.InitialMediaDigest,
		ExpectedMediaDigest:         plan.ExpectedMediaDigest,
		ObservedMediaDigest:         observedMediaDigest,
		BytesWritten:                bytesWritten,
		FSyncComplete:               true,
		ReopenedTarget:              true,
		IndependentReadbackRequired: true,
	}
	digest, err := receipt.derivedDigest(plan)
	if err != nil {
		return StageReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, nil
}

// stageBytesWritten is the exact I/O count for the frozen writer algorithm:
// one complete-target zeroing pass followed by one write of each immutable
// source. It is intentionally distinct from the final target size.
func stageBytesWritten(plan Plan) (uint64, error) {
	total := plan.Target.SizeBytes
	for _, source := range plan.Layout.Sources {
		if source.SizeBytes > math.MaxUint64-total {
			return 0, errors.New("stage byte count overflows uint64")
		}
		total += source.SizeBytes
	}
	return total, nil
}

func (receipt StageReceipt) digestMaterial() ([]byte, error) {
	material := receipt
	material.ReceiptDigest = ""
	return json.Marshal(material)
}

func (receipt StageReceipt) derivedDigest(plan Plan) (Digest, error) {
	if err := receipt.validateAgainst(plan, false); err != nil {
		return "", err
	}
	material, err := receipt.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode stage receipt digest material: %w", err)
	}
	return domainDigest(stageReceiptDigestDomain, material), nil
}

func (receipt StageReceipt) ValidateAgainst(plan Plan) error {
	return receipt.validateAgainst(plan, true)
}

func (receipt StageReceipt) validateAgainst(plan Plan, requireDigest bool) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if receipt.SchemaVersion != StageReceiptSchemaVersion || receipt.Status != StageStatusReadbackRequired {
		return errors.New("stage receipt has an unsupported schema or status")
	}
	if receipt.TransactionID != plan.TransactionID || receipt.PlanDigest != plan.PlanDigest ||
		receipt.SignedReleaseManifestDigest != plan.Release.SignedReleaseManifestDigest ||
		receipt.LayoutDigest != plan.Layout.LayoutDigest || receipt.Target != plan.Target {
		return errors.New("stage receipt transaction, release, layout, plan, or target binding differs")
	}
	if err := validateGUID("stage attachment_boot_id", receipt.AttachmentBootID); err != nil {
		return err
	}
	if receipt.AttachmentSequence == 0 {
		return errors.New("stage receipt requires a non-zero boot-local attachment sequence")
	}
	if receipt.InitialMediaDigest != plan.InitialMediaDigest || receipt.ExpectedMediaDigest != plan.ExpectedMediaDigest || receipt.ObservedMediaDigest != plan.ExpectedMediaDigest {
		return errors.New("stage receipt media digests differ from the approved plan")
	}
	expectedBytesWritten, err := stageBytesWritten(plan)
	if err != nil {
		return err
	}
	if receipt.BytesWritten != expectedBytesWritten || !receipt.FSyncComplete || !receipt.ReopenedTarget || !receipt.IndependentReadbackRequired || receipt.ColdPowerCycleObserved || receipt.OneTimeSettingsChanged {
		return errors.New("stage receipt safety state is not the exact post-fsync/pre-readback state")
	}
	if requireDigest {
		if err := validateDigest("stage receipt_digest", receipt.ReceiptDigest); err != nil {
			return err
		}
		derived, err := receipt.derivedDigest(plan)
		if err != nil {
			return err
		}
		if receipt.ReceiptDigest != derived {
			return errors.New("stage receipt_digest does not match canonical receipt content")
		}
	}
	return nil
}

func (receipt StageReceipt) CanonicalJSON(plan Plan) ([]byte, error) {
	if err := receipt.ValidateAgainst(plan); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func ParseStageReceipt(data []byte, plan Plan) (StageReceipt, error) {
	var receipt StageReceipt
	err := strictCanonicalDecode(data, &receipt, func() ([]byte, error) { return receipt.CanonicalJSON(plan) })
	return receipt, err
}

type VerificationReceipt struct {
	SchemaVersion               string               `json:"schema_version"`
	Status                      string               `json:"status"`
	VerificationMode            VerificationMode     `json:"verification_mode"`
	TransactionID               string               `json:"transaction_id"`
	PlanDigest                  Digest               `json:"plan_digest"`
	StageReceiptDigest          Digest               `json:"stage_receipt_digest"`
	SignedReleaseManifestDigest Digest               `json:"signed_release_manifest_digest"`
	LayoutDigest                Digest               `json:"layout_digest"`
	Target                      TargetBinding        `json:"target"`
	AttachmentBootID            string               `json:"attachment_boot_id"`
	AttachmentSequence          uint64               `json:"attachment_sequence"`
	FullMediaDigest             Digest               `json:"full_media_digest"`
	Regions                     []RegionVerification `json:"regions"`
	GPTVerified                 bool                 `json:"gpt_verified"`
	FATVerified                 bool                 `json:"fat_verified"`
	PartitionDigestsVerified    bool                 `json:"partition_digests_verified"`
	DMVerityVerified            bool                 `json:"dm_verity_verified"`
	BootSignatureVerified       bool                 `json:"boot_signature_verified"`
	ReleaseLineageVerified      bool                 `json:"release_lineage_verified"`
	ReopenedTarget              bool                 `json:"reopened_target"`
	ColdPowerCycleObserved      bool                 `json:"cold_power_cycle_observed"`
	OneTimeSettingsChanged      bool                 `json:"one_time_settings_changed"`
	ReceiptDigest               Digest               `json:"receipt_digest"`
}

func NewVerificationReceipt(plan Plan, stage StageReceipt, mode VerificationMode, attachmentBootID string, attachmentSequence uint64, report VerificationReport) (VerificationReceipt, error) {
	if err := stage.ValidateAgainst(plan); err != nil {
		return VerificationReceipt{}, err
	}
	if report.SchemaVersion != VerificationReportSchemaVersion {
		return VerificationReceipt{}, errors.New("verification report has an unsupported schema")
	}
	receipt := VerificationReceipt{
		SchemaVersion:               VerificationReceiptSchemaVersion,
		Status:                      VerificationStatusVerified,
		VerificationMode:            mode,
		TransactionID:               plan.TransactionID,
		PlanDigest:                  plan.PlanDigest,
		StageReceiptDigest:          stage.ReceiptDigest,
		SignedReleaseManifestDigest: plan.Release.SignedReleaseManifestDigest,
		LayoutDigest:                plan.Layout.LayoutDigest,
		Target:                      plan.Target,
		AttachmentBootID:            attachmentBootID,
		AttachmentSequence:          attachmentSequence,
		FullMediaDigest:             report.FullMediaDigest,
		Regions:                     append([]RegionVerification(nil), report.Regions...),
		GPTVerified:                 report.GPTVerified,
		FATVerified:                 report.FATVerified,
		PartitionDigestsVerified:    report.PartitionDigestsVerified,
		DMVerityVerified:            report.DMVerityVerified,
		BootSignatureVerified:       report.BootSignatureVerified,
		ReleaseLineageVerified:      report.ReleaseLineageVerified,
		ReopenedTarget:              true,
	}
	digest, err := receipt.derivedDigest(plan, stage)
	if err != nil {
		return VerificationReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, nil
}

func (receipt VerificationReceipt) digestMaterial() ([]byte, error) {
	material := receipt
	material.ReceiptDigest = ""
	return json.Marshal(material)
}

func (receipt VerificationReceipt) derivedDigest(plan Plan, stage StageReceipt) (Digest, error) {
	if err := receipt.validateAgainst(plan, stage, false); err != nil {
		return "", err
	}
	material, err := receipt.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode verification receipt digest material: %w", err)
	}
	return domainDigest(verifyReceiptDomain, material), nil
}

func (receipt VerificationReceipt) ValidateAgainst(plan Plan, stage StageReceipt) error {
	return receipt.validateAgainst(plan, stage, true)
}

func (receipt VerificationReceipt) validateAgainst(plan Plan, stage StageReceipt, requireDigest bool) error {
	if err := stage.ValidateAgainst(plan); err != nil {
		return err
	}
	if receipt.SchemaVersion != VerificationReceiptSchemaVersion || receipt.Status != VerificationStatusVerified {
		return errors.New("verification receipt has an unsupported schema or status")
	}
	if receipt.VerificationMode != VerificationIndependentDevice && receipt.VerificationMode != VerificationRegularFixture {
		return errors.New("verification receipt has an unsupported verification_mode")
	}
	if receipt.TransactionID != plan.TransactionID || receipt.PlanDigest != plan.PlanDigest || receipt.StageReceiptDigest != stage.ReceiptDigest ||
		receipt.SignedReleaseManifestDigest != plan.Release.SignedReleaseManifestDigest || receipt.LayoutDigest != plan.Layout.LayoutDigest || receipt.Target != plan.Target {
		return errors.New("verification receipt transaction, release, layout, plan, stage, or target binding differs")
	}
	if receipt.VerificationMode == VerificationIndependentDevice {
		if err := validateGUID("verification attachment_boot_id", receipt.AttachmentBootID); err != nil {
			return err
		}
		if receipt.AttachmentSequence == 0 || (receipt.AttachmentBootID == stage.AttachmentBootID && receipt.AttachmentSequence == stage.AttachmentSequence) {
			return errors.New("independent device verification requires a distinct non-zero (boot_id, attachment sequence) identity")
		}
	} else if receipt.AttachmentBootID != "" || receipt.AttachmentSequence != 0 {
		return errors.New("regular-file fixture verification cannot claim a device attachment identity")
	}
	if receipt.FullMediaDigest != plan.ExpectedMediaDigest || len(receipt.Regions) != len(plan.Layout.Regions) {
		return errors.New("verification receipt full-media or region coverage differs from the plan")
	}
	for index, expected := range plan.Layout.Regions {
		actual := receipt.Regions[index]
		if actual.Role != expected.Role || actual.Digest != expected.ContentDigest || !actual.Verified {
			return fmt.Errorf("verification receipt region %d is not the exact verified plan region", index)
		}
	}
	if !receipt.GPTVerified || !receipt.FATVerified || !receipt.PartitionDigestsVerified || !receipt.DMVerityVerified || !receipt.BootSignatureVerified || !receipt.ReleaseLineageVerified || !receipt.ReopenedTarget || receipt.ColdPowerCycleObserved || receipt.OneTimeSettingsChanged {
		return errors.New("verification receipt is missing a required independent verification or contains a prohibited claim")
	}
	if requireDigest {
		if err := validateDigest("verification receipt_digest", receipt.ReceiptDigest); err != nil {
			return err
		}
		derived, err := receipt.derivedDigest(plan, stage)
		if err != nil {
			return err
		}
		if receipt.ReceiptDigest != derived {
			return errors.New("verification receipt_digest does not match canonical receipt content")
		}
	}
	return nil
}

func (receipt VerificationReceipt) CanonicalJSON(plan Plan, stage StageReceipt) ([]byte, error) {
	if err := receipt.ValidateAgainst(plan, stage); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func ParseVerificationReceipt(data []byte, plan Plan, stage StageReceipt) (VerificationReceipt, error) {
	var receipt VerificationReceipt
	err := strictCanonicalDecode(data, &receipt, func() ([]byte, error) { return receipt.CanonicalJSON(plan, stage) })
	return receipt, err
}

type ColdPowerObservation struct {
	SchemaVersion             string              `json:"schema_version"`
	ObservationID             string              `json:"observation_id"`
	ObservationMode           ColdObservationMode `json:"observation_mode"`
	TransactionID             string              `json:"transaction_id"`
	PlanDigest                Digest              `json:"plan_digest"`
	StageReceiptDigest        Digest              `json:"stage_receipt_digest"`
	VerificationReceiptDigest Digest              `json:"verification_receipt_digest"`
	Target                    TargetBinding       `json:"target"`
	BeforeAttachmentBootID    string              `json:"before_attachment_boot_id"`
	BeforeAttachmentSequence  uint64              `json:"before_attachment_sequence"`
	AfterAttachmentBootID     string              `json:"after_attachment_boot_id"`
	AfterAttachmentSequence   uint64              `json:"after_attachment_sequence"`
	CompletePowerRemoval      bool                `json:"complete_power_removal"`
	CollectorEvidenceDigest   Digest              `json:"collector_evidence_digest"`
	CaptureAuthenticated      bool                `json:"capture_authenticated"`
	FreshnessEstablished      bool                `json:"freshness_established"`
	ObservationDigest         Digest              `json:"observation_digest"`
}

func (observation ColdPowerObservation) digestMaterial() ([]byte, error) {
	material := observation
	material.ObservationDigest = ""
	return json.Marshal(material)
}

func (observation ColdPowerObservation) derivedDigest(plan Plan, stage StageReceipt, verification VerificationReceipt) (Digest, error) {
	if err := observation.validateAgainst(plan, stage, verification, false); err != nil {
		return "", err
	}
	material, err := observation.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode cold-power observation digest material: %w", err)
	}
	return domainDigest(coldObservationDomain, material), nil
}

func (observation ColdPowerObservation) WithDerivedDigest(plan Plan, stage StageReceipt, verification VerificationReceipt) (ColdPowerObservation, error) {
	derived := observation
	derived.ObservationDigest = ""
	digest, err := derived.derivedDigest(plan, stage, verification)
	if err != nil {
		return ColdPowerObservation{}, err
	}
	derived.ObservationDigest = digest
	return derived, nil
}

func (observation ColdPowerObservation) ValidateAgainst(plan Plan, stage StageReceipt, verification VerificationReceipt) error {
	return observation.validateAgainst(plan, stage, verification, true)
}

func (observation ColdPowerObservation) validateAgainst(plan Plan, stage StageReceipt, verification VerificationReceipt, requireDigest bool) error {
	if err := verification.ValidateAgainst(plan, stage); err != nil {
		return err
	}
	if verification.VerificationMode != VerificationIndependentDevice {
		return errors.New("a regular-file fixture cannot satisfy a cold-power observation")
	}
	if observation.SchemaVersion != ColdObservationSchemaVersion {
		return errors.New("cold-power observation has an unsupported schema")
	}
	if err := validateIdentifier("observation_id", observation.ObservationID); err != nil {
		return err
	}
	if observation.ObservationMode != ColdObservationManual {
		return errors.New("cold-power observation requires manual operator confirmation; no authenticated collector authority is implemented")
	}
	if observation.TransactionID != plan.TransactionID || observation.PlanDigest != plan.PlanDigest || observation.StageReceiptDigest != stage.ReceiptDigest || observation.VerificationReceiptDigest != verification.ReceiptDigest || observation.Target != plan.Target {
		return errors.New("cold-power observation transaction, receipt, plan, or target binding differs")
	}
	if observation.BeforeAttachmentBootID != stage.AttachmentBootID || observation.BeforeAttachmentSequence != stage.AttachmentSequence ||
		observation.AfterAttachmentBootID != verification.AttachmentBootID || observation.AfterAttachmentSequence != verification.AttachmentSequence ||
		(observation.BeforeAttachmentBootID == observation.AfterAttachmentBootID && observation.BeforeAttachmentSequence == observation.AfterAttachmentSequence) || !observation.CompletePowerRemoval {
		return errors.New("cold-power observation does not bind the distinct staging and verification attachments")
	}
	if err := validateDigest("collector_evidence_digest", observation.CollectorEvidenceDigest); err != nil {
		return err
	}
	if observation.CaptureAuthenticated || observation.FreshnessEstablished {
		return errors.New("manual cold-power observation cannot claim authenticated capture or freshness")
	}
	if requireDigest {
		if err := validateDigest("observation_digest", observation.ObservationDigest); err != nil {
			return err
		}
		derived, err := observation.derivedDigest(plan, stage, verification)
		if err != nil {
			return err
		}
		if observation.ObservationDigest != derived {
			return errors.New("observation_digest does not match canonical observation content")
		}
	}
	return nil
}

func (observation ColdPowerObservation) CanonicalJSON(plan Plan, stage StageReceipt, verification VerificationReceipt) ([]byte, error) {
	if err := observation.ValidateAgainst(plan, stage, verification); err != nil {
		return nil, err
	}
	return json.Marshal(observation)
}

func ParseColdPowerObservation(data []byte, plan Plan, stage StageReceipt, verification VerificationReceipt) (ColdPowerObservation, error) {
	var observation ColdPowerObservation
	err := strictCanonicalDecode(data, &observation, func() ([]byte, error) {
		return observation.CanonicalJSON(plan, stage, verification)
	})
	return observation, err
}

type FinalReceipt struct {
	SchemaVersion               string        `json:"schema_version"`
	Status                      string        `json:"status"`
	TransactionID               string        `json:"transaction_id"`
	PlanDigest                  Digest        `json:"plan_digest"`
	StageReceiptDigest          Digest        `json:"stage_receipt_digest"`
	VerificationReceiptDigest   Digest        `json:"verification_receipt_digest"`
	ColdPowerObservationDigest  Digest        `json:"cold_power_observation_digest"`
	SignedReleaseManifestDigest Digest        `json:"signed_release_manifest_digest"`
	LayoutDigest                Digest        `json:"layout_digest"`
	Target                      TargetBinding `json:"target"`
	FullMediaDigest             Digest        `json:"full_media_digest"`
	ColdReadbackVerified        bool          `json:"cold_readback_verified"`
	CaptureAuthenticated        bool          `json:"capture_authenticated"`
	FreshnessEstablished        bool          `json:"freshness_established"`
	HardwareObserved            bool          `json:"hardware_observed"`
	SecurityEnforced            bool          `json:"security_enforced"`
	MutationEligible            bool          `json:"mutation_eligible"`
	OneTimeSettingsChanged      bool          `json:"one_time_settings_changed"`
	ReceiptDigest               Digest        `json:"receipt_digest"`
}

func Finalize(plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation) (FinalReceipt, error) {
	if err := observation.ValidateAgainst(plan, stage, verification); err != nil {
		return FinalReceipt{}, err
	}
	receipt := FinalReceipt{
		SchemaVersion:               FinalReceiptSchemaVersion,
		Status:                      FinalStatusVerified,
		TransactionID:               plan.TransactionID,
		PlanDigest:                  plan.PlanDigest,
		StageReceiptDigest:          stage.ReceiptDigest,
		VerificationReceiptDigest:   verification.ReceiptDigest,
		ColdPowerObservationDigest:  observation.ObservationDigest,
		SignedReleaseManifestDigest: plan.Release.SignedReleaseManifestDigest,
		LayoutDigest:                plan.Layout.LayoutDigest,
		Target:                      plan.Target,
		FullMediaDigest:             verification.FullMediaDigest,
		ColdReadbackVerified:        true,
		CaptureAuthenticated:        false,
		FreshnessEstablished:        false,
		HardwareObserved:            false,
	}
	digest, err := receipt.derivedDigest(plan, stage, verification, observation)
	if err != nil {
		return FinalReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, nil
}

func (receipt FinalReceipt) digestMaterial() ([]byte, error) {
	material := receipt
	material.ReceiptDigest = ""
	return json.Marshal(material)
}

func (receipt FinalReceipt) derivedDigest(plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation) (Digest, error) {
	if err := receipt.validateAgainst(plan, stage, verification, observation, false); err != nil {
		return "", err
	}
	material, err := receipt.digestMaterial()
	if err != nil {
		return "", fmt.Errorf("encode final receipt digest material: %w", err)
	}
	return domainDigest(finalReceiptDomain, material), nil
}

func (receipt FinalReceipt) ValidateAgainst(plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation) error {
	return receipt.validateAgainst(plan, stage, verification, observation, true)
}

func (receipt FinalReceipt) validateAgainst(plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation, requireDigest bool) error {
	if err := observation.ValidateAgainst(plan, stage, verification); err != nil {
		return err
	}
	if receipt.SchemaVersion != FinalReceiptSchemaVersion || receipt.Status != FinalStatusVerified {
		return errors.New("final receipt has an unsupported schema or status")
	}
	if receipt.TransactionID != plan.TransactionID || receipt.PlanDigest != plan.PlanDigest || receipt.StageReceiptDigest != stage.ReceiptDigest || receipt.VerificationReceiptDigest != verification.ReceiptDigest || receipt.ColdPowerObservationDigest != observation.ObservationDigest || receipt.SignedReleaseManifestDigest != plan.Release.SignedReleaseManifestDigest || receipt.LayoutDigest != plan.Layout.LayoutDigest || receipt.Target != plan.Target || receipt.FullMediaDigest != plan.ExpectedMediaDigest {
		return errors.New("final receipt binding differs from its raw authority inputs")
	}
	if !receipt.ColdReadbackVerified || receipt.CaptureAuthenticated || receipt.FreshnessEstablished || receipt.HardwareObserved || receipt.SecurityEnforced || receipt.MutationEligible || receipt.OneTimeSettingsChanged {
		return errors.New("final receipt contains an invalid safety or authority claim")
	}
	if requireDigest {
		if err := validateDigest("final receipt_digest", receipt.ReceiptDigest); err != nil {
			return err
		}
		derived, err := receipt.derivedDigest(plan, stage, verification, observation)
		if err != nil {
			return err
		}
		if receipt.ReceiptDigest != derived {
			return errors.New("final receipt_digest does not match canonical receipt content")
		}
	}
	return nil
}

func (receipt FinalReceipt) CanonicalJSON(plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation) ([]byte, error) {
	if err := receipt.ValidateAgainst(plan, stage, verification, observation); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func ParseFinalReceipt(data []byte, plan Plan, stage StageReceipt, verification VerificationReceipt, observation ColdPowerObservation) (FinalReceipt, error) {
	var receipt FinalReceipt
	err := strictCanonicalDecode(data, &receipt, func() ([]byte, error) {
		return receipt.CanonicalJSON(plan, stage, verification, observation)
	})
	return receipt, err
}
