// Package rehearsalorchestrator exercises the real control, audit, and plan
// authority contracts before running only the side-effect-free software
// rehearsal simulator. It contains no physical execution path.
package rehearsalorchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	ReportSchemaVersion = "kaiba.secure_boot.integrated_software_rehearsal.v1alpha1"
	ExecutionMode       = "software_only"
	AuthorityClass      = "non_authoritative"
	fixtureDigestDomain = "kaiba.secure_boot.integrated_software_rehearsal.fixture.v1alpha1"
)

var (
	ErrInvalidConfig       = errors.New("invalid integrated rehearsal configuration")
	ErrPersistenceMismatch = errors.New("integrated rehearsal persistence mismatch")
	rehearsalIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
)

// Config contains no paths, executable selectors, device selectors, or
// physical adapter configuration. Now is explicit so tests and reports are
// reproducible. Failure is injected only into the software simulator.
type Config struct {
	RehearsalID string
	Now         time.Time
	Failure     *rehearsal.FailureInjection
}

func (config Config) Validate() error {
	if !rehearsalIDPattern.MatchString(config.RehearsalID) || config.Now.IsZero() {
		return ErrInvalidConfig
	}
	return nil
}

// Stores are the real durability boundaries used by the control and audit
// services. FileStore values make restart verification exercise disk state;
// MemoryStore remains convenient for callers that only need an in-process run.
type Stores struct {
	Control controlplane.Store
	Audit   auditlog.Store
}

// AuthoritySummary exposes only non-secret bindings needed to verify that the
// integrated path ran. It deliberately omits any production completion state.
type AuthoritySummary struct {
	TransactionID          string `json:"transaction_id"`
	ResourceVersion        uint64 `json:"resource_version"`
	FenceEpoch             uint64 `json:"fence_epoch"`
	PlanDigest             string `json:"plan_digest"`
	ApprovalID             string `json:"approval_id"`
	IntentReceipt          string `json:"intent_receipt"`
	ExecuteRequestCount    int    `json:"execute_request_count"`
	InitialCustomerKeyHash string `json:"initial_customer_key_hash"`
	OwnedCustomerKeyHash   string `json:"owned_customer_key_hash"`
}

// Report makes every safety limitation explicit in serialized output.
type Report struct {
	SchemaVersion          string           `json:"schema_version"`
	RehearsalID            string           `json:"rehearsal_id"`
	ExecutionMode          string           `json:"execution_mode"`
	AuthorityClass         string           `json:"authority_class"`
	ControlAuditExercised  bool             `json:"control_audit_exercised"`
	PersistenceRevalidated bool             `json:"persistence_revalidated"`
	HardwareObserved       bool             `json:"hardware_observed"`
	SecurityEnforced       bool             `json:"security_enforced"`
	MutationEligible       bool             `json:"mutation_eligible"`
	Authority              AuthoritySummary `json:"authority"`
	Simulation             rehearsal.Report `json:"simulation"`
	Detail                 string           `json:"detail"`
}

func (report Report) Validate() error {
	if report.SchemaVersion != ReportSchemaVersion || !rehearsalIDPattern.MatchString(report.RehearsalID) ||
		report.ExecutionMode != ExecutionMode || report.AuthorityClass != AuthorityClass ||
		!report.ControlAuditExercised || !report.PersistenceRevalidated ||
		report.HardwareObserved || report.SecurityEnforced || report.MutationEligible {
		return errors.New("integrated rehearsal report crossed its safety boundary")
	}
	if report.Authority.TransactionID == "" || report.Authority.ResourceVersion == 0 || report.Authority.FenceEpoch == 0 ||
		!validDigest(report.Authority.PlanDigest) || report.Authority.ApprovalID == "" ||
		!validDigest(report.Authority.IntentReceipt) || report.Authority.ExecuteRequestCount != campaign.DevelopmentOperationCount ||
		report.Authority.InitialCustomerKeyHash != plancompiler.ZeroCustomerKeyHash ||
		!validDigest(report.Authority.OwnedCustomerKeyHash) ||
		report.Authority.OwnedCustomerKeyHash == report.Authority.InitialCustomerKeyHash {
		return errors.New("integrated rehearsal authority summary is invalid")
	}
	if report.Simulation.RehearsalID != report.RehearsalID {
		return errors.New("integrated rehearsal simulation identity mismatch")
	}
	if err := report.Simulation.Validate(); err != nil {
		return fmt.Errorf("software simulation report: %w", err)
	}
	if report.Detail == "" {
		return errors.New("integrated rehearsal detail is required")
	}
	return nil
}

// Run creates real control and audit records, binds them through plancompiler,
// then invokes only rehearsal.Simulator. It reopens both stores and validates
// the same authority snapshot before returning.
func Run(ctx context.Context, config Config, stores Stores) (Report, error) {
	if err := config.Validate(); err != nil {
		return Report{}, err
	}
	if stores.Control == nil || stores.Audit == nil {
		return Report{}, fmt.Errorf("%w: control and audit stores are required", ErrInvalidConfig)
	}
	// Validate simulator configuration before creating any durable rehearsal
	// authority. Even these non-authoritative stores should stay untouched when
	// the caller supplied an invalid failure scenario.
	simulator, err := rehearsal.NewSimulator(rehearsal.SimulatorConfig{Failure: config.Failure})
	if err != nil {
		return Report{}, err
	}
	clock := config.Now.UTC()
	control, err := controlplane.NewService(stores.Control,
		controlplane.WithClock(func() time.Time { return clock }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) {
			return prefix + "-" + config.RehearsalID, nil
		}),
	)
	if err != nil {
		return Report{}, fmt.Errorf("open control service: %w", err)
	}
	audit, err := auditlog.NewService(stores.Audit, auditlog.WithClock(func() time.Time { return clock }))
	if err != nil {
		return Report{}, fmt.Errorf("open audit service: %w", err)
	}

	fixture := newFixture(config)
	transaction, err := establishAuthority(ctx, control, audit, fixture)
	if err != nil {
		return Report{}, err
	}
	approvalRecord, approvalReceipt, err := eventAuthority(audit, transaction.ID, fixture.approvalID)
	if err != nil {
		return Report{}, err
	}
	record, receipt, err := eventAuthority(audit, transaction.ID, fixture.operationID)
	if err != nil {
		return Report{}, err
	}
	bound, err := plancompiler.Bind(fixture.draft, plancompiler.Authority{
		Transaction:     transaction,
		ApprovalReceipt: approvalReceipt, ApprovalRecord: approvalRecord,
		IntentReceipt: receipt, IntentRecord: record,
		Now: clock, LeaseSafetyMargin: 30 * time.Second,
	})
	if err != nil {
		return Report{}, fmt.Errorf("bind control and audit authority: %w", err)
	}
	plan := bound.Plan()
	requests := bound.ExecuteRequests()
	if err := validateBoundCampaign(plan, requests); err != nil {
		return Report{}, err
	}

	simulation, err := rehearsal.Run(ctx, rehearsal.NewContract(config.RehearsalID), simulator)
	if err != nil {
		return Report{}, fmt.Errorf("run software simulator: %w", err)
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion, RehearsalID: config.RehearsalID,
		ExecutionMode: ExecutionMode, AuthorityClass: AuthorityClass,
		ControlAuditExercised: true, HardwareObserved: false, SecurityEnforced: false, MutationEligible: false,
		Authority: AuthoritySummary{
			TransactionID: transaction.ID, ResourceVersion: transaction.ResourceVersion,
			FenceEpoch: transaction.FenceEpoch, PlanDigest: plan.PlanDigest,
			ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt,
			ExecuteRequestCount:    len(requests),
			InitialCustomerKeyHash: plan.Operations[0].ExpectedPrestate.CustomerKeyHash,
			OwnedCustomerKeyHash:   plan.Operations[0].ExpectedPoststate.CustomerKeyHash,
		},
		Simulation: simulation,
		Detail:     "real control and audit authority was exercised; only a software model ran and no hardware security property was observed or enforced",
	}
	if err := RevalidatePersistence(ctx, config, stores, report); err != nil {
		return Report{}, err
	}
	report.PersistenceRevalidated = true
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

type fixture struct {
	stationID         string
	laneID            string
	transactionID     string
	assetID           string
	logicalID         string
	profileID         string
	policyDigest      string
	targetFingerprint string
	targetObservation string
	release           releasebinding.Binding
	draft             plancompiler.Draft
	approvalID        string
	operationID       string
	operationNames    []string
}

func newFixture(config Config) fixture {
	id := config.RehearsalID
	release := releasebinding.Binding{
		SignedReleaseManifestDigest: fixtureDigest(id, "signed-release-manifest"),
		LaneGuardPackageDigest:      fixtureDigest(id, "lane-guard-package"),
		CompiledArtifactSetDigest:   fixtureDigest(id, "compiled-artifact-set"),
		ExpectedCustomerKeyHash:     fixtureDigest(id, "customer-key"),
		ExpectedEEPROMDigest:        fixtureDigest(id, "eeprom"),
		ExpectedBootImageDigest:     fixtureDigest(id, "boot-image"),
	}
	fresh := laneguard.DirectState{
		CustomerKeyHash: plancompiler.ZeroCustomerKeyHash,
		EEPROMHash:      fixtureDigest(id, "fresh-eeprom"),
		SecurityState:   "fresh",
		PowerState:      "powered_off",
	}
	stationID := "station-" + id
	laneID := "lane-" + id
	transactionID := "transaction-" + id
	draft, err := plancompiler.BuildDraft(plancompiler.DraftInput{
		StationID: stationID, LaneID: laneID, TransactionID: transactionID,
		Release: release, TargetFingerprint: fixtureDigest(id, "target"), FenceEpoch: 1,
		ApprovalExpiresAt: config.Now.UTC().Add(30 * time.Minute), InitialState: fresh,
		AuthorizationIDs: [7]string{
			"software-auth-1", "software-auth-2", "software-auth-3", "software-auth-4",
			"software-auth-5", "software-auth-6", "software-auth-7",
		},
		MaximumDurations: [7]time.Duration{
			time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute,
		},
	})
	if err != nil {
		panic(fmt.Sprintf("construct fixed integrated rehearsal draft: %v", err))
	}
	operations := campaign.DevelopmentOperations()
	operationNames := make([]string, len(operations))
	for index, operation := range operations {
		operationNames[index] = string(operation)
	}
	return fixture{
		stationID: stationID, laneID: laneID, transactionID: transactionID,
		assetID: "asset-" + id, logicalID: "device-" + id, profileID: "rpi5-software-rehearsal",
		policyDigest: fixtureDigest(id, "policy"), targetFingerprint: fixtureDigest(id, "target"),
		targetObservation: fixtureDigest(id, "target-observation"), release: release, draft: draft,
		approvalID:  "approval-" + id,
		operationID: "operation-1-" + id, operationNames: operationNames,
	}
}

func establishAuthority(ctx context.Context, control *controlplane.Service, audit *auditlog.Service, fixture fixture) (controlplane.Transaction, error) {
	transaction, err := control.CreateTransaction(ctx, controlplane.CreateTransactionRequest{
		SchemaVersion: controlplane.CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-" + fixture.transactionID,
		TransactionID: fixture.transactionID, AssetID: fixture.assetID, IntendedLogicalID: fixture.logicalID,
		ProfileID: fixture.profileID, BundleDigest: fixture.release.SignedReleaseManifestDigest,
		PolicyDigest: fixture.policyDigest, ExpectedPrestateCustomerKeyHash: plancompiler.ZeroCustomerKeyHash,
		ExpectedCustomerKeyHash: fixture.release.ExpectedCustomerKeyHash,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("create rehearsal transaction: %w", err)
	}
	transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
		SchemaVersion: controlplane.AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim-" + fixture.transactionID,
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		StationID: fixture.stationID, LaneID: fixture.laneID, Mode: controlplane.ClaimModeMutation,
		AllowedStages: fixture.operationNames, LeaseDurationSeconds: 3600,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("acquire rehearsal claim: %w", err)
	}
	transaction, err = control.BindTarget(ctx, controlplane.BindTargetRequest{
		SchemaVersion: controlplane.BindTargetRequestSchemaVersion, IdempotencyKey: "target-" + fixture.transactionID,
		MutationContext: mutationContext(transaction), TargetFingerprint: fixture.targetFingerprint,
		ObservationDigest: fixture.targetObservation, CustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("bind synthetic rehearsal target: %w", err)
	}
	approvalReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "approval-audit-" + fixture.transactionID,
		Event: auditEvent(fixture, fixture.approvalID, "plan_approval", fixture.draft.PlanDigest(), auditlog.Actor{ID: "software-rehearsal-approver", Role: "approver"}),
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append rehearsal approval audit: %w", err)
	}
	transaction, err = control.RecordApproval(ctx, controlplane.RecordApprovalRequest{
		SchemaVersion: controlplane.RecordApprovalRequestSchemaVersion, IdempotencyKey: "approval-" + fixture.transactionID,
		MutationContext: mutationContext(transaction), ApprovalID: fixture.approvalID, ApproverID: "software-rehearsal-approver",
		TransactionDigest: transaction.TransactionDigest, PlanDigest: fixture.draft.PlanDigest(),
		TargetFingerprint: fixture.targetFingerprint, Release: fixture.release,
		AllowedOperations: fixture.operationNames, AuditReceiptID: approvalReceipt.ReceiptID,
		ExpiresAt: fixture.draft.Snapshot().ApprovalExpiresAt,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record rehearsal approval: %w", err)
	}
	intentReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion: auditlog.AppendRequestSchemaVersion, IdempotencyKey: "intent-audit-" + fixture.transactionID,
		Event: auditEvent(fixture, fixture.operationID, fixture.operationNames[0], fixture.draft.PlanDigest(), auditlog.Actor{ID: fixture.stationID, Role: "software_rehearsal"}),
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("append rehearsal intent audit: %w", err)
	}
	transaction, err = control.RecordIntent(ctx, controlplane.RecordIntentRequest{
		SchemaVersion: controlplane.RecordIntentRequestSchemaVersion, IdempotencyKey: "intent-" + fixture.transactionID,
		MutationContext: mutationContext(transaction), ApprovalID: fixture.approvalID,
		OperationID: fixture.operationID, Operation: fixture.operationNames[0], PlanDigest: fixture.draft.PlanDigest(),
		InputDigest: fixture.draft.PlanDigest(), PrestateDigest: fixture.draft.InitialPrestateDigest(),
		AuditReceiptID: intentReceipt.ReceiptID,
	})
	if err != nil {
		return controlplane.Transaction{}, fmt.Errorf("record rehearsal control intent: %w", err)
	}
	return transaction, nil
}

func auditEvent(fixture fixture, eventID, stage, inputDigest string, actor auditlog.Actor) auditlog.Event {
	return auditlog.Event{
		SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
		EventID: eventID, TransactionID: fixture.transactionID,
		StationID: fixture.stationID, LaneID: fixture.laneID, Stage: stage,
		FenceEpoch: 1, InputDigest: inputDigest, Result: auditlog.ResultIntentRecorded,
		Actors:       []auditlog.Actor{actor},
		TimeEvidence: auditlog.TimeEvidence{StationTime: fixture.draft.Snapshot().ApprovalExpiresAt.Add(-30 * time.Minute), ClockStatus: "synchronized"},
	}
}

func mutationContext(transaction controlplane.Transaction) controlplane.MutationContext {
	return controlplane.MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

func validateBoundCampaign(plan laneguard.Plan, requests []laneguard.ExecuteRequest) error {
	operations := campaign.DevelopmentOperations()
	if len(plan.Operations) != len(operations) || len(requests) != len(operations) {
		return errors.New("bound rehearsal campaign does not contain seven operations")
	}
	for index, operation := range operations {
		if plan.Operations[index].Operation != operation || requests[index].Sequence != uint32(index+1) ||
			requests[index].PlanDigest != plan.PlanDigest || requests[index].ApprovalID != plan.ApprovalID ||
			requests[index].IntentReceipt != plan.IntentReceipt {
			return fmt.Errorf("bound rehearsal request %d differs from the canonical plan", index+1)
		}
	}
	return nil
}

func fixtureDigest(rehearsalID, label string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(fixtureDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(rehearsalID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(label))
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}
