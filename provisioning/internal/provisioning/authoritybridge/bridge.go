// Package authoritybridge authenticates an authority-free plan snapshot
// against stable control-plane state and durable audit records, then emits the
// exact plan/request pair accepted by the physical lane guard.
package authoritybridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
)

const (
	RequestSchemaVersion  = "provisioning.kaiba.network/authority-bridge-request/v1alpha2"
	ResponseSchemaVersion = "provisioning.kaiba.network/authority-bridge-response/v1alpha2"

	// AuthorityReadTimeout is the maximum duration expected from each
	// authenticated control or audit read. Network adapters must enforce this
	// budget so the bridge's whole-operation deadline remains sound.
	AuthorityReadTimeout = 15 * time.Second
)

var (
	ErrInvalidRequest            = errors.New("invalid authority bridge request")
	ErrAuthoritySource           = errors.New("authenticated authority source failed")
	ErrAuthorityChanged          = errors.New("control authority changed while binding")
	ErrAuthorityRecordMissing    = errors.New("required audit authority record is missing")
	ErrAuthorityRecordDuplicate  = errors.New("required audit authority record is duplicated")
	ErrAuthorityRecordUnexpected = errors.New("audit authority returned an unexpected record")
	ErrAuthorityRejected         = errors.New("control or audit authority rejected the plan")
)

type Mode string

const (
	ModeExecute   Mode = "execute"
	ModeReconcile Mode = "reconcile"
)

// BridgeRequest deliberately contains no executable, artifact path, device,
// GPIO, UART, or operation selector. DraftSnapshot is authority-free material
// whose complete digest must already be present in authenticated control and
// audit state.
type BridgeRequest struct {
	SchemaVersion string         `json:"schema_version"`
	Mode          Mode           `json:"mode"`
	TransactionID string         `json:"transaction_id"`
	DraftSnapshot laneguard.Plan `json:"draft_snapshot"`
}

// BoundRequest is a strict union. Exactly one request variant is present and
// the lane guard independently revalidates it against Plan before constructing
// a physical adapter or observing the target.
type BoundRequest struct {
	Plan             laneguard.Plan
	ExecuteRequest   *laneguard.ExecuteRequest
	ReconcileRequest *laneguard.ReconcileRequest
}

// ControlReader and AuditReader are intentionally read-only. Production
// implementations authenticate the remote service and station/lane identity;
// the bridge never accepts authority records from its Unix-socket caller.
type ControlReader interface {
	GetTransaction(context.Context, string) (controlplane.Transaction, error)
}

type AuditReader interface {
	GetRecordsByReceiptIDs(context.Context, string, []string) ([]auditlog.Record, error)
}

type Binder struct {
	Control           ControlReader
	Audit             AuditReader
	Now               func() time.Time
	LeaseSafetyMargin time.Duration
}

// Bind fetches control state twice around the audit read. This closes the
// obvious mixed-snapshot window: any claim, fence, approval, intent, or
// resource-version change during authority collection fails closed.
func (binder Binder) Bind(ctx context.Context, request BridgeRequest) (BoundRequest, error) {
	if err := validateBridgeRequest(request); err != nil {
		return BoundRequest{}, err
	}
	if binder.Control == nil || binder.Audit == nil {
		return BoundRequest{}, fmt.Errorf("%w: readers are not configured", ErrAuthoritySource)
	}
	if binder.LeaseSafetyMargin < 0 {
		return BoundRequest{}, fmt.Errorf("%w: lease safety margin is negative", ErrAuthoritySource)
	}
	now := time.Now
	if binder.Now != nil {
		now = binder.Now
	}

	draft, err := plancompiler.DraftFromSnapshot(request.DraftSnapshot)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: restore draft: %w", ErrInvalidRequest, err)
	}
	first, err := binder.Control.GetTransaction(ctx, request.TransactionID)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: first control read: %w", ErrAuthoritySource, err)
	}
	firstSnapshot, err := json.Marshal(first)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: snapshot first control read: %w", ErrAuthoritySource, err)
	}
	receiptIDs, err := authorityReceiptIDs(first, request.Mode)
	if err != nil {
		return BoundRequest{}, err
	}
	records, err := binder.Audit.GetRecordsByReceiptIDs(ctx, request.TransactionID, receiptIDs)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: audit read: %w", ErrAuthoritySource, err)
	}
	second, err := binder.Control.GetTransaction(ctx, request.TransactionID)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: second control read: %w", ErrAuthoritySource, err)
	}
	secondSnapshot, err := json.Marshal(second)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("%w: snapshot second control read: %w", ErrAuthoritySource, err)
	}
	if !bytes.Equal(firstSnapshot, secondSnapshot) {
		return BoundRequest{}, ErrAuthorityChanged
	}
	approvalRecord, approvalReceipt, err := selectUniqueRecord(records, receiptIDs[0])
	if err != nil {
		return BoundRequest{}, fmt.Errorf("approval authority: %w", err)
	}
	intentRecord, intentReceipt, err := selectUniqueRecord(records, receiptIDs[1])
	if err != nil {
		return BoundRequest{}, fmt.Errorf("intent authority: %w", err)
	}
	if len(records) != len(receiptIDs) {
		return BoundRequest{}, ErrAuthorityRecordUnexpected
	}
	authority := plancompiler.Authority{
		Transaction:       second,
		ApprovalReceipt:   approvalReceipt,
		ApprovalRecord:    approvalRecord,
		IntentReceipt:     intentReceipt,
		IntentRecord:      intentRecord,
		Now:               now().UTC(),
		LeaseSafetyMargin: binder.LeaseSafetyMargin,
	}
	var result BoundRequest
	switch request.Mode {
	case ModeExecute:
		bound, bindErr := plancompiler.Bind(draft, authority)
		if bindErr != nil {
			return BoundRequest{}, fmt.Errorf("%w: bind execution: %w", ErrAuthorityRejected, bindErr)
		}
		plan, executeRequest, executionErr := bound.Execution()
		if executionErr != nil {
			return BoundRequest{}, fmt.Errorf("%w: construct bound execution: %w", ErrAuthorityRejected, executionErr)
		}
		result = BoundRequest{Plan: plan, ExecuteRequest: &executeRequest}
	case ModeReconcile:
		bound, bindErr := plancompiler.BindReconciliation(draft, authority)
		if bindErr != nil {
			return BoundRequest{}, fmt.Errorf("%w: bind reconciliation: %w", ErrAuthorityRejected, bindErr)
		}
		plan, reconcileRequest, reconciliationErr := bound.Reconciliation()
		if reconciliationErr != nil {
			return BoundRequest{}, fmt.Errorf("%w: construct bound reconciliation: %w", ErrAuthorityRejected, reconciliationErr)
		}
		result = BoundRequest{Plan: plan, ReconcileRequest: &reconcileRequest}
	}
	if err := validateBoundRequest(result, request); err != nil {
		return BoundRequest{}, fmt.Errorf("%w: generated binding: %w", ErrAuthorityRejected, err)
	}
	return result, nil
}

func validateBridgeRequest(request BridgeRequest) error {
	if request.SchemaVersion != RequestSchemaVersion || request.TransactionID == "" || request.TransactionID != request.DraftSnapshot.TransactionID {
		return ErrInvalidRequest
	}
	switch request.Mode {
	case ModeExecute, ModeReconcile:
		return nil
	default:
		return ErrInvalidRequest
	}
}

func authorityReceiptIDs(transaction controlplane.Transaction, mode Mode) ([]string, error) {
	if len(transaction.Operations) == 0 {
		return nil, ErrAuthorityRecordMissing
	}
	operation := transaction.Operations[len(transaction.Operations)-1]
	if operation.IntentAuditReceiptID == "" {
		return nil, ErrAuthorityRecordMissing
	}
	var approvalReceiptID string
	switch mode {
	case ModeExecute:
		if transaction.Approval != nil {
			approvalReceiptID = transaction.Approval.AuditReceiptID
		}
	case ModeReconcile:
		approvalReceiptID = operation.Approval.AuditReceiptID
	}
	if approvalReceiptID == "" {
		return nil, ErrAuthorityRecordMissing
	}
	return []string{approvalReceiptID, operation.IntentAuditReceiptID}, nil
}

func selectUniqueRecord(records []auditlog.Record, receiptID string) (auditlog.Record, auditlog.Receipt, error) {
	var selected auditlog.Record
	matches := 0
	for _, record := range records {
		receipt := receiptFromRecord(record)
		if receipt.ReceiptID == receiptID {
			selected = record
			matches++
		}
	}
	switch matches {
	case 0:
		return auditlog.Record{}, auditlog.Receipt{}, ErrAuthorityRecordMissing
	case 1:
		return selected, receiptFromRecord(selected), nil
	default:
		return auditlog.Record{}, auditlog.Receipt{}, ErrAuthorityRecordDuplicate
	}
}

func receiptFromRecord(record auditlog.Record) auditlog.Receipt {
	digest := sha256.Sum256([]byte("kaiba-audit-receipt\x00" + record.EventHash))
	return auditlog.Receipt{
		SchemaVersion:     auditlog.ReceiptSchemaVersion,
		ReceiptID:         "sha256:" + hex.EncodeToString(digest[:]),
		Sequence:          record.Sequence,
		PreviousEventHash: record.PreviousEventHash,
		EventHash:         record.EventHash,
		RecordedAt:        record.RecordedAt,
	}
}

func validateBoundRequest(binding BoundRequest, source BridgeRequest) error {
	if binding.Plan.TransactionID != source.TransactionID || binding.Plan.PlanDigest != source.DraftSnapshot.PlanDigest {
		return errors.New("binding identity differs from the requested draft")
	}
	authorityFree := binding.Plan
	authorityFree.ApprovalID = ""
	authorityFree.IntentReceipt = ""
	authorityFree.IntentSequence = 0
	if _, err := plancompiler.DraftFromSnapshot(authorityFree); err != nil {
		return fmt.Errorf("bound plan body: %w", err)
	}
	if !reflect.DeepEqual(authorityFree, source.DraftSnapshot) {
		return errors.New("bound plan body differs from the requested draft")
	}
	switch source.Mode {
	case ModeExecute:
		if binding.ExecuteRequest == nil || binding.ReconcileRequest != nil || binding.ExecuteRequest.TransactionID != source.TransactionID {
			return errors.New("execution response is not a strict execute request")
		}
		if err := laneguard.ValidatePlanRequest(validationConfig(binding.Plan.StationID, binding.Plan.LaneID), binding.Plan, *binding.ExecuteRequest); err != nil {
			return fmt.Errorf("plan/execute-request contract: %w", err)
		}
	case ModeReconcile:
		if binding.ExecuteRequest != nil || binding.ReconcileRequest == nil || binding.ReconcileRequest.OriginalRequest.TransactionID != source.TransactionID {
			return errors.New("reconciliation response is not a strict reconcile request")
		}
		claim := binding.ReconcileRequest.Claim
		if err := laneguard.ValidateReconcileRequest(validationConfig(claim.StationID, claim.LaneID), binding.Plan, *binding.ReconcileRequest); err != nil {
			return fmt.Errorf("plan/reconcile-request contract: %w", err)
		}
	default:
		return errors.New("binding mode is invalid")
	}
	return nil
}

func validationConfig(stationID, laneID string) laneguard.Config {
	return laneguard.Config{
		SchemaVersion:    laneguard.ContractSchemaVersion,
		StationID:        stationID,
		LaneID:           laneID,
		RPIBootSysfsPath: "/sys/bus/usb/devices/authority-bridge-validation",
		UARTPath:         "/dev/serial/by-id/authority-bridge-validation",
		PowerGPIO:        laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0"},
	}
}
