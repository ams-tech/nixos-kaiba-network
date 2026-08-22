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
	RequestSchemaVersion  = "provisioning.kaiba.network/authority-bridge-request/v1alpha1"
	ResponseSchemaVersion = "provisioning.kaiba.network/authority-bridge-response/v1alpha1"

	// AuthorityReadTimeout is the maximum duration expected from each
	// authenticated control or audit read. Network adapters must enforce this
	// budget so the bridge's whole-operation deadline remains sound.
	AuthorityReadTimeout = 15 * time.Second
)

var (
	ErrInvalidRequest            = errors.New("invalid authority bridge request")
	ErrReconciliationUnsupported = errors.New("authenticated reconciliation is not implemented")
	ErrAuthoritySource           = errors.New("authenticated authority source failed")
	ErrAuthorityChanged          = errors.New("control authority changed while binding")
	ErrAuthorityRecordMissing    = errors.New("required audit authority record is missing")
	ErrAuthorityRecordDuplicate  = errors.New("required audit authority record is duplicated")
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

// BoundExecution is the only successful bridge result. The lane guard still
// independently validates the pair and its immutable release binding before
// constructing a physical adapter.
type BoundExecution struct {
	Plan    laneguard.Plan           `json:"plan"`
	Request laneguard.ExecuteRequest `json:"request"`
}

// ControlReader and AuditReader are intentionally read-only. Production
// implementations authenticate the remote service and station/lane identity;
// the bridge never accepts authority records from its Unix-socket caller.
type ControlReader interface {
	GetTransaction(context.Context, string) (controlplane.Transaction, error)
}

type AuditReader interface {
	GetRecords(context.Context, string) ([]auditlog.Record, error)
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
func (binder Binder) Bind(ctx context.Context, request BridgeRequest) (BoundExecution, error) {
	if err := validateBridgeRequest(request); err != nil {
		return BoundExecution{}, err
	}
	if binder.Control == nil || binder.Audit == nil {
		return BoundExecution{}, fmt.Errorf("%w: readers are not configured", ErrAuthoritySource)
	}
	if binder.LeaseSafetyMargin < 0 {
		return BoundExecution{}, fmt.Errorf("%w: lease safety margin is negative", ErrAuthoritySource)
	}
	now := time.Now
	if binder.Now != nil {
		now = binder.Now
	}

	draft, err := plancompiler.DraftFromSnapshot(request.DraftSnapshot)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: restore draft: %w", ErrInvalidRequest, err)
	}
	first, err := binder.Control.GetTransaction(ctx, request.TransactionID)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: first control read: %w", ErrAuthoritySource, err)
	}
	firstSnapshot, err := json.Marshal(first)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: snapshot first control read: %w", ErrAuthoritySource, err)
	}
	records, err := binder.Audit.GetRecords(ctx, request.TransactionID)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: audit read: %w", ErrAuthoritySource, err)
	}
	second, err := binder.Control.GetTransaction(ctx, request.TransactionID)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: second control read: %w", ErrAuthoritySource, err)
	}
	secondSnapshot, err := json.Marshal(second)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: snapshot second control read: %w", ErrAuthoritySource, err)
	}
	if !bytes.Equal(firstSnapshot, secondSnapshot) {
		return BoundExecution{}, ErrAuthorityChanged
	}
	if second.Approval == nil || second.Approval.AuditReceiptID == "" || len(second.Operations) == 0 {
		return BoundExecution{}, ErrAuthorityRecordMissing
	}
	currentIntent := second.Operations[len(second.Operations)-1]
	if currentIntent.IntentAuditReceiptID == "" {
		return BoundExecution{}, ErrAuthorityRecordMissing
	}
	approvalRecord, approvalReceipt, err := selectUniqueRecord(records, second.Approval.AuditReceiptID)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("approval authority: %w", err)
	}
	intentRecord, intentReceipt, err := selectUniqueRecord(records, currentIntent.IntentAuditReceiptID)
	if err != nil {
		return BoundExecution{}, fmt.Errorf("intent authority: %w", err)
	}
	bound, err := plancompiler.Bind(draft, plancompiler.Authority{
		Transaction:       second,
		ApprovalReceipt:   approvalReceipt,
		ApprovalRecord:    approvalRecord,
		IntentReceipt:     intentReceipt,
		IntentRecord:      intentRecord,
		Now:               now().UTC(),
		LeaseSafetyMargin: binder.LeaseSafetyMargin,
	})
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: bind plan: %w", ErrAuthorityRejected, err)
	}
	plan, executeRequest, err := bound.Execution()
	if err != nil {
		return BoundExecution{}, fmt.Errorf("%w: construct bound execution: %w", ErrAuthorityRejected, err)
	}
	execution := BoundExecution{Plan: plan, Request: executeRequest}
	if err := validateBoundExecution(execution, request); err != nil {
		return BoundExecution{}, fmt.Errorf("%w: generated execution: %w", ErrAuthorityRejected, err)
	}
	return execution, nil
}

func validateBridgeRequest(request BridgeRequest) error {
	if request.SchemaVersion != RequestSchemaVersion || request.TransactionID == "" || request.TransactionID != request.DraftSnapshot.TransactionID {
		return ErrInvalidRequest
	}
	switch request.Mode {
	case ModeExecute:
		return nil
	case ModeReconcile:
		return ErrReconciliationUnsupported
	default:
		return ErrInvalidRequest
	}
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

func validateBoundExecution(execution BoundExecution, source BridgeRequest) error {
	if execution.Plan.TransactionID != source.TransactionID || execution.Plan.PlanDigest != source.DraftSnapshot.PlanDigest ||
		execution.Request.TransactionID != source.TransactionID {
		return errors.New("execution identity differs from the requested draft")
	}
	authorityFree := execution.Plan
	authorityFree.ApprovalID = ""
	authorityFree.IntentReceipt = ""
	authorityFree.IntentSequence = 0
	if _, err := plancompiler.DraftFromSnapshot(authorityFree); err != nil {
		return fmt.Errorf("bound plan body: %w", err)
	}
	if !reflect.DeepEqual(authorityFree, source.DraftSnapshot) {
		return errors.New("bound plan body differs from the requested draft")
	}
	config := validationConfig(execution.Plan)
	if err := laneguard.ValidatePlanRequest(config, execution.Plan, execution.Request); err != nil {
		return fmt.Errorf("plan/request contract: %w", err)
	}
	return nil
}

func validationConfig(plan laneguard.Plan) laneguard.Config {
	return laneguard.Config{
		SchemaVersion:    laneguard.ContractSchemaVersion,
		StationID:        plan.StationID,
		LaneID:           plan.LaneID,
		RPIBootSysfsPath: "/sys/bus/usb/devices/authority-bridge-validation",
		UARTPath:         "/dev/serial/by-id/authority-bridge-validation",
		PowerGPIO:        laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0"},
	}
}
