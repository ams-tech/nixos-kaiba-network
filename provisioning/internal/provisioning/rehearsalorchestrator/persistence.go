package rehearsalorchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
)

// RevalidatePersistence reopens both authoritative services, reconstructs the
// receipt from the durable record, and verifies the rehearsal-only authority
// again. It never constructs a lane plan/request or executes the simulator.
func RevalidatePersistence(ctx context.Context, config Config, stores Stores, report Report) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if stores.Control == nil || stores.Audit == nil {
		return fmt.Errorf("%w: stores are required", ErrPersistenceMismatch)
	}
	clock := config.Now.UTC()
	control, err := controlplane.NewService(stores.Control,
		controlplane.WithClock(func() time.Time { return clock }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) {
			return prefix + "-restart-validation", nil
		}),
	)
	if err != nil {
		return fmt.Errorf("%w: reopen control store: %v", ErrPersistenceMismatch, err)
	}
	audit, err := auditlog.NewService(stores.Audit, auditlog.WithClock(func() time.Time { return clock }))
	if err != nil {
		return fmt.Errorf("%w: reopen audit store: %v", ErrPersistenceMismatch, err)
	}
	fixture := newFixture(config)
	transaction, err := control.GetTransaction(ctx, fixture.transactionID)
	if err != nil {
		return fmt.Errorf("%w: reload transaction: %v", ErrPersistenceMismatch, err)
	}
	approvalRecord, approvalReceipt, err := eventAuthority(audit, fixture.transactionID, fixture.approvalID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPersistenceMismatch, err)
	}
	record, receipt, err := eventAuthority(audit, fixture.transactionID, fixture.operationID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPersistenceMismatch, err)
	}
	verified, err := plancompiler.VerifySoftwareRehearsalAuthority(fixture.draft, plancompiler.Authority{
		Transaction:     transaction,
		ApprovalReceipt: approvalReceipt, ApprovalRecord: approvalRecord,
		IntentReceipt: receipt, IntentRecord: record,
		Now: clock, LeaseSafetyMargin: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("%w: reverify persisted rehearsal authority: %v", ErrPersistenceMismatch, err)
	}
	if report.Authority != authoritySummary(verified) {
		return ErrPersistenceMismatch
	}
	return nil
}

func eventAuthority(audit *auditlog.Service, transactionID, eventID string) (auditlog.Record, auditlog.Receipt, error) {
	for _, record := range audit.Records(transactionID) {
		if record.Event.EventID != eventID {
			continue
		}
		receipt := auditlog.Receipt{
			SchemaVersion: auditlog.ReceiptSchemaVersion,
			ReceiptID:     auditReceiptID(record.EventHash), Sequence: record.Sequence,
			PreviousEventHash: record.PreviousEventHash, EventHash: record.EventHash, RecordedAt: record.RecordedAt,
		}
		return record, receipt, nil
	}
	return auditlog.Record{}, auditlog.Receipt{}, errors.New("durable authority event was not found")
}

func auditReceiptID(eventHash string) string {
	digest := sha256.Sum256([]byte("kaiba-audit-receipt\x00" + eventHash))
	return "sha256:" + hex.EncodeToString(digest[:])
}
