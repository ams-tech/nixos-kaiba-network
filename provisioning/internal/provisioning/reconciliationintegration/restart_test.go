package reconciliationintegration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authoritybridge"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const (
	stationID       = "station-restart"
	laneID          = "lane-restart"
	transactionID   = "transaction-restart"
	operationID     = "operation-restart-1"
	approvalID      = "approval-restart"
	approverID      = "approver-restart"
	freshEEPROMHex  = "8888888888888888888888888888888888888888888888888888888888888888"
	ownedEEPROMHex  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	ownedKeyHex     = "1111111111111111111111111111111111111111111111111111111111111111"
	zeroCustomerHex = "0000000000000000000000000000000000000000000000000000000000000000"
)

func TestAuthenticatedRestartReconcilesRealAdapterWithoutRedispatch(t *testing.T) {
	for _, test := range []struct {
		name            string
		mutationApplied bool
	}{
		{name: "confirmed applied", mutationApplied: true},
		{name: "confirmed not applied", mutationApplied: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			testAuthenticatedRestartReconciliation(t, test.mutationApplied)
		})
	}
}

func testAuthenticatedRestartReconciliation(t *testing.T, mutationApplied bool) {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	controlPath := filepath.Join(directory, "control.json")
	auditPath := filepath.Join(directory, "audit.json")
	journalPath := filepath.Join(directory, "lane-journal.json")
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	board := newSimulatedBoard(mutationApplied)

	release := releasebinding.Binding{
		SignedReleaseManifestDigest: digest("signed-release"),
		LaneGuardPackageDigest:      digest("lane-guard-package"),
		CompiledArtifactSetDigest:   digest("compiled-artifact-set"),
		ExpectedCustomerKeyHash:     "sha256:" + ownedKeyHex,
		ExpectedEEPROMDigest:        "sha256:" + ownedEEPROMHex,
		ExpectedBootImageDigest:     digest("boot-image"),
	}
	freshObservation, err := rpi5.ParseMetadata([]byte(board.metadata(false)))
	if err != nil {
		t.Fatal(err)
	}
	initialState := laneguard.DirectState{
		CustomerKeyHash: controlplane.UnownedCustomerKeyHash,
		EEPROMHash:      "sha256:" + freshEEPROMHex,
		SecurityState:   "fresh",
		PowerState:      "powered_off",
	}
	operationNames := developmentOperationNames()
	controlStore := controlplane.FileStore{Path: controlPath}
	auditStore := auditlog.FileStore{Path: auditPath}
	control := openControl(t, controlStore, clock, "before-restart")
	audit := openAudit(t, auditStore, clock)

	transaction := createClaimAndBind(t, ctx, control, release, freshObservation.TargetFingerprint, operationNames)
	draft, err := plancompiler.BuildDraft(plancompiler.DraftInput{
		StationID: stationID, LaneID: laneID, TransactionID: transaction.ID,
		Release: release, TargetFingerprint: freshObservation.TargetFingerprint,
		FenceEpoch: transaction.FenceEpoch, ApprovalExpiresAt: now.Add(30 * time.Minute),
		InitialState: initialState,
		AuthorizationIDs: [7]string{
			"authorization-1", "authorization-2", "authorization-3", "authorization-4",
			"authorization-5", "authorization-6", "authorization-7",
		},
		MaximumDurations: [7]time.Duration{
			time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction = approveAndRecordIntent(t, ctx, control, audit, transaction, draft, release, operationNames, now)

	pki := newTestPKI(t, stationID, laneID)
	var controlReads atomic.Int32
	var auditReads atomic.Int32
	controlServer := startAuthorityServer(t, countingReads(controlplane.Handler(control, mtls.MutualTLSIdentityPolicy()), &controlReads))
	auditServer := startAuthorityServer(t, countingReads(auditlog.Handler(audit, mtls.MutualTLSIdentityPolicy()), &auditReads))
	controlServer.start(pki.controlServerFiles)
	auditServer.start(pki.auditServerFiles)
	bridge := startAuthenticatedBridge(t, clock, pki, controlServer.URL(), auditServer.URL())

	execution, err := authoritybridge.Request(ctx, bridge.socketPath, authoritybridge.BridgeRequest{
		SchemaVersion: authoritybridge.RequestSchemaVersion,
		Mode:          authoritybridge.ModeExecute,
		TransactionID: transaction.ID,
		DraftSnapshot: draft.Snapshot(),
	})
	if err != nil {
		t.Fatalf("bind initial execution through authenticated bridge: %v", err)
	}
	if execution.ExecuteRequest == nil || execution.ReconcileRequest != nil {
		t.Fatalf("execute bridge union = %#v", execution)
	}
	originalRequest := *execution.ExecuteRequest
	originalPlan := execution.Plan

	initialAdapter := newPhysicalAdapter(t, board, physicalrpi5.ModeFresh, release)
	initialHardware := &countingHardware{delegate: initialAdapter}
	journal, err := laneguard.NewFileStore(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := laneguard.NewWithClock(laneConfig(), initialHardware, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LoadPlan(ctx, originalPlan); err != nil {
		t.Fatalf("load initial plan: %v", err)
	}
	attempt, err := guard.Execute(ctx, originalRequest)
	if !errors.Is(err, laneguard.ErrReconciliationRequired) || attempt.Status != laneguard.AttemptUncertain {
		t.Fatalf("uncertain ownership commit = %#v, %v", attempt, err)
	}
	if initialHardware.executions() != 1 || board.commitCount() != 1 || board.isOwned() != mutationApplied {
		t.Fatalf("initial dispatch counts/state = hardware:%d commit:%d owned:%t, want owned:%t",
			initialHardware.executions(), board.commitCount(), board.isOwned(), mutationApplied)
	}

	// Discard every in-memory authority and lane object. The journal and the
	// two service stores are the only inputs retained across this boundary.
	bridge.stop()
	controlServer.stop()
	auditServer.stop()
	clock.set(now.Add(31 * time.Minute))
	control = openControl(t, controlStore, clock, "after-restart")
	audit = openAudit(t, auditStore, clock)
	transaction, err = control.GetTransaction(ctx, transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
		SchemaVersion:  controlplane.AcquireClaimRequestSchemaVersion,
		IdempotencyKey: "claim-after-restart", TransactionID: transaction.ID,
		ExpectedResourceVersion: transaction.ResourceVersion,
		StationID:               stationID, LaneID: laneID, Mode: controlplane.ClaimModeReconciliation,
		AllowedStages: []string{"reconciliation"}, LeaseDurationSeconds: 600,
	})
	if err != nil {
		t.Fatalf("acquire post-restart reconciliation claim: %v", err)
	}
	if transaction.Status != controlplane.StatusReconciliationRequired || transaction.FenceEpoch != originalPlan.FenceEpoch+1 {
		t.Fatalf("post-restart transaction = %#v", transaction)
	}

	controlServer = startAuthorityServer(t, countingReads(controlplane.Handler(control, mtls.MutualTLSIdentityPolicy()), &controlReads))
	auditServer = startAuthorityServer(t, countingReads(auditlog.Handler(audit, mtls.MutualTLSIdentityPolicy()), &auditReads))
	controlServer.start(pki.controlServerFiles)
	auditServer.start(pki.auditServerFiles)
	bridge = startAuthenticatedBridge(t, clock, pki, controlServer.URL(), auditServer.URL())
	defer bridge.stop()
	defer controlServer.stop()
	defer auditServer.stop()

	reconciliation, err := authoritybridge.Request(ctx, bridge.socketPath, authoritybridge.BridgeRequest{
		SchemaVersion: authoritybridge.RequestSchemaVersion,
		Mode:          authoritybridge.ModeReconcile,
		TransactionID: transaction.ID,
		DraftSnapshot: draft.Snapshot(),
	})
	if err != nil {
		t.Fatalf("bind reconciliation through authenticated bridge: %v", err)
	}
	if reconciliation.ExecuteRequest != nil || reconciliation.ReconcileRequest == nil {
		t.Fatalf("reconcile bridge union = %#v", reconciliation)
	}
	if reconciliation.Plan.PlanDigest != originalPlan.PlanDigest ||
		reconciliation.ReconcileRequest.OriginalRequest != originalRequest ||
		reconciliation.ReconcileRequest.Claim.FenceEpoch != transaction.FenceEpoch ||
		reconciliation.ReconcileRequest.Claim.ClaimID != transaction.ActiveClaim.ID {
		t.Fatalf("reconciliation binding = %#v / %#v", reconciliation.Plan, reconciliation.ReconcileRequest)
	}

	restartedAdapter := newPhysicalAdapter(t, board, physicalrpi5.ModeAuto, release)
	restartedHardware := &countingHardware{delegate: restartedAdapter}
	restartedJournal, err := laneguard.NewFileStore(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	restartedGuard, err := laneguard.NewWithClock(laneConfig(), restartedHardware, restartedJournal, clock)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := restartedGuard.ReconcilePlan(ctx, reconciliation.Plan, *reconciliation.ReconcileRequest)
	wantAttemptStatus := laneguard.AttemptVerified
	wantResolution := controlplane.ResolutionConfirmedApplied
	wantOperationStatus := controlplane.OperationConfirmedApplied
	if !mutationApplied {
		wantAttemptStatus = laneguard.AttemptConfirmedNotApplied
		wantResolution = controlplane.ResolutionConfirmedNotApplied
		wantOperationStatus = controlplane.OperationConfirmedNotApplied
	}
	if err != nil || reconciled.Status != wantAttemptStatus {
		t.Fatalf("observation-only reconciliation = %#v, %v", reconciled, err)
	}
	if initialHardware.executions() != 1 || restartedHardware.executions() != 0 || board.commitCount() != 1 {
		t.Fatalf("redispatch detected = initial:%d restarted:%d commit:%d",
			initialHardware.executions(), restartedHardware.executions(), board.commitCount())
	}
	persisted, found, err := restartedJournal.Get(reconciled.Key)
	if err != nil || !found || persisted.Status != wantAttemptStatus ||
		persisted.FenceEpoch != originalRequest.FenceEpoch || persisted.ApprovalID != originalRequest.ApprovalID ||
		persisted.IntentReceipt != originalRequest.IntentReceipt {
		t.Fatalf("persisted reconciled attempt = %#v, %t, %v", persisted, found, err)
	}

	observationDigest := digestJSON(t, reconciled.ObservedState)
	resultDigest := digestJSON(t, reconciled)
	reconciliationReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: "audit-reconciliation-result",
		Event: auditlog.Event{
			SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
			EventID: operationID + "-reconciliation", TransactionID: transaction.ID,
			StationID: stationID, LaneID: laneID, Stage: "reconciliation", FenceEpoch: transaction.FenceEpoch,
			InputDigest: originalPlan.PlanDigest, OutputDigest: resultDigest, Result: auditlog.ResultReconciled,
			Actors:                []auditlog.Actor{{ID: stationID, Role: "provisioning_station"}},
			TimeEvidence:          auditlog.TimeEvidence{StationTime: clock.Now(), ClockStatus: "synchronized"},
			ObservationReferences: []auditlog.ObservationReference{{Kind: "direct_state", Digest: observationDigest}},
		},
	})
	if err != nil {
		t.Fatalf("append reconciliation result: %v", err)
	}
	transaction, err = control.RecordReconciliation(ctx, controlplane.RecordReconciliationRequest{
		SchemaVersion:  controlplane.RecordReconciliationRequestSchemaVersion,
		IdempotencyKey: "control-reconciliation-result", MutationContext: mutationContext(transaction),
		OperationID: operationID, Resolution: wantResolution,
		OutputDigest: resultDigest, ObservationDigest: observationDigest,
		AuditReceiptID: reconciliationReceipt.ReceiptID,
	})
	if err != nil {
		t.Fatalf("record reconciliation result: %v", err)
	}
	if transaction.Status != controlplane.StatusReconciled || transaction.Operations[0].Status != wantOperationStatus {
		t.Fatalf("reconciled control transaction = %#v", transaction)
	}
	if !mutationApplied {
		_, retryErr := control.TransferClaim(ctx, controlplane.TransferClaimRequest{
			SchemaVersion: controlplane.TransferClaimRequestSchemaVersion, IdempotencyKey: "forbidden-retry-transfer",
			TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
			ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
			NewStationID: stationID, NewLaneID: laneID, Mode: controlplane.ClaimModeMutation,
			AllowedStages: operationNames, LeaseDurationSeconds: 600,
		})
		if !errors.Is(retryErr, controlplane.ErrIllegalTransition) {
			t.Fatalf("confirmed-not-applied result authorized redispatch claim: %v", retryErr)
		}
	}

	reopenedControl := openControl(t, controlStore, clock, "final-readback")
	reopenedAudit := openAudit(t, auditStore, clock)
	durable, err := reopenedControl.GetTransaction(ctx, transaction.ID)
	if err != nil || durable.Status != controlplane.StatusReconciled ||
		durable.Operations[0].ReconciliationAuditReceiptID != reconciliationReceipt.ReceiptID {
		t.Fatalf("durable reconciliation = %#v, %v", durable, err)
	}
	if len(reopenedAudit.Records(transaction.ID)) != 3 {
		t.Fatalf("durable audit record count = %d", len(reopenedAudit.Records(transaction.ID)))
	}
	if controlReads.Load() != 4 || auditReads.Load() != 2 {
		t.Fatalf("authenticated authority reads = control:%d audit:%d", controlReads.Load(), auditReads.Load())
	}
	for _, path := range []string{controlPath, auditPath, journalPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("durable file %s mode = %v, %v", path, info, err)
		}
	}
}

func developmentOperationNames() []string {
	operations := campaign.DevelopmentOperations()
	names := make([]string, len(operations))
	for index, operation := range operations {
		names[index] = string(operation)
	}
	return names
}

func openControl(t *testing.T, store controlplane.Store, clock *testClock, phase string) *controlplane.Service {
	t.Helper()
	service, err := controlplane.NewService(store,
		controlplane.WithClock(clock.Now),
		controlplane.WithIDGenerator(func(prefix string) (string, error) {
			return prefix + "-" + phase, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func openAudit(t *testing.T, store auditlog.Store, clock *testClock) *auditlog.Service {
	t.Helper()
	service, err := auditlog.NewService(store, auditlog.WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func createClaimAndBind(
	t *testing.T,
	ctx context.Context,
	control *controlplane.Service,
	release releasebinding.Binding,
	targetFingerprint string,
	operationNames []string,
) controlplane.Transaction {
	t.Helper()
	transaction, err := control.CreateTransaction(ctx, controlplane.CreateTransactionRequest{
		SchemaVersion:  controlplane.CreateTransactionRequestSchemaVersion,
		IdempotencyKey: "create-restart", TransactionID: transactionID,
		AssetID: "asset-restart", IntendedLogicalID: "device-restart", ProfileID: "rpi5-restart-integration",
		BundleDigest: release.SignedReleaseManifestDigest, PolicyDigest: digest("development-policy"),
		ExpectedPrestateCustomerKeyHash: controlplane.UnownedCustomerKeyHash,
		ExpectedCustomerKeyHash:         release.ExpectedCustomerKeyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.AcquireClaim(ctx, controlplane.AcquireClaimRequest{
		SchemaVersion:  controlplane.AcquireClaimRequestSchemaVersion,
		IdempotencyKey: "claim-before-restart", TransactionID: transaction.ID,
		ExpectedResourceVersion: transaction.ResourceVersion,
		StationID:               stationID, LaneID: laneID, Mode: controlplane.ClaimModeMutation,
		AllowedStages: operationNames, LeaseDurationSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.BindTarget(ctx, controlplane.BindTargetRequest{
		SchemaVersion:  controlplane.BindTargetRequestSchemaVersion,
		IdempotencyKey: "bind-target-restart", MutationContext: mutationContext(transaction),
		TargetFingerprint: targetFingerprint, ObservationDigest: digest("fresh-target-observation"),
		CustomerKeyHash: controlplane.UnownedCustomerKeyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}

func approveAndRecordIntent(
	t *testing.T,
	ctx context.Context,
	control *controlplane.Service,
	audit *auditlog.Service,
	transaction controlplane.Transaction,
	draft plancompiler.Draft,
	release releasebinding.Binding,
	operationNames []string,
	now time.Time,
) controlplane.Transaction {
	t.Helper()
	approvalReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: "audit-approval-restart",
		Event: authorityEvent(transaction, draft.PlanDigest(), approvalID, "plan_approval", transaction.FenceEpoch,
			auditlog.ResultIntentRecorded, auditlog.Actor{ID: approverID, Role: "approver"}, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.RecordApproval(ctx, controlplane.RecordApprovalRequest{
		SchemaVersion:  controlplane.RecordApprovalRequestSchemaVersion,
		IdempotencyKey: "control-approval-restart", MutationContext: mutationContext(transaction),
		ApprovalID: approvalID, ApproverID: approverID, TransactionDigest: transaction.TransactionDigest,
		PlanDigest: draft.PlanDigest(), TargetFingerprint: transaction.Target.Fingerprint,
		Release: release, AllowedOperations: operationNames, AuditReceiptID: approvalReceipt.ReceiptID,
		ExpiresAt: draft.Snapshot().ApprovalExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	intentReceipt, err := audit.Append(ctx, auditlog.AppendRequest{
		SchemaVersion:  auditlog.AppendRequestSchemaVersion,
		IdempotencyKey: "audit-intent-restart",
		Event: authorityEvent(transaction, draft.PlanDigest(), operationID, operationNames[0], transaction.FenceEpoch,
			auditlog.ResultIntentRecorded, auditlog.Actor{ID: stationID, Role: "provisioning_station"}, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = control.RecordIntent(ctx, controlplane.RecordIntentRequest{
		SchemaVersion:  controlplane.RecordIntentRequestSchemaVersion,
		IdempotencyKey: "control-intent-restart", MutationContext: mutationContext(transaction),
		ApprovalID: approvalID, OperationID: operationID, Operation: operationNames[0],
		PlanDigest: draft.PlanDigest(), InputDigest: draft.PlanDigest(),
		PrestateDigest: draft.InitialPrestateDigest(), AuditReceiptID: intentReceipt.ReceiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}

func authorityEvent(
	transaction controlplane.Transaction,
	inputDigest string,
	eventID string,
	stage string,
	fence uint64,
	result string,
	actor auditlog.Actor,
	now time.Time,
) auditlog.Event {
	return auditlog.Event{
		SchemaVersion: auditlog.EventSchemaVersion, PolicyVersion: auditlog.DefaultPolicyVersion,
		EventID: eventID, TransactionID: transaction.ID,
		StationID: stationID, LaneID: laneID, Stage: stage, FenceEpoch: fence,
		InputDigest: inputDigest, Result: result, Actors: []auditlog.Actor{actor},
		TimeEvidence: auditlog.TimeEvidence{StationTime: now, ClockStatus: "synchronized"},
	}
}

func mutationContext(transaction controlplane.Transaction) controlplane.MutationContext {
	return controlplane.MutationContext{
		TransactionID: transaction.ID, ExpectedResourceVersion: transaction.ResourceVersion,
		ClaimID: transaction.ActiveClaim.ID, FenceEpoch: transaction.FenceEpoch,
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

type simulatedBoard struct {
	mu          sync.Mutex
	powered     bool
	owned       bool
	applyCommit bool
	commitCalls int
}

func newSimulatedBoard(applyCommit bool) *simulatedBoard {
	return &simulatedBoard{applyCommit: applyCommit}
}

func (board *simulatedBoard) setPowered(powered bool) {
	board.mu.Lock()
	defer board.mu.Unlock()
	board.powered = powered
}

func (board *simulatedBoard) isPowered() bool {
	board.mu.Lock()
	defer board.mu.Unlock()
	return board.powered
}

func (board *simulatedBoard) isOwned() bool {
	board.mu.Lock()
	defer board.mu.Unlock()
	return board.owned
}

func (board *simulatedBoard) commitCount() int {
	board.mu.Lock()
	defer board.mu.Unlock()
	return board.commitCalls
}

func (board *simulatedBoard) commitWithoutResponse() error {
	board.mu.Lock()
	defer board.mu.Unlock()
	if board.applyCommit {
		board.owned = true
	}
	board.commitCalls++
	return errors.New("simulated RPIBOOT response loss with unknown ownership result")
}

func (board *simulatedBoard) metadata(forceFresh bool) string {
	board.mu.Lock()
	owned := board.owned && !forceFresh
	board.mu.Unlock()
	key := zeroCustomerHex
	eeprom := freshEEPROMHex
	if owned {
		key = ownedKeyHex
		eeprom = ownedEEPROMHex
	}
	return fmt.Sprintf(
		`{"USER_SERIAL_NUM":"A7EB274C","MAC_ADDR":"2C:CF:67:70:76:F3","EEPROM_HASH":%q,"CUSTOMER_KEY_HASH":%q,"BOOT_ROM":"0000000A","BOARD_ATTR":"00000000","USER_BOARDREV":"B04170","JTAG_LOCKED":"0","SIGNATURE_MODE":"0","MAC_WIFI_ADDR":"2C:CF:67:70:76:F4","MAC_BT_ADDR":"2C:CF:67:70:76:F5","FACTORY_UUID":"001000911006186073"}`,
		eeprom, key,
	)
}

type simulatedRunner struct {
	board *simulatedBoard
	paths physicalrpi5.ImmutablePaths
}

func (runner simulatedRunner) Run(_ context.Context, _ string, arguments []string, stdout, _ io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("simulated rpiboot received no bundle")
	}
	bundle := arguments[len(arguments)-1]
	switch bundle {
	case runner.paths.FreshCommitBundle:
		return runner.board.commitWithoutResponse()
	case runner.paths.FreshReadbackBundle, runner.paths.OwnedReadbackBundle:
		_, _ = io.WriteString(stdout, runner.board.metadata(false))
		return nil
	default:
		return fmt.Errorf("unexpected simulated RPIBOOT bundle %q", bundle)
	}
}

type simulatedFileSystem struct{ board *simulatedBoard }

func (filesystem simulatedFileSystem) ReadDir(string) ([]fs.DirEntry, error) {
	if !filesystem.board.isPowered() {
		return []fs.DirEntry{}, nil
	}
	return []fs.DirEntry{simulatedDirEntry("1-1")}, nil
}

func (filesystem simulatedFileSystem) ReadFile(path string) ([]byte, error) {
	if !filesystem.board.isPowered() || filepath.Base(filepath.Dir(path)) != "1-1" {
		return nil, fs.ErrNotExist
	}
	switch filepath.Base(path) {
	case "idVendor":
		return []byte("0a5c"), nil
	case "idProduct":
		return []byte("2712"), nil
	default:
		return nil, fs.ErrNotExist
	}
}

type simulatedDirEntry string

func (entry simulatedDirEntry) Name() string         { return string(entry) }
func (simulatedDirEntry) IsDir() bool                { return true }
func (simulatedDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (simulatedDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

type simulatedGPIO struct{ board *simulatedBoard }

func (gpio simulatedGPIO) AcquirePower(context.Context, laneguard.GPIODescriptor) (physicalrpi5.PowerLease, error) {
	gpio.board.setPowered(true)
	return &simulatedPowerLease{board: gpio.board}, nil
}

type simulatedPowerLease struct {
	board    *simulatedBoard
	released bool
}

func (lease *simulatedPowerLease) Release() error {
	if !lease.released {
		lease.released = true
		lease.board.setPowered(false)
	}
	return nil
}

type unexpectedUART struct{}

func (unexpectedUART) Capture(context.Context, string, []byte, int, func() error) ([]byte, error) {
	return nil, errors.New("unexpected UART use in ownership-commit restart test")
}

type immediateSleeper struct{}

func (immediateSleeper) Sleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

type countingHardware struct {
	mu       sync.Mutex
	delegate laneguard.Hardware
	executes int
}

func (hardware *countingHardware) Observe(ctx context.Context, config laneguard.Config) (laneguard.Observation, error) {
	return hardware.delegate.Observe(ctx, config)
}

func (hardware *countingHardware) Execute(ctx context.Context, config laneguard.Config, operation laneguard.Operation) (laneguard.OperationResult, error) {
	hardware.mu.Lock()
	hardware.executes++
	hardware.mu.Unlock()
	return hardware.delegate.Execute(ctx, config, operation)
}

func (hardware *countingHardware) executions() int {
	hardware.mu.Lock()
	defer hardware.mu.Unlock()
	return hardware.executes
}

func newPhysicalAdapter(t *testing.T, board *simulatedBoard, mode string, release releasebinding.Binding) *physicalrpi5.Adapter {
	t.Helper()
	paths := physicalrpi5.ImmutablePaths{
		RPIBootBinary: "/immutable/rpiboot", GPIOSetBinary: "/immutable/gpioset",
		FreshReadbackBundle: "/immutable/fresh-readback", FreshCommitBundle: "/immutable/fresh-commit",
		OwnedReadbackBundle: "/immutable/owned-readback", OwnedRecoveryBundle: "/immutable/owned-recovery",
		NegativeBootBundle: "/immutable/negative-boot", RootIntegrityBundle: "/immutable/root-integrity",
	}
	adapter, err := physicalrpi5.New(physicalrpi5.Config{
		Paths: paths, InitialMode: mode,
		ExpectedCustomerKeyHash: release.ExpectedCustomerKeyHash,
		ExpectedEEPROMHash:      release.ExpectedEEPROMDigest,
		ExpectedBootImageDigest: release.ExpectedBootImageDigest,
		CommandTimeout:          time.Second, UARTTimeout: time.Second,
		USBDisappearTimeout: time.Second, USBReappearTimeout: time.Second,
		USBPollInterval: time.Millisecond, MinimumColdInterval: time.Millisecond,
		MaximumOutputBytes: 4096,
	}, physicalrpi5.Dependencies{
		Runner: simulatedRunner{board: board, paths: paths}, FS: simulatedFileSystem{board: board},
		GPIO: simulatedGPIO{board: board}, UART: unexpectedUART{}, Sleeper: immediateSleeper{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func laneConfig() laneguard.Config {
	return laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     stationID, LaneID: laneID,
		RPIBootSysfsPath:  "/sys/bus/usb/devices/1-1",
		UARTPath:          "/dev/serial/by-id/kaiba-restart-uart",
		PowerGPIO:         laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17},
		LeaseSafetyMargin: 30 * time.Second,
	}
}

type testCA struct {
	certificate *x509.Certificate
	der         []byte
	key         *ecdsa.PrivateKey
}

type issuedCertificate struct {
	der []byte
	key *ecdsa.PrivateKey
}

type testPKI struct {
	stationCertificate string
	stationPrivateKey  string
	controlServerCA    string
	auditServerCA      string
	controlServerFiles mtls.Files
	auditServerFiles   mtls.Files
}

func newTestPKI(t *testing.T, station, lane string) testPKI {
	t.Helper()
	directory := t.TempDir()
	validityClock := time.Now().UTC()
	clientCA := newTestCA(t, "restart-client-ca", validityClock, 1)
	controlCA := newTestCA(t, "restart-control-ca", validityClock, 2)
	auditCA := newTestCA(t, "restart-audit-ca", validityClock, 3)
	identity, err := url.Parse("spiffe://kaiba.network/station/" + station + "/lane/" + lane)
	if err != nil {
		t.Fatal(err)
	}
	stationCertificate := clientCA.issue(t, "restart-station", validityClock, 4, false, identity)
	controlCertificate := controlCA.issue(t, "restart-control", validityClock, 5, true, nil)
	auditCertificate := auditCA.issue(t, "restart-audit", validityClock, 6, true, nil)
	clientCAPath := writePEM(t, directory, "client-ca.pem", "CERTIFICATE", clientCA.der)
	controlCAPath := writePEM(t, directory, "control-ca.pem", "CERTIFICATE", controlCA.der)
	auditCAPath := writePEM(t, directory, "audit-ca.pem", "CERTIFICATE", auditCA.der)
	return testPKI{
		stationCertificate: writePEM(t, directory, "station.pem", "CERTIFICATE", stationCertificate.der),
		stationPrivateKey:  writePrivateKey(t, directory, "station-key.pem", stationCertificate.key),
		controlServerCA:    controlCAPath,
		auditServerCA:      auditCAPath,
		controlServerFiles: mtls.Files{
			Certificate: writePEM(t, directory, "control.pem", "CERTIFICATE", controlCertificate.der),
			PrivateKey:  writePrivateKey(t, directory, "control-key.pem", controlCertificate.key),
			ClientCA:    clientCAPath,
		},
		auditServerFiles: mtls.Files{
			Certificate: writePEM(t, directory, "audit.pem", "CERTIFICATE", auditCertificate.der),
			PrivateKey:  writePrivateKey(t, directory, "audit-key.pem", auditCertificate.key),
			ClientCA:    clientCAPath,
		},
	}
}

func newTestCA(t *testing.T, name string, now time.Time, serial int64) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certificate: certificate, der: der, key: key}
}

func (ca testCA) issue(t *testing.T, name string, now time.Time, serial int64, server bool, identity *url.URL) issuedCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{der: der, key: key}
}

func writePEM(t *testing.T, directory, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePrivateKey(t *testing.T, directory, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, directory, name, "PRIVATE KEY", der)
}

type authorityServer struct {
	t       *testing.T
	handler http.Handler
	server  *httptest.Server
	once    sync.Once
}

func startAuthorityServer(t *testing.T, handler http.Handler) *authorityServer {
	t.Helper()
	server := &authorityServer{t: t, handler: handler}
	t.Cleanup(server.stop)
	return server
}

func (server *authorityServer) start(files mtls.Files) {
	server.t.Helper()
	tlsConfig, err := mtls.LoadServerConfig(files)
	if err != nil {
		server.t.Fatal(err)
	}
	server.server = httptest.NewUnstartedServer(server.handler)
	server.server.TLS = tlsConfig
	server.server.StartTLS()
}

func (server *authorityServer) URL() string { return server.server.URL }

func (server *authorityServer) stop() {
	server.once.Do(func() {
		if server.server != nil {
			server.server.Close()
		}
	})
}

func countingReads(next http.Handler, counter *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet &&
			(strings.HasPrefix(request.URL.Path, "/api/v1/transactions/") || request.URL.Path == "/api/v1/events") {
			counter.Add(1)
		}
		next.ServeHTTP(writer, request)
	})
}

type authenticatedBridge struct {
	socketPath string
	cancel     context.CancelFunc
	result     <-chan error
	once       sync.Once
	t          *testing.T
	directory  string
}

func startAuthenticatedBridge(t *testing.T, clock *testClock, pki testPKI, controlURL, auditURL string) *authenticatedBridge {
	t.Helper()
	controlReader, auditReader, err := authorityhttp.NewIndependentReaders(
		controlURL,
		mtls.ClientFiles{Certificate: pki.stationCertificate, PrivateKey: pki.stationPrivateKey, ServerCA: pki.controlServerCA},
		auditURL,
		mtls.ClientFiles{Certificate: pki.stationCertificate, PrivateKey: pki.stationPrivateKey, ServerCA: pki.auditServerCA},
	)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "kaiba-reconcile-bridge-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "bridge.sock")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	binder := &authoritybridge.Binder{
		Control: controlReader, Audit: auditReader,
		Now: clock.Now, LeaseSafetyMargin: 30 * time.Second,
	}
	go func() {
		result <- authoritybridge.Serve(ctx, authoritybridge.ServerConfig{
			SocketPath: socketPath, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
			DirectoryMode: 0o700, SocketMode: 0o600, Binder: binder, ErrorLog: io.Discard,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case err := <-result:
			cancel()
			_ = os.RemoveAll(directory)
			t.Fatalf("authority bridge stopped before creating its socket: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			_ = os.RemoveAll(directory)
			t.Fatal("authority bridge socket did not appear")
		}
		time.Sleep(time.Millisecond)
	}
	bridge := &authenticatedBridge{
		socketPath: socketPath, cancel: cancel, result: result, t: t, directory: directory,
	}
	t.Cleanup(bridge.stop)
	return bridge
}

func (bridge *authenticatedBridge) stop() {
	bridge.once.Do(func() {
		bridge.cancel()
		select {
		case err := <-bridge.result:
			if err != nil {
				bridge.t.Errorf("stop authority bridge: %v", err)
			}
		case <-time.After(2 * time.Second):
			bridge.t.Error("authority bridge did not stop")
		}
		if err := os.RemoveAll(bridge.directory); err != nil {
			bridge.t.Errorf("remove authority bridge directory: %v", err)
		}
	})
}

func digest(label string) string {
	sum := sha256.Sum256([]byte("kaiba-reconciliation-integration\x00" + label))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
