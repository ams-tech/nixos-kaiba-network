package stationui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrStaleRevision    = errors.New("state revision does not match")
	ErrActionNotAllowed = errors.New("action is not allowed in the current phase")
)

type Machine struct {
	mu    sync.Mutex
	state State
}

func NewMockMachine(scenario ScenarioID) (*Machine, error) {
	if !validScenario(scenario) {
		return nil, fmt.Errorf("unsupported mock scenario %q", scenario)
	}
	return &Machine{state: initialState(scenario, 1)}, nil
}

func ScenarioIDs() []ScenarioID {
	return []ScenarioID{
		ScenarioHappyPath,
		ScenarioClassMismatch,
		ScenarioBaselineFailure,
		ScenarioMultipleTargets,
		ScenarioAcquisitionError,
		ScenarioTargetReplaced,
		ScenarioMutationSafetyViolation,
		ScenarioBootFailure,
		ScenarioPreparationFailure,
		ScenarioApprovalFailure,
		ScenarioTrustFailure,
		ScenarioCommitUncertain,
		ScenarioCommitReadbackMismatch,
		ScenarioSignedBootFailure,
		ScenarioOwnedReadbackMismatch,
		ScenarioRecoveryFailure,
		ScenarioNegativeBootFailure,
		ScenarioRootIntegrityFailure,
		ScenarioRollbackFailure,
		ScenarioFinalizationFailure,
		ScenarioFinalRetestFailure,
		ScenarioAuditFailure,
		ScenarioDeferredBaselineFailure,
		ScenarioPrecommitTargetReplaced,
		ScenarioPostRecoveryReadbackMismatch,
	}
}

func (m *Machine) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneState(m.state)
}

func (m *Machine) Apply(request ActionRequest) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if request.ExpectedRevision != m.state.Revision {
		return cloneState(m.state), ErrStaleRevision
	}
	if scenario, ok := scenarioFromAction(request.Action); ok {
		if !validScenario(scenario) || !actionAllowed(m.state.AllowedActions, request.Action) {
			return cloneState(m.state), ErrActionNotAllowed
		}
		m.state = initialState(scenario, m.state.Revision+1)
		return cloneState(m.state), nil
	}
	if !actionAllowed(m.state.AllowedActions, request.Action) {
		return cloneState(m.state), ErrActionNotAllowed
	}

	next := cloneState(m.state)
	switch request.Action {
	case ActionRunStationAdmission:
		runStationAdmission(&next)
	case ActionCreateTransaction:
		createTransaction(&next)
	case ActionAttachTarget:
		attachTarget(&next)
	case ActionRunFirstProbe:
		runFirstProbe(&next)
	case ActionDisconnectTarget:
		disconnectTarget(&next)
	case ActionReconnectTarget:
		reconnectTarget(&next)
	case ActionRunSecondProbe:
		runSecondProbe(&next)
	case ActionConfirmBootOK:
		confirmBoot(&next, true)
	case ActionConfirmBootFailed:
		confirmBoot(&next, false)
	case ActionCloseDeferredBaseline:
		closeDeferredBaseline(&next)
	case ActionPrepareTransaction:
		prepareTransaction(&next)
	case ActionRequestCommitApproval:
		requestCommitApproval(&next)
	case ActionEstablishInitialTrust:
		establishInitialTrust(&next)
	case ActionReidentifyCommitTarget:
		reidentifyCommitTarget(&next)
	case ActionRecordCommitIntent:
		recordCommitIntent(&next)
	case ActionExecuteCommit:
		executeCommit(&next)
	case ActionObserveCommitReadback:
		observeCommitReadback(&next)
	case ActionPowerOffOwnedTarget:
		powerOffOwnedTarget(&next)
	case ActionConfirmSignedBoot:
		confirmSignedBoot(&next)
	case ActionRunOwnedReadback:
		runOwnedReadback(&next)
	case ActionTestOwnedRecovery:
		testOwnedRecovery(&next)
	case ActionRerunOwnedReadback:
		rerunOwnedReadback(&next)
	case ActionTestNegativeBoot:
		testNegativeBoot(&next)
	case ActionTestRootIntegrity:
		testRootIntegrity(&next)
	case ActionTestRollback:
		testRollback(&next)
	case ActionRequestFinalizationApproval:
		requestFinalizationApproval(&next)
	case ActionRecordFinalizationIntent:
		recordFinalizationIntent(&next)
	case ActionApplyFinalControls:
		applyFinalControls(&next)
	case ActionColdRestartFinalizedTarget:
		coldRestartFinalizedTarget(&next)
	case ActionObserveFinalControlsReadback:
		observeFinalControlsReadback(&next)
	case ActionRunFinalRetest:
		runFinalRetest(&next)
	case ActionReconcileAudit:
		reconcileAudit(&next)
	case ActionMarkEnrollmentReady:
		markEnrollmentReady(&next)
	case ActionExportRedacted:
		exportRedacted(&next)
	case ActionReset:
		next = initialState(next.Scenario, next.Revision)
	default:
		return cloneState(m.state), ErrActionNotAllowed
	}
	refreshPresentation(&next)
	next.Revision++
	m.state = next
	return cloneState(m.state), nil
}

func initialState(scenario ScenarioID, revision uint64) State {
	state := State{
		SchemaVersion:  StateSchemaVersion,
		Revision:       revision,
		Simulation:     true,
		Scenario:       scenario,
		Scenarios:      scenarioOptions(),
		Station:        StationState{ID: "kaiba-station-01", Status: "admission_required"},
		Lane:           LaneState{ID: "lane-1", Status: "empty", USBPath: "1-2.3"},
		Phase:          PhaseStationAdmission,
		Lifecycle:      LifecycleUnregistered,
		Instruction:    "Run the synthetic station admission gate before creating a transaction.",
		AllowedActions: []Action{ActionRunStationAdmission},
		Probes:         []ProbeSummary{},
		Comparison:     []Comparison{},
		Findings:       []Finding{},
		Evidence:       []EvidenceSummary{},
		Safety: SafetyState{
			Simulation:             true,
			MutationEligible:       false,
			FullUnprovisionedState: "not_established",
			LiveTargetAccess:       false,
			LiveMutationCapable:    false,
			AuthoritativeEvidence:  false,
			SecretsPresent:         false,
			ApprovalAuthority:      false,
			SigningCapable:         false,
			EnrollmentCapable:      false,
			Disclaimer:             AssessmentDisclaimer,
		},
	}
	refreshPresentation(&state)
	return state
}

func runStationAdmission(state *State) {
	state.Phase = PhaseTransactionCreation
	state.Station.Status = "admitted"
	state.Instruction = "Create the synthetic, claim-bound secure-boot transaction."
	state.AllowedActions = []Action{ActionCreateTransaction, ActionReset}
	appendEvidence(state, "station-admission", "Station admission", WorkflowStageAdmission, EvidencePassed, "Synthetic station, lane, service, time, and operator checks passed.")
}

func createTransaction(state *State) {
	state.Transaction = &TransactionSummary{
		ID:                "txn-rpi5-000042",
		Status:            TransactionCreated,
		AssetID:           "asset-rpi5-0042",
		IntendedLogicalID: "kaiba-edge-0042",
		ClaimID:           "claim-lane-1-0042",
		FenceEpoch:        7,
		OperatorID:        "operator:demo-alex",
		Digest:            "sha256:06e35b7508cf7c9ff1a468752135c24ef6ca05a943db0a26d76439c58d25d67e",
	}
	state.Phase = PhaseReady
	state.Lane.Status = "claimed_empty"
	state.Instruction = "Connect exactly one simulated target to the claimed lane, then review it before probing."
	state.AllowedActions = []Action{ActionAttachTarget, ActionReset}
	appendEvidence(state, "transaction-created", "Transaction and claim", WorkflowStageTransaction, EvidenceRecorded, "The synthetic asset reservation, claim lease, fence epoch, operator, and transaction digest were recorded.")
}

func attachTarget(state *State) {
	if state.Scenario == ScenarioMultipleTargets {
		state.Lane.Status = "blocked"
		state.Findings = []Finding{{Code: "multiple_targets", Message: "The mock lane observed more than one eligible target and refused target selection."}}
		abortBeforeCommit(state, "Target selection stopped", "Target selection was ambiguous; no probe ran.", WorkflowStageQualification)
		return
	}
	state.Phase = PhaseTargetDetected
	state.Lane.Status = "target_detected"
	state.Target = syntheticTarget()
	state.Transaction.Status = TransactionTargetBound
	state.Transaction.TargetFingerprint = state.Target.Fingerprint
	state.Instruction = "Review the synthetic target and explicitly start metadata probe 1."
	state.AllowedActions = []Action{ActionRunFirstProbe, ActionReset}
	appendEvidence(state, "target-bound", "Target binding", WorkflowStageQualification, EvidenceRecorded, "One synthetic target fingerprint was bound to the claim and fence epoch.")
}

func runFirstProbe(state *State) {
	switch state.Scenario {
	case ScenarioAcquisitionError:
		state.Probes = append(state.Probes, failedProbe(1, "acquisition_error", "The simulated rpiboot acquisition did not complete."))
		stop(state, "Probe acquisition failed", "No parsed observation was accepted.")
	case ScenarioMutationSafetyViolation:
		state.Probes = append(state.Probes, failedProbe(1, "mutation_success_reported", "The simulated evidence reported an unexpected persistent mutation result."))
		state.Transaction.IrreversibleBoundaryCrossed = true
		ownedQuarantine(state, "Probe safety violation", "An unexpected persistent-mutation indication means the board cannot be returned to the fresh path.", WorkflowStageQualification)
	case ScenarioClassMismatch:
		observation := syntheticTarget()
		observation.Model = "Raspberry Pi 500"
		observation.BoardRevision = "c041a0"
		observation.ModelCode = "0x1a"
		state.Target = observation
		state.Probes = append(state.Probes, assessedProbe(1, observation, "fail", "indeterminate", false,
			Finding{Code: "device_class_mismatch", Message: "Decoded model code does not identify a Raspberry Pi 5 Model B."}))
		stop(state, "Incompatible device class", "The target is outside the stable Pi 5 Model B profile.")
	case ScenarioBaselineFailure:
		observation := syntheticTarget()
		observation.CustomerKeyHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		observation.CustomerKeyState = "set"
		state.Target = observation
		state.Probes = append(state.Probes, assessedProbe(1, observation, "pass", "fail", false,
			Finding{Code: "customer_key_already_set", Message: "The customer-key hash is nonzero."}))
		ownedQuarantine(state, "Foreign ownership detected", "A nonzero customer-key hash is foreign ownership and cannot enter the fresh-board path.", WorkflowStageQualification)
	default:
		observation := syntheticTarget()
		state.Probes = append(state.Probes, assessedProbe(1, observation, "pass", "pass", true))
		state.Phase = PhasePowerCycleRequired
		state.Lane.Status = "power_cycle_required"
		state.Instruction = "Remove every source of power from the target. The mock requires observing disconnection before reconnecting."
		state.AllowedActions = []Action{ActionDisconnectTarget, ActionReset}
		appendEvidence(state, "fresh-probe-1", "Fresh-board metadata probe 1", WorkflowStageQualification, EvidencePassed, "The synthetic class and observable fresh-board baseline passed.")
	}
}

func disconnectTarget(state *State) {
	state.Phase = PhaseAwaitingReconnect
	state.Lane.Status = "disconnected"
	state.Instruction = "The target is fully disconnected. Reconnect it in RPIBOOT mode on the same lane."
	state.AllowedActions = []Action{ActionReconnectTarget, ActionReset}
}

func reconnectTarget(state *State) {
	state.Phase = PhaseSecondProbeReady
	state.Lane.Status = "target_detected"
	state.Instruction = "A target is present again on lane-1. Explicitly start metadata probe 2."
	state.AllowedActions = []Action{ActionRunSecondProbe, ActionReset}
	if state.Scenario == ScenarioTargetReplaced {
		replacement := replacementTarget()
		state.Target = replacement
	}
}

func runSecondProbe(state *State) {
	observation := syntheticTarget()
	if state.Scenario == ScenarioTargetReplaced {
		observation = replacementTarget()
	}
	state.Probes = append(state.Probes, assessedProbe(2, observation, "pass", "pass", true))
	state.Target = observation
	state.Comparison = compareObservations(state.Probes[0].Observation, observation)
	if hasChangedComparison(state.Comparison) {
		abortBeforeCommit(state, "Target changed after power removal", "Stable target observations did not match the transaction-bound first probe.", WorkflowStageQualification)
		return
	}
	appendEvidence(state, "fresh-probe-2", "Fresh-board metadata probe 2", WorkflowStageQualification, EvidencePassed, "Stable synthetic observations matched across complete power removal.")
	state.Phase = PhaseAwaitingNormalBootConfirmation
	state.Lane.Status = "awaiting_normal_boot_confirmation"
	state.Instruction = "Boot the target normally and record the observed result. This confirmation is operator-supplied evidence."
	if state.Scenario == ScenarioBootFailure {
		state.AllowedActions = []Action{ActionConfirmBootFailed, ActionReset}
	} else {
		state.AllowedActions = []Action{ActionConfirmBootOK, ActionConfirmBootFailed, ActionReset}
	}
}

func confirmBoot(state *State, ok bool) {
	if !ok {
		abortBeforeCommit(state, "Qualification boot failed", "The synthetic candidate did not return to the approved reusable baseline before any OTP operation.", WorkflowStageQualification)
		return
	}
	state.Phase = PhaseQualifiedFreshCandidate
	state.Lifecycle = LifecycleQualifiedFreshCandidate
	state.Lane.Status = "qualified_fresh_candidate"
	state.Instruction = "Close every deferred fresh-board baseline gate before preparing the secure-boot manifest."
	state.AllowedActions = []Action{ActionCloseDeferredBaseline, ActionReset}
	appendEvidence(state, "qualification-boot", "Qualification normal boot", WorkflowStageQualification, EvidencePassed, "Two matching synthetic probes and the pre-commit normal-boot check completed.")
}

func closeDeferredBaseline(state *State) {
	checks := []struct {
		id     string
		label  string
		detail string
	}{
		{"baseline-otp-key-rows", "Remaining OTP and key rows", "All required synthetic OTP/key rows remained in the approved fresh-board state."},
		{"baseline-eeprom-posture", "EEPROM security posture", "Synthetic EEPROM update, secure-boot, write-protection, boot-order, and digest posture matched the fresh-board profile."},
		{"baseline-storage", "Storage baseline", "No disallowed filesystem, partition, protected material, or prior enrollment artifact was present in synthetic storage."},
		{"baseline-inventory", "Inventory and prior transactions", "Synthetic inventory, lease history, and transaction lookup found no prior ownership or unresolved provisioning attempt."},
		{"baseline-firmware-authenticity", "Firmware authenticity", "The synthetic boot ROM, EEPROM release, recovery bundle, and adapter outputs matched pinned authenticity policy."},
		{"baseline-debug-paths", "Debug and alternate paths", "Synthetic JTAG, UART, recovery, and alternate boot paths matched the approved pre-commit posture."},
	}
	for _, check := range checks {
		status := EvidencePassed
		detail := check.detail
		if state.Scenario == ScenarioDeferredBaselineFailure && check.id == "baseline-otp-key-rows" {
			status = EvidenceFailed
			detail = "A synthetic OTP/key row was nonzero or could not be conclusively read as the approved fresh-board prestate."
		}
		appendEvidence(state, check.id, check.label, WorkflowStagePreparation, status, detail)
	}
	if state.Scenario == ScenarioDeferredBaselineFailure {
		abortBeforeCommit(state, "Deferred baseline failed", "The complete fresh-board baseline could not be closed before manifest preparation.", WorkflowStagePreparation)
		return
	}
	state.Transaction.Status = TransactionPreflightPassed
	state.Phase = PhaseBaselineClosed
	state.Instruction = "Resolve and verify the complete secure-boot manifest and operation plan."
	state.AllowedActions = []Action{ActionPrepareTransaction, ActionReset}
}

func prepareTransaction(state *State) {
	state.Manifest = syntheticManifest()
	state.Transaction.PlanDigest = "sha256:9c6bdf087fb66f0b48b824978bc14c425ebcdde49e186bb7b4f2cad87dd8f730"
	if state.Scenario == ScenarioPreparationFailure {
		state.Manifest.VerificationStatus = "failed"
		appendEvidence(state, "manifest-verification", "Manifest and artifact verification", WorkflowStagePreparation, EvidenceFailed, "The synthetic owned-recovery bundle signature did not match the approved key.")
		abortBeforeCommit(state, "Preparation failed", "An artifact, signature, compatibility, or policy gate failed before commit.", WorkflowStagePreparation)
		return
	}
	state.Manifest.VerificationStatus = "verified"
	state.Phase = PhasePrepared
	state.Lifecycle = LifecyclePrepared
	state.Instruction = "Request independent approval for the exact transaction, target, manifest, and operation plan."
	state.AllowedActions = []Action{ActionRequestCommitApproval, ActionReset}
	appendEvidence(state, "manifest-verification", "Manifest and artifact verification", WorkflowStagePreparation, EvidencePassed, "All synthetic artifact digests, signatures, allowlists, size, ramdisk, boot-order, recovery, rollback, debug, and storage policies passed.")
}

func requestCommitApproval(state *State) {
	if state.Scenario == ScenarioApprovalFailure {
		appendEvidence(state, "commit-approval", "Independent commit approval", WorkflowStageApproval, EvidenceFailed, "The synthetic approval service rejected the exact plan digest.")
		abortBeforeCommit(state, "Commit approval denied", "No station action can substitute for independent approval.", WorkflowStageApproval)
		return
	}
	state.Transaction.Status = TransactionCommitApproved
	state.Transaction.ApproverID = "approver:demo-riley"
	state.Transaction.ApprovalID = "approval:commit-0042"
	state.Phase = PhaseCommitApproved
	state.Instruction = "Establish the synthetic target-to-domain and domain-to-target trust gate."
	state.AllowedActions = []Action{ActionEstablishInitialTrust, ActionReset}
	appendEvidence(state, "commit-approval", "Independent commit approval", WorkflowStageApproval, EvidenceRecorded, "An external synthetic approval was bound to the transaction digest, target fingerprint, fence epoch, manifest, and plan.")
}

func establishInitialTrust(state *State) {
	if state.Scenario == ScenarioTrustFailure {
		appendEvidence(state, "initial-trust", "Bidirectional initial trust", WorkflowStageInitialTrust, EvidenceFailed, "The synthetic target could not authenticate the intended provisioning domain.")
		abortBeforeCommit(state, "Initial trust failed", "The commit remains blocked because both trust directions were not established.", WorkflowStageInitialTrust)
		return
	}
	state.Transaction.Status = TransactionTrustEstablished
	state.Phase = PhaseTrustEstablished
	state.Instruction = "Re-identify the exact target on the exclusive RPIBOOT commit lane immediately before recording commit intent."
	state.AllowedActions = []Action{ActionReidentifyCommitTarget, ActionReset}
	appendEvidence(state, "initial-trust", "Bidirectional initial trust", WorkflowStageInitialTrust, EvidencePassed, "Synthetic transaction-bound bootstrap and enrollment-domain trust checks passed.")
}

func reidentifyCommitTarget(state *State) {
	if state.Scenario == ScenarioPrecommitTargetReplaced {
		state.Target = replacementTarget()
		state.Lane.Status = "unexpected_target"
		appendEvidence(state, "precommit-target-reidentification", "Exclusive-lane commit target re-identification", WorkflowStageOwnershipCommit, EvidenceFailed, "The target on the synthetic exclusive RPIBOOT lane did not match the transaction-bound fingerprint immediately before commit.")
		abortBeforeCommit(state, "Pre-commit target changed", "The exact transaction-bound target was not present on the exclusive commit lane, so no intent was recorded and no OTP operation ran.", WorkflowStageOwnershipCommit)
		return
	}
	state.Phase = PhaseCommitTargetReidentified
	state.Lane.Status = "exclusive_rpiboot_verified"
	state.Instruction = "Record and export the one-shot ownership-commit intent for this re-identified target before executing it."
	state.AllowedActions = []Action{ActionRecordCommitIntent, ActionReset}
	appendEvidence(state, "precommit-target-reidentification", "Exclusive-lane commit target re-identification", WorkflowStageOwnershipCommit, EvidencePassed, "The exact fingerprint, zero-key prestate, lane claim, fence epoch, and exclusive RPIBOOT topology were re-observed immediately before commit intent.")
}

func recordCommitIntent(state *State) {
	state.Transaction.IntentReceipt = "audit-receipt:intent-0042-0001"
	state.Lifecycle = LifecycleCommitInProgress
	state.Phase = PhaseCommitIntentRecorded
	state.Instruction = "Execute the approved synthetic program_pubkey operation exactly once. This is the modeled point of no return."
	state.AllowedActions = []Action{ActionExecuteCommit}
	appendEvidence(state, "commit-intent", "Ownership commit intent", WorkflowStageOwnershipCommit, EvidenceRecorded, "The exact target, prestate, plan, approval, and one-shot operation received a synthetic remote audit receipt.")
}

func executeCommit(state *State) {
	state.Transaction.CommitExecutions++
	state.Transaction.IrreversibleBoundaryCrossed = true
	state.Phase = PhaseCommitInProgress
	state.Lane.Status = "ownership_commit_executed"
	if state.Scenario == ScenarioCommitUncertain {
		appendEvidence(state, "ownership-commit", "Ownership commit execution", WorkflowStageOwnershipCommit, EvidenceFailed, "The simulated command outcome is uncertain after the first OTP write may have occurred.")
		ownedQuarantine(state, "Ownership commit outcome uncertain", "The one-shot operation will not be retried; authoritative readback could not establish its postcondition.", WorkflowStageOwnershipCommit)
		return
	}
	state.Instruction = "Directly observe the customer-key hash, secure-boot result, EEPROM update, and EEPROM digest. Do not repeat the commit."
	state.AllowedActions = []Action{ActionObserveCommitReadback}
	appendEvidence(state, "ownership-commit", "Ownership commit execution", WorkflowStageOwnershipCommit, EvidenceRecorded, "The approved synthetic fresh-board bundle executed once; command return alone is not accepted as success.")
}

func observeCommitReadback(state *State) {
	if state.Scenario == ScenarioCommitReadbackMismatch {
		state.Target.CustomerKeyHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		state.Target.CustomerKeyState = "unexpected"
		appendEvidence(state, "commit-readback", "Ownership commit readback", WorkflowStageOwnershipCommit, EvidenceFailed, "The observed customer-key hash did not match the approved manifest.")
		ownedQuarantine(state, "Ownership readback mismatch", "The board crossed the OTP boundary but its effective state does not match the approved transaction.", WorkflowStageOwnershipCommit)
		return
	}
	state.Target.CustomerKeyHash = state.Manifest.ExpectedCustomerKeyHash
	state.Target.CustomerKeyState = "set — expected Kaiba hash"
	state.Target.EEPROMHash = "sha256:7baf7281ecb41b3e147e885677faf12f6898530261f3ed4158a7d6658149e618"
	state.Phase = PhaseCommitReadbackVerified
	state.Lane.Status = "owned_readback_required"
	state.Instruction = "Remove all power before cold-booting the exact approved signed boot image."
	state.AllowedActions = []Action{ActionPowerOffOwnedTarget}
	appendEvidence(state, "commit-readback", "Ownership commit readback", WorkflowStageOwnershipCommit, EvidencePassed, "Expected CUSTOMER_KEY_HASH, SECURE_BOOT_PROVISION, EEPROM_UPDATE, and EEPROM digest were observed.")
}

func powerOffOwnedTarget(state *State) {
	state.Phase = PhaseAwaitingOwnedColdBoot
	state.Lane.Status = "owned_target_power_removed"
	state.Instruction = "Cold-boot the approved signed capsule and reconcile UART plus the bootloader image digest."
	state.AllowedActions = []Action{ActionConfirmSignedBoot}
	appendEvidence(state, "owned-power-removal", "Owned-target power removal", WorkflowStageOwnedVerification, EvidenceRecorded, "Complete target power removal was synthetically observed before the first owned boot.")
}

func confirmSignedBoot(state *State) {
	if state.Scenario == ScenarioSignedBootFailure {
		appendEvidence(state, "signed-cold-boot", "Approved signed cold boot", WorkflowStageOwnedVerification, EvidenceFailed, "The approved signed boot image did not reach the pre-enrollment runtime.")
		ownedQuarantine(state, "Signed cold boot failed", "The owned board did not cold-boot the exact approved image.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseSignedBootVerified
	state.Lane.Status = "signed_boot_verified"
	state.Instruction = "Run the customer-counter-signed owned-device readback and require exact target continuity."
	state.AllowedActions = []Action{ActionRunOwnedReadback}
	appendEvidence(state, "signed-cold-boot", "Approved signed cold boot", WorkflowStageOwnedVerification, EvidencePassed, "Synthetic UART signature evidence, signed bit 3, and boot_img_sha256 matched the manifest.")
}

func runOwnedReadback(state *State) {
	if state.Scenario == ScenarioOwnedReadbackMismatch {
		appendEvidence(state, "owned-readback", "Owned-device signed readback", WorkflowStageOwnedVerification, EvidenceFailed, "The owned-device probe reported an unexpected target fingerprint or security posture.")
		ownedQuarantine(state, "Owned-device readback mismatch", "The counter-signed readback did not match the pre-commit target and manifest.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseOwnedReadbackVerified
	state.Instruction = "Prove the customer-counter-signed recovery path and reject stock or unsigned recovery."
	state.AllowedActions = []Action{ActionTestOwnedRecovery}
	appendEvidence(state, "owned-readback", "Owned-device signed readback", WorkflowStageOwnedVerification, EvidencePassed, "The expected key hash, EEPROM posture, target fingerprint, and secure-boot signed bit were read back through the owned probe.")
}

func testOwnedRecovery(state *State) {
	if state.Scenario == ScenarioRecoveryFailure {
		appendEvidence(state, "owned-recovery", "Owned and unauthorized recovery tests", WorkflowStageOwnedVerification, EvidenceFailed, "Authorized recovery failed or a recovery payload without the customer counter-signature executed.")
		ownedQuarantine(state, "Recovery policy failed", "The owned recovery boundary did not match the approved policy.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseRecoveryVerified
	state.Instruction = "Re-run the authorized owned-device readback after recovery before exercising negative boot candidates."
	state.AllowedActions = []Action{ActionRerunOwnedReadback}
	appendEvidence(state, "owned-recovery", "Owned and unauthorized recovery tests", WorkflowStageOwnedVerification, EvidencePassed, "Counter-signed owned recovery executed and stock or unsigned recovery was rejected.")
}

func rerunOwnedReadback(state *State) {
	if state.Scenario == ScenarioPostRecoveryReadbackMismatch {
		appendEvidence(state, "post-recovery-readback", "Post-recovery owned-device readback", WorkflowStageOwnedVerification, EvidenceFailed, "The authorized post-recovery readback did not match the transaction-bound target or approved security posture.")
		ownedQuarantine(state, "Post-recovery readback mismatch", "Recovery completed, but the required repeated owned-device readback could not re-establish exact target and security-state continuity.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhasePostRecoveryReadbackVerified
	state.Instruction = "Exercise altered, unsigned, and wrong-key images across every enabled boot source."
	state.AllowedActions = []Action{ActionTestNegativeBoot}
	appendEvidence(state, "post-recovery-readback", "Post-recovery owned-device readback", WorkflowStageOwnedVerification, EvidencePassed, "The customer-counter-signed probe re-established the expected key hash, EEPROM posture, target fingerprint, and signed-bit state after recovery.")
}

func testNegativeBoot(state *State) {
	if state.Scenario == ScenarioNegativeBootFailure {
		appendEvidence(state, "negative-boot", "Negative boot-source suite", WorkflowStageOwnedVerification, EvidenceFailed, "An altered, unsigned, wrong-key, or alternate-source candidate reached execution.")
		ownedQuarantine(state, "Negative boot test failed", "At least one unauthorized boot candidate executed or could not be reconciled.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseNegativeBootVerified
	state.Instruction = "Prove persistent-system tampering fails before enrollment services can start."
	state.AllowedActions = []Action{ActionTestRootIntegrity}
	appendEvidence(state, "negative-boot", "Negative boot-source suite", WorkflowStageOwnedVerification, EvidencePassed, "Altered boot image/signature, wrong-key, unsigned media, and every enabled fallback candidate were rejected.")
}

func testRootIntegrity(state *State) {
	if state.Scenario == ScenarioRootIntegrityFailure {
		appendEvidence(state, "root-integrity", "Persistent-root integrity gate", WorkflowStageOwnedVerification, EvidenceFailed, "A tampered persistent system reached the pre-enrollment runtime.")
		ownedQuarantine(state, "Persistent-root integrity failed", "Signed early boot did not prevent execution of the tampered persistent system.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseRootIntegrityVerified
	state.Instruction = "Prove the monotonic rollback policy rejects an older validly signed release."
	state.AllowedActions = []Action{ActionTestRollback}
	appendEvidence(state, "root-integrity", "Persistent-root integrity gate", WorkflowStageOwnedVerification, EvidencePassed, "Synthetic dm-verity failure blocked enrollment services and protected material.")
}

func testRollback(state *State) {
	if state.Scenario == ScenarioRollbackFailure {
		appendEvidence(state, "rollback", "Security rollback gate", WorkflowStageOwnedVerification, EvidenceFailed, "An older validly signed release reached the pre-enrollment runtime.")
		ownedQuarantine(state, "Rollback gate failed", "Native signature validity did not enforce the approved minimum security release.", WorkflowStageOwnedVerification)
		return
	}
	state.Phase = PhaseRollbackVerified
	state.Instruction = "Request separate approval for the exact final JTAG, boot-order, and EEPROM write-protection operation plan."
	state.AllowedActions = []Action{ActionRequestFinalizationApproval}
	appendEvidence(state, "rollback", "Security rollback gate", WorkflowStageOwnedVerification, EvidencePassed, "The synthetic monotonic gate rejected an older validly Kaiba-signed release.")
}

func requestFinalizationApproval(state *State) {
	state.Transaction.FinalizationApprovalID = "approval:final-controls-0042"
	state.Phase = PhaseFinalizationApproved
	state.Instruction = "Record the separately approved final-controls intent and obtain a remote audit receipt before bounded application."
	state.AllowedActions = []Action{ActionRecordFinalizationIntent}
	appendEvidence(state, "finalization-approval", "Independent finalization approval", WorkflowStageFinalization, EvidenceRecorded, "A separate synthetic approval was bound to the exact owned target, current readback, final-control plan, manifest, and transaction digest.")
}

func recordFinalizationIntent(state *State) {
	state.Transaction.FinalizationIntentReceipt = "audit-receipt:final-controls-0042-0001"
	state.Phase = PhaseFinalizationIntentRecorded
	state.Instruction = "Apply the approved final controls once within the bounded synthetic executor, then cold restart before direct readback."
	state.AllowedActions = []Action{ActionApplyFinalControls}
	appendEvidence(state, "finalization-intent", "Final-controls intent", WorkflowStageFinalization, EvidenceRecorded, "The exact JTAG, boot-order, EEPROM write-protection operation set and prestate received a synthetic remote audit receipt.")
}

func applyFinalControls(state *State) {
	state.Transaction.FinalControlExecutions++
	state.Phase = PhaseFinalControlsApplied
	state.Instruction = "Remove all target power and cold restart the finalized target before direct security-state readback."
	state.AllowedActions = []Action{ActionColdRestartFinalizedTarget}
	appendEvidence(state, "final-controls-execution", "Final security controls execution", WorkflowStageFinalization, EvidenceRecorded, "The separately approved synthetic final-controls operation set executed once within its bounded command plan; command return alone is not accepted as success.")
}

func coldRestartFinalizedTarget(state *State) {
	state.Phase = PhaseFinalColdRestartObserved
	state.Lane.Status = "finalized_cold_restart_observed"
	state.Instruction = "Directly read back the effective JTAG, boot-order, and EEPROM write-protection posture before any affected retest."
	state.AllowedActions = []Action{ActionObserveFinalControlsReadback}
	appendEvidence(state, "final-cold-restart", "Finalized-target cold restart", WorkflowStageFinalization, EvidenceRecorded, "Complete synthetic power removal and a cold restart were observed after final-control execution and before direct readback.")
}

func observeFinalControlsReadback(state *State) {
	if state.Scenario == ScenarioFinalizationFailure {
		appendEvidence(state, "final-controls-readback", "Final security controls readback", WorkflowStageFinalization, EvidenceFailed, "A final JTAG, boot-order, or EEPROM write-protection readback did not match the separately approved policy.")
		ownedQuarantine(state, "Final security posture mismatch", "The final controls executed, but direct readback could not establish the approved effective posture.", WorkflowStageFinalization)
		return
	}
	state.Target.VideoCoreJTAGState = "locked"
	state.Target.VideoCoreJTAGLocked = true
	state.Phase = PhaseFinalControlsReadbackVerified
	state.Instruction = "Repeat every boot, recovery, root-integrity, and rollback test affected by finalization."
	state.AllowedActions = []Action{ActionRunFinalRetest}
	appendEvidence(state, "final-controls-readback", "Final security controls readback", WorkflowStageFinalization, EvidencePassed, "Direct synthetic readback confirmed the approved JTAG lock, boot-order, and EEPROM write-protection posture.")
}

func runFinalRetest(state *State) {
	if state.Scenario == ScenarioFinalRetestFailure {
		appendEvidence(state, "final-retest", "Post-finalization acceptance retest", WorkflowStageFinalization, EvidenceFailed, "An affected positive or negative test failed after the final posture was applied.")
		ownedQuarantine(state, "Post-finalization retest failed", "The final controls changed an acceptance result.", WorkflowStageFinalization)
		return
	}
	state.Phase = PhaseFinalRetestVerified
	state.Instruction = "Export and reconcile the complete secret-free evidence with the independent audit and inventory authorities."
	state.AllowedActions = []Action{ActionReconcileAudit}
	appendEvidence(state, "final-retest", "Post-finalization acceptance retest", WorkflowStageFinalization, EvidencePassed, "All affected boot, recovery, persistent-root, and rollback tests passed after cold restart.")
}

func reconcileAudit(state *State) {
	if state.Scenario == ScenarioAuditFailure {
		appendEvidence(state, "audit-reconciliation", "Audit and inventory reconciliation", WorkflowStageAudit, EvidenceFailed, "The terminal audit receipt or inventory reconciliation was unavailable.")
		ownedQuarantine(state, "Audit reconciliation failed", "An owned board with missing required provenance cannot be released to enrollment.", WorkflowStageAudit)
		return
	}
	state.Phase = PhaseAuditReconciled
	state.Transaction.Status = TransactionSecurityApplied
	state.Lifecycle = LifecycleSecurityApplied
	state.Instruction = "Mark this exact owned device enrollment-ready. This simulation does not create or enroll a device identity."
	state.AllowedActions = []Action{ActionMarkEnrollmentReady}
	appendEvidence(state, "audit-reconciliation", "Audit and inventory reconciliation", WorkflowStageAudit, EvidencePassed, "The complete synthetic record received an independent audit receipt and matched inventory.")
}

func markEnrollmentReady(state *State) {
	state.Phase = PhaseEnrollmentReady
	state.Lifecycle = LifecycleEnrollmentReady
	state.Lane.Status = "enrollment_ready"
	state.Instruction = "Export the secret-free simulated secure-boot record. Device-identity enrollment is a later, separately gated workflow."
	state.Outcome = &Outcome{
		Status:  "enrollment_ready",
		Title:   "Secure-boot provisioning complete",
		Message: "The synthetic owned device passed every secure-boot, recovery, integrity, rollback, finalization, and audit gate and is ready for later identity enrollment.",
	}
	state.AllowedActions = []Action{ActionExportRedacted}
	appendEvidence(state, "enrollment-ready", "Enrollment-ready lifecycle mark", WorkflowStageAudit, EvidenceRecorded, "Inventory marked the synthetic device enrollment-ready without creating a key or credential.")
}

func stop(state *State, title, message string) {
	abortBeforeCommit(state, title, message, WorkflowStageQualification)
}

func abortBeforeCommit(state *State, title, message string, stage WorkflowStageID) {
	state.Phase = PhaseStopped
	state.Lane.Status = "stopped"
	state.Station.Status = "attention_required"
	state.Instruction = "Review and export the synthetic evidence. No OTP operation was authorized by this transaction."
	if state.Transaction != nil {
		state.Transaction.Status = TransactionAborted
	}
	state.Outcome = &Outcome{Status: "aborted", Title: title, Message: message}
	state.AllowedActions = []Action{ActionExportRedacted, ActionReset}
	appendEvidence(state, "terminal-abort", "Transaction aborted", stage, EvidenceRecorded, message)
}

func ownedQuarantine(state *State, title, message string, stage WorkflowStageID) {
	state.Phase = PhaseQuarantined
	state.Lifecycle = LifecycleOwnedQuarantined
	state.Lane.Status = "owned_quarantined"
	state.Station.Status = "attention_required"
	state.Instruction = "Keep the synthetic owned target isolated and export evidence. Never return it to the fresh-board path or blindly retry."
	if state.Transaction != nil {
		state.Transaction.Status = TransactionQuarantined
	}
	state.Outcome = &Outcome{Status: "owned_quarantined", Title: title, Message: message}
	state.AllowedActions = []Action{ActionExportRedacted}
	appendEvidence(state, "terminal-quarantine", "Owned-device quarantine", stage, EvidenceRecorded, message)
}

func appendEvidence(state *State, id, label string, stage WorkflowStageID, status EvidenceStatus, detail string) {
	state.Evidence = append(state.Evidence, EvidenceSummary{
		ID:     id,
		Label:  label,
		Stage:  stage,
		Status: status,
		Digest: syntheticDigest("evidence\x00" + id + "\x00" + string(status) + "\x00" + detail),
		Detail: detail,
	})
}

func exportRedacted(state *State) {
	transaction := TransactionSummary{}
	if state.Transaction != nil {
		transaction = *state.Transaction
	}
	manifest := ManifestSummary{}
	if state.Manifest != nil {
		manifest = *state.Manifest
	}
	outcome := Outcome{Status: "aborted", Title: "Simulation stopped", Message: "The synthetic workflow did not reach enrollment readiness."}
	if state.Outcome != nil {
		outcome = *state.Outcome
	}
	state.ExportRecord = &RedactedExport{
		SchemaVersion: ExportSchemaVersion,
		Simulation:    true,
		SecretFree:    true,
		Scenario:      state.Scenario,
		StationID:     state.Station.ID,
		LaneID:        state.Lane.ID,
		Lifecycle:     state.Lifecycle,
		Transaction:   transaction,
		Manifest:      manifest,
		Evidence:      append([]EvidenceSummary(nil), state.Evidence...),
		Outcome:       outcome,
		Safety:        state.Safety,
	}
	if state.Transaction != nil && (state.Transaction.IrreversibleBoundaryCrossed ||
		state.Lifecycle == LifecycleSecurityApplied || state.Lifecycle == LifecycleEnrollmentReady ||
		state.Lifecycle == LifecycleOwnedQuarantined) {
		state.Instruction = "The full secret-free simulation record is ready. This owned terminal state has no reset path; reload the demo for an independent synthetic run."
		state.AllowedActions = []Action{}
		return
	}
	state.Instruction = "The full secret-free simulation record is ready. Reset reuses this pre-ownership synthetic fixture only."
	state.AllowedActions = []Action{ActionReset}
}

func syntheticTarget() *TargetSummary {
	return &TargetSummary{
		Synthetic:           true,
		Model:               "Raspberry Pi 5 Model B",
		ProfileID:           "raspberry-pi-5-model-b-v1alpha1",
		ProfileStatus:       "stable",
		Adapter:             "raspberrypi.rpi5.otp-metadata/v1alpha1",
		Fingerprint:         "sha256:78600d0f50dc838dfb97414d04e8c08efe7771837a620f8503ec465b8628b6c1",
		UserSerial:          "a7eb274c",
		FactoryUUID:         "001000911006186073",
		BoardRevision:       "b04170",
		Processor:           "4 — BCM2712",
		ModelCode:           "0x17",
		BootROM:             "0000000a",
		EEPROMHash:          "",
		CustomerKeyHash:     syntheticZeroCustomerKeyHash(),
		CustomerKeyState:    "unset — zero hash",
		VideoCoreJTAGState:  "unlocked",
		VideoCoreJTAGLocked: false,
	}
}

func syntheticManifest() *ManifestSummary {
	return &ManifestSummary{
		ID:                          "kaiba-rpi5-secure-boot-v1",
		Digest:                      syntheticDigest("manifest"),
		ProfileID:                   "raspberry-pi-5-model-b-v1alpha1",
		ProfileDigest:               syntheticDigest("profile"),
		AdapterID:                   "raspberrypi.rpi5.secure-boot/v1alpha1",
		AdapterDigest:               syntheticDigest("adapter"),
		ExpectedCustomerKeyHash:     expectedCustomerKeyHash(),
		EEPROMImageDigest:           syntheticDigest("signed-eeprom-image"),
		BootImageDigest:             syntheticDigest("boot-image"),
		BootSignatureDigest:         syntheticDigest("boot-signature"),
		RootIntegrityDigest:         syntheticDigest("root-integrity"),
		FreshCommitBundleDigest:     syntheticDigest("fresh-commit-bundle"),
		OwnedRecoveryBundleDigest:   syntheticDigest("owned-recovery-bundle"),
		BootOrder:                   "0xf461",
		RollbackPolicy:              "kaiba-security-version-v1",
		DebugPolicy:                 "videocore-jtag-final-lock",
		EEPROMWriteProtectionPolicy: "hardware-write-protect-after-acceptance",
		SignerID:                    "signer:kaiba-boot-staging-01",
		SigningToolVersion:          "rpi-eeprom-digest-pinned-demo",
		VerificationStatus:          "pending",
	}
}

func syntheticZeroCustomerKeyHash() string {
	return "sha256:" + strings.Repeat("0", 64)
}

func expectedCustomerKeyHash() string {
	return syntheticDigest("kaiba-boot-public-key-v1")
}

func syntheticDigest(value string) string {
	digest := sha256.Sum256([]byte("kaiba-station-demo/v1\x00" + value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func replacementTarget() *TargetSummary {
	target := *syntheticTarget()
	target.Fingerprint = "sha256:a73b7f1649cce641901f1e12f11460d54bd0ac8feaaeb87fdf5f87c265104b04"
	target.UserSerial = "b8fc385d"
	target.FactoryUUID = "003000922007297184"
	return &target
}

func assessedProbe(sequence int, observation *TargetSummary, classStatus, baselineStatus string, eligible bool, findings ...Finding) ProbeSummary {
	copyOfObservation := *observation
	digest := "sha256:1bf5b56d68ea49c27ff142f001b1b36374da9c110c8bc3ea2e8dbe19e37f381a"
	if sequence == 2 {
		digest = "sha256:262c95177f7498f265c3d7c40a70ab7a8df4e932e666165b7415f20dcc16040d"
	}
	return ProbeSummary{
		Sequence: sequence, Status: "observed", DeviceClassStatus: classStatus,
		ObservableBaselineStatus: baselineStatus, EligibleForReversibleQualification: eligible,
		EvidenceDigest: digest, Observation: &copyOfObservation,
		Assessment: assessmentSummary(classStatus, baselineStatus, eligible),
		Findings:   append([]Finding(nil), findings...),
	}
}

func failedProbe(sequence int, code, message string) ProbeSummary {
	return ProbeSummary{
		Sequence: sequence, Status: "failed", DeviceClassStatus: "indeterminate",
		ObservableBaselineStatus: "indeterminate", EligibleForReversibleQualification: false,
		Assessment: assessmentSummary("indeterminate", "indeterminate", false),
		Findings:   []Finding{{Code: code, Message: message}},
	}
}

func assessmentSummary(classStatus, baselineStatus string, eligible bool) AssessmentSummary {
	return AssessmentSummary{
		DeviceClass:                        AssessmentStatus{Status: classStatus},
		ObservableBaseline:                 AssessmentStatus{Status: baselineStatus},
		EligibleForReversibleQualification: eligible,
		MutationEligible:                   false,
		FullUnprovisionedState:             "not_established",
		Disclaimer:                         AssessmentDisclaimer,
	}
}

func compareObservations(first, second *TargetSummary) []Comparison {
	if first == nil || second == nil {
		return []Comparison{}
	}
	fields := []struct{ key, label, first, second string }{
		{"target_fingerprint", "Target fingerprint", first.Fingerprint, second.Fingerprint},
		{"user_serial", "User serial", first.UserSerial, second.UserSerial},
		{"factory_uuid", "Factory UUID", first.FactoryUUID, second.FactoryUUID},
		{"board_revision", "Board revision", first.BoardRevision, second.BoardRevision},
		{"boot_rom", "Boot ROM", first.BootROM, second.BootROM},
		{"eeprom_hash", "EEPROM hash", first.EEPROMHash, second.EEPROMHash},
		{"customer_key_hash", "Customer key hash", first.CustomerKeyHash, second.CustomerKeyHash},
		{"customer_key_state", "Customer key state", first.CustomerKeyState, second.CustomerKeyState},
		{"videocore_jtag_state", "VideoCore JTAG", first.VideoCoreJTAGState, second.VideoCoreJTAGState},
	}
	result := make([]Comparison, 0, len(fields))
	for _, field := range fields {
		status := "match"
		if field.first == "" && field.second == "" {
			status = "not_observed"
		} else if field.first == "" || field.second == "" {
			status = "changed"
		} else if field.first != field.second {
			status = "changed"
		}
		result = append(result, Comparison{Field: field.key, Label: field.label, First: field.first, Second: field.second, Status: status})
	}
	return result
}

func hasChangedComparison(comparison []Comparison) bool {
	for _, field := range comparison {
		if field.Status == "match" || (field.Field == "eeprom_hash" && field.Status == "not_observed") {
			continue
		}
		return true
	}
	return false
}

func refreshPresentation(state *State) {
	if state.Phase == PhaseStationAdmission {
		state.Scenarios = scenarioOptions()
		state.AllowedActions = withScenarioActions(state.AllowedActions)
	} else {
		state.Scenarios = []ScenarioOption{}
	}
	state.WorkflowStages = workflowStages(state)
	state.ActionPresentations = []ActionPresentation{}
	for _, action := range state.AllowedActions {
		if _, simulationControl := scenarioFromAction(action); simulationControl {
			continue
		}
		state.ActionPresentations = append(state.ActionPresentations, actionPresentation(action))
	}
}

func workflowStages(state *State) []WorkflowStage {
	stages := []WorkflowStage{
		{ID: WorkflowStageAdmission, Label: "Station admission"},
		{ID: WorkflowStageTransaction, Label: "Create transaction"},
		{ID: WorkflowStageQualification, Label: "Qualify candidate"},
		{ID: WorkflowStagePreparation, Label: "Prepare manifest"},
		{ID: WorkflowStageApproval, Label: "Independent approval"},
		{ID: WorkflowStageInitialTrust, Label: "Initial trust"},
		{ID: WorkflowStageOwnershipCommit, Label: "Commit ownership"},
		{ID: WorkflowStageOwnedVerification, Label: "Prove owned state"},
		{ID: WorkflowStageFinalization, Label: "Finalize and retest"},
		{ID: WorkflowStageAudit, Label: "Reconcile audit"},
	}
	current := currentWorkflowStage(state)
	terminalFailure := state.Phase == PhaseStopped || state.Phase == PhaseQuarantined
	for index := range stages {
		stages[index].Status = WorkflowStagePending
		if current >= len(stages) || index < current {
			stages[index].Status = WorkflowStageComplete
		} else if index == current {
			if terminalFailure {
				stages[index].Status = WorkflowStageFailed
			} else {
				stages[index].Status = WorkflowStageCurrent
			}
		}
	}
	return stages
}

func currentWorkflowStage(state *State) int {
	if state.Phase == PhaseStopped || state.Phase == PhaseQuarantined {
		return terminalWorkflowStage(state)
	}
	switch state.Phase {
	case PhaseStationAdmission:
		return 0
	case PhaseTransactionCreation:
		return 1
	case PhaseReady, PhaseTargetDetected, PhasePowerCycleRequired, PhaseAwaitingReconnect,
		PhaseSecondProbeReady, PhaseAwaitingNormalBootConfirmation:
		return 2
	case PhaseQualifiedFreshCandidate, PhaseBaselineClosed:
		return 3
	case PhasePrepared:
		return 4
	case PhaseCommitApproved:
		return 5
	case PhaseTrustEstablished, PhaseCommitTargetReidentified, PhaseCommitIntentRecorded, PhaseCommitInProgress:
		return 6
	case PhaseCommitReadbackVerified, PhaseAwaitingOwnedColdBoot, PhaseSignedBootVerified,
		PhaseOwnedReadbackVerified, PhaseRecoveryVerified, PhasePostRecoveryReadbackVerified, PhaseNegativeBootVerified,
		PhaseRootIntegrityVerified:
		return 7
	case PhaseRollbackVerified, PhaseFinalizationApproved, PhaseFinalizationIntentRecorded,
		PhaseFinalControlsApplied, PhaseFinalColdRestartObserved, PhaseFinalControlsReadbackVerified:
		return 8
	case PhaseFinalRetestVerified:
		return 9
	case PhaseAuditReconciled, PhaseEnrollmentReady:
		return 10
	default:
		return 0
	}
}

func terminalWorkflowStage(state *State) int {
	for index := len(state.Evidence) - 1; index >= 0; index-- {
		evidence := state.Evidence[index]
		if evidence.ID == "terminal-abort" || evidence.ID == "terminal-quarantine" {
			return workflowStageIndex(evidence.Stage)
		}
	}
	return 0
}

func workflowStageIndex(stage WorkflowStageID) int {
	switch stage {
	case WorkflowStageAdmission:
		return 0
	case WorkflowStageTransaction:
		return 1
	case WorkflowStageQualification:
		return 2
	case WorkflowStagePreparation:
		return 3
	case WorkflowStageApproval:
		return 4
	case WorkflowStageInitialTrust:
		return 5
	case WorkflowStageOwnershipCommit:
		return 6
	case WorkflowStageOwnedVerification:
		return 7
	case WorkflowStageFinalization:
		return 8
	case WorkflowStageAudit:
		return 9
	default:
		return 0
	}
}

func actionPresentation(action Action) ActionPresentation {
	presentation := ActionPresentation{Action: action, Classification: ActionAdministrative}
	switch action {
	case ActionRunStationAdmission:
		presentation.Label = "Run station admission"
		presentation.Description = "Verify the synthetic station, lane, control services, trusted time, and operator role."
	case ActionCreateTransaction:
		presentation.Label = "Create transaction"
		presentation.Description = "Reserve the synthetic asset and bind the claim, fence epoch, operator, and immutable transaction inputs."
	case ActionAttachTarget:
		presentation.Label = "Attach mock target"
		presentation.Description = "Bind exactly one synthetic target to the claimed lane."
		presentation.Classification = ActionReversible
	case ActionRunFirstProbe:
		presentation.Label = "Run metadata probe 1"
		presentation.Description = "Observe the synthetic device class and partial fresh-board baseline."
		presentation.Classification = ActionReadOnly
	case ActionDisconnectTarget:
		presentation.Label = "Simulate full power removal"
		presentation.Description = "Remove every synthetic source of target power before the continuity probe."
		presentation.Classification = ActionReversible
	case ActionReconnectTarget:
		presentation.Label = "Reconnect same target"
		presentation.Description = "Reconnect the same synthetic target in RPIBOOT mode."
		presentation.Classification = ActionReversible
	case ActionRunSecondProbe:
		presentation.Label = "Run metadata probe 2"
		presentation.Description = "Repeat the read-only observation and compare stable target fields."
		presentation.Classification = ActionReadOnly
	case ActionConfirmBootOK:
		presentation.Label = "Qualification boot passed"
		presentation.Description = "Record the synthetic pre-commit normal-boot result."
		presentation.Classification = ActionReadOnly
	case ActionConfirmBootFailed:
		presentation.Label = "Qualification boot failed"
		presentation.Description = "Record a failed pre-commit boot and abort the synthetic transaction."
		presentation.Classification = ActionReadOnly
		presentation.RequiresConfirmation = true
	case ActionCloseDeferredBaseline:
		presentation.Label = "Close deferred baseline"
		presentation.Description = "Verify remaining OTP/key rows, EEPROM posture, storage, inventory history, firmware authenticity, and debug paths."
		presentation.Classification = ActionReadOnly
	case ActionPrepareTransaction:
		presentation.Label = "Verify manifest and plan"
		presentation.Description = "Resolve every pinned artifact, signature, policy, test, and postcondition before approval."
		presentation.Classification = ActionReadOnly
	case ActionRequestCommitApproval:
		presentation.Label = "Request independent approval"
		presentation.Description = "Ask the external synthetic approval service to authorize this exact target and plan digest."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionEstablishInitialTrust:
		presentation.Label = "Establish initial trust"
		presentation.Description = "Prove both synthetic target-to-domain and domain-to-target trust."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionReidentifyCommitTarget:
		presentation.Label = "Re-identify commit target"
		presentation.Description = "Re-observe the exact transaction-bound target and zero-key prestate on the exclusive RPIBOOT lane immediately before commit intent."
		presentation.Classification = ActionReadOnly
	case ActionRecordCommitIntent:
		presentation.Label = "Record commit intent"
		presentation.Description = "Export the exact one-shot operation intent and obtain a synthetic remote audit receipt."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionExecuteCommit:
		presentation.Label = "Execute one-shot ownership commit"
		presentation.Description = "Simulate program_pubkey=1 exactly once; this models the first irreversible effect and cannot be retried."
		presentation.Classification = ActionIrreversible
		presentation.RequiresConfirmation = true
		presentation.PointOfNoReturn = true
	case ActionObserveCommitReadback:
		presentation.Label = "Observe commit readback"
		presentation.Description = "Read back the effective customer-key, secure-boot, and EEPROM state without repeating the commit."
		presentation.Classification = ActionReadOnly
	case ActionPowerOffOwnedTarget:
		presentation.Label = "Power off owned target"
		presentation.Description = "Remove all target power before the first signed cold boot."
		presentation.Classification = ActionReversible
	case ActionConfirmSignedBoot:
		presentation.Label = "Verify signed cold boot"
		presentation.Description = "Reconcile UART, the signed bit, and the boot image digest for the approved capsule."
		presentation.Classification = ActionReadOnly
	case ActionRunOwnedReadback:
		presentation.Label = "Run owned-device readback"
		presentation.Description = "Use the synthetic customer-counter-signed probe to verify target continuity and security state."
		presentation.Classification = ActionReadOnly
	case ActionTestOwnedRecovery:
		presentation.Label = "Test owned recovery"
		presentation.Description = "Prove authorized recovery works and stock or unsigned recovery is rejected."
		presentation.Classification = ActionReadOnly
	case ActionRerunOwnedReadback:
		presentation.Label = "Repeat owned readback"
		presentation.Description = "Re-establish exact target and security-state continuity through the authorized probe after recovery."
		presentation.Classification = ActionReadOnly
	case ActionTestNegativeBoot:
		presentation.Label = "Run negative boot suite"
		presentation.Description = "Reject altered, unsigned, wrong-key, and alternate-source boot candidates."
		presentation.Classification = ActionReadOnly
	case ActionTestRootIntegrity:
		presentation.Label = "Test persistent-root integrity"
		presentation.Description = "Prove tampered persistent state cannot reach enrollment services."
		presentation.Classification = ActionReadOnly
	case ActionTestRollback:
		presentation.Label = "Test rollback gate"
		presentation.Description = "Reject an older but validly signed release before enrollment services."
		presentation.Classification = ActionReadOnly
	case ActionRequestFinalizationApproval:
		presentation.Label = "Request finalization approval"
		presentation.Description = "Request separate approval for the exact owned target, current prestate, and final-control operation plan."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionRecordFinalizationIntent:
		presentation.Label = "Record finalization intent"
		presentation.Description = "Record the approved JTAG, boot-order, and EEPROM protection intent and obtain a synthetic remote audit receipt."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionApplyFinalControls:
		presentation.Label = "Apply final security controls"
		presentation.Description = "Simulate the separately approved one-way JTAG, boot-order, and EEPROM protection posture."
		presentation.Classification = ActionIrreversible
		presentation.RequiresConfirmation = true
	case ActionColdRestartFinalizedTarget:
		presentation.Label = "Cold restart finalized target"
		presentation.Description = "Observe complete power removal and a cold restart after final-control execution and before direct readback."
		presentation.Classification = ActionReversible
	case ActionObserveFinalControlsReadback:
		presentation.Label = "Observe final-controls readback"
		presentation.Description = "Directly verify the effective JTAG, boot-order, and EEPROM write-protection posture after bounded application."
		presentation.Classification = ActionReadOnly
	case ActionRunFinalRetest:
		presentation.Label = "Run post-finalization retest"
		presentation.Description = "Repeat every acceptance test affected by final controls after the observed cold restart and direct readback."
		presentation.Classification = ActionReadOnly
	case ActionReconcileAudit:
		presentation.Label = "Reconcile audit and inventory"
		presentation.Description = "Export the complete secret-free evidence and reconcile authoritative inventory state."
	case ActionMarkEnrollmentReady:
		presentation.Label = "Mark enrollment-ready"
		presentation.Description = "Complete the secure-boot stage without creating or enrolling a device identity."
		presentation.Classification = ActionAuthorizationAffecting
	case ActionExportRedacted:
		presentation.Label = "Prepare secret-free record"
		presentation.Description = "Render the full synthetic transaction, manifest, evidence, outcome, and safety boundary."
	case ActionReset:
		presentation.Label = "Reset pre-ownership simulation"
		presentation.Description = "Reuse the pre-ownership synthetic fixture; owned or security-applied terminal states intentionally expose no reset path."
	}
	return presentation
}

func actionAllowed(allowed []Action, action Action) bool {
	for _, candidate := range allowed {
		if action == candidate {
			return true
		}
	}
	return false
}

func validScenario(scenario ScenarioID) bool {
	for _, candidate := range ScenarioIDs() {
		if scenario == candidate {
			return true
		}
	}
	return false
}

func scenarioOptions() []ScenarioOption {
	labels := map[ScenarioID]string{
		ScenarioHappyPath:                    "Enrollment-ready happy path",
		ScenarioClassMismatch:                "Device-class mismatch",
		ScenarioBaselineFailure:              "Foreign ownership detected",
		ScenarioMultipleTargets:              "Multiple targets",
		ScenarioAcquisitionError:             "Probe acquisition error",
		ScenarioTargetReplaced:               "Target replaced",
		ScenarioMutationSafetyViolation:      "Unexpected probe mutation",
		ScenarioBootFailure:                  "Qualification boot failure",
		ScenarioPreparationFailure:           "Preparation failure",
		ScenarioApprovalFailure:              "Approval failure",
		ScenarioTrustFailure:                 "Initial-trust failure",
		ScenarioCommitUncertain:              "Commit outcome uncertain",
		ScenarioCommitReadbackMismatch:       "Commit readback mismatch",
		ScenarioSignedBootFailure:            "Signed cold-boot failure",
		ScenarioOwnedReadbackMismatch:        "Owned readback mismatch",
		ScenarioRecoveryFailure:              "Recovery failure",
		ScenarioNegativeBootFailure:          "Negative boot failure",
		ScenarioRootIntegrityFailure:         "Root-integrity failure",
		ScenarioRollbackFailure:              "Rollback failure",
		ScenarioFinalizationFailure:          "Finalization failure",
		ScenarioFinalRetestFailure:           "Final retest failure",
		ScenarioAuditFailure:                 "Audit reconciliation failure",
		ScenarioDeferredBaselineFailure:      "Deferred baseline failure",
		ScenarioPrecommitTargetReplaced:      "Pre-commit target replaced",
		ScenarioPostRecoveryReadbackMismatch: "Post-recovery readback mismatch",
	}
	result := make([]ScenarioOption, 0, len(ScenarioIDs()))
	for _, id := range ScenarioIDs() {
		result = append(result, ScenarioOption{ID: id, Label: labels[id], Action: Action("select_scenario:" + string(id))})
	}
	return result
}

func withScenarioActions(actions []Action) []Action {
	result := append([]Action(nil), actions...)
	for _, scenario := range ScenarioIDs() {
		action := Action("select_scenario:" + string(scenario))
		if !actionAllowed(result, action) {
			result = append(result, action)
		}
	}
	return result
}

func scenarioFromAction(action Action) (ScenarioID, bool) {
	const prefix = "select_scenario:"
	value := string(action)
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	return ScenarioID(strings.TrimPrefix(value, prefix)), true
}

func cloneState(state State) State {
	encoded, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	var clone State
	if err := json.Unmarshal(encoded, &clone); err != nil {
		panic(err)
	}
	return clone
}
