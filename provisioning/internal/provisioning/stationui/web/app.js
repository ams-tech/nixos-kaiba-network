"use strict";

(() => {
  const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha2";
  const exportSchema = "provisioning.kaiba.network/station-demo-export/v1alpha2";
  const pollIntervalMs = 2500;
  const falseSafetyCapabilities = [
    "mutation_eligible",
    "live_target_access",
    "live_mutation_capable",
    "authoritative_evidence",
    "secrets_present",
    "approval_authority",
    "signing_capable",
    "enrollment_capable",
  ];
  const workflowStageStatuses = new Set(["pending", "current", "complete", "failed"]);
  const workflowStageIDs = [
    "admission",
    "transaction",
    "qualification",
    "preparation",
    "approval",
    "initial_trust",
    "ownership_commit",
    "owned_verification",
    "finalization",
    "audit_reconciliation",
  ];
  const actionClassifications = new Set(["administrative", "read_only", "reversible", "authorization_affecting", "irreversible"]);
  const transactionStatuses = new Set(["created", "target_bound", "preflight_passed", "commit_approved", "trust_established", "security_applied", "aborted", "quarantined"]);
  const lifecycleStates = new Set(["unregistered", "qualified_fresh_candidate", "prepared", "commit_in_progress", "security_applied", "enrollment_ready", "owned_quarantined"]);
  const evidenceStatuses = new Set(["pending", "passed", "failed", "recorded"]);
  const sensitiveKeys = new Set([
    "private_key",
    "private_key_pem",
    "signing_key",
    "shared_secret",
    "enrollment_secret",
    "password",
    "credential",
    "access_token",
  ]);

  const elements = {
    stationId: document.querySelector("#station-id"),
    laneId: document.querySelector("#lane-id"),
    transactionId: document.querySelector("#transaction-id"),
    stationStatus: document.querySelector("#station-status"),
    laneStatus: document.querySelector("#lane-status"),
    targetStatus: document.querySelector("#target-status"),
    lifecycleStatus: document.querySelector("#lifecycle-status"),
    stationDot: document.querySelector("#station-dot"),
    laneDot: document.querySelector("#lane-dot"),
    targetDot: document.querySelector("#target-dot"),
    lifecycleDot: document.querySelector("#lifecycle-dot"),
    phaseCode: document.querySelector("#phase-code"),
    phaseTitle: document.querySelector("#phase-title"),
    phaseInstruction: document.querySelector("#phase-instruction"),
    announcement: document.querySelector("#workflow-announcement"),
    connectionAlert: document.querySelector("#connection-alert"),
    connectionMessage: document.querySelector("#connection-message"),
    retryState: document.querySelector("#retry-state"),
    workflowStages: document.querySelector("#workflow-stages"),
    laneBinding: document.querySelector("#lane-binding"),
    boundTarget: document.querySelector("#bound-target"),
    lifecycleDetail: document.querySelector("#lifecycle-detail"),
    workKicker: document.querySelector("#work-kicker"),
    workTitle: document.querySelector("#work-title"),
    profileBadge: document.querySelector("#profile-badge"),
    targetEmpty: document.querySelector("#target-empty"),
    targetSummary: document.querySelector("#target-summary"),
    targetModel: document.querySelector("#target-model"),
    targetClassStatus: document.querySelector("#target-class-status"),
    targetFacts: document.querySelector("#target-facts"),
    transactionPanel: document.querySelector("#transaction-panel"),
    transactionFacts: document.querySelector("#transaction-facts"),
    manifestPanel: document.querySelector("#manifest-panel"),
    manifestFacts: document.querySelector("#manifest-facts"),
    policyList: document.querySelector("#policy-list"),
    evidencePanel: document.querySelector("#evidence-panel"),
    evidenceSummary: document.querySelector("#evidence-summary"),
    evidenceChecks: document.querySelector("#evidence-checks"),
    assessmentPanel: document.querySelector("#assessment-panel"),
    classResult: document.querySelector("#class-result"),
    baselineResult: document.querySelector("#baseline-result"),
    reversibleResult: document.querySelector("#reversible-result"),
    assessmentNote: document.querySelector("#assessment-note"),
    comparisonPanel: document.querySelector("#comparison-panel"),
    comparisonBody: document.querySelector("#comparison-body"),
    outcomePanel: document.querySelector("#outcome-panel"),
    outcomeLabel: document.querySelector("#outcome-label"),
    outcomeTitle: document.querySelector("#outcome-title"),
    outcomeDescription: document.querySelector("#outcome-description"),
    actionButtons: document.querySelector("#action-buttons"),
    actionHelp: document.querySelector("#action-help"),
    exportPanel: document.querySelector("#export-panel"),
    exportRecord: document.querySelector("#export-record"),
    downloadExport: document.querySelector("#download-export"),
    developerPanel: document.querySelector("#developer-panel"),
    scenarioButtons: document.querySelector("#scenario-buttons"),
    revisionLabel: document.querySelector("#revision-label"),
  };

  const phasePresentation = {
    station_admission: ["Admit the station", "Verify the synthetic station and exclusive lane."],
    transaction_creation: ["Create the transaction", "Bind the synthetic asset, target, operator, and approver."],
    ready: ["Station ready", "Attach exactly one mock Pi 5 target."],
    target_detected: ["Target detected", "Review the lane-bound synthetic target."],
    power_cycle_required: ["Power removal required", "Simulate removal of every target power source."],
    awaiting_reconnect: ["Target absent", "Reconnect the same synthetic target."],
    second_probe_ready: ["Target reconnected", "Run the second qualification observation."],
    awaiting_normal_boot_confirmation: ["Normal boot check", "Record the synthetic operator observation."],
    qualified_fresh_candidate: ["Fresh candidate qualified", "Resolve the deferred fresh-board baseline before preparation."],
    baseline_closed: ["Deferred baseline closed", "Prepare the complete secure-boot transaction."],
    prepared: ["Transaction prepared", "Review every pinned artifact and policy."],
    commit_approved: ["Commit approved", "Establish the modeled initial trust prerequisite."],
    trust_established: ["Initial trust established", "Re-identify the exact target at the commit boundary."],
    commit_target_reidentified: ["Commit target re-identified", "Record target-bound mutation intent."],
    commit_intent_recorded: ["Point of no return", "The next modeled action represents the one-shot OTP/EEPROM commit."],
    commit_in_progress: ["Commit result pending", "Do not repeat the modeled commit; inspect authoritative readback."],
    commit_readback_verified: ["Ownership read back", "Remove all modeled power before the owned-device proof."],
    awaiting_owned_cold_boot: ["Owned cold boot", "Verify the exact approved signed boot capsule."],
    signed_boot_verified: ["Signed boot verified", "Run the customer-counter-signed owned-device readback."],
    owned_readback_verified: ["Owned state reconciled", "Prove authorized and unauthorized recovery behavior."],
    recovery_verified: ["Recovery policy verified", "Repeat the owned-device readback after recovery."],
    post_recovery_readback_verified: ["Post-recovery state reconciled", "Exercise every negative boot candidate and enabled source."],
    negative_boot_verified: ["Negative boot tests passed", "Prove persistent-root integrity enforcement."],
    root_integrity_verified: ["Root integrity verified", "Prove the independent rollback gate."],
    rollback_verified: ["Rollback gate verified", "Request separate approval for the exact final-control plan."],
    finalization_approved: ["Final controls approved", "Record a separate target-bound finalization intent."],
    finalization_intent_recorded: ["Finalization intent recorded", "Apply the approved one-way final controls."],
    final_controls_applied: ["Final controls applied", "Cold-restart the finalized target before readback."],
    final_cold_restart_observed: ["Final cold restart observed", "Read back JTAG, boot-order, and EEPROM protection state."],
    final_controls_readback_verified: ["Final controls read back", "Repeat every affected positive and negative test."],
    final_retest_verified: ["Final posture verified", "Reconcile the complete secret-free audit record."],
    audit_reconciled: ["Audit reconciled", "Mark the modeled device enrollment-ready."],
    enrollment_ready: ["Enrollment-ready", "Export the secret-free synthetic audit record."],
    stopped: ["Workflow stopped", "Review the synthetic evidence before resetting."],
    quarantined: ["Owned target quarantined", "Export evidence; never return this modeled target to the fresh path."],
  };

  let currentState = null;
  let transport = null;
  let initializationInFlight = false;
  let requestInFlight = false;
  let armedAction = null;
  let exportURL = null;

  function normalized(value) {
    return String(value ?? "").trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
  }

  function titleCase(value) {
    const text = String(value ?? "").replaceAll("_", " ").replaceAll("-", " ").trim();
    return text ? text.replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Unknown";
  }

  function shorten(value, front = 12, back = 8) {
    const text = String(value ?? "");
    if (text.length <= front + back + 1) return text || "—";
    return `${text.slice(0, front)}…${text.slice(-back)}`;
  }

  function isObject(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
  }

  function requireString(value, label, { empty = false } = {}) {
    if (typeof value !== "string" || (!empty && value.length === 0)) throw new Error(`${label} must be a string.`);
  }

  function assertSafety(safety, label) {
    if (!isObject(safety) || safety.simulation !== true
      || safety.full_unprovisioned_state !== "not_established") {
      throw new Error(`${label} does not establish the simulation safety boundary.`);
    }
    for (const field of falseSafetyCapabilities) {
      if (safety[field] !== false) throw new Error(`${label} did not deny ${field}.`);
    }
  }

  function assertSecretFree(value, label, seen = new Set()) {
    if (!value || typeof value !== "object") {
      if (typeof value === "string" && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) {
        throw new Error(`${label} contains private key material.`);
      }
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    for (const [key, nested] of Object.entries(value)) {
      if (sensitiveKeys.has(normalized(key))) throw new Error(`${label} contains forbidden secret field ${key}.`);
      assertSecretFree(nested, label, seen);
    }
  }

  function ensureMockState(state) {
    if (!isObject(state)) throw new Error("Station returned an invalid state object.");
    if (state.schema_version !== stateSchema || state.simulation !== true) {
      throw new Error("This interface refuses incompatible or non-simulation station state.");
    }
    if (!Number.isSafeInteger(state.revision) || state.revision < 1) throw new Error("Station state has an invalid revision.");
    requireString(state.phase, "Station phase");
    requireString(state.lifecycle, "Station lifecycle");
    if (!lifecycleStates.has(state.lifecycle)) throw new Error("Station returned an unsupported lifecycle state.");
    if (!Array.isArray(state.allowed_actions) || new Set(state.allowed_actions).size !== state.allowed_actions.length
      || !state.allowed_actions.every((action) => typeof action === "string" && action.length > 0)) {
      throw new Error("Station state has invalid allowed actions.");
    }
    if (!Array.isArray(state.scenarios)) throw new Error("Station state has invalid simulation scenarios.");
    const scenarioActions = new Set();
    for (const scenario of state.scenarios) {
      if (!isObject(scenario)) throw new Error("Station state has malformed simulation scenarios.");
      for (const field of ["id", "label", "action"]) requireString(scenario[field], `Scenario ${field}`);
      if (!scenario.action.startsWith("select_scenario:") || scenarioActions.has(scenario.action)) {
        throw new Error("Station state has malformed simulation scenario actions.");
      }
      scenarioActions.add(scenario.action);
    }
    const allowedScenarioActions = state.allowed_actions.filter((action) => action.startsWith("select_scenario:"));
    if (scenarioActions.size !== allowedScenarioActions.length
      || allowedScenarioActions.some((action) => !scenarioActions.has(action))
      || (state.phase !== "station_admission" && state.scenarios.length !== 0)) {
      throw new Error("Station state exposed scenarios outside the admission phase.");
    }
    if (!Array.isArray(state.workflow_stages) || state.workflow_stages.length === 0) {
      throw new Error("Station state has no typed workflow stages.");
    }
    if (state.workflow_stages.length !== workflowStageIDs.length
      || state.workflow_stages.some((stage, index) => stage?.id !== workflowStageIDs[index])) {
      throw new Error("Station state does not expose the complete ordered secure-boot workflow.");
    }
    const stageIDs = new Set();
    for (const stage of state.workflow_stages) {
      if (!isObject(stage)) throw new Error("Station returned a malformed workflow stage.");
      requireString(stage.id, "Workflow stage id");
      requireString(stage.label, "Workflow stage label");
      requireString(stage.status, "Workflow stage status");
      if (!workflowStageStatuses.has(stage.status)) throw new Error("Station returned an unsupported workflow stage status.");
      if (stageIDs.has(stage.id)) throw new Error("Station returned duplicate workflow stage ids.");
      stageIDs.add(stage.id);
    }
    if (!Array.isArray(state.action_presentations)) throw new Error("Station state has no typed action presentations.");
    const actionPresentations = new Map();
    for (const presentation of state.action_presentations) {
      if (!isObject(presentation)) throw new Error("Station returned malformed action metadata.");
      for (const field of ["action", "label", "description", "classification"]) {
        requireString(presentation[field], `Action presentation ${field}`);
      }
      if (typeof presentation.requires_confirmation !== "boolean" || typeof presentation.point_of_no_return !== "boolean") {
        throw new Error("Station returned untyped action confirmation metadata.");
      }
      if (!actionClassifications.has(presentation.classification)) throw new Error("Station returned an unsupported action classification.");
      if (presentation.classification === "irreversible" && presentation.requires_confirmation !== true) {
        throw new Error("Station returned irreversible action metadata without confirmation.");
      }
      if (presentation.point_of_no_return !== (presentation.action === "execute_commit")
        || (presentation.point_of_no_return
          && (presentation.classification !== "irreversible" || presentation.requires_confirmation !== true))) {
        throw new Error("Station returned unsafe point-of-no-return metadata.");
      }
      if (actionPresentations.has(presentation.action)) throw new Error("Station returned duplicate action metadata.");
      actionPresentations.set(presentation.action, presentation);
    }
    for (const action of state.allowed_actions.filter((candidate) => !candidate.startsWith("select_scenario:"))) {
      if (!actionPresentations.has(action)) throw new Error(`Station omitted presentation metadata for ${action}.`);
    }
    assertSafety(state.safety, "Station state");
    for (const probe of Array.isArray(state.probes) ? state.probes : []) {
      if (!isObject(probe) || !isObject(probe.assessment)
        || probe.assessment.mutation_eligible !== false
        || probe.assessment.full_unprovisioned_state !== "not_established") {
        throw new Error("Station returned an unsafe probe assessment.");
      }
    }
    if (state.transaction !== null && state.transaction !== undefined) {
      if (!isObject(state.transaction) || !Number.isSafeInteger(state.transaction.commit_executions)
        || state.transaction.commit_executions < 0 || state.transaction.commit_executions > 1
        || !Number.isSafeInteger(state.transaction.final_control_executions)
        || state.transaction.final_control_executions < 0 || state.transaction.final_control_executions > 1
        || typeof state.transaction.irreversible_boundary_crossed !== "boolean") {
        throw new Error("Station returned malformed transaction state.");
      }
      for (const field of [
        "id", "status", "asset_id", "intended_logical_id", "claim_id", "operator_id", "approver_id",
        "target_fingerprint", "digest", "plan_digest", "approval_id", "intent_receipt",
        "finalization_approval_id", "finalization_intent_receipt",
      ]) {
        requireString(state.transaction[field], `Transaction ${field}`, { empty: true });
      }
      if (!transactionStatuses.has(state.transaction.status)) throw new Error("Station returned an unsupported transaction status.");
      if (state.transaction.commit_executions === 1
        && (state.transaction.irreversible_boundary_crossed !== true
          || !state.transaction.approval_id || !state.transaction.intent_receipt)) {
        throw new Error("Station returned a commit without its approval, intent, and boundary evidence.");
      }
      if (state.transaction.final_control_executions === 1
        && (state.transaction.commit_executions !== 1
          || state.transaction.irreversible_boundary_crossed !== true
          || !state.transaction.finalization_approval_id
          || !state.transaction.finalization_intent_receipt)) {
        throw new Error("Station returned final controls without the commit boundary and separate approval and intent evidence.");
      }
    }
    if (state.manifest !== null && state.manifest !== undefined) {
      if (!isObject(state.manifest)) throw new Error("Station returned malformed manifest state.");
      for (const field of ["id", "digest", "expected_customer_key_hash", "boot_image_digest", "verification_status"]) {
        requireString(state.manifest[field], `Manifest ${field}`, { empty: true });
      }
    }
    if (!Array.isArray(state.evidence)) throw new Error("Station returned malformed cumulative evidence.");
    const evidenceIDs = new Set();
    for (const evidence of state.evidence) {
      if (!isObject(evidence)) throw new Error("Station returned malformed cumulative evidence.");
      for (const field of ["id", "label", "stage", "status", "digest", "detail"]) {
        requireString(evidence[field], `Evidence ${field}`, { empty: field === "digest" || field === "detail" });
      }
      if (!evidenceStatuses.has(evidence.status)) throw new Error("Station returned an unsupported evidence status.");
      if (evidenceIDs.has(evidence.id)) throw new Error("Station returned duplicate cumulative evidence ids.");
      evidenceIDs.add(evidence.id);
    }
    if (state.export_record) {
      if (!isObject(state.export_record) || state.export_record.schema_version !== exportSchema
        || state.export_record.simulation !== true || state.export_record.secret_free !== true) {
        throw new Error("Station returned an incompatible audit export.");
      }
      assertSafety(state.export_record.safety, "Audit export");
      assertSecretFree(state.export_record, "Audit export");
    }
    assertSecretFree(state, "Station state");
    return state;
  }

  function statusClass(value) {
    const status = normalized(value);
    if (["ready", "connected", "detected", "pass", "passed", "match", "matched", "complete", "completed", "verified", "enrollment_ready"].includes(status)) return "is-ready";
    if (["failed", "fail", "error", "fenced", "quarantined", "owned_quarantined", "changed", "mismatch"].includes(status)) return "is-error";
    if (["warning", "waiting", "active", "in_progress", "absent", "disconnected", "indeterminate", "pending"].includes(status)) return "is-warning";
    return "";
  }

  function setDot(element, value) {
    element.className = `status-dot ${statusClass(value)}`.trim();
  }

  function presentationFor(state, action) {
    return state.action_presentations.find((item) => item.action === action) || null;
  }

  function showError(message) {
    elements.connectionMessage.textContent = message;
    elements.connectionAlert.hidden = false;
  }

  function clearError() {
    elements.connectionAlert.hidden = true;
  }

  async function refreshState({ announce = false, focus = false } = {}) {
    if (!transport || requestInFlight) return;
    try {
      const state = ensureMockState(await transport.getState());
      const changed = !currentState || state.revision !== currentState.revision;
      currentState = state;
      if (changed) armedAction = null;
      clearError();
      render(state);
      if (announce && changed) announceState(state);
      if (focus) elements.phaseTitle.focus({ preventScroll: true });
    } catch (error) {
      showError(error.name === "AbortError" ? "The station did not respond before the request deadline." : error.message);
    }
  }

  async function submitAction(action) {
    if (!transport || !currentState || requestInFlight || !actionIsExposed(currentState, action)) return;
    const presentation = presentationFor(currentState, action);
    if (presentation?.requires_confirmation === true && armedAction !== action) {
      armedAction = action;
      renderActions(currentState);
      elements.actionHelp.textContent = presentation.point_of_no_return
        ? "Confirm the one-shot modeled commit. The simulation will not offer this commit action again."
        : `Confirm ${presentation.label}. No state has changed yet.`;
      elements.announcement.textContent = elements.actionHelp.textContent;
      return;
    }
    armedAction = null;
    requestInFlight = true;
    setActionBusy(action, presentation);
    clearError();
    try {
      const responseState = await transport.applyAction({ action, expected_revision: currentState.revision });
      currentState = responseState ? ensureMockState(responseState) : ensureMockState(await transport.getState());
      render(currentState);
      announceState(currentState);
      elements.phaseTitle.focus({ preventScroll: true });
    } catch (error) {
      if (error.status === 409) {
        try {
          currentState = ensureMockState(await transport.getState());
          render(currentState);
          announceState(currentState);
        } catch {
          // Keep the conflict visible; the periodic state read will retry.
        }
        showError("Station state changed before that action was accepted. Review the refreshed phase before continuing.");
      } else {
        showError(error.name === "AbortError"
          ? "The action did not complete before the request deadline. Modeled commit state may be uncertain; refresh before any next action."
          : error.message);
      }
    } finally {
      requestInFlight = false;
      if (currentState) renderActions(currentState);
    }
  }

  function actionIsExposed(state, action) {
    return state.allowed_actions.includes(action)
      || (Array.isArray(state.scenarios) && state.scenarios.some((scenario) => scenario?.action === action));
  }

  function setActionBusy(action, presentation) {
    for (const button of elements.actionButtons.querySelectorAll("button")) button.disabled = true;
    for (const button of elements.scenarioButtons.querySelectorAll("button")) button.disabled = true;
    elements.actionHelp.textContent = `${presentation?.label || titleCase(action)} is being applied by the mock station…`;
  }

  function announceState(state) {
    const presentation = phasePresentation[normalized(state.phase)] || [titleCase(state.phase), "State updated"];
    elements.announcement.textContent = `${presentation[0]}. ${state.instruction || presentation[1]}`;
  }

  function render(state) {
    const station = state.station || {};
    const lane = state.lane || {};
    const transaction = state.transaction || null;
    const phase = normalized(state.phase);
    const lifecycle = normalized(state.lifecycle);
    const presentation = phasePresentation[phase] || [titleCase(state.phase), "Follow the station instruction"];

    elements.stationId.textContent = station.id || "Unknown station";
    elements.laneId.textContent = lane.id || "No lane";
    elements.transactionId.textContent = transaction?.id ? shorten(transaction.id, 12, 8) : "Not started";
    elements.stationStatus.textContent = titleCase(station.status || "unknown");
    elements.laneStatus.textContent = titleCase(lane.status || "unknown");
    elements.targetStatus.textContent = state.target ? "Detected" : titleCase(lane.target_status || "not detected");
    elements.lifecycleStatus.textContent = titleCase(state.lifecycle);
    setDot(elements.stationDot, station.status);
    setDot(elements.laneDot, lane.status);
    setDot(elements.targetDot, state.target ? "detected" : lane.target_status || lane.status);
    setDot(elements.lifecycleDot, lifecycle);

    elements.phaseCode.textContent = String(state.phase).replaceAll("_", " ").toUpperCase();
    elements.phaseTitle.textContent = presentation[0];
    elements.phaseInstruction.textContent = state.instruction || presentation[1];
    elements.laneBinding.textContent = lane.usb_path ? `${lane.id || "lane"} · USB ${lane.usb_path}` : `${lane.id || "lane"} · no target path`;
    elements.boundTarget.textContent = transaction?.target_fingerprint
      ? shorten(transaction.target_fingerprint, 16, 10)
      : state.target?.target_fingerprint || state.target?.fingerprint
        ? shorten(state.target.target_fingerprint || state.target.fingerprint, 16, 10)
        : "Not bound";
    elements.lifecycleDetail.textContent = lifecycle === "owned_quarantined"
      ? "Owned and permanently quarantined from the fresh path"
      : lifecycle === "enrollment_ready"
        ? "Synthetic security posture reconciled; enrollment itself unavailable"
        : titleCase(state.lifecycle);
    elements.revisionLabel.textContent = `State r${state.revision}`;
    elements.profileBadge.textContent = `${titleCase(state.target?.profile_status || state.manifest?.verification_status || "simulation")} · no live authority`;
    elements.workKicker.textContent = transaction ? "Current synthetic transaction" : "Station admission";
    elements.workTitle.textContent = presentation[1];

    renderWorkflowStages(state.workflow_stages);
    renderTarget(state);
    renderTransaction(state);
    renderManifest(state.manifest);
    renderEvidence(state.evidence);
    renderAssessment(state);
    renderComparison(state.comparison);
    renderOutcome(state.outcome, phase, lifecycle);
    renderActions(state);
    renderScenarios(state);
    renderExport(state.export_record);
  }

  function renderWorkflowStages(stages) {
    elements.workflowStages.replaceChildren(...stages.map((stage, index) => {
      const item = document.createElement("li");
      const status = normalized(stage.status);
      const complete = ["complete", "completed", "pass", "passed", "verified"].includes(status);
      const current = ["current", "active", "in_progress"].includes(status);
      const failed = ["fail", "failed", "blocked", "quarantined"].includes(status);
      item.classList.toggle("is-complete", complete);
      item.classList.toggle("is-current", current);
      item.classList.toggle("is-failed", failed);
      if (current) item.setAttribute("aria-current", "step");
      const number = document.createElement("span");
      number.textContent = String(index + 1);
      const copy = document.createElement("div");
      const label = document.createElement("strong");
      const detail = document.createElement("small");
      label.textContent = stage.label;
      detail.textContent = titleCase(stage.status);
      copy.append(label, detail);
      item.append(number, copy);
      return item;
    }));
  }

  function renderTarget(state) {
    const target = state.target;
    elements.targetEmpty.hidden = Boolean(target);
    elements.targetSummary.hidden = !target;
    if (!target) return;
    const observation = target.observation || target;
    elements.targetModel.textContent = observation.model || observation.device_model || "Raspberry Pi 5 Model B";
    const latestProbe = Array.isArray(state.probes) && state.probes.length > 0 ? state.probes[state.probes.length - 1] : null;
    const classStatus = latestProbe?.device_class_status || observation.class_status || target.class_status || "observed";
    elements.targetClassStatus.textContent = titleCase(classStatus);
    elements.targetClassStatus.className = `result-chip ${normalized(classStatus) === "pass" ? "result-pass" : normalized(classStatus) === "fail" ? "result-fail" : "result-neutral"}`;
    const revision = observation.board_revision;
    const revisionText = isObject(revision) ? revision.raw : revision;
    const facts = [
      ["Fingerprint", shorten(observation.target_fingerprint || observation.fingerprint, 16, 10), observation.target_fingerprint || observation.fingerprint],
      ["Serial", shorten(observation.user_serial, 5, 4), observation.user_serial],
      ["Factory UUID", shorten(observation.factory_uuid, 9, 6), observation.factory_uuid],
      ["Board revision", revisionText || "—", revisionText],
      ["Boot ROM", observation.boot_rom || "—", observation.boot_rom],
      ["EEPROM hash", shorten(observation.eeprom_hash, 10, 8), observation.eeprom_hash],
      ["Customer key", titleCase(observation.customer_key_state || "unknown"), observation.customer_key_hash],
      ["VideoCore JTAG", observation.videocore_jtag_state ? titleCase(observation.videocore_jtag_state) : observation.videocore_jtag_locked === false ? "Unlocked" : observation.videocore_jtag_locked === true ? "Locked" : "Unknown", ""],
    ];
    elements.targetFacts.replaceChildren(...facts.map(([label, value, full]) => factNode(label, value, full)));
  }

  function factNode(label, value, full) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = value || "—";
    if (full && full !== value) detail.title = String(full);
    wrapper.append(term, detail);
    return wrapper;
  }

  function renderTransaction(state) {
    const transaction = state.transaction;
    elements.transactionPanel.hidden = !transaction;
    if (!transaction) {
      elements.transactionFacts.replaceChildren();
      return;
    }
    const facts = [
      ["Transaction", shorten(transaction.id, 14, 8), transaction.id],
      ["Status", titleCase(transaction.status), ""],
      ["Lifecycle", titleCase(state.lifecycle), ""],
      ["Asset", transaction.asset_id || "Not assigned", transaction.asset_id],
      ["Logical ID", transaction.intended_logical_id || "Not assigned", transaction.intended_logical_id],
      ["Claim / fence", `${transaction.claim_id || "—"} · ${transaction.fence_epoch ?? "—"}`, ""],
      ["Operator", transaction.operator_id || "Not assigned", transaction.operator_id],
      ["Approver", transaction.approver_id || "Not assigned", transaction.approver_id],
      ["Plan digest", shorten(transaction.plan_digest, 12, 8), transaction.plan_digest],
      ["Approval", transaction.approval_id || "Pending", transaction.approval_id],
      ["Intent receipt", shorten(transaction.intent_receipt, 12, 8), transaction.intent_receipt],
      ["Final approval", transaction.finalization_approval_id || "Pending", transaction.finalization_approval_id],
      ["Final intent", shorten(transaction.finalization_intent_receipt, 12, 8), transaction.finalization_intent_receipt],
      ["Commit executions", String(transaction.commit_executions), ""],
      ["Final-control executions", String(transaction.final_control_executions), ""],
      ["Irreversible boundary", transaction.irreversible_boundary_crossed ? "Crossed in simulation" : "Not crossed", ""],
    ];
    elements.transactionFacts.replaceChildren(...facts.map(([label, value, full]) => factNode(label, value, full)));
  }

  function renderManifest(manifest) {
    elements.manifestPanel.hidden = !manifest;
    if (!manifest) {
      elements.manifestFacts.replaceChildren();
      elements.policyList.replaceChildren();
      return;
    }
    const facts = [
      ["Manifest", manifest.id, manifest.id],
      ["Manifest digest", shorten(manifest.digest, 12, 8), manifest.digest],
      ["Profile", manifest.profile_id, manifest.profile_id],
      ["Profile digest", shorten(manifest.profile_digest, 12, 8), manifest.profile_digest],
      ["Adapter", manifest.adapter_id, manifest.adapter_id],
      ["Adapter digest", shorten(manifest.adapter_digest, 12, 8), manifest.adapter_digest],
      ["Customer key hash", shorten(manifest.expected_customer_key_hash, 12, 8), manifest.expected_customer_key_hash],
      ["EEPROM image", shorten(manifest.eeprom_image_digest, 12, 8), manifest.eeprom_image_digest],
      ["Boot image", shorten(manifest.boot_image_digest, 12, 8), manifest.boot_image_digest],
      ["Boot signature", shorten(manifest.boot_signature_digest, 12, 8), manifest.boot_signature_digest],
      ["Root integrity", shorten(manifest.root_integrity_digest, 12, 8), manifest.root_integrity_digest],
      ["Fresh commit bundle", shorten(manifest.fresh_commit_bundle_digest, 12, 8), manifest.fresh_commit_bundle_digest],
      ["Owned recovery", shorten(manifest.owned_recovery_bundle_digest, 12, 8), manifest.owned_recovery_bundle_digest],
      ["Signer", manifest.signer_id, manifest.signer_id],
      ["Signing tool", manifest.signing_tool_version, manifest.signing_tool_version],
      ["Offline verification", titleCase(manifest.verification_status), ""],
    ];
    elements.manifestFacts.replaceChildren(...facts.map(([label, value, full]) => factNode(label, value, full)));
    const policies = [
      ["Boot order", manifest.boot_order],
      ["Rollback", manifest.rollback_policy],
      ["Debug / JTAG", manifest.debug_policy],
      ["EEPROM write protection", manifest.eeprom_write_protection_policy],
    ];
    elements.policyList.replaceChildren(...policies.map(([label, value]) => {
      const item = document.createElement("li");
      const copy = document.createElement("span");
      const code = document.createElement("code");
      copy.textContent = label;
      code.textContent = value || "Not approved";
      code.title = value || "";
      item.append(copy, code);
      return item;
    }));
  }

  function evidenceClass(status) {
    const value = normalized(status);
    if (["pass", "passed", "complete", "completed", "verified", "recorded"].includes(value)) return "is-pass";
    if (["fail", "failed", "quarantined", "mismatch"].includes(value)) return "is-fail";
    return "is-pending";
  }

  function renderEvidence(evidence) {
    elements.evidencePanel.hidden = evidence.length === 0;
    if (evidence.length === 0) {
      elements.evidenceChecks.replaceChildren();
      return;
    }
    const completed = evidence.filter((item) => evidenceClass(item.status) === "is-pass").length;
    elements.evidenceSummary.textContent = `${completed} / ${evidence.length} complete`;
    elements.evidenceChecks.replaceChildren(...evidence.map((entry) => {
      const item = document.createElement("li");
      item.className = evidenceClass(entry.status);
      const label = document.createElement("strong");
      const detail = document.createElement("small");
      label.textContent = entry.label;
      detail.textContent = `${titleCase(entry.status)} · ${titleCase(entry.stage)}${entry.detail ? ` · ${entry.detail}` : ""}`;
      if (entry.digest) detail.title = entry.digest;
      item.append(label, detail);
      return item;
    }));
  }

  function latestAssessment(state) {
    if (Array.isArray(state.probes) && state.probes.length > 0) {
      const probe = state.probes[state.probes.length - 1];
      const nested = probe.assessment || probe.result?.assessment;
      if (nested) return { ...nested, findings: probe.findings };
    }
    return state.assessment || state.target?.assessment || null;
  }

  function renderAssessment(state) {
    const assessment = latestAssessment(state);
    elements.assessmentPanel.hidden = !assessment;
    if (!assessment) return;
    const classStatus = assessment.device_class?.status || assessment.class_status || "indeterminate";
    const baselineStatus = assessment.observable_baseline?.status || assessment.baseline_status || "indeterminate";
    const reversible = assessment.eligible_for_reversible_qualification === true;
    setAssessmentValue(elements.classResult, classStatus);
    setAssessmentValue(elements.baselineResult, baselineStatus);
    setAssessmentValue(elements.reversibleResult, reversible ? "eligible" : "not eligible", reversible ? "pass" : "indeterminate");
    const firstFinding = Array.isArray(assessment.findings) ? assessment.findings.find((finding) => finding?.message) : null;
    elements.assessmentNote.textContent = firstFinding?.message || assessment.disclaimer || state.safety.disclaimer;
  }

  function setAssessmentValue(element, value, semantic = value) {
    element.textContent = titleCase(value);
    const status = normalized(semantic);
    element.className = ["pass", "passed", "eligible"].includes(status) ? "is-pass" : ["fail", "failed", "not_eligible"].includes(status) ? "is-fail" : "is-indeterminate";
  }

  function renderComparison(comparison) {
    const rows = Array.isArray(comparison) ? comparison : [];
    elements.comparisonPanel.hidden = rows.length === 0;
    if (rows.length === 0) return;
    elements.comparisonBody.replaceChildren(...rows.map((entry) => {
      const row = document.createElement("tr");
      const field = document.createElement("th");
      const result = document.createElement("td");
      field.scope = "row";
      field.textContent = entry.label || titleCase(entry.field || entry.id || "observation");
      const status = normalized(entry.status);
      result.textContent = status === "match" ? "MATCH" : status === "changed" ? "CHANGED" : titleCase(status);
      result.className = status === "match" ? "comparison-match" : status === "changed" ? "comparison-changed" : "comparison-missing";
      row.append(field, result);
      return row;
    }));
  }

  function renderOutcome(outcome, phase, lifecycle) {
    const enrollmentReady = lifecycle === "enrollment_ready" || phase === "enrollment_ready";
    const ownedQuarantined = lifecycle === "owned_quarantined" || phase === "quarantined";
    const stopped = phase === "stopped";
    const present = Boolean(outcome) || enrollmentReady || ownedQuarantined || stopped;
    elements.outcomePanel.hidden = !present;
    if (!present) return;
    elements.outcomePanel.classList.toggle("is-quarantined", ownedQuarantined);
    elements.outcomePanel.classList.toggle("is-stopped", stopped && !ownedQuarantined);
    elements.outcomeLabel.textContent = ownedQuarantined
      ? "Owned-device safety outcome"
      : enrollmentReady
        ? "Synthetic terminal lifecycle"
        : "Workflow safety stop";
    elements.outcomeTitle.textContent = ownedQuarantined
      ? "OWNED · QUARANTINED"
      : enrollmentReady
        ? "ENROLLMENT-READY · SIMULATION"
        : outcome?.title?.toUpperCase() || "WORKFLOW STOPPED";
    elements.outcomeDescription.textContent = outcome?.message || (ownedQuarantined
      ? "The modeled irreversible boundary was crossed, but a required postcondition failed. This target can never re-enter the fresh-device path."
      : enrollmentReady
        ? "Every modeled gate and evidence check passed. This demo cannot enroll or create a device credential."
        : "No modeled irreversible operation occurred. Review the evidence before resetting the simulation.");
  }

  function actionButtonClass(action, presentation) {
    if (action === "reset" || action === "export_redacted") return "button-secondary";
    if (presentation?.point_of_no_return === true) return "button-commit";
    const classification = normalized(presentation?.classification);
    if (["dangerous", "destructive", "quarantine", "failure", "irreversible"].includes(classification)
      || action === "confirm_boot_failed") return "button-danger";
    return "button-primary";
  }

  function renderActions(state) {
    const actions = state.allowed_actions.filter((action) => !action.startsWith("select_scenario:"));
    elements.actionButtons.replaceChildren();
    if (actions.length === 0) {
      const message = document.createElement("p");
      message.textContent = requestInFlight ? "Waiting for the station…" : "No simulated operator action is authorized in this phase.";
      elements.actionButtons.append(message);
    } else {
      for (const action of actions) {
        const presentation = presentationFor(state, action);
        const card = document.createElement("div");
        card.className = "action-card";
        const button = document.createElement("button");
        button.type = "button";
        button.className = `button ${actionButtonClass(action, presentation)}`;
        button.textContent = armedAction === action ? `Confirm: ${presentation.label}` : presentation.label;
        button.disabled = requestInFlight;
        button.setAttribute("aria-describedby", `action-meta-${state.revision}-${action.replaceAll(":", "-")}`);
        button.addEventListener("click", () => submitAction(action));
        const metadata = document.createElement("div");
        metadata.className = "action-meta";
        metadata.id = `action-meta-${state.revision}-${action.replaceAll(":", "-")}`;
        const description = document.createElement("span");
        description.textContent = presentation.description;
        const classification = document.createElement("span");
        classification.textContent = presentation.classification;
        if (presentation.point_of_no_return || presentation.classification === "irreversible") {
          classification.classList.add("is-dangerous");
        }
        metadata.append(description, classification);
        if (presentation.requires_confirmation) {
          const confirmation = document.createElement("span");
          confirmation.textContent = presentation.point_of_no_return ? "one-shot · point of no return" : "confirmation required";
          if (presentation.point_of_no_return) confirmation.classList.add("is-dangerous");
          metadata.append(confirmation);
        }
        card.append(button, metadata);
        elements.actionButtons.append(card);
      }
    }
    if (armedAction === null) elements.actionHelp.textContent = "Only actions authorized for this exact state revision are available.";
  }

  function scenarioDefinitions(state) {
    if (!Array.isArray(state.scenarios)) return [];
    return state.scenarios
      .filter((scenario) => isObject(scenario) && typeof scenario.action === "string")
      .map((scenario) => ({ action: scenario.action, label: scenario.label || titleCase(scenario.id) }));
  }

  function renderScenarios(state) {
    const scenarios = scenarioDefinitions(state);
    elements.developerPanel.hidden = scenarios.length === 0;
    elements.scenarioButtons.replaceChildren(...scenarios.map(({ action, label }) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button button-secondary";
      button.textContent = label;
      button.disabled = requestInFlight;
      button.setAttribute("aria-pressed", String(normalized(state.scenario) === normalized(action.replace(/^select_scenario:/, ""))));
      button.addEventListener("click", () => submitAction(action));
      return button;
    }));
  }

  function renderExport(record) {
    elements.exportPanel.hidden = !record;
    if (!record) {
      elements.exportRecord.textContent = "";
      revokeExportURL();
      return;
    }
    const text = `${JSON.stringify(record, null, 2)}\n`;
    elements.exportRecord.textContent = text;
    revokeExportURL();
    exportURL = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  }

  function revokeExportURL() {
    if (exportURL) URL.revokeObjectURL(exportURL);
    exportURL = null;
  }

  function downloadExport() {
    if (!exportURL) return;
    const link = document.createElement("a");
    link.href = exportURL;
    link.download = `kaiba-secure-boot-simulation-r${currentState?.revision ?? "unknown"}.json`;
    document.body.append(link);
    link.click();
    link.remove();
  }

  async function initialize({ focus = false } = {}) {
    if (initializationInFlight) return;
    initializationInFlight = true;
    try {
      if (!window.KaibaStationTransport || typeof window.KaibaStationTransport.create !== "function") {
        throw new Error("The station transport runtime is unavailable.");
      }
      transport = await window.KaibaStationTransport.create();
      await refreshState({ announce: true, focus });
    } catch (error) {
      transport = null;
      showError(error.name === "AbortError" ? "The station did not respond before the request deadline." : error.message);
    } finally {
      initializationInFlight = false;
    }
  }

  elements.retryState.addEventListener("click", () => initialize({ focus: true }));
  elements.downloadExport.addEventListener("click", downloadExport);
  window.addEventListener("beforeunload", revokeExportURL);
  window.setInterval(() => {
    if (transport && !document.hidden && !requestInFlight) refreshState({ announce: true });
  }, pollIntervalMs);

  initialize();
})();
