"use strict";

(() => {
  const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha1";
  const pollIntervalMs = 2500;

  const elements = {
    stationId: document.querySelector("#station-id"),
    laneId: document.querySelector("#lane-id"),
    stationStatus: document.querySelector("#station-status"),
    laneStatus: document.querySelector("#lane-status"),
    targetStatus: document.querySelector("#target-status"),
    stationDot: document.querySelector("#station-dot"),
    laneDot: document.querySelector("#lane-dot"),
    targetDot: document.querySelector("#target-dot"),
    phaseCode: document.querySelector("#phase-code"),
    phaseTitle: document.querySelector("#phase-title"),
    phaseInstruction: document.querySelector("#phase-instruction"),
    announcement: document.querySelector("#workflow-announcement"),
    connectionAlert: document.querySelector("#connection-alert"),
    connectionMessage: document.querySelector("#connection-message"),
    retryState: document.querySelector("#retry-state"),
    steps: [...document.querySelectorAll("#ceremony-steps li")],
    laneBinding: document.querySelector("#lane-binding"),
    workKicker: document.querySelector("#work-kicker"),
    workTitle: document.querySelector("#work-title"),
    profileBadge: document.querySelector("#profile-badge"),
    targetEmpty: document.querySelector("#target-empty"),
    targetSummary: document.querySelector("#target-summary"),
    targetModel: document.querySelector("#target-model"),
    targetClassStatus: document.querySelector("#target-class-status"),
    targetFacts: document.querySelector("#target-facts"),
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

  const actionLabels = {
    attach_target: "Attach mock target",
    run_first_probe: "Run metadata probe 1",
    disconnect_target: "Simulate full power removal",
    reconnect_target: "Reconnect same target",
    run_second_probe: "Run metadata probe 2",
    confirm_boot_ok: "Booted normally",
    confirm_boot_failed: "Did not boot normally",
    quarantine: "Quarantine target",
    export_redacted: "Prepare redacted record",
    reset: "Reset station",
  };

  const phasePresentation = {
    ready: ["Station ready", "Attach one mock target"],
    awaiting_target: ["Station ready", "Attach one mock target"],
    target_detected: ["Target detected", "Review the lane binding"],
    ready_for_first_probe: ["Target detected", "Review and run probe 1"],
    first_probe_running: ["Probe 1 running", "Reading volatile metadata"],
    first_probe_complete: ["First observation complete", "Remove all target power"],
    power_cycle_required: ["Power removal required", "Disconnect every target power source"],
    awaiting_disconnect: ["Power removal required", "Disconnect every target power source"],
    target_disconnected: ["Target absent", "Reconnect the same target"],
    awaiting_reconnect: ["Target absent", "Reconnect the same target"],
    second_probe_ready: ["Target reconnected", "Run the second observation"],
    ready_for_second_probe: ["Target reconnected", "Run the second observation"],
    second_probe_running: ["Probe 2 running", "Comparing stable evidence"],
    second_probe_complete: ["Observations compared", "Review the stability result"],
    awaiting_boot_confirmation: ["Normal boot check", "Record the operator observation"],
    complete: ["Qualification complete", "Review and export the result"],
    qualified: ["Qualification complete", "Review and export the result"],
    stopped: ["Probe stopped", "Review the evidence before resetting"],
    quarantined: ["Target quarantined", "Export evidence for review"],
  };

  let currentState = null;
  let transport = null;
  let initializationInFlight = false;
  let requestInFlight = false;
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

  function statusClass(value) {
    const status = normalized(value);
    if (["ready", "connected", "detected", "pass", "passed", "match", "matched", "qualified", "complete"].includes(status)) return "is-ready";
    if (["failed", "fail", "error", "fenced", "quarantined", "changed", "mismatch"].includes(status)) return "is-error";
    if (["warning", "waiting", "absent", "disconnected", "indeterminate", "pending"].includes(status)) return "is-warning";
    return "";
  }

  function setDot(element, value) {
    element.className = `status-dot ${statusClass(value)}`.trim();
  }

  function ensureMockState(state) {
    if (!state || typeof state !== "object" || Array.isArray(state)) throw new Error("Station returned an invalid state object.");
    if (state.schema_version !== stateSchema || state.simulation !== true) throw new Error("This interface refuses incompatible or non-simulation station state.");
    if (!Number.isSafeInteger(state.revision) || state.revision < 1) throw new Error("Station state has an invalid revision.");
    if (!Array.isArray(state.allowed_actions) || new Set(state.allowed_actions).size !== state.allowed_actions.length
      || !state.allowed_actions.every((action) => typeof action === "string" && action.length > 0)) {
      throw new Error("Station state has invalid allowed actions.");
    }
    if (!state.safety || state.safety.simulation !== true || state.safety.mutation_eligible !== false
      || state.safety.full_unprovisioned_state !== "not_established") {
      throw new Error("Station did not affirm that persistent mutation is blocked.");
    }
    for (const probe of Array.isArray(state.probes) ? state.probes : []) {
      if (!probe || typeof probe !== "object" || !probe.assessment
        || probe.assessment.mutation_eligible !== false
        || probe.assessment.full_unprovisioned_state !== "not_established") {
        throw new Error("Station returned an unsafe probe assessment.");
      }
    }
    if (state.export_record && (state.export_record.simulation !== true
      || state.export_record.mutation_eligible !== false
      || state.export_record.full_unprovisioned_state !== "not_established")) {
      throw new Error("Station returned an unsafe export record.");
    }
    return state;
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
    requestInFlight = true;
    setActionBusy(action);
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
          // Keep the conflict message visible; the periodic state read will retry.
        }
        showError("Station state changed before that action was accepted. Review the refreshed phase before continuing.");
      } else {
        showError(error.name === "AbortError" ? "The action did not complete before the request deadline. Station state is uncertain; refresh before retrying." : error.message);
      }
    } finally {
      requestInFlight = false;
      if (currentState) renderActions(currentState.allowed_actions);
    }
  }

  function actionIsExposed(state, action) {
    return state.allowed_actions.includes(action)
      || (Array.isArray(state.scenarios) && state.scenarios.some((scenario) => scenario?.action === action));
  }

  function setActionBusy(action) {
    for (const button of elements.actionButtons.querySelectorAll("button")) button.disabled = true;
    for (const button of elements.scenarioButtons.querySelectorAll("button")) button.disabled = true;
    elements.actionHelp.textContent = `${actionLabels[action] || titleCase(action)} is being applied by the mock station…`;
  }

  function announceState(state) {
    const presentation = phasePresentation[normalized(state.phase)] || [titleCase(state.phase), "State updated"];
    elements.announcement.textContent = `${presentation[0]}. ${state.instruction || presentation[1]}`;
  }

  function phaseProgress(state) {
    const probeCount = Array.isArray(state.probes) ? state.probes.length : 0;
    const firstProbe = probeCount > 0 ? state.probes[0] : null;
    const secondProbe = probeCount > 1 ? state.probes[1] : null;
    const phase = normalized(state.phase);
    const hasTarget = Boolean(state.target);
    let current = "attach";
    const complete = new Set();
    const failed = new Set();

    if (hasTarget || probeCount > 0) {
      complete.add("attach");
      current = "probe-one";
    }
    if (probeCount >= 1) {
      if (normalized(firstProbe.status) === "failed" || normalized(firstProbe.device_class_status) === "fail" || normalized(firstProbe.observable_baseline_status) === "fail") {
        failed.add("probe-one");
        current = null;
      } else {
        complete.add("probe-one");
        current = "power-cycle";
      }
    }
    if (["second_probe_ready", "ready_for_second_probe", "second_probe_running", "second_probe_complete", "awaiting_normal_boot_confirmation", "awaiting_boot_confirmation", "complete", "qualified", "quarantined"].includes(phase) || probeCount >= 2) {
      complete.add("power-cycle");
      current = "probe-two";
    }
    if (probeCount >= 2 || ["awaiting_normal_boot_confirmation", "awaiting_boot_confirmation", "complete", "qualified", "quarantined"].includes(phase)) {
      if (normalized(secondProbe?.status) === "failed" || state.comparison?.some((item) => normalized(item.status) !== "match")) {
        failed.add("probe-two");
        current = null;
      } else {
        complete.add("probe-two");
        current = "boot";
      }
    }
    if (["complete", "qualified"].includes(phase)) complete.add("boot");
    if (phase === "quarantined" && state.outcome?.title === "Normal boot failed") failed.add("boot");
    if (phase === "stopped" || phase === "quarantined") current = null;
    return { complete, failed, current };
  }

  function render(state) {
    const station = state.station || {};
    const lane = state.lane || {};
    const phase = normalized(state.phase);
    const presentation = phasePresentation[phase] || [titleCase(state.phase), "Follow the station instruction"];

    elements.stationId.textContent = station.id || "Unknown station";
    elements.laneId.textContent = lane.id || "No lane";
    elements.stationStatus.textContent = titleCase(station.status || "unknown");
    elements.laneStatus.textContent = titleCase(lane.status || "unknown");
    elements.targetStatus.textContent = state.target ? "Detected" : titleCase(lane.target_status || "not detected");
    setDot(elements.stationDot, station.status);
    setDot(elements.laneDot, lane.status);
    setDot(elements.targetDot, state.target ? "detected" : lane.target_status || lane.status);

    elements.phaseCode.textContent = String(state.phase || "station state").replaceAll("_", " ").toUpperCase();
    elements.phaseTitle.textContent = presentation[0];
    elements.phaseInstruction.textContent = state.instruction || presentation[1];
    elements.laneBinding.textContent = lane.usb_path ? `${lane.id || "lane"} · USB ${lane.usb_path}` : `${lane.id || "lane"} · no target path`;
    elements.revisionLabel.textContent = `State r${state.revision}`;
    elements.profileBadge.textContent = `${titleCase(state.target?.profile_status || state.profile?.status || "experimental")} profile`;

    const progress = phaseProgress(state);
    for (const step of elements.steps) {
      const id = step.dataset.step;
      step.classList.toggle("is-complete", progress.complete.has(id));
      step.classList.toggle("is-failed", progress.failed.has(id));
      step.classList.toggle("is-current", !progress.complete.has(id) && progress.current === id);
      if (!progress.complete.has(id) && progress.current === id) step.setAttribute("aria-current", "step");
      else step.removeAttribute("aria-current");
    }

    renderTarget(state);
    renderAssessment(state);
    renderComparison(state.comparison);
    renderOutcome(state.outcome, phase);
    renderActions(state.allowed_actions);
    renderScenarios(state);
    renderExport(state.export_record);
  }

  function renderTarget(state) {
    const target = state.target;
    elements.targetEmpty.hidden = Boolean(target);
    elements.targetSummary.hidden = !target;
    if (!target) {
      elements.workKicker.textContent = "Current evidence";
      elements.workTitle.textContent = "Awaiting target observation";
      return;
    }

    const observation = target.observation || target;
    elements.workKicker.textContent = "Lane-bound candidate";
    elements.workTitle.textContent = "Review the observed target";
    elements.targetModel.textContent = observation.model || observation.device_model || "Raspberry Pi 5 Model B";
    const latestProbe = Array.isArray(state.probes) && state.probes.length > 0 ? state.probes[state.probes.length - 1] : null;
    const classStatus = latestProbe?.device_class_status || observation.class_status || target.class_status || "observed";
    elements.targetClassStatus.textContent = titleCase(classStatus);
    elements.targetClassStatus.className = `result-chip ${normalized(classStatus) === "pass" ? "result-pass" : normalized(classStatus) === "fail" ? "result-fail" : "result-neutral"}`;

    const revision = observation.board_revision;
    const revisionText = revision && typeof revision === "object" ? revision.raw : revision;
    const facts = [
      ["Fingerprint", shorten(observation.target_fingerprint, 16, 10), observation.target_fingerprint],
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

  function latestAssessment(state) {
    if (Array.isArray(state.probes) && state.probes.length > 0) {
      const probe = state.probes[state.probes.length - 1];
      const nested = probe.assessment || probe.result?.assessment;
      if (nested) return { ...nested, findings: probe.findings };
      return {
        device_class: { status: probe.device_class_status },
        observable_baseline: { status: probe.observable_baseline_status },
        eligible_for_reversible_qualification: probe.eligible_for_reversible_qualification,
        findings: probe.findings,
      };
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
    elements.assessmentNote.textContent = firstFinding?.message || assessment.disclaimer || state.safety?.disclaimer || "Partial preflight evidence only; no authentication, attestation, or mutation authorization is established.";
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
    elements.comparisonBody.replaceChildren(...rows.map((item) => {
      const row = document.createElement("tr");
      const field = document.createElement("th");
      const result = document.createElement("td");
      field.scope = "row";
      field.textContent = item.label || titleCase(item.field || item.id || "observation");
      const status = normalized(item.status || (item.match === true ? "match" : item.match === false ? "changed" : "not observed"));
      result.textContent = status === "match" || status === "matched" ? "MATCH" : status === "changed" || status === "mismatch" ? "CHANGED" : titleCase(status);
      result.className = status === "match" || status === "matched" ? "comparison-match" : status === "changed" || status === "mismatch" ? "comparison-changed" : "comparison-missing";
      row.append(field, result);
      return row;
    }));
  }

  function renderOutcome(outcome, phase) {
    const present = Boolean(outcome) || ["complete", "qualified", "stopped", "quarantined"].includes(phase);
    elements.outcomePanel.hidden = !present;
    if (!present) return;
    const status = normalized(typeof outcome === "string" ? outcome : outcome?.status || phase);
    const quarantined = ["quarantine", "quarantined"].includes(status) || phase === "quarantined";
    const stopped = quarantined || ["stopped", "failed", "failure"].includes(status) || phase === "stopped";
    const passed = ["hardware_qualification_passed", "passed", "qualified", "complete"].includes(status) && !stopped;
    elements.outcomePanel.classList.toggle("is-quarantined", quarantined);
    elements.outcomePanel.classList.toggle("is-stopped", stopped && !quarantined);
    elements.outcomeLabel.textContent = stopped ? "Safety stop" : passed ? "Qualification ceremony" : "Station outcome";
    elements.outcomeTitle.textContent = typeof outcome === "object" && outcome.title
      ? outcome.title.toUpperCase()
      : quarantined
        ? "TARGET QUARANTINED"
        : stopped
          ? "PROBE STOPPED"
          : passed
            ? "HARDWARE QUALIFICATION PASSED"
            : titleCase(status).toUpperCase();
    elements.outcomeDescription.textContent = typeof outcome === "object" && (outcome.message || outcome.description)
      ? outcome.message || outcome.description
      : quarantined
        ? "Do not retry or release this target. Preserve and export the available evidence for review."
        : stopped
          ? "Review the evidence before resetting this simulation. Persistent provisioning remains unavailable."
          : "Both observations were stable and the operator reported a normal boot. Persistent provisioning remains disabled.";
  }

  function renderActions(actions) {
    const normal = actions.filter((action) => !action.startsWith("select_scenario"));
    elements.actionButtons.replaceChildren();
    if (normal.length === 0) {
      const message = document.createElement("p");
      message.textContent = requestInFlight ? "Waiting for the station…" : "No operator action is authorized in this phase.";
      elements.actionButtons.append(message);
    } else {
      for (const action of normal) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `button ${action === "confirm_boot_failed" || action === "quarantine" ? "button-danger" : action === "reset" || action === "export_redacted" ? "button-secondary" : "button-primary"}`;
        button.textContent = actionLabels[action] || titleCase(action);
        button.disabled = requestInFlight;
        button.addEventListener("click", () => submitAction(action));
        elements.actionButtons.append(button);
      }
    }
    elements.actionHelp.textContent = "Only actions authorized for this exact state revision are available.";
  }

  function scenarioDefinitions(state) {
    if (Array.isArray(state.scenarios)) {
      return state.scenarios
        .filter((scenario) => scenario && typeof scenario === "object" && typeof scenario.action === "string")
        .map((scenario) => ({ action: scenario.action, label: scenario.label || titleCase(scenario.id || scenario.action.replace(/^select_scenario[:_]/, "")) }));
    }
    return state.allowed_actions
      .filter((action) => action.startsWith("select_scenario"))
      .map((action) => ({ action, label: titleCase(action.replace(/^select_scenario[:_]/, "")) }));
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
      button.setAttribute("aria-pressed", String(normalized(state.scenario) === normalized(action.replace(/^select_scenario[:_]/, ""))));
      button.addEventListener("click", () => submitAction(action));
      return button;
    }));
  }

  function renderExport(record) {
    elements.exportPanel.hidden = record === undefined || record === null;
    if (elements.exportPanel.hidden) {
      elements.exportRecord.textContent = "";
      revokeExportURL();
      return;
    }
    const text = typeof record === "string" ? record : `${JSON.stringify(record, null, 2)}\n`;
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
    link.download = `kaiba-simulated-qualification-r${currentState?.revision ?? "unknown"}.json`;
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
