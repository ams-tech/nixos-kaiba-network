"use strict";

(() => {
  const runtimeConfigURL = "./runtime-config.json";
  const runtimeConfigSchema = "provisioning.kaiba.network/station-demo-runtime/v1alpha1";
  const transitionGraphSchema = "provisioning.kaiba.network/station-demo-transition-graph/v1alpha1";
  const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha2";
  const exportSchema = "provisioning.kaiba.network/station-demo-export/v1alpha2";
  const requestTimeoutMs = 12000;
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
    "admission", "transaction", "qualification", "preparation", "approval", "initial_trust",
    "ownership_commit", "owned_verification", "finalization", "audit_reconciliation",
  ];
  const actionClassifications = new Set(["administrative", "read_only", "reversible", "authorization_affecting", "irreversible"]);
  const transactionStatuses = new Set(["created", "target_bound", "preflight_passed", "commit_approved", "trust_established", "security_applied", "aborted", "quarantined"]);
  const lifecycleStates = new Set(["unregistered", "qualified_fresh_candidate", "prepared", "commit_in_progress", "security_applied", "enrollment_ready", "owned_quarantined"]);
  const evidenceStatuses = new Set(["pending", "passed", "failed", "recorded"]);
  const outcomeStatuses = new Set(["aborted", "owned_quarantined", "enrollment_ready"]);
  const requiredOperatorActions = new Set([
    "run_station_admission", "create_transaction", "attach_target", "run_first_probe", "disconnect_target",
    "reconnect_target", "run_second_probe", "confirm_boot_ok", "confirm_boot_failed", "prepare_transaction",
    "close_deferred_baseline",
    "request_commit_approval", "establish_initial_trust", "record_commit_intent", "execute_commit",
    "reidentify_commit_target",
    "observe_commit_readback", "power_off_owned_target", "confirm_signed_boot", "run_owned_readback",
    "test_owned_recovery", "rerun_owned_readback", "test_negative_boot", "test_root_integrity", "test_rollback",
    "request_finalization_approval", "record_finalization_intent", "apply_final_controls",
    "cold_restart_finalized_target", "observe_final_controls_readback",
    "run_final_retest", "reconcile_audit", "mark_enrollment_ready", "export_redacted", "reset",
  ]);
  const forbiddenSecretKeys = new Set([
    "private_key",
    "private_key_pem",
    "signing_key",
    "shared_secret",
    "enrollment_secret",
    "password",
    "credential",
    "access_token",
  ]);

  function runtimeError(message, status = 0, code = "runtime_error") {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
  }

  function exactKeys(value, expected, label) {
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
      throw runtimeError(`${label} has unsupported or missing fields.`);
    }
  }

  function objectValue(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw runtimeError(`${label} must be an object.`);
    }
    return value;
  }

  function stringValue(value, label, { empty = false } = {}) {
    if (typeof value !== "string" || (!empty && value.length === 0)) {
      throw runtimeError(`${label} must be a string.`);
    }
    return value;
  }

  function relativeSameOriginURL(value, label) {
    if (typeof value !== "string" || !value.startsWith("./") || value.includes("\\")) {
      throw runtimeError(`${label} must be an explicit path-relative URL.`);
    }
    const resolved = new URL(value, document.baseURI);
    const baseDirectory = new URL("./", document.baseURI);
    if (resolved.origin !== window.location.origin || resolved.username || resolved.password
      || !resolved.pathname.startsWith(baseDirectory.pathname) || resolved.search || resolved.hash) {
      throw runtimeError(`${label} must stay within the interface directory.`);
    }
    return resolved.href;
  }

  async function fetchJSON(url, options = {}) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetch(url, {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json", ...(options.headers || {}) },
        redirect: "error",
        ...options,
        signal: controller.signal,
      });
      if (!response.ok) {
        const body = (await response.text()).slice(0, 4096).trim();
        let detail = body;
        try {
          const problem = JSON.parse(body);
          detail = problem.detail || problem.title || body;
        } catch {
          // A non-JSON error body is still useful as a bounded diagnostic.
        }
        throw runtimeError(detail || `Station request failed with status ${response.status}.`, response.status, "request_failed");
      }
      try {
        return await response.json();
      } catch {
        throw runtimeError("Station returned malformed JSON.", 0, "malformed_response");
      }
    } finally {
      window.clearTimeout(timer);
    }
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function normalized(value) {
    return String(value ?? "").trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
  }

  function requireSafety(value, label) {
    const safety = objectValue(value, label);
    exactKeys(safety, [
      "simulation",
      "mutation_eligible",
      "full_unprovisioned_state",
      "live_target_access",
      "live_mutation_capable",
      "authoritative_evidence",
      "secrets_present",
      "approval_authority",
      "signing_capable",
      "enrollment_capable",
      "disclaimer",
    ], label);
    if (safety.simulation !== true || safety.full_unprovisioned_state !== "not_established") {
      throw runtimeError(`${label} violates the simulation safety boundary.`);
    }
    for (const field of falseSafetyCapabilities) {
      if (safety[field] !== false) throw runtimeError(`${label} did not deny ${field}.`);
    }
    stringValue(safety.disclaimer, `${label} disclaimer`);
    return safety;
  }

  function requireSecretFree(value, label, seen = new Set()) {
    if (!value || typeof value !== "object") {
      if (typeof value === "string" && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) {
        throw runtimeError(`${label} contains private key material.`);
      }
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    for (const [key, nested] of Object.entries(value)) {
      if (forbiddenSecretKeys.has(normalized(key))) {
        throw runtimeError(`${label} contains forbidden secret field ${key}.`);
      }
      requireSecretFree(nested, label, seen);
    }
  }

  function requireTransaction(value, label, { allowEmptyStatus = false } = {}) {
    const transaction = objectValue(value, label);
    exactKeys(transaction, [
      "id", "status", "asset_id", "intended_logical_id", "claim_id", "fence_epoch", "operator_id",
      "approver_id", "target_fingerprint", "digest", "plan_digest", "approval_id", "intent_receipt",
      "finalization_approval_id", "finalization_intent_receipt", "irreversible_boundary_crossed",
      "commit_executions", "final_control_executions",
    ], label);
    for (const field of [
      "id", "status", "asset_id", "intended_logical_id", "claim_id", "operator_id", "approver_id",
      "target_fingerprint", "digest", "plan_digest", "approval_id", "intent_receipt",
      "finalization_approval_id", "finalization_intent_receipt",
    ]) stringValue(transaction[field], `${label} ${field}`, { empty: true });
    if ((!allowEmptyStatus || transaction.status !== "") && !transactionStatuses.has(transaction.status)) {
      throw runtimeError(`${label} has an unsupported status.`);
    }
    if (!Number.isSafeInteger(transaction.fence_epoch) || transaction.fence_epoch < 0
      || !Number.isSafeInteger(transaction.commit_executions) || transaction.commit_executions < 0
      || !Number.isSafeInteger(transaction.final_control_executions) || transaction.final_control_executions < 0
      || typeof transaction.irreversible_boundary_crossed !== "boolean") {
      throw runtimeError(`${label} has malformed irreversible transaction state.`);
    }
    if (transaction.commit_executions > 1) throw runtimeError(`${label} repeated the one-shot modeled commit.`);
    if (transaction.final_control_executions > 1) throw runtimeError(`${label} repeated the one-shot modeled final controls.`);
    if (transaction.commit_executions === 1 && transaction.irreversible_boundary_crossed !== true) {
      throw runtimeError(`${label} lost the irreversible-boundary marker.`);
    }
    if (transaction.commit_executions === 1 && (!transaction.approval_id || !transaction.intent_receipt)) {
      throw runtimeError(`${label} lost commit approval or intent evidence.`);
    }
    if (transaction.final_control_executions === 1
      && (transaction.commit_executions !== 1
        || transaction.irreversible_boundary_crossed !== true
        || !transaction.finalization_approval_id
        || !transaction.finalization_intent_receipt)) {
      throw runtimeError(`${label} lost the commit boundary or finalization approval and intent evidence.`);
    }
    return transaction;
  }

  function requireManifest(value, label) {
    const manifest = objectValue(value, label);
    const fields = [
      "id", "digest", "profile_id", "profile_digest", "adapter_id", "adapter_digest",
      "expected_customer_key_hash", "eeprom_image_digest", "boot_image_digest", "boot_signature_digest",
      "root_integrity_digest", "fresh_commit_bundle_digest", "owned_recovery_bundle_digest", "boot_order",
      "rollback_policy", "debug_policy", "eeprom_write_protection_policy", "signer_id",
      "signing_tool_version", "verification_status",
    ];
    exactKeys(manifest, fields, label);
    for (const field of fields) stringValue(manifest[field], `${label} ${field}`, { empty: true });
    return manifest;
  }

  function requireEvidence(value, label) {
    if (!Array.isArray(value)) throw runtimeError(`${label} must be an array.`);
    const ids = new Set();
    for (const entryValue of value) {
      const entry = objectValue(entryValue, `${label} entry`);
      exactKeys(entry, ["id", "label", "stage", "status", "digest", "detail"], `${label} entry`);
      for (const field of ["id", "label", "stage", "status"]) stringValue(entry[field], `${label} ${field}`);
      for (const field of ["digest", "detail"]) stringValue(entry[field], `${label} ${field}`, { empty: true });
      if (!evidenceStatuses.has(entry.status)) throw runtimeError(`${label} has an unsupported evidence status.`);
      if (ids.has(entry.id)) throw runtimeError(`${label} contains duplicate ids.`);
      ids.add(entry.id);
    }
    return value;
  }

  function requireExport(value, label) {
    const record = objectValue(value, label);
    exactKeys(record, [
      "schema_version", "simulation", "secret_free", "scenario", "station_id", "lane_id", "lifecycle",
      "transaction", "manifest", "evidence", "outcome", "safety",
    ], label);
    if (record.schema_version !== exportSchema || record.simulation !== true || record.secret_free !== true) {
      throw runtimeError(`${label} is not a compatible secret-free simulation export.`);
    }
    if (!lifecycleStates.has(record.lifecycle)) throw runtimeError(`${label} has an unsupported lifecycle.`);
    requireTransaction(record.transaction, `${label} transaction`, { allowEmptyStatus: true });
    requireManifest(record.manifest, `${label} manifest`);
    requireEvidence(record.evidence, `${label} evidence`);
    const outcome = objectValue(record.outcome, `${label} outcome`);
    exactKeys(outcome, ["status", "title", "message"], `${label} outcome`);
    for (const field of ["status", "title", "message"]) stringValue(outcome[field], `${label} outcome ${field}`, { empty: true });
    if (outcome.status !== "" && !outcomeStatuses.has(outcome.status)) throw runtimeError(`${label} has an unsupported outcome.`);
    requireSafety(record.safety, `${label} safety`);
    requireSecretFree(record, label);
    return record;
  }

  function requireSimulationState(value, label, revision) {
    const state = objectValue(value, label);
    if (state.schema_version !== stateSchema || state.simulation !== true) {
      throw runtimeError(`${label} is not a compatible simulation state.`);
    }
    if (revision === undefined) {
      if (!Number.isSafeInteger(state.revision) || state.revision < 1) throw runtimeError(`${label} has an invalid revision.`);
    } else if (state.revision !== revision) {
      throw runtimeError(`${label} has an unexpected revision.`);
    }
    stringValue(state.phase, `${label} phase`);
    if (!lifecycleStates.has(state.lifecycle)) throw runtimeError(`${label} has an unsupported lifecycle.`);
    requireSafety(state.safety, `${label} safety`);
    if (!Array.isArray(state.allowed_actions) || new Set(state.allowed_actions).size !== state.allowed_actions.length
      || !state.allowed_actions.every((action) => typeof action === "string" && action.length > 0)) {
      throw runtimeError(`${label} has invalid allowed actions.`);
    }
    if (!Array.isArray(state.scenarios)) throw runtimeError(`${label} has invalid simulation scenarios.`);
    const scenarioActions = new Set();
    for (const value of state.scenarios) {
      const scenario = objectValue(value, `${label} simulation scenario`);
      exactKeys(scenario, ["id", "label", "action"], `${label} simulation scenario`);
      for (const field of ["id", "label", "action"]) stringValue(scenario[field], `${label} scenario ${field}`);
      if (!scenario.action.startsWith("select_scenario:") || scenarioActions.has(scenario.action)) {
        throw runtimeError(`${label} has malformed simulation scenario actions.`);
      }
      scenarioActions.add(scenario.action);
    }
    const allowedScenarioActions = state.allowed_actions.filter((action) => action.startsWith("select_scenario:"));
    if (scenarioActions.size !== allowedScenarioActions.length
      || allowedScenarioActions.some((action) => !scenarioActions.has(action))
      || (state.phase !== "station_admission" && state.scenarios.length !== 0)) {
      throw runtimeError(`${label} exposes scenarios outside the admission phase.`);
    }

    if (!Array.isArray(state.workflow_stages) || state.workflow_stages.length === 0) {
      throw runtimeError(`${label} has no typed workflow stages.`);
    }
    if (state.workflow_stages.length !== workflowStageIDs.length
      || state.workflow_stages.some((stage, index) => stage?.id !== workflowStageIDs[index])) {
      throw runtimeError(`${label} does not expose the complete ordered secure-boot workflow.`);
    }
    const stageIDs = new Set();
    let currentStages = 0;
    for (const stageValue of state.workflow_stages) {
      const stage = objectValue(stageValue, `${label} workflow stage`);
      exactKeys(stage, ["id", "label", "status"], `${label} workflow stage`);
      stringValue(stage.id, `${label} workflow stage id`);
      stringValue(stage.label, `${label} workflow stage label`);
      if (!workflowStageStatuses.has(stage.status)) throw runtimeError(`${label} has an unsupported workflow stage status.`);
      if (stageIDs.has(stage.id)) throw runtimeError(`${label} has duplicate workflow stage ids.`);
      stageIDs.add(stage.id);
      if (stage.status === "current") currentStages += 1;
    }
    if (currentStages > 1) throw runtimeError(`${label} has multiple current workflow stages.`);

    if (!Array.isArray(state.action_presentations)) throw runtimeError(`${label} has no typed action metadata.`);
    const presentationActions = new Set();
    for (const value of state.action_presentations) {
      const presentation = objectValue(value, `${label} action presentation`);
      exactKeys(presentation, [
        "action", "label", "description", "classification", "requires_confirmation", "point_of_no_return",
      ], `${label} action presentation`);
      for (const field of ["action", "label", "description"]) stringValue(presentation[field], `${label} action presentation ${field}`);
      if (!actionClassifications.has(presentation.classification)
        || typeof presentation.requires_confirmation !== "boolean"
        || typeof presentation.point_of_no_return !== "boolean") {
        throw runtimeError(`${label} contains malformed action classification metadata.`);
      }
      if (presentation.classification === "irreversible" && presentation.requires_confirmation !== true) {
        throw runtimeError(`${label} exposes an irreversible action without confirmation.`);
      }
      if (presentation.point_of_no_return !== (presentation.action === "execute_commit")
        || (presentation.point_of_no_return
          && (presentation.classification !== "irreversible" || presentation.requires_confirmation !== true))) {
        throw runtimeError(`${label} weakens point-of-no-return confirmation metadata.`);
      }
      if (presentationActions.has(presentation.action)) throw runtimeError(`${label} has duplicate action presentations.`);
      presentationActions.add(presentation.action);
    }
    const normalActions = state.allowed_actions.filter((action) => !action.startsWith("select_scenario:"));
    if (presentationActions.size !== normalActions.length
      || normalActions.some((action) => !presentationActions.has(action))) {
      throw runtimeError(`${label} action presentations do not exactly cover operator actions.`);
    }

    if (state.transaction !== undefined && state.transaction !== null) requireTransaction(state.transaction, `${label} transaction`);
    if (state.manifest !== undefined && state.manifest !== null) requireManifest(state.manifest, `${label} manifest`);
    requireEvidence(state.evidence, `${label} evidence`);
    for (const probe of Array.isArray(state.probes) ? state.probes : []) {
      if (!probe || typeof probe !== "object" || !probe.assessment
        || probe.assessment.mutation_eligible !== false
        || probe.assessment.full_unprovisioned_state !== "not_established") {
        throw runtimeError(`${label} contains an unsafe probe assessment.`);
      }
    }
    if (state.export_record !== undefined && state.export_record !== null) requireExport(state.export_record, `${label} export`);
    requireSecretFree(state, label);
    return state;
  }

  function validateTransitionGraph(value) {
    const graph = objectValue(value, "Transition graph");
    exactKeys(graph, ["schema_version", "state_schema_version", "default_node", "nodes"], "Transition graph");
    if (graph.schema_version !== transitionGraphSchema || graph.state_schema_version !== stateSchema) {
      throw runtimeError("Transition graph has an unsupported schema.");
    }
    const nodes = objectValue(graph.nodes, "Transition graph nodes");
    const nodeIDs = Object.keys(nodes);
    if (nodeIDs.length === 0 || nodeIDs.length > 512 || !nodes[graph.default_node]) {
      throw runtimeError("Transition graph has an invalid default node or size.");
    }
    const graphActions = new Set();
    for (const nodeID of nodeIDs) {
      if (!/^sha256:[0-9a-f]{64}$/.test(nodeID)) throw runtimeError("Transition graph contains a malformed node identifier.");
      const node = objectValue(nodes[nodeID], `Transition node ${nodeID}`);
      exactKeys(node, ["state", "transitions"], `Transition node ${nodeID}`);
      const state = requireSimulationState(node.state, `Transition node ${nodeID}`, 0);
      const transitions = objectValue(node.transitions, `Transitions for ${nodeID}`);
      const actions = Object.keys(transitions);
      for (const action of actions) {
        if (!action.startsWith("select_scenario:")) graphActions.add(action);
      }
      if (actions.length !== state.allowed_actions.length || actions.some((action) => !state.allowed_actions.includes(action))) {
        throw runtimeError(`Transition node ${nodeID} does not exactly cover its allowed actions.`);
      }
      for (const targetID of Object.values(transitions)) {
        if (typeof targetID !== "string" || !nodes[targetID]) throw runtimeError(`Transition node ${nodeID} references an unknown target.`);
      }
    }
    const missingActions = [...requiredOperatorActions].filter((action) => !graphActions.has(action));
    if (missingActions.length > 0) throw runtimeError("Transition graph omits required secure-boot workflow actions.");
    return graph;
  }

  function createHTTPClient(config) {
    const stateURL = relativeSameOriginURL(config.state_url, "HTTP state URL");
    const actionURL = relativeSameOriginURL(config.action_url, "HTTP action URL");
    return Object.freeze({
      mode: "http",
      getState: async () => requireSimulationState(await fetchJSON(stateURL), "HTTP station state"),
      applyAction: async (request) => requireSimulationState(await fetchJSON(actionURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      }), "HTTP action state"),
    });
  }

  function createTransitionGraphClient(graph) {
    let currentNodeID = graph.default_node;
    let revision = 1;

    function snapshot() {
      const state = clone(graph.nodes[currentNodeID].state);
      state.revision = revision;
      return requireSimulationState(state, "Browser simulation state", revision);
    }

    return Object.freeze({
      mode: "transition-graph",
      getState: async () => snapshot(),
      applyAction: async (request) => {
        objectValue(request, "Action request");
        exactKeys(request, ["action", "expected_revision"], "Action request");
        if (!Number.isSafeInteger(request.expected_revision) || request.expected_revision < 1
          || request.expected_revision !== revision) {
          throw runtimeError("Reload authoritative state before attempting another action.", 409, "stale_revision");
        }
        const targetID = graph.nodes[currentNodeID].transitions[request.action];
        if (typeof request.action !== "string" || !targetID) {
          throw runtimeError("The action is not allowed in the authoritative workflow phase.", 409, "action_not_allowed");
        }
        currentNodeID = targetID;
        revision += 1;
        return snapshot();
      },
    });
  }

  async function create() {
    const config = objectValue(
      await fetchJSON(relativeSameOriginURL(runtimeConfigURL, "Runtime configuration URL")),
      "Runtime configuration",
    );
    if (config.schema_version !== runtimeConfigSchema) throw runtimeError("Runtime configuration has an unsupported schema.");
    if (config.mode === "http") {
      exactKeys(config, ["schema_version", "mode", "state_url", "action_url"], "HTTP runtime configuration");
      return createHTTPClient(config);
    }
    if (config.mode === "transition-graph") {
      exactKeys(config, ["schema_version", "mode", "graph_url"], "Pages runtime configuration");
      const graph = validateTransitionGraph(await fetchJSON(relativeSameOriginURL(config.graph_url, "Transition graph URL")));
      return createTransitionGraphClient(graph);
    }
    throw runtimeError("Runtime configuration selected an unsupported transport mode.");
  }

  window.KaibaStationTransport = Object.freeze({ create });
})();
