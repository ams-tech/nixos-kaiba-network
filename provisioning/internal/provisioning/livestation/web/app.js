(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.KaibaLiveStation = api;
  if (root.document) {
    root.addEventListener("DOMContentLoaded", function () {
      api.start(root).catch(function (error) {
        api.showFatal(root.document, error);
      });
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis, function () {
  "use strict";

  const RUNTIME_SCHEMA = "provisioning.kaiba.network/station-live-runtime/v1alpha1";
  const LIVE_STATE_SCHEMA = "provisioning.kaiba.network/station-live-state/v1alpha1";
  const ROLLBACK_STATUS = "rollback_unimplemented";
  const FORBIDDEN_ACTION = "mark_enrollment_ready";
  const SUPPORTED_ACTIONS = new Set([
    "run_station_admission",
    "create_transaction",
    "attach_target",
    "run_fresh_qualification",
    "prepare_transaction",
    "request_commit_approval",
    "record_commit_intent",
    "execute_commit",
    "reconcile_commit",
    "confirm_signed_boot",
    "run_owned_readback",
    "test_owned_recovery",
    "rerun_owned_readback",
    "test_negative_boot",
    "test_root_integrity",
    "reconcile_audit",
    "mark_security_applied",
    "export_redacted",
    "reset"
  ]);

  function fail(message) {
    throw new Error("Live station contract rejected: " + message);
  }

  function object(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(label + " must be an object");
    return value;
  }

  function text(value, label) {
    if (typeof value !== "string" || value.length === 0) fail(label + " must be a non-empty string");
    return value;
  }

  function exactKeys(value, expected, label) {
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    if (actual.length !== wanted.length || actual.some(function (key, index) { return key !== wanted[index]; })) {
      fail(label + " fields changed");
    }
  }

  function validateRuntimeConfig(value, browserOrigin) {
    const config = object(value, "runtime config");
    exactKeys(config, [
      "schema_version", "state_schema_version", "expected_origin", "state_endpoint",
      "action_endpoint", "simulation", "secret_free", "rollback_status", "enrollment_capable"
    ], "runtime config");
    if (config.schema_version !== RUNTIME_SCHEMA) fail("unsupported runtime schema");
    if (config.state_schema_version !== LIVE_STATE_SCHEMA) fail("unsupported live state schema");
    if (config.expected_origin !== browserOrigin) fail("browser origin does not match the station origin");
    if (config.state_endpoint !== "/api/v1/state" || config.action_endpoint !== "/api/v1/actions") {
      fail("runtime endpoints are not the fixed same-origin endpoints");
    }
    if (config.simulation !== false || config.secret_free !== true) fail("runtime is not live and secret-free");
    if (config.rollback_status !== ROLLBACK_STATUS) fail("rollback status is not explicitly unimplemented");
    if (config.enrollment_capable !== false) fail("runtime unexpectedly permits enrollment");
    return config;
  }

  function validateActionPresentation(value, action) {
    const presentation = object(value, "action presentation");
    if (presentation.action !== action) fail("action presentation does not match allowed action");
    text(presentation.label, "action label");
    text(presentation.description, "action description");
    text(presentation.classification, "action classification");
    if (typeof presentation.requires_confirmation !== "boolean" || typeof presentation.point_of_no_return !== "boolean") {
      fail("action confirmation metadata is invalid");
    }
    if (presentation.classification === "irreversible" && (!presentation.requires_confirmation || !presentation.point_of_no_return)) {
      fail("irreversible action lacks explicit confirmation metadata");
    }
    return presentation;
  }

  function validateState(value) {
    const state = object(value, "state");
    if (state.schema_version !== LIVE_STATE_SCHEMA) fail("unsupported state schema");
    if (!Number.isSafeInteger(state.revision) || state.revision < 1) fail("revision is not a positive safe integer");
    if (state.simulation !== false || state.secret_free !== true) fail("state is not live and secret-free");
    text(state.phase, "phase");
    text(state.instruction, "instruction");
    if (state.phase === "enrollment_ready" || state.lifecycle === "enrollment_ready") fail("enrollment-ready lifecycle is prohibited");
    const safety = object(state.safety, "safety");
    if (safety.simulation !== false || safety.secret_free !== true) fail("safety boundary is not live and secret-free");
    if (safety.rollback_status !== ROLLBACK_STATUS) fail("rollback gate is not explicitly unimplemented");
    if (safety.enrollment_capable !== false) fail("state unexpectedly permits enrollment");
    if (!Array.isArray(state.allowed_actions) || !Array.isArray(state.action_presentations)) {
      fail("allowed actions and presentations must be arrays");
    }
    const seen = new Set();
    const presentations = new Map();
    state.action_presentations.forEach(function (entry) {
      const candidate = object(entry, "action presentation");
      const action = text(candidate.action, "presented action");
      if (presentations.has(action)) fail("duplicate action presentation");
      presentations.set(action, candidate);
    });
    state.allowed_actions.forEach(function (action) {
      if (typeof action !== "string" || !SUPPORTED_ACTIONS.has(action) || action === FORBIDDEN_ACTION) {
        fail("unsupported or enrollment action was offered");
      }
      if (seen.has(action)) fail("duplicate allowed action");
      seen.add(action);
      if (!presentations.has(action)) fail("allowed action has no presentation");
      validateActionPresentation(presentations.get(action), action);
    });
    if (presentations.size !== seen.size) fail("presentation exists for an action that is not allowed");
    if (!Array.isArray(state.evidence)) fail("evidence must be an array");
    state.evidence.forEach(function (entry) {
      const evidence = object(entry, "evidence entry");
      ["id", "stage", "status", "digest", "detail", "receipt_id", "recorded_at"].forEach(function (field) {
        text(evidence[field], "evidence " + field);
      });
    });
    return state;
  }

  function buildActionRequest(action, revision) {
    if (!SUPPORTED_ACTIONS.has(action) || action === FORBIDDEN_ACTION) fail("cannot construct unsupported action");
    if (!Number.isSafeInteger(revision) || revision < 1) fail("cannot construct action with invalid revision");
    return { action: action, expected_revision: revision };
  }

  function requiresExplicitConfirmation(presentation) {
    return presentation.classification === "irreversible" || presentation.point_of_no_return === true || presentation.requires_confirmation === true;
  }

  function addFact(document, list, label, value) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value || "Not recorded";
    list.append(term, detail);
  }

  function renderFacts(document, list, value, definitions, emptyMessage) {
    list.replaceChildren();
    if (!value) {
      addFact(document, list, "Status", emptyMessage);
      return;
    }
    definitions.forEach(function (definition) {
      const fact = value[definition[1]];
      addFact(document, list, definition[0], fact === undefined || fact === null || fact === "" ? "Not recorded" : String(fact));
    });
  }

  function renderEvidence(document, evidence) {
    const list = document.getElementById("evidence-list");
    list.replaceChildren();
    evidence.forEach(function (entry) {
      const item = document.createElement("li");
      const heading = document.createElement("div");
      const id = document.createElement("strong");
      id.textContent = entry.id || "unnamed evidence";
      const status = document.createElement("span");
      status.className = "evidence-status status-" + String(entry.status || "unknown").replace(/[^a-z0-9_-]/g, "-");
      status.textContent = entry.status || "unknown";
      heading.append(id, status);
      const detail = document.createElement("p");
      detail.textContent = entry.detail || "No detail supplied.";
      const binding = document.createElement("code");
      binding.textContent = (entry.stage || "unknown stage") + " · " + (entry.receipt_id || "missing receipt");
      item.append(heading, detail, binding);
      list.append(item);
    });
    document.getElementById("evidence-count").textContent = evidence.length + (evidence.length === 1 ? " record" : " records");
  }

  function confirmationMessage(presentation) {
    if (presentation.classification === "irreversible" || presentation.point_of_no_return) {
      return "IRREVERSIBLE ONE-SHOT ACTION\n\n" + presentation.description +
        "\n\nConfirm only after checking the target, current fence epoch, approval, plan, and durable intent receipt. This action must never be blindly repeated.";
    }
    return "Confirm action\n\n" + presentation.description;
  }

  function renderActions(windowObject, runtime, state, reload) {
    const document = windowObject.document;
    const container = document.getElementById("actions");
    container.replaceChildren();
    const presentations = new Map(state.action_presentations.map(function (entry) { return [entry.action, entry]; }));
    if (state.allowed_actions.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "No action is authorized in the current phase.";
      container.append(empty);
      return;
    }
    state.allowed_actions.forEach(function (action) {
      const presentation = presentations.get(action);
      const card = document.createElement("article");
      card.className = "action-card" + (presentation.point_of_no_return ? " irreversible" : "");
      const title = document.createElement("h3");
      title.textContent = presentation.label;
      const description = document.createElement("p");
      description.textContent = presentation.description;
      const classification = document.createElement("span");
      classification.className = "classification";
      classification.textContent = presentation.classification.replace(/_/g, " ");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = presentation.point_of_no_return ? "Review and execute once" : "Run action";
      button.addEventListener("click", async function () {
        if (requiresExplicitConfirmation(presentation) && !windowObject.confirm(confirmationMessage(presentation))) return;
        button.disabled = true;
        setConnection(document, "Submitting action for revision " + state.revision + "…", "working");
        try {
          const response = await windowObject.fetch(runtime.action_endpoint, {
            method: "POST",
            credentials: "same-origin",
            redirect: "error",
            referrerPolicy: "no-referrer",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(buildActionRequest(action, state.revision))
          });
          if (!response.ok) {
            const problem = await response.json().catch(function () { return {}; });
            throw new Error(problem.detail || ("Action failed with HTTP " + response.status));
          }
          render(windowObject, runtime, validateState(await response.json()), reload);
          setConnection(document, "Authoritative state updated.", "ok");
        } catch (error) {
          setConnection(document, error.message, "error");
          await reload();
        } finally {
          button.disabled = false;
        }
      });
      card.append(title, description, classification, button);
      container.append(card);
    });
  }

  function setConnection(document, message, status) {
    const element = document.getElementById("connection-status");
    element.textContent = message;
    element.dataset.status = status;
  }

  function render(windowObject, runtime, state, reload) {
    const document = windowObject.document;
    document.getElementById("phase-title").textContent = state.phase.replace(/_/g, " ");
    document.getElementById("instruction").textContent = state.instruction;
    document.getElementById("revision").textContent = "Revision " + state.revision;
    renderFacts(document, document.getElementById("target-facts"), state.target, [
      ["Model", "model"], ["Profile", "profile_id"], ["Fingerprint", "target_fingerprint"],
      ["Customer key", "customer_key_hash"], ["Secure boot", "secure_boot_state"]
    ], "No target is bound");
    renderFacts(document, document.getElementById("transaction-facts"), state.transaction, [
      ["Transaction", "id"], ["Status", "status"], ["Claim", "claim_id"],
      ["Fence epoch", "fence_epoch"], ["Plan", "plan_digest"], ["Commit executions", "commit_executions"]
    ], "No transaction exists");
    renderEvidence(document, state.evidence);
    renderActions(windowObject, runtime, state, reload);
  }

  async function readJSON(response, label) {
    if (!response.ok) throw new Error(label + " failed with HTTP " + response.status);
    const contentType = response.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) throw new Error(label + " returned a non-JSON response");
    return response.json();
  }

  async function start(windowObject) {
    const runtimeResponse = await windowObject.fetch("/runtime-config.json", {
      method: "GET", credentials: "same-origin", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"
    });
    const runtime = validateRuntimeConfig(await readJSON(runtimeResponse, "Runtime config"), windowObject.location.origin);
    const reload = async function () {
      try {
        const response = await windowObject.fetch(runtime.state_endpoint, {
          method: "GET", credentials: "same-origin", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"
        });
        const state = validateState(await readJSON(response, "Live state"));
        render(windowObject, runtime, state, reload);
        setConnection(windowObject.document, "Connected to the local authoritative orchestrator.", "ok");
      } catch (error) {
        setConnection(windowObject.document, error.message, "error");
      }
    };
    windowObject.document.getElementById("refresh").addEventListener("click", reload);
    await reload();
  }

  function showFatal(document, error) {
    const element = document.getElementById("connection-status");
    if (element) {
      element.textContent = error.message;
      element.dataset.status = "error";
    }
  }

  return {
    RUNTIME_SCHEMA: RUNTIME_SCHEMA,
    LIVE_STATE_SCHEMA: LIVE_STATE_SCHEMA,
    validateRuntimeConfig: validateRuntimeConfig,
    validateState: validateState,
    buildActionRequest: buildActionRequest,
    requiresExplicitConfirmation: requiresExplicitConfirmation,
    start: start,
    showFatal: showFatal
  };
});
