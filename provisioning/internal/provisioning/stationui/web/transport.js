"use strict";

(() => {
  const runtimeConfigURL = "./runtime-config.json";
  const runtimeConfigSchema = "provisioning.kaiba.network/station-demo-runtime/v1alpha1";
  const transitionGraphSchema = "provisioning.kaiba.network/station-demo-transition-graph/v1alpha1";
  const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha1";
  const requestTimeoutMs = 12000;

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

  function requireSimulationState(value, label, revision) {
    const state = objectValue(value, label);
    if (state.schema_version !== stateSchema || state.revision !== revision || state.simulation !== true) {
      throw runtimeError(`${label} is not a compatible simulation state.`);
    }
    if (!state.safety || state.safety.simulation !== true || state.safety.mutation_eligible !== false
      || state.safety.full_unprovisioned_state !== "not_established") {
      throw runtimeError(`${label} violates the simulation safety boundary.`);
    }
    if (!Array.isArray(state.allowed_actions) || new Set(state.allowed_actions).size !== state.allowed_actions.length
      || !state.allowed_actions.every((action) => typeof action === "string" && action.length > 0)) {
      throw runtimeError(`${label} has invalid allowed actions.`);
    }
    for (const probe of Array.isArray(state.probes) ? state.probes : []) {
      if (!probe || typeof probe !== "object" || !probe.assessment
        || probe.assessment.mutation_eligible !== false
        || probe.assessment.full_unprovisioned_state !== "not_established") {
        throw runtimeError(`${label} contains an unsafe probe assessment.`);
      }
    }
    if (state.export_record && (state.export_record.simulation !== true
      || state.export_record.mutation_eligible !== false
      || state.export_record.full_unprovisioned_state !== "not_established")) {
      throw runtimeError(`${label} contains an unsafe export record.`);
    }
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

    for (const nodeID of nodeIDs) {
      if (!/^sha256:[0-9a-f]{64}$/.test(nodeID)) {
        throw runtimeError("Transition graph contains a malformed node identifier.");
      }
      const node = objectValue(nodes[nodeID], `Transition node ${nodeID}`);
      exactKeys(node, ["state", "transitions"], `Transition node ${nodeID}`);
      const state = requireSimulationState(node.state, `Transition node ${nodeID}`, 0);
      const transitions = objectValue(node.transitions, `Transitions for ${nodeID}`);
      const actions = Object.keys(transitions);
      if (actions.length !== state.allowed_actions.length
        || actions.some((action) => !state.allowed_actions.includes(action))) {
        throw runtimeError(`Transition node ${nodeID} does not exactly cover its allowed actions.`);
      }
      for (const targetID of Object.values(transitions)) {
        if (typeof targetID !== "string" || !nodes[targetID]) {
          throw runtimeError(`Transition node ${nodeID} references an unknown target.`);
        }
      }
    }
    return graph;
  }

  function createHTTPClient(config) {
    const stateURL = relativeSameOriginURL(config.state_url, "HTTP state URL");
    const actionURL = relativeSameOriginURL(config.action_url, "HTTP action URL");
    return Object.freeze({
      mode: "http",
      getState: () => fetchJSON(stateURL),
      applyAction: (request) => fetchJSON(actionURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      }),
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
    if (config.schema_version !== runtimeConfigSchema) {
      throw runtimeError("Runtime configuration has an unsupported schema.");
    }
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
