import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const transportPath = path.join(repository, "provisioning/internal/provisioning/stationui/web/transport.js");
const transportSource = fs.readFileSync(transportPath, "utf8");
const pagesRoot = process.env.KAIBA_STATION_PAGES;
if (!pagesRoot) throw new Error("KAIBA_STATION_PAGES must identify the generated Pages bundle");

const graph = JSON.parse(fs.readFileSync(path.join(pagesRoot, "workflow-graph.json"), "utf8"));
const pagesConfig = JSON.parse(fs.readFileSync(path.join(pagesRoot, "runtime-config.json"), "utf8"));
const baseURL = "https://example.invalid/nixos-kaiba-network/provisioning-demo/";
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

function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function response(value, { status = 200 } = {}) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => jsonClone(value),
    text: async () => text,
  };
}

function loadTransport(fetchImplementation, location = baseURL) {
  const pageURL = new URL(location);
  const browserWindow = {
    location: pageURL,
    setTimeout,
    clearTimeout,
  };
  const context = vm.createContext({
    AbortController,
    Error,
    JSON,
    Map,
    Number,
    Object,
    Promise,
    RegExp,
    Set,
    String,
    URL,
    console,
    document: { baseURI: pageURL.href },
    fetch: fetchImplementation,
    window: browserWindow,
  });
  vm.runInContext(transportSource, context, { filename: transportPath });
  return browserWindow.KaibaStationTransport;
}

function pagesRuntime(config = pagesConfig, graphValue = graph) {
  const calls = [];
  const fetchImplementation = async (url, options) => {
    calls.push({ url: String(url), options: jsonClone(options) });
    if (String(url) === `${baseURL}runtime-config.json`) return response(config);
    if (String(url) === `${baseURL}workflow-graph.json`) return response(graphValue);
    return response({ detail: "not found" }, { status: 404 });
  };
  return { calls, transport: loadTransport(fetchImplementation) };
}

function expectedState(nodeID, revision) {
  const state = jsonClone(graph.nodes[nodeID].state);
  state.revision = revision;
  return state;
}

async function follow(client, actions) {
  let state = await client.getState();
  for (const action of actions) {
    state = await client.applyAction({ action, expected_revision: state.revision });
  }
  return jsonClone(state);
}

function representativeScenarioPath(scenario) {
  const actions = [scenario.action];
  let nodeID = graph.nodes[graph.default_node].transitions[scenario.action];
  assert.ok(nodeID, `${scenario.id} must be selectable from station admission`);
  const seen = new Set();

  while (true) {
    assert.ok(!seen.has(nodeID), `${scenario.id} representative path must not cycle`);
    seen.add(nodeID);
    const node = graph.nodes[nodeID];
    const state = node.state;
    const terminal = ["stopped", "quarantined", "enrollment_ready"].includes(state.phase)
      || ["owned_quarantined", "enrollment_ready"].includes(state.lifecycle);
    if (terminal) {
      if (state.allowed_actions.includes("export_redacted")) {
        actions.push("export_redacted");
        nodeID = node.transitions.export_redacted;
      }
      return { actions, nodeID };
    }

    const candidates = state.allowed_actions.filter((action) => (
      action !== "reset"
      && action !== "export_redacted"
      && !action.startsWith("select_scenario:")
    ));
    let action;
    if (candidates.includes("confirm_boot_ok") && candidates.includes("confirm_boot_failed")) {
      action = scenario.id === "boot-failure" ? "confirm_boot_failed" : "confirm_boot_ok";
    } else {
      assert.equal(candidates.length, 1, `${scenario.id} must have one representative forward action at ${state.phase}`);
      [action] = candidates;
    }
    actions.push(action);
    nodeID = node.transitions[action];
    assert.ok(nodeID, `${scenario.id} action ${action} must identify a generated target node`);
  }
}

test("Pages adapter validates the complete graph and follows every scenario to a terminal outcome", async () => {
  assert.equal(graph.schema_version, "provisioning.kaiba.network/station-demo-transition-graph/v1alpha1");
  assert.equal(graph.state_schema_version, "provisioning.kaiba.network/station-demo-state/v1alpha2");
  const scenarios = graph.nodes[graph.default_node].state.scenarios;
  assert.equal(scenarios.length, 25, "the complete synthetic failure matrix must be present");

  for (const scenario of scenarios) {
    const { actions, nodeID } = representativeScenarioPath(scenario);
    const runtime = pagesRuntime();
    const client = await runtime.transport.create();
    const terminal = await follow(client, actions);
    assert.deepEqual(terminal, expectedState(nodeID, actions.length + 1));
    assert.ok(terminal.outcome, `${scenario.id} must produce a typed terminal outcome`);
    assert.equal(terminal.scenario, scenario.id);
  }

  const happyPath = representativeScenarioPath(scenarios.find((scenario) => scenario.id === "happy-path"));
  assert.equal(graph.nodes[happyPath.nodeID].state.lifecycle, "enrollment_ready");
  assert.equal(graph.nodes[happyPath.nodeID].state.outcome.status, "enrollment_ready");
});

test("Pages adapter is in-memory, revisioned, and conflict-safe", async () => {
  const runtime = pagesRuntime();
  const client = await runtime.transport.create();
  const initial = await client.getState();
  const action = initial.allowed_actions[0];

  await assert.rejects(
    client.applyAction({ action, expected_revision: initial.revision + 1 }),
    (error) => error.status === 409 && error.code === "stale_revision",
  );
  await assert.rejects(
    client.applyAction({ action: "not_an_action", expected_revision: initial.revision }),
    (error) => error.status === 409 && error.code === "action_not_allowed",
  );
  assert.deepEqual(jsonClone(await client.getState()), jsonClone(initial));

  const results = await Promise.allSettled([
    client.applyAction({ action, expected_revision: initial.revision }),
    client.applyAction({ action, expected_revision: initial.revision }),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected" && result.reason.status === 409).length, 1);
  assert.equal((await client.getState()).revision, initial.revision + 1);

  const freshClient = await pagesRuntime().transport.create();
  assert.equal((await freshClient.getState()).revision, 1, "a new page runtime must reset the simulation");
});

test("terminal owned identities never expose reset or cached scenario controls", () => {
  const states = Object.values(graph.nodes).map((node) => node.state);
  assert.ok(states.some((state) => state.phase === "station_admission" && state.scenarios.length > 0));
  assert.ok(states.some((state) => state.phase === "final_cold_restart_observed"));
  assert.ok(states.some((state) => state.evidence.some((item) => item.id === "final-cold-restart")));
  for (const state of states) {
    if (state.phase !== "station_admission") {
      assert.deepEqual(state.scenarios, [], `${state.phase} must not retain developer scenario controls`);
      assert.ok(!state.allowed_actions.some((action) => action.startsWith("select_scenario:")));
    }
    if (["owned_quarantined", "enrollment_ready"].includes(state.lifecycle)) {
      assert.ok(!state.allowed_actions.includes("reset"), `${state.lifecycle} must not return to the fresh path`);
    }
  }
});

test("Pages mode performs only two path-relative GETs", async () => {
  const runtime = pagesRuntime();
  const client = await runtime.transport.create();
  const state = await client.getState();
  await client.applyAction({ action: state.allowed_actions[0], expected_revision: state.revision });

  assert.deepEqual(runtime.calls.map((call) => call.url), [
    `${baseURL}runtime-config.json`,
    `${baseURL}workflow-graph.json`,
  ]);
  for (const call of runtime.calls) {
    assert.equal(call.options.method, undefined);
    assert.equal(call.options.credentials, "same-origin");
    assert.equal(call.options.cache, "no-store");
    assert.equal(call.options.redirect, "error");
  }
});

test("HTTP mode uses the same client contract without fallback", async () => {
  const calls = [];
  const initial = expectedState(graph.default_node, 1);
  const firstAction = initial.allowed_actions[0];
  const targetID = graph.nodes[graph.default_node].transitions[firstAction];
  const next = expectedState(targetID, 2);
  const config = {
    schema_version: "provisioning.kaiba.network/station-demo-runtime/v1alpha1",
    mode: "http",
    state_url: "./api/v1/state",
    action_url: "./api/v1/actions",
  };
  const fetchImplementation = async (url, options) => {
    calls.push({ url: String(url), options: jsonClone(options) });
    if (String(url).endsWith("runtime-config.json")) return response(config);
    if (String(url).endsWith("api/v1/state")) return response(initial);
    if (String(url).endsWith("api/v1/actions")) return response(next);
    return response({ detail: "not found" }, { status: 404 });
  };
  const client = await loadTransport(fetchImplementation).create();
  assert.deepEqual(jsonClone(await client.getState()), initial);
  assert.deepEqual(
    jsonClone(await client.applyAction({ action: firstAction, expected_revision: 1 })),
    next,
  );

  assert.deepEqual(calls.map((call) => call.url), [
    `${baseURL}runtime-config.json`,
    `${baseURL}api/v1/state`,
    `${baseURL}api/v1/actions`,
  ]);
  assert.equal(calls[2].options.method, "POST");
  assert.equal(calls[2].options.headers["Content-Type"], "application/json");
  assert.equal(calls[2].options.body, JSON.stringify({ action: firstAction, expected_revision: 1 }));
});

test("transport selection is explicit and fails closed", async () => {
  const unsupported = pagesRuntime({ schema_version: pagesConfig.schema_version, mode: "automatic" });
  await assert.rejects(unsupported.transport.create(), /unsupported transport mode/);
  assert.equal(unsupported.calls.length, 1);

  const crossOrigin = pagesRuntime({
    schema_version: pagesConfig.schema_version,
    mode: "transition-graph",
    graph_url: "https://evil.invalid/workflow.json",
  });
  await assert.rejects(crossOrigin.transport.create(), /path-relative URL/);
  assert.equal(crossOrigin.calls.length, 1);

  for (const capability of falseSafetyCapabilities) {
    const unsafeGraph = jsonClone(graph);
    unsafeGraph.nodes[unsafeGraph.default_node].state.safety[capability] = true;
    const unsafe = pagesRuntime(pagesConfig, unsafeGraph);
    await assert.rejects(unsafe.transport.create(), new RegExp(`simulation safety boundary|did not deny ${capability}`));
    assert.equal(unsafe.calls.length, 2);
  }
});

test("v1alpha2 typed workflow, irreversible metadata, and redacted export fail closed", async () => {
  const malformedStageGraph = jsonClone(graph);
  malformedStageGraph.nodes[malformedStageGraph.default_node].state.workflow_stages[0].status = "guessed";
  await assert.rejects(pagesRuntime(pagesConfig, malformedStageGraph).transport.create(), /workflow stage status/);

  const unsafePresentationGraph = jsonClone(graph);
  const presentations = Object.values(unsafePresentationGraph.nodes)
    .flatMap((node) => node.state.action_presentations);
  const irreversible = presentations.filter((presentation) => presentation.classification === "irreversible");
  assert.ok(irreversible.length > 0);
  assert.ok(irreversible.every((presentation) => presentation.requires_confirmation === true));
  assert.deepEqual(
    [...new Set(presentations.filter((presentation) => presentation.point_of_no_return).map((presentation) => presentation.action))],
    ["execute_commit"],
  );
  const commitPresentation = presentations.find((presentation) => presentation.point_of_no_return === true);
  assert.equal(commitPresentation.action, "execute_commit");
  assert.equal(commitPresentation.classification, "irreversible");
  assert.equal(commitPresentation.requires_confirmation, true);
  commitPresentation.requires_confirmation = false;
  await assert.rejects(
    pagesRuntime(pagesConfig, unsafePresentationGraph).transport.create(),
    /irreversible action without confirmation/,
  );

  const misplacedBoundaryGraph = jsonClone(graph);
  const misplacedBoundary = Object.values(misplacedBoundaryGraph.nodes)
    .flatMap((node) => node.state.action_presentations)
    .find((presentation) => presentation.action === "apply_final_controls");
  misplacedBoundary.point_of_no_return = true;
  await assert.rejects(pagesRuntime(pagesConfig, misplacedBoundaryGraph).transport.create(), /point-of-no-return/);

  const missingBoundaryGraph = jsonClone(graph);
  const missingBoundary = Object.values(missingBoundaryGraph.nodes)
    .flatMap((node) => node.state.action_presentations)
    .find((presentation) => presentation.action === "execute_commit");
  missingBoundary.point_of_no_return = false;
  await assert.rejects(pagesRuntime(pagesConfig, missingBoundaryGraph).transport.create(), /point-of-no-return/);

  const unconfirmedFinalControlsGraph = jsonClone(graph);
  const finalControlsPresentation = Object.values(unconfirmedFinalControlsGraph.nodes)
    .flatMap((node) => node.state.action_presentations)
    .find((presentation) => presentation.action === "apply_final_controls");
  finalControlsPresentation.requires_confirmation = false;
  await assert.rejects(
    pagesRuntime(pagesConfig, unconfirmedFinalControlsGraph).transport.create(),
    /irreversible action without confirmation/,
  );

  const repeatedCommitGraph = jsonClone(graph);
  const committedState = Object.values(repeatedCommitGraph.nodes)
    .map((node) => node.state)
    .find((state) => state.transaction?.commit_executions === 1);
  assert.ok(committedState, "generated graph must include the modeled one-shot commit");
  committedState.transaction.commit_executions = 2;
  await assert.rejects(pagesRuntime(pagesConfig, repeatedCommitGraph).transport.create(), /repeated the one-shot/);

  const repeatedFinalControlsGraph = jsonClone(graph);
  const finalizedState = Object.values(repeatedFinalControlsGraph.nodes)
    .map((node) => node.state)
    .find((state) => state.transaction?.final_control_executions === 1);
  assert.ok(finalizedState, "generated graph must include one modeled final-control execution");
  finalizedState.transaction.final_control_executions = 2;
  await assert.rejects(
    pagesRuntime(pagesConfig, repeatedFinalControlsGraph).transport.create(),
    /repeated the one-shot modeled final controls/,
  );

  for (const [field, value] of [
    ["commit_executions", 0],
    ["irreversible_boundary_crossed", false],
  ]) {
    const missingCommitBoundaryGraph = jsonClone(graph);
    const finalControlsState = Object.values(missingCommitBoundaryGraph.nodes)
      .map((node) => node.state)
      .find((state) => state.transaction?.final_control_executions === 1);
    assert.ok(finalControlsState, "generated graph must include modeled final controls");
    finalControlsState.transaction[field] = value;
    await assert.rejects(
      pagesRuntime(pagesConfig, missingCommitBoundaryGraph).transport.create(),
      /lost the commit boundary|lost the irreversible-boundary marker/,
    );
  }

  const secretGraph = jsonClone(graph);
  const exportedState = Object.values(secretGraph.nodes)
    .map((node) => node.state)
    .find((state) => state.export_record);
  assert.ok(exportedState, "generated graph must include a redacted export");
  exportedState.export_record.private_key = "-----BEGIN PRIVATE KEY-----";
  await assert.rejects(pagesRuntime(pagesConfig, secretGraph).transport.create(), /unsupported or missing fields|private key/);
});

test("shared transport has no browser persistence or hardware API", () => {
  assert.doesNotMatch(transportSource, /localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(transportSource, /navigator\s*\.\s*usb|requestDevice|WebUSB/);
  assert.doesNotMatch(transportSource, /location\.(?:host|hostname).*mode|URLSearchParams/);
});
