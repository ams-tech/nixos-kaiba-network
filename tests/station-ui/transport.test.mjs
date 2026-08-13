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

function reachablePaths() {
  const paths = new Map([[graph.default_node, []]]);
  const queue = [graph.default_node];
  while (queue.length > 0) {
    const nodeID = queue.shift();
    for (const [action, targetID] of Object.entries(graph.nodes[nodeID].transitions)) {
      if (!paths.has(targetID)) {
        paths.set(targetID, [...paths.get(nodeID), action]);
        queue.push(targetID);
      }
    }
  }
  return paths;
}

test("Pages adapter follows every Go-generated transition exactly", async () => {
  const paths = reachablePaths();
  assert.equal(paths.size, Object.keys(graph.nodes).length, "every generated node must be reachable");

  for (const [nodeID, actions] of paths) {
    const runtime = pagesRuntime();
    const client = await runtime.transport.create();
    assert.deepEqual(await follow(client, actions), expectedState(nodeID, actions.length + 1));

    for (const [action, targetID] of Object.entries(graph.nodes[nodeID].transitions)) {
      const edgeRuntime = pagesRuntime();
      const edgeClient = await edgeRuntime.transport.create();
      const state = await follow(edgeClient, actions);
      const next = await edgeClient.applyAction({ action, expected_revision: state.revision });
      assert.deepEqual(jsonClone(next), expectedState(targetID, actions.length + 2));
    }
  }
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

  const unsafeGraph = jsonClone(graph);
  unsafeGraph.nodes[unsafeGraph.default_node].state.safety.mutation_eligible = true;
  const unsafe = pagesRuntime(pagesConfig, unsafeGraph);
  await assert.rejects(unsafe.transport.create(), /safety boundary/);
  assert.equal(unsafe.calls.length, 2);
});

test("shared transport has no browser persistence or hardware API", () => {
  assert.doesNotMatch(transportSource, /localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(transportSource, /navigator\s*\.\s*usb|requestDevice|WebUSB/);
  assert.doesNotMatch(transportSource, /location\.(?:host|hostname).*mode|URLSearchParams/);
});
