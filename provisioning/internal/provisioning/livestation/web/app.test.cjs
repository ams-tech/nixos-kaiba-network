"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const live = require("./app.js");

function runtime() {
  return {
    schema_version: live.RUNTIME_SCHEMA,
    state_schema_version: live.LIVE_STATE_SCHEMA,
    expected_origin: "http://127.0.0.1:8081",
    state_endpoint: "/api/v1/state",
    action_endpoint: "/api/v1/actions",
    simulation: false,
    secret_free: true,
    rollback_status: "rollback_unimplemented",
    enrollment_capable: false
  };
}

function state() {
  return {
    schema_version: live.LIVE_STATE_SCHEMA,
    revision: 7,
    simulation: false,
    secret_free: true,
    phase: "commit_intent_recorded",
    instruction: "Execute the approved commit exactly once.",
    safety: {
      simulation: false,
      secret_free: true,
      rollback_status: "rollback_unimplemented",
      enrollment_capable: false
    },
    allowed_actions: ["execute_commit"],
    action_presentations: [{
      action: "execute_commit",
      label: "Execute commit",
      description: "Cross the one-way ownership boundary.",
      classification: "irreversible",
      requires_confirmation: true,
      point_of_no_return: true
    }],
    evidence: []
  };
}

test("accepts only the exact live runtime and state safety boundary", () => {
  assert.equal(live.validateRuntimeConfig(runtime(), "http://127.0.0.1:8081").simulation, false);
  assert.equal(live.validateState(state()).revision, 7);

  const simulatedRuntime = runtime();
  simulatedRuntime.simulation = true;
  assert.throws(() => live.validateRuntimeConfig(simulatedRuntime, "http://127.0.0.1:8081"), /contract rejected/);
  assert.throws(() => live.validateRuntimeConfig(runtime(), "http://127.0.0.1:9999"), /origin/);
  const widenedRuntime = runtime();
  widenedRuntime.unexpected_field = true;
  assert.throws(() => live.validateRuntimeConfig(widenedRuntime, "http://127.0.0.1:8081"), /fields changed/);

  for (const mutate of [
    value => { value.simulation = true; },
    value => { value.secret_free = false; },
    value => { value.safety.rollback_status = "implemented"; },
    value => { value.safety.enrollment_capable = true; }
  ]) {
    const value = state();
    mutate(value);
    assert.throws(() => live.validateState(value), /contract rejected/);
  }
});

test("never accepts an enrollment-ready action or phase", () => {
  const offered = state();
  offered.allowed_actions = ["mark_enrollment_ready"];
  offered.action_presentations[0].action = "mark_enrollment_ready";
  assert.throws(() => live.validateState(offered), /enrollment action/);
  const phase = state();
  phase.phase = "enrollment_ready";
  assert.throws(() => live.validateState(phase), /lifecycle is prohibited/);
});

test("constructs an optimistic action and confirms irreversible metadata", () => {
  assert.deepEqual(live.buildActionRequest("execute_commit", 7), {
    action: "execute_commit",
    expected_revision: 7
  });
  assert.equal(live.requiresExplicitConfirmation(state().action_presentations[0]), true);
  const unsafe = state();
  unsafe.action_presentations[0].requires_confirmation = false;
  unsafe.action_presentations[0].point_of_no_return = false;
  assert.throws(() => live.validateState(unsafe), /confirmation metadata/);
  assert.throws(() => live.buildActionRequest("mark_enrollment_ready", 7));
  assert.throws(() => live.buildActionRequest("execute_commit", 0));
});
