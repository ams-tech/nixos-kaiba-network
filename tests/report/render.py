#!/usr/bin/env python3
"""Render deterministic, self-contained evidence for the Kaiba DNS VM test.

The integration test owns collection.  This program owns the stable interchange
format and presentation.  It intentionally uses only the Python standard
library so it can run in a small Nix derivation without network access.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, NoReturn


SCHEMA_VERSION = 1
SUITE = "kaiba-dns-pilot"
PROVISIONING_SUITE = "kaiba-rpi5-provisioning-probe"
PLATFORM_RESULT_SUITE = "kaiba-rpi5-provisioning-platform-result"
PROVISIONING_SYSTEMS = {"x86_64-linux", "aarch64-linux"}
EXPECTED_NODES = {
    "parent",
    "p0",
    "p1",
    "public-a",
    "public-b",
    "resolver",
    "pi-001",
}
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
RECORD_TYPE = re.compile(r"^[A-Z][A-Z0-9]*$")
EVIDENCE_PATH = re.compile(r"^evidence/[A-Za-z0-9._/-]+$")
FORBIDDEN_KEY_PARTS = (
    "timestamp",
    "time-stamp",
    "wall-time",
    "elapsed",
    "process-id",
    "dns-transaction-id",
    "transaction-id",
    "ephemeral-port",
    "private-key",
    "key-material",
    "password",
    "secret",
    "token",
)
FORBIDDEN_TEXT = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:password|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bpid\s*[:=]\s*\d+"),
    re.compile(r"(?i)\b(?:elapsed|wall[-_ ]?time)\s*[:=]\s*\d"),
    re.compile(r"(?i)\b(?:client|source|ephemeral)[-_ ]?port\s*[:=]\s*\d+"),
    re.compile(r";;\s*->>HEADER<<-.*\bid:\s*\d+"),
    re.compile(r"(?i)\bdns(?:[-_ ]transaction)?[-_ ]id\s*[:=]?\s*\d+"),
    re.compile(r"(?:#|:)(?:3[2-9]\d{3}|[4-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
)
NETWORK_COLOURS = {
    "public-query": "#2563eb",
    "origin-transfer": "#7c3aed",
    "device-update": "#059669",
    "p0-loopback": "#64748b",
}
BOUNDARY_COLOURS = {
    "registrar-simulation": "#fef3c7",
    "hidden-origin": "#ede9fe",
    "managed-secondary-simulation": "#dbeafe",
    "untrusted-client": "#f1f5f9",
    "secure-device": "#d1fae5",
}


class ReportError(ValueError):
    """An input cannot be represented as a trustworthy canonical report."""


def fail(context: str, message: str) -> NoReturn:
    raise ReportError(f"{context}: {message}")


def load_json(path: Path, context: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(context, f"duplicate object key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"{context}: cannot read JSON: {exc}") from exc


def expect_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(context, "must be an object")
    return value


def expect_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(context, "must be an array")
    return value


def expect_string(value: Any, context: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value:
        fail(context, "must be a non-empty string")
    if identifier and not IDENTIFIER.fullmatch(value):
        fail(context, "must be a lowercase dash-separated identifier")
    return value


def exact_keys(
    value: dict[str, Any],
    required: Iterable[str],
    optional: Iterable[str],
    context: str,
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        fail(context, f"missing keys: {', '.join(missing)}")
    if unknown:
        fail(context, f"unknown keys: {', '.join(unknown)}")


def normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-")


def normalize_string(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def normalize_and_scan(value: Any, context: str = "input") -> Any:
    """Normalize line endings and reject common secret/non-deterministic fields."""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                fail(context, "object keys must be strings")
            key_form = normalized_key(key)
            if key_form in {"pid", "dns-id"} or any(part in key_form for part in FORBIDDEN_KEY_PARTS):
                fail(f"{context}.{key}", "forbidden secret or dynamic-noise field")
            result[key] = normalize_and_scan(child, f"{context}.{key}")
        return result
    if isinstance(value, list):
        return [normalize_and_scan(child, f"{context}[{index}]") for index, child in enumerate(value)]
    if isinstance(value, str):
        result = normalize_string(value)
        for pattern in FORBIDDEN_TEXT:
            if pattern.search(result):
                fail(context, "contains a secret or non-deterministic value")
        return result
    if isinstance(value, float) and not math.isfinite(value):
        fail(context, "non-finite numbers are not valid canonical JSON")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    fail(context, f"unsupported value type {type(value).__name__}")


def checked_evidence_path(value: Any, context: str) -> str:
    path = expect_string(value, context)
    posix = PurePosixPath(path)
    if not EVIDENCE_PATH.fullmatch(path) or posix.is_absolute() or ".." in posix.parts or posix.as_posix() != path:
        fail(context, "must be a safe path below evidence/")
    if any(not part or part in {".", ".."} for part in posix.parts):
        fail(context, "contains an invalid path component")
    return path


def require_unique(values: Iterable[Any], context: str) -> None:
    seen: set[Any] = set()
    for value in values:
        if value in seen:
            fail(context, f"duplicate value {value!r}")
        seen.add(value)


def validate_result(value: Any, node_ids: set[str], evidence_paths: set[str]) -> dict[str, Any]:
    result = expect_object(value, "result")
    exact_keys(
        result,
        ("schema_version", "suite", "overall", "assertions", "claims", "serials", "answers"),
        (),
        "result",
    )
    if result["schema_version"] != SCHEMA_VERSION:
        fail("result.schema_version", f"must equal {SCHEMA_VERSION}")
    if result["suite"] != SUITE:
        fail("result.suite", f"must equal {SUITE!r}")
    if result["overall"] not in {"passed", "failed"}:
        fail("result.overall", "must be passed or failed")

    assertions = expect_list(result["assertions"], "result.assertions")
    if not assertions:
        fail("result.assertions", "must contain at least one assertion")
    assertion_ids: list[str] = []
    for index, raw in enumerate(assertions):
        context = f"result.assertions[{index}]"
        assertion = expect_object(raw, context)
        exact_keys(
            assertion,
            ("id", "phase", "status", "description", "expected", "observed", "evidence"),
            (),
            context,
        )
        assertion_ids.append(expect_string(assertion["id"], f"{context}.id", identifier=True))
        expect_string(assertion["phase"], f"{context}.phase", identifier=True)
        expect_string(assertion["description"], f"{context}.description")
        if assertion["status"] not in {"passed", "failed"}:
            fail(f"{context}.status", "must be passed or failed")
        refs = [
            checked_evidence_path(item, f"{context}.evidence[{item_index}]")
            for item_index, item in enumerate(expect_list(assertion["evidence"], f"{context}.evidence"))
        ]
        require_unique(refs, f"{context}.evidence")
        missing = sorted(set(refs) - evidence_paths)
        if missing:
            fail(f"{context}.evidence", f"missing evidence files: {', '.join(missing)}")
    require_unique(assertion_ids, "result.assertions ids")
    expected_overall = "failed" if any(item["status"] == "failed" for item in assertions) else "passed"
    if result["overall"] != expected_overall:
        fail("result.overall", f"must be {expected_overall!r} for the recorded assertions")

    claims = expect_object(result["claims"], "result.claims")
    exact_keys(claims, ("exercised", "simulated", "deferred"), (), "result.claims")
    all_claim_ids: list[str] = []
    for category in ("exercised", "simulated", "deferred"):
        entries = expect_list(claims[category], f"result.claims.{category}")
        for index, raw in enumerate(entries):
            context = f"result.claims.{category}[{index}]"
            claim = expect_object(raw, context)
            required = ("id", "statement", "assertions") if category == "exercised" else ("id", "statement")
            exact_keys(claim, required, (), context)
            all_claim_ids.append(expect_string(claim["id"], f"{context}.id", identifier=True))
            expect_string(claim["statement"], f"{context}.statement")
            if category == "exercised":
                refs = [
                    expect_string(item, f"{context}.assertions[{item_index}]", identifier=True)
                    for item_index, item in enumerate(expect_list(claim["assertions"], f"{context}.assertions"))
                ]
                if not refs:
                    fail(f"{context}.assertions", "must cite at least one assertion")
                require_unique(refs, f"{context}.assertions")
                missing = sorted(set(refs) - set(assertion_ids))
                if missing:
                    fail(f"{context}.assertions", f"unknown assertion ids: {', '.join(missing)}")
    require_unique(all_claim_ids, "result claim ids")

    serial_keys: list[tuple[str, str]] = []
    for index, raw in enumerate(expect_list(result["serials"], "result.serials")):
        context = f"result.serials[{index}]"
        observation = expect_object(raw, context)
        exact_keys(observation, ("phase", "server", "serial"), (), context)
        phase = expect_string(observation["phase"], f"{context}.phase", identifier=True)
        server = expect_string(observation["server"], f"{context}.server", identifier=True)
        if server not in node_ids:
            fail(f"{context}.server", "is not a topology node")
        if isinstance(observation["serial"], bool) or not isinstance(observation["serial"], int) or observation["serial"] < 0:
            fail(f"{context}.serial", "must be a non-negative integer")
        serial_keys.append((phase, server))
    require_unique(serial_keys, "result.serials phase/server pairs")

    answer_keys: list[tuple[str, str, str, str, str]] = []
    for index, raw in enumerate(expect_list(result["answers"], "result.answers")):
        context = f"result.answers[{index}]"
        answer = expect_object(raw, context)
        exact_keys(answer, ("phase", "server", "name", "type", "values", "authoritative"), ("transport",), context)
        phase = expect_string(answer["phase"], f"{context}.phase", identifier=True)
        server = expect_string(answer["server"], f"{context}.server", identifier=True)
        if server not in node_ids:
            fail(f"{context}.server", "is not a topology node")
        name = expect_string(answer["name"], f"{context}.name")
        record_type = expect_string(answer["type"], f"{context}.type")
        if not RECORD_TYPE.fullmatch(record_type):
            fail(f"{context}.type", "must be an uppercase DNS record type")
        values = [expect_string(item, f"{context}.values[{item_index}]") for item_index, item in enumerate(expect_list(answer["values"], f"{context}.values"))]
        require_unique(values, f"{context}.values")
        if not isinstance(answer["authoritative"], bool):
            fail(f"{context}.authoritative", "must be a boolean")
        transport = answer.get("transport", "")
        if transport and transport not in {"udp", "tcp", "https"}:
            fail(f"{context}.transport", "must be udp, tcp, or https")
        answer_keys.append((phase, server, name, record_type, transport))
    require_unique(answer_keys, "result.answers observation keys")
    return result


def validate_evidence_references(
    value: Any,
    context: str,
    evidence_paths: set[str] | None,
) -> list[str]:
    refs = [
        checked_evidence_path(item, f"{context}[{index}]")
        for index, item in enumerate(expect_list(value, context))
    ]
    require_unique(refs, context)
    if evidence_paths is not None:
        missing = sorted(set(refs) - evidence_paths)
        if missing:
            fail(context, f"missing evidence files: {', '.join(missing)}")
    return refs


def expected_automated_status(checks: list[dict[str, Any]]) -> str:
    if any(item["status"] == "failed" for item in checks):
        return "failed"
    if any(item["status"] == "not-observed" for item in checks):
        return "partial"
    return "passed"


def validate_provisioning(value: Any, evidence_paths: set[str]) -> dict[str, Any]:
    provisioning = expect_object(value, "provisioning")
    exact_keys(
        provisioning,
        ("schema_version", "suite", "automated", "hardware_qualification", "mutation_eligible"),
        (),
        "provisioning",
    )
    if type(provisioning["schema_version"]) is not int or provisioning["schema_version"] != SCHEMA_VERSION:
        fail("provisioning.schema_version", f"must equal {SCHEMA_VERSION}")
    if provisioning["suite"] != PROVISIONING_SUITE:
        fail("provisioning.suite", f"must equal {PROVISIONING_SUITE!r}")
    if provisioning["mutation_eligible"] is not False:
        fail("provisioning.mutation_eligible", "must be false for this probe-only slice")

    automated = expect_object(provisioning["automated"], "provisioning.automated")
    exact_keys(automated, ("overall", "checks"), (), "provisioning.automated")
    automated_status = expect_string(automated["overall"], "provisioning.automated.overall")
    if automated_status not in {"passed", "failed", "partial"}:
        fail("provisioning.automated.overall", "must be passed, failed, or partial")
    checks = expect_list(automated["checks"], "provisioning.automated.checks")
    if not checks:
        fail("provisioning.automated.checks", "must contain at least one check")
    check_keys: list[tuple[str, str]] = []
    for index, raw in enumerate(checks):
        context = f"provisioning.automated.checks[{index}]"
        check = expect_object(raw, context)
        exact_keys(
            check,
            ("id", "system", "status", "description", "evidence"),
            ("source_revision",),
            context,
        )
        check_id = expect_string(check["id"], f"{context}.id", identifier=True)
        system = expect_string(check["system"], f"{context}.system")
        if system not in PROVISIONING_SYSTEMS:
            fail(f"{context}.system", "must be x86_64-linux or aarch64-linux")
        check_status = expect_string(check["status"], f"{context}.status")
        if check_status not in {"passed", "failed", "not-observed"}:
            fail(f"{context}.status", "must be passed, failed, or not-observed")
        expect_string(check["description"], f"{context}.description")
        refs = validate_evidence_references(check["evidence"], f"{context}.evidence", evidence_paths)
        revision = check.get("source_revision")
        if revision is not None and (not isinstance(revision, str) or not SOURCE_REVISION.fullmatch(revision)):
            fail(f"{context}.source_revision", "must be a lowercase 40- or 64-hex source revision")
        if check_status == "not-observed" and (refs or revision is not None):
            fail(context, "a not-observed check cannot claim evidence or a source revision")
        check_keys.append((system, check_id))
    require_unique(check_keys, "provisioning automated system/check pairs")
    expected = expected_automated_status(checks)
    if automated["overall"] != expected:
        fail("provisioning.automated.overall", f"must be {expected!r} for the recorded checks")

    hardware = expect_object(provisioning["hardware_qualification"], "provisioning.hardware_qualification")
    exact_keys(hardware, ("status", "description", "evidence"), (), "provisioning.hardware_qualification")
    hardware_status = expect_string(hardware["status"], "provisioning.hardware_qualification.status")
    if hardware_status not in {"pending", "passed", "failed"}:
        fail("provisioning.hardware_qualification.status", "must be pending, passed, or failed")
    expect_string(hardware["description"], "provisioning.hardware_qualification.description")
    hardware_evidence = validate_evidence_references(
        hardware["evidence"],
        "provisioning.hardware_qualification.evidence",
        evidence_paths,
    )
    if hardware_status == "pending" and hardware_evidence:
        fail("provisioning.hardware_qualification.evidence", "must be empty while qualification is pending")
    if hardware_status in {"passed", "failed"} and not hardware_evidence:
        fail("provisioning.hardware_qualification.evidence", "must cite evidence for a completed qualification")
    return provisioning


def validate_platform_result(
    value: Any,
    evidence_paths: set[str] | None,
    *,
    require_source_revision: bool,
) -> dict[str, Any]:
    receipt = expect_object(value, "provisioning platform result")
    exact_keys(
        receipt,
        ("schema_version", "suite", "system", "checks"),
        ("source_revision",),
        "provisioning platform result",
    )
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != SCHEMA_VERSION:
        fail("provisioning platform result.schema_version", f"must equal {SCHEMA_VERSION}")
    if receipt["suite"] != PLATFORM_RESULT_SUITE:
        fail("provisioning platform result.suite", f"must equal {PLATFORM_RESULT_SUITE!r}")
    system = expect_string(receipt["system"], "provisioning platform result.system")
    if system not in PROVISIONING_SYSTEMS:
        fail("provisioning platform result.system", "must be x86_64-linux or aarch64-linux")
    revision = receipt.get("source_revision")
    if require_source_revision and revision is None:
        fail("provisioning platform result.source_revision", "is required for a published platform receipt")
    if revision is not None and (not isinstance(revision, str) or not SOURCE_REVISION.fullmatch(revision)):
        fail("provisioning platform result.source_revision", "must be null or a lowercase 40- or 64-hex source revision")

    checks = expect_list(receipt["checks"], "provisioning platform result.checks")
    if not checks:
        fail("provisioning platform result.checks", "must contain at least one check")
    check_ids: list[str] = []
    for index, raw in enumerate(checks):
        context = f"provisioning platform result.checks[{index}]"
        check = expect_object(raw, context)
        exact_keys(check, ("id", "status", "description", "evidence"), (), context)
        check_ids.append(expect_string(check["id"], f"{context}.id", identifier=True))
        status = expect_string(check["status"], f"{context}.status")
        if status not in {"passed", "failed"}:
            fail(f"{context}.status", "must be passed or failed")
        expect_string(check["description"], f"{context}.description")
        validate_evidence_references(check["evidence"], f"{context}.evidence", evidence_paths)
    require_unique(check_ids, "provisioning platform result check ids")
    return receipt


def merge_platform_results(
    provisioning: dict[str, Any],
    receipts: list[dict[str, Any]],
    expected_source_revision: str | None = None,
) -> dict[str, Any]:
    if expected_source_revision is not None and (
        not isinstance(expected_source_revision, str) or not SOURCE_REVISION.fullmatch(expected_source_revision)
    ):
        fail("expected source revision", "must be a lowercase 40- or 64-hex source revision")
    if expected_source_revision is not None and not receipts:
        fail("expected source revision", "requires at least one provisioning platform result")
    merged = copy.deepcopy(provisioning)
    checks = merged["automated"]["checks"]
    revisions = {item["source_revision"] for item in checks if "source_revision" in item}
    for receipt_index, receipt in enumerate(receipts):
        if expected_source_revision is not None and receipt.get("source_revision") != expected_source_revision:
            fail(
                f"provisioning platform result[{receipt_index}].source_revision",
                "does not match the expected checked-out source revision",
            )
        system = receipt["system"]
        placeholders = {
            item["id"]: item
            for item in checks
            if item["system"] == system and item["status"] == "not-observed"
        }
        supplied = {item["id"]: item for item in receipt["checks"]}
        if set(placeholders) != set(supplied):
            missing = sorted(set(placeholders) - set(supplied))
            extra = sorted(set(supplied) - set(placeholders))
            details: list[str] = []
            if missing:
                details.append(f"missing checks: {', '.join(missing)}")
            if extra:
                details.append(f"unexpected or already-observed checks: {', '.join(extra)}")
            fail(f"provisioning platform result[{receipt_index}]", "; ".join(details))
        revision = receipt.get("source_revision")
        if revision is not None:
            revisions.add(revision)
        for check_id, observed in supplied.items():
            target = placeholders[check_id]
            if observed["description"] != target["description"]:
                fail(
                    f"provisioning platform result[{receipt_index}].checks.{check_id}.description",
                    "must match the source-controlled placeholder description",
                )
            target["status"] = observed["status"]
            target["evidence"] = list(observed["evidence"])
            if revision is not None:
                target["source_revision"] = revision
    if len(revisions) > 1:
        fail("provisioning platform results", "source revisions do not match")
    merged["automated"]["overall"] = expected_automated_status(checks)
    return merged


def validate_topology(value: Any) -> dict[str, Any]:
    topology = expect_object(value, "topology")
    exact_keys(
        topology,
        ("schema_version", "title", "zone", "production_analogue", "networks", "trust_boundaries", "nodes", "edges", "delegation"),
        (),
        "topology",
    )
    if topology["schema_version"] != SCHEMA_VERSION:
        fail("topology.schema_version", f"must equal {SCHEMA_VERSION}")
    for key in ("title", "zone", "production_analogue"):
        expect_string(topology[key], f"topology.{key}")

    network_ids: list[str] = []
    for index, raw in enumerate(expect_list(topology["networks"], "topology.networks")):
        context = f"topology.networks[{index}]"
        network = expect_object(raw, context)
        exact_keys(network, ("id", "kind", "vlan", "purpose", "trust"), (), context)
        network_ids.append(expect_string(network["id"], f"{context}.id", identifier=True))
        if network["kind"] not in {"vlan", "local"}:
            fail(f"{context}.kind", "must be vlan or local")
        if network["kind"] == "vlan" and (isinstance(network["vlan"], bool) or not isinstance(network["vlan"], int) or not 1 <= network["vlan"] <= 4094):
            fail(f"{context}.vlan", "must be a VLAN identifier from 1 through 4094")
        if network["kind"] == "local" and network["vlan"] is not None:
            fail(f"{context}.vlan", "must be null for a host-local network")
        expect_string(network["purpose"], f"{context}.purpose")
        expect_string(network["trust"], f"{context}.trust", identifier=True)
    require_unique(network_ids, "topology network ids")

    boundary_ids: list[str] = []
    for index, raw in enumerate(expect_list(topology["trust_boundaries"], "topology.trust_boundaries")):
        context = f"topology.trust_boundaries[{index}]"
        boundary = expect_object(raw, context)
        exact_keys(boundary, ("id", "label"), (), context)
        boundary_ids.append(expect_string(boundary["id"], f"{context}.id", identifier=True))
        expect_string(boundary["label"], f"{context}.label")
    require_unique(boundary_ids, "topology trust boundary ids")

    node_ids: list[str] = []
    for index, raw in enumerate(expect_list(topology["nodes"], "topology.nodes")):
        context = f"topology.nodes[{index}]"
        node = expect_object(raw, context)
        exact_keys(node, ("id", "label", "role", "trust_boundary", "networks", "position"), (), context)
        node_ids.append(expect_string(node["id"], f"{context}.id", identifier=True))
        expect_string(node["label"], f"{context}.label")
        expect_string(node["role"], f"{context}.role")
        boundary = expect_string(node["trust_boundary"], f"{context}.trust_boundary", identifier=True)
        if boundary not in boundary_ids:
            fail(f"{context}.trust_boundary", "is not declared")
        memberships = [expect_string(item, f"{context}.networks[{item_index}]", identifier=True) for item_index, item in enumerate(expect_list(node["networks"], f"{context}.networks"))]
        require_unique(memberships, f"{context}.networks")
        unknown = sorted(set(memberships) - set(network_ids))
        if unknown:
            fail(f"{context}.networks", f"unknown networks: {', '.join(unknown)}")
        position = expect_object(node["position"], f"{context}.position")
        exact_keys(position, ("x", "y"), (), f"{context}.position")
        if not all(isinstance(position[axis], int) and not isinstance(position[axis], bool) for axis in ("x", "y")):
            fail(f"{context}.position", "x and y must be integers")
    require_unique(node_ids, "topology node ids")
    if set(node_ids) != EXPECTED_NODES:
        fail("topology.nodes", f"must describe exactly the seven pilot nodes: {', '.join(sorted(EXPECTED_NODES))}")

    nodes_by_id = {node["id"]: node for node in topology["nodes"]}
    edge_ids: list[str] = []
    for index, raw in enumerate(expect_list(topology["edges"], "topology.edges")):
        context = f"topology.edges[{index}]"
        edge = expect_object(raw, context)
        exact_keys(edge, ("id", "from", "to", "network", "protocol", "ports", "authentication", "purpose"), (), context)
        edge_ids.append(expect_string(edge["id"], f"{context}.id", identifier=True))
        source = expect_string(edge["from"], f"{context}.from", identifier=True)
        target = expect_string(edge["to"], f"{context}.to", identifier=True)
        network = expect_string(edge["network"], f"{context}.network", identifier=True)
        if source not in nodes_by_id or target not in nodes_by_id:
            fail(context, "edge endpoint is not a topology node")
        if network not in network_ids:
            fail(f"{context}.network", "is not declared")
        if network not in nodes_by_id[source]["networks"] or network not in nodes_by_id[target]["networks"]:
            fail(context, "both edge endpoints must attach to the selected network")
        expect_string(edge["protocol"], f"{context}.protocol")
        expect_string(edge["authentication"], f"{context}.authentication")
        expect_string(edge["purpose"], f"{context}.purpose")
        ports = expect_list(edge["ports"], f"{context}.ports")
        if not ports or any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            fail(f"{context}.ports", "must contain valid fixed transport ports")
        require_unique(ports, f"{context}.ports")
    require_unique(edge_ids, "topology edge ids")

    delegation = expect_object(topology["delegation"], "topology.delegation")
    exact_keys(delegation, ("parent", "zone", "nameservers", "hidden_origins"), (), "topology.delegation")
    if delegation["parent"] != "parent" or delegation["zone"] != topology["zone"]:
        fail("topology.delegation", "parent and zone must match the simulated topology")
    if set(expect_list(delegation["nameservers"], "topology.delegation.nameservers")) != {"public-a", "public-b"}:
        fail("topology.delegation.nameservers", "must name only public-a and public-b")
    if set(expect_list(delegation["hidden_origins"], "topology.delegation.hidden_origins")) != {"p0", "p1"}:
        fail("topology.delegation.hidden_origins", "must identify p0 and p1")
    if set(delegation["nameservers"]) & set(delegation["hidden_origins"]):
        fail("topology.delegation", "hidden origins cannot be delegated nameservers")
    return topology


def read_events(path: Path, node_ids: set[str], evidence_paths: set[str]) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReportError(f"events: cannot read JSON Lines: {exc}") from exc
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line, parse_constant=lambda constant: fail(f"events line {line_number}", f"invalid number {constant}"))
        except json.JSONDecodeError as exc:
            raise ReportError(f"events line {line_number}: invalid JSON: {exc}") from exc
        event = expect_object(normalize_and_scan(raw, f"events[{line_number}]"), f"events[{line_number}]")
        exact_keys(event, ("sequence", "event", "phase", "actor", "summary", "evidence"), (), f"events[{line_number}]")
        if isinstance(event["sequence"], bool) or not isinstance(event["sequence"], int) or event["sequence"] < 1:
            fail(f"events[{line_number}].sequence", "must be a positive integer")
        expect_string(event["event"], f"events[{line_number}].event", identifier=True)
        expect_string(event["phase"], f"events[{line_number}].phase", identifier=True)
        actor = expect_string(event["actor"], f"events[{line_number}].actor", identifier=True)
        if actor not in node_ids | {"test-driver"}:
            fail(f"events[{line_number}].actor", "must be a topology node or test-driver")
        expect_string(event["summary"], f"events[{line_number}].summary")
        refs = [checked_evidence_path(item, f"events[{line_number}].evidence") for item in expect_list(event["evidence"], f"events[{line_number}].evidence")]
        require_unique(refs, f"events[{line_number}].evidence")
        missing = sorted(set(refs) - evidence_paths)
        if missing:
            fail(f"events[{line_number}].evidence", f"missing evidence files: {', '.join(missing)}")
        events.append(event)
    events.sort(key=lambda item: item["sequence"])
    sequences = [item["sequence"] for item in events]
    if sequences != list(range(1, len(events) + 1)):
        fail("events.sequence", "must be unique and contiguous beginning at 1")
    return events


def collect_evidence(root: Path) -> dict[str, str]:
    return collect_text_tree(root, "evidence")


def collect_text_tree(root: Path, prefix: str) -> dict[str, str]:
    if not root.is_dir():
        fail(prefix, f"directory does not exist: {root}")
    collected: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            fail(prefix, f"symbolic links are not allowed: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(prefix, f"unsupported filesystem entry: {path}")
        relative = path.relative_to(root).as_posix()
        output_name = f"{prefix}/{relative}"
        if prefix == "evidence":
            checked_evidence_path(output_name, "evidence path")
        elif not re.fullmatch(r"zones/[A-Za-z0-9._/-]+", output_name) or PurePosixPath(output_name).as_posix() != output_name or ".." in PurePosixPath(output_name).parts:
            fail(f"{prefix} path", "must be a safe path containing only portable filename characters")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ReportError(f"{prefix}/{relative}: must be readable UTF-8 text: {exc}") from exc
        if "\x00" in content:
            fail(f"{prefix}/{relative}", "binary content is not allowed")
        content = normalize_string(content)
        content = "\n".join(line.rstrip() for line in content.split("\n")).rstrip("\n")
        if content:
            content += "\n"
        for pattern in FORBIDDEN_TEXT:
            if pattern.search(content):
                fail(f"{prefix}/{relative}", "contains a secret or non-deterministic value")
        collected[output_name] = content
    return collected


def canonicalize_result(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    for assertion in result["assertions"]:
        assertion["evidence"] = sorted(assertion["evidence"])
    result["assertions"].sort(key=lambda item: item["id"])
    for category in ("exercised", "simulated", "deferred"):
        for claim in result["claims"][category]:
            if "assertions" in claim:
                claim["assertions"] = sorted(claim["assertions"])
        result["claims"][category].sort(key=lambda item: item["id"])
    result["serials"].sort(key=lambda item: (item["phase"], item["server"]))
    for answer in result["answers"]:
        answer["values"] = sorted(answer["values"])
    result["answers"].sort(key=lambda item: (item["phase"], item["server"], item["name"], item["type"], item.get("transport", "")))
    return result


def canonicalize_provisioning(value: dict[str, Any]) -> dict[str, Any]:
    provisioning = copy.deepcopy(value)
    for check in provisioning["automated"]["checks"]:
        check["evidence"] = sorted(check["evidence"])
    provisioning["automated"]["checks"].sort(key=lambda item: (item["id"], item["system"]))
    provisioning["hardware_qualification"]["evidence"] = sorted(
        provisioning["hardware_qualification"]["evidence"]
    )
    return provisioning


def canonicalize_topology(value: dict[str, Any]) -> dict[str, Any]:
    topology = copy.deepcopy(value)
    topology["networks"].sort(key=lambda item: item["id"])
    topology["trust_boundaries"].sort(key=lambda item: item["id"])
    for node in topology["nodes"]:
        node["networks"] = sorted(node["networks"])
    topology["nodes"].sort(key=lambda item: item["id"])
    for edge in topology["edges"]:
        edge["ports"] = sorted(edge["ports"])
    topology["edges"].sort(key=lambda item: item["id"])
    topology["delegation"]["nameservers"] = sorted(topology["delegation"]["nameservers"])
    topology["delegation"]["hidden_origins"] = sorted(topology["delegation"]["hidden_origins"])
    return topology


def json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def compact(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def md_cell(value: Any) -> str:
    return compact(value).replace("|", "\\|").replace("\n", "<br>")


def evidence_links(paths: list[str], *, markdown: bool) -> str:
    if not paths:
        return "—"
    if markdown:
        return ", ".join(f"[{PurePosixPath(path).name}]({path})" for path in paths)
    return ", ".join(f'<a href="{html.escape(path, quote=True)}">{html.escape(PurePosixPath(path).name)}</a>' for path in paths)


def render_markdown(
    result: dict[str, Any],
    provisioning: dict[str, Any],
    events: list[dict[str, Any]],
    topology: dict[str, Any],
    evidence: dict[str, str],
    zones: dict[str, str],
) -> str:
    passed = sum(item["status"] == "passed" for item in result["assertions"])
    failed = len(result["assertions"]) - passed
    provisioning_checks = provisioning["automated"]["checks"]
    provisioning_passed = sum(item["status"] == "passed" for item in provisioning_checks)
    provisioning_failed = sum(item["status"] == "failed" for item in provisioning_checks)
    provisioning_unobserved = sum(item["status"] == "not-observed" for item in provisioning_checks)
    hardware = provisioning["hardware_qualification"]
    lines = [
        "# Kaiba pilot validation report",
        "",
        f"**DNS topology:** {result['overall'].upper()} — {passed} passed, {failed} failed.",
        "",
        f"**Provisioning automation:** {provisioning['automated']['overall'].upper()} — {provisioning_passed} passed, {provisioning_failed} failed, {provisioning_unobserved} not observed.",
        "",
        f"**Hardware qualification:** {hardware['status'].upper()}.",
        "",
        f"The test zone `{topology['zone']}` simulates the production zone `{topology['production_analogue']}`. No external DNS service was contacted or modified.",
        "",
        "![Test topology](topology.svg)",
        "",
        "## Assertions",
        "",
        "| Status | Phase | Assertion | Expected | Observed | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for item in result["assertions"]:
        lines.append(f"| {item['status'].upper()} | {md_cell(item['phase'])} | {md_cell(item['description'])} | {md_cell(item['expected'])} | {md_cell(item['observed'])} | {evidence_links(item['evidence'], markdown=True)} |")

    lines.extend([
        "",
        "## Provisioning probe validation",
        "",
        "Automated provisioning checks are reported independently from the DNS topology suite.",
        "",
        "| Status | System | Check | Description | Source revision | Evidence |",
        "|---|---|---|---|---|---|",
    ])
    for item in provisioning_checks:
        revision = f"`{item['source_revision']}`" if "source_revision" in item else "—"
        lines.append(
            f"| {item['status'].replace('-', ' ').upper()} | `{item['system']}` | `{item['id']}` | "
            f"{md_cell(item['description'])} | {revision} | {evidence_links(item['evidence'], markdown=True)} |"
        )
    lines.extend([
        "",
        "### Hardware qualification",
        "",
        f"**Status: {hardware['status'].upper()}.** {hardware['description']}",
        "",
        f"Evidence: {evidence_links(hardware['evidence'], markdown=True)}",
        "",
        "Hardware qualification is a separate manual gate. It is not included in the DNS overall status, automated provisioning status, or JUnit output.",
        "",
        "`mutation_eligible` remains `false`; these results do not authorize irreversible provisioning.",
        "The automated checks do not execute physical recovery firmware and do not establish device authentication, attestation, or the full unprovisioned state.",
    ])

    lines.extend(["", "## Claims", ""])
    for category in ("exercised", "simulated", "deferred"):
        lines.extend([f"### {category.title()}", ""])
        entries = result["claims"][category]
        if not entries:
            lines.extend(["None.", ""])
            continue
        for claim in entries:
            references = f" Assertions: {', '.join(f'`{item}`' for item in claim['assertions'])}." if "assertions" in claim else ""
            lines.append(f"- `{claim['id']}` — {claim['statement']}{references}")
        lines.append("")

    lines.extend([
        "## Ordered events",
        "",
        "| Sequence | Phase | Actor | Event | Summary | Evidence |",
        "|---:|---|---|---|---|---|",
    ])
    for event in events:
        lines.append(f"| {event['sequence']} | {md_cell(event['phase'])} | {md_cell(event['actor'])} | {md_cell(event['event'])} | {md_cell(event['summary'])} | {evidence_links(event['evidence'], markdown=True)} |")

    lines.extend([
        "",
        "## SOA serial progression",
        "",
        "| Phase | Server | Serial |",
        "|---|---|---:|",
    ])
    for item in result["serials"]:
        lines.append(f"| {md_cell(item['phase'])} | {md_cell(item['server'])} | {item['serial']} |")
    if not result["serials"]:
        lines.append("| — | — | — |")

    lines.extend([
        "",
        "## DNS and HTTPS observations",
        "",
        "| Phase | Observer | Transport | Name | Type | Values | Authoritative |",
        "|---|---|---|---|---|---|---|",
    ])
    for item in result["answers"]:
        lines.append(f"| {md_cell(item['phase'])} | {md_cell(item['server'])} | {md_cell(item.get('transport', '—'))} | {md_cell(item['name'])} | {md_cell(item['type'])} | {md_cell(item['values'])} | {'yes' if item['authoritative'] else 'no'} |")
    if not result["answers"]:
        lines.append("| — | — | — | — | — | — | — |")

    lines.extend([
        "",
        "## Topology and trust boundaries",
        "",
        "| Node | Role | Trust boundary | Networks |",
        "|---|---|---|---|",
    ])
    for node in topology["nodes"]:
        lines.append(f"| `{node['id']}` | {md_cell(node['role'])} | `{node['trust_boundary']}` | {', '.join(f'`{item}`' for item in node['networks'])} |")
    lines.extend([
        "",
        "| From → to | Network | Protocol / ports | Authentication | Purpose |",
        "|---|---|---|---|---|",
    ])
    for edge in topology["edges"]:
        ports = ", ".join(str(port) for port in edge["ports"])
        lines.append(f"| `{edge['from']}` → `{edge['to']}` | `{edge['network']}` | {md_cell(edge['protocol'])} / {ports} | {md_cell(edge['authentication'])} | {md_cell(edge['purpose'])} |")

    lines.extend(["", "## Evidence inventory", ""])
    if evidence:
        lines.extend(f"- [{path}]({path})" for path in sorted(evidence))
    else:
        lines.append("No evidence files were recorded.")
    lines.extend(["", "## Zone snapshot inventory", ""])
    if zones:
        lines.extend(f"- [{path}]({path})" for path in sorted(zones))
    else:
        lines.append("No zone snapshots were recorded.")
    lines.extend([
        "",
        "## Reproducibility",
        "",
        "This report contains no generation timestamp, process identifier, elapsed time, DNS transaction identifier, ephemeral source port, or credential material. `manifest.sha256` covers every generated file except itself.",
        "",
    ])
    return "\n".join(lines)


def html_table(headers: list[str], rows: Iterable[list[str]]) -> str:
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def h(value: Any) -> str:
    return html.escape(compact(value))


def status_class(status: str) -> str:
    if status == "passed":
        return "pass"
    if status == "failed":
        return "fail"
    return "partial"


def render_html(
    result: dict[str, Any],
    provisioning: dict[str, Any],
    events: list[dict[str, Any]],
    topology: dict[str, Any],
    evidence: dict[str, str],
    zones: dict[str, str],
) -> str:
    passed = sum(item["status"] == "passed" for item in result["assertions"])
    failed = len(result["assertions"]) - passed
    dns_status_class = "pass" if result["overall"] == "passed" else "fail"
    provisioning_checks = provisioning["automated"]["checks"]
    provisioning_passed = sum(item["status"] == "passed" for item in provisioning_checks)
    provisioning_failed = sum(item["status"] == "failed" for item in provisioning_checks)
    provisioning_unobserved = sum(item["status"] == "not-observed" for item in provisioning_checks)
    hardware = provisioning["hardware_qualification"]
    assertion_rows = [
        [f'<strong class="{item["status"][:-2] if item["status"] == "passed" else "fail"}">{html.escape(item["status"].upper())}</strong>', h(item["phase"]), h(item["description"]), f"<code>{h(item['expected'])}</code>", f"<code>{h(item['observed'])}</code>", evidence_links(item["evidence"], markdown=False)]
        for item in result["assertions"]
    ]
    event_rows = [[str(item["sequence"]), h(item["phase"]), h(item["actor"]), h(item["event"]), h(item["summary"]), evidence_links(item["evidence"], markdown=False)] for item in events]
    serial_rows = [[h(item["phase"]), h(item["server"]), str(item["serial"])] for item in result["serials"]]
    answer_rows = [[h(item["phase"]), h(item["server"]), h(item.get("transport", "—")), h(item["name"]), h(item["type"]), f"<code>{h(item['values'])}</code>", "yes" if item["authoritative"] else "no"] for item in result["answers"]]
    node_rows = [[f"<code>{h(item['id'])}</code>", h(item["role"]), f"<code>{h(item['trust_boundary'])}</code>", ", ".join(f"<code>{h(network)}</code>" for network in item["networks"])] for item in topology["nodes"]]
    edge_rows = [[f"<code>{h(item['from'])}</code> → <code>{h(item['to'])}</code>", f"<code>{h(item['network'])}</code>", f"{h(item['protocol'])} / {', '.join(str(port) for port in item['ports'])}", h(item["authentication"]), h(item["purpose"])] for item in topology["edges"]]
    provisioning_rows = [
        [
            f'<strong class="{status_class(item["status"])}">{html.escape(item["status"].replace("-", " ").upper())}</strong>',
            f"<code>{h(item['system'])}</code>",
            f"<code>{h(item['id'])}</code>",
            h(item["description"]),
            f"<code>{h(item['source_revision'])}</code>" if "source_revision" in item else "—",
            evidence_links(item["evidence"], markdown=False),
        ]
        for item in provisioning_checks
    ]

    claim_sections: list[str] = []
    for category in ("exercised", "simulated", "deferred"):
        items = result["claims"][category]
        rendered = "".join(f"<li><code>{h(item['id'])}</code> — {h(item['statement'])}" + (f" <small>Assertions: {', '.join(f'<code>{h(ref)}</code>' for ref in item['assertions'])}</small>" if "assertions" in item else "") + "</li>" for item in items)
        claim_sections.append(f"<h3>{html.escape(category.title())}</h3><ul>{rendered or '<li>None.</li>'}</ul>")

    evidence_items = "".join(f'<li><a href="{html.escape(path, quote=True)}">{html.escape(path)}</a></li>' for path in sorted(evidence)) or "<li>No evidence files were recorded.</li>"
    zone_items = "".join(f'<li><a href="{html.escape(path, quote=True)}">{html.escape(path)}</a></li>' for path in sorted(zones)) or "<li>No zone snapshots were recorded.</li>"
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kaiba pilot validation report</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; }}
body {{ max-width: 1180px; margin: 2rem auto; padding: 0 1rem 4rem; color: #172033; }}
h1, h2, h3 {{ color: #102a43; }}
.summary {{ border-left: .45rem solid #64748b; background: #f8fafc; padding: 1rem 1.25rem; }}
.summary.pass {{ border-color: #15803d; }} .summary.fail {{ border-color: #b91c1c; }} .summary.partial {{ border-color: #a16207; }}
.pass {{ color: #15803d; }} .fail {{ color: #b91c1c; }} .partial {{ color: #a16207; }}
table {{ width: 100%; border-collapse: collapse; margin: .75rem 0 1.5rem; font-size: .92rem; }}
th, td {{ border: 1px solid #cbd5e1; padding: .45rem .55rem; text-align: left; vertical-align: top; }}
th {{ background: #e2e8f0; }} tr:nth-child(even) {{ background: #f8fafc; }}
code {{ overflow-wrap: anywhere; }} img {{ max-width: 100%; height: auto; border: 1px solid #cbd5e1; }}
</style>
</head>
<body>
<h1>Kaiba pilot validation report</h1>
<p class="summary {dns_status_class}"><strong>DNS topology: {html.escape(result['overall'].upper())}</strong> — {passed} passed, {failed} failed.</p>
<p class="summary {status_class(provisioning['automated']['overall'])}"><strong>Provisioning automation: {html.escape(provisioning['automated']['overall'].upper())}</strong> — {provisioning_passed} passed, {provisioning_failed} failed, {provisioning_unobserved} not observed.</p>
<p class="summary {status_class(hardware['status'])}"><strong>Hardware qualification: {html.escape(hardware['status'].upper())}</strong></p>
<p>The test zone <code>{h(topology['zone'])}</code> simulates <code>{h(topology['production_analogue'])}</code>. No external DNS service was contacted or modified.</p>
<img src="topology.svg" alt="Seven-node DNS pilot topology">
<h2>Assertions</h2>
{html_table(['Status', 'Phase', 'Assertion', 'Expected', 'Observed', 'Evidence'], assertion_rows)}
<h2>Provisioning probe validation</h2>
<p>Automated provisioning checks are reported independently from the DNS topology suite.</p>
{html_table(['Status', 'System', 'Check', 'Description', 'Source revision', 'Evidence'], provisioning_rows)}
<h3>Hardware qualification</h3>
<p><strong class="{status_class(hardware['status'])}">Status: {html.escape(hardware['status'].upper())}.</strong> {h(hardware['description'])}</p>
<p>Evidence: {evidence_links(hardware['evidence'], markdown=False)}</p>
<p>Hardware qualification is a separate manual gate. It is not included in the DNS overall status, automated provisioning status, or JUnit output.</p>
<p><code>mutation_eligible</code> remains <code>false</code>; these results do not authorize irreversible provisioning.</p>
<p>The automated checks do not execute physical recovery firmware and do not establish device authentication, attestation, or the full unprovisioned state.</p>
<h2>Claims</h2>
{''.join(claim_sections)}
<h2>Ordered events</h2>
{html_table(['Sequence', 'Phase', 'Actor', 'Event', 'Summary', 'Evidence'], event_rows)}
<h2>SOA serial progression</h2>
{html_table(['Phase', 'Server', 'Serial'], serial_rows)}
<h2>DNS and HTTPS observations</h2>
{html_table(['Phase', 'Observer', 'Transport', 'Name', 'Type', 'Values', 'Authoritative'], answer_rows)}
<h2>Topology and trust boundaries</h2>
{html_table(['Node', 'Role', 'Trust boundary', 'Networks'], node_rows)}
{html_table(['From → to', 'Network', 'Protocol / ports', 'Authentication', 'Purpose'], edge_rows)}
<h2>Evidence inventory</h2><ul>{evidence_items}</ul>
<h2>Zone snapshot inventory</h2><ul>{zone_items}</ul>
<h2>Reproducibility</h2>
<p>This report contains no generation timestamp, process identifier, elapsed time, DNS transaction identifier, ephemeral source port, or credential material. <code>manifest.sha256</code> covers every generated file except itself.</p>
</body>
</html>
"""
    return document


def dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_dot(topology: dict[str, Any]) -> str:
    lines = [
        "digraph kaiba_dns_pilot {",
        "  graph [layout=neato, overlap=false, outputorder=edgesfirst, bgcolor=white];",
        '  node [shape=box, style="rounded,filled", color="#475569", fontname="sans-serif"];',
        '  edge [fontname="sans-serif", fontsize=8, arrowsize=0.7];',
    ]
    for node in topology["nodes"]:
        position = node["position"]
        fill = BOUNDARY_COLOURS.get(node["trust_boundary"], "#f8fafc")
        label = f"{node['label']}\n{node['trust_boundary']}"
        lines.append(f'  "{dot_escape(node["id"])}" [label="{dot_escape(label)}", fillcolor="{fill}", pos="{position["x"]},{-position["y"]}!"];')
    for edge in topology["edges"]:
        colour = NETWORK_COLOURS.get(edge["network"], "#475569")
        ports = ",".join(str(port) for port in edge["ports"])
        label = f"{edge['network']} | {edge['protocol']}:{ports}"
        lines.append(f'  "{dot_escape(edge["from"])}" -> "{dot_escape(edge["to"])}" [id="{dot_escape(edge["id"])}", label="{dot_escape(label)}", color="{colour}", fontcolor="{colour}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def svg_text(x: int, y: int, value: str, css_class: str = "") -> str:
    class_attr = f' class="{css_class}"' if css_class else ""
    return f'<text x="{x}" y="{y}"{class_attr}>{html.escape(value)}</text>'


def render_svg(topology: dict[str, Any]) -> str:
    width, height = 820, 620
    node_width, node_height = 150, 58
    nodes = {item["id"]: item for item in topology["nodes"]}
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title description">',
        '<title id="title">Kaiba DNS pilot integration topology</title>',
        '<desc id="description">Seven virtual machines connected across isolated query, transfer, and update networks.</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="context-stroke"/></marker></defs>',
        '<style>text{font-family:system-ui,sans-serif;fill:#172033}.node{stroke:#475569;stroke-width:1.5}.label{font-size:13px;font-weight:700;text-anchor:middle}.boundary{font-size:9px;text-anchor:middle;fill:#475569}.edge{fill:none;stroke-width:1.7;marker-end:url(#arrow)}.edge-label{font-size:8px;text-anchor:middle;paint-order:stroke;stroke:white;stroke-width:3px;stroke-linejoin:round}.legend{font-size:10px}.title{font-size:18px;font-weight:700}</style>',
        svg_text(20, 28, topology["title"], "title"),
    ]
    for edge in topology["edges"]:
        source = nodes[edge["from"]]["position"]
        target = nodes[edge["to"]]["position"]
        colour = NETWORK_COLOURS.get(edge["network"], "#475569")
        title = html.escape(f"{edge['protocol']} on {edge['network']}; {edge['authentication']}; {edge['purpose']}")
        if edge["from"] == edge["to"]:
            x, y = source["x"], source["y"]
            path = f"M{x + 55},{y - 15} C{x + 105},{y - 70} {x - 105},{y - 70} {x - 55},{y - 15}"
            label_x, label_y = x, y - 52
        else:
            x1, y1, x2, y2 = source["x"], source["y"], target["x"], target["y"]
            path = f"M{x1},{y1} L{x2},{y2}"
            label_x, label_y = (x1 + x2) // 2, (y1 + y2) // 2 - 5
        parts.append(f'<g><title>{title}</title><path class="edge" d="{path}" stroke="{colour}"/><text x="{label_x}" y="{label_y}" class="edge-label" fill="{colour}">{html.escape(edge["network"])}</text></g>')
    for node in topology["nodes"]:
        x, y = node["position"]["x"], node["position"]["y"]
        fill = BOUNDARY_COLOURS.get(node["trust_boundary"], "#f8fafc")
        title = html.escape(f"{node['role']}; networks: {', '.join(node['networks'])}")
        parts.extend([
            f'<g><title>{title}</title><rect class="node" x="{x - node_width // 2}" y="{y - node_height // 2}" width="{node_width}" height="{node_height}" rx="8" fill="{fill}"/>',
            svg_text(x, y - 3, node["label"], "label"),
            svg_text(x, y + 15, node["trust_boundary"], "boundary"),
            "</g>",
        ])
    parts.append('<g transform="translate(20 548)">')
    for index, network in enumerate(sorted(topology["networks"], key=lambda item: item["id"])):
        x = index * 195
        colour = NETWORK_COLOURS.get(network["id"], "#475569")
        prefix = f"VLAN {network['vlan']}" if network["kind"] == "vlan" else "Local"
        parts.append(f'<line x1="{x}" y1="0" x2="{x + 24}" y2="0" stroke="{colour}" stroke-width="3"/>{svg_text(x + 30, 4, f"{prefix}: {network['id']}", "legend")}')
    parts.extend(["</g>", "</svg>", ""])
    return "\n".join(parts)


def render_junit(result: dict[str, Any], provisioning: dict[str, Any]) -> bytes:
    dns_failures = sum(item["status"] == "failed" for item in result["assertions"])
    provisioning_checks = provisioning["automated"]["checks"]
    provisioning_failures = sum(item["status"] == "failed" for item in provisioning_checks)
    provisioning_skipped = sum(item["status"] == "not-observed" for item in provisioning_checks)
    total = len(result["assertions"]) + len(provisioning_checks)
    root = ET.Element(
        "testsuites",
        {
            "name": "kaiba-pilot-validation",
            "tests": str(total),
            "failures": str(dns_failures + provisioning_failures),
            "errors": "0",
            "skipped": str(provisioning_skipped),
        },
    )
    suite = ET.SubElement(
        root,
        "testsuite",
        {
            "name": SUITE,
            "tests": str(len(result["assertions"])),
            "failures": str(dns_failures),
            "errors": "0",
            "skipped": "0",
        },
    )
    for item in result["assertions"]:
        case = ET.SubElement(suite, "testcase", {"classname": item["phase"], "name": item["id"]})
        if item["status"] == "failed":
            failure = ET.SubElement(case, "failure", {"message": item["description"], "type": "assertion"})
            failure.text = f"Expected: {compact(item['expected'])}\nObserved: {compact(item['observed'])}"
        output = ET.SubElement(case, "system-out")
        output.text = "Evidence: " + (", ".join(item["evidence"]) if item["evidence"] else "none")

    provisioning_suite = ET.SubElement(
        root,
        "testsuite",
        {
            "name": PROVISIONING_SUITE,
            "tests": str(len(provisioning_checks)),
            "failures": str(provisioning_failures),
            "errors": "0",
            "skipped": str(provisioning_skipped),
        },
    )
    for item in provisioning_checks:
        case = ET.SubElement(
            provisioning_suite,
            "testcase",
            {"classname": f"provisioning.{item['system']}", "name": item["id"]},
        )
        if item["status"] == "failed":
            failure = ET.SubElement(case, "failure", {"message": item["description"], "type": "automated-check"})
            failure.text = f"Automated provisioning check failed on {item['system']}"
        elif item["status"] == "not-observed":
            ET.SubElement(case, "skipped", {"message": "not observed on this platform"})
        output = ET.SubElement(case, "system-out")
        revision = item.get("source_revision", "not recorded")
        evidence_text = ", ".join(item["evidence"]) if item["evidence"] else "none"
        output.text = f"Source revision: {revision}\nEvidence: {evidence_text}"
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True, short_empty_elements=True) + b"\n"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_manifest(output: Path) -> None:
    entries: list[str] = []
    for path in sorted(output.rglob("*"), key=lambda item: item.relative_to(output).as_posix()):
        if not path.is_file() or path.name == "manifest.sha256":
            continue
        relative = path.relative_to(output).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {relative}")
    write_text(output / "manifest.sha256", "\n".join(entries) + "\n")


def prepare_output(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        existing = list(path.iterdir())
    except OSError as exc:
        raise ReportError(f"output: cannot prepare directory: {exc}") from exc
    if existing:
        fail("output", "directory must be empty so stale files cannot enter the report")


def render(
    result_path: Path,
    events_path: Path,
    evidence_root: Path,
    topology_path: Path,
    output: Path,
    schema_path: Path | None = None,
    zones_root: Path | None = None,
    provisioning_path: Path | None = None,
    provisioning_schema_path: Path | None = None,
    platform_result_paths: Iterable[Path] = (),
    expected_source_revision: str | None = None,
) -> None:
    output_resolved = output.resolve()
    evidence_resolved = evidence_root.resolve()
    if output_resolved == evidence_resolved or output_resolved in evidence_resolved.parents or evidence_resolved in output_resolved.parents:
        fail("output", "must not overlap the input evidence directory")
    if zones_root is not None:
        zones_resolved = zones_root.resolve()
        if output_resolved == zones_resolved or output_resolved in zones_resolved.parents or zones_resolved in output_resolved.parents:
            fail("output", "must not overlap the input zones directory")
    prepare_output(output)

    evidence = collect_evidence(evidence_root)
    zones = collect_text_tree(zones_root, "zones") if zones_root is not None else {}
    topology = canonicalize_topology(validate_topology(normalize_and_scan(load_json(topology_path, "topology"), "topology")))
    node_ids = {item["id"] for item in topology["nodes"]}
    raw_result = normalize_and_scan(load_json(result_path, "result"), "result")
    result = canonicalize_result(validate_result(raw_result, node_ids, set(evidence)))
    events = read_events(events_path, node_ids, set(evidence))
    schema_source = schema_path or Path(__file__).with_name("result.schema.json")
    schema = normalize_and_scan(load_json(schema_source, "result schema"), "result_schema")
    if provisioning_path is None:
        fail("provisioning", "a provisioning result is required")
    if provisioning_schema_path is None:
        fail("provisioning schema", "a provisioning schema is required")
    raw_provisioning = normalize_and_scan(
        load_json(provisioning_path, "provisioning"),
        "provisioning",
    )
    provisioning = validate_provisioning(raw_provisioning, set(evidence))
    receipts = [
        validate_platform_result(
            normalize_and_scan(load_json(path, f"provisioning platform result {index}"), "provisioning_platform_result"),
            set(evidence),
            require_source_revision=True,
        )
        for index, path in enumerate(platform_result_paths)
    ]
    provisioning = canonicalize_provisioning(
        validate_provisioning(
            merge_platform_results(provisioning, receipts, expected_source_revision),
            set(evidence),
        )
    )
    provisioning_schema = normalize_and_scan(
        load_json(provisioning_schema_path, "provisioning schema"),
        "provisioning_schema",
    )

    write_text(output / "result.json", json_text(result))
    write_text(output / "result.schema.json", json_text(schema))
    write_text(output / "provisioning.json", json_text(provisioning))
    write_text(output / "provisioning.schema.json", json_text(provisioning_schema))
    write_text(output / "topology.json", json_text(topology))
    write_text(output / "events.jsonl", "".join(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n" for item in events))
    for relative, content in sorted(evidence.items()):
        write_text(output / relative, content)
    for relative, content in sorted(zones.items()):
        write_text(output / relative, content)
    write_text(output / "topology.dot", render_dot(topology))
    write_text(output / "topology.svg", render_svg(topology))
    write_text(output / "index.md", render_markdown(result, provisioning, events, topology, evidence, zones))
    write_text(output / "index.html", render_html(result, provisioning, events, topology, evidence, zones))
    (output / "junit.xml").write_bytes(render_junit(result, provisioning))
    write_manifest(output)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True, help="canonical result JSON")
    parser.add_argument("--events", type=Path, required=True, help="ordered JSON Lines event log")
    parser.add_argument("--evidence", type=Path, required=True, help="directory of normalized UTF-8 evidence")
    parser.add_argument("--topology", type=Path, required=True, help="seven-node topology manifest")
    parser.add_argument("--schema", type=Path, help="result schema (defaults to the file beside this script)")
    parser.add_argument("--provisioning", type=Path, required=True, help="canonical provisioning validation JSON")
    parser.add_argument("--provisioning-schema", type=Path, required=True, help="provisioning result schema")
    parser.add_argument(
        "--provisioning-platform-result",
        type=Path,
        action="append",
        default=[],
        help="strict per-platform result receipt; may be repeated",
    )
    parser.add_argument(
        "--expected-source-revision",
        help="require every platform receipt to match this lowercase 40- or 64-hex revision",
    )
    parser.add_argument("--zones", type=Path, help="optional directory of normalized authoritative zone snapshots")
    parser.add_argument("--output", type=Path, required=True, help="new or empty report directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        render(
            args.result,
            args.events,
            args.evidence,
            args.topology,
            args.output,
            args.schema,
            args.zones,
            args.provisioning,
            args.provisioning_schema,
            args.provisioning_platform_result,
            args.expected_source_revision,
        )
    except ReportError as exc:
        print(f"report error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
