#!/usr/bin/env python3
"""Validate the assembled GitHub Pages product site and canonical report tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
CSS_URL = re.compile(r"url\(\s*(['\"]?)([^)'\"]+)\1\s*\)")
PROVISIONING_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
EVIDENCE_PATH = re.compile(r"^evidence/[A-Za-z0-9._/-]+$")
ALLOWED_EXTERNAL_SCHEMES = {"http", "https", "mailto"}
STATION_STATE_SCHEMA = "provisioning.kaiba.network/station-demo-state/v1alpha2"
STATION_EXPORT_SCHEMA = "provisioning.kaiba.network/station-demo-export/v1alpha2"
STATION_SAFETY_FALSE_FIELDS = {
    "mutation_eligible",
    "live_target_access",
    "live_mutation_capable",
    "authoritative_evidence",
    "secrets_present",
    "approval_authority",
    "signing_capable",
    "enrollment_capable",
}
STATION_SAFETY_FIELDS = STATION_SAFETY_FALSE_FIELDS | {
    "simulation",
    "full_unprovisioned_state",
    "disclaimer",
}
STATION_LIFECYCLES = {
    "unregistered",
    "qualified_fresh_candidate",
    "prepared",
    "commit_in_progress",
    "security_applied",
    "enrollment_ready",
    "owned_quarantined",
}
STATION_TRANSACTION_STATUSES = {
    "created",
    "target_bound",
    "preflight_passed",
    "commit_approved",
    "trust_established",
    "security_applied",
    "aborted",
    "quarantined",
}
STATION_WORKFLOW_STATUSES = {"pending", "current", "complete", "failed"}
STATION_WORKFLOW_STAGE_IDS = [
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
]
STATION_ACTION_CLASSIFICATIONS = {
    "administrative",
    "read_only",
    "reversible",
    "authorization_affecting",
    "irreversible",
}
STATION_EVIDENCE_STATUSES = {"pending", "passed", "failed", "recorded"}
STATION_OUTCOME_STATUSES = {"aborted", "owned_quarantined", "enrollment_ready"}
STATION_REQUIRED_OPERATOR_ACTIONS = {
    "run_station_admission",
    "create_transaction",
    "attach_target",
    "run_first_probe",
    "disconnect_target",
    "reconnect_target",
    "run_second_probe",
    "confirm_boot_ok",
    "confirm_boot_failed",
    "close_deferred_baseline",
    "prepare_transaction",
    "request_commit_approval",
    "establish_initial_trust",
    "reidentify_commit_target",
    "record_commit_intent",
    "execute_commit",
    "observe_commit_readback",
    "power_off_owned_target",
    "confirm_signed_boot",
    "run_owned_readback",
    "test_owned_recovery",
    "rerun_owned_readback",
    "test_negative_boot",
    "test_root_integrity",
    "test_rollback",
    "request_finalization_approval",
    "record_finalization_intent",
    "apply_final_controls",
    "cold_restart_finalized_target",
    "observe_final_controls_readback",
    "run_final_retest",
    "reconcile_audit",
    "mark_enrollment_ready",
    "export_redacted",
    "reset",
}
STATION_FORBIDDEN_SECRET_KEYS = {
    "private_key",
    "private_key_pem",
    "signing_key",
    "shared_secret",
    "enrollment_secret",
    "password",
    "credential",
    "access_token",
}
REQUIRED_PATHS = (
    "index.html",
    "styles.css",
    "site.js",
    "dns/index.html",
    "provisioning/index.html",
    "provisioning-demo/index.html",
    "provisioning-demo/styles.css",
    "provisioning-demo/transport.js",
    "provisioning-demo/app.js",
    "provisioning-demo/runtime-config.json",
    "provisioning-demo/workflow-graph.json",
    "reports/latest/index.html",
    "reports/latest/result.json",
    "reports/latest/provisioning.json",
    "reports/latest/provisioning.schema.json",
    "reports/latest/manifest.sha256",
)


class PageParser(HTMLParser):
    """Collect references and lightweight accessibility metadata."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.ids: list[str] = []
        self.heading_levels: list[int] = []
        self.anchor_stack: list[dict[str, str]] = []
        self.unnamed_links = 0
        self.has_doctype = False
        self.has_main = False
        self.has_viewport = False
        self.has_base = False
        self.html_lang = ""
        self.title_parts: list[str] = []
        self.in_title = False
        self.images_without_alt = 0
        self.accessible_status_ids: set[str] = set()

    def handle_decl(self, decl: str) -> None:
        if decl.lower().strip() == "doctype html":
            self.has_doctype = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()

        for attribute in ("href", "src"):
            if values.get(attribute):
                self.references.append(values[attribute])

        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "html":
            self.html_lang = values.get("lang", "")
        elif tag == "title":
            self.in_title = True
        elif tag == "meta" and values.get("name", "").lower() == "viewport":
            self.has_viewport = bool(values.get("content"))
        elif tag == "main":
            self.has_main = True
        elif tag == "base":
            self.has_base = True
        elif tag == "img" and "alt" not in values:
            self.images_without_alt += 1
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.heading_levels.append(int(tag[1]))
        elif tag == "a":
            self.anchor_stack.append({"text": "", "aria": values.get("aria-label", "")})

        if values.get("id") and (
            values.get("role") == "status" or values.get("aria-live") in {"polite", "assertive"}
        ):
            self.accessible_status_ids.add(values["id"])

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "a" and self.anchor_stack:
            anchor = self.anchor_stack.pop()
            if not anchor["text"].strip() and not anchor["aria"].strip():
                self.unnamed_links += 1

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        for anchor in self.anchor_stack:
            anchor["text"] += data


def parse_page(path: Path) -> PageParser:
    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def ensure_safe_tree(root: Path, errors: list[str]) -> None:
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            errors.append(f"{relative}: symbolic links are not allowed")
        elif path.is_file() and path.stat().st_nlink != 1:
            errors.append(f"{relative}: hard-linked files are not allowed")


def validate_manifest(root: Path, errors: list[str]) -> None:
    report_root = root / "reports" / "latest"
    manifest_path = report_root / "manifest.sha256"
    if not manifest_path.is_file():
        return

    recorded: dict[str, str] = {}
    for number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        match = MANIFEST_LINE.fullmatch(line)
        if not match:
            errors.append(f"reports/latest/manifest.sha256:{number}: malformed entry")
            continue
        digest, relative = match.groups()
        posix = PurePosixPath(relative)
        if posix.is_absolute() or ".." in posix.parts or posix.as_posix() != relative:
            errors.append(f"reports/latest/manifest.sha256:{number}: unsafe path {relative!r}")
            continue
        if relative in recorded:
            errors.append(f"reports/latest/manifest.sha256:{number}: duplicate path {relative!r}")
            continue
        recorded[relative] = digest

    actual = {
        relative
        for path in report_root.rglob("*")
        if path.is_file() and (relative := path.relative_to(report_root).as_posix()) != "manifest.sha256"
    }
    missing = sorted(actual - recorded.keys())
    extra = sorted(recorded.keys() - actual)
    if missing:
        errors.append(f"report manifest is missing files: {', '.join(missing)}")
    if extra:
        errors.append(f"report manifest names absent files: {', '.join(extra)}")

    for relative, expected in recorded.items():
        path = report_root / relative
        if not path.is_file():
            continue
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected:
            errors.append(f"reports/latest/{relative}: SHA-256 does not match manifest")


def local_target(root: Path, source: Path, reference: str, errors: list[str]) -> tuple[Path, str] | None:
    parsed = urlsplit(reference)
    if reference.startswith("//"):
        errors.append(f"{source.relative_to(root)}: protocol-relative URL is not allowed: {reference!r}")
        return None
    if parsed.scheme:
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_EXTERNAL_SCHEMES:
            errors.append(f"{source.relative_to(root)}: URL scheme is not allowed: {reference!r}")
        elif scheme in {"http", "https"} and not parsed.netloc:
            errors.append(f"{source.relative_to(root)}: external URL has no host: {reference!r}")
        elif scheme == "mailto" and not parsed.path:
            errors.append(f"{source.relative_to(root)}: mailto URL has no address: {reference!r}")
        return None
    if parsed.netloc:
        errors.append(f"{source.relative_to(root)}: URL authority requires an allowed scheme: {reference!r}")
        return None
    if parsed.path.startswith("/"):
        errors.append(f"{source.relative_to(root)}: root-relative URL breaks project Pages: {reference!r}")
        return None

    decoded = unquote(parsed.path)
    target = source if not decoded else source.parent / decoded
    resolved_root = root.resolve()
    resolved = target.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        errors.append(f"{source.relative_to(root)}: URL escapes the Pages tree: {reference!r}")
        return None
    if resolved.is_dir():
        resolved = resolved / "index.html"
    return resolved, unquote(parsed.fragment)


def validate_references(root: Path, pages: dict[Path, PageParser], errors: list[str]) -> None:
    references: list[tuple[Path, str]] = []
    for path, parser in pages.items():
        references.extend((path, reference) for reference in parser.references)
        if parser.has_base:
            errors.append(f"{path.relative_to(root)}: <base> is not allowed on a project Pages site")

    for stylesheet in root.rglob("*.css"):
        text = stylesheet.read_text(encoding="utf-8")
        references.extend((stylesheet, match.group(2).strip()) for match in CSS_URL.finditer(text))

    for source, reference in references:
        target_info = local_target(root, source, reference, errors)
        if target_info is None:
            continue
        target, fragment = target_info
        if not target.is_file():
            errors.append(f"{source.relative_to(root)}: missing local target for {reference!r}")
            continue
        if fragment and target.suffix.lower() in {".html", ".htm"}:
            target_parser = pages.get(target)
            if target_parser is None:
                target_parser = parse_page(target)
                pages[target] = target_parser
            if fragment not in target_parser.ids:
                errors.append(
                    f"{source.relative_to(root)}: fragment #{fragment} is absent from {target.relative_to(root)}"
                )


def validate_product_page(relative: str, parser: PageParser, errors: list[str]) -> None:
    if not parser.has_doctype:
        errors.append(f"{relative}: missing HTML5 doctype")
    if not parser.html_lang.strip():
        errors.append(f"{relative}: html element must declare a language")
    if not "".join(parser.title_parts).strip():
        errors.append(f"{relative}: title must not be empty")
    if not parser.has_viewport:
        errors.append(f"{relative}: viewport metadata is required")
    if not parser.has_main:
        errors.append(f"{relative}: main landmark is required")
    if parser.heading_levels.count(1) != 1:
        errors.append(f"{relative}: exactly one h1 is required")
    for previous, current in zip(parser.heading_levels, parser.heading_levels[1:]):
        if current > previous + 1:
            errors.append(f"{relative}: heading level jumps from h{previous} to h{current}")
    duplicates = sorted({identifier for identifier in parser.ids if parser.ids.count(identifier) > 1})
    if duplicates:
        errors.append(f"{relative}: duplicate ids: {', '.join(duplicates)}")
    if parser.images_without_alt:
        errors.append(f"{relative}: every image must have an alt attribute")
    if parser.unnamed_links:
        errors.append(f"{relative}: every link must have accessible text or an aria-label")


def validate_homepage(parser: PageParser, errors: list[str]) -> None:
    required_status_ids = {
        "report-status",
        "provisioning-automated-status",
        "provisioning-hardware-status",
    }
    missing_status_ids = sorted(required_status_ids - parser.accessible_status_ids)
    if missing_status_ids:
        errors.append(
            "index.html: dynamic status must use role=status or aria-live: "
            + ", ".join(missing_status_ids)
        )
    if not any(urlsplit(reference).path in {"reports/latest/", "./reports/latest/"} for reference in parser.references):
        errors.append("index.html: direct reports/latest/ link is required")
    if not any(
        urlsplit(reference).path in {"reports/latest/provisioning.json", "./reports/latest/provisioning.json"}
        for reference in parser.references
    ):
        errors.append("index.html: direct provisioning result link is required")
    if not any(
        urlsplit(reference).path in {"provisioning-demo/", "./provisioning-demo/"}
        for reference in parser.references
    ):
        errors.append("index.html: direct provisioning-demo/ link is required")
    if not any(
        urlsplit(reference).path in {"provisioning/", "./provisioning/"}
        for reference in parser.references
    ):
        errors.append("index.html: direct provisioning/ product link is required")
    if not any(
        urlsplit(reference).path in {"dns/", "./dns/"}
        for reference in parser.references
    ):
        errors.append("index.html: direct dns/ product link is required")


def station_secret_free(value: object) -> bool:
    if isinstance(value, str):
        return re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", value) is None
    if isinstance(value, list):
        return all(station_secret_free(item) for item in value)
    if isinstance(value, dict):
        return not (set(value) & STATION_FORBIDDEN_SECRET_KEYS) and all(
            station_secret_free(item) for item in value.values()
        )
    return True


def station_safety_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == STATION_SAFETY_FIELDS
        and value.get("simulation") is True
        and value.get("full_unprovisioned_state") == "not_established"
        and isinstance(value.get("disclaimer"), str)
        and bool(value["disclaimer"])
        and all(value.get(field) is False for field in STATION_SAFETY_FALSE_FIELDS)
    )


STATION_TRANSACTION_FIELDS = {
    "id",
    "status",
    "asset_id",
    "intended_logical_id",
    "claim_id",
    "fence_epoch",
    "operator_id",
    "approver_id",
    "target_fingerprint",
    "digest",
    "plan_digest",
    "approval_id",
    "intent_receipt",
    "finalization_approval_id",
    "finalization_intent_receipt",
    "irreversible_boundary_crossed",
    "commit_executions",
    "final_control_executions",
}


def station_transaction_valid(value: object, *, allow_empty_status: bool = False) -> bool:
    if not isinstance(value, dict) or set(value) != STATION_TRANSACTION_FIELDS:
        return False
    string_fields = STATION_TRANSACTION_FIELDS - {
        "fence_epoch",
        "irreversible_boundary_crossed",
        "commit_executions",
        "final_control_executions",
    }
    if any(not isinstance(value.get(field), str) for field in string_fields):
        return False
    status = value.get("status")
    if status not in STATION_TRANSACTION_STATUSES and not (allow_empty_status and status == ""):
        return False
    fence = value.get("fence_epoch")
    executions = value.get("commit_executions")
    final_executions = value.get("final_control_executions")
    crossed = value.get("irreversible_boundary_crossed")
    return (
        isinstance(fence, int)
        and not isinstance(fence, bool)
        and fence >= 0
        and isinstance(executions, int)
        and not isinstance(executions, bool)
        and 0 <= executions <= 1
        and isinstance(final_executions, int)
        and not isinstance(final_executions, bool)
        and 0 <= final_executions <= 1
        and isinstance(crossed, bool)
        and (executions != 1 or crossed is True)
        and (
            executions != 1
            or (bool(value.get("approval_id")) and bool(value.get("intent_receipt")))
        )
        and (
            final_executions != 1
            or (
                executions == 1
                and crossed is True
                and bool(value.get("finalization_approval_id"))
                and bool(value.get("finalization_intent_receipt"))
            )
        )
    )


STATION_MANIFEST_FIELDS = {
    "id",
    "digest",
    "profile_id",
    "profile_digest",
    "adapter_id",
    "adapter_digest",
    "expected_customer_key_hash",
    "eeprom_image_digest",
    "boot_image_digest",
    "boot_signature_digest",
    "root_integrity_digest",
    "fresh_commit_bundle_digest",
    "owned_recovery_bundle_digest",
    "boot_order",
    "rollback_policy",
    "debug_policy",
    "eeprom_write_protection_policy",
    "signer_id",
    "signing_tool_version",
    "verification_status",
}


def station_manifest_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == STATION_MANIFEST_FIELDS
        and all(isinstance(item, str) for item in value.values())
    )


def station_evidence_valid(value: object) -> bool:
    if not isinstance(value, list):
        return False
    identifiers: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"id", "label", "stage", "status", "digest", "detail"}:
            return False
        if any(not isinstance(entry.get(field), str) for field in entry):
            return False
        if not entry["id"] or not entry["label"] or not entry["stage"] or entry["status"] not in STATION_EVIDENCE_STATUSES:
            return False
        if entry["id"] in identifiers:
            return False
        identifiers.add(entry["id"])
    return True


def station_export_valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "simulation",
        "secret_free",
        "scenario",
        "station_id",
        "lane_id",
        "lifecycle",
        "transaction",
        "manifest",
        "evidence",
        "outcome",
        "safety",
    }:
        return False
    outcome = value.get("outcome")
    return (
        value.get("schema_version") == STATION_EXPORT_SCHEMA
        and value.get("simulation") is True
        and value.get("secret_free") is True
        and value.get("lifecycle") in STATION_LIFECYCLES
        and station_transaction_valid(value.get("transaction"), allow_empty_status=True)
        and station_manifest_valid(value.get("manifest"))
        and station_evidence_valid(value.get("evidence"))
        and isinstance(outcome, dict)
        and set(outcome) == {"status", "title", "message"}
        and all(isinstance(item, str) for item in outcome.values())
        and (outcome.get("status") in STATION_OUTCOME_STATUSES or outcome.get("status") == "")
        and station_safety_valid(value.get("safety"))
        and station_secret_free(value)
    )


def validate_station_demo(root: Path, errors: list[str]) -> None:
    demo_root = root / "provisioning-demo"
    config_path = demo_root / "runtime-config.json"
    graph_path = demo_root / "workflow-graph.json"
    if not config_path.is_file() or not graph_path.is_file():
        return
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"provisioning-demo/runtime-config.json: cannot parse JSON: {exc}")
        return
    expected_config = {
        "schema_version": "provisioning.kaiba.network/station-demo-runtime/v1alpha1",
        "mode": "transition-graph",
        "graph_url": "./workflow-graph.json",
    }
    if config != expected_config:
        errors.append("provisioning-demo/runtime-config.json: unexpected Pages runtime configuration")

    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"provisioning-demo/workflow-graph.json: cannot parse JSON: {exc}")
        return
    if not isinstance(graph, dict) or set(graph) != {
        "schema_version",
        "state_schema_version",
        "default_node",
        "nodes",
    }:
        errors.append("provisioning-demo/workflow-graph.json: malformed top-level fields")
        return
    if graph.get("schema_version") != "provisioning.kaiba.network/station-demo-transition-graph/v1alpha1":
        errors.append("provisioning-demo/workflow-graph.json: unsupported graph schema")
    if graph.get("state_schema_version") != STATION_STATE_SCHEMA:
        errors.append("provisioning-demo/workflow-graph.json: unsupported state schema")
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict) or not nodes or len(nodes) > 512 or graph.get("default_node") not in nodes:
        errors.append("provisioning-demo/workflow-graph.json: invalid nodes or default node")
        return

    node_id_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    graph_actions: set[str] = set()
    for node_id, node in nodes.items():
        label = f"provisioning-demo/workflow-graph.json: node {node_id!r}"
        if not isinstance(node_id, str) or not node_id_pattern.fullmatch(node_id):
            errors.append(f"{label} has a malformed identifier")
            continue
        if not isinstance(node, dict) or set(node) != {"state", "transitions"}:
            errors.append(f"{label} has malformed fields")
            continue
        state = node.get("state")
        transitions = node.get("transitions")
        if not isinstance(state, dict) or not isinstance(transitions, dict):
            errors.append(f"{label} has malformed state or transitions")
            continue
        safety = state.get("safety")
        if (
            state.get("schema_version") != graph.get("state_schema_version")
            or state.get("revision") != 0
            or state.get("simulation") is not True
            or state.get("lifecycle") not in STATION_LIFECYCLES
            or not station_safety_valid(safety)
        ):
            errors.append(f"{label} violates the simulation safety contract")
        stages = state.get("workflow_stages")
        if (
            not isinstance(stages, list)
            or not stages
            or any(
                not isinstance(stage, dict)
                or set(stage) != {"id", "label", "status"}
                or not isinstance(stage.get("id"), str)
                or not stage["id"]
                or not isinstance(stage.get("label"), str)
                or not stage["label"]
                or stage.get("status") not in STATION_WORKFLOW_STATUSES
                for stage in stages
            )
            or len({stage.get("id") for stage in stages if isinstance(stage, dict)}) != len(stages)
            or [stage.get("id") for stage in stages if isinstance(stage, dict)]
            != STATION_WORKFLOW_STAGE_IDS
            or sum(stage.get("status") == "current" for stage in stages if isinstance(stage, dict)) > 1
        ):
            errors.append(f"{label} has malformed typed workflow stages")
        probes = state.get("probes")
        if not isinstance(probes, list) or any(
            not isinstance(probe, dict)
            or not isinstance(probe.get("assessment"), dict)
            or probe["assessment"].get("mutation_eligible") is not False
            or probe["assessment"].get("full_unprovisioned_state") != "not_established"
            for probe in probes
        ):
            errors.append(f"{label} contains an unsafe probe assessment")
        transaction = state.get("transaction")
        if transaction is not None and not station_transaction_valid(transaction):
            errors.append(f"{label} has malformed transaction state")
        manifest = state.get("manifest")
        if manifest is not None and not station_manifest_valid(manifest):
            errors.append(f"{label} has malformed manifest state")
        if not station_evidence_valid(state.get("evidence")):
            errors.append(f"{label} has malformed cumulative evidence")
        export = state.get("export_record")
        if export is not None and not station_export_valid(export):
            errors.append(f"{label} contains an unsafe export record")
        actions = state.get("allowed_actions")
        if (
            not isinstance(actions, list)
            or any(not isinstance(action, str) or not action for action in actions)
            or len(actions) != len(set(actions))
            or set(transitions) != set(actions)
        ):
            errors.append(f"{label} does not exactly map its allowed actions")
            continue
        graph_actions.update(
            action for action in actions if not action.startswith("select_scenario:")
        )
        scenarios = state.get("scenarios")
        scenario_actions = {
            scenario.get("action")
            for scenario in scenarios
            if isinstance(scenarios, list) and isinstance(scenario, dict)
        } if isinstance(scenarios, list) else set()
        allowed_scenario_actions = {
            action for action in actions if action.startswith("select_scenario:")
        }
        if (
            not isinstance(scenarios, list)
            or any(
                not isinstance(scenario, dict)
                or set(scenario) != {"id", "label", "action"}
                or not isinstance(scenario.get("id"), str)
                or not scenario["id"]
                or not isinstance(scenario.get("label"), str)
                or not scenario["label"]
                or not isinstance(scenario.get("action"), str)
                or not scenario["action"].startswith("select_scenario:")
                for scenario in scenarios
            )
            or len(scenario_actions) != len(scenarios)
            or scenario_actions != allowed_scenario_actions
            or (state.get("phase") != "station_admission" and scenarios)
        ):
            errors.append(f"{label} has malformed or out-of-phase scenario controls")
        presentations = state.get("action_presentations")
        normal_actions = {
            action for action in actions if not action.startswith("select_scenario:")
        }
        if (
            not isinstance(presentations, list)
            or any(
                not isinstance(presentation, dict)
                or set(presentation)
                != {
                    "action",
                    "label",
                    "description",
                    "classification",
                    "requires_confirmation",
                    "point_of_no_return",
                }
                or not isinstance(presentation.get("action"), str)
                or not isinstance(presentation.get("label"), str)
                or not presentation["label"]
                or not isinstance(presentation.get("description"), str)
                or not presentation["description"]
                or presentation.get("classification") not in STATION_ACTION_CLASSIFICATIONS
                or not isinstance(presentation.get("requires_confirmation"), bool)
                or not isinstance(presentation.get("point_of_no_return"), bool)
                or (
                    presentation.get("classification") == "irreversible"
                    and presentation.get("requires_confirmation") is not True
                )
                or (
                    presentation.get("point_of_no_return")
                    != (presentation.get("action") == "execute_commit")
                )
                or (
                    presentation.get("point_of_no_return") is True
                    and (
                        presentation.get("classification") != "irreversible"
                        or presentation.get("requires_confirmation") is not True
                    )
                )
                for presentation in presentations
            )
            or len(
                {
                    presentation.get("action")
                    for presentation in presentations
                    if isinstance(presentation, dict)
                }
            )
            != len(presentations)
            or {
                presentation.get("action")
                for presentation in presentations
                if isinstance(presentation, dict)
            }
            != normal_actions
        ):
            errors.append(f"{label} has malformed action presentation metadata")
        if any(not isinstance(target, str) or target not in nodes for target in transitions.values()):
            errors.append(f"{label} references a missing transition target")
        if not station_secret_free(state):
            errors.append(f"{label} contains forbidden secret material")
    missing_actions = sorted(STATION_REQUIRED_OPERATOR_ACTIONS - graph_actions)
    if missing_actions:
        errors.append(
            "provisioning-demo/workflow-graph.json: required secure-boot actions are absent: "
            + ", ".join(missing_actions)
        )


def validate_result(root: Path, errors: list[str]) -> None:
    path = root / "reports" / "latest" / "result.json"
    if not path.is_file():
        return
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"reports/latest/result.json: cannot parse JSON: {exc}")
        return
    if not isinstance(result, dict) or result.get("suite") != "kaiba-dns-pilot":
        errors.append("reports/latest/result.json: unexpected suite")
        return
    assertions = result.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        errors.append("reports/latest/result.json: assertions must be a non-empty list")
        return
    statuses = [item.get("status") if isinstance(item, dict) else None for item in assertions]
    if any(status not in {"passed", "failed"} for status in statuses):
        errors.append("reports/latest/result.json: malformed assertion status")
        return
    expected = "passed" if all(status == "passed" for status in statuses) else "failed"
    if result.get("overall") != expected:
        errors.append(f"reports/latest/result.json: overall must be {expected!r}")


def valid_evidence_paths(value: object) -> bool:
    if not isinstance(value, list) or len(value) != len(set(item for item in value if isinstance(item, str))):
        return False
    for item in value:
        if not isinstance(item, str) or not EVIDENCE_PATH.fullmatch(item):
            return False
        path = PurePosixPath(item)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != item:
            return False
    return True


def validate_provisioning(root: Path, errors: list[str]) -> None:
    path = root / "reports" / "latest" / "provisioning.json"
    if not path.is_file():
        return
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"reports/latest/provisioning.json: cannot parse JSON: {exc}")
        return
    if not isinstance(result, dict) or result.get("suite") != "kaiba-rpi5-provisioning-probe":
        errors.append("reports/latest/provisioning.json: unexpected suite")
        return
    expected_top_level = {
        "schema_version",
        "suite",
        "automated",
        "hardware_qualification",
        "mutation_eligible",
    }
    if set(result) != expected_top_level:
        errors.append("reports/latest/provisioning.json: malformed top-level fields")
    if result.get("schema_version") != 1:
        errors.append("reports/latest/provisioning.json: schema_version must be 1")
    if result.get("mutation_eligible") is not False:
        errors.append("reports/latest/provisioning.json: mutation_eligible must be false")

    automated = result.get("automated")
    if not isinstance(automated, dict):
        errors.append("reports/latest/provisioning.json: automated must be an object")
        return
    if set(automated) != {"overall", "checks"}:
        errors.append("reports/latest/provisioning.json: malformed automated fields")
    overall = automated.get("overall")
    if overall not in {"passed", "failed", "partial"}:
        errors.append("reports/latest/provisioning.json: malformed automated overall")
        return
    checks = automated.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("reports/latest/provisioning.json: automated checks must be a non-empty list")
        return

    statuses: list[str] = []
    check_keys: list[tuple[str, str]] = []
    for index, check in enumerate(checks):
        context = f"reports/latest/provisioning.json: automated check {index}"
        if not isinstance(check, dict):
            errors.append(f"{context} must be an object")
            continue
        if set(check) - {"id", "system", "status", "description", "evidence", "source_revision"}:
            errors.append(f"{context} has unknown fields")
        if not {"id", "system", "status", "description", "evidence"}.issubset(check):
            errors.append(f"{context} is missing required fields")
        for field in ("id", "system", "description"):
            value = check.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{context} has malformed {field}")
        if isinstance(check.get("id"), str) and not PROVISIONING_IDENTIFIER.fullmatch(check["id"]):
            errors.append(f"{context} has malformed id")
        if check.get("system") not in {"x86_64-linux", "aarch64-linux"}:
            errors.append(f"{context} has malformed system")
        status = check.get("status")
        if status not in {"passed", "failed", "not-observed"}:
            errors.append(f"{context} has malformed status")
        else:
            statuses.append(status)
        if isinstance(check.get("id"), str) and isinstance(check.get("system"), str):
            check_keys.append((check["system"], check["id"]))
        evidence = check.get("evidence")
        if not valid_evidence_paths(evidence):
            errors.append(f"{context} has malformed evidence")
        elif any(not (root / "reports" / "latest" / item).is_file() for item in evidence):
            errors.append(f"{context} references missing evidence")
        revision = check.get("source_revision")
        if revision is not None and (not isinstance(revision, str) or not SOURCE_REVISION.fullmatch(revision)):
            errors.append(f"{context} has malformed source_revision")
        if status == "not-observed" and (evidence or revision is not None):
            errors.append(f"{context} must not claim evidence or a source revision when not observed")

    duplicate_keys = sorted({item for item in check_keys if check_keys.count(item) > 1})
    if duplicate_keys:
        errors.append(
            "reports/latest/provisioning.json: duplicate automated system/check pairs: "
            + ", ".join(f"{system}/{check_id}" for system, check_id in duplicate_keys)
        )
    if len(statuses) == len(checks):
        expected = "failed" if "failed" in statuses else "partial" if "not-observed" in statuses else "passed"
        if overall != expected:
            errors.append(f"reports/latest/provisioning.json: automated overall must be {expected!r}")

    hardware = result.get("hardware_qualification")
    if not isinstance(hardware, dict) or hardware.get("status") not in {"pending", "passed", "failed"}:
        errors.append("reports/latest/provisioning.json: malformed hardware qualification status")
    elif set(hardware) != {"status", "description", "evidence"}:
        errors.append("reports/latest/provisioning.json: malformed hardware qualification fields")
    elif not isinstance(hardware.get("description"), str) or not hardware["description"].strip():
        errors.append("reports/latest/provisioning.json: malformed hardware qualification description")
    elif not valid_evidence_paths(hardware.get("evidence")):
        errors.append("reports/latest/provisioning.json: malformed hardware qualification evidence")
    elif any(not (root / "reports" / "latest" / item).is_file() for item in hardware["evidence"]):
        errors.append("reports/latest/provisioning.json: hardware qualification references missing evidence")
    elif hardware["status"] == "pending" and hardware["evidence"]:
        errors.append("reports/latest/provisioning.json: pending hardware qualification must not claim evidence")
    elif hardware["status"] != "pending" and not hardware["evidence"]:
        errors.append("reports/latest/provisioning.json: completed hardware qualification must cite evidence")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="assembled GitHub Pages tree")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    errors: list[str] = []

    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    for relative in REQUIRED_PATHS:
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")

    ensure_safe_tree(root, errors)
    validate_manifest(root, errors)
    pages = {path.resolve(): parse_page(path) for path in root.rglob("*.html")}
    product_pages = ("index.html", "provisioning/index.html", "dns/index.html")
    for relative in product_pages:
        product_page = pages.get((root / relative).resolve())
        if product_page is not None:
            validate_product_page(relative, product_page, errors)
    homepage = pages.get((root / "index.html").resolve())
    if homepage is not None:
        validate_homepage(homepage, errors)
    validate_references(root, pages, errors)
    validate_result(root, errors)
    validate_provisioning(root, errors)
    validate_station_demo(root, errors)

    if errors:
        for error in errors:
            print(f"site validation: {error}", file=sys.stderr)
        return 1
    file_count = sum(1 for path in root.rglob("*") if path.is_file())
    print(f"validated Pages site with {file_count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
