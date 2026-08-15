#!/usr/bin/env python3
"""Small dependency-free static contract check for the station kiosk assets."""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.text: list[str] = []
        self.has_main = False
        self.has_live_region = False
        self.has_alert = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if identifier := values.get("id"):
            if identifier in self.ids:
                raise ValueError(f"duplicate HTML id: {identifier}")
            self.ids.add(identifier)
        if tag == "main":
            self.has_main = True
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"] or "")
        if tag == "link" and values.get("rel") == "stylesheet":
            self.stylesheets.append(values.get("href") or "")
        if values.get("aria-live"):
            self.has_live_region = True
        if values.get("role") == "alert":
            self.has_alert = True

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(web_root: Path) -> None:
    index_path = web_root / "index.html"
    script_path = web_root / "app.js"
    transport_path = web_root / "transport.js"
    style_path = web_root / "styles.css"
    for path in (index_path, script_path, transport_path, style_path):
        require(path.is_file(), f"missing kiosk asset: {path.name}")

    html = index_path.read_text(encoding="utf-8")
    script = script_path.read_text(encoding="utf-8")
    transport = transport_path.read_text(encoding="utf-8")
    styles = style_path.read_text(encoding="utf-8")
    parser = DocumentParser()
    parser.feed(html)
    document_text = " ".join(" ".join(parser.text).split())

    require(parser.has_main, "kiosk must contain a main landmark")
    require(parser.has_live_region, "kiosk must announce asynchronous station updates")
    require(parser.has_alert, "kiosk must expose request failures as alerts")
    require(parser.scripts == ["./transport.js", "./app.js"], "kiosk must load only its local JavaScript in transport-first order")
    require(parser.stylesheets == ["./styles.css"], "kiosk must load only its local stylesheet")
    require(not re.search(r"(?:https?:)?//", html, re.IGNORECASE), "kiosk must not load external assets")
    require("MOCK / SIMULATION" in document_text, "simulation boundary must be visible")
    require(
        "SIMULATION ONLY · LIVE MUTATION AND ENROLLMENT UNAVAILABLE" in document_text,
        "live-capability boundary must be visible",
    )
    require("no live target access" in document_text, "live target boundary must be explicit")
    require("no approval or provisioning authority" in document_text, "approval boundary must be explicit")
    require("modeled point of no return" in document_text, "irreversible-model disclaimer must be present")
    require("download-export" in parser.ids and "export-record" in parser.ids, "redacted export controls are required")
    require("developer-panel" in parser.ids and "scenario-buttons" in parser.ids, "developer scenario surface is required")
    for identifier in (
        "workflow-stages",
        "transaction-panel",
        "transaction-facts",
        "manifest-panel",
        "manifest-facts",
        "policy-list",
        "evidence-panel",
        "evidence-checks",
        "lifecycle-status",
        "bound-target",
    ):
        require(identifier in parser.ids, f"secure-boot UI is missing #{identifier}")
    require("data-step=" not in html, "workflow progress must not be hard-coded in HTML")

    for token in (
        'const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha2"',
        'const exportSchema = "provisioning.kaiba.network/station-demo-export/v1alpha2"',
        "transport.getState()",
        "transport.applyAction({ action, expected_revision: currentState.revision })",
        "window.KaibaStationTransport.create()",
        "state.allowed_actions",
        "state.scenarios.some",
        "state.schema_version !== stateSchema",
        "state.simulation !== true",
        "assertSafety(state.safety",
        "for (const field of falseSafetyCapabilities)",
        "state.workflow_stages",
        "state.action_presentations",
        "state.transaction",
        "transaction.finalization_approval_id",
        "transaction.finalization_intent_receipt",
        "transaction.final_control_executions",
        "final_cold_restart_observed",
        "state.manifest",
        "state.evidence",
        "renderWorkflowStages",
        "renderTransaction",
        "renderManifest",
        "renderEvidence",
        "presentation.point_of_no_return",
        "presentation.requires_confirmation",
        'action === "reset" || action === "export_redacted"',
        'return "button-commit"',
        "observation.videocore_jtag_state",
        'lifecycle === "owned_quarantined"',
        'lifecycle === "enrollment_ready"',
        "outcome?.title",
        "outcome?.message",
        "confirm_boot_failed",
        "export_redacted",
        "reset",
        "URL.createObjectURL",
    ):
        require(token in script, f"JavaScript contract is missing {token!r}")
    for capability in (
        "mutation_eligible",
        "live_target_access",
        "live_mutation_capable",
        "authoritative_evidence",
        "secrets_present",
        "approval_authority",
        "signing_capable",
        "enrollment_capable",
    ):
        require(f'"{capability}"' in script, f"JavaScript safety contract is missing {capability!r}")
    require("localStorage" not in script and "sessionStorage" not in script, "browser storage must not own workflow state")
    require(not re.search(r"https?://", script, re.IGNORECASE), "JavaScript must use same-origin APIs only")

    for token in (
        'const runtimeConfigURL = "./runtime-config.json"',
        'const stateSchema = "provisioning.kaiba.network/station-demo-state/v1alpha2"',
        'const exportSchema = "provisioning.kaiba.network/station-demo-export/v1alpha2"',
        'mode: "http"',
        'mode: "transition-graph"',
        "config.mode === \"http\"",
        "config.mode === \"transition-graph\"",
        "request.expected_revision !== revision",
        "requireSafety(state.safety",
        "for (const field of falseSafetyCapabilities)",
        "requireTransaction",
        "requireManifest",
        "requireEvidence",
        "requireExport",
        "presentation.point_of_no_return",
        "transaction.commit_executions > 1",
        "transaction.final_control_executions > 1",
        '"cold_restart_finalized_target"',
        "window.KaibaStationTransport = Object.freeze({ create })",
    ):
        require(token in transport, f"transport contract is missing {token!r}")
    for capability in (
        "mutation_eligible",
        "live_target_access",
        "live_mutation_capable",
        "authoritative_evidence",
        "secrets_present",
        "approval_authority",
        "signing_capable",
        "enrollment_capable",
    ):
        require(f'"{capability}"' in transport, f"transport safety contract is missing {capability!r}")
    require("localStorage" not in transport and "sessionStorage" not in transport, "transport must keep simulation state in memory")
    require("navigator.usb" not in transport and "requestDevice" not in transport, "transport must not access USB")
    require(not re.search(r"https?://", transport, re.IGNORECASE), "transport must not hard-code an external endpoint")

    require(re.search(r"\.button\s*\{[^}]*min-height:\s*56px", styles, re.DOTALL) is not None, "primary touch controls must be at least 56px high")
    require(".button-commit" in styles, "one-shot simulated commit styling is required")
    require(".button-secondary" in styles, "secondary reset styling is required")
    require(".evidence-checks" in styles and ".manifest-facts" in styles, "secure-boot evidence surfaces must be styled")
    require(":focus-visible" in styles, "visible keyboard focus is required")
    require("prefers-reduced-motion: reduce" in styles, "reduced-motion support is required")
    require("@media (max-height: 560px)" in styles, "800x480-class landscape adaptation is required")


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(f"usage: {argv[0]} [WEB_ROOT]", file=sys.stderr)
        return 2
    default_root = (
        Path(__file__).resolve().parents[2]
        / "provisioning"
        / "internal"
        / "provisioning"
        / "stationui"
        / "web"
    )
    try:
        validate(Path(argv[1]) if len(argv) == 2 else default_root)
    except (OSError, ValueError) as error:
        print(f"station UI validation failed: {error}", file=sys.stderr)
        return 1
    print("station UI validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
