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
    require("PERSISTENT MUTATION BLOCKED" in document_text, "mutation boundary must be visible")
    require("not device authentication or attestation" in document_text, "preflight disclaimer must be present")
    require("download-export" in parser.ids and "export-record" in parser.ids, "redacted export controls are required")
    require("developer-panel" in parser.ids and "scenario-buttons" in parser.ids, "developer scenario surface is required")

    for token in (
        "transport.getState()",
        "transport.applyAction({ action, expected_revision: currentState.revision })",
        "window.KaibaStationTransport.create()",
        "state.allowed_actions",
        "state.scenarios.some",
        "state.schema_version !== stateSchema",
        "state.simulation !== true",
        "state.safety.mutation_eligible !== false",
        'state.safety.full_unprovisioned_state !== "not_established"',
        "probe.device_class_status",
        "probe.observable_baseline_status",
        "observation.videocore_jtag_state",
        'stopped: ["Probe stopped"',
        "outcome.title",
        "outcome.message",
        "confirm_boot_ok",
        "confirm_boot_failed",
        "export_redacted",
        "reset",
        "URL.createObjectURL",
    ):
        require(token in script, f"JavaScript contract is missing {token!r}")
    require("localStorage" not in script and "sessionStorage" not in script, "browser storage must not own workflow state")
    require(not re.search(r"https?://", script, re.IGNORECASE), "JavaScript must use same-origin APIs only")

    for token in (
        'const runtimeConfigURL = "./runtime-config.json"',
        'mode: "http"',
        'mode: "transition-graph"',
        "config.mode === \"http\"",
        "config.mode === \"transition-graph\"",
        "request.expected_revision !== revision",
        "state.safety.mutation_eligible !== false",
        "window.KaibaStationTransport = Object.freeze({ create })",
    ):
        require(token in transport, f"transport contract is missing {token!r}")
    require("localStorage" not in transport and "sessionStorage" not in transport, "transport must keep simulation state in memory")
    require("navigator.usb" not in transport and "requestDevice" not in transport, "transport must not access USB")
    require(not re.search(r"https?://", transport, re.IGNORECASE), "transport must not hard-code an external endpoint")

    require(re.search(r"\.button\s*\{[^}]*min-height:\s*56px", styles, re.DOTALL) is not None, "primary touch controls must be at least 56px high")
    require(":focus-visible" in styles, "visible keyboard focus is required")
    require("prefers-reduced-motion: reduce" in styles, "reduced-motion support is required")
    require("@media (max-height: 560px)" in styles, "800x480-class landscape adaptation is required")


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(f"usage: {argv[0]} [WEB_ROOT]", file=sys.stderr)
        return 2
    default_root = Path(__file__).resolve().parents[2] / "internal" / "provisioning" / "stationui" / "web"
    try:
        validate(Path(argv[1]) if len(argv) == 2 else default_root)
    except (OSError, ValueError) as error:
        print(f"station UI validation failed: {error}", file=sys.stderr)
        return 1
    print("station UI validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
