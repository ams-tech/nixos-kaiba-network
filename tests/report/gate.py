#!/usr/bin/env python3
"""Enforce the source-controlled Kaiba DNS assertion contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


def load_json(path: Path, label: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} contains duplicate object key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc


def load_result(path: Path) -> dict[str, Any]:
    value = load_json(path, "result JSON")
    if not isinstance(value, dict):
        raise ValueError("result must be an object")
    if value.get("schema_version") != 1 or value.get("suite") != "kaiba-dns-pilot":
        raise ValueError("result is not a Kaiba DNS pilot schema version 1 document")
    assertions = value.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise ValueError("result must contain assertions")
    seen: set[str] = set()
    for index, assertion in enumerate(assertions):
        if not isinstance(assertion, dict):
            raise ValueError(f"assertion {index} is malformed")
        assertion_id = assertion.get("id")
        phase = assertion.get("phase")
        if (
            not isinstance(assertion_id, str)
            or not IDENTIFIER.fullmatch(assertion_id)
            or not isinstance(phase, str)
            or not IDENTIFIER.fullmatch(phase)
            or assertion.get("status") not in {"passed", "failed"}
        ):
            raise ValueError(f"assertion {index} is malformed")
        if assertion_id in seen:
            raise ValueError(f"result contains duplicate assertion id {assertion_id!r}")
        seen.add(assertion_id)
    expected = "failed" if any(item["status"] == "failed" for item in assertions) else "passed"
    if value.get("overall") != expected:
        raise ValueError(f"overall status must be {expected}")
    return value


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    value = load_json(path, "required-assertion manifest")
    if not isinstance(value, dict) or set(value) != {"schema_version", "assertions"}:
        raise ValueError("required-assertion manifest must contain only schema_version and assertions")
    if value["schema_version"] != 1 or not isinstance(value["assertions"], dict) or not value["assertions"]:
        raise ValueError("required-assertion manifest must be a non-empty schema version 1 document")
    assertions: dict[str, dict[str, Any]] = {}
    for assertion_id, metadata in value["assertions"].items():
        if not IDENTIFIER.fullmatch(assertion_id):
            raise ValueError(f"manifest assertion id {assertion_id!r} is invalid")
        if not isinstance(metadata, dict) or set(metadata) != {"phase", "security"}:
            raise ValueError(f"manifest assertion {assertion_id!r} must contain only phase and security")
        phase = metadata["phase"]
        if not isinstance(phase, str) or not IDENTIFIER.fullmatch(phase):
            raise ValueError(f"manifest assertion {assertion_id!r} has an invalid phase")
        if not isinstance(metadata["security"], bool):
            raise ValueError(f"manifest assertion {assertion_id!r} security must be a boolean")
        assertions[assertion_id] = metadata
    if not any(item["security"] for item in assertions.values()):
        raise ValueError("required-assertion manifest must identify at least one security assertion")
    return assertions


def evaluate(
    result: dict[str, Any],
    manifest: dict[str, dict[str, Any]],
    scope: str,
) -> list[str]:
    recorded = {item["id"]: item for item in result["assertions"]}
    failures: list[str] = []

    if scope == "functional":
        required = manifest
        missing = sorted(set(required) - set(recorded))
        extra = sorted(set(recorded) - set(required))
        failures.extend(f"missing required assertion {item}" for item in missing)
        failures.extend(f"undeclared assertion {item}" for item in extra)
    else:
        required = {
            assertion_id: metadata
            for assertion_id, metadata in manifest.items()
            if metadata["security"]
        }
        recorded_security_ids = {
            assertion_id
            for assertion_id, assertion in recorded.items()
            if assertion["phase"] == "security"
        }
        missing = sorted(set(required) - set(recorded))
        extra = sorted(recorded_security_ids - set(required))
        failures.extend(f"missing required security assertion {item}" for item in missing)
        failures.extend(f"undeclared security assertion {item}" for item in extra)

    for assertion_id, metadata in sorted(required.items()):
        assertion = recorded.get(assertion_id)
        if assertion is None:
            continue
        if assertion["phase"] != metadata["phase"]:
            failures.append(
                f"assertion {assertion_id} phase is {assertion['phase']!r}, expected {metadata['phase']!r}"
            )
        if assertion["status"] != "passed":
            failures.append(f"assertion {assertion_id} did not pass")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="source-controlled required assertion manifest")
    parser.add_argument(
        "--scope",
        choices=("functional", "security"),
        default="functional",
        help="assertion subset to enforce",
    )
    parser.add_argument("result", type=Path, help="rendered result.json")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = load_result(args.result)
        manifest = load_manifest(args.manifest)
    except ValueError as exc:
        print(f"gate error: {exc}", file=sys.stderr)
        return 2

    failures = evaluate(result, manifest, args.scope)
    if failures:
        print("gate failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    count = len(manifest) if args.scope == "functional" else sum(
        item["security"] for item in manifest.values()
    )
    label = "required assertions" if args.scope == "functional" else "required security assertions"
    print(f"all {count} {label} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
