#!/usr/bin/env python3
"""Validate a canonical result with its published Draft 2020-12 schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


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


def path_text(parts: Any) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{part}"
    return path


def validate(schema: Any, instance: Any) -> list[str]:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(f"published result schema is invalid: {exc.message}") from exc
    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: (path_text(error.absolute_path), error.message),
    )
    return [f"{path_text(error.absolute_path)}: {error.message}" for error in errors]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True, help="published JSON Schema")
    parser.add_argument("--instance", type=Path, required=True, help="canonical result.json")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        schema = load_json(args.schema, "result schema")
        instance = load_json(args.instance, "result JSON")
        failures = validate(schema, instance)
    except ValueError as exc:
        print(f"schema gate error: {exc}", file=sys.stderr)
        return 2
    if failures:
        print("schema validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("result.json conforms to the published Draft 2020-12 schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
