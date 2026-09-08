#!/usr/bin/env python3

"""Require every evaluated flake check to be built by the main CI workflow."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SYSTEMS = ("x86_64-linux", "aarch64-linux")
FLAKE_PREFIXES = {
    "root": ".",
    "dns": "./nix/dns",
}

# Keep exclusions exceptional, reviewable, and tied to one concrete output.
# An empty set is intentional: every currently evaluated check is safe in CI.
INTENTIONAL_EXCLUSIONS: dict[tuple[str, str, str], str] = {}

CHECK_NAME = re.compile(r"[a-z][a-z0-9-]*")
CHECK_TARGET = re.compile(
    r"(?P<prefix>\.|\./nix/dns)"
    r"#checks\.(?P<system>x86_64-linux|aarch64-linux)\."
    r"(?P<name>[a-z][a-z0-9-]*)"
)
SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)
BLOCK_SCALARS = {"|", "|-", "|+", ">", ">-", ">+"}


def fail(message: str) -> None:
    raise SystemExit(f"flake check coverage: {message}")


def evaluated_checks(path: Path) -> set[tuple[str, str, str]]:
    try:
        manifest: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read evaluated check manifest {path}: {error}")

    if not isinstance(manifest, dict) or set(manifest) != set(FLAKE_PREFIXES):
        fail(
            "evaluated manifest must contain exactly the root and dns flakes"
        )

    expected: set[tuple[str, str, str]] = set()
    for flake in FLAKE_PREFIXES:
        platforms = manifest[flake]
        if not isinstance(platforms, dict) or set(platforms) != set(SYSTEMS):
            fail(f"evaluated manifest for {flake} must contain exactly {SYSTEMS!r}")
        for system in SYSTEMS:
            names = platforms[system]
            if not isinstance(names, list) or not names:
                fail(f"evaluated checks for {flake}:{system} must be a non-empty list")
            if len(names) != len(set(names)):
                fail(f"evaluated checks for {flake}:{system} contain duplicates")
            for name in names:
                if not isinstance(name, str) or CHECK_NAME.fullmatch(name) is None:
                    fail(f"invalid evaluated check name for {flake}:{system}: {name!r}")
                expected.add((flake, system, name))
    return expected


def yaml_run_blocks(source: str) -> list[str]:
    """Extract step-level run values without treating comments as commands."""

    lines = source.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(
            r"^(?P<indent> +)(?:- )?run:\s*(?P<value>.*?)\s*$", line
        )
        if match is None:
            index += 1
            continue

        indent = len(match.group("indent"))
        value = match.group("value")
        if value not in BLOCK_SCALARS:
            blocks.append(value)
            index += 1
            continue

        index += 1
        raw_block: list[str] = []
        while index < len(lines):
            candidate = lines[index]
            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
            if candidate.strip() and candidate_indent <= indent:
                break
            raw_block.append(candidate)
            index += 1

        content_indents = [
            len(candidate) - len(candidate.lstrip(" "))
            for candidate in raw_block
            if candidate.strip()
        ]
        if not content_indents:
            blocks.append("")
            continue
        content_indent = min(content_indents)
        if content_indent <= indent:
            fail("a workflow run block has invalid indentation")
        blocks.append(
            "\n".join(
                candidate[content_indent:] if candidate.strip() else ""
                for candidate in raw_block
            )
        )
    return blocks


def logical_shell_commands(block: str) -> list[str]:
    commands: list[str] = []
    continued = ""
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        if continued:
            line = continued + line.lstrip()
        if line.endswith("\\"):
            continued = line[:-1].rstrip() + " "
            continue
        commands.append(line)
        continued = ""
    if continued:
        fail("a workflow run block ends with an unterminated continuation")
    return commands


def nix_build_targets(command: str) -> list[tuple[str, str, str]]:
    if "#checks." not in command:
        return []
    try:
        tokens = shlex.split(command, comments=False, posix=True)
    except ValueError as error:
        fail(f"cannot parse shell command containing a check target: {error}")
    comment_index = next(
        (index for index, token in enumerate(tokens) if token.startswith("#")),
        len(tokens),
    )
    tokens = tokens[:comment_index]
    if not tokens:
        return []

    command_index = 0
    while command_index < len(tokens) and SHELL_ASSIGNMENT.fullmatch(
        tokens[command_index]
    ):
        command_index += 1
    if command_index >= len(tokens) or tokens[command_index] != "nix":
        return []

    build_index = next(
        (
            index
            for index in range(command_index + 1, len(tokens))
            if tokens[index] == "build"
        ),
        None,
    )
    if build_index is None:
        return []

    prefix_to_flake = {prefix: name for name, prefix in FLAKE_PREFIXES.items()}
    targets: list[tuple[str, str, str]] = []
    for token in tokens[build_index + 1 :]:
        match = CHECK_TARGET.fullmatch(token)
        if match is None:
            continue
        targets.append(
            (
                prefix_to_flake[match.group("prefix")],
                match.group("system"),
                match.group("name"),
            )
        )
    return targets


def workflow_targets(source: str) -> dict[tuple[str, str, str], int]:
    targets: dict[tuple[str, str, str], int] = {}
    for block in yaml_run_blocks(source):
        for command in logical_shell_commands(block):
            for key in nix_build_targets(command):
                targets[key] = targets.get(key, 0) + 1
    return targets


def main() -> None:
    if len(sys.argv) != 3:
        fail(
            "usage: flake_check_coverage.py CI_WORKFLOW "
            "EVALUATED_CHECK_MANIFEST"
        )

    expected = evaluated_checks(Path(sys.argv[2]))
    unknown_exclusions = set(INTENTIONAL_EXCLUSIONS) - expected
    if unknown_exclusions:
        fail(f"stale exclusions: {sorted(unknown_exclusions)!r}")
    for key, reason in INTENTIONAL_EXCLUSIONS.items():
        if not reason.strip():
            fail(f"exclusion {key!r} has no reviewable reason")

    targets = workflow_targets(Path(sys.argv[1]).read_text(encoding="utf-8"))
    unknown = set(targets) - expected
    if unknown:
        fail(f"workflow names undeclared checks: {sorted(unknown)!r}")

    duplicate = sorted(key for key, count in targets.items() if count != 1)
    if duplicate:
        fail(f"workflow must build each check exactly once: {duplicate!r}")

    missing = expected - set(INTENTIONAL_EXCLUSIONS) - set(targets)
    if missing:
        rendered = [f"{flake}:{system}:{name}" for flake, system, name in sorted(missing)]
        fail("workflow does not build evaluated checks: " + ", ".join(rendered))

    print(
        "flake check coverage passed: "
        f"{len(expected)} evaluated platform check outputs are built"
    )


if __name__ == "__main__":
    main()
