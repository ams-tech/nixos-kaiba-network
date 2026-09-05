#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


CACHE_ACTION = (
    "uses: cachix/cachix-action@"
    "5f2d7c5294214f71b873db4b969586b980625e71 # v17"
)
CACHE_NAME = "name: nixos-kaiba-network"
CACHE_URL = "https://nixos-kaiba-network.cachix.org"
CACHE_PUBLIC_KEY = (
    "nixos-kaiba-network.cachix.org-1:"
    "BCAt/P9Fo2JFexLB4T7eB3o0csSQI/Dy+hx+3RwzA8U="
)
WRITE_TOKEN = (
    "authToken: ${{ github.event_name == 'push' && "
    "github.ref == 'refs/heads/main' && secrets.CACHIX_AUTH_TOKEN || '' }}"
)
WRITE_POLICY = (
    "skipPush: ${{ github.event_name != 'push' || "
    "github.ref != 'refs/heads/main' || secrets.CACHIX_AUTH_TOKEN == '' }}"
)
WRITE_STEP_CONDITION = (
    "if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
)


def fail(message: str) -> None:
    raise SystemExit(f"cache workflow policy: {message}")


def workflow_jobs(path: Path) -> dict[str, str]:
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "jobs:":
            in_jobs = True
            current = None
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" "):
            break
        match = re.fullmatch(r"  ([a-z0-9-]+):", line)
        if match:
            current = match.group(1)
            jobs[current] = []
            continue
        if current is not None:
            jobs[current].append(line)

    if not jobs:
        fail(f"{path} has no jobs")
    return {name: "\n".join(lines) for name, lines in jobs.items()}


def require_once(body: str, value: str, label: str) -> None:
    count = body.count(value)
    if count != 1:
        fail(f"{label} must contain {value!r} exactly once, found {count}")


def require_nix_setting(body: str, setting: str, value: str, label: str) -> None:
    lines = [
        line.strip()
        for line in body.splitlines()
        if line.strip().startswith(f"{setting} = ")
    ]
    if len(lines) != 1:
        fail(f"{label} must define {setting} exactly once, found {len(lines)}")
    values = lines[0].partition("=")[2].split()
    if values.count(value) != 1:
        fail(f"{label} must pin {value!r} exactly once in {setting}")


def check_cache_config(body: str, label: str) -> None:
    require_once(body, "uses: cachix/install-nix-action@", label)
    require_once(body, CACHE_URL, label)
    require_once(body, CACHE_PUBLIC_KEY, label)
    require_nix_setting(body, "extra-substituters", CACHE_URL, label)
    require_nix_setting(body, "extra-trusted-public-keys", CACHE_PUBLIC_KEY, label)


def check_cache_job(body: str, label: str) -> None:
    require_once(body, "uses: cachix/cachix-action@", label)
    require_once(body, CACHE_ACTION, label)
    require_once(body, CACHE_NAME, label)
    install = body.find("uses: cachix/install-nix-action@")
    cache = body.find(CACHE_ACTION)
    if install < 0 or cache < install:
        fail(f"{label} must configure Cachix after installing Nix")


def check_writer(body: str, label: str) -> None:
    check_cache_config(body, label)
    check_cache_job(body, label)
    require_once(body, WRITE_STEP_CONDITION, label)
    require_once(body, "authToken:", label)
    require_once(body, WRITE_TOKEN, label)
    require_once(body, "skipAddingSubstituter: true", label)
    require_once(body, WRITE_POLICY, label)
    token_references = body.count("CACHIX_AUTH_TOKEN")
    if token_references != 2:
        fail(
            f"{label} must reference CACHIX_AUTH_TOKEN exactly twice, "
            f"found {token_references}"
        )


def check_reader(body: str, label: str) -> None:
    check_cache_config(body, label)
    if "cachix/cachix-action@" in body:
        fail(f"{label} must pull from the pinned Nix configuration without an action")
    if "CACHIX_AUTH_TOKEN" in body or "authToken:" in body:
        fail(f"{label} must not receive a Cachix write token")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: workflow_cache_policy.py CI_WORKFLOW RELEASE_WORKFLOW")

    ci_path = Path(sys.argv[1])
    release_path = Path(sys.argv[2])
    ci_jobs = workflow_jobs(ci_path)
    release_jobs = workflow_jobs(release_path)

    ci_writers = {"quality", "aarch64-packages", "dns-integration"}
    ci_readers = {"provisioning-image"}
    ci_config_jobs = {
        name for name, body in ci_jobs.items() if CACHE_URL in body
    }
    if ci_config_jobs != ci_writers | ci_readers:
        fail(
            f"{ci_path} configured cache jobs are {sorted(ci_config_jobs)}, "
            f"expected {sorted(ci_writers | ci_readers)}"
        )
    ci_cache_jobs = {
        name for name, body in ci_jobs.items() if "cachix/cachix-action@" in body
    }
    if ci_cache_jobs != ci_writers:
        fail(
            f"{ci_path} cache jobs are {sorted(ci_cache_jobs)}, expected "
            f"{sorted(ci_writers)}"
        )

    for name in sorted(ci_writers):
        check_writer(ci_jobs[name], f"{ci_path}:{name}")
    for name in sorted(ci_readers):
        check_reader(ci_jobs[name], f"{ci_path}:{name}")

    release_config_jobs = {
        name
        for name, body in release_jobs.items()
        if CACHE_URL in body
    }
    if release_config_jobs:
        fail(
            f"{release_path} configured cache jobs are "
            f"{sorted(release_config_jobs)}, "
            "expected none for fixed-archive publication"
        )
    release_cache_jobs = {
        name
        for name, body in release_jobs.items()
        if "cachix/cachix-action@" in body
    }
    if release_cache_jobs:
        fail(
            f"{release_path} must not expose a cache publisher, found "
            f"{sorted(release_cache_jobs)}"
        )
    print("cache workflow policy passed")


if __name__ == "__main__":
    main()
