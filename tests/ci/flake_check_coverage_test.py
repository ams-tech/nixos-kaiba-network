#!/usr/bin/env python3

"""Adversarial unit tests for executable flake-check target discovery."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


if len(sys.argv) != 2:
    raise SystemExit("usage: flake_check_coverage_test.py FLAKE_CHECK_COVERAGE")

policy_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("flake_check_coverage", policy_path)
if spec is None or spec.loader is None:
    raise SystemExit(f"cannot import {policy_path}")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

real_target = ("root", "x86_64-linux", "real-check")
leaf_target = ("dns", "aarch64-linux", "leaf-check")
workflow = """
# nix build .#checks.x86_64-linux.outside-run-comment
jobs:
  example:
    steps:
      - name: Comments and non-build commands do not establish coverage
        run: |
          # nix build .#checks.x86_64-linux.block-comment
          echo .#checks.x86_64-linux.echo-only
          nix eval .#checks.x86_64-linux.eval-only
      - name: A continued Nix build does establish exact coverage
        run: |
          nix --accept-flake-config build --no-link -L \\
            .#checks.x86_64-linux.real-check \\
            ./nix/dns#checks.aarch64-linux.leaf-check
"""

observed = policy.workflow_targets(workflow)
expected = {real_target: 1, leaf_target: 1}
if observed != expected:
    raise SystemExit(f"unexpected executable targets: {observed!r}, expected {expected!r}")

inline = """
jobs:
  example:
    steps:
      - run: nix build ./provisioning#checks.x86_64-linux.inline-check
"""
inline_target = ("provisioning", "x86_64-linux", "inline-check")
if policy.workflow_targets(inline) != {inline_target: 1}:
    raise SystemExit("an inline nix build target was not discovered")

print("flake check coverage parser tests passed")
