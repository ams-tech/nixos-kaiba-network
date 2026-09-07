#!/usr/bin/env python3

"""Adversarial regression tests for the main CI workflow policy."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path


POLICY: Path
WORKFLOW: Path

Mutation = Callable[[str], str]


class CIWorkflowPolicyAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def run_policy(self, workflow: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(POLICY), str(workflow)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_policy_rejects(self, mutation: Mutation) -> None:
        mutated = mutation(self.workflow)
        self.assertNotEqual(self.workflow, mutated, "mutation changed no workflow text")
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "ci.yml"
            fixture.write_text(mutated, encoding="utf-8")
            completed = self.run_policy(fixture)
        self.assertNotEqual(0, completed.returncode, completed.stdout)
        self.assertIn("CI workflow policy:", completed.stderr)

    def replace_once(self, old: str, new: str) -> Mutation:
        def mutate(source: str) -> str:
            self.assertIn(old, source)
            return source.replace(old, new, 1)

        return mutate

    def replace_nth(self, old: str, new: str, occurrence: int) -> Mutation:
        def mutate(source: str) -> str:
            self.assertGreaterEqual(source.count(old), occurrence)
            start = -1
            for _ in range(occurrence):
                start = source.index(old, start + 1)
            return source[:start] + new + source[start + len(old) :]

        return mutate

    def test_repository_workflow_passes(self) -> None:
        completed = self.run_policy(WORKFLOW)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn(
            "CI workflow privilege and provenance policy passed",
            completed.stdout,
        )

    def test_top_level_write_all_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "permissions:\n  contents: read\n",
                "permissions: write-all\n",
            )
        )

    def test_job_write_all_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "  quality:\n    name: Formatting, unit tests, and module evaluation\n",
                "  quality:\n"
                "    name: Formatting, unit tests, and module evaluation\n"
                "    permissions: write-all\n",
            )
        )

    def test_inline_permissions_are_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "permissions:\n  contents: read\n",
                "permissions: { contents: read }\n",
            )
        )

    def test_quoted_permissions_key_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "permissions:\n  contents: read\n",
                '"permissions":\n  contents: read\n',
            )
        )

    def test_quoted_permissions_entry_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "permissions:\n  contents: read\n",
                'permissions:\n  "contents": read\n',
            )
        )

    def test_bracket_secret_access_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "secrets.CACHIX_AUTH_TOKEN",
                "secrets['CACHIX_AUTH_TOKEN']",
            )
        )

    def test_whole_secrets_context_access_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "      - name: Check formatting\n",
                "      - name: Check formatting\n"
                "        env:\n"
                "          ALL_SECRETS: ${{ toJSON(secrets) }}\n",
            )
        )

    def test_cache_secret_moved_out_of_cachix_step_is_rejected(self) -> None:
        auth_token = (
            "          authToken: ${{ github.event_name == 'push' && "
            "github.ref == 'refs/heads/main' && secrets.CACHIX_AUTH_TOKEN || '' }}\n"
        )

        def mutate(source: str) -> str:
            self.assertIn(auth_token, source)
            source = source.replace(auth_token, "", 1)
            marker = "      - name: Check formatting\n"
            self.assertIn(marker, source)
            return source.replace(
                marker,
                marker
                + "        env:\n"
                + "          MOVED_CACHE_TOKEN: ${{ secrets.CACHIX_AUTH_TOKEN }}\n",
                1,
            )

        self.assert_policy_rejects(mutate)

    def test_extra_secret_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "  provisioning-image:\n"
                "    name: Raspberry Pi 5 operator-started secure-boot station image\n",
                "  provisioning-image:\n"
                "    name: Raspberry Pi 5 operator-started secure-boot station image\n"
                "    env:\n"
                "      RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
            )
        )

    def test_old_pages_assembly_not_cancelled_condition_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_nth(
                "        if: ${{ success() &&",
                "        if: ${{ !cancelled() &&",
                1,
            )
        )

    def test_old_pages_upload_not_cancelled_condition_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_nth(
                "        if: ${{ success() &&",
                "        if: ${{ !cancelled() &&",
                2,
            )
        )

    def test_old_deploy_not_cancelled_condition_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "    if: ${{ success() && github.ref == 'refs/heads/main' &&",
                "    if: ${{ !cancelled() && github.ref == 'refs/heads/main' &&",
            )
        )

    def test_missing_enforce_gates_condition_binding_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                " && steps.enforce_gates.outcome == 'success'",
                "",
            )
        )

    def test_missing_enforce_gates_step_id_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once("        id: enforce_gates\n", "")
        )

    def test_unpinned_action_is_rejected(self) -> None:
        self.assert_policy_rejects(
            self.replace_once(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v7",
            )
        )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: ci_workflow_policy_test.py POLICY CI_WORKFLOW",
            file=sys.stderr,
        )
        return 2

    global POLICY, WORKFLOW
    POLICY = Path(argv[1])
    WORKFLOW = Path(argv[2])
    program = unittest.main(argv=[argv[0]], exit=False)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
