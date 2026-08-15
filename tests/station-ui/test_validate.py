from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WEB_ROOT = ROOT / "provisioning" / "internal" / "provisioning" / "stationui" / "web"
sys.path.insert(0, str(HERE))

import validate  # noqa: E402


class StationUIValidationTests(unittest.TestCase):
    def test_repository_assets_pass(self) -> None:
        validate.validate(WEB_ROOT)

    def test_external_dependency_is_rejected(self) -> None:
        with self.fixture() as fixture:
            index = fixture / "index.html"
            index.write_text(
                index.read_text(encoding="utf-8").replace(
                    "</head>", '<script src="https://example.invalid/ui.js"></script></head>'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "local JavaScript|external assets"):
                validate.validate(fixture)

    def test_missing_safety_boundary_is_rejected(self) -> None:
        with self.fixture() as fixture:
            index = fixture / "index.html"
            index.write_text(
                index.read_text(encoding="utf-8").replace(
                    "SIMULATION ONLY · LIVE MUTATION AND ENROLLMENT UNAVAILABLE",
                    "LIVE PROVISIONING AVAILABLE",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "live-capability boundary"):
                validate.validate(fixture)

    def test_hard_coded_workflow_progress_is_rejected(self) -> None:
        with self.fixture() as fixture:
            index = fixture / "index.html"
            index.write_text(
                index.read_text(encoding="utf-8").replace(
                    '<li class="is-current" aria-current="step">',
                    '<li class="is-current" aria-current="step" data-step="commit">',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must not be hard-coded"):
                validate.validate(fixture)

    def test_live_target_boundary_is_required(self) -> None:
        with self.fixture() as fixture:
            index = fixture / "index.html"
            index.write_text(
                index.read_text(encoding="utf-8").replace("no live target access", "direct target access"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "live target boundary"):
                validate.validate(fixture)

    def test_all_false_safety_capabilities_are_required_in_both_clients(self) -> None:
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
            for asset in ("app.js", "transport.js"):
                with self.subTest(capability=capability, asset=asset), self.fixture() as fixture:
                    script = fixture / asset
                    script.write_text(
                        script.read_text(encoding="utf-8").replace(
                            f'"{capability}"',
                            '"removed_capability"',
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "safety contract"):
                        validate.validate(fixture)

    def test_one_shot_commit_styling_is_required(self) -> None:
        with self.fixture() as fixture:
            styles = fixture / "styles.css"
            styles.write_text(
                styles.read_text(encoding="utf-8").replace(".button-commit", ".button-ordinary"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "one-shot simulated commit styling"):
                validate.validate(fixture)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        fixture = Path(temporary.name) / "web"
        shutil.copytree(WEB_ROOT, fixture)
        for path in fixture.rglob("*"):
            if path.is_file():
                path.chmod(0o600)

        class FixtureContext:
            def __enter__(self):
                return fixture

            def __exit__(self, exc_type, exc, traceback):
                temporary.cleanup()

        return FixtureContext()


if __name__ == "__main__":
    unittest.main()
