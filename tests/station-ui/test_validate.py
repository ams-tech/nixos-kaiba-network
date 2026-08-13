from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WEB_ROOT = ROOT / "internal" / "provisioning" / "stationui" / "web"
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
                index.read_text(encoding="utf-8").replace("PERSISTENT MUTATION BLOCKED", "PERSISTENT CHANGE AVAILABLE"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "mutation boundary"):
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
