from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPORT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPORT_DIR))

import platform_receipt  # noqa: E402
import render  # noqa: E402


class PlatformReceiptTest(unittest.TestCase):
    def platform_result(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "suite": "kaiba-rpi5-provisioning-platform-result",
            "system": "aarch64-linux",
            "checks": [
                {
                    "id": "provision-package",
                    "status": "passed",
                    "description": "The native provision package built.",
                    "evidence": [],
                },
                {
                    "id": "go-tests",
                    "status": "passed",
                    "description": "The native Go tests passed.",
                    "evidence": [],
                },
            ],
        }

    def test_receipt_is_revision_bound_canonical_and_new_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "platform.json"
            first = root / "first.json"
            second = root / "second.json"
            source.write_text(json.dumps(self.platform_result()), encoding="utf-8")

            platform_receipt.create_receipt(source, "a" * 40, first)
            platform_receipt.create_receipt(source, "a" * 40, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            receipt = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual("a" * 40, receipt["source_revision"])
            self.assertEqual(
                ["go-tests", "provision-package"],
                [item["id"] for item in receipt["checks"]],
            )
            with self.assertRaises(FileExistsError):
                platform_receipt.create_receipt(source, "a" * 40, first)

    def test_receipt_rejects_malformed_or_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1,"suite":"kaiba-rpi5-provisioning-platform-result"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(render.ReportError, "duplicate object key"):
                platform_receipt.create_receipt(duplicate, "a" * 40, root / "duplicate-receipt.json")

            oversized = root / "oversized.json"
            oversized.write_text(" " * (platform_receipt.MAX_INPUT_BYTES + 1), encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "exceeds"):
                platform_receipt.create_receipt(oversized, "a" * 40, root / "oversized-receipt.json")

    def test_cli_rejects_a_non_revision_without_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "platform.json"
            source.write_text(json.dumps(self.platform_result()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPORT_DIR / "platform_receipt.py"),
                    "--input",
                    str(source),
                    "--source-revision",
                    "NOT-A-REVISION",
                    "--output",
                    str(root / "receipt.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, completed.returncode)
            self.assertEqual("", completed.stdout)
            self.assertIn("lowercase 40- or 64-hex", completed.stderr)


if __name__ == "__main__":
    unittest.main()
