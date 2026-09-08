#!/usr/bin/env python3
"""Unit tests for the assembled GitHub Pages site validator."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


REPOSITORY = Path(__file__).resolve().parents[2]
SITE = REPOSITORY / "site"
REPORT = REPOSITORY / "tests" / "report"
FIXTURES = REPORT / "fixtures"


class SiteValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def render_report(self, *, failed: bool = False) -> Path:
        result_path = FIXTURES / "result.json"
        if failed:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["overall"] = "failed"
            result["assertions"][0]["status"] = "failed"
            result_path = self.workspace / "failed-result.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")

        output = self.workspace / ("failed-report" if failed else "report")
        subprocess.run(
            [
                sys.executable,
                str(REPORT / "render.py"),
                "--result",
                str(result_path),
                "--events",
                str(FIXTURES / "events.jsonl"),
                "--evidence",
                str(FIXTURES / "evidence"),
                "--zones",
                str(FIXTURES / "zones"),
                "--topology",
                str(REPOSITORY / "tests" / "topology.json"),
                "--output",
                str(output),
            ],
            check=True,
        )
        return output

    def assemble_site(self, *, failed: bool = False) -> Path:
        root = self.workspace / ("failed-site" if failed else "pages-site")
        report_root = root / "reports" / "latest"
        report_root.mkdir(parents=True)
        shutil.copytree(SITE, root, dirs_exist_ok=True)
        shutil.copytree(self.render_report(failed=failed), report_root, dirs_exist_ok=True)
        return root

    def validation_result(self, root: Path) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = validate.main([str(root)])
        return status, output.getvalue()

    def test_complete_project_site_is_valid(self) -> None:
        status, output = self.validation_result(self.assemble_site())
        self.assertEqual(0, status, output)

    def test_well_formed_failed_report_is_valid(self) -> None:
        status, output = self.validation_result(self.assemble_site(failed=True))
        self.assertEqual(0, status, output)

    def test_protocol_relative_reference_is_rejected(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.chmod(index.stat().st_mode | 0o200)
        index.write_text(
            index.read_text(encoding="utf-8").replace(
                '<link rel="stylesheet" href="./styles.css">',
                '<link rel="stylesheet" href="//example.invalid/styles.css">',
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("protocol-relative URL is not allowed", output)

    def test_root_relative_reference_is_rejected(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.chmod(index.stat().st_mode | 0o200)
        index.write_text(
            index.read_text(encoding="utf-8").replace("./styles.css", "/styles.css"),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("root-relative URL breaks project Pages", output)

    def test_script_url_is_rejected(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.chmod(index.stat().st_mode | 0o200)
        index.write_text(
            index.read_text(encoding="utf-8").replace(
                'href="https://github.com/ams-tech/nixos-kaiba-network"',
                'href="javascript:alert(document.domain)"',
                1,
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("URL scheme is not allowed", output)

    def test_nested_manifest_named_file_must_be_hashed(self) -> None:
        root = self.assemble_site()
        nested_manifest = root / "reports" / "latest" / "evidence" / "manifest.sha256"
        nested_manifest.write_text("untracked evidence\n", encoding="utf-8")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("report manifest is missing files: evidence/manifest.sha256", output)


if __name__ == "__main__":
    unittest.main()
