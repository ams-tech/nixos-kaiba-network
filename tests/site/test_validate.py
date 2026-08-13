#!/usr/bin/env python3
"""Unit tests for the assembled GitHub Pages site validator."""

from __future__ import annotations

import contextlib
import io
import json
import os
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
STATION_PAGES = Path(os.environ["KAIBA_STATION_PAGES"])


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
                "--provisioning",
                str(FIXTURES / "provisioning.json"),
                "--provisioning-schema",
                str(REPORT / "provisioning.schema.json"),
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
        root.chmod(0o700)
        shutil.copytree(STATION_PAGES, root / "provisioning-demo", dirs_exist_ok=True)
        shutil.copytree(self.render_report(failed=failed), report_root, dirs_exist_ok=True)
        for path in root.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        return root

    def validation_result(self, root: Path) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = validate.main([str(root)])
        return status, output.getvalue()

    def execute_homepage_script(self, *, dns_available: bool = True) -> dict[str, object]:
        dns = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
        provisioning = json.loads((FIXTURES / "provisioning.json").read_text(encoding="utf-8"))
        script = r"""
const fs = require("fs");
class ClassList {
  constructor() { this.values = new Set(); }
  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
}
const ids = [
  "report-link",
  "report-signal",
  "report-signal-text",
  "report-status",
  "report-summary",
  "report-assertions",
  "provisioning-automated-status",
  "provisioning-hardware-status",
  "provisioning-summary",
];
const elements = new Map(ids.map((id) => [id, { classList: new ClassList(), textContent: "" }]));
elements.get("report-link").href = "https://example.invalid/reports/latest/";
global.document = { querySelector: (selector) => elements.get(selector.slice(1)) };
const dns = JSON.parse(process.argv[2]);
const provisioning = JSON.parse(process.argv[3]);
const dnsAvailable = process.argv[4] === "true";
const fetched = [];
global.fetch = (url) => {
  const value = String(url);
  fetched.push(value);
  const isProvisioning = value.endsWith("/provisioning.json");
  return Promise.resolve({
    ok: isProvisioning || dnsAvailable,
    json: () => Promise.resolve(isProvisioning ? provisioning : dns),
  });
};
eval(fs.readFileSync(process.argv[1], "utf8"));
setTimeout(() => {
  process.stdout.write(JSON.stringify({
    fetched,
    dnsSignal: elements.get("report-signal-text").textContent,
    dnsStatus: elements.get("report-status").textContent,
    automatedStatus: elements.get("provisioning-automated-status").textContent,
    hardwareStatus: elements.get("provisioning-hardware-status").textContent,
    provisioningSummary: elements.get("provisioning-summary").textContent,
  }));
}, 0);
"""
        completed = subprocess.run(
            [
                "node",
                "-e",
                script,
                str(SITE / "site.js"),
                json.dumps(dns),
                json.dumps(provisioning),
                str(dns_available).lower(),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_complete_project_site_is_valid(self) -> None:
        status, output = self.validation_result(self.assemble_site())
        self.assertEqual(0, status, output)

    def test_missing_dns_product_page_is_rejected(self) -> None:
        root = self.assemble_site()
        (root / "dns" / "index.html").unlink()

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("missing required file: dns/index.html", output)

    def test_missing_provisioning_product_page_is_rejected(self) -> None:
        root = self.assemble_site()
        (root / "provisioning" / "index.html").unlink()

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("missing required file: provisioning/index.html", output)

    def test_homepage_must_link_to_dns_product_page(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.write_text(
            index.read_text(encoding="utf-8").replace(
                'href="./dns/"',
                'href="https://example.invalid/dns/"',
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("direct dns/ product link is required", output)

    def test_homepage_must_link_to_provisioning_product_page(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.write_text(
            index.read_text(encoding="utf-8").replace(
                'href="./provisioning/"',
                'href="https://example.invalid/provisioning/"',
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("direct provisioning/ product link is required", output)

    def test_broken_product_page_reference_is_rejected(self) -> None:
        root = self.assemble_site()
        dns_page = root / "dns" / "index.html"
        dns_page.write_text(
            dns_page.read_text(encoding="utf-8").replace(
                'href="../styles.css"',
                'href="../missing-styles.css"',
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("dns/index.html: missing local target", output)

    def test_product_detail_page_requires_one_h1(self) -> None:
        root = self.assemble_site()
        page = root / "provisioning" / "index.html"
        page.write_text(
            page.read_text(encoding="utf-8")
            .replace('<h2 id="current-title">', '<h1 id="current-title">')
            .replace('</h2>\n            <p>\n              Acquisition', '</h1>\n            <p>\n              Acquisition', 1),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("provisioning/index.html: exactly one h1 is required", output)

    def test_homepage_keeps_dns_and_provisioning_status_separate(self) -> None:
        result = self.execute_homepage_script(dns_available=False)
        self.assertEqual("DNS report status unavailable", result["dnsSignal"])
        self.assertEqual("STATUS UNAVAILABLE", result["dnsStatus"])
        self.assertEqual("PARTIAL (2 / 3)", result["automatedStatus"])
        self.assertEqual("PENDING — MANUAL", result["hardwareStatus"])
        self.assertIn("not run in CI", result["provisioningSummary"])
        self.assertEqual(
            [
                "https://example.invalid/reports/latest/result.json",
                "https://example.invalid/reports/latest/provisioning.json",
            ],
            result["fetched"],
        )

    def test_well_formed_failed_report_is_valid(self) -> None:
        status, output = self.validation_result(self.assemble_site(failed=True))
        self.assertEqual(0, status, output)

    def test_missing_provisioning_result_is_rejected(self) -> None:
        root = self.assemble_site()
        provisioning = root / "reports" / "latest" / "provisioning.json"
        provisioning.unlink()

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("missing required file: reports/latest/provisioning.json", output)
        self.assertIn("report manifest names absent files: provisioning.json", output)

    def test_missing_station_demo_is_rejected(self) -> None:
        root = self.assemble_site()
        shutil.rmtree(root / "provisioning-demo")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("missing required file: provisioning-demo/index.html", output)

    def test_unsafe_station_demo_graph_is_rejected(self) -> None:
        root = self.assemble_site()
        graph_path = root / "provisioning-demo" / "workflow-graph.json"
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        graph["nodes"][graph["default_node"]]["state"]["safety"]["mutation_eligible"] = True
        graph_path.write_text(json.dumps(graph), encoding="utf-8")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("violates the simulation safety contract", output)

    def test_inconsistent_provisioning_overall_is_rejected(self) -> None:
        root = self.assemble_site()
        provisioning = root / "reports" / "latest" / "provisioning.json"
        result = json.loads(provisioning.read_text(encoding="utf-8"))
        result["automated"]["overall"] = "failed"
        provisioning.write_text(json.dumps(result), encoding="utf-8")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("automated overall must be", output)

    def test_malformed_hardware_qualification_status_is_rejected(self) -> None:
        root = self.assemble_site()
        provisioning = root / "reports" / "latest" / "provisioning.json"
        result = json.loads(provisioning.read_text(encoding="utf-8"))
        result["hardware_qualification"]["status"] = "not-run"
        provisioning.write_text(json.dumps(result), encoding="utf-8")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("malformed hardware qualification status", output)

    def test_duplicate_provisioning_check_pair_is_rejected(self) -> None:
        root = self.assemble_site()
        provisioning = root / "reports" / "latest" / "provisioning.json"
        result = json.loads(provisioning.read_text(encoding="utf-8"))
        result["automated"]["checks"].append(result["automated"]["checks"][0])
        provisioning.write_text(json.dumps(result), encoding="utf-8")

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("duplicate automated system/check pairs", output)

    def test_provisioning_status_must_be_accessible(self) -> None:
        root = self.assemble_site()
        index = root / "index.html"
        index.chmod(index.stat().st_mode | 0o200)
        index.write_text(
            index.read_text(encoding="utf-8").replace(
                'id="provisioning-hardware-status"\n                  role="status"\n                  aria-live="polite"',
                'id="provisioning-hardware-status"',
            ),
            encoding="utf-8",
        )

        status, output = self.validation_result(root)
        self.assertEqual(1, status)
        self.assertIn("provisioning-hardware-status", output)

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
