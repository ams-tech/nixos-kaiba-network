from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


REPORT_DIR = Path(__file__).resolve().parent
REPO_ROOT = REPORT_DIR.parent.parent
FIXTURES = REPORT_DIR / "fixtures"
sys.path.insert(0, str(REPORT_DIR))

import gate  # noqa: E402
import render  # noqa: E402
import schema_gate  # noqa: E402


class ReportRendererTest(unittest.TestCase):
    gate_args = ["--manifest", str(FIXTURES / "required-assertions.json")]

    def render_fixture(self, output: Path, *, result_path: Path | None = None, evidence: Path | None = None) -> None:
        render.render(
            result_path or FIXTURES / "result.json",
            FIXTURES / "events.jsonl",
            evidence or FIXTURES / "evidence",
            REPO_ROOT / "tests" / "topology.json",
            output,
            zones_root=FIXTURES / "zones",
        )

    def test_complete_report_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            self.render_fixture(first)
            self.render_fixture(second)
            first_files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
            second_files = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
            self.assertEqual(first_files, second_files)
            self.assertEqual(
                {path: (first / path).read_bytes() for path in first_files},
                {path: (second / path).read_bytes() for path in second_files},
            )
            self.assertEqual(
                {
                    Path("events.jsonl"),
                    Path("index.html"),
                    Path("index.md"),
                    Path("junit.xml"),
                    Path("manifest.sha256"),
                    Path("result.json"),
                    Path("result.schema.json"),
                    Path("topology.dot"),
                    Path("topology.json"),
                    Path("topology.svg"),
                    Path("zones/p0.zone"),
                    Path("zones/public-a.zone"),
                    Path("evidence/delegation/dig-ns.txt"),
                    Path("evidence/outage/public-a.txt"),
                    Path("evidence/resolution/public-answers.txt"),
                    Path("evidence/update/controller.txt"),
                },
                set(first_files),
            )

    def test_topology_declares_seven_nodes_three_vlans_and_hidden_origins(self) -> None:
        topology = render.validate_topology(
            render.normalize_and_scan(
                json.loads((REPO_ROOT / "tests" / "topology.json").read_text(encoding="utf-8")),
                "topology",
            )
        )
        self.assertEqual(render.EXPECTED_NODES, {item["id"] for item in topology["nodes"]})
        self.assertEqual({1, 2, 3}, {item["vlan"] for item in topology["networks"] if item["kind"] == "vlan"})
        self.assertEqual({"public-a", "public-b"}, set(topology["delegation"]["nameservers"]))
        self.assertEqual({"p0", "p1"}, set(topology["delegation"]["hidden_origins"]))
        self.assertTrue(any(item["protocol"] == "RFC 2136 DNS UPDATE" for item in topology["edges"]))
        self.assertTrue(any("AXFR/IXFR" in item["protocol"] for item in topology["edges"]))

    def test_manifest_covers_every_other_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            self.render_fixture(output)
            lines = (output / "manifest.sha256").read_text(encoding="utf-8").splitlines()
            recorded: dict[str, str] = {}
            for line in lines:
                digest, relative = line.split("  ", 1)
                recorded[relative] = digest
            expected = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file() and path.name != "manifest.sha256"
            }
            self.assertEqual(expected, set(recorded))
            for relative, digest in recorded.items():
                self.assertEqual(digest, hashlib.sha256((output / relative).read_bytes()).hexdigest())

    def test_canonicalizes_unordered_collections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            self.render_fixture(output)
            result = json.loads((output / "result.json").read_text(encoding="utf-8"))
            events = [json.loads(line) for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([item["id"] for item in result["assertions"]], sorted(item["id"] for item in result["assertions"]))
            self.assertEqual([item["sequence"] for item in events], list(range(1, len(events) + 1)))
            self.assertEqual(result["claims"]["deferred"], sorted(result["claims"]["deferred"], key=lambda item: item["id"]))

    def test_failed_suite_still_renders_and_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
            result["overall"] = "failed"
            result["assertions"][0]["status"] = "failed"
            result["assertions"][0]["observed"] = []
            result_path = root / "failed.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            output = root / "report"
            self.render_fixture(output, result_path=result_path)
            self.assertTrue((output / "index.html").is_file())
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, gate.main(self.gate_args + [str(output / "result.json")]))
            junit = (output / "junit.xml").read_text(encoding="utf-8")
            self.assertIn('failures="1"', junit)
            self.assertIn("<failure", junit)

    def test_inconsistent_overall_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
            result["overall"] = "failed"
            result_path = root / "inconsistent.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "must be 'passed'"):
                self.render_fixture(root / "report", result_path=result_path)

    def test_missing_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
            result["assertions"][0]["evidence"] = ["evidence/not-collected.txt"]
            result_path = root / "missing.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "missing evidence files"):
                self.render_fixture(root / "report", result_path=result_path)

    def test_dynamic_noise_and_private_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
            result["assertions"][0]["observed"] = {"timestamp": "unstable"}
            result_path = root / "noise.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "dynamic-noise"):
                self.render_fixture(root / "report-one", result_path=result_path)

            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "key.txt").write_text("-----BEGIN PRIVATE KEY-----\nmaterial\n", encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "secret or non-deterministic"):
                render.collect_evidence(evidence)

    def test_cli_and_gate_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPORT_DIR / "render.py"),
                    "--result",
                    str(FIXTURES / "result.json"),
                    "--events",
                    str(FIXTURES / "events.jsonl"),
                    "--evidence",
                    str(FIXTURES / "evidence"),
                    "--zones",
                    str(FIXTURES / "zones"),
                    "--topology",
                    str(REPO_ROOT / "tests" / "topology.json"),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            schema_gated = subprocess.run(
                [
                    sys.executable,
                    str(REPORT_DIR / "schema_gate.py"),
                    "--schema",
                    str(output / "result.schema.json"),
                    "--instance",
                    str(output / "result.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, schema_gated.returncode, schema_gated.stderr)
            gated = subprocess.run(
                [
                    sys.executable,
                    str(REPORT_DIR / "gate.py"),
                    *self.gate_args,
                    str(output / "result.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, gated.returncode, gated.stderr)
            self.assertEqual("all 4 required assertions passed\n", gated.stdout)

    def test_gate_rejects_missing_extra_and_wrong_phase_assertions(self) -> None:
        manifest = gate.load_manifest(FIXTURES / "required-assertions.json")
        result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))

        missing = json.loads(json.dumps(result))
        missing["assertions"] = missing["assertions"][:-1]
        self.assertTrue(any("missing required assertion" in item for item in gate.evaluate(missing, manifest, "functional")))

        extra = json.loads(json.dumps(result))
        extra["assertions"].append(
            {
                "id": "undeclared-check",
                "phase": "resolution",
                "status": "passed",
            }
        )
        self.assertTrue(any("undeclared assertion" in item for item in gate.evaluate(extra, manifest, "functional")))

        wrong_phase = json.loads(json.dumps(result))
        wrong_phase["assertions"][0]["phase"] = "outage"
        self.assertTrue(any("phase is" in item for item in gate.evaluate(wrong_phase, manifest, "functional")))

    def test_security_gate_uses_manifest_subset(self) -> None:
        manifest = gate.load_manifest(FIXTURES / "required-assertions.json")
        result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
        self.assertEqual([], gate.evaluate(result, manifest, "security"))
        identity = next(item for item in result["assertions"] if item["id"] == "device-identity")
        identity["status"] = "failed"
        self.assertEqual(["assertion device-identity did not pass"], gate.evaluate(result, manifest, "security"))

    def test_published_schema_is_valid_and_rejects_malformed_result(self) -> None:
        schema = json.loads((REPORT_DIR / "result.schema.json").read_text(encoding="utf-8"))
        result = json.loads((FIXTURES / "result.json").read_text(encoding="utf-8"))
        self.assertEqual([], schema_gate.validate(schema, result))
        del result["suite"]
        self.assertTrue(any("suite" in item for item in schema_gate.validate(schema, result)))


if __name__ == "__main__":
    unittest.main()
