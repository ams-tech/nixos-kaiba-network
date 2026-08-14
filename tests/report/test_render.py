from __future__ import annotations

import hashlib
import io
import json
import shutil
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


def hardware_qualification_record() -> dict[str, object]:
    digest = "sha256:" + "a" * 64
    comparison_fields = [
        "target_fingerprint",
        "user_serial",
        "factory_uuid",
        "board_revision",
        "board_attributes",
        "ethernet_mac",
        "wifi_mac",
        "bluetooth_mac",
        "boot_rom",
        "eeprom_hash",
        "customer_key_hash",
        "customer_key_state",
        "videocore_jtag_locked",
        "signature_mode",
        "advanced_boot",
    ]
    probe = {
        "sequence": 1,
        "evidence_digest": digest,
        "target_fingerprint": digest,
        "board_revision": {
            "raw": "b04170",
            "new_style": True,
            "memory_code": 3,
            "manufacturer_code": 0,
            "processor_code": 4,
            "model_code": 23,
            "pcb_revision": 0,
        },
        "board_attributes": "00000000",
        "boot_rom": "0000000a",
        "eeprom_hash": None,
        "customer_key_hash": "0" * 64,
        "customer_key_state": "unset",
        "videocore_jtag_locked": False,
        "assessment": {
            "device_class_status": "pass",
            "observable_baseline_status": "pass",
            "eligible_for_reversible_qualification": True,
            "mutation_eligible": False,
            "full_unprovisioned_state": "not_established",
        },
        "mutation_audit": {"success_reported": False},
    }
    return {
        "schema_version": "provisioning.kaiba.network/rpi5-hardware-qualification/v1alpha1",
        "source_revision": "c" * 40,
        "station_system": "x86_64-linux",
        "nix_system_closure_digest": digest,
        "profile": {
            "id": "raspberry-pi-5-model-b-v1alpha1",
            "status": "experimental",
            "digest": digest,
            "policy_digest": digest,
        },
        "adapter": {"id": "raspberrypi.rpi5.otp-metadata", "version": "v1alpha1"},
        "source": {
            "kind": "live-rpiboot",
            "tool_version": "test",
            "tool_digest": digest,
            "bundle_digest": digest,
            "firmware_digest": digest,
            "config_digest": digest,
            "lane_continuity": "match",
            "usb_path_continuity": "match",
        },
        "probes": [probe, {**probe, "sequence": 2}],
        "comparisons": [
            {"field": field, "status": "not_observed" if field == "eeprom_hash" else "match"}
            for field in comparison_fields
        ],
        "power_cycle_confirmation": "operator_confirmed_complete",
        "pre_probe_normal_boot_confirmation": "operator_confirmed_normal",
        "normal_boot_confirmation": "operator_confirmed_unchanged",
        "status": "passed",
        "quarantine_required": False,
        "findings": [],
        "mutation_eligible": False,
        "full_unprovisioned_state": "not_established",
        "disclaimer": (
            "This observation is correlation and partial preflight evidence; it is not device authentication or "
            "attestation and does not authorize irreversible provisioning."
        ),
    }


class ReportRendererTest(unittest.TestCase):
    gate_args = ["--manifest", str(FIXTURES / "required-assertions.json")]

    def render_fixture(
        self,
        output: Path,
        *,
        result_path: Path | None = None,
        evidence: Path | None = None,
        provisioning_path: Path | None = None,
        platform_results: list[Path] | None = None,
        expected_source_revision: str | None = None,
    ) -> None:
        render.render(
            result_path or FIXTURES / "result.json",
            FIXTURES / "events.jsonl",
            evidence or FIXTURES / "evidence",
            REPO_ROOT / "tests" / "topology.json",
            output,
            zones_root=FIXTURES / "zones",
            provisioning_path=provisioning_path or FIXTURES / "provisioning.json",
            provisioning_schema_path=REPORT_DIR / "provisioning.schema.json",
            platform_result_paths=platform_results or [],
            expected_source_revision=expected_source_revision,
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
                    Path("provisioning.json"),
                    Path("provisioning.schema.json"),
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
            provisioning = json.loads((output / "provisioning.json").read_text(encoding="utf-8"))
            pairs = [(item["id"], item["system"]) for item in provisioning["automated"]["checks"]]
            self.assertEqual(pairs, sorted(pairs))

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
                    "--provisioning",
                    str(FIXTURES / "provisioning.json"),
                    "--provisioning-schema",
                    str(REPORT_DIR / "provisioning.schema.json"),
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

    def test_provisioning_section_separates_automated_and_hardware_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            self.render_fixture(output)
            markdown = (output / "index.md").read_text(encoding="utf-8")
            page = (output / "index.html").read_text(encoding="utf-8")
            junit = (output / "junit.xml").read_text(encoding="utf-8")
            self.assertIn("Provisioning automation:** PARTIAL", markdown)
            self.assertIn("Hardware qualification:** PENDING", markdown)
            self.assertIn("Hardware qualification is a separate manual gate", page)
            self.assertIn('name="kaiba-rpi5-provisioning-probe"', junit)
            self.assertIn('skipped="1"', junit)
            self.assertNotIn("Hardware qualification", junit)

    def test_completed_hardware_evidence_is_copied_linked_and_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            shutil.copytree(FIXTURES / "evidence", evidence)
            evidence.chmod(0o755)
            relative = Path("provisioning/hardware-qualification/sacrificial-pi-5.json")
            public_record = evidence / relative
            public_record.parent.mkdir(parents=True)
            public_record.write_text(
                json.dumps(hardware_qualification_record(), sort_keys=True, indent=2)
                + "\n",
                encoding="utf-8",
            )
            provisioning = json.loads((FIXTURES / "provisioning.json").read_text(encoding="utf-8"))
            evidence_reference = f"evidence/{relative.as_posix()}"
            provisioning["hardware_qualification"] = {
                "status": "passed",
                "description": "A sacrificial Pi 5 passed the reviewed physical ceremony.",
                "evidence": [evidence_reference],
            }
            provisioning_path = root / "provisioning.json"
            provisioning_path.write_text(json.dumps(provisioning), encoding="utf-8")

            first, second = root / "first", root / "second"
            self.render_fixture(first, evidence=evidence, provisioning_path=provisioning_path)
            self.render_fixture(second, evidence=evidence, provisioning_path=provisioning_path)
            self.assertEqual((first / evidence_reference).read_bytes(), public_record.read_bytes())
            self.assertIn(evidence_reference, (first / "index.md").read_text(encoding="utf-8"))
            manifest = (first / "manifest.sha256").read_text(encoding="utf-8")
            self.assertIn(evidence_reference, manifest)
            self.assertEqual(
                {path.relative_to(first): path.read_bytes() for path in first.rglob("*") if path.is_file()},
                {path.relative_to(second): path.read_bytes() for path in second.rglob("*") if path.is_file()},
            )

    def test_provisioning_rejects_inconsistent_status_duplicate_and_invalid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = json.loads((FIXTURES / "provisioning.json").read_text(encoding="utf-8"))
            cases: list[tuple[str, dict[str, object], str]] = []

            inconsistent = json.loads(json.dumps(base))
            inconsistent["automated"]["overall"] = "passed"
            cases.append(("inconsistent", inconsistent, "must be 'partial'"))

            duplicate = json.loads(json.dumps(base))
            duplicate["automated"]["checks"].append(json.loads(json.dumps(duplicate["automated"]["checks"][0])))
            cases.append(("duplicate", duplicate, "duplicate value"))

            completed_without_evidence = json.loads(json.dumps(base))
            completed_without_evidence["hardware_qualification"]["status"] = "passed"
            cases.append(("hardware", completed_without_evidence, "must cite evidence"))

            pending_with_evidence = json.loads(json.dumps(base))
            pending_with_evidence["hardware_qualification"]["evidence"] = ["evidence/resolution/public-answers.txt"]
            cases.append(("pending", pending_with_evidence, "must be empty"))

            missing_evidence = json.loads(json.dumps(base))
            missing_evidence["automated"]["checks"][1]["evidence"] = ["evidence/provisioning/missing.txt"]
            cases.append(("missing", missing_evidence, "missing evidence files"))

            for name, value, expected in cases:
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(render.ReportError, expected):
                        self.render_fixture(root / f"report-{name}", provisioning_path=path)

    def test_platform_result_replaces_only_matching_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = {
                "schema_version": 1,
                "suite": "kaiba-rpi5-provisioning-platform-result",
                "system": "aarch64-linux",
                "source_revision": "a" * 40,
                "checks": [
                    {
                        "id": "go-probe-tests",
                        "status": "passed",
                        "description": "Provisioning probe Go tests pass on the target platform",
                        "evidence": [],
                    }
                ],
            }
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            output = root / "report"
            self.render_fixture(output, platform_results=[receipt_path])
            provisioning = json.loads((output / "provisioning.json").read_text(encoding="utf-8"))
            self.assertEqual("passed", provisioning["automated"]["overall"])
            arm = next(item for item in provisioning["automated"]["checks"] if item["system"] == "aarch64-linux")
            self.assertEqual("passed", arm["status"])
            self.assertEqual("a" * 40, arm["source_revision"])

            bad = json.loads(json.dumps(receipt))
            bad["checks"][0]["id"] = "uncontracted-check"
            bad_path = root / "bad-receipt.json"
            bad_path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(render.ReportError, "missing checks.*unexpected"):
                self.render_fixture(root / "bad-report", platform_results=[bad_path])

            with self.assertRaisesRegex(render.ReportError, "does not match"):
                self.render_fixture(
                    root / "revision-mismatch-report",
                    platform_results=[receipt_path],
                    expected_source_revision="b" * 40,
                )

            with self.assertRaisesRegex(render.ReportError, "requires at least one"):
                self.render_fixture(
                    root / "receipt-missing-report",
                    expected_source_revision="a" * 40,
                )

    def test_published_provisioning_schema_is_valid_and_strict(self) -> None:
        schema = json.loads((REPORT_DIR / "provisioning.schema.json").read_text(encoding="utf-8"))
        provisioning = json.loads((FIXTURES / "provisioning.json").read_text(encoding="utf-8"))
        self.assertEqual([], schema_gate.validate(schema, provisioning))
        provisioning["mutation_eligible"] = True
        self.assertTrue(any("mutation_eligible" in item for item in schema_gate.validate(schema, provisioning)))

    def test_hardware_qualification_evidence_schema_is_valid_strict_and_redacted(self) -> None:
        schema = json.loads(
            (REPO_ROOT / "provisioning" / "schemas" / "rpi5-hardware-qualification-v1alpha1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        record = hardware_qualification_record()
        self.assertEqual([], schema_gate.validate(schema, record))

        observed = json.loads(json.dumps(record))
        for probe in observed["probes"]:
            probe["eeprom_hash"] = "b" * 64
        observed["comparisons"][9]["status"] = "match"
        self.assertEqual([], schema_gate.validate(schema, observed))

        null_match = json.loads(json.dumps(record))
        null_match["comparisons"][9]["status"] = "match"
        self.assertTrue(any("comparisons" in item for item in schema_gate.validate(schema, null_match)))

        observed_not_observed = json.loads(json.dumps(observed))
        observed_not_observed["comparisons"][9]["status"] = "not_observed"
        self.assertTrue(any("comparisons" in item for item in schema_gate.validate(schema, observed_not_observed)))

        mixed_match = json.loads(json.dumps(observed))
        mixed_match["probes"][0]["eeprom_hash"] = None
        self.assertTrue(any("comparisons" in item for item in schema_gate.validate(schema, mixed_match)))

        reverse_mixed_match = json.loads(json.dumps(observed))
        reverse_mixed_match["probes"][1]["eeprom_hash"] = None
        self.assertTrue(any("comparisons" in item for item in schema_gate.validate(schema, reverse_mixed_match)))

        for null_probe in (0, 1):
            with self.subTest(null_probe=null_probe):
                mixed_changed = json.loads(json.dumps(observed))
                mixed_changed["probes"][null_probe]["eeprom_hash"] = None
                mixed_changed["comparisons"][9]["status"] = "changed"
                mixed_changed["status"] = "failed"
                mixed_changed["quarantine_required"] = True
                mixed_changed["findings"] = ["eeprom-hash-changed"]
                self.assertEqual([], schema_gate.validate(schema, mixed_changed))

        incomplete = json.loads(json.dumps(record))
        incomplete["status"] = "incomplete"
        incomplete["normal_boot_confirmation"] = "not_yet_observed"
        self.assertEqual([], schema_gate.validate(schema, incomplete))

        missing_hash = json.loads(json.dumps(record))
        del missing_hash["probes"][0]["eeprom_hash"]
        self.assertTrue(any("eeprom_hash" in item for item in schema_gate.validate(schema, missing_hash)))

        malformed_hash = json.loads(json.dumps(record))
        malformed_hash["probes"][0]["eeprom_hash"] = "not-a-hash"
        self.assertTrue(any("eeprom_hash" in item for item in schema_gate.validate(schema, malformed_hash)))

        unrelated_not_observed = json.loads(json.dumps(record))
        unrelated_not_observed["comparisons"][0]["status"] = "not_observed"
        self.assertTrue(any("comparisons[0].status" in item for item in schema_gate.validate(schema, unrelated_not_observed)))

        changed_while_passed = json.loads(json.dumps(record))
        changed_while_passed["comparisons"][9]["status"] = "changed"
        self.assertNotEqual([], schema_gate.validate(schema, changed_while_passed))

        unredacted = json.loads(json.dumps(record))
        unredacted["probes"][0]["user_serial"] = "private-inventory-value"
        self.assertTrue(any("user_serial" in item for item in schema_gate.validate(schema, unredacted)))

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
