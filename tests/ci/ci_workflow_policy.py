#!/usr/bin/env python3

"""Enforce the main CI workflow's least-privilege and provenance contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path


EXPECTED_JOBS = (
    "quality",
    "aarch64-packages",
    "provisioning-image",
    "dns-integration",
    "deploy-report",
)
READ_ONLY_JOBS = EXPECTED_JOBS[:-1]
CHECKOUT_ACTION = "actions/checkout"
UPLOAD_ACTION = "actions/upload-artifact"
DOWNLOAD_ACTION = "actions/download-artifact"
UPLOAD_PAGES_ACTION = "actions/upload-pages-artifact"
CONFIGURE_PAGES_ACTION = "actions/configure-pages"
DEPLOY_PAGES_ACTION = "actions/deploy-pages"
CACHIX_ACTION = "cachix/cachix-action"
PROVISIONING_ARTIFACT = "kaiba-provisioning-aarch64-${{ github.sha }}"
CACHE_SECRET_JOBS = ("quality", "aarch64-packages", "dns-integration")
CACHE_AUTH_TOKEN_LINE = (
    "authToken: ${{ github.event_name == 'push' && "
    "github.ref == 'refs/heads/main' && secrets.CACHIX_AUTH_TOKEN || '' }}"
)
CACHE_SKIP_PUSH_LINE = (
    "skipPush: ${{ github.event_name != 'push' || "
    "github.ref != 'refs/heads/main' || secrets.CACHIX_AUTH_TOKEN == '' }}"
)
SECRET_CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])secrets(?![A-Za-z0-9_])")
PERMISSIONS_DECLARATION = re.compile(
    r'(?m)^(?P<indent> *)(?P<key>permissions|[\'\"]permissions[\'\"])'
    r"\s*:(?P<value>[^\n]*)$"
)
PAGES_CONDITION = (
    "${{ success() && github.ref == 'refs/heads/main' && "
    "github.event_name != 'pull_request' && steps.enforce_gates.outcome == "
    "'success' && steps.verify_report.outcome == 'success' && "
    "steps.collect_report.outcome == 'success' }}"
)
PAGES_UPLOAD_CONDITION = (
    "${{ success() && github.ref == 'refs/heads/main' && "
    "github.event_name != 'pull_request' && steps.enforce_gates.outcome == "
    "'success' && steps.assemble_pages.outcome == 'success' }}"
)
DEPLOY_CONDITION = (
    "${{ success() && github.ref == 'refs/heads/main' && "
    "github.event_name != 'pull_request' && "
    "needs.dns-integration.outputs.pages_artifact_id != '' }}"
)


def fail(message: str) -> None:
    raise SystemExit(f"CI workflow policy: {message}")


def require_once(source: str, value: str, label: str) -> int:
    count = source.count(value)
    if count != 1:
        fail(f"{label} must contain {value!r} exactly once, found {count}")
    return source.find(value)


def workflow_jobs(source: str) -> tuple[str, dict[str, str]]:
    marker = "jobs:\n"
    jobs_offset = require_once(source, marker, "workflow")
    preamble = source[:jobs_offset]
    matches = list(
        re.finditer(r"(?m)^  ([a-z0-9][a-z0-9-]*):\n", source[jobs_offset:])
    )
    names = tuple(match.group(1) for match in matches)
    if names != EXPECTED_JOBS:
        fail(f"expected ordered jobs {EXPECTED_JOBS!r}, found {names!r}")

    jobs: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = jobs_offset + match.start()
        end = (
            jobs_offset + matches[index + 1].start()
            if index + 1 < len(matches)
            else len(source)
        )
        jobs[match.group(1)] = source[start:end]
    return preamble, jobs


def permissions(source: str, indentation: int) -> dict[str, str] | None:
    prefix = " " * indentation
    matches = [
        match
        for match in PERMISSIONS_DECLARATION.finditer(source)
        if len(match.group("indent")) == indentation
    ]
    if not matches:
        return None
    if len(matches) != 1:
        fail(f"found {len(matches)} permissions declarations at indentation {indentation}")

    match = matches[0]
    if match.group(0) != f"{prefix}permissions:":
        fail(f"permissions declaration at indentation {indentation} is not canonical")

    entries: dict[str, str] = {}
    entry_prefix = " " * (indentation + 2)
    for line in source[match.end() :].splitlines():
        if not line.strip():
            continue
        line_indentation = len(line) - len(line.lstrip(" "))
        if line_indentation <= indentation:
            break
        entry = re.fullmatch(
            rf"{entry_prefix}([a-z][a-z-]*): ([a-z]+)", line
        )
        if entry is None:
            fail(f"permissions entry is not canonical: {line.strip()!r}")
        if entry.group(1) in entries:
            fail(f"permissions entry {entry.group(1)!r} is duplicated")
        entries[entry.group(1)] = entry.group(2)
    return entries


def secret_context_lines(source: str) -> list[str]:
    return [
        line.strip()
        for line in source.splitlines()
        if SECRET_CONTEXT.search(line)
    ]


def needs(job: str) -> tuple[str, ...]:
    match = re.search(r"(?m)^    needs:[ \t]*([^\n]*)$", job)
    if match is None:
        return ()
    inline = match.group(1).strip()
    if inline:
        return (inline,)
    return tuple(
        re.findall(r"(?m)^      - ([a-z0-9][a-z0-9-]*)\s*$", job[match.end() :])
    )


def action_steps(job: str, action: str) -> list[tuple[int, str, dict[str, str]]]:
    steps: list[tuple[int, str, dict[str, str]]] = []
    pattern = rf"(?m)^        uses:\s*{re.escape(action)}@([^\s#]+)[^\n]*$"
    for match in re.finditer(pattern, job):
        next_step = re.search(r"(?m)^      - ", job[match.end() :])
        end = match.end() + next_step.start() if next_step else len(job)
        step = job[match.start() : end]
        options = dict(
            re.findall(
                r"(?m)^          ([a-z][a-z0-9-]*):\s*([^\n]+?)\s*$",
                step,
            )
        )
        steps.append((match.start(), match.group(1), options))
    return steps


def require_action(
    job: str, action: str, label: str
) -> tuple[int, str, dict[str, str]]:
    steps = action_steps(job, action)
    if len(steps) != 1:
        fail(f"{label} must use {action} exactly once, found {len(steps)}")
    return steps[0]


def check_action_pins(source: str) -> None:
    uses = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", source)
    if not uses:
        fail("workflow contains no actions")
    for value in uses:
        if value.startswith("./"):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", value) is None:
            fail(f"external action is not pinned to one full commit: {value!r}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: ci_workflow_policy.py CI_WORKFLOW")

    workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
    preamble, jobs = workflow_jobs(workflow)
    check_action_pins(workflow)

    if "pull_request_target:" in preamble:
        fail("pull_request_target must not be enabled")
    require_once(preamble, "  pull_request:\n", "workflow triggers")
    require_once(preamble, "  push:\n    branches:\n      - main\n", "workflow triggers")
    require_once(preamble, "  workflow_dispatch:\n", "workflow triggers")
    if permissions(preamble, 0) != {"contents": "read"}:
        fail("workflow-wide permissions must be exactly contents: read")
    require_once(
        preamble,
        "  group: ci-${{ github.workflow }}-${{ github.ref }}\n"
        "  cancel-in-progress: true\n",
        "workflow concurrency",
    )

    expected_needs = {
        "quality": (),
        "aarch64-packages": ("quality",),
        "provisioning-image": ("quality",),
        "dns-integration": ("quality", "aarch64-packages"),
        "deploy-report": ("dns-integration",),
    }
    for name, expected in expected_needs.items():
        actual = needs(jobs[name])
        if actual != expected:
            fail(f"{name} dependencies are {actual!r}, expected {expected!r}")

    for name in READ_ONLY_JOBS:
        if permissions(jobs[name], 4) is not None:
            fail(f"{name} must inherit the read-only workflow permissions")
    if permissions(jobs["deploy-report"], 4) != {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    }:
        fail("deploy-report permissions must be contents:read, pages:write, id-token:write")
    if "contents: write" in workflow:
        fail("main CI must never receive contents: write")

    for name in READ_ONLY_JOBS:
        _, _, options = require_action(jobs[name], CHECKOUT_ACTION, name)
        if options.get("persist-credentials") != "false":
            fail(f"{name} checkout must disable persisted credentials")
    if action_steps(jobs["deploy-report"], CHECKOUT_ACTION):
        fail("deploy-report must not check out or execute repository code")

    expected_cache_secret_lines = [CACHE_AUTH_TOKEN_LINE, CACHE_SKIP_PUSH_LINE]
    if secret_context_lines(workflow) != expected_cache_secret_lines * len(
        CACHE_SECRET_JOBS
    ):
        fail("workflow contains a secret-context reference outside the exact cache policy")
    for name, job in jobs.items():
        observed_secret_lines = secret_context_lines(job)
        if name not in CACHE_SECRET_JOBS:
            if observed_secret_lines:
                fail(f"{name} must not reference the secrets context")
            continue

        cache_step = require_action(job, CACHIX_ACTION, name)
        if observed_secret_lines != expected_cache_secret_lines:
            fail(
                f"{name} secret references are not the exact Cachix write-token policy"
            )
        cache_step_start = cache_step[0]
        next_step = re.search(r"(?m)^      - ", job[cache_step_start:])
        cache_step_end = (
            cache_step_start + next_step.start()
            if next_step is not None
            else len(job)
        )
        if secret_context_lines(job[cache_step_start:cache_step_end]) != expected_cache_secret_lines:
            fail(f"{name} may reference CACHIX_AUTH_TOKEN only in its Cachix step")

    aarch = jobs["aarch64-packages"]
    dns = jobs["dns-integration"]
    aarch_upload = require_action(aarch, UPLOAD_ACTION, "aarch64-packages")
    dns_download = require_action(dns, DOWNLOAD_ACTION, "dns-integration")
    dns_report_upload = require_action(dns, UPLOAD_ACTION, "dns-integration")
    pages_upload = require_action(dns, UPLOAD_PAGES_ACTION, "dns-integration")
    if len(action_steps(workflow, UPLOAD_ACTION)) != 2:
        fail("only the ARM receipt and canonical DNS report may use upload-artifact")
    if len(action_steps(workflow, DOWNLOAD_ACTION)) != 1:
        fail("only dns-integration may download an Actions artifact")
    if len(action_steps(workflow, UPLOAD_PAGES_ACTION)) != 1:
        fail("only dns-integration may create a Pages artifact")
    for name in ("quality", "provisioning-image", "deploy-report"):
        for action in (UPLOAD_ACTION, DOWNLOAD_ACTION, UPLOAD_PAGES_ACTION):
            if action_steps(jobs[name], action):
                fail(f"{name} must not transfer {action} artifacts")
    for action in (DOWNLOAD_ACTION, UPLOAD_PAGES_ACTION):
        if action_steps(aarch, action):
            fail(f"aarch64-packages must not use {action}")
    if aarch_upload[2].get("name") != PROVISIONING_ARTIFACT:
        fail("aarch64-packages must upload the source-SHA-named provisioning receipt")
    if aarch_upload[2].get("path") != "ci-receipt/provisioning-aarch64.json":
        fail("aarch64-packages must upload only the bound provisioning receipt")
    if aarch_upload[2].get("if-no-files-found") != "error":
        fail("aarch64 provisioning receipt upload must fail when absent")
    if dns_download[2].get("name") != PROVISIONING_ARTIFACT:
        fail("dns-integration must download the source-SHA-named provisioning receipt")
    if dns_download[2].get("path") != "ci-input/aarch64":
        fail("dns-integration must isolate the provisioning receipt download")
    if dns_report_upload[2].get("name") != "kaiba-dns-test-report":
        fail("dns-integration must upload only the canonical named report artifact")
    if dns_report_upload[2].get("path") != "ci-report/":
        fail("the DNS report artifact must contain only the canonical report tree")
    if dns_report_upload[2].get("if-no-files-found") != "error":
        fail("the DNS report upload must fail when the report is absent")
    if pages_upload[2].get("path") != "pages-site/":
        fail("the Pages artifact must contain only the validated pages-site tree")

    build_receipt = require_once(
        aarch, "Build the native provisioning test result", "aarch64-packages"
    )
    bind_receipt = require_once(
        aarch, "Bind the provisioning result to this source revision", "aarch64-packages"
    )
    output_receipt = require_once(
        aarch,
        "provisioning_receipt_sha256: ${{ steps.provisioning_receipt.outputs.sha256 }}",
        "aarch64-packages",
    )
    digest_receipt = require_once(
        aarch,
        'receipt_sha256="$(sha256sum ci-receipt/provisioning-aarch64.json',
        "aarch64-packages",
    )
    publish_output = require_once(
        aarch, 'echo "sha256=$receipt_sha256" >> "$GITHUB_OUTPUT"', "aarch64-packages"
    )
    if not output_receipt < build_receipt < bind_receipt < digest_receipt < publish_output < aarch_upload[0]:
        fail("the ARM receipt must be built, source-bound, digested, and exported before upload")

    download_position = dns_download[0]
    verify_position = require_once(
        dns, "Verify the native ARM64 provisioning result", "dns-integration"
    )
    compose_position = require_once(dns, "Compose the canonical test report", "dns-integration")
    for provenance_guard in (
        "EXPECTED_SHA256: ${{ needs.aarch64-packages.outputs.provisioning_receipt_sha256 }}",
        "mapfile -d '' receipt_entries",
        "${#receipt_entries[@]} != 1",
        '[[ -L "$receipt" || ! -f "$receipt" ]]',
        '[[ ! "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ || "$actual_sha256" != "$EXPECTED_SHA256" ]]',
        "SOURCE_REVISION: ${{ github.sha }}",
        '--expected-source-revision "$SOURCE_REVISION"',
    ):
        require_once(dns, provenance_guard, "dns-integration provenance")
    if not download_position < verify_position < compose_position:
        fail("the ARM receipt must be downloaded and verified before report composition")

    assemble_marker = "Assemble and validate the GitHub Pages site"
    pages_marker = "Upload the project site for GitHub Pages"
    gates_position = require_once(
        dns, "Enforce schema, security, and functional gates", "dns-integration"
    )
    require_once(dns, "id: enforce_gates", "dns-integration gates")
    assemble_position = require_once(dns, assemble_marker, "dns-integration")
    pages_position = require_once(dns, pages_marker, "dns-integration")
    require_once(dns, f"if: {PAGES_CONDITION}", "Pages assembly")
    require_once(dns, f"if: {PAGES_UPLOAD_CONDITION}", "Pages upload")
    if not gates_position < assemble_position < pages_position < pages_upload[0]:
        fail("the site must be assembled and validated before its Pages upload")

    deploy = jobs["deploy-report"]
    require_once(deploy, f"if: {DEPLOY_CONDITION}", "deploy-report")
    configure = require_action(deploy, CONFIGURE_PAGES_ACTION, "deploy-report")
    publish = require_action(deploy, DEPLOY_PAGES_ACTION, "deploy-report")
    if configure[0] >= publish[0]:
        fail("Pages must be configured before deployment")
    if re.search(r"(?m)^        run:", deploy):
        fail("deploy-report must use only the pinned Pages actions")
    deploy_uses = re.findall(r"(?m)^        uses:\s*([^\s#]+)", deploy)
    if len(deploy_uses) != 2:
        fail("deploy-report must contain exactly the configure and deploy actions")

    print("CI workflow privilege and provenance policy passed")


if __name__ == "__main__":
    main()
