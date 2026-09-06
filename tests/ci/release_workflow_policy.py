#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


GUARD_COMMAND = (
    'run: bash scripts/ci/verify_release_tag.sh "$RELEASE_TAG" '
    '"$SOURCE_REVISION" origin/main'
)
REMOTE_GUARD_COMMAND = "bash scripts/ci/verify_remote_release_tag.sh"
REMOTE_GUARD_ARGUMENTS = (
    '"$GH_REPO" "$RELEASE_TAG" "$SOURCE_REVISION" \\\n'
    '              "$EXPECTED_TAG_OBJECT_SHA"'
)
BINDING_COMMAND = "bash scripts/ci/read_release_image_binding.sh"
REMOTE_TAG_REF_ENDPOINT = '"repos/$gh_repo/git/ref/tags/$release_tag"'
REMOTE_TAG_OBJECT_ENDPOINT = '"repos/$gh_repo/git/tags/$tag_object_sha"'
REMOTE_TAG_REF_QUERY = "--jq '[.ref, .object.type, .object.sha] | @tsv'"
REMOTE_TAG_OBJECT_QUERY = "--jq '[.sha, .object.type, .object.sha] | @tsv'"
MAIN_LINEAGE_CHECK = (
    'if ! git merge-base --is-ancestor "$SOURCE_REVISION" origin/main; then'
)
DIRECT_IMAGE_SOURCE = (
    'source_image="target-image/$image_name"'
)
DIRECT_IMAGE_NAME = (
    'image_name="kaiba-rpi5-development-secure-boot-target-'
    '${RELEASE_TAG}.img.zst"'
)
EXPECTED_JOBS = (
    "validate-release",
    "fetch-draft-image",
    "build-image",
    "publish-release",
)
UNVERIFIED_ARTIFACT = (
    "kaiba-rpi5-development-secure-boot-target-unverified-"
    "${{ github.sha }}"
)
VERIFIED_ARTIFACT = (
    "kaiba-rpi5-development-secure-boot-target-${{ github.sha }}"
)


def fail(message: str) -> None:
    raise SystemExit(f"release workflow policy: {message}")


def require_once(source: str, value: str) -> int:
    count = source.count(value)
    if count != 1:
        fail(f"expected {value!r} exactly once, found {count}")
    return source.find(value)


def release_jobs(source: str) -> dict[str, tuple[str, int]]:
    jobs_marker = require_once(source, "jobs:\n")
    matches = list(
        re.finditer(r"(?m)^  ([a-z0-9][a-z0-9-]*):\n", source[jobs_marker:])
    )
    names = tuple(match.group(1) for match in matches)
    if names != EXPECTED_JOBS:
        fail(
            "expected the ordered validation, fetch, verification, and "
            "publication jobs "
            f"{EXPECTED_JOBS!r}, found {names!r}"
        )

    jobs: dict[str, tuple[str, int]] = {}
    for index, match in enumerate(matches):
        start = jobs_marker + match.start()
        if index + 1 < len(matches):
            end = jobs_marker + matches[index + 1].start()
        else:
            end = len(source)
        jobs[match.group(1)] = (source[start:end], start)
    return jobs


def permissions(source: str, indentation: int) -> dict[str, str] | None:
    prefix = " " * indentation
    if re.search(rf"(?m)^{prefix}permissions:\s*\{{\s*\}}\s*$", source):
        return {}
    match = re.search(rf"(?m)^{prefix}permissions:\n", source)
    if match is None:
        return None

    entries: dict[str, str] = {}
    entry_prefix = " " * (indentation + 2)
    for line in source[match.end() :].splitlines():
        entry = re.fullmatch(
            rf"{entry_prefix}([a-z][a-z-]*):\s*([a-z]+)", line
        )
        if entry is None:
            break
        entries[entry.group(1)] = entry.group(2)
    return entries


def require_needs(job: str, dependencies: tuple[str, ...]) -> None:
    match = re.search(r"(?m)^    needs:[ \t]*([^\n]*)$", job)
    if match is None:
        fail(f"expected job to depend directly on {dependencies!r}")
    needs = match.group(1).strip()
    if not needs:
        actual = tuple(
            re.findall(r"(?m)^      - ([a-z0-9][a-z0-9-]*)\s*$", job[match.end() :])
        )
    elif needs.startswith("[") and needs.endswith("]"):
        actual = tuple(part.strip() for part in needs[1:-1].split(","))
    else:
        actual = (needs,)
    if actual != dependencies:
        fail(f"expected job dependencies {dependencies!r}, found {actual!r}")


def action_steps(
    job: str, action: str
) -> list[tuple[int, dict[str, str]]]:
    steps: list[tuple[int, dict[str, str]]] = []
    pattern = rf"(?m)^        uses:\s*{re.escape(action)}@[^\n]+$"
    for match in re.finditer(pattern, job):
        next_step = re.search(r"(?m)^      - ", job[match.end() :])
        end = (
            match.end() + next_step.start()
            if next_step is not None
            else len(job)
        )
        step = job[match.start() : end]
        options = dict(
            re.findall(
                r"(?m)^          ([a-z][a-z0-9-]*):\s*([^\n]+?)\s*$",
                step,
            )
        )
        steps.append((match.start(), options))
    return steps


def require_one_artifact_step(
    job: str, action: str, job_name: str
) -> tuple[int, dict[str, str]]:
    steps = action_steps(job, action)
    if len(steps) != 1:
        fail(
            f"expected {job_name} to use {action} exactly once, "
            f"found {len(steps)}"
        )
    if "name" not in steps[0][1]:
        fail(f"expected the {action} step in {job_name} to name its artifact")
    return steps[0]


def main() -> None:
    if len(sys.argv) != 3:
        fail(
            "usage: release_workflow_policy.py RELEASE_WORKFLOW "
            "REMOTE_TAG_GUARD"
        )

    workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
    remote_guard = Path(sys.argv[2]).read_text(encoding="utf-8")
    jobs = release_jobs(workflow)
    validate_job = jobs["validate-release"][0]
    fetch_job = jobs["fetch-draft-image"][0]
    build_job = jobs["build-image"][0]
    publish_job, publish_offset = jobs["publish-release"]

    jobs_marker = workflow.index("jobs:\n")
    if permissions(workflow[:jobs_marker], 0) != {"contents": "read"}:
        fail("the workflow-wide default permission must be contents: read")
    expected_permissions = {
        "validate-release": {"contents": "read"},
        "fetch-draft-image": {"contents": "write"},
        "build-image": {},
        "publish-release": {"actions": "read", "contents": "write"},
    }
    for job_name, expected in expected_permissions.items():
        actual = permissions(jobs[job_name][0], 4)
        if actual != expected:
            fail(
                f"expected {job_name} permissions {expected!r}, "
                f"found {actual!r}"
            )
    if workflow.count("contents: write") != 2:
        fail("only draft fetching and publication may receive contents: write")

    if re.search(r"(?m)^    needs:", validate_job):
        fail("release validation must be the first job in the release DAG")
    require_needs(fetch_job, ("validate-release",))
    require_needs(build_job, ("validate-release", "fetch-draft-image"))
    require_needs(publish_job, ("validate-release", "build-image"))

    checkouts = list(re.finditer(r"uses: actions/checkout@", workflow))
    if len(checkouts) != 2:
        fail(f"expected validation and publish checkouts, found {len(checkouts)}")
    validate_checkout = require_once(validate_job, "uses: actions/checkout@")
    publish_checkout = require_once(publish_job, "uses: actions/checkout@")
    if "actions/checkout@" in fetch_job or "actions/checkout@" in build_job:
        fail("the draft fetch and archive verification jobs must not check out code")
    full_checkout = require_once(validate_job, "fetch-depth: 0")
    main_lineage = require_once(validate_job, MAIN_LINEAGE_CHECK)
    guard = require_once(validate_job, GUARD_COMMAND)
    binding = require_once(validate_job, BINDING_COMMAND)
    if not (
        validate_checkout
        < full_checkout
        < main_lineage
        < guard
        < binding
    ):
        fail(
            "main-lineage and annotated-tag checks must precede reading the "
            "image binding"
        )
    if workflow.count("persist-credentials: false") != 2:
        fail("both checkouts must disable persisted GitHub credentials")

    fetch_uses = re.findall(r"(?m)^        uses:\s*([^\s#]+)", fetch_job)
    if len(fetch_uses) != 1 or not fetch_uses[0].startswith(
        "actions/upload-artifact@"
    ):
        fail("the privileged draft fetch may only invoke upload-artifact")
    for repo_code_reference in (
        "scripts/",
        "uses: ./",
        "nix run",
        "nix build",
    ):
        if repo_code_reference in fetch_job:
            fail(
                "the privileged draft fetch must not execute repository code "
                f"({repo_code_reference!r})"
            )

    seed_download = require_once(fetch_job, 'gh release download "$RELEASE_TAG"')
    release_commands = re.findall(r"\bgh release ([a-z-]+)", fetch_job)
    if release_commands != ["download"] or "gh api" in fetch_job:
        fail("the privileged draft fetch may only read a release asset")
    require_once(fetch_job, 'cat "$download_error" >&2')
    if "2>/dev/null" in fetch_job:
        fail("the draft fetch must retain its final download error")
    fetch_upload, fetch_upload_options = require_one_artifact_step(
        fetch_job, "actions/upload-artifact", "fetch-draft-image"
    )
    build_download, build_download_options = require_one_artifact_step(
        build_job, "actions/download-artifact", "build-image"
    )
    build_upload, build_upload_options = require_one_artifact_step(
        build_job, "actions/upload-artifact", "build-image"
    )
    publish_download, publish_download_options = require_one_artifact_step(
        publish_job, "actions/download-artifact", "publish-release"
    )
    if workflow.count("uses: actions/upload-artifact@") != 2:
        fail("only the unverified and verified artifact handoffs may upload")
    if workflow.count("uses: actions/download-artifact@") != 2:
        fail("only verification and publication may download handed-off artifacts")
    artifact_names = (
        fetch_upload_options["name"],
        build_download_options["name"],
        build_upload_options["name"],
        publish_download_options["name"],
    )
    if artifact_names[:2] != (UNVERIFIED_ARTIFACT, UNVERIFIED_ARTIFACT):
        fail("the fetch and verification jobs must hand off the unverified artifact")
    if artifact_names[2:] != (VERIFIED_ARTIFACT, VERIFIED_ARTIFACT):
        fail("the verification and publication jobs must hand off verified assets")
    if UNVERIFIED_ARTIFACT == VERIFIED_ARTIFACT:
        fail("unverified and verified artifact identities must remain distinct")

    fetch_image_name = require_once(fetch_job, DIRECT_IMAGE_NAME)
    if not fetch_image_name < seed_download < fetch_upload:
        fail("the draft image must be fetched before its artifact handoff")

    source_image = require_once(build_job, DIRECT_IMAGE_SOURCE)
    archive_digest = require_once(
        build_job,
        '"$EXPECTED_ARCHIVE_SHA256"',
    )
    media_digest = require_once(
        build_job,
        '"$EXPECTED_MEDIA_SHA256"',
    )
    archive_size = require_once(
        build_job,
        "image_size != EXPECTED_ARCHIVE_SIZE_BYTES",
    )
    for binding_output in (
        "archive_sha256=$archive_sha256",
        "media_sha256=$media_sha256",
        "archive_size_bytes=$archive_size_bytes",
        "tag_object_sha=$tag_object_sha",
        "archive_sha256: ${{ steps.image-binding.outputs.archive_sha256 }}",
        "media_sha256: ${{ steps.image-binding.outputs.media_sha256 }}",
        "archive_size_bytes: ${{ steps.image-binding.outputs.archive_size_bytes }}",
        "tag_object_sha: ${{ steps.image-binding.outputs.tag_object_sha }}",
    ):
        require_once(workflow, binding_output)
    for build_binding in (
        "EXPECTED_ARCHIVE_SHA256: ${{ needs.validate-release.outputs.archive_sha256 }}",
        "EXPECTED_MEDIA_SHA256: ${{ needs.validate-release.outputs.media_sha256 }}",
        "EXPECTED_ARCHIVE_SIZE_BYTES: ${{ needs.validate-release.outputs.archive_size_bytes }}",
    ):
        require_once(build_job, build_binding)
    for publish_binding in (
        "EXPECTED_ARCHIVE_SHA256: ${{ needs.validate-release.outputs.archive_sha256 }}",
        "EXPECTED_ARCHIVE_SIZE_BYTES: ${{ needs.validate-release.outputs.archive_size_bytes }}",
        "EXPECTED_TAG_OBJECT_SHA: ${{ needs.validate-release.outputs.tag_object_sha }}",
    ):
        require_once(publish_job, publish_binding)
    for obsolete_binding in (
        "c82a0fad4aa859ba51cd31f35f041450b4b96d767060c9da31cdae98cd36bf8a",
        "9ba3e880a81d35b2fef237840f3791a81bd79c095a3b6f19c44b3f142a22d4b5",
        "1166253581",
    ):
        if obsolete_binding in workflow:
            fail("the release workflow retains a v0.1.14 artifact binding")
    image_names = list(re.finditer(re.escape(DIRECT_IMAGE_NAME), workflow))
    if len(image_names) != 3:
        fail(
            "the exact signed target release filename must appear in fetch, "
            "verification, and publication "
            f"jobs, found {len(image_names)}"
        )
    build_image_name = require_once(build_job, DIRECT_IMAGE_NAME)
    publish_image_name = require_once(publish_job, DIRECT_IMAGE_NAME)
    publish_archive_hash = require_once(
        publish_job, 'actual_sha256="$(sha256sum "$image"'
    )
    publish_archive_check = require_once(
        publish_job, '"$actual_sha256" != "$EXPECTED_ARCHIVE_SHA256"'
    )
    publish_size = require_once(
        publish_job, 'image_size="$(stat --format=%s "$image")"'
    )
    publish_size_check = require_once(
        publish_job, '"$image_size" != "$EXPECTED_ARCHIVE_SIZE_BYTES"'
    )
    publish_checksum_binding = require_once(
        publish_job,
        'expected_checksum_line="$EXPECTED_ARCHIVE_SHA256  $image_name"',
    )
    publish_checksum_check = require_once(
        publish_job, 'sha256sum --check --strict "$image_name.sha256"'
    )
    if not (
        build_download
        < build_image_name
        < source_image
        < archive_digest
        < media_digest
        < archive_size
        < build_upload
    ):
        fail("the unverified archive must be checked before the verified handoff")
    if not (
        publish_checkout
        < publish_download
        < publish_image_name
        < publish_archive_hash
        < publish_archive_check
        < publish_size
        < publish_size_check
        < publish_checksum_binding
        < publish_checksum_check
    ):
        fail(
            "the publish job must bind the downloaded archive and checksum "
            "before publication"
        )
    if ".#packages.aarch64-linux.rpi5-v016-signed-target-sd-image" in workflow:
        fail("the self-hosted target archive cannot be built before its release exists")
    if ".#packages.aarch64-linux.rpi5-provisioning-sd-image" in workflow:
        fail("the release workflow still builds the read-only qualification image")
    if ".#packages.aarch64-linux.rpi5-development-secure-boot-station-sd-image" in workflow:
        fail("the signed target release workflow still builds a provisioning-station image")

    remote_guard_call = require_once(workflow, REMOTE_GUARD_COMMAND)
    require_once(workflow, REMOTE_GUARD_ARGUMENTS)
    if not publish_offset + publish_checkout < remote_guard_call:
        fail("the publish job must check out the remote tag guard before invoking it")

    require_once(remote_guard, REMOTE_TAG_REF_ENDPOINT)
    require_once(remote_guard, REMOTE_TAG_OBJECT_ENDPOINT)
    require_once(remote_guard, REMOTE_TAG_REF_QUERY)
    require_once(remote_guard, REMOTE_TAG_OBJECT_QUERY)
    for check in (
        "if ! ref_fields=\"$(",
        "if ! tag_fields=\"$(",
        '"$remote_tag_type" != tag',
        '"$tag_object_sha" != "$expected_tag_object_sha"',
        '"$returned_tag_sha" != "$tag_object_sha"',
        '"$target_type" != commit',
        '"$remote_revision" != "$source_revision"',
    ):
        require_once(remote_guard, check)
    if "commits/tags/" in remote_guard:
        fail("the commits/tags endpoint does not peel annotated tags")
    remote_checks = [
        match.start()
        for match in re.finditer(r"(?m)^          verify_remote_tag$", workflow)
    ]
    if len(remote_checks) != 2:
        fail(f"expected two publish-time remote tag checks, found {len(remote_checks)}")

    release_create = require_once(workflow, 'gh release create "$RELEASE_TAG"')
    release_upload = require_once(workflow, 'gh release upload "$RELEASE_TAG"')
    release_publish = require_once(
        workflow, 'gh release edit "$RELEASE_TAG" --draft=false'
    )
    if not publish_offset + publish_checksum_check < release_create:
        fail("the immutable archive binding must be checked before any release write")
    if not (
        remote_guard_call
        < remote_checks[0]
        < release_create
        < release_upload
        < remote_checks[1]
        < release_publish
    ):
        fail("remote tag checks must bracket release creation and publication")

    print("release workflow policy passed")


if __name__ == "__main__":
    main()
