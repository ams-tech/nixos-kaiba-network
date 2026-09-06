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


def fail(message: str) -> None:
    raise SystemExit(f"release workflow policy: {message}")


def require_once(source: str, value: str) -> int:
    count = source.count(value)
    if count != 1:
        fail(f"expected {value!r} exactly once, found {count}")
    return source.find(value)


def main() -> None:
    if len(sys.argv) != 3:
        fail(
            "usage: release_workflow_policy.py RELEASE_WORKFLOW "
            "REMOTE_TAG_GUARD"
        )

    workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
    remote_guard = Path(sys.argv[2]).read_text(encoding="utf-8")
    checkouts = [
        match.start()
        for match in re.finditer(r"uses: actions/checkout@", workflow)
    ]
    if len(checkouts) != 2:
        fail(f"expected build and publish checkouts, found {len(checkouts)}")
    build_checkout, publish_checkout = checkouts
    full_checkout = require_once(workflow, "fetch-depth: 0")
    main_lineage = require_once(workflow, MAIN_LINEAGE_CHECK)
    guard = require_once(workflow, GUARD_COMMAND)
    binding = require_once(workflow, BINDING_COMMAND)
    seed_download = require_once(workflow, 'gh release download "$RELEASE_TAG"')
    if not (
        build_checkout
        < full_checkout
        < main_lineage
        < guard
        < binding
        < seed_download
    ):
        fail(
            "main-lineage, annotated-tag, and image-binding checks must "
            "precede the archive download"
        )
    if workflow.count("persist-credentials: false") != 2:
        fail("both checkouts must disable persisted GitHub credentials")

    source_image = require_once(workflow, DIRECT_IMAGE_SOURCE)
    archive_digest = require_once(
        workflow,
        '"$EXPECTED_ARCHIVE_SHA256"',
    )
    media_digest = require_once(
        workflow,
        '"$EXPECTED_MEDIA_SHA256"',
    )
    archive_size = require_once(
        workflow,
        "image_size != EXPECTED_ARCHIVE_SIZE_BYTES",
    )
    for binding_output in (
        "archive_sha256=$archive_sha256",
        "media_sha256=$media_sha256",
        "archive_size_bytes=$archive_size_bytes",
        "tag_object_sha=$tag_object_sha",
        "EXPECTED_ARCHIVE_SHA256: ${{ steps.image-binding.outputs.archive_sha256 }}",
        "EXPECTED_MEDIA_SHA256: ${{ steps.image-binding.outputs.media_sha256 }}",
        "EXPECTED_ARCHIVE_SIZE_BYTES: ${{ steps.image-binding.outputs.archive_size_bytes }}",
        "tag_object_sha: ${{ steps.image-binding.outputs.tag_object_sha }}",
        "EXPECTED_TAG_OBJECT_SHA: ${{ needs.build-image.outputs.tag_object_sha }}",
    ):
        require_once(workflow, binding_output)
    for obsolete_binding in (
        "c82a0fad4aa859ba51cd31f35f041450b4b96d767060c9da31cdae98cd36bf8a",
        "9ba3e880a81d35b2fef237840f3791a81bd79c095a3b6f19c44b3f142a22d4b5",
        "1166253581",
    ):
        if obsolete_binding in workflow:
            fail("the release workflow retains a v0.1.14 artifact binding")
    image_names = [
        match.start()
        for match in re.finditer(re.escape(DIRECT_IMAGE_NAME), workflow)
    ]
    if len(image_names) != 2:
        fail(
            "the exact signed target release filename must appear in both "
            f"jobs, found {len(image_names)}"
        )
    if not (
        image_names[0]
        < seed_download
        < source_image
        < archive_digest
        < media_digest
        < archive_size
        < publish_checkout
        < image_names[1]
    ):
        fail("the signed target archive verification and release names are out of order")
    if ".#packages.aarch64-linux.rpi5-v016-signed-target-sd-image" in workflow:
        fail("the self-hosted target archive cannot be built before its release exists")
    if ".#packages.aarch64-linux.rpi5-provisioning-sd-image" in workflow:
        fail("the release workflow still builds the read-only qualification image")
    if ".#packages.aarch64-linux.rpi5-development-secure-boot-station-sd-image" in workflow:
        fail("the signed target release workflow still builds a provisioning-station image")

    remote_guard_call = require_once(workflow, REMOTE_GUARD_COMMAND)
    require_once(workflow, REMOTE_GUARD_ARGUMENTS)
    if not publish_checkout < remote_guard_call:
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
