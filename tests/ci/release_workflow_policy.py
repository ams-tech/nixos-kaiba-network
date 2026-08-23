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
REMOTE_GUARD_ARGUMENTS = '"$GH_REPO" "$RELEASE_TAG" "$SOURCE_REVISION"'
REMOTE_TAG_REF_ENDPOINT = '"repos/$gh_repo/git/ref/tags/$release_tag"'
REMOTE_TAG_OBJECT_ENDPOINT = '"repos/$gh_repo/git/tags/$tag_object_sha"'
REMOTE_TAG_REF_QUERY = "--jq '[.ref, .object.type, .object.sha] | @tsv'"
REMOTE_TAG_OBJECT_QUERY = "--jq '[.sha, .object.type, .object.sha] | @tsv'"
MAIN_LINEAGE_CHECK = (
    'if ! git merge-base --is-ancestor "$SOURCE_REVISION" origin/main; then'
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
    install_nix = require_once(workflow, "uses: cachix/install-nix-action@")
    if not build_checkout < full_checkout < main_lineage < guard < install_nix:
        fail("main-lineage and annotated-tag checks must follow checkout and precede Nix")
    if workflow.count("persist-credentials: false") != 2:
        fail("both checkouts must disable persisted GitHub credentials")

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
