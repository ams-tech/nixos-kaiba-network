#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
  echo "usage: verify_release_tag_test.sh VERIFY_RELEASE_TAG" >&2
  exit 2
fi

guard="$(realpath "$1")"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
repository="$test_root/repository"

git init --quiet --initial-branch=main "$repository"
git -C "$repository" config user.name "Kaiba CI"
git -C "$repository" config user.email "kaiba-ci@example.invalid"
git -C "$repository" commit --quiet --allow-empty --message "initial"
first_revision="$(git -C "$repository" rev-parse HEAD)"

expect_failure() {
  local description="$1"
  shift
  if (cd "$repository" && bash "$guard" "$@") >/dev/null 2>&1; then
    echo "expected failure: $description" >&2
    exit 1
  fi
}

git -C "$repository" tag --annotate v0.2.0 \
  --message "Kaiba provisioning image v0.2.0" "$first_revision"
(cd "$repository" && bash "$guard" v0.2.0 "$first_revision" main)

git -C "$repository" tag v0.2.1 "$first_revision"
expect_failure "lightweight tag" v0.2.1 "$first_revision" main

git -C "$repository" tag --annotate v0.2.4 \
  --message "Nested annotated tag" v0.2.0 2>/dev/null
expect_failure "nested annotated tag" v0.2.4 "$first_revision" main

git -C "$repository" commit --quiet --allow-empty --message "second"
second_revision="$(git -C "$repository" rev-parse HEAD)"
git -C "$repository" update-ref refs/remotes/origin/main "$second_revision"
(cd "$repository" && bash "$guard" v0.2.0 "$first_revision" origin/main)
expect_failure "source revision mismatch" v0.2.0 "$second_revision" main

git -C "$repository" switch --quiet --create side "$first_revision"
git -C "$repository" commit --quiet --allow-empty --message "off main"
side_revision="$(git -C "$repository" rev-parse HEAD)"
git -C "$repository" tag --annotate v0.2.2 \
  --message "Kaiba provisioning image v0.2.2" "$side_revision"
git -C "$repository" switch --quiet main
expect_failure "tagged commit outside main" v0.2.2 "$side_revision" origin/main

blob_revision="$(git -C "$repository" hash-object -w /dev/null)"
git -C "$repository" tag --annotate v0.2.3 \
  --message "Invalid non-commit tag" "$blob_revision"
expect_failure "tag does not resolve to a commit" v0.2.3 "$first_revision" origin/main

expect_failure "missing tag" v9.9.9 "$first_revision" main
expect_failure "malformed source revision" v0.2.0 not-a-revision main
expect_failure "missing main ref" v0.2.0 "$first_revision" upstream/main

echo "release tag guard tests passed"
