#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: publish_verified_release_test.sh PUBLISH_VERIFIED_RELEASE FAKE_GH" >&2
  exit 2
fi

publisher="$(realpath "$1")"
fake_gh="$(realpath "$2")"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

# An exported Bash function keeps the fake executable under the same explicit
# interpreter in both GitHub runners and Nix build sandboxes, where /usr/bin/env
# intentionally does not exist.
FAKE_GH_EXECUTABLE="$fake_gh"
export FAKE_GH_EXECUTABLE
gh() {
  bash "$FAKE_GH_EXECUTABLE" "$@"
}
export -f gh

release_tag=v0.2.0
source_revision="$(printf '1%.0s' {1..40})"
tag_object_sha="$(printf '2%.0s' {1..40})"
workflow_revision="$(printf '4%.0s' {1..40})"
image_name="kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst"
checksum_name="$image_name.sha256"

reset_fixture() {
  rm -rf -- "$test_root/release-assets" "$test_root/state" "$test_root/runner-temp"
  mkdir -p -- \
    "$test_root/release-assets" "$test_root/state" "$test_root/runner-temp"
  printf 'verified release archive fixture\n' > "$test_root/release-assets/$image_name"
  archive_sha256="$(sha256sum -- "$test_root/release-assets/$image_name" | cut -d ' ' -f 1)"
  archive_size="$(stat --format=%s -- "$test_root/release-assets/$image_name")"
  (
    cd -- "$test_root/release-assets"
    sha256sum -- "$image_name" > "$checksum_name"
  )
  checksum_sha256="$(sha256sum -- "$test_root/release-assets/$checksum_name" | cut -d ' ' -f 1)"
  checksum_size="$(stat --format=%s -- "$test_root/release-assets/$checksum_name")"

  unset TEST_EVENT_NAME FAKE_GH_IS_DRAFT FAKE_GH_IS_PRERELEASE
  unset FAKE_GH_RELEASE_TITLE FAKE_GH_RELEASE_BODY FAKE_GH_EXTRA_ASSET
  unset FAKE_GH_SUCCESSFUL_SOURCE_CI_RUNS FAKE_GH_SUCCESSFUL_WORKFLOW_CI_RUNS
  unset FAKE_GH_TAG_MOVE_ON_REF_CALL FAKE_GH_INJECT_ASSET_AFTER_UPLOAD
  unset FAKE_GH_RELEASE_EXISTS FAKE_GH_CHECKSUM_EXISTS FAKE_GH_EDIT_NOOP
  unset FAKE_GH_REMOTE_IMAGE_DIGEST_OVERRIDE FAKE_GH_REMOTE_CHECKSUM_DIGEST_OVERRIDE
  unset RECOVERY_REPOSITORY RECOVERY_RELEASE_TAG RECOVERY_SOURCE_REVISION
  unset RECOVERY_TAG_OBJECT_SHA RECOVERY_ARCHIVE_SHA256
  unset RECOVERY_ARCHIVE_SIZE_BYTES RECOVERY_RELEASE_ID RECOVERY_IMAGE_ASSET_ID
}

run_publisher() {
  RUNNER_TEMP="$test_root/runner-temp" \
    FAKE_GH_STATE_DIRECTORY="$test_root/state" \
    FAKE_GH_REPO=example/kaiba \
    FAKE_GH_RELEASE_TAG="$release_tag" \
    FAKE_GH_SOURCE_REVISION="$source_revision" \
    FAKE_GH_WORKFLOW_REVISION="$workflow_revision" \
    FAKE_GH_TAG_OBJECT_SHA="$tag_object_sha" \
    FAKE_GH_REMOTE_IMAGE_SIZE="$archive_size" \
    FAKE_GH_REMOTE_IMAGE_DIGEST="${FAKE_GH_REMOTE_IMAGE_DIGEST_OVERRIDE:-sha256:$archive_sha256}" \
    FAKE_GH_REMOTE_CHECKSUM_SIZE="$checksum_size" \
    FAKE_GH_REMOTE_CHECKSUM_DIGEST="${FAKE_GH_REMOTE_CHECKSUM_DIGEST_OVERRIDE:-sha256:$checksum_sha256}" \
    EVENT_NAME="${TEST_EVENT_NAME:-push}" \
    GH_REPO=example/kaiba \
    RELEASE_TAG="$release_tag" \
    SOURCE_REVISION="$source_revision" \
    WORKFLOW_REVISION="$workflow_revision" \
    EXPECTED_ARCHIVE_SHA256="$archive_sha256" \
    EXPECTED_ARCHIVE_SIZE_BYTES="$archive_size" \
    EXPECTED_TAG_OBJECT_SHA="$tag_object_sha" \
    RECOVERY_REPOSITORY="${RECOVERY_REPOSITORY:-}" \
    RECOVERY_RELEASE_TAG="${RECOVERY_RELEASE_TAG:-}" \
    RECOVERY_SOURCE_REVISION="${RECOVERY_SOURCE_REVISION:-}" \
    RECOVERY_TAG_OBJECT_SHA="${RECOVERY_TAG_OBJECT_SHA:-}" \
    RECOVERY_ARCHIVE_SHA256="${RECOVERY_ARCHIVE_SHA256:-}" \
    RECOVERY_ARCHIVE_SIZE_BYTES="${RECOVERY_ARCHIVE_SIZE_BYTES:-}" \
    RECOVERY_RELEASE_ID="${RECOVERY_RELEASE_ID:-}" \
    RECOVERY_IMAGE_ASSET_ID="${RECOVERY_IMAGE_ASSET_ID:-}" \
    bash "$publisher" "$test_root/release-assets"
}

assert_not_published() {
  local description="$1"
  if [[ -e "$test_root/state/release-published" ]]; then
    echo "release was published after $description" >&2
    exit 1
  fi
}

assert_not_uploaded() {
  local description="$1"
  if [[ -f "$test_root/state/invocations.log" ]] &&
    grep -q '^release upload ' "$test_root/state/invocations.log"; then
    echo "release assets were uploaded after $description" >&2
    exit 1
  fi
}

expect_failure() {
  local description="$1"
  local expected_message="$2"
  local output
  if output="$(run_publisher 2>&1)"; then
    echo "expected failure: $description" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected_message"* ]]; then
    echo "wrong failure for $description: $output" >&2
    exit 1
  fi
  assert_not_published "$description"
}

reset_fixture
run_publisher >/dev/null
test -f "$test_root/state/checksum-uploaded"
test -f "$test_root/state/release-published"
test "$(< "$test_root/state/ref-calls")" = 3
if grep -q '^release create ' "$test_root/state/invocations.log"; then
  echo "publisher attempted to create a release" >&2
  exit 1
fi

reset_fixture
archive_sha256="$(printf '0%.0s' {1..64})"
expect_failure "wrong archive digest" "Archive digest mismatch"
assert_not_uploaded "wrong archive digest"

reset_fixture
(( archive_size += 1 ))
expect_failure "wrong archive size" "Image size mismatch"
assert_not_uploaded "wrong archive size"

reset_fixture
printf '%s  wrong-name.img.zst\n' "$archive_sha256" > \
  "$test_root/release-assets/$checksum_name"
expect_failure "wrong checksum filename" "Invalid checksum"
assert_not_uploaded "wrong checksum filename"

reset_fixture
printf '%s  %s\n' "$(printf '0%.0s' {1..64})" "$image_name" > \
  "$test_root/release-assets/$checksum_name"
expect_failure "wrong checksum digest" "Invalid checksum"
assert_not_uploaded "wrong checksum digest"

reset_fixture
rm -- "$test_root/release-assets/$checksum_name"
ln -s -- "$test_root/release-assets/$image_name" \
  "$test_root/release-assets/$checksum_name"
expect_failure "symbolic-link checksum" "Unsafe release asset"
assert_not_uploaded "symbolic-link checksum"

reset_fixture
touch "$test_root/release-assets/unexpected"
expect_failure "extra local release asset" "Unexpected release contents"
assert_not_uploaded "extra local release asset"

reset_fixture
export FAKE_GH_RELEASE_TITLE="Unexpected title"
expect_failure "unexpected draft metadata" "Unexpected release"
assert_not_uploaded "unexpected draft metadata"

reset_fixture
export FAKE_GH_EXTRA_ASSET=legacy.img
expect_failure "unexpected existing draft asset" "Unexpected release"
assert_not_uploaded "unexpected existing draft asset"

reset_fixture
export FAKE_GH_RELEASE_EXISTS=false
expect_failure "missing exact draft" "Draft release unavailable"
assert_not_uploaded "missing exact draft"

reset_fixture
FAKE_GH_REMOTE_IMAGE_DIGEST_OVERRIDE="sha256:$(printf '0%.0s' {1..64})"
export FAKE_GH_REMOTE_IMAGE_DIGEST_OVERRIDE
expect_failure "wrong remote archive digest" "Remote archive mismatch"
assert_not_uploaded "wrong remote archive digest"

reset_fixture
export FAKE_GH_CHECKSUM_EXISTS=true
FAKE_GH_REMOTE_CHECKSUM_DIGEST_OVERRIDE="sha256:$(printf '0%.0s' {1..64})"
export FAKE_GH_REMOTE_CHECKSUM_DIGEST_OVERRIDE
expect_failure "wrong existing remote checksum" "Remote checksum mismatch"
assert_not_uploaded "wrong existing remote checksum"

reset_fixture
export FAKE_GH_SUCCESSFUL_SOURCE_CI_RUNS=0
expect_failure "missing exact source-SHA CI" "CI approval missing"
assert_not_uploaded "missing exact source-SHA CI"
grep -q -- "head_sha=$source_revision" "$test_root/state/invocations.log"
grep -q -- 'branch=main' "$test_root/state/invocations.log"
grep -q -- 'event=push' "$test_root/state/invocations.log"
grep -q -- 'status=success' "$test_root/state/invocations.log"

reset_fixture
export FAKE_GH_SUCCESSFUL_WORKFLOW_CI_RUNS=0
expect_failure "missing exact workflow-SHA CI" "CI approval missing"
assert_not_uploaded "missing exact workflow-SHA CI"
grep -q -- "head_sha=$workflow_revision" "$test_root/state/invocations.log"

reset_fixture
export FAKE_GH_TAG_MOVE_ON_REF_CALL=2
expect_failure "tag replacement during publication" "Release tag replaced"
grep -q '^release upload ' "$test_root/state/invocations.log"
assert_not_published "tag replacement during publication"

reset_fixture
export FAKE_GH_INJECT_ASSET_AFTER_UPLOAD=unexpected.txt
expect_failure "unexpected uploaded draft asset" "Unexpected release"
assert_not_published "unexpected uploaded draft asset"

reset_fixture
export FAKE_GH_EDIT_NOOP=true
expect_failure "publication command without state transition" "Unexpected release"

reset_fixture
export TEST_EVENT_NAME=workflow_dispatch
export RECOVERY_REPOSITORY=example/kaiba
export RECOVERY_RELEASE_TAG="$release_tag"
export RECOVERY_SOURCE_REVISION="$source_revision"
export RECOVERY_TAG_OBJECT_SHA="$tag_object_sha"
export RECOVERY_ARCHIVE_SHA256="$archive_sha256"
export RECOVERY_ARCHIVE_SIZE_BYTES="$archive_size"
export RECOVERY_RELEASE_ID=123
export RECOVERY_IMAGE_ASSET_ID=456
run_publisher >/dev/null
test -f "$test_root/state/release-published"

reset_fixture
export TEST_EVENT_NAME=workflow_dispatch
export RECOVERY_REPOSITORY=example/kaiba
export RECOVERY_RELEASE_TAG="$release_tag"
export RECOVERY_SOURCE_REVISION="$source_revision"
export RECOVERY_TAG_OBJECT_SHA="$tag_object_sha"
export RECOVERY_ARCHIVE_SHA256="$archive_sha256"
export RECOVERY_ARCHIVE_SIZE_BYTES="$archive_size"
export RECOVERY_RELEASE_ID=123
export RECOVERY_IMAGE_ASSET_ID=999
expect_failure "changed recovery asset identity" "Recovery release changed"
assert_not_uploaded "changed recovery asset identity"

echo "verified release publication tests passed"
