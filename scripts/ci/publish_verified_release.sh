#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
  echo "usage: publish_verified_release.sh RELEASE_DIRECTORY" >&2
  exit 2
fi

release_directory="$1"
event_name="${EVENT_NAME:-}"
gh_repo="${GH_REPO:-}"
release_tag="${RELEASE_TAG:-}"
source_revision="${SOURCE_REVISION:-}"
workflow_revision="${WORKFLOW_REVISION:-}"
expected_archive_sha256="${EXPECTED_ARCHIVE_SHA256:-}"
expected_archive_size_bytes="${EXPECTED_ARCHIVE_SIZE_BYTES:-}"
expected_tag_object_sha="${EXPECTED_TAG_OBJECT_SHA:-}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

fail() {
  local title="$1"
  local message="$2"
  echo "::error title=$title::$message" >&2
  exit 1
}

if [[ "$event_name" != push && "$event_name" != workflow_dispatch ]]; then
  fail "Invalid release event" "Only a tag push or the fixed recovery dispatch may publish a release."
fi
if [[ ! "$gh_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  fail "Invalid repository" "The GitHub repository name is malformed."
fi
if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  fail "Invalid release tag" "The release tag is not a stable vMAJOR.MINOR.PATCH tag."
fi
if [[ ! "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  fail "Invalid source revision" "The release source revision is malformed."
fi
if [[ ! "$workflow_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  fail "Invalid workflow revision" "The release workflow revision is malformed."
fi
if [[ ! "$expected_archive_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  fail "Invalid archive digest" "The expected archive SHA-256 is malformed."
fi
if [[ ! "$expected_archive_size_bytes" =~ ^[1-9][0-9]*$ ]] ||
  (( expected_archive_size_bytes >= 2147483648 )); then
  fail "Invalid image size" "The expected archive size is malformed or exceeds the GitHub asset limit."
fi
if [[ ! "$expected_tag_object_sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  fail "Invalid tag object" "The expected release tag object ID is malformed."
fi

if [[ -L "$release_directory" || ! -d "$release_directory" ]]; then
  fail "Unsafe release directory" "$release_directory must be a regular directory, not a symbolic link."
fi

image_name="kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst"
checksum_name="$image_name.sha256"
image="$release_directory/$image_name"
checksum="$release_directory/$checksum_name"
release_title="Kaiba signed secure-boot target image $release_tag"
release_marker="Raspberry Pi 5 signed secure-boot target SD image verified for release at commit ${source_revision}."

mapfile -d '' release_entries < <(
  find "$release_directory" -mindepth 1 -maxdepth 1 -print0
)
if (( ${#release_entries[@]} != 2 )); then
  fail "Unexpected release contents" "Expected exactly the image and its checksum."
fi
for asset in "$image" "$checksum"; do
  if [[ -L "$asset" || ! -f "$asset" ]]; then
    fail "Unsafe release asset" "$asset must be a regular, non-symbolic-link file."
  fi
done

actual_archive_sha256="$(sha256sum -- "$image" | cut -d ' ' -f 1)"
if [[ "$actual_archive_sha256" != "$expected_archive_sha256" ]]; then
  fail "Archive digest mismatch" "The verified handoff is not bound to the release tag."
fi
actual_archive_size_bytes="$(stat --format=%s -- "$image")"
if [[ "$actual_archive_size_bytes" != "$expected_archive_size_bytes" ]]; then
  fail "Image size mismatch" "The verified handoff has an unexpected size."
fi

mapfile -t checksum_lines < "$checksum"
expected_checksum_line="$expected_archive_sha256  $image_name"
if (( ${#checksum_lines[@]} != 1 )) ||
  [[ "${checksum_lines[0]}" != "$expected_checksum_line" ]]; then
  fail "Invalid checksum" "The checksum must name and match the expected image."
fi
(
  cd -- "$release_directory"
  sha256sum --check --strict -- "$checksum_name"
)
checksum_sha256="$(sha256sum -- "$checksum" | cut -d ' ' -f 1)"
checksum_size_bytes="$(stat --format=%s -- "$checksum")"

verify_remote_tag() {
  bash "$script_directory/verify_remote_release_tag.sh" \
    "$gh_repo" "$release_tag" "$source_revision" \
    "$expected_tag_object_sha"
}

require_successful_main_ci() {
  local revision="$1"
  local label="$2"
  local successful_ci_runs
  successful_ci_runs="$(
    gh api \
      --method GET \
      "repos/$gh_repo/actions/workflows/ci.yml/runs" \
      -f branch=main \
      -f event=push \
      -f head_sha="$revision" \
      -f status=success \
      -f per_page=1 \
      --jq .total_count
  )"
  if [[ ! "$successful_ci_runs" =~ ^[0-9]+$ ]] ||
    (( successful_ci_runs < 1 )); then
    fail "CI approval missing" "No successful main-branch CI run exists for the $label revision $revision."
  fi
}

runner_temp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ -L "$runner_temp" || ! -d "$runner_temp" ]]; then
  fail "Unsafe runner temporary directory" "$runner_temp must be a regular directory, not a symbolic link."
fi
release_json="$(mktemp "$runner_temp/kaiba-release.XXXXXXXX.json")"
trap 'rm -f -- "$release_json"' EXIT

load_release() {
  local release_list
  release_list="$(mktemp "$runner_temp/kaiba-releases.XXXXXXXX.json")"
  if ! gh api "repos/$gh_repo/releases?per_page=100" > "$release_list"; then
    rm -f -- "$release_list"
    fail "Draft release unavailable" "Unable to read the repository releases."
  fi
  if ! jq --exit-status --arg tag "$release_tag" \
    '[.[] | select(.tag_name == $tag)] |
     if length == 1 then .[0] else empty end' \
    "$release_list" > "$release_json"; then
    rm -f -- "$release_list"
    fail "Draft release unavailable" "Expected exactly one pre-staged $release_tag release."
  fi
  rm -f -- "$release_list"
}

verify_release() {
  local expected_draft="$1"
  local minimum_assets="$2"
  local maximum_assets="$3"
  local release_id existing_tag target_commitish is_draft is_prerelease
  local existing_title existing_body asset_count unexpected_assets
  local image_count image_id image_size_remote image_state image_digest
  local checksum_count checksum_size_remote checksum_state checksum_digest

  release_id="$(jq --raw-output .id "$release_json")"
  existing_tag="$(jq --raw-output .tag_name "$release_json")"
  target_commitish="$(jq --raw-output .target_commitish "$release_json")"
  is_draft="$(jq --raw-output .draft "$release_json")"
  is_prerelease="$(jq --raw-output .prerelease "$release_json")"
  existing_title="$(jq --raw-output .name "$release_json")"
  existing_body="$(jq --raw-output .body "$release_json")"
  asset_count="$(jq '.assets | length' "$release_json")"
  unexpected_assets="$(
    jq --arg image "$image_name" --arg checksum "$checksum_name" \
      '[.assets[].name | select(. != $image and . != $checksum)] | length' \
      "$release_json"
  )"
  if [[ "$existing_tag" != "$release_tag" || "$is_draft" != "$expected_draft" ]] ||
    [[ "$is_prerelease" != false || "$existing_title" != "$release_title" ]] ||
    [[ "$existing_body" != "$release_marker"* ]] ||
    (( asset_count < minimum_assets || asset_count > maximum_assets || unexpected_assets != 0 )); then
    fail "Unexpected release" "Refusing to modify or accept a release whose identity, metadata, state, or asset set changed."
  fi

  image_count="$(
    jq --arg name "$image_name" \
      '[.assets[] | select(.name == $name)] | length' "$release_json"
  )"
  if (( image_count != 1 )); then
    fail "Target image unavailable" "The release must contain exactly one bound target archive."
  fi
  image_id="$(
    jq --raw-output --arg name "$image_name" \
      '.assets[] | select(.name == $name) | .id' "$release_json"
  )"
  image_size_remote="$(
    jq --raw-output --arg name "$image_name" \
      '.assets[] | select(.name == $name) | .size' "$release_json"
  )"
  image_state="$(
    jq --raw-output --arg name "$image_name" \
      '.assets[] | select(.name == $name) | .state' "$release_json"
  )"
  image_digest="$(
    jq --raw-output --arg name "$image_name" \
      '.assets[] | select(.name == $name) | .digest' "$release_json"
  )"
  if [[ "$image_size_remote" != "$expected_archive_size_bytes" ||
    "$image_state" != uploaded ]] ||
    [[ "$image_digest" != "sha256:$expected_archive_sha256" ]]; then
    fail "Remote archive mismatch" "The remote target archive metadata does not match the annotated tag."
  fi

  checksum_count="$(
    jq --arg name "$checksum_name" \
      '[.assets[] | select(.name == $name)] | length' "$release_json"
  )"
  if (( checksum_count > 1 )); then
    fail "Unexpected checksum assets" "The release contains duplicate checksum assets."
  fi
  if (( checksum_count == 1 )); then
    checksum_size_remote="$(
      jq --raw-output --arg name "$checksum_name" \
        '.assets[] | select(.name == $name) | .size' "$release_json"
    )"
    checksum_state="$(
      jq --raw-output --arg name "$checksum_name" \
        '.assets[] | select(.name == $name) | .state' "$release_json"
    )"
    checksum_digest="$(
      jq --raw-output --arg name "$checksum_name" \
        '.assets[] | select(.name == $name) | .digest' "$release_json"
    )"
    if [[ "$checksum_size_remote" != "$checksum_size_bytes" ||
      "$checksum_state" != uploaded ]] ||
      [[ "$checksum_digest" != "sha256:$checksum_sha256" ]]; then
      fail "Remote checksum mismatch" "The remote checksum asset is not the verified checksum."
    fi
  fi

  if [[ "$event_name" == workflow_dispatch ]] &&
    { [[ "$gh_repo" != "${RECOVERY_REPOSITORY:-}" ]] ||
      [[ "$release_tag" != "${RECOVERY_RELEASE_TAG:-}" ]] ||
      [[ "$source_revision" != "${RECOVERY_SOURCE_REVISION:-}" ]] ||
      [[ "$expected_tag_object_sha" != "${RECOVERY_TAG_OBJECT_SHA:-}" ]] ||
      [[ "$expected_archive_sha256" != "${RECOVERY_ARCHIVE_SHA256:-}" ]] ||
      [[ "$expected_archive_size_bytes" != "${RECOVERY_ARCHIVE_SIZE_BYTES:-}" ]] ||
      [[ "$release_id" != "${RECOVERY_RELEASE_ID:-}" ]] ||
      [[ "$image_id" != "${RECOVERY_IMAGE_ASSET_ID:-}" ]] ||
      [[ "$target_commitish" != main ]]; }; then
    fail "Recovery release changed" "The fixed recovery release no longer matches its reviewed release and asset identities."
  fi

  verified_checksum_count="$checksum_count"
}

verify_remote_tag
require_successful_main_ci "$source_revision" "release source"
require_successful_main_ci "$workflow_revision" "release workflow"
load_release
verify_release true 1 2

if (( verified_checksum_count == 0 )); then
  gh release upload "$release_tag" "$checksum"
fi

verify_remote_tag
load_release
verify_release true 2 2
gh release edit "$release_tag" --draft=false

# Read back both remote objects after publication so a successful command alone
# is never treated as proof of the final state.
load_release
verify_release false 2 2
verify_remote_tag

echo "Published verified release $release_tag."
