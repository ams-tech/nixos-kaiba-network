#!/usr/bin/env bash

set -euo pipefail

state_directory="${FAKE_GH_STATE_DIRECTORY:?FAKE_GH_STATE_DIRECTORY is required}"
gh_repo="${FAKE_GH_REPO:-example/kaiba}"
release_tag="${FAKE_GH_RELEASE_TAG:-v0.2.0}"
source_revision="${FAKE_GH_SOURCE_REVISION:-1111111111111111111111111111111111111111}"
workflow_revision="${FAKE_GH_WORKFLOW_REVISION:-4444444444444444444444444444444444444444}"
tag_object_sha="${FAKE_GH_TAG_OBJECT_SHA:-2222222222222222222222222222222222222222}"
replacement_tag_object_sha="${FAKE_GH_REPLACEMENT_TAG_OBJECT_SHA:-3333333333333333333333333333333333333333}"
tag_move_on_ref_call="${FAKE_GH_TAG_MOVE_ON_REF_CALL:-0}"
mkdir -p -- "$state_directory"

{
  separator=""
  for argument in "$@"; do
    printf '%s' "$separator"
    printf '%q' "$argument"
    separator=" "
  done
  printf '\n'
} >> "$state_directory/invocations.log"

fail_unexpected() {
  echo "unexpected gh invocation: $*" >&2
  exit 2
}

render_release_list() {
  if [[ "${FAKE_GH_RELEASE_EXISTS:-true}" != true ]]; then
    printf '[]\n'
    return
  fi

  assets="$(
    jq --null-input \
      --arg id "${FAKE_GH_IMAGE_ASSET_ID:-456}" \
      --arg name "kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst" \
      --arg size "${FAKE_GH_REMOTE_IMAGE_SIZE:?FAKE_GH_REMOTE_IMAGE_SIZE is required}" \
      --arg state "${FAKE_GH_REMOTE_IMAGE_STATE:-uploaded}" \
      --arg digest "${FAKE_GH_REMOTE_IMAGE_DIGEST:?FAKE_GH_REMOTE_IMAGE_DIGEST is required}" \
      '[{id: ($id | tonumber), name: $name, size: ($size | tonumber), state: $state, digest: $digest}]'
  )"
  if [[ -e "$state_directory/checksum-uploaded" ||
    "${FAKE_GH_CHECKSUM_EXISTS:-false}" == true ]]; then
    assets="$(
      jq --arg id "${FAKE_GH_CHECKSUM_ASSET_ID:-789}" \
        --arg name "kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst.sha256" \
        --arg size "${FAKE_GH_REMOTE_CHECKSUM_SIZE:?FAKE_GH_REMOTE_CHECKSUM_SIZE is required}" \
        --arg state "${FAKE_GH_REMOTE_CHECKSUM_STATE:-uploaded}" \
        --arg digest "${FAKE_GH_REMOTE_CHECKSUM_DIGEST:?FAKE_GH_REMOTE_CHECKSUM_DIGEST is required}" \
        '. + [{id: ($id | tonumber), name: $name, size: ($size | tonumber), state: $state, digest: $digest}]' \
        <<< "$assets"
    )"
  fi
  if [[ -n "${FAKE_GH_EXTRA_ASSET:-}" ]] ||
    { [[ -e "$state_directory/checksum-uploaded" ]] &&
      [[ -n "${FAKE_GH_INJECT_ASSET_AFTER_UPLOAD:-}" ]]; }; then
    extra_asset="${FAKE_GH_EXTRA_ASSET:-${FAKE_GH_INJECT_ASSET_AFTER_UPLOAD}}"
    assets="$(
      jq --arg name "$extra_asset" \
        '. + [{id: 999, name: $name, size: 1, state: "uploaded", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]' \
        <<< "$assets"
    )"
  fi

  draft=true
  if [[ -e "$state_directory/release-published" ]]; then
    draft=false
  elif [[ -n "${FAKE_GH_IS_DRAFT:-}" ]]; then
    draft="$FAKE_GH_IS_DRAFT"
  fi
  jq --null-input \
    --arg id "${FAKE_GH_RELEASE_ID:-123}" \
    --arg tag "$release_tag" \
    --arg target_commitish "${FAKE_GH_TARGET_COMMITISH:-main}" \
    --arg draft "$draft" \
    --arg prerelease "${FAKE_GH_IS_PRERELEASE:-false}" \
    --arg name "${FAKE_GH_RELEASE_TITLE:-Kaiba signed secure-boot target image $release_tag}" \
    --arg body "${FAKE_GH_RELEASE_BODY:-Raspberry Pi 5 signed secure-boot target SD image verified for release at commit $source_revision.}" \
    --argjson assets "$assets" \
    '[{id: ($id | tonumber), tag_name: $tag, target_commitish: $target_commitish,
       draft: ($draft == "true"), prerelease: ($prerelease == "true"),
       name: $name, body: $body, assets: $assets}]'
}

if [[ "${1:-}" == api ]]; then
  shift
  if [[ "${1:-}" == "repos/$gh_repo/git/ref/tags/$release_tag" ]]; then
    shift
    [[ "${1:-}" == --jq && $# == 2 ]] || fail_unexpected api "$@"
    [[ "$2" == '[.ref, .object.type, .object.sha] | @tsv' ]] ||
      fail_unexpected api "repos/$gh_repo/git/ref/tags/$release_tag" "$@"
    ref_calls=0
    if [[ -f "$state_directory/ref-calls" ]]; then
      read -r ref_calls < "$state_directory/ref-calls"
    fi
    (( ref_calls += 1 ))
    printf '%s\n' "$ref_calls" > "$state_directory/ref-calls"
    current_tag_object_sha="$tag_object_sha"
    if [[ "$tag_move_on_ref_call" =~ ^[0-9]+$ ]] &&
      (( ref_calls >= tag_move_on_ref_call )) &&
      (( tag_move_on_ref_call > 0 )); then
      current_tag_object_sha="$replacement_tag_object_sha"
    fi
    printf 'refs/tags/%s\ttag\t%s\n' "$release_tag" "$current_tag_object_sha"
    exit 0
  fi
  if [[ "${1:-}" == "repos/$gh_repo/git/tags/$tag_object_sha" ]]; then
    shift
    [[ "${1:-}" == --jq && $# == 2 ]] || fail_unexpected api "$@"
    [[ "$2" == '[.sha, .object.type, .object.sha] | @tsv' ]] ||
      fail_unexpected api "repos/$gh_repo/git/tags/$tag_object_sha" "$@"
    printf '%s\tcommit\t%s\n' "$tag_object_sha" "$source_revision"
    exit 0
  fi
  if [[ "${1:-}" == --method && "${2:-}" == GET &&
    "${3:-}" == "repos/$gh_repo/actions/workflows/ci.yml/runs" ]]; then
    shift 3
    if (( $# != 12 )); then
      fail_unexpected api --method GET "repos/$gh_repo/actions/workflows/ci.yml/runs" "$@"
    fi
    [[ "$1" == -f && "$2" == branch=main &&
      "$3" == -f && "$4" == event=push &&
      "$5" == -f && "$6" == head_sha=* &&
      "$7" == -f && "$8" == status=success &&
      "$9" == -f && "${10}" == per_page=1 &&
      "${11}" == --jq && "${12}" == .total_count ]] ||
      fail_unexpected api --method GET "repos/$gh_repo/actions/workflows/ci.yml/runs" "$@"
    revision="${6#head_sha=}"
    case "$revision" in
      "$source_revision") printf '%s\n' "${FAKE_GH_SUCCESSFUL_SOURCE_CI_RUNS:-1}" ;;
      "$workflow_revision") printf '%s\n' "${FAKE_GH_SUCCESSFUL_WORKFLOW_CI_RUNS:-1}" ;;
      *) fail_unexpected "CI revision $revision" ;;
    esac
    exit 0
  fi
  if [[ "${1:-}" == "repos/$gh_repo/releases?per_page=100" && $# == 1 ]]; then
    render_release_list
    exit 0
  fi
  fail_unexpected api "$@"
fi

if [[ "${1:-}" != release ]]; then
  fail_unexpected "$@"
fi
shift
release_command="${1:-}"
shift || true

case "$release_command" in
  upload)
    [[ "${1:-}" == "$release_tag" && $# == 2 ]] ||
      fail_unexpected release upload "$@"
    [[ "$(basename -- "$2")" == \
      "kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst.sha256" ]] ||
      fail_unexpected release upload "$@"
    touch "$state_directory/checksum-uploaded"
    ;;
  edit)
    [[ "${1:-}" == "$release_tag" && "${2:-}" == --draft=false && $# == 2 ]] ||
      fail_unexpected release edit "$@"
    if [[ "${FAKE_GH_EDIT_NOOP:-false}" != true ]]; then
      touch "$state_directory/release-published"
    fi
    ;;
  create) fail_unexpected "release creation is forbidden" ;;
  *) fail_unexpected release "$release_command" "$@" ;;
esac
