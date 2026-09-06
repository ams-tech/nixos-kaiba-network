#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
  echo "usage: read_release_image_binding_test.sh READ_RELEASE_IMAGE_BINDING" >&2
  exit 2
fi

reader="$(realpath "$1")"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
repository="$test_root/repository"

git init --quiet --initial-branch=main "$repository"
git -C "$repository" config user.name "Kaiba CI"
git -C "$repository" config user.email "kaiba-ci@example.invalid"
git -C "$repository" commit --quiet --allow-empty --message "release"
revision="$(git -C "$repository" rev-parse HEAD)"
archive_sha256="$(printf 'a%.0s' {1..64})"
media_sha256="$(printf 'b%.0s' {1..64})"

tag_message() {
  local tag="$1"
  local source_revision="$2"
  local archive_digest="$3"
  local media_digest="$4"
  local archive_size="$5"
  printf '%s\n\n%s\n%s\n%s\n%s\n' \
    "Kaiba signed secure-boot target image $tag" \
    "Source-Revision: $source_revision" \
    "Archive-SHA256: $archive_digest" \
    "Media-SHA256: $media_digest" \
    "Archive-Size-Bytes: $archive_size"
}

expect_failure() {
  local description="$1"
  local tag="$2"
  if (cd "$repository" && bash "$reader" "$tag" "$revision") >/dev/null 2>&1; then
    echo "expected failure: $description" >&2
    exit 1
  fi
}

valid_message="$(tag_message v0.2.0 "$revision" "$archive_sha256" "$media_sha256" 123456789)"
git -C "$repository" tag --annotate v0.2.0 --message "$valid_message" "$revision"
binding="$(cd "$repository" && bash "$reader" v0.2.0 "$revision")"
IFS=$'\t' read -r actual_archive actual_media actual_size tag_object <<< "$binding"
test "$actual_archive" = "$archive_sha256"
test "$actual_media" = "$media_sha256"
test "$actual_size" = 123456789
test "$tag_object" = "$(git -C "$repository" rev-parse refs/tags/v0.2.0)"

git -C "$repository" tag v0.2.1 "$revision"
expect_failure "lightweight tag" v0.2.1

wrong_revision="$(printf 'c%.0s' {1..40})"
wrong_source_message="$(tag_message v0.2.2 "$wrong_revision" "$archive_sha256" "$media_sha256" 123456789)"
git -C "$repository" tag --annotate v0.2.2 --message "$wrong_source_message" "$revision"
expect_failure "wrong source revision" v0.2.2

uppercase_message="$(tag_message v0.2.3 "$revision" "${archive_sha256^^}" "$media_sha256" 123456789)"
git -C "$repository" tag --annotate v0.2.3 --message "$uppercase_message" "$revision"
expect_failure "noncanonical archive digest" v0.2.3

oversize_message="$(tag_message v0.2.4 "$revision" "$archive_sha256" "$media_sha256" 2147483648)"
git -C "$repository" tag --annotate v0.2.4 --message "$oversize_message" "$revision"
expect_failure "oversized archive" v0.2.4

echo "release image binding tests passed"
