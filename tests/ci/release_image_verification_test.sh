#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
  echo "usage: release_image_verification_test.sh RELEASE_WORKFLOW" >&2
  exit 2
fi

workflow="$(realpath "$1")"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
verification_script="$test_root/verify-image.sh"

awk '
  $0 == "      - name: Verify the prebuilt release image" {
    in_step = 1
    next
  }
  in_step && $0 == "        run: |" {
    in_run = 1
    next
  }
  in_run && /^      - / {
    exit
  }
  in_run {
    if ($0 == "") {
      print
      next
    }
    if ($0 !~ /^          /) {
      print "unexpected indentation in release image verification block" > "/dev/stderr"
      exit 2
    }
    sub(/^          /, "")
    print
    lines += 1
  }
  END {
    if (!in_run || lines == 0) {
      print "release image verification block was not found" > "/dev/stderr"
      exit 2
    }
  }
' "$workflow" > "$verification_script"
chmod 0500 "$verification_script"

release_tag=v0.2.0
image_name="kaiba-rpi5-development-secure-boot-target-${release_tag}.img.zst"
media="$test_root/media.img"
printf 'deterministic signed target image fixture\n' > "$media"

reset_fixture() {
  rm -rf -- "$test_root/case"
  mkdir -p -- "$test_root/case/target-image"
  zstd --quiet --force -o "$test_root/case/target-image/$image_name" -- "$media"
  archive_sha256="$(
    sha256sum -- "$test_root/case/target-image/$image_name" | cut -d ' ' -f 1
  )"
  media_sha256="$(sha256sum -- "$media" | cut -d ' ' -f 1)"
  archive_size="$(stat --format=%s -- "$test_root/case/target-image/$image_name")"
}

run_verification() {
  (
    cd -- "$test_root/case"
    RELEASE_TAG="$release_tag" \
      EXPECTED_ARCHIVE_SHA256="$archive_sha256" \
      EXPECTED_MEDIA_SHA256="$media_sha256" \
      EXPECTED_ARCHIVE_SIZE_BYTES="$archive_size" \
      bash "$verification_script"
  )
}

expect_failure() {
  local description="$1"
  local expected_message="$2"
  local output
  if output="$(run_verification 2>&1)"; then
    echo "expected failure: $description" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected_message"* ]]; then
    echo "wrong failure for $description: $output" >&2
    exit 1
  fi
}

reset_fixture
run_verification >/dev/null
test -f "$test_root/case/release-assets/$image_name"
test -f "$test_root/case/release-assets/$image_name.sha256"
(
  cd -- "$test_root/case/release-assets"
  sha256sum --check --strict -- "$image_name.sha256" >/dev/null
)

reset_fixture
archive_sha256="$(printf '0%.0s' {1..64})"
expect_failure "wrong archive digest" "Archive digest mismatch"

reset_fixture
media_sha256="$(printf '0%.0s' {1..64})"
expect_failure "wrong media digest" "Media digest mismatch"

reset_fixture
(( archive_size += 1 ))
expect_failure "wrong archive size" "Image size mismatch"

reset_fixture
rm -- "$test_root/case/target-image/$image_name"
ln -s -- "$media" "$test_root/case/target-image/$image_name"
expect_failure "symbolic-link image" "Unsafe image"

reset_fixture
touch "$test_root/case/target-image/unexpected"
expect_failure "extra staged file" "Unexpected image contents"

echo "release workflow image verification tests passed"
