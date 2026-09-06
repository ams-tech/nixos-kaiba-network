#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: read_release_image_binding.sh RELEASE_TAG SOURCE_REVISION" >&2
  exit 2
fi

release_tag="$1"
source_revision="$2"

if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "invalid stable release tag" >&2
  exit 1
fi
if [[ ! "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "invalid source revision" >&2
  exit 1
fi

tag_ref="refs/tags/$release_tag"
if [[ "$(git cat-file -t "$tag_ref" 2>/dev/null || true)" != tag ]]; then
  echo "annotated release tag is unavailable" >&2
  exit 1
fi
if [[ "$(git rev-parse --verify --end-of-options "${tag_ref}^{commit}")" != "$source_revision" ]]; then
  echo "release tag source revision does not match" >&2
  exit 1
fi

tag_message="$(git for-each-ref --format='%(contents)' "$tag_ref")"
mapfile -t message_lines <<< "$tag_message"
if (( ${#message_lines[@]} != 6 )); then
  echo "release tag image binding must contain exactly six lines" >&2
  exit 1
fi
if [[ "${message_lines[0]}" != "Kaiba signed secure-boot target image $release_tag" ]] ||
  [[ -n "${message_lines[1]}" ]] ||
  [[ "${message_lines[2]}" != "Source-Revision: $source_revision" ]]; then
  echo "release tag image binding header does not match" >&2
  exit 1
fi
if [[ ! "${message_lines[3]}" =~ ^Archive-SHA256:\ ([0-9a-f]{64})$ ]]; then
  echo "release tag archive digest is malformed" >&2
  exit 1
fi
archive_sha256="${BASH_REMATCH[1]}"
if [[ ! "${message_lines[4]}" =~ ^Media-SHA256:\ ([0-9a-f]{64})$ ]]; then
  echo "release tag media digest is malformed" >&2
  exit 1
fi
media_sha256="${BASH_REMATCH[1]}"
if [[ ! "${message_lines[5]}" =~ ^Archive-Size-Bytes:\ ([1-9][0-9]*)$ ]]; then
  echo "release tag archive size is malformed" >&2
  exit 1
fi
archive_size_bytes="${BASH_REMATCH[1]}"
if (( archive_size_bytes >= 2147483648 )); then
  echo "release tag archive size exceeds the GitHub asset limit" >&2
  exit 1
fi

tag_object_sha="$(git rev-parse --verify --end-of-options "$tag_ref")"
if [[ ! "$tag_object_sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "release tag object ID is malformed" >&2
  exit 1
fi

printf '%s\t%s\t%s\t%s\n' \
  "$archive_sha256" "$media_sha256" "$archive_size_bytes" "$tag_object_sha"
