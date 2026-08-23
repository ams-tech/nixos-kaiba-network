#!/usr/bin/env bash

set -euo pipefail

if (( $# != 3 )); then
  echo "usage: verify_release_tag.sh RELEASE_TAG SOURCE_REVISION MAIN_REF" >&2
  exit 2
fi

release_tag="$1"
source_revision="$2"
main_ref="$3"

if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "::error title=Invalid release tag::$release_tag is not a stable vMAJOR.MINOR.PATCH tag."
  exit 1
fi
if [[ ! "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "::error title=Invalid source revision::The release source revision is malformed."
  exit 1
fi

tag_ref="refs/tags/$release_tag"
if ! tag_type="$(git cat-file -t "$tag_ref" 2>/dev/null)"; then
  echo "::error title=Release tag unavailable::$tag_ref was not fetched."
  exit 1
fi
if [[ "$tag_type" != tag ]]; then
  echo "::error title=Annotated release tag required::$release_tag is a lightweight tag; create releases with git tag --annotate."
  exit 1
fi
tag_target_type="$(git cat-file tag "$tag_ref" | sed -n '2s/^type //p')"
if [[ "$tag_target_type" != commit ]]; then
  echo "::error title=Direct commit tag required::$release_tag must directly annotate a commit."
  exit 1
fi
if ! tagged_revision="$(
  git rev-parse --verify --end-of-options "${tag_ref}^{commit}" 2>/dev/null
)"; then
  echo "::error title=Invalid release tag::$release_tag does not resolve to a commit."
  exit 1
fi
if [[ "$tagged_revision" != "$source_revision" ]]; then
  echo "::error title=Release revision mismatch::$release_tag resolves to $tagged_revision, not $source_revision."
  exit 1
fi
if ! git rev-parse --verify --quiet --end-of-options "${main_ref}^{commit}" >/dev/null; then
  echo "::error title=Main revision unavailable::$main_ref does not resolve to a commit."
  exit 1
fi
if ! git merge-base --is-ancestor "$tagged_revision" "$main_ref"; then
  echo "::error title=Unreviewed release commit::$tagged_revision is not reachable from $main_ref."
  exit 1
fi

echo "Verified annotated release tag $release_tag at $tagged_revision."
