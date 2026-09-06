#!/usr/bin/env bash

set -euo pipefail

if (( $# != 4 )); then
  echo "usage: verify_remote_release_tag.sh GH_REPO RELEASE_TAG SOURCE_REVISION EXPECTED_TAG_OBJECT_SHA" >&2
  exit 2
fi

gh_repo="$1"
release_tag="$2"
source_revision="$3"
expected_tag_object_sha="$4"

if [[ ! "$gh_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error title=Invalid repository::The GitHub repository name is malformed."
  exit 1
fi
if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "::error title=Invalid release tag::$release_tag is not a stable vMAJOR.MINOR.PATCH tag."
  exit 1
fi
if [[ ! "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "::error title=Invalid source revision::The release source revision is malformed."
  exit 1
fi
if [[ ! "$expected_tag_object_sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "::error title=Invalid tag object::The expected release tag object ID is malformed."
  exit 1
fi

if ! ref_fields="$(
  gh api "repos/$gh_repo/git/ref/tags/$release_tag" \
    --jq '[.ref, .object.type, .object.sha] | @tsv'
)"; then
  echo "::error title=Release tag unavailable::Unable to read $release_tag."
  exit 1
fi
IFS=$'\t' read -r remote_ref remote_tag_type tag_object_sha <<< "$ref_fields"
if [[ "$remote_ref" != "refs/tags/$release_tag" || "$remote_tag_type" != tag ]] || \
  [[ ! "$tag_object_sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "::error title=Annotated release tag required::$release_tag is not a valid annotated tag ref."
  exit 1
fi
if [[ "$tag_object_sha" != "$expected_tag_object_sha" ]]; then
  echo "::error title=Release tag replaced::$release_tag no longer names the verified tag object."
  exit 1
fi

if ! tag_fields="$(
  gh api "repos/$gh_repo/git/tags/$tag_object_sha" \
    --jq '[.sha, .object.type, .object.sha] | @tsv'
)"; then
  echo "::error title=Invalid release tag::Unable to read tag object $tag_object_sha."
  exit 1
fi
IFS=$'\t' read -r returned_tag_sha target_type remote_revision <<< "$tag_fields"
if [[ "$returned_tag_sha" != "$tag_object_sha" ]]; then
  echo "::error title=Invalid release tag::GitHub returned the wrong tag object for $release_tag."
  exit 1
fi
if [[ "$target_type" != commit ]]; then
  echo "::error title=Direct commit tag required::$release_tag must directly annotate a commit."
  exit 1
fi
if [[ ! "$remote_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "::error title=Invalid release tag::$release_tag contains a malformed commit ID."
  exit 1
fi
if [[ "$remote_revision" != "$source_revision" ]]; then
  echo "::error title=Release tag moved::$release_tag no longer directly annotates $source_revision."
  exit 1
fi

echo "Verified remote annotated release tag $release_tag at $remote_revision."
