#!/usr/bin/env bash

set -euo pipefail

if (( $# != 1 )); then
  echo "usage: verify_remote_release_tag_test.sh VERIFY_REMOTE_RELEASE_TAG" >&2
  exit 2
fi

guard="$(realpath "$1")"

gh() {
  if (( $# != 4 )) || [[ "$1" != api || "$3" != --jq ]]; then
    echo "unexpected gh invocation: $*" >&2
    return 2
  fi

  case "$2" in
    "repos/example/kaiba/git/ref/tags/v0.2.0")
      if [[ "${MOCK_REF_API_FAILURE:-false}" == true ]]; then
        return 1
      fi
      printf '%s\n' "$MOCK_REF_FIELDS"
      ;;
    "repos/example/kaiba/git/tags/$MOCK_TAG_OBJECT_SHA")
      if [[ "${MOCK_TAG_API_FAILURE:-false}" == true ]]; then
        return 1
      fi
      printf '%s\n' "$MOCK_TAG_FIELDS"
      ;;
    *)
      echo "unexpected API endpoint: $2" >&2
      return 2
      ;;
  esac
}
export -f gh

source_revision="1111111111111111111111111111111111111111"
tag_object_sha="2222222222222222222222222222222222222222"
other_revision="3333333333333333333333333333333333333333"

reset_fixture() {
  export MOCK_REF_API_FAILURE=false
  export MOCK_TAG_API_FAILURE=false
  export MOCK_TAG_OBJECT_SHA="$tag_object_sha"
  export MOCK_REF_FIELDS=$'refs/tags/v0.2.0\ttag\t'"$tag_object_sha"
  export MOCK_TAG_FIELDS="$tag_object_sha"$'\tcommit\t'"$source_revision"
}

expect_failure() {
  local description="$1"
  local expected_message="$2"
  local output
  shift 2
  if output="$(bash "$guard" "$@" 2>&1)"; then
    echo "expected failure: $description" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected_message"* ]]; then
    echo "wrong failure for $description: $output" >&2
    exit 1
  fi
}

reset_fixture
bash "$guard" example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_REF_FIELDS=$'refs/tags/v0.2.0\tcommit\t'"$source_revision"
expect_failure "lightweight tag" "Annotated release tag required" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_REF_FIELDS=$'refs/tags/v9.9.9\ttag\t'"$tag_object_sha"
expect_failure "wrong remote ref" "Annotated release tag required" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_REF_FIELDS=$'refs/tags/v0.2.0\ttag\tnot-an-object-id'
expect_failure "malformed tag object ID" "Annotated release tag required" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_REF_API_FAILURE=true
expect_failure "ref API failure" "Release tag unavailable" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_API_FAILURE=true
expect_failure "tag-object API failure" "Unable to read tag object" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_FIELDS="$other_revision"$'\tcommit\t'"$source_revision"
expect_failure "wrong tag object response" "returned the wrong tag object" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_FIELDS="$tag_object_sha"$'\ttag\t'"$other_revision"
expect_failure "nested annotated tag" "Direct commit tag required" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_FIELDS="$tag_object_sha"$'\tblob\t'"$other_revision"
expect_failure "non-commit target" "Direct commit tag required" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_FIELDS="$tag_object_sha"$'\tcommit\tnot-a-commit-id'
expect_failure "malformed commit ID" "malformed commit ID" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
export MOCK_TAG_FIELDS="$tag_object_sha"$'\tcommit\t'"$other_revision"
expect_failure "source revision mismatch" "Release tag moved" \
  example/kaiba v0.2.0 "$source_revision"

reset_fixture
expect_failure "malformed repository" "Invalid repository" \
  invalid-repository v0.2.0 "$source_revision"
expect_failure "malformed release tag" "Invalid release tag" \
  example/kaiba latest "$source_revision"
expect_failure "malformed source revision" "Invalid source revision" \
  example/kaiba v0.2.0 not-a-revision

echo "remote release tag guard tests passed"
