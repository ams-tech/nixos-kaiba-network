#!/usr/bin/env bash
# Test doubles below replace dynamically dispatched helper functions and
# globals after sourcing the orchestrator.
# shellcheck disable=SC2034,SC2329

set -euo pipefail
umask 077

script="${1-}"
[[ -n "$script" && -f "$script" ]] || {
  printf 'usage: %s PATH_TO_CEREMONY_SCRIPT\n' "$0" >&2
  exit 2
}

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

repository="$work/repository"
mkdir -p "$repository"
git -C "$repository" init --initial-branch=main >/dev/null
git -C "$repository" config user.name 'Ceremony Test'
git -C "$repository" config user.email 'ceremony-test@example.invalid'
printf '%s\n' fixture > "$repository/tracked"
git -C "$repository" add tracked
git -C "$repository" commit -m fixture >/dev/null
commit="$(git -C "$repository" rev-parse HEAD)"
git -C "$repository" tag --annotate v1.2.3 --message 'test release' "$commit"
git -C "$repository" tag v1.2.4 "$commit"
git -C "$repository" tag --annotate v1.2.5 --message 'nested test release' v1.2.3 >/dev/null 2>&1
git -C "$repository" tag --annotate v01.2.3 --message 'leading-zero test release' "$commit"
git -C "$repository" tag --annotate v1.2.3-rc1 --message 'prerelease test release' "$commit"
git -C "$repository" update-ref refs/remotes/origin/main "$commit"
git -C "$repository" switch --detach v1.2.3 >/dev/null 2>&1

fake_bin="$work/fake-bin"
mkdir -p "$fake_bin"
test_bash="$(command -v bash)"
printf '#!%s\n' "$test_bash" > "$fake_bin/nix"
cat >> "$fake_bin/nix" <<'EOF'
printf '%s\n' "$*" >> "$KAIBA_TEST_INVOCATIONS"
exit 23
EOF
chmod 0755 "$fake_bin/nix"
for forbidden in \
  sudo \
  systemctl \
  ykman \
  pkcs11-tool \
  pcsc_scan \
  opensc-tool \
  yubico-piv-tool \
  kaiba-provision-sign-boot \
  kaiba-provision-sign-eeprom \
  kaiba-provision-signer \
  kaiba-provision-signing-client \
  kaiba-provision-signing-gate \
  kaiba-provision-yubikey-wrapper; do
  printf '#!%s\n' "$test_bash" > "$fake_bin/$forbidden"
  cat >> "$fake_bin/$forbidden" <<'EOF'
printf 'forbidden command invoked: %s\n' "${0##*/}" >> "$KAIBA_TEST_FORBIDDEN"
exit 97
EOF
  chmod 0755 "$fake_bin/$forbidden"
done

invocations="$work/invocations"
forbidden_log="$work/forbidden"
: > "$invocations"
: > "$forbidden_log"
export KAIBA_TEST_INVOCATIONS="$invocations"
export KAIBA_TEST_FORBIDDEN="$forbidden_log"

help="$work/help"
bash "$script" --help > /dev/null 2> "$help"
for forbidden_subcommand in run-all approve sign retry install start stop provision-pin transfer; do
  if grep -Eq "^[[:space:]]*kaiba-provision-signing-ceremony[[:space:]]+$forbidden_subcommand([[:space:]]|$)" "$help"; then
    fail "help exposes forbidden subcommand $forbidden_subcommand"
  fi
done

if grep -Eq '^[[:space:]]*(sudo|systemctl|ykman|pkcs11-tool|pcsc_scan|opensc-tool|yubico-piv-tool|kaiba-provision-sign-(boot|eeprom)|kaiba-provision-signer|kaiba-provision-signing-(client|gate)|kaiba-provision-yubikey-wrapper)([[:space:]]|$)' "$script"; then
  fail 'public-only orchestrator contains a live-authority command invocation'
fi
if grep -Eq '(pkcs11-tool|pcsc_scan|opensc-tool|yubico-piv-tool|kaiba-provision-sign-(boot|eeprom)|kaiba-provision-signer|kaiba-provision-signing-(client|gate)|kaiba-provision-yubikey-wrapper)' "$script"; then
  fail 'public-only orchestrator names a forbidden live-authority executable'
fi

evidence_dir="$work/evidence"
mkdir -m 0700 "$evidence_dir"
printf '%s\n' first > "$evidence_dir/first.tmp"
(
  # shellcheck source=/dev/null
  source "$script"
  publish_evidence "$evidence_dir/first.tmp" "$evidence_dir/record.json"
)
[[ "$(cat "$evidence_dir/record.json")" == first ]] || fail 'first evidence publication changed bytes'
printf '%s\n' first > "$evidence_dir/same.tmp"
(
  # shellcheck source=/dev/null
  source "$script"
  publish_evidence "$evidence_dir/same.tmp" "$evidence_dir/record.json"
)
[[ ! -e "$evidence_dir/same.tmp" ]] || fail 'identical evidence replay did not consume its temporary file'
printf '%s\n' different > "$evidence_dir/different.tmp"
if (
  # shellcheck source=/dev/null
  source "$script"
  publish_evidence "$evidence_dir/different.tmp" "$evidence_dir/record.json"
); then
  fail 'different evidence replaced an existing record'
fi
[[ "$(cat "$evidence_dir/record.json")" == first ]] || fail 'conflicting evidence overwrote the original record'

mkdir "$evidence_dir/redirect-target"
ln -s "$evidence_dir/redirect-target" "$evidence_dir/symlink-record.json"
printf '%s\n' escaped > "$evidence_dir/symlink.tmp"
if (
  # shellcheck source=/dev/null
  source "$script"
  publish_evidence "$evidence_dir/symlink.tmp" "$evidence_dir/symlink-record.json"
); then
  fail 'evidence publication followed a destination symlink to a directory'
fi
[[ ! -e "$evidence_dir/redirect-target/symlink.tmp" ]] ||
  fail 'evidence publication escaped through a destination symlink'

if (
  # shellcheck source=/dev/null
  source "$script"
  ceremony_dir="$work/missing-inventory"
  require_private_directory() { :; }
  resolve_result_link() {
    printf -v "$1" '/nix/store/00000000000000000000000000000000-test'
  }
  resolve_public_paths
); then
  fail 'a later phase could resolve public paths without the immutable review inventory'
fi

(
  # shellcheck source=/dev/null
  source "$script"
  ceremony_dir="$work/missing-inventory"
  require_private_directory() { :; }
  resolve_result_link() {
    printf -v "$1" '/nix/store/00000000000000000000000000000000-test'
  }
  resolve_public_paths --allow-missing-inventory
) || fail 'prepare-only public path resolution rejected its construction state'

resume_dir="$work/resume"
mkdir -p "$resume_dir/public" "$resume_dir/logs"
ln -s /nix/store/00000000000000000000000000000000-resumed "$resume_dir/public/resumed"
(
  # shellcheck source=/dev/null
  source "$script"
  ceremony_dir="$resume_dir"
  flake_ref='git+file:/fixture?rev=0000000000000000000000000000000000000000'
  readlink() { printf '%s\n' /nix/store/00000000000000000000000000000000-resumed; }
  nix-store() { return 0; }
  nix() { printf '%s\n' /nix/store/00000000000000000000000000000000-resumed; }
  run_public_build resumed test-output
) || fail 'fixed-output resume rejected the exact evaluated store path'

assembly_ceremony="$work/assembly-ceremony"
assembly_handoff="$work/assembly-handoff"
assembly_review="$work/assembly-review"
assembly_intent="$work/assembly-intent"
mkdir -p \
  "$assembly_ceremony/public" \
  "$assembly_ceremony/logs" \
  "$assembly_ceremony/gc-roots" \
  "$assembly_handoff/boot-signed" \
  "$assembly_handoff/eeprom-signed" \
  "$assembly_handoff/owned-recovery-signed" \
  "$assembly_review" \
  "$assembly_intent"
release_digest="sha256:$(printf '1%.0s' {1..64})"
export_digest="sha256:$(printf '2%.0s' {1..64})"
registry_digest="sha256:$(printf '3%.0s' {1..64})"
printf '%s\n' '{"fixture":true}' > "$assembly_intent/release-intent.json"
cp "$assembly_intent/release-intent.json" "$assembly_handoff/release-intent.json"
for handoff_file in approval.json signing-grants.json signing-receipts.json; do
  printf '%s\n' '{"fixture":true}' > "$assembly_handoff/$handoff_file"
done
for receipt_digit in 4 5 6 7 8; do
  printf 'sha256:%s\n' "$(printf "$receipt_digit%.0s" {1..64})"
done > "$assembly_handoff/live-result-receipt-digests.txt"
printf '%s\n' authenticated-manifest > "$assembly_ceremony/handoff-manifest.sha256"
assembly_manifest_hash="$(sha256sum "$assembly_ceremony/handoff-manifest.sha256" | cut -d ' ' -f 1)"
test_executable="$(readlink -e "$(command -v bash)")"
test_store_path="$(dirname "$(dirname "$test_executable")")"
if [[ "$test_store_path" != /nix/store/* ]]; then
  test_executable="$(readlink -e "$(command -v nix)")"
  test_store_path="$(dirname "$(dirname "$test_executable")")"
fi
[[ "$test_store_path" == /nix/store/* && -d "$test_store_path" ]] ||
  fail 'test could not resolve an existing Nix store directory'
test_store_nar_hash='sha256:test-store-nar-hash'
test_store_name="${test_store_path#/nix/store/}"
test_store_hash="${test_store_name%%-*}"
assembly_handoff_gc_root="$assembly_ceremony/gc-roots/handoff-snapshot-$test_store_hash"
ln -s "$test_store_path" "$assembly_handoff_gc_root"
assembly_approval_sha256="$(sha256sum "$assembly_handoff/approval.json" | cut -d ' ' -f 1)"
assembly_registry_sha256="$(sha256sum "$assembly_handoff/signing-grants.json" | cut -d ' ' -f 1)"

gc_root_fixture="$work/gc-root-fixture"
install -d -m 0700 "$gc_root_fixture" "$gc_root_fixture/gc-roots"
(
  # shellcheck source=/dev/null
  source "$script"
  ceremony_dir="$gc_root_fixture"
  nix-store() { return 0; }
  gc_root="$(register_store_gc_root immutable-snapshot "$test_store_path")"
  [[ "$gc_root" == "$gc_root_fixture/gc-roots/immutable-snapshot" ]]
  [[ "$(readlink -- "$gc_root")" == "$test_store_path" ]]
  [[ "$(register_store_gc_root immutable-snapshot "$test_store_path")" == "$gc_root" ]]
) || fail 'immutable snapshot GC-root registration was not idempotent'
other_test_store_path="$test_executable"
[[ "$other_test_store_path" != "$test_store_path" && "$other_test_store_path" == /nix/store/* ]] ||
  fail 'test could not resolve a distinct Nix store path for GC-root collision'
gc_root_collision_output="$work/gc-root-collision-output"
if (
  # shellcheck source=/dev/null
  source "$script"
  ceremony_dir="$gc_root_fixture"
  nix-store() { return 0; }
  register_store_gc_root immutable-snapshot "$other_test_store_path"
) > "$gc_root_collision_output" 2>&1; then
  fail 'snapshot GC root was retargeted to different content'
fi
grep -Fq 'refusing to retarget the immutable-snapshot GC root' "$gc_root_collision_output" ||
  fail 'GC-root collision did not identify the no-retarget boundary'
[[ "$(readlink -- "$gc_root_fixture/gc-roots/immutable-snapshot")" == "$test_store_path" ]] ||
  fail 'GC-root collision changed the original target'
jq --null-input \
  --arg release "$release_digest" \
  '{release_intent_digest: $release}' \
  > "$assembly_review/review.json"
jq --null-input \
  --arg release "$release_digest" \
  --arg export "$export_digest" \
  --arg registry "$registry_digest" '
    {
      schema_version: "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2",
      status: "valid",
      release_intent_digest: $release,
      export_digest: $export,
      registry_digest: $registry,
      receipt_digests: [
        "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "sha256:8888888888888888888888888888888888888888888888888888888888888888"
      ]
    }
  ' > "$assembly_ceremony/offline-receipt-verification.json"
jq --null-input \
  --arg revision "$commit" \
  --arg manifest "$assembly_manifest_hash" \
  --arg handoff_store "$test_store_path" \
  --arg handoff_store_nar_hash "$test_store_nar_hash" \
  --arg handoff_gc_root "$assembly_handoff_gc_root" \
  --arg approval_sha256 "$assembly_approval_sha256" \
  --arg registry_sha256 "$assembly_registry_sha256" \
  --arg release "$release_digest" \
  --arg export "$export_digest" \
  --arg registry "$registry_digest" '
    {
      schema_version: "kaiba.provisioning.development-signing-handoff-verification/v1alpha1",
      source_revision: $revision,
      manifest_sha256: $manifest,
      handoff_store: $handoff_store,
      handoff_store_nar_hash: $handoff_store_nar_hash,
      handoff_gc_root: $handoff_gc_root,
      approval_sha256: $approval_sha256,
      registry_sha256: $registry_sha256,
      release_intent_digest: $release,
      receipt_export_digest: $export,
      registry_digest: $registry,
      receipt_count: 5,
      status: "passed"
    }
  ' > "$assembly_ceremony/handoff-verification.json"
assembly_invocation="$work/assembly-invocation"
if (
  # shellcheck source=/dev/null
  source "$script"
  load_session() {
    expected_commit="$commit"
    release_tag=v1.2.3
    flake_ref="git+file:$repository?rev=$commit"
  }
  resolve_public_paths() {
    release_review="$assembly_review"
    release_intent="$assembly_intent"
  }
  write_handoff_manifest() {
    cp "$assembly_ceremony/handoff-manifest.sha256" "$2"
  }
  require_handoff_shape() { :; }
  cmp() { return 0; }
  sha256sum() {
    case "${1-}" in
      "$test_store_path/approval.json") printf '%s  %s\n' "$assembly_approval_sha256" "$1" ;;
      "$test_store_path/signing-grants.json") printf '%s  %s\n' "$assembly_registry_sha256" "$1" ;;
      *) command sha256sum "$@" ;;
    esac
  }
  nix-store() {
    if [[ "${1-}" == --query && "${2-}" == --hash ]]; then
      printf '%s\n' "$test_store_nar_hash"
    fi
    return 0
  }
  nix() {
    if [[ "${1-}" == store && "${2-}" == add-path ]]; then
      printf '%s\n' "$test_store_path"
      return 0
    fi
    printf '%s\n' "$@" > "$assembly_invocation"
    return 23
  }
  assemble_release \
    --ceremony-dir "$assembly_ceremony" \
    --handoff-dir "$assembly_handoff"
); then
  fail 'mocked signed-release assembly unexpectedly succeeded'
fi
grep -Fq 'signingGrantRegistry = builtins.storePath' "$assembly_invocation" ||
  fail 'assembly expression omitted the signingGrantRegistry factory input'
grep -Fq 'signingReceiptExport = builtins.storePath' "$assembly_invocation" ||
  fail 'assembly expression omitted the signingReceiptExport factory input'
grep -Fq '}).release' "$assembly_invocation" ||
  fail 'assembly expression selected the wrong signed-release factory output'
jq --exit-status '
  .status == "failed_preserve_evidence"
  and .build_status == 23
  and .log_status == 0
  and .next_boundary == "code_review_no_signing_retry"
' "$assembly_ceremony/assembly-failure.json" >/dev/null ||
  fail 'failed assembly did not publish terminal preserve-evidence state'

: > "$assembly_invocation"
rm -f "$assembly_ceremony/assembly-failure.json"
mutation_output="$work/assembly-mutation-output"
if (
  # shellcheck source=/dev/null
  source "$script"
  load_session() {
    expected_commit="$commit"
    release_tag=v1.2.3
    flake_ref="git+file:$repository?rev=$commit"
  }
  resolve_public_paths() {
    release_review="$assembly_review"
    release_intent="$assembly_intent"
  }
  require_handoff_shape() { :; }
  sha256sum() {
    case "${1-}" in
      "$test_store_path/approval.json") printf '%s  %s\n' "$assembly_approval_sha256" "$1" ;;
      "$test_store_path/signing-grants.json") printf '%s  %s\n' "$assembly_registry_sha256" "$1" ;;
      *) command sha256sum "$@" ;;
    esac
  }
  nix-store() {
    if [[ "${1-}" == --query && "${2-}" == --hash ]]; then
      printf '%s\n' "$test_store_nar_hash"
    fi
    return 0
  }
  nix() {
    if [[ "${1-}" == store && "${2-}" == add-path ]]; then
      printf '%s\n' /nix/store/00000000000000000000000000000000-changed
      return 0
    fi
    printf '%s\n' "$@" >> "$assembly_invocation"
    return 97
  }
  assemble_release \
    --ceremony-dir "$assembly_ceremony" \
    --handoff-dir "$assembly_handoff"
) > "$mutation_output" 2>&1; then
  fail 'assembly accepted handoff bytes changed after verification'
fi
grep -Fq 'handoff changed after independent verification' "$mutation_output" || {
  cat "$mutation_output" >&2
  fail 'changed-handoff rejection did not identify the verification boundary'
}
[[ ! -s "$assembly_invocation" ]] || fail 'changed handoff reached Nix import or assembly'

owned_contract="$work/owned-plan-contract"
mkdir -p "$owned_contract/review" "$owned_contract/eeprom"
owned_release_digest="sha256:$(printf '9%.0s' {1..64})"
owned_fresh_plan_id='release:rpi5-prototype:test:eeprom'
jq --null-input --arg digest "$owned_release_digest" \
  '{release_intent_digest: $digest}' > "$owned_contract/review/review.json"
jq --null-input --arg plan_id "$owned_fresh_plan_id" \
  '{plan_id: $plan_id}' > "$owned_contract/eeprom/plan.json"
jq --null-input \
  --arg digest "$owned_release_digest" \
  --arg plan_id "$owned_fresh_plan_id" '
    {
      schema_version: "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1",
      plan_id: ($plan_id + ":owned-recovery"),
      updater_mode: "owned-recovery",
      updater_flags: ["-f", "-r"],
      fresh_eeprom_plan: {
        plan_id: $plan_id,
        release_intent_digest: $digest
      },
      fresh_eeprom_result: {
        plan_id: $plan_id,
        release_intent_digest: $digest,
        signatures: [
          {role: "rpi5.eeprom_bootcode"},
          {role: "rpi5.eeprom_bootsys"},
          {role: "rpi5.eeprom_config"}
        ]
      },
      owned_recovery_signing_input: {
        role: "rpi5.owned_recovery_bootcode"
      }
    }
  ' > "$owned_contract/plan.json"
(
  # shellcheck source=/dev/null
  source "$script"
  release_review="$owned_contract/review"
  eeprom_plan="$owned_contract/eeprom"
  validate_owned_recovery_plan_contract "$owned_contract/plan.json"
) || fail 'valid nested owned-recovery plan contract was rejected'
jq '.fresh_eeprom_result.release_intent_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "$owned_contract/plan.json" > "$owned_contract/wrong-release.json"
if (
  # shellcheck source=/dev/null
  source "$script"
  release_review="$owned_contract/review"
  eeprom_plan="$owned_contract/eeprom"
  validate_owned_recovery_plan_contract "$owned_contract/wrong-release.json"
) >/dev/null 2>&1; then
  fail 'owned-recovery plan accepted mismatched fresh-result release lineage'
fi

expect_failure() {
  local expected="$1"
  shift
  local output="$work/failure-output"
  if PATH="$fake_bin:$PATH" bash "$script" "$@" > "$output" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
  grep -Fq "$expected" "$output" || {
    cat "$output" >&2
    fail "failure did not contain: $expected"
  }
}

expect_failure 'release tag must be annotated' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.4 \
  --expected-commit "$commit" \
  --main-ref origin/main \
  --ceremony-dir "$work/lightweight"
[[ ! -s "$invocations" ]] || fail 'lightweight tag reached Nix'

for invalid_tag in v01.2.3 v1.2.3-rc1; do
  expect_failure 'release tag is not a stable canonical vMAJOR.MINOR.PATCH tag' \
    prepare-public \
    --repository "$repository" \
    --release-tag "$invalid_tag" \
    --expected-commit "$commit" \
    --main-ref origin/main \
    --ceremony-dir "$work/invalid-tag-${invalid_tag//[^0-9A-Za-z]/-}"
done
[[ ! -s "$invocations" ]] || fail 'non-release tag reached Nix'

expect_failure 'release tag must directly annotate a commit' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.5 \
  --expected-commit "$commit" \
  --main-ref origin/main \
  --ceremony-dir "$work/nested-tag"
[[ ! -s "$invocations" ]] || fail 'nested annotated tag reached Nix'

expect_failure 'release tag does not identify the independently supplied commit' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.3 \
  --expected-commit 0000000000000000000000000000000000000000 \
  --main-ref origin/main \
  --ceremony-dir "$work/wrong-commit"
[[ ! -s "$invocations" ]] || fail 'wrong commit reached Nix'

printf '%s\n' dirty > "$repository/untracked"
expect_failure 'checkout must be clean' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.3 \
  --expected-commit "$commit" \
  --main-ref origin/main \
  --ceremony-dir "$work/dirty"
rm -f -- "$repository/untracked"
[[ ! -s "$invocations" ]] || fail 'dirty checkout reached Nix'

ceremony="$work/ceremony"
expect_failure 'unsigned-artifacts build failed with status 23' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.3 \
  --expected-commit "$commit" \
  --main-ref origin/main \
  --ceremony-dir "$ceremony"

[[ "$(stat -c '%a' "$ceremony")" == 700 ]] || fail 'ceremony directory is not private'
[[ "$(stat -c '%a' "$ceremony/ceremony.json")" == 600 ]] || fail 'ceremony session is not private'
jq --exit-status \
  --arg commit "$commit" \
  '.schema_version == "kaiba.provisioning.development-signing-ceremony-session/v1alpha1"
   and .release_tag == "v1.2.3"
   and .source_revision == $commit' \
  "$ceremony/ceremony.json" >/dev/null || fail 'ceremony session is not bound to the exact release'
[[ -f "$ceremony/logs/unsigned-artifacts.attempt-1.log" ]] || fail 'first failed build log was not retained'

expect_failure 'unsigned-artifacts build failed with status 23' \
  prepare-public \
  --repository "$repository" \
  --release-tag v1.2.3 \
  --expected-commit "$commit" \
  --main-ref origin/main \
  --ceremony-dir "$ceremony"
[[ -f "$ceremony/logs/unsigned-artifacts.attempt-2.log" ]] || fail 'resumed build did not preserve a second attempt log'
[[ "$(wc -l < "$invocations")" -eq 2 ]] || fail 'resumed public build invoked an unexpected number of Nix builds'

stale_helper_output="$work/stale-helper-output"
if (
  # shellcheck source=/dev/null
  source "$script"
  packaged_source_revision=0000000000000000000000000000000000000000
  load_session "$ceremony"
) > "$stale_helper_output" 2>&1; then
  fail 'helper from a different revision reopened an existing ceremony session'
fi
grep -Fq 'ceremony helper source revision differs from the existing session' "$stale_helper_output" ||
  fail 'stale-helper rejection did not identify the session source binding'

dirty_helper_output="$work/dirty-helper-output"
if (
  # shellcheck source=/dev/null
  source "$script"
  packaged_source_tree_clean=false
  load_session "$ceremony"
) > "$dirty_helper_output" 2>&1; then
  fail 'helper built from dirty source reopened an existing ceremony session'
fi
grep -Fq 'ceremony helper must be built from a clean Git source' "$dirty_helper_output" ||
  fail 'dirty-helper rejection did not identify the clean-source boundary'

PATH="$fake_bin:$PATH" bash "$script" status --ceremony-dir "$ceremony" > "$work/status"
grep -Fq '"release_tag": "v1.2.3"' "$work/status" || fail 'status did not reopen the immutable ceremony session'
[[ ! -s "$forbidden_log" ]] || {
  cat "$forbidden_log" >&2
  fail 'public ceremony checks invoked a forbidden live-authority command'
}

printf '%s\n' 'signing ceremony automation tests: PASS'
