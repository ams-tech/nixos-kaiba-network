# shellcheck shell=bash

set -euo pipefail
umask 077

readonly session_schema='kaiba.provisioning.development-signing-ceremony-session/v1alpha1'
readonly inventory_schema='kaiba.provisioning.development-signing-public-inventory/v1alpha1'
readonly authorization_schema='kaiba.provisioning.development-signing-authorization-check/v1alpha1'
readonly owned_plan_schema='kaiba.provisioning.development-signing-owned-plan-review-input/v1alpha1'
readonly handoff_schema='kaiba.provisioning.development-signing-handoff-verification/v1alpha1'
readonly assembly_schema='kaiba.provisioning.development-signed-release-summary/v1alpha1'

# Populated only by resolve_public_paths after each fixed result link is
# independently resolved into the Nix store.
unsigned_artifacts=''
release_intent=''
boot_plan=''
eeprom_plan=''
release_review=''
signing_package=''
deployment=''
approval_tool=''
receipts_tool=''

usage() {
  cat >&2 <<'EOF'
usage:
  kaiba-provision-signing-ceremony prepare-public \
    --repository ABSOLUTE_DIR --release-tag TAG --expected-commit HEX \
    --main-ref REF --ceremony-dir NEW_ABSOLUTE_DIR
  kaiba-provision-signing-ceremony verify-authorization \
    --ceremony-dir ABSOLUTE_DIR --received-authorization ABSOLUTE_DIR \
    --expected-approval-sha256 HEX --expected-registry-sha256 HEX
  kaiba-provision-signing-ceremony derive-owned-recovery \
    --ceremony-dir ABSOLUTE_DIR --eeprom-signed-store /nix/store/PATH
  kaiba-provision-signing-ceremony verify-handoff \
    --ceremony-dir ABSOLUTE_DIR --handoff-dir ABSOLUTE_DIR \
    --checksum-manifest ABSOLUTE_FILE --expected-manifest-sha256 HEX \
    --expected-approval-sha256 HEX --expected-registry-sha256 HEX
  kaiba-provision-signing-ceremony assemble \
    --ceremony-dir ABSOLUTE_DIR --handoff-dir ABSOLUTE_DIR
  kaiba-provision-signing-ceremony status --ceremony-dir ABSOLUTE_DIR

This helper automates public, non-authority ceremony plumbing only. It never
authors approval, installs authority, accepts a PIN, starts a gate, signs,
transfers evidence, retries a request, or authorizes hardware mutation.
EOF
}

fail() {
  printf 'STOP: %s\n' "$*" >&2
  exit 1
}

human_stop() {
  printf 'STOP (human boundary): %s\n' "$*" >&2
}

require_hex() {
  local label="$1"
  local value="$2"
  local lengths="$3"
  case ":$lengths:" in
    *":${#value}:"*) ;;
    *) fail "$label has an invalid length" ;;
  esac
  [[ "$value" =~ ^[0-9a-f]+$ ]] || fail "$label must be canonical lower-case hexadecimal"
}

require_release_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    fail 'release tag is not a stable canonical vMAJOR.MINOR.PATCH tag'
}

require_clean_absolute_path() {
  local label="$1"
  local path="$2"
  [[ "$path" == /* && "$path" != / ]] || fail "$label must be an absolute path other than /"
  [[ "$(realpath -m -- "$path")" == "$path" ]] || fail "$label must be a clean path"
}

require_existing_directory() {
  local label="$1"
  local path="$2"
  require_clean_absolute_path "$label" "$path"
  [[ -d "$path" && ! -L "$path" ]] || fail "$label must be a non-symlink directory"
}

require_regular_file() {
  local label="$1"
  local path="$2"
  require_clean_absolute_path "$label" "$path"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular non-symlink file"
}

require_private_directory() {
  local label="$1"
  local path="$2"
  require_existing_directory "$label" "$path"
  [[ "$(stat -c '%u:%a' -- "$path")" == "$(id -u):700" ]] ||
    fail "$label must be owned by the current user with mode 0700"
}

register_store_gc_root() {
  local label="$1"
  local store_path="$2"
  [[ "$label" =~ ^[0-9a-z][0-9a-z-]*$ ]] || fail 'internal error: invalid GC-root label'
  [[ "$store_path" == /nix/store/* && -e "$store_path" && ! -L "$store_path" ]] ||
    fail "$label must identify an existing non-symlink Nix-store path"
  local root_directory="$ceremony_dir/gc-roots"
  local root="$root_directory/$label"
  require_private_directory 'ceremony GC-root directory' "$root_directory"

  if [[ -e "$root" || -L "$root" ]]; then
    [[ -L "$root" && "$(readlink -- "$root")" == "$store_path" ]] ||
      fail "refusing to retarget the $label GC root"
  elif ! ln --symbolic --no-target-directory -- "$store_path" "$root"; then
    [[ -L "$root" && "$(readlink -- "$root")" == "$store_path" ]] ||
      fail "could not reserve the $label GC root without replacement"
  fi

  # Re-registering the already-bound indirect root is idempotent and repairs
  # missing per-user GC-root metadata without permitting a target change.
  nix-store --realise "$store_path" --add-root "$root" --indirect >/dev/null
  [[ -L "$root" && "$(readlink -- "$root")" == "$store_path" &&
    "$(readlink -e -- "$root")" == "$store_path" ]] ||
    fail "$label GC root does not resolve to its immutable snapshot"
  nix-store --verify-path "$store_path"
  printf '%s\n' "$root"
}

store_gc_root_label() {
  local prefix="$1"
  local store_path="$2"
  [[ "$prefix" =~ ^[0-9a-z][0-9a-z-]*$ ]] || fail 'internal error: invalid GC-root prefix'
  local store_name="${store_path#/nix/store/}"
  local store_hash="${store_name%%-*}"
  [[ "$store_path" == /nix/store/* && "$store_hash" =~ ^[0-9a-z]{32}$ ]] ||
    fail 'cannot derive a content-addressed GC-root label from the Nix-store path'
  printf '%s-%s\n' "$prefix" "$store_hash"
}

publish_evidence() {
  local temporary="$1"
  local destination="$2"
  chmod 0600 "$temporary"
  if ln --no-target-directory -- "$temporary" "$destination" 2>/dev/null; then
    rm -f -- "$temporary"
    return
  fi
  require_regular_file 'existing evidence' "$destination"
  if cmp --silent -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    return
  fi
  fail "refusing to replace different evidence at $destination"
}

write_session() {
  local created_at temporary session_path
  session_path="$ceremony_dir/ceremony.json"
  [[ ! -e "$session_path" && ! -L "$session_path" ]] || fail 'ceremony session already exists'
  created_at="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
  temporary="$(mktemp "$ceremony_dir/.ceremony.XXXXXX")"
  jq --null-input \
    --arg schema_version "$session_schema" \
    --arg release_tag "$release_tag" \
    --arg source_revision "$expected_commit" \
    --arg repository "$repository" \
    --arg flake_ref "$flake_ref" \
    --arg created_at "$created_at" \
    '{
      schema_version: $schema_version,
      release_tag: $release_tag,
      source_revision: $source_revision,
      repository: $repository,
      flake_ref: $flake_ref,
      created_at: $created_at
    }' > "$temporary"
  publish_evidence "$temporary" "$session_path"
}

load_session() {
  ceremony_dir="$1"
  require_private_directory 'ceremony directory' "$ceremony_dir"
  require_private_directory 'ceremony GC-root directory' "$ceremony_dir/gc-roots"
  local session_path="$ceremony_dir/ceremony.json"
  require_regular_file 'ceremony session' "$session_path"
  jq --exit-status \
    --arg schema "$session_schema" '
      .schema_version == $schema
      and (.release_tag | type == "string")
      and (.source_revision | type == "string")
      and (.repository | type == "string")
      and (.flake_ref | type == "string")
      and (.created_at | type == "string")
    ' "$session_path" >/dev/null || fail 'ceremony session is invalid'
  release_tag="$(jq --exit-status --raw-output '.release_tag' "$session_path")"
  expected_commit="$(jq --exit-status --raw-output '.source_revision' "$session_path")"
  repository="$(jq --exit-status --raw-output '.repository' "$session_path")"
  flake_ref="$(jq --exit-status --raw-output '.flake_ref' "$session_path")"
  require_release_tag "$release_tag"
  require_hex 'session source revision' "$expected_commit" '40:64'
  if [[ "${packaged_source_tree_clean:-true}" != true ]]; then
    fail 'ceremony helper must be built from a clean Git source'
  fi
  if [[ -n "${packaged_source_revision:-}" ]]; then
    [[ "$packaged_source_revision" == "$expected_commit" ]] ||
      fail 'ceremony helper source revision differs from the existing session'
  fi
  require_clean_absolute_path 'session repository' "$repository"
  [[ "$flake_ref" == "git+file:$repository?rev=$expected_commit" ]] ||
    fail 'ceremony session flake reference does not bind its repository and revision'
}

resolve_result_link() {
  local variable="$1"
  local link="$2"
  local label="$3"
  [[ -L "$link" ]] || fail "$label result link is absent"
  local resolved
  resolved="$(readlink -e -- "$link")"
  [[ "$resolved" == /nix/store/* ]] || fail "$label did not resolve into the Nix store"
  printf -v "$variable" '%s' "$resolved"
}

resolve_public_paths() {
  local allow_missing_inventory=false
  if [[ "${1-}" == --allow-missing-inventory ]]; then
    allow_missing_inventory=true
    shift
  fi
  (($# == 0)) || fail 'internal error: unexpected public-path resolver argument'
  local public="$ceremony_dir/public"
  require_private_directory 'public result directory' "$public"
  resolve_result_link unsigned_artifacts "$public/unsigned-artifacts" 'unsigned artifacts'
  resolve_result_link release_intent "$public/release-intent" 'release intent'
  resolve_result_link boot_plan "$public/boot-signing-plan" 'boot signing plan'
  resolve_result_link eeprom_plan "$public/eeprom-signing-plan" 'EEPROM signing plan'
  resolve_result_link release_review "$public/release-review" 'release review'
  resolve_result_link signing_package "$public/development-signing" 'development signing package'
  resolve_result_link deployment "$public/ubuntu-signing-gate-deployment" 'Ubuntu deployment'
  resolve_result_link approval_tool "$public/signing-approval-tool" 'approval tool'
  resolve_result_link receipts_tool "$public/signing-receipts-tool" 'receipt tool'
  if [[ -e "$ceremony_dir/public-review-inventory.json" || -L "$ceremony_dir/public-review-inventory.json" ]]; then
    require_regular_file 'public review inventory' "$ceremony_dir/public-review-inventory.json"
    jq --exit-status \
      --arg schema "$inventory_schema" \
      --arg tag "$release_tag" \
      --arg revision "$expected_commit" \
      --arg ref "$flake_ref" \
      --arg unsigned "$unsigned_artifacts" \
      --arg intent "$release_intent" \
      --arg boot "$boot_plan" \
      --arg eeprom "$eeprom_plan" \
      --arg review "$release_review" \
      --arg package "$signing_package" \
      --arg deployment "$deployment" \
      --arg approval "$approval_tool" \
      --arg receipts "$receipts_tool" '
        .schema_version == $schema
        and .release_tag == $tag
        and .source_revision == $revision
        and .flake_ref == $ref
        and .paths.unsigned_artifacts == $unsigned
        and .paths.release_intent == $intent
        and .paths.boot_signing_plan == $boot
        and .paths.eeprom_signing_plan == $eeprom
        and .paths.release_review == $review
        and .paths.signing_package == $package
        and .paths.ubuntu_deployment == $deployment
        and .paths.approval_tool == $approval
        and .paths.receipts_tool == $receipts
        and .status == "awaiting_human_review"
      ' "$ceremony_dir/public-review-inventory.json" >/dev/null ||
      fail 'public result links differ from the immutable review inventory'
    local inventory_signing_hash inventory_deployment_hash
    inventory_signing_hash="$(jq --exit-status --raw-output '.nar_hashes.signing_package' "$ceremony_dir/public-review-inventory.json")"
    inventory_deployment_hash="$(jq --exit-status --raw-output '.nar_hashes.ubuntu_deployment' "$ceremony_dir/public-review-inventory.json")"
    [[ "$(nix-store --query --hash "$signing_package")" == "$inventory_signing_hash" ]] ||
      fail 'signing package differs from the review inventory'
    [[ "$(nix-store --query --hash "$deployment")" == "$inventory_deployment_hash" ]] ||
      fail 'Ubuntu deployment differs from the review inventory'
  elif [[ "$allow_missing_inventory" != true ]]; then
    fail 'immutable public review inventory is absent; complete prepare-public and human review before advancing'
  fi
}

run_public_build() {
  local name="$1"
  local attribute="$2"
  local link="$ceremony_dir/public/$name"
  if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" ]] || fail "$name output path is not a result link"
    local existing
    existing="$(readlink -e -- "$link")"
    [[ "$existing" == /nix/store/* ]] || fail "$name existing result is not in the Nix store"
    nix-store --verify-path "$existing"
    local expected
    if ! expected="$(nix --accept-flake-config build \
      "$flake_ref#$attribute" --no-link --print-out-paths)"; then
      fail "$name fixed output could not be re-evaluated while resuming"
    fi
    [[ -n "$expected" && "$expected" != *$'\n'* && "$expected" == /nix/store/* ]] ||
      fail "$name fixed output evaluation returned an unexpected path set"
    [[ "$existing" == "$expected" ]] ||
      fail "$name existing result differs from the fixed release output"
    printf 'already built: %s -> %s\n' "$name" "$existing"
    return
  fi
  local attempt=1 log log_tmp
  while [[ -e "$ceremony_dir/logs/$name.attempt-$attempt.log" || -L "$ceremony_dir/logs/$name.attempt-$attempt.log" ]]; do
    attempt=$((attempt + 1))
  done
  log="$ceremony_dir/logs/$name.attempt-$attempt.log"
  log_tmp="$(mktemp "$ceremony_dir/logs/.$name.attempt-$attempt.XXXXXX")"
  local build_status log_status
  local -a pipeline_status
  set +e
  nix --accept-flake-config build -L \
    "$flake_ref#$attribute" \
    --out-link "$link" 2>&1 | tee "$log_tmp"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  build_status="${pipeline_status[0]}"
  log_status="${pipeline_status[1]}"
  publish_evidence "$log_tmp" "$log"
  if ((log_status != 0)); then
    fail "$name audit-log write failed with status $log_status; preserve the output and do not advance"
  fi
  if ((build_status != 0)); then
    fail "$name build failed with status $build_status; preserve the log and do not advance"
  fi
  [[ -L "$link" ]] || fail "$name build did not create its fixed output link"
}

prepare_public() {
  local main_ref=''
  repository=''
  release_tag=''
  expected_commit=''
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --repository) repository="${2-}"; shift 2 ;;
      --release-tag) release_tag="${2-}"; shift 2 ;;
      --expected-commit) expected_commit="${2-}"; shift 2 ;;
      --main-ref) main_ref="${2-}"; shift 2 ;;
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$repository" && -n "$release_tag" && -n "$expected_commit" &&
    -n "$main_ref" && -n "$ceremony_dir" ]] || { usage; exit 2; }
  require_existing_directory 'repository' "$repository"
  [[ "$repository" =~ ^/[0-9A-Za-z._/+:-]+$ ]] ||
    fail 'repository path contains characters that are unsafe in a git+file flake reference'
  require_release_tag "$release_tag"
  require_hex 'expected commit' "$expected_commit" '40:64'
  if [[ "${packaged_source_tree_clean:-true}" != true ]]; then
    fail 'ceremony helper must be built from a clean Git source'
  fi
  if [[ -n "${packaged_source_revision:-}" ]]; then
    [[ "$packaged_source_revision" == "$expected_commit" ]] ||
      fail 'ceremony helper was not built from the independently supplied release commit'
  fi
  [[ "$main_ref" =~ ^[0-9A-Za-z._/-]+$ && "$main_ref" != -* ]] || fail 'main ref is invalid'
  require_clean_absolute_path 'ceremony directory' "$ceremony_dir"

  [[ "$(git -C "$repository" cat-file -t "refs/tags/$release_tag")" == tag ]] ||
    fail 'release tag must be annotated'
  local tagged_object
  tagged_object="$(git -C "$repository" cat-file -p "refs/tags/$release_tag" | sed -n 's/^object //p')"
  require_hex 'release tag target object' "$tagged_object" '40:64'
  [[ "$(git -C "$repository" cat-file -t "$tagged_object")" == commit ]] ||
    fail 'release tag must directly annotate a commit'
  [[ "$tagged_object" == "$expected_commit" ]] ||
    fail 'release tag does not identify the independently supplied commit'
  [[ "$(git -C "$repository" rev-parse "$release_tag^{commit}")" == "$expected_commit" ]] ||
    fail 'release tag does not identify the independently supplied commit'
  [[ "$(git -C "$repository" rev-parse HEAD)" == "$expected_commit" ]] ||
    fail 'checkout HEAD does not equal the expected commit'
  git -C "$repository" rev-parse --verify "$main_ref^{commit}" >/dev/null ||
    fail 'main ref is unavailable; fetch it separately before retrying'
  git -C "$repository" merge-base --is-ancestor "$expected_commit" "$main_ref" ||
    fail 'expected commit is not reachable from the supplied main ref'
  [[ -z "$(git -C "$repository" status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'checkout must be clean, including untracked files'

  flake_ref="git+file:$repository?rev=$expected_commit"
  if [[ ! -e "$ceremony_dir" && ! -L "$ceremony_dir" ]]; then
    local requested_ceremony_dir="$ceremony_dir"
    local initialization_dir
    initialization_dir="$(mktemp -d "${ceremony_dir}.initializing.XXXXXX")"
    chmod 0700 "$initialization_dir"
    ceremony_dir="$initialization_dir"
    install -d -m 0700 "$ceremony_dir/public" "$ceremony_dir/logs" "$ceremony_dir/gc-roots"
    write_session
    ceremony_dir="$requested_ceremony_dir"
    mv --no-clobber --no-target-directory "$initialization_dir" "$ceremony_dir"
    [[ ! -e "$initialization_dir" && ! -L "$initialization_dir" ]] ||
      fail "ceremony initialization collided with $ceremony_dir; preserve the private initialization directory for review"
    require_private_directory 'ceremony directory' "$ceremony_dir"
  else
    local requested_repository="$repository"
    local requested_release_tag="$release_tag"
    local requested_commit="$expected_commit"
    require_private_directory 'ceremony directory' "$ceremony_dir"
    load_session "$ceremony_dir"
    [[ "$repository" == "$requested_repository" && "$release_tag" == "$requested_release_tag" &&
      "$expected_commit" == "$requested_commit" ]] ||
      fail 'existing ceremony session binds different release inputs'
    require_private_directory 'public result directory' "$ceremony_dir/public"
    require_private_directory 'ceremony log directory' "$ceremony_dir/logs"
    require_private_directory 'ceremony GC-root directory' "$ceremony_dir/gc-roots"
  fi

  run_public_build unsigned-artifacts packages.aarch64-linux.rpi5-prototype-unsigned-artifacts
  run_public_build release-intent rpi5-prototype-release-intent
  run_public_build boot-signing-plan rpi5-prototype-signing-plan
  run_public_build eeprom-signing-plan rpi5-prototype-eeprom-signing-plan
  run_public_build release-review rpi5-prototype-release-review
  run_public_build development-signing development-signing
  run_public_build ubuntu-signing-gate-deployment ubuntu-signing-gate-deployment
  run_public_build signing-approval-tool kaiba-provision-signing-approval
  run_public_build signing-receipts-tool kaiba-provision-signing-receipts

  resolve_public_paths --allow-missing-inventory
  nix-store --verify-path "$signing_package"
  nix-store --verify-path "$deployment"
  local signing_package_nar_hash deployment_nar_hash
  signing_package_nar_hash="$(nix-store --query --hash "$signing_package")"
  deployment_nar_hash="$(nix-store --query --hash "$deployment")"

  jq --exit-status --arg revision "$expected_commit" '
    .status == "passed"
    and .source_revision == $revision
    and .scope == "public-unsigned-prototype"
    and .hardware_access == false
    and .mutation_capable == false
    and .one_time_setting_capable == false
    and .private_key_access == false
  ' "$release_review/review.json" >/dev/null || fail 'release review did not pass the public no-authority contract'
  jq --exit-status --arg revision "$expected_commit" '
    .source_revision == $revision
    and .authorization_scope == "cohort_release"
    and (.signing_inputs | length == 5)
    and (.required_output_roles | length == 18)
  ' "$release_intent/release-intent.json" >/dev/null || fail 'release intent did not pass the fixed five-input/eighteen-output contract'
  cmp -- "$unsigned_artifacts/unsigned/boot.img" "$boot_plan/boot.img"
  cmp -- "$release_intent/release-intent.json" "$boot_plan/release-intent.json"
  cmp -- "$release_intent/release-intent.json" "$eeprom_plan/release-intent.json"

  local inventory_tmp
  inventory_tmp="$(mktemp "$ceremony_dir/.public-review-inventory.XXXXXX")"
  jq --null-input \
    --arg schema_version "$inventory_schema" \
    --arg release_tag "$release_tag" \
    --arg source_revision "$expected_commit" \
    --arg flake_ref "$flake_ref" \
    --arg unsigned_artifacts "$unsigned_artifacts" \
    --arg release_intent "$release_intent" \
    --arg boot_plan "$boot_plan" \
    --arg eeprom_plan "$eeprom_plan" \
    --arg release_review "$release_review" \
    --arg signing_package "$signing_package" \
    --arg signing_package_nar_hash "$signing_package_nar_hash" \
    --arg deployment "$deployment" \
    --arg deployment_nar_hash "$deployment_nar_hash" \
    --arg approval_tool "$approval_tool" \
    --arg receipts_tool "$receipts_tool" \
    '{
      schema_version: $schema_version,
      release_tag: $release_tag,
      source_revision: $source_revision,
      flake_ref: $flake_ref,
      paths: {
        unsigned_artifacts: $unsigned_artifacts,
        release_intent: $release_intent,
        boot_signing_plan: $boot_plan,
        eeprom_signing_plan: $eeprom_plan,
        release_review: $release_review,
        signing_package: $signing_package,
        ubuntu_deployment: $deployment,
        approval_tool: $approval_tool,
        receipts_tool: $receipts_tool
      },
      nar_hashes: {
        signing_package: $signing_package_nar_hash,
        ubuntu_deployment: $deployment_nar_hash
      },
      status: "awaiting_human_review"
    }' > "$inventory_tmp"
  publish_evidence "$inventory_tmp" "$ceremony_dir/public-review-inventory.json"
  jq . "$ceremony_dir/public-review-inventory.json"
  human_stop 'inspect review.json, release-intent.json, both signing plans, signer policy, and the reviewed public-key fingerprint before any approval is authored'
}

verify_authorization() {
  local received='' expected_approval_hash='' expected_registry_hash=''
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      --received-authorization) received="${2-}"; shift 2 ;;
      --expected-approval-sha256) expected_approval_hash="${2-}"; shift 2 ;;
      --expected-registry-sha256) expected_registry_hash="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$ceremony_dir" && -n "$received" && -n "$expected_approval_hash" && -n "$expected_registry_hash" ]] || { usage; exit 2; }
  load_session "$ceremony_dir"
  resolve_public_paths
  require_private_directory 'received authorization directory' "$received"
  require_hex 'expected approval SHA-256' "$expected_approval_hash" '64'
  require_hex 'expected registry SHA-256' "$expected_registry_hash" '64'

  local received_store received_store_nar_hash authorization_gc_root
  received_store="$(nix store add-path "$received")"
  [[ "$received_store" == /nix/store/* && -d "$received_store" && ! -L "$received_store" ]] ||
    fail 'received authorization did not import as an immutable Nix-store directory'
  nix-store --verify-path "$received_store"
  received_store_nar_hash="$(nix-store --query --hash "$received_store")"
  received="$received_store"

  local approval="$received/approval.json"
  local registry="$received/signing-grants.json"
  local checksum_file="$received/SHA256SUMS"
  require_regular_file 'received approval' "$approval"
  require_regular_file 'received registry' "$registry"
  require_regular_file 'received checksum file' "$checksum_file"
  local entries
  entries="$(find "$received" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  [[ "$entries" == $'SHA256SUMS\napproval.json\nsigning-grants.json' ]] ||
    fail 'received authorization directory must contain exactly the two records and SHA256SUMS'
  mapfile -t checksum_lines < "$checksum_file"
  ((${#checksum_lines[@]} == 2)) || fail 'received checksum file must contain exactly two entries'
  [[ "${checksum_lines[0]}" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]approval\.json$ ]] || fail 'approval checksum entry is not canonical'
  [[ "${checksum_lines[1]}" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]signing-grants\.json$ ]] || fail 'registry checksum entry is not canonical'
  (
    cd "$received"
    sha256sum --check --strict SHA256SUMS
  )

  local actual_approval_hash actual_registry_hash
  actual_approval_hash="$(sha256sum "$approval" | cut -d ' ' -f 1)"
  actual_registry_hash="$(sha256sum "$registry" | cut -d ' ' -f 1)"
  [[ "$actual_approval_hash" == "$expected_approval_hash" ]] || fail 'approval differs from the independently communicated digest'
  [[ "$actual_registry_hash" == "$expected_registry_hash" ]] || fail 'registry differs from the independently communicated digest'
  "$approval_tool/bin/kaiba-provision-signing-approval" validate \
    --release-intent "$release_intent/release-intent.json" \
    --approval "$approval" \
    --registry "$registry"

  local approved_at expires_at now_epoch approved_epoch expires_epoch
  approved_at="$(jq --exit-status --raw-output '.approved_at' "$approval")"
  expires_at="$(jq --exit-status --raw-output '.expires_at' "$approval")"
  now_epoch="$(date --utc +%s)"
  approved_epoch="$(date --utc --date="$approved_at" +%s)"
  expires_epoch="$(date --utc --date="$expires_at" +%s)"
  ((now_epoch >= approved_epoch)) || fail 'approval lower bound has not arrived on this host clock'
  ((now_epoch < expires_epoch)) || fail 'approval has expired on this host clock'
  authorization_gc_root="$(register_store_gc_root \
    "$(store_gc_root_label authorization-snapshot "$received_store")" \
    "$received_store")"

  local evidence_tmp
  evidence_tmp="$(mktemp "$ceremony_dir/.authorization-verification.XXXXXX")"
  jq --null-input \
    --arg schema_version "$authorization_schema" \
    --arg source_revision "$expected_commit" \
    --arg authorization_store "$received_store" \
    --arg authorization_store_nar_hash "$received_store_nar_hash" \
    --arg authorization_gc_root "$authorization_gc_root" \
    --arg approval_sha256 "$actual_approval_hash" \
    --arg registry_sha256 "$actual_registry_hash" \
    --arg approval_id "$(jq --exit-status --raw-output '.approval_id' "$approval")" \
    --arg approval_digest "$(jq --exit-status --raw-output '.approval_digest' "$approval")" \
    --arg release_intent_digest "$(jq --exit-status --raw-output '.release_intent_digest' "$approval")" \
    --arg approved_at "$approved_at" \
    --arg expires_at "$expires_at" \
    '{
      schema_version: $schema_version,
      source_revision: $source_revision,
      authorization_store: $authorization_store,
      authorization_store_nar_hash: $authorization_store_nar_hash,
      authorization_gc_root: $authorization_gc_root,
      approval_sha256: $approval_sha256,
      registry_sha256: $registry_sha256,
      approval_id: $approval_id,
      approval_digest: $approval_digest,
      release_intent_digest: $release_intent_digest,
      approved_at: $approved_at,
      expires_at: $expires_at,
      status: "valid"
    }' > "$evidence_tmp"
  publish_evidence "$evidence_tmp" "$ceremony_dir/authorization-verification.json"
  jq . "$ceremony_dir/authorization-verification.json"
  human_stop 'a root operator must separately review authority rotation, install the registry, disable swap, provision the PIN, verify token custody, and explicitly start the gate'
}

validate_owned_recovery_plan_contract() {
  local plan_file="$1"
  jq --exit-status \
    --arg release_intent_digest "$(jq --exit-status --raw-output '.release_intent_digest' "$release_review/review.json")" \
    --arg fresh_plan_id "$(jq --exit-status --raw-output '.plan_id' "$eeprom_plan/plan.json")" '
      .schema_version == "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1"
      and .fresh_eeprom_plan.release_intent_digest == $release_intent_digest
      and .fresh_eeprom_result.release_intent_digest == $release_intent_digest
      and .plan_id == ($fresh_plan_id + ":owned-recovery")
      and .fresh_eeprom_plan.plan_id == $fresh_plan_id
      and .fresh_eeprom_result.plan_id == $fresh_plan_id
      and .updater_mode == "owned-recovery"
      and .updater_flags == ["-f", "-r"]
      and ([.fresh_eeprom_result.signatures[].role]) == [
        "rpi5.eeprom_bootcode",
        "rpi5.eeprom_bootsys",
        "rpi5.eeprom_config"
      ]
      and .owned_recovery_signing_input.role == "rpi5.owned_recovery_bootcode"
    ' "$plan_file" >/dev/null || fail 'derived owned-recovery plan violates the fixed phase transition'
}

validate_owned_recovery_plan() {
  local plan="$1"
  [[ "$plan" == /nix/store/* && -d "$plan" && ! -L "$plan" ]] ||
    fail 'owned-recovery plan must be an immutable Nix-store directory'
  nix-store --verify-path "$plan"
  require_regular_file 'owned-recovery plan' "$plan/plan.json"
  validate_owned_recovery_plan_contract "$plan/plan.json"
}

derive_owned_recovery() {
  local eeprom_store=''
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      --eeprom-signed-store) eeprom_store="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$ceremony_dir" && -n "$eeprom_store" ]] || { usage; exit 2; }
  load_session "$ceremony_dir"
  resolve_public_paths
  [[ "$eeprom_store" == /nix/store/* && -d "$eeprom_store" && ! -L "$eeprom_store" ]] ||
    fail 'EEPROM signed result must be an existing Nix-store directory'
  nix-store --verify-path "$eeprom_store"
  local link="$ceremony_dir/public/owned-recovery-plan"
  local receipt="$ceremony_dir/owned-recovery-plan-review-input.json"
  local flake_literal store_literal expression
  flake_literal="$(jq --null-input --arg value "$flake_ref" '$value')"
  store_literal="$(jq --null-input --arg value "$eeprom_store" '$value')"
  expression="let kaiba = builtins.getFlake $flake_literal; in (kaiba.lib.mkRpi5PrototypeOwnedRecoveryPlan { eepromSignedOutput = builtins.storePath $store_literal; }).ownedRecoverySigningPlan"
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    require_regular_file 'owned-recovery review input' "$receipt"
    [[ -L "$link" ]] || fail 'owned-recovery review input exists without its result link'
    local existing_plan expected_plan
    existing_plan="$(readlink -e -- "$link")"
    expected_plan="$(nix --accept-flake-config build --impure \
      --no-link --print-out-paths --expr "$expression")"
    [[ -n "$expected_plan" && "$expected_plan" != *$'\n'* && "$expected_plan" == /nix/store/* ]] ||
      fail 'owned-recovery fixed expression returned an unexpected output set'
    [[ "$existing_plan" == "$expected_plan" ]] ||
      fail 'existing owned-recovery plan differs from the fixed phase-transition expression'
    validate_owned_recovery_plan "$existing_plan"
    jq --exit-status \
      --arg schema "$owned_plan_schema" \
      --arg revision "$expected_commit" \
      --arg eeprom "$eeprom_store" \
      --arg plan "$existing_plan" \
      --arg plan_sha256 "$(sha256sum "$existing_plan/plan.json" | cut -d ' ' -f 1)" \
      --arg release_intent_digest "$(jq --exit-status --raw-output '.fresh_eeprom_plan.release_intent_digest' "$existing_plan/plan.json")" '
        .schema_version == $schema
        and .source_revision == $revision
        and .eeprom_signed_store == $eeprom
        and .plan == $plan
        and .plan_sha256 == $plan_sha256
        and .release_intent_digest == $release_intent_digest
        and .remaining_role == "rpi5.owned_recovery_bootcode"
        and .status == "awaiting_human_review"
      ' "$receipt" >/dev/null || fail 'existing owned-recovery review input binds different inputs'
    jq . "$existing_plan/plan.json"
    human_stop 'review the existing derived plan before separately invoking sign-owned-recovery; never auto-retry a signing request'
    return
  fi
  local plan
  if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" ]] || fail 'owned-recovery plan result path is not a symlink'
    local expected_plan
    expected_plan="$(nix --accept-flake-config build --impure \
      --no-link --print-out-paths --expr "$expression")"
    [[ -n "$expected_plan" && "$expected_plan" != *$'\n'* && "$expected_plan" == /nix/store/* ]] ||
      fail 'owned-recovery fixed expression returned an unexpected output set'
    plan="$(readlink -e -- "$link")"
    [[ "$plan" == "$expected_plan" ]] ||
      fail 'interrupted owned-recovery result differs from the fixed phase-transition expression'
  else
    local attempt=1 log log_tmp
    while [[ -e "$ceremony_dir/logs/owned-recovery-plan.attempt-$attempt.log" ||
      -L "$ceremony_dir/logs/owned-recovery-plan.attempt-$attempt.log" ]]; do
      attempt=$((attempt + 1))
    done
    log="$ceremony_dir/logs/owned-recovery-plan.attempt-$attempt.log"
    log_tmp="$(mktemp "$ceremony_dir/logs/.owned-recovery-plan.attempt-$attempt.XXXXXX")"
    local build_status log_status
    local -a pipeline_status
    set +e
    nix --accept-flake-config build -L --impure \
      --out-link "$link" --expr "$expression" 2>&1 | tee "$log_tmp"
    pipeline_status=("${PIPESTATUS[@]}")
    set -e
    build_status="${pipeline_status[0]}"
    log_status="${pipeline_status[1]}"
    publish_evidence "$log_tmp" "$log"
    if ((log_status != 0)); then
      fail "owned-recovery plan audit-log write failed with status $log_status; preserve the output and do not advance"
    fi
    if ((build_status != 0)); then
      fail "owned-recovery plan derivation failed with status $build_status; do not submit another signing request"
    fi
    plan="$(readlink -e -- "$link")"
  fi
  validate_owned_recovery_plan "$plan"
  local receipt_tmp
  receipt_tmp="$(mktemp "$ceremony_dir/.owned-recovery-plan-review-input.XXXXXX")"
  jq --null-input \
    --arg schema_version "$owned_plan_schema" \
    --arg source_revision "$expected_commit" \
    --arg eeprom_signed_store "$eeprom_store" \
    --arg plan "$plan" \
    --arg plan_sha256 "$(sha256sum "$plan/plan.json" | cut -d ' ' -f 1)" \
    --arg release_intent_digest "$(jq --exit-status --raw-output '.fresh_eeprom_plan.release_intent_digest' "$plan/plan.json")" \
    '{
      schema_version: $schema_version,
      source_revision: $source_revision,
      eeprom_signed_store: $eeprom_signed_store,
      plan: $plan,
      plan_sha256: $plan_sha256,
      release_intent_digest: $release_intent_digest,
      remaining_role: "rpi5.owned_recovery_bootcode",
      status: "awaiting_human_review"
    }' > "$receipt_tmp"
  publish_evidence "$receipt_tmp" "$ceremony_dir/owned-recovery-plan-review-input.json"
  jq . "$plan/plan.json"
  human_stop 'review the derived plan and its single remaining role before separately invoking sign-owned-recovery; never auto-retry a signing request'
}

require_handoff_shape() {
  local handoff="$1"
  local top_entries unsupported
  top_entries="$(find "$handoff" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  [[ "$top_entries" == $'approval.json\nboot-signed\neeprom-signed\nlive-result-receipt-digests.txt\nowned-recovery-signed\nrelease-intent.json\nsigning-grants.json\nsigning-receipts.json' ]] ||
    fail 'handoff has an unexpected top-level entry set'
  local directory_entry file_entry
  for directory_entry in boot-signed eeprom-signed owned-recovery-signed; do
    [[ -d "$handoff/$directory_entry" && ! -L "$handoff/$directory_entry" ]] ||
      fail "$directory_entry handoff entry must be a non-symlink directory"
  done
  for file_entry in \
    approval.json \
    live-result-receipt-digests.txt \
    release-intent.json \
    signing-grants.json \
    signing-receipts.json; do
    [[ -f "$handoff/$file_entry" && ! -L "$handoff/$file_entry" ]] ||
      fail "$file_entry handoff entry must be a regular non-symlink file"
  done
  unsupported="$(find "$handoff" -mindepth 1 ! -type d ! -type f -print -quit)"
  [[ -z "$unsupported" ]] || fail 'handoff contains a symbolic link or special file'
}

write_handoff_manifest() {
  local handoff="$1"
  local destination="$2"
  (
    cd "$handoff"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
  ) > "$destination"
}

validate_signed_release() {
  local signed_release="$1"
  [[ "$signed_release" == /nix/store/* && -d "$signed_release" && ! -L "$signed_release" ]] ||
    fail 'signed release must be an immutable Nix-store directory'
  nix-store --verify-path "$signed_release"
  local entries
  entries="$(find "$signed_release" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  [[ "$entries" == $'manifests\nobjects\npublication-digest\npublication.json\nrecords\ntree-records\ntrees' ]] ||
    fail 'signed release has an unexpected top-level entry set'
  require_regular_file 'signed-release publication' "$signed_release/publication.json"
  require_regular_file 'signed-release publication digest' "$signed_release/publication-digest"
  jq --exit-status --arg revision "$expected_commit" '
    .schema_version == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
    and .source_revision == $revision
    and (.artifacts | length == 18)
    and (.records | length == 9)
  ' "$signed_release/publication.json" >/dev/null || fail 'signed release violates the eighteen-role/nine-record publication contract'
  local publication_digest
  publication_digest="$(tr -d '\n' < "$signed_release/publication-digest")"
  [[ "$publication_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'signed-release publication digest is malformed'
  printf '%s\n' "$publication_digest"
}

publish_signed_release_summary() {
  local signed_release="$1"
  local publication_digest="$2"
  local summary_tmp
  summary_tmp="$(mktemp "$ceremony_dir/.signed-release-summary.XXXXXX")"
  jq --null-input \
    --arg schema_version "$assembly_schema" \
    --arg release_tag "$release_tag" \
    --arg source_revision "$expected_commit" \
    --arg signed_release "$signed_release" \
    --arg publication_digest "$publication_digest" \
    '{
      schema_version: $schema_version,
      release_tag: $release_tag,
      source_revision: $source_revision,
      signed_release: $signed_release,
      publication_digest: $publication_digest,
      artifact_role_count: 18,
      lineage_record_count: 9,
      status: "passed"
    }' > "$summary_tmp"
  publish_evidence "$summary_tmp" "$ceremony_dir/signed-release-summary.json"
}

verify_handoff() {
  local handoff='' manifest='' expected_manifest_hash=''
  local expected_approval_hash='' expected_registry_hash=''
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      --handoff-dir) handoff="${2-}"; shift 2 ;;
      --checksum-manifest) manifest="${2-}"; shift 2 ;;
      --expected-manifest-sha256) expected_manifest_hash="${2-}"; shift 2 ;;
      --expected-approval-sha256) expected_approval_hash="${2-}"; shift 2 ;;
      --expected-registry-sha256) expected_registry_hash="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$ceremony_dir" && -n "$handoff" && -n "$manifest" &&
    -n "$expected_manifest_hash" && -n "$expected_approval_hash" &&
    -n "$expected_registry_hash" ]] || { usage; exit 2; }
  load_session "$ceremony_dir"
  resolve_public_paths
  require_private_directory 'handoff directory' "$handoff"
  require_regular_file 'handoff checksum manifest' "$manifest"
  require_hex 'expected handoff-manifest SHA-256' "$expected_manifest_hash" '64'
  require_hex 'expected approval SHA-256' "$expected_approval_hash" '64'
  require_hex 'expected registry SHA-256' "$expected_registry_hash" '64'
  local authenticated_manifest_tmp
  authenticated_manifest_tmp="$(mktemp "$ceremony_dir/.authenticated-handoff-manifest.XXXXXX")"
  cp -- "$manifest" "$authenticated_manifest_tmp"
  require_regular_file 'copied handoff checksum manifest' "$authenticated_manifest_tmp"
  [[ "$(sha256sum "$authenticated_manifest_tmp" | cut -d ' ' -f 1)" == "$expected_manifest_hash" ]] ||
    fail 'handoff checksum manifest differs from the independently communicated digest'

  require_handoff_shape "$handoff"
  local handoff_store handoff_store_nar_hash handoff_gc_root
  handoff_store="$(nix store add-path "$handoff")"
  [[ "$handoff_store" == /nix/store/* && -d "$handoff_store" && ! -L "$handoff_store" ]] ||
    fail 'handoff did not import as an immutable Nix-store directory'
  nix-store --verify-path "$handoff_store"
  handoff_store_nar_hash="$(nix-store --query --hash "$handoff_store")"
  handoff="$handoff_store"
  require_handoff_shape "$handoff"
  local recomputed
  recomputed="$(mktemp "$ceremony_dir/.handoff-manifest.XXXXXX")"
  write_handoff_manifest "$handoff" "$recomputed"
  if ! cmp -- "$recomputed" "$authenticated_manifest_tmp"; then
    rm -f -- "$recomputed"
    fail 'handoff bytes or canonical file list do not match the authenticated manifest'
  fi
  rm -f -- "$recomputed"
  cmp -- "$handoff/release-intent.json" "$release_intent/release-intent.json"
  local actual_approval_hash actual_registry_hash
  actual_approval_hash="$(sha256sum "$handoff/approval.json" | cut -d ' ' -f 1)"
  actual_registry_hash="$(sha256sum "$handoff/signing-grants.json" | cut -d ' ' -f 1)"
  [[ "$actual_approval_hash" == "$expected_approval_hash" ]] ||
    fail 'handoff approval differs from the independently authenticated reviewer digest'
  [[ "$actual_registry_hash" == "$expected_registry_hash" ]] ||
    fail 'handoff registry differs from the independently authenticated reviewer digest'
  "$approval_tool/bin/kaiba-provision-signing-approval" validate \
    --release-intent "$release_intent/release-intent.json" \
    --approval "$handoff/approval.json" \
    --registry "$handoff/signing-grants.json"

  mapfile -t receipt_digests < "$handoff/live-result-receipt-digests.txt"
  ((${#receipt_digests[@]} == 5)) || fail 'handoff must contain exactly five independently captured receipt digests'
  [[ "$(printf '%s\n' "${receipt_digests[@]}" | LC_ALL=C sort -u | wc -l)" -eq 5 ]] ||
    fail 'handoff receipt digests must be unique'
  local digest
  for digest in "${receipt_digests[@]}"; do
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'handoff contains a malformed receipt digest'
  done

  local verification="$ceremony_dir/offline-receipt-verification.json"
  local verification_tmp
  verification_tmp="$(mktemp "$ceremony_dir/.offline-receipt-verification.XXXXXX")"
  "$receipts_tool/bin/kaiba-provision-signing-receipts" verify \
    --export "$handoff/signing-receipts.json" \
    --registry "$handoff/signing-grants.json" \
    --public-key "$boot_plan/public.pem" \
    --expected-receipt-digest "${receipt_digests[0]}" \
    --expected-receipt-digest "${receipt_digests[1]}" \
    --expected-receipt-digest "${receipt_digests[2]}" \
    --expected-receipt-digest "${receipt_digests[3]}" \
    --expected-receipt-digest "${receipt_digests[4]}" \
    > "$verification_tmp"
  jq --exit-status '
    .schema_version == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
    and .status == "valid"
    and (.receipt_digests | length == 5)
    and (.receipt_digests | unique | length == 5)
  ' "$verification_tmp" >/dev/null || fail 'offline receipt verification result is invalid'
  handoff_gc_root="$(register_store_gc_root \
    "$(store_gc_root_label handoff-snapshot "$handoff_store")" \
    "$handoff_store")"
  publish_evidence "$authenticated_manifest_tmp" "$ceremony_dir/handoff-manifest.sha256"
  publish_evidence "$verification_tmp" "$verification"
  local handoff_receipt_tmp
  handoff_receipt_tmp="$(mktemp "$ceremony_dir/.handoff-verification.XXXXXX")"
  jq --null-input \
    --arg schema_version "$handoff_schema" \
    --arg source_revision "$expected_commit" \
    --arg manifest_sha256 "$expected_manifest_hash" \
    --arg handoff_store "$handoff_store" \
    --arg handoff_store_nar_hash "$handoff_store_nar_hash" \
    --arg handoff_gc_root "$handoff_gc_root" \
    --arg approval_sha256 "$actual_approval_hash" \
    --arg registry_sha256 "$actual_registry_hash" \
    --arg release_intent_digest "$(jq --exit-status --raw-output '.release_intent_digest' "$verification")" \
    --arg receipt_export_digest "$(jq --exit-status --raw-output '.export_digest' "$verification")" \
    --arg registry_digest "$(jq --exit-status --raw-output '.registry_digest' "$verification")" \
    '{
      schema_version: $schema_version,
      source_revision: $source_revision,
      manifest_sha256: $manifest_sha256,
      handoff_store: $handoff_store,
      handoff_store_nar_hash: $handoff_store_nar_hash,
      handoff_gc_root: $handoff_gc_root,
      approval_sha256: $approval_sha256,
      registry_sha256: $registry_sha256,
      release_intent_digest: $release_intent_digest,
      receipt_export_digest: $receipt_export_digest,
      registry_digest: $registry_digest,
      receipt_count: 5,
      status: "passed"
    }' > "$handoff_receipt_tmp"
  publish_evidence "$handoff_receipt_tmp" "$ceremony_dir/handoff-verification.json"
  jq . "$verification"
  human_stop 'the independent verifier must review the authenticated packet before invoking the separate assembly phase'
}

assemble_release() {
  local handoff=''
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      --handoff-dir) handoff="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$ceremony_dir" && -n "$handoff" ]] || { usage; exit 2; }
  load_session "$ceremony_dir"
  resolve_public_paths
  require_private_directory 'handoff directory' "$handoff"
  require_regular_file 'authenticated handoff manifest' "$ceremony_dir/handoff-manifest.sha256"
  require_regular_file 'offline receipt verification' "$ceremony_dir/offline-receipt-verification.json"
  require_regular_file 'handoff verification' "$ceremony_dir/handoff-verification.json"
  local verification="$ceremony_dir/offline-receipt-verification.json"
  local handoff_verification="$ceremony_dir/handoff-verification.json"
  local stored_manifest="$ceremony_dir/handoff-manifest.sha256"
  local stored_manifest_hash expected_release_intent_digest verified_handoff_store verified_handoff_store_nar_hash verified_handoff_gc_root
  stored_manifest_hash="$(sha256sum "$stored_manifest" | cut -d ' ' -f 1)"
  expected_release_intent_digest="$(jq --exit-status --raw-output '.release_intent_digest' "$release_review/review.json")"
  verified_handoff_store="$(jq --exit-status --raw-output '.handoff_store' "$handoff_verification")"
  verified_handoff_store_nar_hash="$(jq --exit-status --raw-output '.handoff_store_nar_hash' "$handoff_verification")"
  verified_handoff_gc_root="$(jq --exit-status --raw-output '.handoff_gc_root' "$handoff_verification")"
  [[ "$verified_handoff_store" == /nix/store/* && -d "$verified_handoff_store" && ! -L "$verified_handoff_store" ]] ||
    fail 'handoff verification does not name an existing immutable store snapshot'
  nix-store --verify-path "$verified_handoff_store"
  [[ "$(nix-store --query --hash "$verified_handoff_store")" == "$verified_handoff_store_nar_hash" ]] ||
    fail 'verified handoff store snapshot differs from its recorded NAR hash'
  [[ "$verified_handoff_gc_root" == "$ceremony_dir/gc-roots/$(store_gc_root_label handoff-snapshot "$verified_handoff_store")" ]] ||
    fail 'handoff verification names an unexpected GC root'
  [[ "$(register_store_gc_root \
    "$(store_gc_root_label handoff-snapshot "$verified_handoff_store")" \
    "$verified_handoff_store")" == "$verified_handoff_gc_root" ]] ||
    fail 'handoff snapshot GC-root validation failed'
  local verified_approval_hash verified_registry_hash
  verified_approval_hash="$(jq --exit-status --raw-output '.approval_sha256' "$handoff_verification")"
  verified_registry_hash="$(jq --exit-status --raw-output '.registry_sha256' "$handoff_verification")"
  require_hex 'verified approval SHA-256' "$verified_approval_hash" '64'
  require_hex 'verified registry SHA-256' "$verified_registry_hash" '64'
  [[ "$(sha256sum "$verified_handoff_store/approval.json" | cut -d ' ' -f 1)" == "$verified_approval_hash" ]] ||
    fail 'verified handoff approval differs from its reviewer-authenticated digest'
  [[ "$(sha256sum "$verified_handoff_store/signing-grants.json" | cut -d ' ' -f 1)" == "$verified_registry_hash" ]] ||
    fail 'verified handoff registry differs from its reviewer-authenticated digest'
  jq --exit-status \
    --arg revision "$expected_commit" \
    --arg manifest_sha256 "$stored_manifest_hash" \
    --arg handoff_store "$verified_handoff_store" \
    --arg handoff_store_nar_hash "$verified_handoff_store_nar_hash" \
    --arg handoff_gc_root "$verified_handoff_gc_root" \
    --arg approval_sha256 "$verified_approval_hash" \
    --arg registry_sha256 "$verified_registry_hash" \
    --arg release_intent_digest "$expected_release_intent_digest" \
    --arg receipt_export_digest "$(jq --exit-status --raw-output '.export_digest' "$verification")" \
    --arg registry_digest "$(jq --exit-status --raw-output '.registry_digest' "$verification")" '
      .schema_version == "kaiba.provisioning.development-signing-handoff-verification/v1alpha1"
      and .source_revision == $revision
      and .manifest_sha256 == $manifest_sha256
      and .handoff_store == $handoff_store
      and .handoff_store_nar_hash == $handoff_store_nar_hash
      and .handoff_gc_root == $handoff_gc_root
      and .approval_sha256 == $approval_sha256
      and .registry_sha256 == $registry_sha256
      and .release_intent_digest == $release_intent_digest
      and .receipt_export_digest == $receipt_export_digest
      and .registry_digest == $registry_digest
      and .receipt_count == 5
      and .status == "passed"
    ' "$handoff_verification" >/dev/null || fail 'handoff verification is not bound to the current immutable evidence'
  jq --exit-status \
    --arg release_intent_digest "$expected_release_intent_digest" '
      .schema_version == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
      and .status == "valid"
      and .release_intent_digest == $release_intent_digest
      and (.receipt_digests | length == 5)
      and (.receipt_digests | unique | length == 5)
    ' "$verification" >/dev/null || fail 'offline receipt verification has not passed for this release intent'
  local current_handoff_store
  current_handoff_store="$(nix store add-path "$handoff")"
  [[ "$current_handoff_store" == "$verified_handoff_store" ]] ||
    fail 'handoff changed after independent verification'
  handoff="$verified_handoff_store"
  require_handoff_shape "$handoff"
  local current_manifest
  current_manifest="$(mktemp "$ceremony_dir/.assembly-handoff-manifest.XXXXXX")"
  write_handoff_manifest "$handoff" "$current_manifest"
  if ! cmp -- "$current_manifest" "$stored_manifest"; then
    rm -f -- "$current_manifest"
    fail 'handoff changed after independent verification'
  fi
  rm -f -- "$current_manifest"
  cmp -- "$handoff/release-intent.json" "$release_intent/release-intent.json" ||
    fail 'handoff release intent changed after independent verification'
  if [[ -e "$ceremony_dir/assembly-failure.json" || -L "$ceremony_dir/assembly-failure.json" ]]; then
    require_regular_file 'assembly failure record' "$ceremony_dir/assembly-failure.json"
    fail 'this ceremony has a preserved assembly failure; review and fix code under a new release without repeating these signing requests'
  fi
  local boot_store eeprom_store owned_store registry_store receipt_store
  boot_store="$(nix store add-path "$handoff/boot-signed")"
  eeprom_store="$(nix store add-path "$handoff/eeprom-signed")"
  owned_store="$(nix store add-path "$handoff/owned-recovery-signed")"
  registry_store="$(nix store add-path "$handoff/signing-grants.json")"
  receipt_store="$(nix store add-path "$handoff/signing-receipts.json")"
  local store_path
  for store_path in "$boot_store" "$eeprom_store" "$owned_store" "$registry_store" "$receipt_store"; do
    [[ "$store_path" == /nix/store/* ]] || fail 'a handoff input did not import into the Nix store'
  done
  register_store_gc_root "$(store_gc_root_label assembly-boot "$boot_store")" "$boot_store" >/dev/null
  register_store_gc_root "$(store_gc_root_label assembly-eeprom "$eeprom_store")" "$eeprom_store" >/dev/null
  register_store_gc_root "$(store_gc_root_label assembly-owned-recovery "$owned_store")" "$owned_store" >/dev/null
  register_store_gc_root "$(store_gc_root_label assembly-registry "$registry_store")" "$registry_store" >/dev/null
  register_store_gc_root "$(store_gc_root_label assembly-receipts "$receipt_store")" "$receipt_store" >/dev/null

  local link="$ceremony_dir/public/signed-release"
  local log="$ceremony_dir/logs/signed-release.log"
  local log_tmp
  local flake_literal boot_literal eeprom_literal owned_literal registry_literal receipt_literal expression build_status log_status
  local -a pipeline_status
  flake_literal="$(jq --null-input --arg value "$flake_ref" '$value')"
  boot_literal="$(jq --null-input --arg value "$boot_store" '$value')"
  eeprom_literal="$(jq --null-input --arg value "$eeprom_store" '$value')"
  owned_literal="$(jq --null-input --arg value "$owned_store" '$value')"
  registry_literal="$(jq --null-input --arg value "$registry_store" '$value')"
  receipt_literal="$(jq --null-input --arg value "$receipt_store" '$value')"
  expression="let kaiba = builtins.getFlake $flake_literal; in (kaiba.lib.mkRpi5PrototypeSignedRelease { bootSignedOutput = builtins.storePath $boot_literal; eepromSignedOutput = builtins.storePath $eeprom_literal; ownedRecoverySignedOutput = builtins.storePath $owned_literal; signingGrantRegistry = builtins.storePath $registry_literal; signingReceiptExport = builtins.storePath $receipt_literal; }).release"

  local existing_summary="$ceremony_dir/signed-release-summary.json"
  if [[ -e "$existing_summary" || -L "$existing_summary" ]]; then
    require_regular_file 'signed-release summary' "$existing_summary"
  fi
  if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" ]] || fail 'signed-release result path is not a symlink'
    local expected_release signed_release publication_digest
    expected_release="$(nix --accept-flake-config build --impure \
      --no-link --print-out-paths --expr "$expression")"
    [[ -n "$expected_release" && "$expected_release" != *$'\n'* && "$expected_release" == /nix/store/* ]] ||
      fail 'signed-release fixed expression returned an unexpected output set'
    signed_release="$(readlink -e -- "$link")"
    [[ "$signed_release" == "$expected_release" ]] ||
      fail 'existing signed-release result differs from the fixed release expression'
    publication_digest="$(validate_signed_release "$signed_release")"
    publish_signed_release_summary "$signed_release" "$publication_digest"
    jq . "$existing_summary"
    human_stop 'independently accept and retain the existing publication digest; it does not authorize hardware mutation'
    return
  fi
  [[ ! -e "$existing_summary" && ! -L "$existing_summary" ]] ||
    fail 'signed-release summary exists without its result link'
  [[ ! -e "$log" && ! -L "$log" ]] ||
    fail 'signed-release build log exists without a result link; preserve and review the interrupted attempt'
  log_tmp="$(mktemp "$ceremony_dir/logs/.signed-release.XXXXXX")"

  set +e
  nix --accept-flake-config build -L --impure \
    --out-link "$link" --expr "$expression" 2>&1 | tee "$log_tmp"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  build_status="${pipeline_status[0]}"
  log_status="${pipeline_status[1]}"
  publish_evidence "$log_tmp" "$log"
  if ((build_status != 0 || log_status != 0)); then
    local failure_tmp
    failure_tmp="$(mktemp "$ceremony_dir/.assembly-failure.XXXXXX")"
    jq --null-input \
      --arg schema_version "$assembly_schema" \
      --arg release_tag "$release_tag" \
      --arg source_revision "$expected_commit" \
      --arg build_log "$log" \
      --argjson build_status "$build_status" \
      --argjson log_status "$log_status" \
      '{
        schema_version: $schema_version,
        release_tag: $release_tag,
        source_revision: $source_revision,
        build_log: $build_log,
        build_status: $build_status,
        log_status: $log_status,
        status: "failed_preserve_evidence",
        next_boundary: "code_review_no_signing_retry"
      }' > "$failure_tmp"
    publish_evidence "$failure_tmp" "$ceremony_dir/assembly-failure.json"
    fail "signed-release assembly failed (build status $build_status, log status $log_status); preserve all evidence and do not repeat any signing request"
  fi
  local signed_release publication_digest
  signed_release="$(readlink -e -- "$link")"
  publication_digest="$(validate_signed_release "$signed_release")"
  publish_signed_release_summary "$signed_release" "$publication_digest"
  jq . "$ceremony_dir/signed-release-summary.json"
  human_stop 'independently accept and retain the publication digest; this software result does not authorize NVMe, EEPROM, OTP, JTAG, or other hardware mutation'
}

show_status() {
  ceremony_dir=''
  while (($#)); do
    case "$1" in
      --ceremony-dir) ceremony_dir="${2-}"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ -n "$ceremony_dir" ]] || { usage; exit 2; }
  load_session "$ceremony_dir"
  if [[ -f "$ceremony_dir/authorization-verification.json" &&
    ! -L "$ceremony_dir/authorization-verification.json" ]]; then
    local authorization_store authorization_gc_root
    authorization_store="$(jq --exit-status --raw-output \
      '.authorization_store' "$ceremony_dir/authorization-verification.json")"
    authorization_gc_root="$(jq --exit-status --raw-output \
      '.authorization_gc_root' "$ceremony_dir/authorization-verification.json")"
    [[ "$authorization_gc_root" == "$ceremony_dir/gc-roots/$(store_gc_root_label authorization-snapshot "$authorization_store")" ]] ||
      fail 'authorization verification names an unexpected GC root'
    [[ "$(register_store_gc_root \
      "$(store_gc_root_label authorization-snapshot "$authorization_store")" \
      "$authorization_store")" == "$authorization_gc_root" ]] ||
      fail 'authorization snapshot GC-root validation failed'
  fi
  if [[ -f "$ceremony_dir/handoff-verification.json" &&
    ! -L "$ceremony_dir/handoff-verification.json" ]]; then
    local handoff_store handoff_gc_root
    handoff_store="$(jq --exit-status --raw-output \
      '.handoff_store' "$ceremony_dir/handoff-verification.json")"
    handoff_gc_root="$(jq --exit-status --raw-output \
      '.handoff_gc_root' "$ceremony_dir/handoff-verification.json")"
    [[ "$handoff_gc_root" == "$ceremony_dir/gc-roots/$(store_gc_root_label handoff-snapshot "$handoff_store")" ]] ||
      fail 'handoff verification names an unexpected GC root'
    [[ "$(register_store_gc_root \
      "$(store_gc_root_label handoff-snapshot "$handoff_store")" \
      "$handoff_store")" == "$handoff_gc_root" ]] ||
      fail 'handoff snapshot GC-root validation failed'
  fi
  jq . "$ceremony_dir/ceremony.json"
  if [[ -d "$ceremony_dir/public" && ! -L "$ceremony_dir/public" ]]; then
    find "$ceremony_dir/public" -mindepth 1 -maxdepth 1 -type l \
      -printf '%f -> %l\n' | LC_ALL=C sort
  fi
  find "$ceremony_dir/gc-roots" -mindepth 1 -maxdepth 1 -type l \
    -printf 'GC root: %f -> %l\n' | LC_ALL=C sort
  for evidence in \
    public-review-inventory.json \
    authorization-verification.json \
    owned-recovery-plan-review-input.json \
    handoff-manifest.sha256 \
    offline-receipt-verification.json \
    handoff-verification.json \
    assembly-failure.json \
    signed-release-summary.json; do
    if [[ -f "$ceremony_dir/$evidence" && ! -L "$ceremony_dir/$evidence" ]]; then
      sha256sum "$ceremony_dir/$evidence"
    fi
  done
}

main() {
  (($# > 0)) || { usage; exit 2; }
  local command="$1"
  shift
  case "$command" in
    prepare-public) prepare_public "$@" ;;
    verify-authorization) verify_authorization "$@" ;;
    derive-owned-recovery) derive_owned_recovery "$@" ;;
    verify-handoff) verify_handoff "$@" ;;
    assemble) assemble_release "$@" ;;
    status) show_status "$@" ;;
    --help|-h|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
