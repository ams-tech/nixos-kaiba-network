#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
system_path=/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test_path_override=
test_mode=false
if [[ -n "${KAIBA_AUTHORITY_TEST_PATH:-}" ]]; then
  (( EUID != 0 )) || {
    printf 'authority install: FAIL: test PATH override is forbidden for root\n' >&2
    exit 1
  }
  test_path_override=$KAIBA_AUTHORITY_TEST_PATH
  export PATH="$test_path_override:$system_path"
  unset KAIBA_AUTHORITY_TEST_PATH
  test_mode=true
else
  export PATH=$system_path
fi
readonly system_path test_mode test_path_override
umask 077

readonly CONTROL_SERVICE=kaiba-provisioning-control
readonly AUDIT_SERVICE=kaiba-provisioning-audit
readonly CONFIG_PATH=/etc/kaiba-provisioning/authority-deployment.conf
readonly CREDENTIAL_DIRECTORY=/etc/kaiba-provisioning/authority
readonly GC_ROOT=/nix/var/nix/gcroots/kaiba-ubuntu-provisioning-authority-deployment
readonly ASSET_SUFFIX=/share/kaiba/ubuntu-provisioning-authority
readonly -a SYSTEMD_UNIT_ROOTS=(
  /etc/systemd/system.control
  /run/systemd/system.control
  /run/systemd/transient
  /run/systemd/generator.early
  /etc/systemd/system
  /etc/systemd/system.attached
  /run/systemd/system
  /run/systemd/system.attached
  /run/systemd/generator
  /usr/local/lib/systemd/system
  /usr/lib/systemd/system
  /lib/systemd/system
  /run/systemd/generator.late
)

die() {
  printf 'authority install: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo kaiba-ubuntu-provisioning-authority-install \
    --pki-directory /run/ABSOLUTE_ROOT_OWNED_DEVELOPMENT_PKI_PACKET

Test-only rendering:
  kaiba-ubuntu-provisioning-authority-install \
    --pki-directory ABSOLUTE_DEVELOPMENT_PKI_PACKET \
    --staging-root ABSOLUTE_EMPTY_0700_DIRECTORY

The live installer accepts only a root-owned, ACL-free 0700 PKI snapshot on
tmpfs. It validates and installs the fixed mutual-TLS deployment, does not
enable or start either service, and does not create authority state.
EOF
}

pki_directory=
staging_root=
while (( $# > 0 )); do
  case "$1" in
    --pki-directory)
      (( $# >= 2 )) || die "--pki-directory requires a value"
      pki_directory=$2
      shift 2
      ;;
    --staging-root)
      (( $# >= 2 )) || die "--staging-root requires a value"
      staging_root=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$pki_directory" ]] || die "--pki-directory is required"
[[ "$pki_directory" == /* && "$pki_directory" != / ]] ||
  die "--pki-directory must be an absolute path other than /"
[[ -d "$pki_directory" && ! -L "$pki_directory" ]] ||
  die "PKI packet must be a non-symlink directory"
pki_directory="$(readlink -f -- "$pki_directory")" ||
  die "could not resolve the PKI packet"
[[ "$pki_directory" != / ]] || die "refusing / as the PKI packet"

script_path="$(readlink -f -- "${BASH_SOURCE[0]}" || true)"
[[ -n "$script_path" ]] || die "could not resolve the installer path"
source_directory="$(dirname -- "$script_path")"
[[ -f "$source_directory/deployment.conf" ]] ||
  die "the rendered deployment configuration is absent"

if [[ -n "$staging_root" ]]; then
  (( EUID != 0 )) || die "--staging-root must be run as a non-root user"
  [[ "$staging_root" == /* && "$staging_root" != / ]] ||
    die "--staging-root must be an absolute path other than /"
  [[ -d "$staging_root" && ! -L "$staging_root" ]] ||
    die "staging root must be a pre-created non-symlink directory"
  staging_root="$(readlink -f -- "$staging_root")" || die "could not resolve staging root"
  [[ "$(stat -c %u -- "$staging_root")" == "$EUID" ]] ||
    die "staging root must be owned by the caller"
  [[ "$(stat -c %a -- "$staging_root")" == 700 ]] ||
    die "staging root must have mode 0700"
  for command_name in getfacl grep; do
    command -v "$command_name" >/dev/null 2>&1 ||
      die "required staging command is unavailable: $command_name"
  done
  staging_root_acl="$(getfacl --absolute-names --numeric --omit-header \
    "$staging_root" 2>/dev/null)" || die "could not inspect the staging root ACL"
  if grep -Eq '^(user:[^:]+:|group:[^:]+:|mask::|default:)' <<<"$staging_root_acl"; then
    die "staging root must not have an extended or default ACL"
  fi
  [[ -z "$(find "$staging_root" -mindepth 1 -print -quit)" ]] ||
    die "staging root must be empty"
else
  (( EUID == 0 )) || die "live installation must run as root"
  [[ "$source_directory" =~ ^/nix/store/[0-9a-z]{32}-[^/[:space:]]+$ASSET_SUFFIX$ ]] ||
    die "live installation must run from the immutable Nix deployment bundle"
  [[ "$(stat -c %u -- "$source_directory")" == 0 ]] ||
    die "deployment source must be root-owned"
fi

for command_name in awk cmp find getfacl grep openssl readlink sed sha256sum sort stat systemctl tr; do
  if [[ -n "$staging_root" && "$command_name" == systemctl ]]; then
    continue
  fi
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command is unavailable: $command_name"
done

config_value() {
  local key=$1 count value
  count="$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' \
    "$source_directory/deployment.conf")"
  [[ "$count" == 1 ]] || die "deployment configuration must contain exactly one $key"
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' \
    "$source_directory/deployment.conf")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || die "invalid $key value"
  printf '%s\n' "$value"
}

deployment_path="$(config_value DEPLOYMENT_PATH)"
control_package="$(config_value CONTROL_PACKAGE)"
audit_package="$(config_value AUDIT_PACKAGE)"
listen_address="$(config_value LISTEN_ADDRESS)"
station_uri="$(config_value STATION_URI)"
approver_uri="$(config_value APPROVER_URI)"

if [[ -z "$staging_root" ]]; then
  for command_name in findmnt nix-store systemd; do
    command -v "$command_name" >/dev/null 2>&1 ||
      die "required live-host command is unavailable: $command_name"
  done
  # /etc/os-release is an operating-system-owned shell fragment on Ubuntu.
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID-}" == ubuntu && "${VERSION_ID-}" == 24.04 ]] ||
    die "this deployment bundle requires Ubuntu 24.04"
  systemd_version="$(systemd --version | awk 'NR == 1 { print $2 }')"
  [[ "$systemd_version" =~ ^[0-9]+$ ]] || die "could not determine the systemd version"
  (( systemd_version >= 255 )) || die "systemd 255 or newer is required"
  [[ "$pki_directory" == /run/* ]] ||
    die "live PKI packet must be a root-owned snapshot beneath /run"
  [[ "$(findmnt --noheadings --output FSTYPE --target "$pki_directory")" == tmpfs ]] ||
    die "live PKI packet must be backed by tmpfs"
fi

[[ "$deployment_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "deployment path is not one canonical Nix store path"
[[ "$control_package" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "control package is not one canonical Nix store path"
[[ "$audit_package" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "audit package is not one canonical Nix store path"
[[ -x "$control_package/bin/kaiba-provision-control" ]] ||
  die "the exact control binary is unavailable"
[[ -x "$audit_package/bin/kaiba-provision-audit" ]] ||
  die "the exact audit binary is unavailable"
[[ "$source_directory" == "$deployment_path$ASSET_SUFFIX" ]] ||
  die "deployment configuration does not bind this immutable bundle"

expected_owner="$EUID:$(id -g)"
if [[ -z "$staging_root" ]]; then
  expected_owner=0:0
fi

assert_acl_free() {
  local acl path=$1
  acl="$(getfacl --absolute-names --numeric --omit-header "$path" 2>/dev/null)" ||
    die "could not inspect ACL for $path"
  if grep -Eq '^(user:[^:]+:|group:[^:]+:|mask::|default:)' <<<"$acl"; then
    die "$path must not have an extended or default ACL"
  fi
}

assert_directory() {
  local path=$1 expected_mode=$2
  [[ -d "$path" && ! -L "$path" ]] || die "$path must be a non-symlink directory"
  [[ "$(stat -c %a -- "$path")" == "$expected_mode" ]] ||
    die "$path must have mode 0$expected_mode"
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_owner" ]] ||
    die "$path has unexpected ownership"
  assert_acl_free "$path"
}

assert_file() {
  local path=$1 expected_mode=$2
  [[ -f "$path" && ! -L "$path" ]] || die "$path must be a regular non-symlink file"
  [[ "$(stat -c %a -- "$path")" == "$expected_mode" ]] ||
    die "$path must have mode 0$expected_mode"
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_owner" ]] ||
    die "$path has unexpected ownership"
  [[ "$(stat -c %h -- "$path")" == 1 ]] || die "$path must have exactly one hard link"
  assert_acl_free "$path"
}

assert_directory "$pki_directory" 700
assert_directory "$pki_directory/authority" 700
assert_directory "$pki_directory/station" 700
assert_directory "$pki_directory/station/bridge" 700
assert_directory "$pki_directory/station/lane-workflow" 700
assert_directory "$pki_directory/approver" 700
assert_file "$pki_directory/manifest.conf" 444
assert_file "$pki_directory/SHA256SUMS" 444

expected_directories="$(printf '%s\n' \
  approver \
  authority \
  station \
  station/bridge \
  station/lane-workflow)"
observed_directories="$(
  cd "$pki_directory"
  find . -mindepth 1 -type d -printf '%P\n' | sort
)"
[[ "$observed_directories" == "$expected_directories" ]] ||
  die "PKI packet directory set is not exact"

expected_files="$(printf '%s\n' \
  SHA256SUMS \
  approver/SHA256SUMS \
  approver/audit-server-ca.crt \
  approver/client.crt \
  approver/client.key \
  approver/control-server-ca.crt \
  authority/audit-server-ca.crt \
  authority/audit-server.crt \
  authority/audit-server.key \
  authority/client-ca.crt \
  authority/control-server-ca.crt \
  authority/control-server.crt \
  authority/control-server.key \
  manifest.conf \
  station/bridge/SHA256SUMS \
  station/bridge/audit-server-ca.crt \
  station/bridge/control-server-ca.crt \
  station/bridge/station-client.crt \
  station/bridge/station-client.key \
  station/lane-workflow/SHA256SUMS \
  station/lane-workflow/audit-server-ca.crt \
  station/lane-workflow/control-server-ca.crt \
  station/lane-workflow/station-client.crt \
  station/lane-workflow/station-client.key)"
observed_files="$(
  cd "$pki_directory"
  find . -type f -printf '%P\n' | sort
)"
[[ "$observed_files" == "$expected_files" ]] || die "PKI packet file set is not exact"
[[ -z "$(find "$pki_directory" \( -type l -o \( ! -type d ! -type f \) \) -print -quit)" ]] ||
  die "PKI packet contains an unsupported filesystem object"

assert_canonical_single_certificate_pem() {
  local path=$1
  # openssl x509 consumes the first parseable certificate. Comparing its
  # canonical PEM rendering with the complete input rejects a second block,
  # CRLF-smuggled boundaries, comments, and trailing data that a trust-pool
  # parser could otherwise accept.
  openssl x509 -in "$path" -outform PEM |
    cmp --silent - "$path" ||
    die "$path must contain exactly one canonical PEM certificate and no other data"
}

for checksum_manifest in \
  approver/SHA256SUMS \
  station/bridge/SHA256SUMS \
  station/lane-workflow/SHA256SUMS; do
  assert_file "$pki_directory/$checksum_manifest" 444
done
for public_file in \
  authority/control-server-ca.crt authority/control-server.crt \
  authority/audit-server-ca.crt authority/audit-server.crt authority/client-ca.crt \
  station/bridge/control-server-ca.crt station/bridge/audit-server-ca.crt \
  station/bridge/station-client.crt \
  station/lane-workflow/control-server-ca.crt station/lane-workflow/audit-server-ca.crt \
  station/lane-workflow/station-client.crt \
  approver/control-server-ca.crt approver/audit-server-ca.crt approver/client.crt; do
  assert_file "$pki_directory/$public_file" 444
  assert_canonical_single_certificate_pem "$pki_directory/$public_file"
done
for private_file in \
  authority/control-server.key authority/audit-server.key \
  station/bridge/station-client.key station/lane-workflow/station-client.key \
  approver/client.key; do
  assert_file "$pki_directory/$private_file" 400
done

(
  cd "$pki_directory"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || die "PKI packet checksum verification failed"
for packet in station/bridge station/lane-workflow approver; do
  (
    cd "$pki_directory/$packet"
    sha256sum --check --strict SHA256SUMS >/dev/null
  ) || die "$packet packet checksum verification failed"
done

[[ "$(grep -c '^' "$pki_directory/manifest.conf")" == 9 ]] ||
  die "PKI packet manifest has unexpected fields"
grep -Fxq 'SCHEMA_VERSION=kaiba.provisioning.development-authority-pki/v1alpha2' \
  "$pki_directory/manifest.conf" || die "PKI packet schema is wrong"
grep -Fxq "LISTEN_ADDRESS=$listen_address" "$pki_directory/manifest.conf" ||
  die "PKI packet listener is wrong"
grep -Fxq "STATION_URI=$station_uri" "$pki_directory/manifest.conf" ||
  die "PKI packet station identity is wrong"
grep -Fxq "APPROVER_URI=$approver_uri" "$pki_directory/manifest.conf" ||
  die "PKI packet approver identity is wrong"
grep -Fxq 'STATION_CREDENTIAL_KEYS=distinct_bridge_and_lane_workflow' \
  "$pki_directory/manifest.conf" || die "station credential separation is wrong"
grep -Fxq 'CONTROL_SERVER_CA=distinct_ephemeral_unlinked_not_retained' \
  "$pki_directory/manifest.conf" ||
  die "control CA lifecycle is wrong"
grep -Fxq 'AUDIT_SERVER_CA=distinct_ephemeral_unlinked_not_retained' \
  "$pki_directory/manifest.conf" ||
  die "audit CA lifecycle is wrong"
grep -Fxq 'CLIENT_CA=shared_for_exact_role_separated_clients_ephemeral_unlinked_not_retained' \
  "$pki_directory/manifest.conf" || die "client CA lifecycle is wrong"
grep -Fxq 'CA_PRIVATE_KEYS_RETAINED=false' "$pki_directory/manifest.conf" ||
  die "PKI packet retained a CA key"

cmp --silent "$pki_directory/authority/control-server-ca.crt" \
  "$pki_directory/station/bridge/control-server-ca.crt" || die "station bridge control CA differs"
cmp --silent "$pki_directory/authority/control-server-ca.crt" \
  "$pki_directory/station/lane-workflow/control-server-ca.crt" ||
  die "station lane-workflow control CA differs"
cmp --silent "$pki_directory/authority/control-server-ca.crt" \
  "$pki_directory/approver/control-server-ca.crt" || die "approver control CA differs"
cmp --silent "$pki_directory/authority/audit-server-ca.crt" \
  "$pki_directory/station/bridge/audit-server-ca.crt" || die "station bridge audit CA differs"
cmp --silent "$pki_directory/authority/audit-server-ca.crt" \
  "$pki_directory/station/lane-workflow/audit-server-ca.crt" ||
  die "station lane-workflow audit CA differs"
cmp --silent "$pki_directory/authority/audit-server-ca.crt" \
  "$pki_directory/approver/audit-server-ca.crt" || die "approver audit CA differs"

certificate_public_key() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    sha256sum | awk '{ print $1 }'
}

private_public_key() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null |
    sha256sum | awk '{ print $1 }'
}

assert_key_pair() {
  local certificate=$1 private_key=$2
  [[ "$(certificate_public_key "$certificate")" == "$(private_public_key "$private_key")" ]] ||
    die "$certificate and $private_key are not one key pair"
}

control_ca_key="$(certificate_public_key "$pki_directory/authority/control-server-ca.crt")"
audit_ca_key="$(certificate_public_key "$pki_directory/authority/audit-server-ca.crt")"
client_ca_key="$(certificate_public_key "$pki_directory/authority/client-ca.crt")"
[[ "$control_ca_key" != "$audit_ca_key" && "$control_ca_key" != "$client_ca_key" && \
   "$audit_ca_key" != "$client_ca_key" ]] || die "the three PKI trust roots are not distinct"

openssl verify -purpose sslserver \
  -CAfile "$pki_directory/authority/control-server-ca.crt" \
  "$pki_directory/authority/control-server.crt" >/dev/null || die "control certificate is invalid"
openssl verify -purpose sslserver \
  -CAfile "$pki_directory/authority/audit-server-ca.crt" \
  "$pki_directory/authority/audit-server.crt" >/dev/null || die "audit certificate is invalid"
openssl verify -purpose sslclient \
  -CAfile "$pki_directory/authority/client-ca.crt" \
  "$pki_directory/station/bridge/station-client.crt" >/dev/null ||
  die "station bridge certificate is invalid"
openssl verify -purpose sslclient \
  -CAfile "$pki_directory/authority/client-ca.crt" \
  "$pki_directory/station/lane-workflow/station-client.crt" >/dev/null ||
  die "station lane-workflow certificate is invalid"
openssl verify -purpose sslclient \
  -CAfile "$pki_directory/authority/client-ca.crt" \
  "$pki_directory/approver/client.crt" >/dev/null || die "approver certificate is invalid"

certificate_san() {
  openssl x509 -in "$1" -noout -ext subjectAltName |
    sed '1d' | tr -d '[:space:]'
}
[[ "$(certificate_san "$pki_directory/authority/control-server.crt")" == \
   "IPAddress:$listen_address" ]] || die "control server SAN is not exact"
[[ "$(certificate_san "$pki_directory/authority/audit-server.crt")" == \
   "IPAddress:$listen_address" ]] || die "audit server SAN is not exact"
[[ "$(certificate_san "$pki_directory/station/bridge/station-client.crt")" == \
   "URI:$station_uri" ]] || die "station bridge URI SAN is not exact"
[[ "$(certificate_san "$pki_directory/station/lane-workflow/station-client.crt")" == \
   "URI:$station_uri" ]] || die "station lane-workflow URI SAN is not exact"
[[ "$(certificate_san "$pki_directory/approver/client.crt")" == "URI:$approver_uri" ]] ||
  die "approver URI SAN is not exact"

assert_key_pair "$pki_directory/authority/control-server.crt" \
  "$pki_directory/authority/control-server.key"
assert_key_pair "$pki_directory/authority/audit-server.crt" \
  "$pki_directory/authority/audit-server.key"
assert_key_pair "$pki_directory/station/bridge/station-client.crt" \
  "$pki_directory/station/bridge/station-client.key"
assert_key_pair "$pki_directory/station/lane-workflow/station-client.crt" \
  "$pki_directory/station/lane-workflow/station-client.key"
assert_key_pair "$pki_directory/approver/client.crt" "$pki_directory/approver/client.key"

bridge_client_key="$(certificate_public_key \
  "$pki_directory/station/bridge/station-client.crt")"
operator_client_key="$(certificate_public_key \
  "$pki_directory/station/lane-workflow/station-client.crt")"
approver_client_key="$(certificate_public_key "$pki_directory/approver/client.crt")"
[[ "$bridge_client_key" != "$operator_client_key" && \
   "$bridge_client_key" != "$approver_client_key" && \
   "$operator_client_key" != "$approver_client_key" ]] ||
  die "bridge, lane-workflow, and approver client keys must be distinct"

host_path() {
  if [[ -n "$staging_root" ]]; then
    printf '%s%s\n' "$staging_root" "$1"
  else
    printf '%s\n' "$1"
  fi
}

array_contains() {
  local candidate=$1 item
  shift
  for item in "$@"; do
    [[ "$item" == "$candidate" ]] && return 0
  done
  return 1
}

assert_no_service_dropins() {
  local service_name=$1 dropin_name dropin_path unit_root unit_root_on_disk
  for unit_root in "${SYSTEMD_UNIT_ROOTS[@]}"; do
    unit_root_on_disk="$(host_path "$unit_root")"
    for dropin_name in \
      service.d \
      kaiba-.service.d \
      kaiba-provisioning-.service.d \
      "$service_name.service.d"; do
      dropin_path="$unit_root_on_disk/$dropin_name"
      [[ ! -e "$dropin_path" && ! -L "$dropin_path" ]] ||
        die "$service_name.service must not inherit a systemd drop-in: $dropin_path"
    done
  done
}

assert_service_not_enabled_or_aliased() {
  local service_name=$1 alias_name changed dependency_directory entry entry_name target target_name
  local unit_root unit_root_on_disk
  local -a aliases dependency_entries entries
  aliases=("$service_name.service")
  shopt -s nullglob

  changed=true
  while $changed; do
    changed=false
    for unit_root in "${SYSTEMD_UNIT_ROOTS[@]}"; do
      unit_root_on_disk="$(host_path "$unit_root")"
      [[ ! -e "$unit_root_on_disk" && ! -L "$unit_root_on_disk" ]] && continue
      [[ -d "$unit_root_on_disk" && ! -L "$unit_root_on_disk" ]] ||
        die "systemd unit root must be a non-symlink directory: $unit_root_on_disk"
      entries=("$unit_root_on_disk"/*.service)
      for entry in "${entries[@]}"; do
        [[ -L "$entry" ]] || continue
        entry_name="${entry##*/}"
        target="$(readlink -- "$entry")" || die "could not inspect systemd alias $entry"
        target="${target%/}"
        target_name="${target##*/}"
        if array_contains "$target_name" "${aliases[@]}" &&
           ! array_contains "$entry_name" "${aliases[@]}"; then
          aliases+=("$entry_name")
          changed=true
        fi
      done
    done
  done

  if (( ${#aliases[@]} > 1 )); then
    alias_name="${aliases[1]}"
    die "$service_name.service must not have a systemd alias: $alias_name"
  fi

  for unit_root in "${SYSTEMD_UNIT_ROOTS[@]}"; do
    unit_root_on_disk="$(host_path "$unit_root")"
    [[ ! -e "$unit_root_on_disk" && ! -L "$unit_root_on_disk" ]] && continue
    entries=("$unit_root_on_disk"/*.wants "$unit_root_on_disk"/*.requires)
    for dependency_directory in "${entries[@]}"; do
      [[ -d "$dependency_directory" && ! -L "$dependency_directory" ]] ||
        die "systemd dependency path must be a non-symlink directory: $dependency_directory"
      dependency_entries=("$dependency_directory"/*)
      for entry in "${dependency_entries[@]}"; do
        entry_name="${entry##*/}"
        [[ "$entry_name" != "$service_name.service" ]] ||
          die "$service_name.service is enabled through $entry"
        if [[ -L "$entry" ]]; then
          target="$(readlink -- "$entry")" ||
            die "could not inspect systemd enablement link $entry"
          target="${target%/}"
          target_name="${target##*/}"
          [[ "$target_name" != "$service_name.service" ]] ||
            die "$service_name.service is enabled through $entry"
        fi
      done
    done
  done
  shopt -u nullglob
}

unit_directory="$(host_path /etc/systemd/system)"
installed_config="$(host_path "$CONFIG_PATH")"
installed_credentials="$(host_path "$CREDENTIAL_DIRECTORY")"
installed_doc="$(host_path /usr/local/share/doc/kaiba-ubuntu-provisioning-authority/README.md)"
installed_preflight="$(host_path /usr/local/sbin/kaiba-provision-authority-preflight)"
installed_smoke="$(host_path /usr/local/sbin/kaiba-provision-authority-live-smoke)"

for service in "$CONTROL_SERVICE" "$AUDIT_SERVICE"; do
  assert_no_service_dropins "$service"
  assert_service_not_enabled_or_aliased "$service"
done

for target in \
  "$unit_directory/$CONTROL_SERVICE.service" \
  "$unit_directory/$AUDIT_SERVICE.service" \
  "$installed_config" "$installed_credentials" "$installed_doc" \
  "$installed_preflight" "$installed_smoke" \
  "$(host_path /var/lib/kaiba-provision-control)" \
  "$(host_path /var/lib/kaiba-provision-audit)"; do
  [[ ! -e "$target" && ! -L "$target" ]] || die "installation target already exists: $target"
done
if [[ -z "$staging_root" ]]; then
  [[ ! -e "$GC_ROOT" && ! -L "$GC_ROOT" ]] || die "deployment GC root already exists"
fi

if [[ -z "$staging_root" ]]; then
  for service in "$CONTROL_SERVICE.service" "$AUDIT_SERVICE.service"; do
    ! systemctl is-active --quiet "$service" || die "$service is active"
    ! systemctl is-enabled --quiet "$service" || die "$service is enabled"
  done
  nix-store --verify-path "$deployment_path" >/dev/null || die "deployment Nix path failed verification"
  nix-store --verify-path "$control_package" >/dev/null || die "control Nix path failed verification"
  nix-store --verify-path "$audit_package" >/dev/null || die "audit Nix path failed verification"
  nix-store --realise "$deployment_path" --add-root "$GC_ROOT" >/dev/null
fi

ensure_public_directory() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || die "directory path is unsafe: $path"
  else
    install -d -m 0755 "$path"
  fi
}

ensure_public_directory "$unit_directory"
ensure_public_directory "$(dirname -- "$installed_config")"
ensure_public_directory "$(dirname -- "$installed_doc")"
ensure_public_directory "$(dirname -- "$installed_preflight")"
install -d -m 0700 "$installed_credentials"
install -m 0644 "$source_directory/$CONTROL_SERVICE.service" \
  "$unit_directory/$CONTROL_SERVICE.service"
install -m 0644 "$source_directory/$AUDIT_SERVICE.service" \
  "$unit_directory/$AUDIT_SERVICE.service"
install -m 0644 "$source_directory/deployment.conf" "$installed_config"
install -m 0644 "$source_directory/README.md" "$installed_doc"
install -m 0755 "$source_directory/preflight.sh" "$installed_preflight"
install -m 0755 "$source_directory/smoke-test.sh" "$installed_smoke"
install -m 0444 \
  "$pki_directory/authority/control-server-ca.crt" \
  "$pki_directory/authority/control-server.crt" \
  "$pki_directory/authority/audit-server-ca.crt" \
  "$pki_directory/authority/audit-server.crt" \
  "$pki_directory/authority/client-ca.crt" \
  "$installed_credentials/"
install -m 0400 \
  "$pki_directory/authority/control-server.key" \
  "$pki_directory/authority/audit-server.key" \
  "$installed_credentials/"

if [[ -z "$staging_root" ]]; then
  chown -R root:root -- "$installed_credentials"
  chown root:root -- \
    "$unit_directory/$CONTROL_SERVICE.service" \
    "$unit_directory/$AUDIT_SERVICE.service" \
    "$installed_config" "$installed_doc" "$installed_preflight" "$installed_smoke"
  systemctl daemon-reload
  ! systemctl is-active --quiet "$CONTROL_SERVICE.service" || die "control service became active"
  ! systemctl is-active --quiet "$AUDIT_SERVICE.service" || die "audit service became active"
  ! systemctl is-enabled --quiet "$CONTROL_SERVICE.service" || die "control service became enabled"
  ! systemctl is-enabled --quiet "$AUDIT_SERVICE.service" || die "audit service became enabled"
  "$installed_preflight" --static
else
  if $test_mode; then
    KAIBA_AUTHORITY_TEST_PATH="$test_path_override" \
      "$installed_preflight" --staging-root "$staging_root" --static
  else
    "$installed_preflight" --staging-root "$staging_root" --static
  fi
fi

printf 'authority install: OK: deployment is installed disabled and inactive; no service was started\n'
