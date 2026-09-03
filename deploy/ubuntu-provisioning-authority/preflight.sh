#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
system_path=/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [[ -n "${KAIBA_AUTHORITY_TEST_PATH:-}" ]]; then
  (( EUID != 0 )) || {
    printf 'authority preflight: FAIL: test PATH override is forbidden for root\n' >&2
    exit 1
  }
  export PATH="$KAIBA_AUTHORITY_TEST_PATH:$system_path"
  unset KAIBA_AUTHORITY_TEST_PATH
else
  export PATH=$system_path
fi
readonly system_path
umask 077

readonly CONTROL_SERVICE=kaiba-provisioning-control
readonly AUDIT_SERVICE=kaiba-provisioning-audit
readonly CONFIG_PATH=/etc/kaiba-provisioning/authority-deployment.conf
readonly CREDENTIAL_DIRECTORY=/etc/kaiba-provisioning/authority
readonly CONTROL_STATE_DIRECTORY=/var/lib/kaiba-provision-control
readonly AUDIT_STATE_DIRECTORY=/var/lib/kaiba-provision-audit
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
  printf 'authority preflight: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo kaiba-provision-authority-preflight [--static]

Validate the fixed Ubuntu mutual-TLS control/audit deployment without reading
either server private key or opening a network connection. --static also
requires both disabled services to be inactive with no authority state yet.

Test-only staged validation:
  kaiba-provision-authority-preflight \
    --staging-root ABSOLUTE_0700_DIRECTORY --static
EOF
}

static_only=false
staging_root=
while (( $# > 0 )); do
  case "$1" in
    --static)
      static_only=true
      shift
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

if [[ -n "$staging_root" ]]; then
  $static_only || die "--staging-root requires --static"
  (( EUID != 0 )) || die "--staging-root must be run as a non-root user"
  [[ "$staging_root" == /* && "$staging_root" != / ]] ||
    die "staging root must be an absolute path other than /"
  [[ -d "$staging_root" && ! -L "$staging_root" ]] ||
    die "staging root must be a non-symlink directory"
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
else
  (( EUID == 0 )) || die "live-host preflight must run as root"
fi

for command_name in awk cmp find getfacl grep openssl readlink sed sha256sum sort stat systemctl tr; do
  if [[ -n "$staging_root" && "$command_name" == systemctl ]]; then
    continue
  fi
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command is unavailable: $command_name"
done

if [[ -z "$staging_root" ]]; then
  for command_name in nix-store systemd systemd-analyze; do
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
fi

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

installed_config="$(host_path "$CONFIG_PATH")"
installed_credentials="$(host_path "$CREDENTIAL_DIRECTORY")"
unit_directory="$(host_path /etc/systemd/system)"
installed_doc="$(host_path /usr/local/share/doc/kaiba-ubuntu-provisioning-authority/README.md)"
installed_preflight="$(host_path /usr/local/sbin/kaiba-provision-authority-preflight)"
installed_smoke="$(host_path /usr/local/sbin/kaiba-provision-authority-live-smoke)"

for service in "$CONTROL_SERVICE" "$AUDIT_SERVICE"; do
  assert_no_service_dropins "$service"
  assert_service_not_enabled_or_aliased "$service"
done

[[ -f "$installed_config" && ! -L "$installed_config" ]] ||
  die "installed deployment configuration is unavailable"
[[ "$(grep -c '^' "$installed_config")" == 10 ]] ||
  die "installed deployment configuration has unexpected fields"

config_value() {
  local key=$1 count value
  count="$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' \
    "$installed_config")"
  [[ "$count" == 1 ]] || die "installed configuration must contain exactly one $key"
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' \
    "$installed_config")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || die "invalid $key value"
  printf '%s\n' "$value"
}

schema_version="$(config_value SCHEMA_VERSION)"
deployment_path="$(config_value DEPLOYMENT_PATH)"
control_package="$(config_value CONTROL_PACKAGE)"
audit_package="$(config_value AUDIT_PACKAGE)"
listen_address="$(config_value LISTEN_ADDRESS)"
control_port="$(config_value CONTROL_PORT)"
audit_port="$(config_value AUDIT_PORT)"
station_uri="$(config_value STATION_URI)"
approver_uri="$(config_value APPROVER_URI)"
credential_path="$(config_value AUTHORITY_CREDENTIAL_DIRECTORY)"

[[ "$schema_version" == kaiba.provisioning.ubuntu-authority-deployment/v1alpha1 ]] ||
  die "deployment schema is wrong"
[[ "$deployment_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "deployment path is not canonical"
[[ "$control_package" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "control package is not canonical"
[[ "$audit_package" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "audit package is not canonical"
[[ "$listen_address" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] ||
  die "listener is not a concrete IPv4 address"
[[ "$control_port" =~ ^[0-9]+$ && "$audit_port" =~ ^[0-9]+$ && \
   "$control_port" -ge 1 && "$control_port" -le 65535 && \
   "$audit_port" -ge 1 && "$audit_port" -le 65535 && \
   "$control_port" != "$audit_port" ]] || die "authority ports are invalid or equal"
[[ "$station_uri" =~ ^spiffe://kaiba\.network/station/[a-z0-9][a-z0-9._-]*/lane/[a-z0-9][a-z0-9._-]*$ ]] ||
  die "station URI is malformed"
[[ "$approver_uri" =~ ^spiffe://kaiba\.network/approver/[a-z0-9][a-z0-9._-]*$ ]] ||
  die "approver URI is malformed"
[[ "$credential_path" == "$CREDENTIAL_DIRECTORY" ]] || die "credential directory is wrong"

source_directory="$deployment_path$ASSET_SUFFIX"
[[ -d "$source_directory" && ! -L "$source_directory" ]] ||
  die "immutable deployment source is unavailable"
cmp --silent "$source_directory/deployment.conf" "$installed_config" ||
  die "installed deployment configuration differs from the immutable bundle"
cmp --silent "$source_directory/$CONTROL_SERVICE.service" \
  "$unit_directory/$CONTROL_SERVICE.service" || die "installed control unit differs"
cmp --silent "$source_directory/$AUDIT_SERVICE.service" \
  "$unit_directory/$AUDIT_SERVICE.service" || die "installed audit unit differs"
cmp --silent "$source_directory/README.md" "$installed_doc" || die "installed documentation differs"
cmp --silent "$source_directory/preflight.sh" "$installed_preflight" ||
  die "installed preflight differs from the immutable bundle"
cmp --silent "$source_directory/smoke-test.sh" "$installed_smoke" ||
  die "installed live smoke test differs from the immutable bundle"

expected_uid=$EUID
expected_gid="$(id -g)"
if [[ -z "$staging_root" ]]; then
  expected_uid=0
  expected_gid=0
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
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_uid:$expected_gid" ]] ||
    die "$path has unexpected ownership"
  assert_acl_free "$path"
}

assert_file() {
  local path=$1 expected_mode=$2
  [[ -f "$path" && ! -L "$path" ]] || die "$path must be a regular non-symlink file"
  [[ "$(stat -c %a -- "$path")" == "$expected_mode" ]] ||
    die "$path must have mode 0$expected_mode"
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_uid:$expected_gid" ]] ||
    die "$path has unexpected ownership"
  [[ "$(stat -c %h -- "$path")" == 1 ]] || die "$path must have one hard link"
  assert_acl_free "$path"
}

assert_directory "$installed_credentials" 700

credential_parent="$(dirname -- "$installed_credentials")"
[[ -d "$credential_parent" && ! -L "$credential_parent" ]] ||
  die "credential parent directory is unavailable"
[[ "$(stat -c %u:%g -- "$credential_parent")" == "$expected_uid:$expected_gid" ]] ||
  die "credential parent directory has unexpected ownership"
credential_parent_mode="$(stat -c %a -- "$credential_parent")"
(( (8#$credential_parent_mode & 0022) == 0 )) ||
  die "credential parent directory is group- or world-writable"
assert_acl_free "$credential_parent"

expected_credential_files="$(printf '%s\n' \
  audit-server-ca.crt \
  audit-server.crt \
  audit-server.key \
  client-ca.crt \
  control-server-ca.crt \
  control-server.crt \
  control-server.key)"
observed_credential_files="$(
  cd "$installed_credentials"
  find . -mindepth 1 -maxdepth 1 -type f -printf '%P\n' | sort
)"
[[ "$observed_credential_files" == "$expected_credential_files" ]] ||
  die "installed authority credential file set is not exact"
[[ -z "$(find "$installed_credentials" -mindepth 1 \
  \( -type l -o \( ! -type f \) \) -print -quit)" ]] ||
  die "installed authority credential directory contains an unsupported object"

assert_canonical_single_certificate_pem() {
  local path=$1
  openssl x509 -in "$path" -outform PEM |
    cmp --silent - "$path" ||
    die "$path must contain exactly one canonical PEM certificate and no other data"
}

for public_file in \
  control-server-ca.crt control-server.crt audit-server-ca.crt audit-server.crt client-ca.crt; do
  assert_file "$installed_credentials/$public_file" 444
  assert_canonical_single_certificate_pem "$installed_credentials/$public_file"
done
for private_file in control-server.key audit-server.key; do
  # Metadata only: preflight deliberately never opens either private key.
  assert_file "$installed_credentials/$private_file" 400
done
assert_file "$unit_directory/$CONTROL_SERVICE.service" 644
assert_file "$unit_directory/$AUDIT_SERVICE.service" 644
assert_file "$installed_config" 644
assert_file "$installed_doc" 644
assert_file "$installed_preflight" 755
assert_file "$installed_smoke" 755

openssl verify -purpose sslserver \
  -CAfile "$installed_credentials/control-server-ca.crt" \
  "$installed_credentials/control-server.crt" >/dev/null || die "control certificate is invalid"
openssl verify -purpose sslserver \
  -CAfile "$installed_credentials/audit-server-ca.crt" \
  "$installed_credentials/audit-server.crt" >/dev/null || die "audit certificate is invalid"

certificate_san() {
  openssl x509 -in "$1" -noout -ext subjectAltName |
    sed '1d' | tr -d '[:space:]'
}
[[ "$(certificate_san "$installed_credentials/control-server.crt")" == \
   "IPAddress:$listen_address" ]] || die "control server SAN is not exact"
[[ "$(certificate_san "$installed_credentials/audit-server.crt")" == \
   "IPAddress:$listen_address" ]] || die "audit server SAN is not exact"

certificate_public_key() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    sha256sum | awk '{ print $1 }'
}
control_ca_key="$(certificate_public_key "$installed_credentials/control-server-ca.crt")"
audit_ca_key="$(certificate_public_key "$installed_credentials/audit-server-ca.crt")"
client_ca_key="$(certificate_public_key "$installed_credentials/client-ca.crt")"
[[ "$control_ca_key" != "$audit_ca_key" && "$control_ca_key" != "$client_ca_key" && \
   "$audit_ca_key" != "$client_ca_key" ]] || die "authority trust roots are not distinct"

grep -Fxq "ExecStart=$control_package/bin/kaiba-provision-control --listen $listen_address:$control_port --state /var/lib/kaiba-provision-control/control.json --tls-cert %d/server-cert --tls-key %d/server-key --client-ca %d/client-ca" \
  "$unit_directory/$CONTROL_SERVICE.service" || die "control unit command is not exact"
grep -Fxq "ExecStart=$audit_package/bin/kaiba-provision-audit --listen $listen_address:$audit_port --state /var/lib/kaiba-provision-audit/audit.json --tls-cert %d/server-cert --tls-key %d/server-key --client-ca %d/client-ca" \
  "$unit_directory/$AUDIT_SERVICE.service" || die "audit unit command is not exact"
for unit in "$unit_directory/$CONTROL_SERVICE.service" "$unit_directory/$AUDIT_SERVICE.service"; do
  grep -Fxq 'DynamicUser=yes' "$unit" || die "$unit omits DynamicUser"
  grep -Fxq 'StateDirectoryMode=0700' "$unit" || die "$unit has a weak state directory"
  grep -Fxq 'LimitCORE=0' "$unit" || die "$unit permits core dumps"
  grep -Fxq 'NoNewPrivileges=yes' "$unit" || die "$unit omits NoNewPrivileges"
  ! grep -Eq '^(Environment|EnvironmentFile|PassEnvironment|SetCredential)=' "$unit" ||
    die "$unit contains a secret-capable environment or inline credential"
done

if [[ -z "$staging_root" ]]; then
  SYSTEMD_LOG_LEVEL=warning systemd-analyze verify \
    "$unit_directory/$CONTROL_SERVICE.service" \
    "$unit_directory/$AUDIT_SERVICE.service" >/dev/null ||
    die "installed authority units failed systemd-analyze verification"

  [[ "$(readlink -e -- "$GC_ROOT")" == "$deployment_path" ]] ||
    die "deployment GC root is absent or wrong"
  nix-store --verify-path "$deployment_path" >/dev/null || die "deployment Nix path failed verification"
  nix-store --verify-path "$control_package" >/dev/null || die "control Nix path failed verification"
  nix-store --verify-path "$audit_package" >/dev/null || die "audit Nix path failed verification"

  for service in "$CONTROL_SERVICE.service" "$AUDIT_SERVICE.service"; do
    [[ "$(systemctl show "$service" --property=UnitFileState --value)" == disabled ]] ||
      die "$service must remain disabled"
    [[ "$(systemctl show "$service" --property=DropInPaths --value)" == "" ]] ||
      die "$service has an unreviewed systemd drop-in"
    [[ "$(systemctl show "$service" --property=FragmentPath --value)" == \
       "/etc/systemd/system/$service" ]] || die "$service resolves to an unexpected unit"
    [[ "$(systemctl show "$service" --property=NeedDaemonReload --value)" == no ]] ||
      die "$service effective configuration requires a daemon reload"
    [[ "$(systemctl show "$service" --property=LimitCORE --value)" == 0 ]] ||
      die "$service effective hard core-size limit is not zero"
    [[ "$(systemctl show "$service" --property=LimitCORESoft --value)" == 0 ]] ||
      die "$service effective soft core-size limit is not zero"
    if $static_only; then
      [[ "$(systemctl show "$service" --property=ActiveState --value)" == inactive ]] ||
        die "$service is active"
      [[ "$(systemctl show "$service" --property=SubState --value)" == dead ]] ||
        die "$service has a live sub-state"
      [[ "$(systemctl show "$service" --property=MainPID --value)" == 0 ]] ||
        die "$service has a main process"
    fi
  done
fi

if $static_only; then
  [[ ! -e "$(host_path "$CONTROL_STATE_DIRECTORY")" ]] ||
    die "control authority state already exists"
  [[ ! -e "$(host_path "$AUDIT_STATE_DIRECTORY")" ]] ||
    die "audit authority state already exists"
fi

printf 'authority preflight: OK: fixed mutual-TLS deployment is consistent; no private key or network endpoint was accessed\n'
