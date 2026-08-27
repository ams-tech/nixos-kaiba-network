#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
export PATH=/nix/var/nix/profiles/default/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

readonly SERVICE_NAME=kaiba-provision-signing-gate
readonly SERVICE_USER=kaiba-signing
readonly SERVICE_GROUP=kaiba-signing
readonly PIN_DIRECTORY=/run/kaiba-provision-signing-credentials
readonly PIN_SOURCE=/run/kaiba-provision-signing-credentials/yubikey-pin
readonly PIN_CREDENTIAL=/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin
readonly REGISTRY_PATH=/etc/kaiba-provisioning/signing-grants.json
readonly RUNTIME_DIRECTORY=/run/kaiba-provision-signing
readonly STATE_DIRECTORY=/var/lib/kaiba-provision-signing
readonly EXPORT_DIRECTORY=/var/lib/kaiba-provision-signing-exports
readonly SOCKET_PATH=/run/kaiba-provision-signing/signing.sock
readonly GC_ROOT=/nix/var/nix/gcroots/kaiba-provision-signing-gate
readonly DEPLOYMENT_GC_ROOT=/nix/var/nix/gcroots/kaiba-ubuntu-signing-gate-deployment
readonly DEPLOYMENT_ASSET_SUFFIX=/share/kaiba/ubuntu-signing-gate
readonly STAGING_DEPLOYMENT_ASSET_PATH=/usr/local/share/kaiba-ubuntu-signing-gate-validation-source
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
readonly -a SYSTEMD_DROPIN_NAMES=(
  service.d
  kaiba-.service.d
  kaiba-provision-.service.d
  kaiba-provision-signing-.service.d
  kaiba-provision-signing-gate.service.d
)

die() {
  printf 'preflight: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo kaiba-signing-gate-preflight [--static]

Validate the Ubuntu signing-gate deployment without enumerating a smartcard,
opening PC/SC, invoking PKCS#11, submitting a signing request, or reading the
PIN value. --static omits live identity, registry, daemon, credential, and
socket checks, but still validates the PIN-source directory and file metadata.

Test/offline-image use only:
  kaiba-signing-gate-preflight --staging-root /absolute/path --static

A staging root contains its own mutable validation baseline. It is suitable
only for deterministic tests, not deployment or boot. Test mode is non-root
only and requires a caller-owned, ACL-free directory with mode 0700.
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
  $static_only || die "--staging-root may only be used with --static"
  (( EUID != 0 )) || die "--staging-root must be run as a non-root user"
  [[ "$staging_root" == /* && "$staging_root" != / ]] ||
    die "--staging-root must be an absolute path other than /"
  [[ -d "$staging_root" && ! -L "$staging_root" ]] ||
    die "staging root must be a non-symlink directory"
  staging_root="$(readlink -f -- "$staging_root")" ||
    die "could not resolve the staging root"
  [[ "$staging_root" != / ]] || die "refusing to inspect / as a staging root"
  [[ "$(stat -c %u -- "$staging_root")" == "$EUID" ]] ||
    die "staging root must be owned by the non-root caller"
  [[ "$(stat -c %a -- "$staging_root")" == 700 ]] ||
    die "staging root must have private mode 0700"
  for command_name in getfacl grep; do
    command -v "$command_name" >/dev/null 2>&1 ||
      die "required staging command is unavailable: $command_name"
  done
  staging_root_acl="$(getfacl --absolute-names --numeric --omit-header \
    "$staging_root" 2>/dev/null)" ||
    die "could not inspect the staging root ACL"
  if grep -Eq '^(user:[^:]+:|group:[^:]+:|mask::|default:)' <<<"$staging_root_acl"; then
    die "staging root must not have an extended or default ACL"
  fi
else
  (( EUID == 0 )) || die "live-host preflight must run as root"
fi

assert_staging_path_confined() {
  local candidate=$1 component current relative
  local -a components
  [[ -n "$staging_root" ]] || return
  [[ "$candidate" == "$staging_root" || "$candidate" == "$staging_root/"* ]] ||
    die "staging path escapes the staging root: $candidate"
  relative="${candidate#"$staging_root"}"
  current=$staging_root
  IFS=/ read -r -a components <<<"${relative#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      die "staging path contains an unsafe component: $candidate"
    current="$current/$component"
    [[ ! -L "$current" ]] || die "staging path has a symlinked component: $current"
    if [[ "$current" != "$candidate" && -e "$current" ]]; then
      [[ -d "$current" ]] || die "staging path ancestor is not a directory: $current"
    fi
  done
}

host_path() {
  local path=$1 result
  if [[ -n "$staging_root" ]]; then
    result="$staging_root$path"
    assert_staging_path_confined "$result"
    printf '%s\n' "$result"
  else
    printf '%s\n' "$path"
  fi
}

expected_root_uid=0
expected_root_gid=0
if [[ -n "$staging_root" ]]; then
  expected_root_uid=$EUID
  expected_root_gid="$(id -g)"
fi

for command_name in awk cmp getfacl grep id readlink sed stat; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command is unavailable: $command_name"
done
if [[ -z "$staging_root" ]]; then
  for command_name in findmnt getent nix-store; do
    command -v "$command_name" >/dev/null 2>&1 ||
      die "required command is unavailable: $command_name"
  done
fi

expected_registry_gid=$expected_root_gid
if [[ -z "$staging_root" ]]; then
  expected_registry_gid="$(getent group "$SERVICE_GROUP" | cut -d: -f3)" ||
    die "service group does not exist"
fi

assert_regular_file() {
  local expected_gid=$4 expected_mode=$2 expected_uid=$3 path=$1
  [[ -f "$path" && ! -L "$path" ]] || die "$path must be a regular non-symlink file"
  [[ "$(stat -c %a -- "$path")" == "$expected_mode" ]] ||
    die "$path must have mode 0$expected_mode"
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_uid:$expected_gid" ]] ||
    die "$path has unexpected ownership"
}

assert_directory() {
  local expected_gid=$4 expected_mode=$2 expected_uid=$3 path=$1
  [[ -d "$path" && ! -L "$path" ]] || die "$path must be a non-symlink directory"
  [[ "$(stat -c %a -- "$path")" == "$expected_mode" ]] ||
    die "$path must have mode 0$expected_mode"
  [[ "$(stat -c %u:%g -- "$path")" == "$expected_uid:$expected_gid" ]] ||
    die "$path has unexpected ownership"
}

assert_no_extended_acl() {
  local acl path=$1
  acl="$(getfacl --absolute-names --numeric --omit-header "$path" 2>/dev/null)" ||
    die "could not inspect the ACL on $path"
  if grep -Eq '^(user:[^:]+:|group:[^:]+:|mask::|default:)' <<<"$acl"; then
    die "$path has an extended or default ACL"
  fi
}

assert_one_line() {
  local expected=$2 path=$1
  [[ "$(grep -Fxc -- "$expected" "$path")" == 1 ]] ||
    die "$path must contain exactly one '$expected' directive"
}

verify_nix_store_path() {
  local label=$2 path=$1 store_hash
  if ! store_hash="$(nix-store --query --hash "$path")"; then
    die "$label is not registered in the local Nix store: $path"
  fi
  [[ -n "$store_hash" && "$store_hash" != *$'\n'* ]] ||
    die "$label returned an invalid registered Nix store hash"
  nix-store --verify-path "$path" >/dev/null ||
    die "$label failed Nix store content verification: $path"
}

require_tmpfs_target() {
  local filesystem_type target=$1
  if ! filesystem_type="$(findmnt --noheadings --output FSTYPE --target "$target")"; then
    die "could not determine the filesystem containing $target"
  fi
  [[ "$filesystem_type" == tmpfs ]] || die "$target must be backed by tmpfs"
}

compare_asset() {
  local installed=$2 label=$3 source=$1
  cmp --silent -- "$source" "$installed" ||
    die "$label differs from the pinned deployment bundle"
}

array_contains() {
  local candidate=$1 item
  shift
  for item in "$@"; do
    [[ "$item" == "$candidate" ]] && return 0
  done
  return 1
}

assert_no_unit_dropins() {
  local dropin_name dropin_path unit_root unit_root_on_disk
  for unit_root in "${SYSTEMD_UNIT_ROOTS[@]}"; do
    unit_root_on_disk="$(host_path "$unit_root")"
    for dropin_name in "${SYSTEMD_DROPIN_NAMES[@]}"; do
      dropin_path="$unit_root_on_disk/$dropin_name"
      [[ ! -e "$dropin_path" && ! -L "$dropin_path" ]] ||
        die "$SERVICE_NAME.service must not inherit a systemd drop-in: $dropin_path"
    done
  done
}

assert_service_not_enabled_or_aliased() {
  local alias_name changed dependency_directory entry entry_name target target_name
  local unit_root unit_root_on_disk
  local -a aliases dependency_entries entries
  aliases=("$SERVICE_NAME.service")
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
    die "$SERVICE_NAME.service must not have a systemd alias: $alias_name"
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
        [[ "$entry_name" != "$SERVICE_NAME.service" ]] ||
          die "$SERVICE_NAME.service is enabled through $entry"
        if [[ -L "$entry" ]]; then
          target="$(readlink -- "$entry")" ||
            die "could not inspect systemd enablement link $entry"
          target="${target%/}"
          target_name="${target##*/}"
          [[ "$target_name" != "$SERVICE_NAME.service" ]] ||
            die "$SERVICE_NAME.service is enabled through $entry"
        fi
      done
    done
  done
  shopt -u nullglob
}

assert_pin_directory_contents() {
  local directory expected_gid expected_uid link_count pin_path pin_size
  local -a entries
  directory="$(host_path "$PIN_DIRECTORY")"
  pin_path="$(host_path "$PIN_SOURCE")"
  expected_uid=$expected_root_uid
  expected_gid=$expected_root_gid

  shopt -s dotglob nullglob
  entries=("$directory"/*)
  shopt -u dotglob nullglob
  (( ${#entries[@]} <= 1 )) ||
    die "$directory contains unexpected or leftover PIN-source entries"
  if (( ${#entries[@]} == 0 )); then
    return
  fi
  [[ "${entries[0]}" == "$pin_path" ]] ||
    die "$directory contains an unexpected or leftover PIN-source entry"
  assert_regular_file "$pin_path" 400 "$expected_uid" "$expected_gid"
  assert_no_extended_acl "$pin_path"
  link_count="$(stat -c %h -- "$pin_path")"
  [[ "$link_count" == 1 ]] || die "$pin_path must have exactly one hard link"
  pin_size="$(stat -c %s -- "$pin_path")"
  (( pin_size >= 7 && pin_size <= 9 )) ||
    die "PIN source must contain 6-8 bytes plus one newline"
}

config_path="$(host_path /etc/kaiba-provisioning/signing-gate-deployment.conf)"
unit_path="$(host_path "/etc/systemd/system/$SERVICE_NAME.service")"
polkit_path="$(host_path /etc/polkit-1/rules.d/49-kaiba-signing-pcscd.rules)"
tmpfiles_path="$(host_path /etc/tmpfiles.d/kaiba-provision-signing.conf)"
installed_preflight="$(host_path /usr/local/sbin/kaiba-signing-gate-preflight)"
installed_pin_helper="$(host_path /usr/local/sbin/kaiba-signing-gate-provision-pin)"
installed_readme="$(host_path /usr/local/share/doc/kaiba-ubuntu-signing-gate/README.md)"

assert_regular_file "$config_path" 644 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$unit_path" 644 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$polkit_path" 644 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$tmpfiles_path" 644 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$installed_preflight" 755 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$installed_pin_helper" 755 "$expected_root_uid" "$expected_root_gid"
assert_regular_file "$installed_readme" 644 "$expected_root_uid" "$expected_root_gid"
for installed_object in \
  "$config_path" \
  "$unit_path" \
  "$polkit_path" \
  "$tmpfiles_path" \
  "$installed_preflight" \
  "$installed_pin_helper" \
  "$installed_readme"; do
  assert_no_extended_acl "$installed_object"
done

mapfile -t deployment_config <"$config_path"
[[ ${#deployment_config[@]} == 3 ]] || die "$config_path must contain exactly three lines"
[[ "${deployment_config[0]}" == PACKAGE_PATH=* ]] || die "deployment package path is missing"
[[ "${deployment_config[1]}" == DEPLOYMENT_PATH=* ]] || die "deployment bundle path is missing"
[[ "${deployment_config[2]}" == "PIN_SOURCE=$PIN_SOURCE" ]] ||
  die "deployment PIN source does not match the fixed path"
package_path="${deployment_config[0]#PACKAGE_PATH=}"
deployment_path="${deployment_config[1]#DEPLOYMENT_PATH=}"
[[ "$package_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "deployment package is not one canonical Nix store path"

if [[ -n "$staging_root" ]]; then
  [[ "$deployment_path" == "$STAGING_DEPLOYMENT_ASSET_PATH" ]] ||
    die "staging must use only its fixed in-image validation source"
  deployment_asset_directory="$(host_path "$deployment_path")"
  [[ -d "$deployment_asset_directory" && ! -L "$deployment_asset_directory" ]] ||
    die "staged deployment validation source must be a non-symlink directory"
  assert_directory \
    "$deployment_asset_directory" 755 "$expected_root_uid" "$expected_root_gid"
  assert_no_extended_acl "$deployment_asset_directory"
else
  [[ "$deployment_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
    die "deployment bundle is not one canonical Nix store path"
  deployment_asset_directory="$deployment_path$DEPLOYMENT_ASSET_SUFFIX"
  [[ -d "$deployment_asset_directory" && ! -L "$deployment_asset_directory" ]] ||
    die "deployment bundle lacks its fixed asset directory"
  verify_nix_store_path "$deployment_path" "deployment bundle"
  verify_nix_store_path "$package_path" "configured signing package"
fi

for deployment_asset in \
  49-kaiba-signing-pcscd.rules \
  README.md \
  kaiba-provision-signing-gate.service.in \
  kaiba-provision-signing.conf \
  preflight.sh \
  provision-pin-source.sh; do
  [[ -f "$deployment_asset_directory/$deployment_asset" &&
     ! -L "$deployment_asset_directory/$deployment_asset" ]] ||
    die "pinned deployment asset is missing: $deployment_asset"
  if [[ -n "$staging_root" ]]; then
    deployment_asset_mode=644
    case "$deployment_asset" in
      preflight.sh|provision-pin-source.sh) deployment_asset_mode=755 ;;
    esac
    assert_regular_file \
      "$deployment_asset_directory/$deployment_asset" \
      "$deployment_asset_mode" \
      "$expected_root_uid" \
      "$expected_root_gid"
    assert_no_extended_acl "$deployment_asset_directory/$deployment_asset"
  fi
done

package_on_disk="$(host_path "$package_path")"
[[ -d "$package_on_disk" && ! -L "$package_on_disk" ]] ||
  die "configured signing package must be a non-symlink directory"
[[ "$(readlink -f -- "$package_on_disk")" == "$package_on_disk" ]] ||
  die "configured signing package path is not canonical"
package_mode="$(stat -c %a -- "$package_on_disk")"
(( (8#$package_mode & 0022) == 0 )) || die "configured signing package is writable by group or world"
if [[ -z "$staging_root" ]]; then
  [[ "$(stat -c %u -- "$package_on_disk")" == 0 ]] ||
    die "configured signing package must be root-owned"
fi
assert_no_extended_acl "$package_on_disk"

for relative_path in \
  bin/kaiba-provision-sign-boot \
  bin/kaiba-provision-sign-eeprom \
  bin/kaiba-provision-signing-client \
  bin/kaiba-provision-signing-gate \
  bin/kaiba-provision-signing-receipts \
  bin/kaiba-provision-yubikey-wrapper \
  share/kaiba/customer-key-hash \
  share/kaiba/signer-policy-digest \
  share/kaiba/signer-policy.json; do
  [[ -e "$package_on_disk/$relative_path" ]] ||
    die "configured signing package is missing $relative_path"
  assert_no_extended_acl "$package_on_disk/$relative_path"
done
for executable in \
  bin/kaiba-provision-sign-boot \
  bin/kaiba-provision-sign-eeprom \
  bin/kaiba-provision-signing-client \
  bin/kaiba-provision-signing-gate \
  bin/kaiba-provision-signing-receipts \
  bin/kaiba-provision-yubikey-wrapper; do
  [[ -x "$package_on_disk/$executable" ]] ||
    die "configured signing package executable is not executable: $executable"
done

compare_asset \
  "$deployment_asset_directory/49-kaiba-signing-pcscd.rules" \
  "$polkit_path" \
  "installed pcscd polkit rule"
compare_asset \
  "$deployment_asset_directory/kaiba-provision-signing.conf" \
  "$tmpfiles_path" \
  "installed tmpfiles policy"
compare_asset \
  "$deployment_asset_directory/preflight.sh" \
  "$installed_preflight" \
  "installed preflight"
compare_asset \
  "$deployment_asset_directory/provision-pin-source.sh" \
  "$installed_pin_helper" \
  "installed PIN helper"
compare_asset \
  "$deployment_asset_directory/README.md" \
  "$installed_readme" \
  "installed deployment documentation"

temporary_unit="$(mktemp)"
cleanup() {
  rm -f -- "$temporary_unit"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
[[ "$(grep -Fc '@PACKAGE_PATH@' \
  "$deployment_asset_directory/kaiba-provision-signing-gate.service.in")" == 1 ]] ||
  die "pinned service template must contain exactly one package placeholder"
sed "s|@PACKAGE_PATH@|$package_path|" \
  "$deployment_asset_directory/kaiba-provision-signing-gate.service.in" \
  >"$temporary_unit"
compare_asset "$temporary_unit" "$unit_path" "installed service unit"
assert_no_unit_dropins
assert_service_not_enabled_or_aliased

assert_one_line "$unit_path" "User=$SERVICE_USER"
assert_one_line "$unit_path" "Group=$SERVICE_GROUP"
assert_one_line "$unit_path" "ExecStart=$package_path/bin/kaiba-provision-signing-gate"
assert_one_line "$unit_path" "LoadCredential=yubikey-pin:$PIN_SOURCE"
for directive in \
  'AmbientCapabilities=' \
  'CapabilityBoundingSet=' \
  'DevicePolicy=closed' \
  'IPAddressDeny=any' \
  'InaccessiblePaths=-/run/kaiba-provision-signing-credentials' \
  'MemoryDenyWriteExecute=yes' \
  'NoNewPrivileges=yes' \
  'PrivateDevices=yes' \
  'ProtectProc=invisible' \
  'ProtectSystem=strict' \
  'RestrictAddressFamilies=AF_UNIX' \
  'RestrictNamespaces=yes' \
  'StateDirectory=kaiba-provision-signing' \
  'StateDirectoryMode=0700' \
  'RuntimeDirectory=kaiba-provision-signing' \
  'RuntimeDirectoryMode=0700' \
  'LimitCORE=0' \
  'SystemCallFilter=~@privileged' \
  'UMask=0077'; do
  assert_one_line "$unit_path" "$directive"
done
[[ "$(grep -Fc '@PACKAGE_PATH@' "$unit_path")" == 0 ]] || die "unit contains an unrendered placeholder"
if grep -Eq '^(DeviceAllow|DynamicUser|Environment|EnvironmentFile|PassEnvironment|SupplementaryGroups)=' "$unit_path"; then
  die "unit contains a forbidden identity, environment, or device override"
fi

assert_one_line "$polkit_path" '    if (subject.user === "kaiba-signing" &&'
[[ "$(grep -Fc 'org.debian.pcsc-lite.access_pcsc' "$polkit_path")" == 1 ]] ||
  die "pcscd access_pcsc authorization is missing or duplicated"
[[ "$(grep -Fc 'org.debian.pcsc-lite.access_card' "$polkit_path")" == 1 ]] ||
  die "pcscd access_card authorization is missing or duplicated"
[[ "$(grep -Fc 'polkit.addRule' "$polkit_path")" == 1 ]] || die "polkit rule count is not one"
! grep -Fq 'isInGroup' "$polkit_path" || die "polkit access must not be granted through a group"

assert_one_line "$tmpfiles_path" 'd /run/kaiba-provision-signing-credentials 0700 root root -'
assert_one_line "$tmpfiles_path" 'd /var/lib/kaiba-provision-signing 0700 kaiba-signing kaiba-signing -'
assert_one_line "$tmpfiles_path" 'd /var/lib/kaiba-provision-signing-exports 0700 kaiba-signing kaiba-signing -'

assert_directory "$(host_path /etc/kaiba-provisioning)" 750 "$expected_root_uid" "$expected_registry_gid"
assert_directory "$(host_path "$PIN_DIRECTORY")" 700 "$expected_root_uid" "$expected_root_gid"
assert_no_extended_acl "$(host_path /etc/kaiba-provisioning)"
assert_no_extended_acl "$(host_path "$PIN_DIRECTORY")"
if [[ -n "$staging_root" ]]; then
  assert_directory "$(host_path "$STATE_DIRECTORY")" 700 "$expected_root_uid" "$expected_root_gid"
  assert_directory "$(host_path "$EXPORT_DIRECTORY")" 700 "$expected_root_uid" "$expected_root_gid"
  assert_no_extended_acl "$(host_path "$STATE_DIRECTORY")"
  assert_no_extended_acl "$(host_path "$EXPORT_DIRECTORY")"
else
  require_tmpfs_target "$PIN_DIRECTORY"
fi
assert_pin_directory_contents

if $static_only; then
  printf 'preflight: OK: static deployment is internally consistent; no PIN or token access occurred.\n'
  exit 0
fi

for command_name in jq passwd pcscd swapon systemctl systemd systemd-analyze; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command is unavailable: $command_name"
done

# /etc/os-release is an operating-system-owned shell fragment on Ubuntu.
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID-}" == ubuntu && "${VERSION_ID-}" == 24.04 ]] ||
  die "runtime host must be Ubuntu 24.04"
systemd_version="$(systemd --version | awk 'NR == 1 { print $2 }')"
[[ "$systemd_version" =~ ^[0-9]+$ && "$systemd_version" -ge 255 ]] ||
  die "runtime host must provide systemd 255 or newer"
require_tmpfs_target "$PIN_DIRECTORY"
require_tmpfs_target "$PIN_SOURCE"
if ! swap_output="$(swapon --show --noheadings)"; then
  die "could not inspect active swap devices"
fi
[[ -z "$swap_output" ]] ||
  die "swap must be disabled while the signing PIN is present"

local_group_record="$(awk -F: -v expected="$SERVICE_GROUP" '
  $1 == expected { matches++; record = $0 }
  END { if (matches == 1) print record; else exit 1 }
' /etc/group)" || die "$SERVICE_GROUP must be exactly one local /etc/group entry"
local_user_record="$(awk -F: -v expected="$SERVICE_USER" '
  $1 == expected { matches++; record = $0 }
  END { if (matches == 1) print record; else exit 1 }
' /etc/passwd)" || die "$SERVICE_USER must be exactly one local /etc/passwd entry"
group_record="$(getent group "$SERVICE_GROUP")" || die "service group does not exist"
[[ "$group_record" == "$local_group_record" ]] ||
  die "$SERVICE_GROUP NSS record must resolve to its unique local group"
IFS=: read -r _ _ service_gid group_members <<<"$group_record"
[[ "$service_gid" =~ ^[0-9]+$ && "$service_gid" != 0 && "$service_gid" -lt 1000 ]] ||
  die "$SERVICE_GROUP must have a non-root system GID"
numeric_group_record="$(getent group "$service_gid")" ||
  die "$SERVICE_GROUP numeric GID does not resolve"
[[ "$numeric_group_record" == "$local_group_record" ]] ||
  die "$SERVICE_GROUP GID must resolve back to only the local service group"
[[ -z "$group_members" ]] || die "$SERVICE_GROUP must not have supplementary members"

user_record="$(getent passwd "$SERVICE_USER")" || die "service user does not exist"
[[ "$user_record" == "$local_user_record" ]] ||
  die "$SERVICE_USER NSS record must resolve to its unique local account"
IFS=: read -r _ _ service_uid user_primary_gid _ service_home service_shell <<<"$user_record"
[[ "$service_uid" =~ ^[0-9]+$ && "$service_uid" != 0 && "$service_uid" -lt 1000 ]] ||
  die "$SERVICE_USER must have a non-root system UID"
[[ "$user_primary_gid" == "$service_gid" ]] ||
  die "$SERVICE_USER passwd entry must use the service group as its primary GID"
numeric_user_record="$(getent passwd "$service_uid")" ||
  die "$SERVICE_USER numeric UID does not resolve"
[[ "$numeric_user_record" == "$local_user_record" ]] ||
  die "$SERVICE_USER UID must resolve back to only the local service account"
uid_matches="$(getent passwd | awk -F: -v expected="$service_uid" \
  '$3 == expected { count++ } END { print count + 0 }')" ||
  die "could not enumerate passwd records"
[[ "$uid_matches" == 1 ]] || die "$SERVICE_USER UID must resolve to exactly one account"
gid_matches="$(getent group | awk -F: -v expected="$service_gid" \
  '$3 == expected { count++ } END { print count + 0 }')" ||
  die "could not enumerate group records"
[[ "$gid_matches" == 1 ]] || die "$SERVICE_GROUP GID must resolve to exactly one group"
primary_gid_users="$(getent passwd | awk -F: -v expected="$service_gid" \
  '$4 == expected { print $1 }')" || die "could not enumerate primary GID users"
[[ "$primary_gid_users" == "$SERVICE_USER" ]] ||
  die "$SERVICE_GROUP GID must be the primary GID of only $SERVICE_USER"
local_primary_gid_users="$(awk -F: -v expected="$service_gid" \
  '$4 == expected { print $1 }' /etc/passwd)" ||
  die "could not inspect local primary GID users"
[[ "$local_primary_gid_users" == "$SERVICE_USER" ]] ||
  die "$SERVICE_GROUP local primary GID must be unique to $SERVICE_USER"
[[ "$(id -g "$SERVICE_USER")" == "$service_gid" ]] || die "service primary group is incorrect"
[[ "$(id -G "$SERVICE_USER")" == "$service_gid" ]] || die "service user has supplementary groups"
[[ "$service_home" == /nonexistent && "$service_shell" == /usr/sbin/nologin ]] ||
  die "service login posture is incorrect"
password_record="$(passwd -S "$SERVICE_USER")" ||
  die "could not inspect $SERVICE_USER password status"
[[ "$(awk '{ print $2 }' <<<"$password_record")" == L ]] ||
  die "service password must be locked"

assert_directory /etc/kaiba-provisioning 750 0 "$service_gid"
assert_directory /run/kaiba-provision-signing-credentials 700 0 0
assert_directory "$STATE_DIRECTORY" 700 "$service_uid" "$service_gid"
assert_directory "$EXPORT_DIRECTORY" 700 "$service_uid" "$service_gid"
assert_no_extended_acl /etc/kaiba-provisioning
assert_no_extended_acl /run/kaiba-provision-signing-credentials
assert_no_extended_acl "$STATE_DIRECTORY"
assert_no_extended_acl "$EXPORT_DIRECTORY"

[[ -L "$GC_ROOT" ]] || die "configured signing package is not pinned by $GC_ROOT"
[[ "$(readlink -e -- "$GC_ROOT")" == "$package_path" ]] ||
  die "Nix GC root does not pin the configured signing package"
[[ -L "$DEPLOYMENT_GC_ROOT" ]] ||
  die "deployment bundle is not pinned by $DEPLOYMENT_GC_ROOT"
[[ "$(readlink -e -- "$DEPLOYMENT_GC_ROOT")" == "$deployment_path" ]] ||
  die "Nix GC root does not pin the configured deployment bundle"

[[ -f "$REGISTRY_PATH" && ! -L "$REGISTRY_PATH" ]] ||
  die "$REGISTRY_PATH must be a regular non-symlink file"
[[ "$(stat -c %u:%g:%a -- "$REGISTRY_PATH")" == "0:$service_gid:440" ]] ||
  die "grant registry must be root:$SERVICE_GROUP with mode 0440"
assert_no_extended_acl "$REGISTRY_PATH"
registry_size="$(stat -c %s -- "$REGISTRY_PATH")"
(( registry_size >= 1 && registry_size <= 1048576 )) || die "grant registry has an invalid size"
jq -e '
  .schema_version == "kaiba.provisioning.signing-grant-registry/v1alpha2" and
  (.grants | type == "array" and length >= 1 and length <= 512)
' "$REGISTRY_PATH" >/dev/null || die "grant registry lacks the required v1alpha2 envelope"

assert_pin_directory_contents
[[ -f "$PIN_SOURCE" && ! -L "$PIN_SOURCE" ]] ||
  die "$PIN_SOURCE must be a regular non-symlink file"
[[ "$(stat -c %u:%g:%a -- "$PIN_SOURCE")" == 0:0:400 ]] ||
  die "$PIN_SOURCE must be root:root with mode 0400"
assert_no_extended_acl "$PIN_SOURCE"
[[ "$(stat -c %h -- "$PIN_SOURCE")" == 1 ]] ||
  die "$PIN_SOURCE must have exactly one hard link"
pin_size="$(stat -c %s -- "$PIN_SOURCE")"
(( pin_size >= 7 && pin_size <= 9 )) || die "PIN source must contain 6-8 bytes plus one newline"

pcscd_version="$(pcscd --version 2>&1)"
[[ "${pcscd_version,,}" == *polkit* ]] || die "pcscd lacks polkit support"
grep -Rqs -- 'org.debian.pcsc-lite.access_pcsc' /usr/share/polkit-1/actions ||
  die "pcsc-lite polkit action definitions are unavailable"
systemctl is-active --quiet polkit.service || die "polkit.service is not active"
if ! systemctl is-active --quiet pcscd.service; then
  systemctl is-active --quiet pcscd.socket ||
    die "neither pcscd.service nor its activation socket is active"
fi
pcscd_exec="$(systemctl show --property=ExecStart --value pcscd.service)"
if [[ "${pcscd_exec,,}" =~ (^|[[:space:];])(--disable-polkit|--apdu|-a|--debug|-d)([[:space:];]|$) ]]; then
  die "pcscd.service contains an authorization-bypass or APDU/debug logging argument"
fi
pcscd_dropins="$(systemctl show --property=DropInPaths --value pcscd.service)"
[[ -z "$pcscd_dropins" ]] || die "pcscd.service must not have systemd drop-ins"
pcscd_fragment="$(systemctl show --property=FragmentPath --value pcscd.service)"
[[ "$pcscd_fragment" == /usr/lib/systemd/system/pcscd.service ||
   "$pcscd_fragment" == /lib/systemd/system/pcscd.service ]] ||
  die "pcscd.service must use the Ubuntu package unit"
[[ -f "$pcscd_fragment" && ! -L "$pcscd_fragment" && "$(stat -c %u -- "$pcscd_fragment")" == 0 ]] ||
  die "pcscd.service package unit must be a root-owned regular file"
pcscd_fragment_mode="$(stat -c %a -- "$pcscd_fragment")"
(( (8#$pcscd_fragment_mode & 0022) == 0 )) ||
  die "pcscd.service package unit is writable by group or world"
assert_no_extended_acl "$pcscd_fragment"
systemctl show-environment >/dev/null || die "could not inspect the systemd manager environment"
if systemctl show-environment | grep -E '^PCSCD_ARGS=.+$' >/dev/null; then
  die "the systemd manager environment must not set PCSCD_ARGS"
fi
if [[ -e /etc/default/pcscd || -L /etc/default/pcscd ]]; then
  [[ -f /etc/default/pcscd && ! -L /etc/default/pcscd ]] ||
    die "/etc/default/pcscd must be a regular non-symlink file"
  [[ "$(stat -c %u -- /etc/default/pcscd)" == 0 ]] ||
    die "/etc/default/pcscd must be root-owned"
  defaults_mode="$(stat -c %a -- /etc/default/pcscd)"
  (( (8#$defaults_mode & 0022) == 0 )) ||
    die "/etc/default/pcscd is group- or world-writable"
  assert_no_extended_acl /etc/default/pcscd
  while IFS= read -r defaults_line || [[ -n "$defaults_line" ]]; do
    if [[ "$defaults_line" =~ ^[[:space:]]*PCSCD_ARGS[[:space:]]*= ]]; then
      defaults_compact="${defaults_line//[[:space:]]/}"
      [[ "$defaults_compact" == 'PCSCD_ARGS=' ||
         "$defaults_compact" == 'PCSCD_ARGS=""' ||
         "$defaults_compact" == "PCSCD_ARGS=''" ]] ||
        die "/etc/default/pcscd must not set PCSCD_ARGS"
    fi
  done </etc/default/pcscd
fi

systemd-analyze verify "$unit_path" >/dev/null
load_state="$(systemctl show --property=LoadState --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service load state"
fragment_path="$(systemctl show --property=FragmentPath --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service fragment path"
gate_dropins="$(systemctl show --property=DropInPaths --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service drop-ins"
need_daemon_reload="$(systemctl show --property=NeedDaemonReload --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service reload state"
unit_file_state="$(systemctl show --property=UnitFileState --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service enablement"
limit_core="$(systemctl show --property=LimitCORE --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service hard core limit"
limit_core_soft="$(systemctl show --property=LimitCORESoft --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service soft core limit"
active_state="$(systemctl show --property=ActiveState --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service active state"
sub_state="$(systemctl show --property=SubState --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service sub-state"
main_pid="$(systemctl show --property=MainPID --value "$SERVICE_NAME.service")" ||
  die "could not inspect $SERVICE_NAME.service main PID"

[[ "$load_state" == loaded ]] || die "$SERVICE_NAME.service must be loaded"
[[ "$fragment_path" == "/etc/systemd/system/$SERVICE_NAME.service" ]] ||
  die "$SERVICE_NAME.service is not loaded from its fixed installed fragment"
[[ -z "$gate_dropins" ]] || die "$SERVICE_NAME.service must not have effective drop-ins"
[[ "$need_daemon_reload" == no ]] ||
  die "$SERVICE_NAME.service effective configuration is stale"
[[ "$unit_file_state" == disabled ]] || die "$SERVICE_NAME.service must remain disabled"
[[ "$limit_core" == 0 && "$limit_core_soft" == 0 ]] ||
  die "$SERVICE_NAME.service must have zero hard and soft core-dump limits"
case "$active_state:$sub_state" in
  active:running)
    [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] ||
      die "$SERVICE_NAME.service is active without one positive main PID"
    ;;
  inactive:dead)
    [[ "$main_pid" == 0 ]] ||
      die "$SERVICE_NAME.service is inactive but retains a main PID"
    ;;
  *)
    die "$SERVICE_NAME.service is in unexpected state $active_state/$sub_state"
    ;;
esac

assert_credential_acl() {
  local acl expected_permission=$2 index path=$1
  local -a actual expected
  acl="$(getfacl --absolute-names --numeric --omit-header "$path" 2>/dev/null)" ||
    die "could not inspect the credential ACL on $path"
  mapfile -t actual < <(sed '/^$/d' <<<"$acl")
  expected=(
    "user::$expected_permission"
    "user:$service_uid:$expected_permission"
    'group::---'
    "mask::$expected_permission"
    'other::---'
  )
  [[ ${#actual[@]} -eq ${#expected[@]} ]] || die "$path has a non-canonical credential ACL"
  for index in "${!expected[@]}"; do
    [[ "${actual[$index]}" == "${expected[$index]}" ]] ||
      die "$path has a non-canonical credential ACL"
  done
}

if [[ "$active_state" == active ]]; then
  assert_directory "$RUNTIME_DIRECTORY" 700 "$service_uid" "$service_gid"
  assert_no_extended_acl "$RUNTIME_DIRECTORY"
  credential_directory="${PIN_CREDENTIAL%/*}"
  assert_directory "$credential_directory" 550 0 0
  [[ -f "$PIN_CREDENTIAL" && ! -L "$PIN_CREDENTIAL" ]] ||
    die "systemd PIN credential is not a regular non-symlink file"
  [[ "$(stat -c %u:%g:%a -- "$PIN_CREDENTIAL")" == 0:0:440 ]] ||
    die "systemd PIN credential metadata is not canonical"
  credential_size="$(stat -c %s -- "$PIN_CREDENTIAL")"
  (( credential_size >= 7 && credential_size <= 9 )) ||
    die "systemd PIN credential has an invalid size"
  assert_credential_acl "$credential_directory" r-x
  assert_credential_acl "$PIN_CREDENTIAL" r--

  [[ -S "$SOCKET_PATH" && ! -L "$SOCKET_PATH" ]] ||
    die "active signing gate does not own its fixed Unix socket"
  [[ "$(stat -c %u:%g:%a -- "$SOCKET_PATH")" == "$service_uid:$service_gid:600" ]] ||
    die "signing socket ownership or mode is not private"
  assert_no_extended_acl "$SOCKET_PATH"
else
  [[ ! -e "$RUNTIME_DIRECTORY" && ! -L "$RUNTIME_DIRECTORY" ]] ||
    die "inactive signing gate left a runtime directory behind"
  [[ ! -e "$SOCKET_PATH" && ! -L "$SOCKET_PATH" ]] ||
    die "inactive signing gate left a stale socket behind"
  credential_directory="${PIN_CREDENTIAL%/*}"
  [[ ! -e "$credential_directory" && ! -L "$credential_directory" ]] ||
    die "inactive signing gate left a credential mount behind"
fi

printf 'preflight: OK: Ubuntu signing-gate boundary is ready; no PIN value or token was accessed.\n'
