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

script_path="$(readlink -f -- "${BASH_SOURCE[0]}")"
readonly SOURCE_DIRECTORY="$(dirname -- "$script_path")"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh --package /nix/store/<hash>-<configured-signing-package>

Options:
  --package PATH       Exact mkDevelopmentYubiKeySigning output to deploy.
  --staging-root PATH  Render into a pre-created, caller-owned, ACL-free 0700
                       offline/test root. This option is non-root-only and
                       performs no host account, Nix GC-root, tmpfiles, or
                       systemd operations. The result must never be booted.
  -h, --help           Show this help.

This installer never accepts, reads, or writes a YubiKey PIN. It installs the
gate disabled and does not start pcscd, the gate, a signing client, or a token
utility.
EOF
}

package_path=
staging_root=
while (( $# > 0 )); do
  case "$1" in
    --package)
      (( $# >= 2 )) || die "--package requires a value"
      package_path=$2
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

[[ -n "$package_path" ]] || die "--package is required"
[[ "$package_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
  die "--package must be one canonical Nix store path"

if [[ -n "$staging_root" ]]; then
  (( EUID != 0 )) || die "--staging-root must be run as a non-root user"
  [[ "$staging_root" == /* && "$staging_root" != / ]] ||
    die "--staging-root must be an absolute path other than /"
  [[ -d "$staging_root" && ! -L "$staging_root" ]] ||
    die "staging root must be a pre-created non-symlink directory"
  staging_root="$(readlink -f -- "$staging_root")" ||
    die "could not resolve the staging root"
  [[ "$staging_root" != / ]] || die "refusing to use / as a staging root"
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
  deployment_path=$STAGING_DEPLOYMENT_ASSET_PATH
else
  (( EUID == 0 )) || die "must run as root unless --staging-root is used"
  [[ "$SOURCE_DIRECTORY" =~ ^/nix/store/[0-9a-z]{32}-[^/[:space:]]+/share/kaiba/ubuntu-signing-gate$ ]] ||
    die "live installation must run the deployment bundle from its immutable Nix output"
  [[ "$(stat -c %u -- "$SOURCE_DIRECTORY")" == 0 ]] ||
    die "deployment source directory must be root-owned"
  source_mode="$(stat -c %a -- "$SOURCE_DIRECTORY")"
  (( (8#$source_mode & 0022) == 0 )) ||
    die "deployment source directory is group- or world-writable"
  deployment_path="${SOURCE_DIRECTORY%"$DEPLOYMENT_ASSET_SUFFIX"}"
  [[ "$deployment_path" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] ||
    die "could not derive the deployment bundle's canonical Nix store path"
fi
readonly deployment_path

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

ensure_staging_directory_chain() {
  local candidate=$1 component current relative
  local -a components
  assert_staging_path_confined "$candidate"
  relative="${candidate#"$staging_root"}"
  current=$staging_root
  IFS=/ read -r -a components <<<"${relative#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    if [[ -e "$current" || -L "$current" ]]; then
      [[ -d "$current" && ! -L "$current" ]] ||
        die "staging directory chain is unsafe at $current"
    else
      mkdir -m 0755 -- "$current"
    fi
  done
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
        if [[ "$entry_name" == "$SERVICE_NAME.service" ]]; then
          die "$SERVICE_NAME.service is enabled through $entry"
        fi
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

require_source_asset() {
  local asset_mode path="$SOURCE_DIRECTORY/$1"
  [[ -f "$path" && ! -L "$path" ]] || die "missing deployment asset: $path"
  if [[ -z "$staging_root" ]]; then
    [[ "$(stat -c %u -- "$path")" == 0 ]] ||
      die "deployment asset must be root-owned: $path"
    asset_mode="$(stat -c %a -- "$path")"
    (( (8#$asset_mode & 0022) == 0 )) ||
      die "deployment asset is group- or world-writable: $path"
  fi
}

for asset in \
  49-kaiba-signing-pcscd.rules \
  README.md \
  kaiba-provision-signing-gate.service.in \
  kaiba-provision-signing.conf \
  preflight.sh \
  provision-pin-source.sh; do
  require_source_asset "$asset"
done

package_on_disk="$(host_path "$package_path")"
[[ -d "$package_on_disk" && ! -L "$package_on_disk" ]] ||
  die "configured signing package is not a non-symlink directory: $package_path"
[[ "$(readlink -f -- "$package_on_disk")" == "$package_on_disk" ]] ||
  die "configured signing package path is not canonical"

package_mode="$(stat -c %a -- "$package_on_disk")"
(( (8#$package_mode & 0022) == 0 )) ||
  die "configured signing package is group- or world-writable"
if [[ -z "$staging_root" ]]; then
  [[ "$(stat -c %u -- "$package_on_disk")" == 0 ]] ||
    die "configured signing package must be root-owned"
fi

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

require_service_inactive() {
  local active_state dropin_paths fragment_path load_state main_pid need_daemon_reload
  local sub_state unit_file_state
  load_state="$(systemctl show --property=LoadState --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service load state"
  active_state="$(systemctl show --property=ActiveState --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service active state"
  sub_state="$(systemctl show --property=SubState --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service sub-state"
  main_pid="$(systemctl show --property=MainPID --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service main PID"
  unit_file_state="$(systemctl show --property=UnitFileState --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service enablement"
  dropin_paths="$(systemctl show --property=DropInPaths --value "$SERVICE_NAME.service")" ||
    die "could not inspect $SERVICE_NAME.service drop-ins"

  [[ "$load_state" == loaded || "$load_state" == not-found ]] ||
    die "$SERVICE_NAME.service has unsafe load state $load_state"
  [[ "$active_state" == inactive && "$sub_state" == dead && "$main_pid" == 0 ]] ||
    die "$SERVICE_NAME.service must be exactly inactive/dead with no main process"
  [[ -z "$dropin_paths" ]] || die "$SERVICE_NAME.service must not have effective drop-ins"
  if [[ "$load_state" == loaded ]]; then
    [[ "$unit_file_state" == disabled ]] ||
      die "$SERVICE_NAME.service must be exactly disabled before deployment"
    need_daemon_reload="$(systemctl show --property=NeedDaemonReload --value "$SERVICE_NAME.service")" ||
      die "could not inspect $SERVICE_NAME.service reload state"
    [[ "$need_daemon_reload" == no ]] ||
      die "$SERVICE_NAME.service effective configuration is stale"
    if [[ -e "/etc/systemd/system/$SERVICE_NAME.service" ||
          -L "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
      fragment_path="$(systemctl show --property=FragmentPath --value "$SERVICE_NAME.service")" ||
        die "could not inspect $SERVICE_NAME.service fragment path"
      [[ "$fragment_path" == "/etc/systemd/system/$SERVICE_NAME.service" ]] ||
        die "$SERVICE_NAME.service is not loaded from its fixed installed fragment"
    fi
  else
    [[ -z "$unit_file_state" ]] ||
      die "an uninstalled $SERVICE_NAME.service has unexpected enablement $unit_file_state"
  fi
}

check_ubuntu_host() {
  local command_name defaults_compact defaults_line defaults_mode dropins fragment_mode
  local fragment_path package_name pcscd_unit pcscd_version systemd_version
  for command_name in \
    awk cut dpkg-query findmnt getent grep groupadd id install jq nix-store \
    passwd pcscd readlink sed setfacl stat swapon systemctl systemd \
    systemd-analyze systemd-tmpfiles useradd; do
    command -v "$command_name" >/dev/null 2>&1 ||
      die "required command is unavailable: $command_name"
  done

  # /etc/os-release is an operating-system-owned shell fragment on Ubuntu.
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID-}" == ubuntu && "${VERSION_ID-}" == 24.04 ]] ||
    die "this deployment bundle requires Ubuntu 24.04"

  systemd_version="$(systemd --version | awk 'NR == 1 { print $2 }')"
  [[ "$systemd_version" =~ ^[0-9]+$ ]] || die "could not determine the systemd version"
  (( systemd_version >= 255 )) || die "systemd 255 or newer is required"
  require_tmpfs_target /run

  for package_name in acl jq libccid pcscd polkitd; do
    dpkg-query -W -f='${Status}\n' "$package_name" 2>/dev/null |
      grep -Fxq 'install ok installed' ||
      die "required Ubuntu package is not installed: $package_name"
  done

  pcscd_version="$(pcscd --version 2>&1)"
  [[ "${pcscd_version,,}" == *polkit* ]] ||
    die "pcscd was not built with polkit authorization support"
  grep -Rqs -- 'org.debian.pcsc-lite.access_pcsc' /usr/share/polkit-1/actions ||
    die "pcsc-lite polkit action definitions are unavailable"

  pcscd_unit="$(systemctl cat pcscd.service)" || die "pcscd.service is unavailable"
  if [[ "${pcscd_unit,,}" =~ (^|[[:space:];])(--disable-polkit|--apdu|-a|--debug|-d)([[:space:];]|$) ]]; then
    die "pcscd.service contains an authorization-bypass or APDU/debug logging argument"
  fi
  dropins="$(systemctl show --property=DropInPaths --value pcscd.service)"
  [[ -z "$dropins" ]] || die "pcscd.service must not have systemd drop-ins"
  fragment_path="$(systemctl show --property=FragmentPath --value pcscd.service)"
  [[ "$fragment_path" == /usr/lib/systemd/system/pcscd.service ||
     "$fragment_path" == /lib/systemd/system/pcscd.service ]] ||
    die "pcscd.service must use the Ubuntu package unit"
  [[ -f "$fragment_path" && ! -L "$fragment_path" && "$(stat -c %u -- "$fragment_path")" == 0 ]] ||
    die "pcscd.service package unit must be a root-owned regular file"
  fragment_mode="$(stat -c %a -- "$fragment_path")"
  (( (8#$fragment_mode & 0022) == 0 )) || die "pcscd.service package unit is writable by group or world"
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
}

validate_service_identity() {
  local gid_matches group_ids group_members group_record home local_group_record
  local local_primary_gid_users local_user_record numeric_group_record numeric_user_record
  local password_record password_status primary_gid primary_gid_users shell uid uid_matches
  local user_primary_gid user_record

  local_group_record="$(awk -F: -v expected="$SERVICE_GROUP" '
    $1 == expected { matches++; record = $0 }
    END { if (matches == 1) print record; else exit 1 }
  ' /etc/group)" || die "$SERVICE_GROUP must be exactly one local /etc/group entry"
  local_user_record="$(awk -F: -v expected="$SERVICE_USER" '
    $1 == expected { matches++; record = $0 }
    END { if (matches == 1) print record; else exit 1 }
  ' /etc/passwd)" || die "$SERVICE_USER must be exactly one local /etc/passwd entry"

  group_record="$(getent group "$SERVICE_GROUP")" || die "service group was not created"
  [[ "$group_record" == "$local_group_record" ]] ||
    die "$SERVICE_GROUP NSS record must resolve to its unique local group"
  IFS=: read -r _ _ primary_gid group_members <<<"$group_record"
  [[ "$primary_gid" =~ ^[0-9]+$ && "$primary_gid" != 0 && "$primary_gid" -lt 1000 ]] ||
    die "$SERVICE_GROUP must have a non-root system GID"
  numeric_group_record="$(getent group "$primary_gid")" ||
    die "$SERVICE_GROUP numeric GID does not resolve"
  [[ "$numeric_group_record" == "$local_group_record" ]] ||
    die "$SERVICE_GROUP GID must resolve back to only the local service group"
  [[ -z "$group_members" ]] ||
    die "$SERVICE_GROUP must not contain supplementary human or service members"

  user_record="$(getent passwd "$SERVICE_USER")" || die "service user was not created"
  [[ "$user_record" == "$local_user_record" ]] ||
    die "$SERVICE_USER NSS record must resolve to its unique local account"
  IFS=: read -r _ _ uid user_primary_gid _ home shell <<<"$user_record"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 && "$uid" -lt 1000 ]] ||
    die "$SERVICE_USER must have a non-root system UID"
  [[ "$user_primary_gid" == "$primary_gid" ]] ||
    die "$SERVICE_USER passwd entry must use the service group as its primary GID"
  numeric_user_record="$(getent passwd "$uid")" ||
    die "$SERVICE_USER numeric UID does not resolve"
  [[ "$numeric_user_record" == "$local_user_record" ]] ||
    die "$SERVICE_USER UID must resolve back to only the local service account"

  uid_matches="$(getent passwd | awk -F: -v expected="$uid" \
    '$3 == expected { count++ } END { print count + 0 }')" ||
    die "could not enumerate passwd records"
  [[ "$uid_matches" == 1 ]] || die "$SERVICE_USER UID must resolve to exactly one account"
  gid_matches="$(getent group | awk -F: -v expected="$primary_gid" \
    '$3 == expected { count++ } END { print count + 0 }')" ||
    die "could not enumerate group records"
  [[ "$gid_matches" == 1 ]] || die "$SERVICE_GROUP GID must resolve to exactly one group"
  primary_gid_users="$(getent passwd | awk -F: -v expected="$primary_gid" \
    '$4 == expected { print $1 }')" || die "could not enumerate primary GID users"
  [[ "$primary_gid_users" == "$SERVICE_USER" ]] ||
    die "$SERVICE_GROUP GID must be the primary GID of only $SERVICE_USER"
  local_primary_gid_users="$(awk -F: -v expected="$primary_gid" \
    '$4 == expected { print $1 }' /etc/passwd)" ||
    die "could not inspect local primary GID users"
  [[ "$local_primary_gid_users" == "$SERVICE_USER" ]] ||
    die "$SERVICE_GROUP local primary GID must be unique to $SERVICE_USER"
  [[ "$(id -g "$SERVICE_USER")" == "$primary_gid" ]] ||
    die "$SERVICE_USER primary group must be $SERVICE_GROUP"
  group_ids="$(id -G "$SERVICE_USER")"
  [[ "$group_ids" == "$primary_gid" ]] ||
    die "$SERVICE_USER must not have supplementary groups"
  [[ "$home" == /nonexistent && "$shell" == /usr/sbin/nologin ]] ||
    die "$SERVICE_USER must use /nonexistent and /usr/sbin/nologin"
  password_record="$(passwd -S "$SERVICE_USER")" ||
    die "could not inspect $SERVICE_USER password status"
  password_status="$(awk '{ print $2 }' <<<"$password_record")"
  [[ "$password_status" == L ]] || die "$SERVICE_USER password must be locked"
}

ensure_service_identity() {
  if ! getent group "$SERVICE_GROUP" >/dev/null; then
    groupadd --system "$SERVICE_GROUP"
  elif [[ "$(awk -F: -v expected="$SERVICE_GROUP" '$1 == expected { count++ } END { print count + 0 }' /etc/group)" != 1 ]]; then
    die "refusing a non-local or ambiguous pre-existing $SERVICE_GROUP group"
  fi
  if ! getent passwd "$SERVICE_USER" >/dev/null; then
    useradd \
      --system \
      --gid "$SERVICE_GROUP" \
      --home-dir /nonexistent \
      --shell /usr/sbin/nologin \
      --no-create-home \
      "$SERVICE_USER"
  elif [[ "$(awk -F: -v expected="$SERVICE_USER" '$1 == expected { count++ } END { print count + 0 }' /etc/passwd)" != 1 ]]; then
    die "refusing a non-local or ambiguous pre-existing $SERVICE_USER account"
  fi
  validate_service_identity
}

prepare_directory() {
  local group=$4 mode=$2 owner=$3 path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || die "$path must be a non-symlink directory"
  fi
  install -d -o "$owner" -g "$group" -m "$mode" -- "$path"
  setfacl --remove-all --remove-default -- "$path"
}

prepare_staging_directory() {
  local mode=$2 path
  path="$(host_path "$1")"
  ensure_staging_directory_chain "$path"
  chmod "$mode" -- "$path"
}

install_root_file() {
  local mode=$1 parent source=$2 target
  target="$(host_path "$3")"
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" ]] ||
      die "$target must be a regular non-symlink file"
  fi
  if [[ -n "$staging_root" ]]; then
    parent="$(dirname -- "$target")"
    ensure_staging_directory_chain "$parent"
    install -m "$mode" -- "$source" "$target"
  else
    install -D -o root -g root -m "$mode" -- "$source" "$target"
    setfacl --remove-all -- "$target"
  fi
}

if [[ -z "$staging_root" ]]; then
  check_ubuntu_host
  verify_nix_store_path "$deployment_path" "deployment bundle"
  verify_nix_store_path "$package_path" "configured signing package"
  require_service_inactive
  assert_no_service_dropins
  assert_service_not_enabled_or_aliased
  ensure_service_identity
  prepare_directory /etc/kaiba-provisioning 0750 root "$SERVICE_GROUP"
  if [[ -e "$PIN_DIRECTORY" || -L "$PIN_DIRECTORY" ]]; then
    [[ -d "$PIN_DIRECTORY" && ! -L "$PIN_DIRECTORY" ]] ||
      die "$PIN_DIRECTORY must be a non-symlink directory"
    require_tmpfs_target "$PIN_DIRECTORY"
  fi
  prepare_directory "$PIN_DIRECTORY" 0700 root root
  require_tmpfs_target "$PIN_DIRECTORY"
  prepare_directory /var/lib/kaiba-provision-signing 0700 "$SERVICE_USER" "$SERVICE_GROUP"
  prepare_directory /var/lib/kaiba-provision-signing-exports 0700 "$SERVICE_USER" "$SERVICE_GROUP"

  ensure_gc_root() {
    local root=$1 store_path=$2
    if [[ -e "$root" || -L "$root" ]]; then
      [[ -L "$root" ]] || die "$root exists and is not a symbolic link"
      [[ "$(readlink -e -- "$root")" == "$store_path" ]] ||
        die "$root pins a different output; review and remove it before redeployment"
    else
      nix-store --realise "$store_path" --add-root "$root" >/dev/null
    fi
  }
  ensure_gc_root "$GC_ROOT" "$package_path"
  ensure_gc_root "$DEPLOYMENT_GC_ROOT" "$deployment_path"
else
  assert_no_service_dropins
  assert_service_not_enabled_or_aliased
  prepare_staging_directory /etc/kaiba-provisioning 0750
  prepare_staging_directory /run/kaiba-provision-signing-credentials 0700
  prepare_staging_directory /var/lib/kaiba-provision-signing 0700
  prepare_staging_directory /var/lib/kaiba-provision-signing-exports 0700
fi

temporary_directory="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(grep -Fc '@PACKAGE_PATH@' "$SOURCE_DIRECTORY/kaiba-provision-signing-gate.service.in")" == 1 ]] ||
  die "service template must contain exactly one package placeholder"
sed "s|@PACKAGE_PATH@|$package_path|" \
  "$SOURCE_DIRECTORY/kaiba-provision-signing-gate.service.in" \
  >"$temporary_directory/$SERVICE_NAME.service"
printf 'PACKAGE_PATH=%s\nDEPLOYMENT_PATH=%s\nPIN_SOURCE=%s\n' \
  "$package_path" "$deployment_path" "$PIN_SOURCE" \
  >"$temporary_directory/signing-gate-deployment.conf"

if [[ -n "$staging_root" ]]; then
  for asset in \
    49-kaiba-signing-pcscd.rules \
    README.md \
    kaiba-provision-signing-gate.service.in \
    kaiba-provision-signing.conf; do
    install_root_file 0644 \
      "$SOURCE_DIRECTORY/$asset" \
      "$STAGING_DEPLOYMENT_ASSET_PATH/$asset"
  done
  for asset in preflight.sh provision-pin-source.sh; do
    install_root_file 0755 \
      "$SOURCE_DIRECTORY/$asset" \
      "$STAGING_DEPLOYMENT_ASSET_PATH/$asset"
  done
fi

install_root_file 0644 \
  "$temporary_directory/$SERVICE_NAME.service" \
  "/etc/systemd/system/$SERVICE_NAME.service"
install_root_file 0644 \
  "$SOURCE_DIRECTORY/49-kaiba-signing-pcscd.rules" \
  /etc/polkit-1/rules.d/49-kaiba-signing-pcscd.rules
install_root_file 0644 \
  "$SOURCE_DIRECTORY/kaiba-provision-signing.conf" \
  /etc/tmpfiles.d/kaiba-provision-signing.conf
install_root_file 0644 \
  "$temporary_directory/signing-gate-deployment.conf" \
  /etc/kaiba-provisioning/signing-gate-deployment.conf
install_root_file 0755 \
  "$SOURCE_DIRECTORY/preflight.sh" \
  /usr/local/sbin/kaiba-signing-gate-preflight
install_root_file 0755 \
  "$SOURCE_DIRECTORY/provision-pin-source.sh" \
  /usr/local/sbin/kaiba-signing-gate-provision-pin
install_root_file 0644 \
  "$SOURCE_DIRECTORY/README.md" \
  /usr/local/share/doc/kaiba-ubuntu-signing-gate/README.md

installed_preflight="$(host_path /usr/local/sbin/kaiba-signing-gate-preflight)"
if [[ -n "$staging_root" ]]; then
  "$installed_preflight" --staging-root "$staging_root" --static
  printf 'Rendered an inert signing-gate deployment under %s.\n' "$staging_root"
else
  systemd-tmpfiles --create /etc/tmpfiles.d/kaiba-provision-signing.conf
  systemctl daemon-reload
  systemd-analyze verify "/etc/systemd/system/$SERVICE_NAME.service"
  require_service_inactive
  "$installed_preflight" --static
  printf '%s\n' \
    "Installed $SERVICE_NAME.service without enabling or starting it." \
    "No PIN was read or written and no token operation was performed." \
    "Install the reviewed grant registry, provision the tmpfs PIN source, and run:" \
    "  sudo /usr/local/sbin/kaiba-signing-gate-preflight"
fi
