#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
ulimit -c 0

readonly PIN_DIRECTORY=/run/kaiba-provision-signing-credentials
readonly PIN_SOURCE="$PIN_DIRECTORY/yubikey-pin"
readonly SERVICE_NAME=kaiba-provision-signing-gate

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo kaiba-signing-gate-provision-pin

Interactively create the fixed, root-only tmpfs PIN source consumed by
systemd LoadCredential. The PIN is never accepted through argv, stdin pipes,
an environment variable, or a persistent file.
EOF
}

case "${1-}" in
  "") ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

(( EUID == 0 )) || die "must run as root"
[[ -t 0 && -t 2 ]] || die "a controlling terminal is required"
command -v findmnt >/dev/null 2>&1 || die "findmnt is required"
command -v getfacl >/dev/null 2>&1 || die "getfacl is required"
command -v grep >/dev/null 2>&1 || die "grep is required"
command -v setfacl >/dev/null 2>&1 || die "setfacl is required"
command -v swapon >/dev/null 2>&1 || die "swapon is required"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"

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
[[ "$load_state" == loaded ]] || die "$SERVICE_NAME.service must be loaded"
[[ "$active_state" == inactive && "$sub_state" == dead && "$main_pid" == 0 ]] ||
  die "stop $SERVICE_NAME.service completely before provisioning its PIN source"
[[ "$unit_file_state" == disabled ]] ||
  die "$SERVICE_NAME.service must remain disabled"

if ! swap_output="$(swapon --show --noheadings)"; then
  die "could not inspect active swap devices"
fi
[[ -z "$swap_output" ]] ||
  die "swap must be disabled before the signing PIN is entered"
[[ -d /run && ! -L /run ]] || die "/run must be a non-symlink directory"

require_tmpfs_target() {
  local filesystem_type target=$1
  if ! filesystem_type="$(findmnt --noheadings --output FSTYPE --target "$target")"; then
    die "could not determine the filesystem containing $target"
  fi
  [[ "$filesystem_type" == tmpfs ]] || die "$target must be backed by tmpfs"
}

assert_no_extended_acl() {
  local acl path=$1
  acl="$(getfacl --absolute-names --numeric --omit-header "$path" 2>/dev/null)" ||
    die "could not inspect the ACL on $path"
  if grep -Eq '^(user:[^:]+:|group:[^:]+:|mask::|default:)' <<<"$acl"; then
    die "$path has an extended or default ACL"
  fi
}

require_tmpfs_target /run

if [[ -e "$PIN_DIRECTORY" || -L "$PIN_DIRECTORY" ]]; then
  [[ -d "$PIN_DIRECTORY" && ! -L "$PIN_DIRECTORY" ]] ||
    die "$PIN_DIRECTORY must be a non-symlink directory"
  [[ "$(stat -c '%u:%g:%a' -- "$PIN_DIRECTORY")" == "0:0:700" ]] ||
    die "$PIN_DIRECTORY must be owned by root:root with mode 0700"
  require_tmpfs_target "$PIN_DIRECTORY"
else
  install -d -o root -g root -m 0700 -- "$PIN_DIRECTORY"
fi
setfacl --remove-all --remove-default -- "$PIN_DIRECTORY"
assert_no_extended_acl "$PIN_DIRECTORY"
require_tmpfs_target "$PIN_DIRECTORY"

shopt -s dotglob nullglob
pin_directory_entries=("$PIN_DIRECTORY"/*)
shopt -u dotglob nullglob
(( ${#pin_directory_entries[@]} == 0 )) ||
  die "$PIN_DIRECTORY must be empty; remove the reviewed stale PIN source or temporary entry first"

first_pin=
confirmation=
temporary_path=
cleanup() {
  unset first_pin confirmation
  if [[ -n "$temporary_path" && -e "$temporary_path" ]]; then
    rm -f -- "$temporary_path"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

IFS= read -r -s -p 'YubiKey PIV PIN (6-8 printable non-space bytes): ' first_pin ||
  die "could not read the PIN from the terminal"
printf '\n' >&2

if (( ${#first_pin} < 6 || ${#first_pin} > 8 )) ||
  [[ "$first_pin" =~ [^[:graph:]] ]]; then
  die "the PIN must contain 6-8 printable non-space bytes"
fi

IFS= read -r -s -p 'Confirm YubiKey PIV PIN: ' confirmation ||
  die "could not read the PIN confirmation from the terminal"
printf '\n' >&2
[[ "$first_pin" == "$confirmation" ]] || die "PIN confirmation did not match"

temporary_path="$(mktemp --tmpdir="$PIN_DIRECTORY" .yubikey-pin.XXXXXX)"
printf '%s\n' "$first_pin" >"$temporary_path"
unset first_pin confirmation
chown root:root -- "$temporary_path"
chmod 0400 -- "$temporary_path"

# The root-only parent prevents an unprivileged pathname race. A hard link is
# used so creation of the final name fails atomically if it appeared meanwhile.
if ! ln -- "$temporary_path" "$PIN_SOURCE"; then
  die "refusing to replace an existing PIN source"
fi
rm -f -- "$temporary_path"
temporary_path=

[[ "$(stat -c '%u:%g:%a:%s' -- "$PIN_SOURCE")" =~ ^0:0:400:[7-9]$ ]] ||
  die "created PIN source has unexpected metadata"
[[ "$(stat -c %h -- "$PIN_SOURCE")" == 1 ]] ||
  die "created PIN source must have exactly one hard link"
assert_no_extended_acl "$PIN_SOURCE"
require_tmpfs_target "$PIN_SOURCE"

shopt -s dotglob nullglob
pin_directory_entries=("$PIN_DIRECTORY"/*)
shopt -u dotglob nullglob
[[ ${#pin_directory_entries[@]} == 1 && "${pin_directory_entries[0]}" == "$PIN_SOURCE" ]] ||
  die "$PIN_DIRECTORY contains an unexpected or leftover temporary entry"

printf 'Created %s in tmpfs; the signing service was not started.\n' "$PIN_SOURCE"
