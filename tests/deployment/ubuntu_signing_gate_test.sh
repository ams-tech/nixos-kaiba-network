#!/bin/bash
set -euo pipefail

export LC_ALL=C
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
deployment="$repository_root/deploy/ubuntu-signing-gate"
temporary_directory="$(mktemp -d)"
cleanup() {
  chmod -R u+w -- "$temporary_directory" 2>/dev/null || true
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'ubuntu signing-gate test: FAIL: %s\n' "$*" >&2
  exit 1
}

for script in install.sh preflight.sh provision-pin-source.sh; do
  bash -n "$deployment/$script"
done

if command -v systemd-analyze >/dev/null 2>&1; then
  verify_package="$temporary_directory/systemd-package"
  mkdir -p "$verify_package/bin"
  cp /usr/bin/true "$verify_package/bin/kaiba-provision-signing-gate"
  sed "s|@PACKAGE_PATH@|$verify_package|" \
    "$deployment/kaiba-provision-signing-gate.service.in" \
    >"$temporary_directory/kaiba-provision-signing-gate.service"
  systemd-analyze verify "$temporary_directory/kaiba-provision-signing-gate.service"
fi

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck \
    "$deployment/install.sh" \
    "$deployment/preflight.sh" \
    "$deployment/provision-pin-source.sh"
fi

stage="$temporary_directory/root"
package_path=/nix/store/00000000000000000000000000000000-kaiba-test-signing
package_on_disk="$stage$package_path"
mkdir -p "$package_on_disk/bin" "$package_on_disk/share/kaiba"

for executable in \
  kaiba-provision-sign-boot \
  kaiba-provision-sign-eeprom \
  kaiba-provision-signing-client \
  kaiba-provision-signing-gate \
  kaiba-provision-signing-receipts \
  kaiba-provision-yubikey-wrapper; do
  printf '#!/bin/sh\nexit 99\n' >"$package_on_disk/bin/$executable"
  chmod 0555 "$package_on_disk/bin/$executable"
done
printf '%s\n' 'sha256:test-customer-key-hash' >"$package_on_disk/share/kaiba/customer-key-hash"
printf '%s\n' 'sha256:test-policy-digest' >"$package_on_disk/share/kaiba/signer-policy-digest"
printf '%s\n' '{}' >"$package_on_disk/share/kaiba/signer-policy.json"
chmod 0444 "$package_on_disk/share/kaiba/"*
chmod 0555 "$package_on_disk" "$package_on_disk/bin" "$package_on_disk/share" "$package_on_disk/share/kaiba"

"$deployment/install.sh" --package "$package_path" --staging-root "$stage"
"$stage/usr/local/sbin/kaiba-signing-gate-preflight" \
  --staging-root "$stage" \
  --static

unit="$stage/etc/systemd/system/kaiba-provision-signing-gate.service"
config="$stage/etc/kaiba-provisioning/signing-gate-deployment.conf"
polkit="$stage/etc/polkit-1/rules.d/49-kaiba-signing-pcscd.rules"
preflight="$stage/usr/local/sbin/kaiba-signing-gate-preflight"
validation_source="$stage/usr/local/share/kaiba-ubuntu-signing-gate-validation-source"

[[ "$(stat -c %a -- "$unit")" == 644 ]] || fail "unit mode is not 0644"
[[ "$(stat -c %a -- "$config")" == 644 ]] || fail "deployment config mode is not 0644"
[[ "$(stat -c %a -- "$polkit")" == 644 ]] || fail "polkit rule mode is not 0644"
[[ "$(stat -c %a -- "$stage/run/kaiba-provision-signing-credentials")" == 700 ]] ||
  fail "PIN source directory mode is not 0700"
[[ "$(stat -c %a -- "$stage/var/lib/kaiba-provision-signing")" == 700 ]] ||
  fail "state directory mode is not 0700"
[[ "$(stat -c %a -- "$stage/var/lib/kaiba-provision-signing-exports")" == 700 ]] ||
  fail "receipt export directory mode is not 0700"

grep -Fxq "ExecStart=$package_path/bin/kaiba-provision-signing-gate" "$unit" ||
  fail "unit does not bind the exact package path"
grep -Fxq \
  'LoadCredential=yubikey-pin:/run/kaiba-provision-signing-credentials/yubikey-pin' \
  "$unit" || fail "unit does not use the fixed systemd credential source"
grep -Fxq 'InaccessiblePaths=-/run/kaiba-provision-signing-credentials' "$unit" ||
  fail "service can see the root PIN source directory"
grep -Fxq 'RestrictAddressFamilies=AF_UNIX' "$unit" || fail "network boundary is missing"
grep -Fxq 'DevicePolicy=closed' "$unit" || fail "device boundary is missing"
grep -Fxq 'CapabilityBoundingSet=' "$unit" || fail "capability boundary is missing"
grep -Fxq 'LimitCORE=0' "$unit" || fail "core-dump limit is missing"
! grep -Eq '^(Environment|EnvironmentFile|PassEnvironment|SetCredential)=' "$unit" ||
  fail "unit contains a secret-capable environment or inline credential directive"

grep -Fq 'live installation must run the deployment bundle from its immutable Nix output' \
  "$deployment/install.sh" || fail "installer lacks immutable source enforcement"
grep -Fq 'UID must resolve to exactly one account' "$deployment/install.sh" ||
  fail "installer lacks service UID uniqueness enforcement"
grep -Fq 'GID must resolve to exactly one group' "$deployment/preflight.sh" ||
  fail "preflight lacks service GID uniqueness enforcement"
grep -Fq 'has an extended or default ACL' "$deployment/preflight.sh" ||
  fail "preflight lacks ACL drift enforcement"
grep -Fq 'stop $SERVICE_NAME.service completely before provisioning its PIN source' \
  "$deployment/provision-pin-source.sh" || fail "PIN helper permits a transitional gate"
grep -Fq 'swap must be disabled before the signing PIN is entered' \
  "$deployment/provision-pin-source.sh" || fail "PIN helper permits active swap"
grep -Fq 'if ! swap_output="$(swapon --show --noheadings)"; then' \
  "$deployment/provision-pin-source.sh" || fail "PIN helper does not fail closed on swapon errors"
grep -Fq 'require_tmpfs_target "$PIN_DIRECTORY"' \
  "$deployment/provision-pin-source.sh" || fail "PIN helper checks only the parent /run mount"
grep -Fq 'systemctl show --property=SubState' \
  "$deployment/provision-pin-source.sh" || fail "PIN helper omits the exact service sub-state"
grep -Fq 'systemctl show --property=MainPID' \
  "$deployment/install.sh" || fail "installer omits exact service process-state validation"
grep -Fq 'nix-store --verify-path "$path"' \
  "$deployment/install.sh" || fail "installer does not verify registered Nix contents"
grep -Fq 'DEPLOYMENT_GC_ROOT=' \
  "$deployment/preflight.sh" || fail "preflight does not require the deployment GC root"

[[ "$(grep -c '^' "$config")" == 3 ]] || fail "deployment config contains unexpected fields"
grep -Fxq "PACKAGE_PATH=$package_path" "$config" || fail "deployment package config is incorrect"
grep -Fxq \
  'DEPLOYMENT_PATH=/usr/local/share/kaiba-ubuntu-signing-gate-validation-source' \
  "$config" ||
  fail "deployment bundle config is incorrect"
[[ -d "$validation_source" && ! -L "$validation_source" ]] ||
  fail "staging validation source is not self-contained"
! grep -Fq "$repository_root" "$config" ||
  fail "staging config depends on the mutable source checkout"
grep -Fxq \
  'PIN_SOURCE=/run/kaiba-provision-signing-credentials/yubikey-pin' \
  "$config" || fail "deployment PIN path config is incorrect"

grep -Fq 'subject.user === "kaiba-signing"' "$polkit" || fail "polkit user selector is missing"
grep -Fq 'org.debian.pcsc-lite.access_pcsc' "$polkit" || fail "pcsc access action is missing"
grep -Fq 'org.debian.pcsc-lite.access_card' "$polkit" || fail "card access action is missing"
! grep -Fq 'isInGroup' "$polkit" || fail "polkit rule grants a service group"

[[ ! -e "$stage/run/kaiba-provision-signing-credentials/yubikey-pin" ]] ||
  fail "installer created a PIN source"
[[ ! -e "$stage/run/kaiba-provision-signing/signing.sock" ]] ||
  fail "installer created a signing socket"
[[ ! -e "$stage/etc/systemd/system/multi-user.target.wants/kaiba-provision-signing-gate.service" ]] ||
  fail "installer enabled the signing gate"

"$deployment/install.sh" --help >/dev/null
"$deployment/preflight.sh" --help >/dev/null
"$deployment/provision-pin-source.sh" --help >/dev/null

for staging_script in install.sh preflight.sh; do
  grep -Fq '(( EUID != 0 )) || die "--staging-root must be run as a non-root user"' \
    "$deployment/$staging_script" ||
    fail "$staging_script does not reject root staging callers"
  grep -Fq 'staging root must be owned by the non-root caller' \
    "$deployment/$staging_script" ||
    fail "$staging_script does not require caller ownership"
  grep -Fq 'staging root must not have an extended or default ACL' \
    "$deployment/$staging_script" ||
    fail "$staging_script does not reject staging-root ACLs"
done

unsafe_mode_stage="$temporary_directory/unsafe-mode-root"
mkdir -m 0700 "$unsafe_mode_stage"
chmod 0755 "$unsafe_mode_stage"
if "$deployment/install.sh" \
  --package "$package_path" --staging-root "$unsafe_mode_stage" >/dev/null 2>&1; then
  fail "installer accepted a non-private staging root"
fi
if "$deployment/preflight.sh" \
  --staging-root "$unsafe_mode_stage" --static >/dev/null 2>&1; then
  fail "preflight accepted a non-private staging root"
fi

chmod 0775 "$package_on_disk"
if "$deployment/install.sh" --package "$package_path" --staging-root "$stage" >/dev/null 2>&1; then
  fail "installer accepted a group-writable signing package"
fi
chmod 0555 "$package_on_disk"

expect_static_rejection() {
  local description=$1
  if "$preflight" --staging-root "$stage" --static >/dev/null 2>&1; then
    fail "preflight accepted $description"
  fi
}

restore_stage() {
  "$deployment/install.sh" --package "$package_path" --staging-root "$stage" >/dev/null
}

printf '\nPrivateDevices=no\n' >>"$unit"
expect_static_rejection "a contradictory appended service directive"
restore_stage

sed -i '/^LimitCORE=0$/d' "$unit"
expect_static_rejection "a service unit without LimitCORE=0"
restore_stage

for dropin_name in \
  kaiba-provision-signing-gate.service.d \
  service.d \
  kaiba-.service.d; do
  dropin_directory="$stage/etc/systemd/system/$dropin_name"
  mkdir -p "$dropin_directory"
  printf '[Service]\nPrivateDevices=no\n' >"$dropin_directory/override.conf"
  expect_static_rejection "the inherited systemd drop-in $dropin_name"
  if "$deployment/install.sh" \
    --package "$package_path" --staging-root "$stage" >/dev/null 2>&1; then
    fail "staging installer accepted the inherited systemd drop-in $dropin_name"
  fi
  rm -f -- "$dropin_directory/override.conf"
  rmdir -- "$dropin_directory"
  restore_stage
done

dropin_directory="$stage/run/systemd/system.control/kaiba-provision-.service.d"
mkdir -p "$dropin_directory"
printf '[Service]\nProtectSystem=no\n' >"$dropin_directory/override.conf"
expect_static_rejection "a prefix drop-in in system.control"
if "$deployment/install.sh" \
  --package "$package_path" --staging-root "$stage" >/dev/null 2>&1; then
  fail "staging installer accepted a prefix drop-in in system.control"
fi
rm -f -- "$dropin_directory/override.conf"
rmdir -- "$dropin_directory"
restore_stage

for dependency_kind in wants requires; do
  dependency_directory="$stage/etc/systemd/system/multi-user.target.$dependency_kind"
  mkdir -p "$dependency_directory"
  ln -s \
    ../kaiba-provision-signing-gate.service \
    "$dependency_directory/kaiba-provision-signing-gate.service"
  expect_static_rejection "a .$dependency_kind enablement link"
  if "$deployment/install.sh" \
    --package "$package_path" --staging-root "$stage" >/dev/null 2>&1; then
    fail "staging installer accepted a .$dependency_kind enablement link"
  fi
  rm -f -- "$dependency_directory/kaiba-provision-signing-gate.service"
  rmdir -- "$dependency_directory"
  restore_stage
done

alias_name=kaiba-signing-autostart-alias.service
dependency_directory="$stage/etc/systemd/system/multi-user.target.wants"
ln -s kaiba-provision-signing-gate.service \
  "$stage/etc/systemd/system/$alias_name"
mkdir -p "$dependency_directory"
ln -s "../$alias_name" "$dependency_directory/$alias_name"
expect_static_rejection "an enabled alias of the signing gate"
if "$deployment/install.sh" \
  --package "$package_path" --staging-root "$stage" >/dev/null 2>&1; then
  fail "staging installer accepted an enabled alias of the signing gate"
fi
rm -f -- \
  "$dependency_directory/$alias_name" \
  "$stage/etc/systemd/system/$alias_name"
rmdir -- "$dependency_directory"
restore_stage

printf '\n// unauthorized drift\n' >>"$polkit"
expect_static_rejection "a changed installed deployment asset"
restore_stage

printf 'UNREVIEWED=1\n' >>"$config"
expect_static_rejection "an extra deployment configuration field"
restore_stage

printf 'stale\n' >"$stage/run/kaiba-provision-signing-credentials/.yubikey-pin.stale"
expect_static_rejection "a leftover hidden PIN temporary file"
rm -f -- "$stage/run/kaiba-provision-signing-credentials/.yubikey-pin.stale"

pin_source="$stage/run/kaiba-provision-signing-credentials/yubikey-pin"
printf '123456\n' >"$pin_source"
chmod 0400 "$pin_source"
ln -- "$pin_source" "$stage/run/duplicate-pin-hardlink"
expect_static_rejection "a multiply linked PIN source"
rm -f -- "$stage/run/duplicate-pin-hardlink" "$pin_source"
restore_stage

relocated_stage="$temporary_directory/relocated-root"
cp -a -- "$stage" "$relocated_stage"
"$relocated_stage/usr/local/sbin/kaiba-signing-gate-preflight" \
  --staging-root "$relocated_stage" --static >/dev/null

escape_stage="$temporary_directory/escape-root"
escape_target="$temporary_directory/escape-target"
mkdir -p "$escape_stage" "$escape_target"
cp -a -- "$stage/nix" "$escape_stage/nix"
ln -s "$escape_target" "$escape_stage/etc"
if "$deployment/install.sh" \
  --package "$package_path" --staging-root "$escape_stage" >/dev/null 2>&1; then
  fail "staging installer followed a symlinked ancestor outside the staging root"
fi
[[ ! -e "$escape_target/kaiba-provisioning" ]] ||
  fail "staging installer wrote through a symlinked ancestor"

fake_commands="$temporary_directory/fake-commands"
acl_drift_deployment="$temporary_directory/acl-drift-deployment"
acl_drift_stage="$temporary_directory/acl-drift-root"
cp -a -- "$deployment" "$acl_drift_deployment"
cp -a -- "$stage" "$acl_drift_stage"
mkdir -p "$fake_commands"
printf '%s\n' \
  '#!/bin/sh' \
  'last=' \
  'for last do :; done' \
  "if [ \"\$last\" = '$acl_drift_stage' ]; then" \
  "  printf '%s\\n' 'user::rwx' 'group::---' 'other::---'" \
  'else' \
  "  printf '%s\\n' 'user::rw-' 'user:65534:r--' 'group::r--' 'mask::r--' 'other::r--'" \
  'fi' \
  >"$fake_commands/getfacl"
chmod 0755 "$fake_commands/getfacl"
sed -i \
  "s|^export PATH=|export PATH=$fake_commands:|" \
  "$acl_drift_deployment/preflight.sh"
if "$acl_drift_deployment/install.sh" \
  --package "$package_path" \
  --staging-root "$acl_drift_stage" >/dev/null 2>&1; then
  fail "preflight accepted an extended ACL on an installed object"
fi

root_acl_deployment="$temporary_directory/root-acl-deployment"
root_acl_stage="$temporary_directory/root-acl-stage"
cp -a -- "$deployment" "$root_acl_deployment"
cp -a -- "$stage" "$root_acl_stage"
for staging_script in install.sh preflight.sh; do
  sed -i \
    "s|^export PATH=|export PATH=$fake_commands:|" \
    "$root_acl_deployment/$staging_script"
done
if "$root_acl_deployment/install.sh" \
  --package "$package_path" --staging-root "$root_acl_stage" >/dev/null 2>&1; then
  fail "installer accepted an extended ACL on the staging root"
fi
if "$root_acl_deployment/preflight.sh" \
  --staging-root "$root_acl_stage" --static >/dev/null 2>&1; then
  fail "preflight accepted an extended ACL on the staging root"
fi

acl_failure_deployment="$temporary_directory/acl-failure-deployment"
acl_failure_stage="$temporary_directory/acl-failure-root"
cp -a -- "$deployment" "$acl_failure_deployment"
cp -a -- "$stage" "$acl_failure_stage"
printf '#!/bin/sh\nexit 66\n' >"$fake_commands/getfacl"
chmod 0755 "$fake_commands/getfacl"
sed -i \
  "s|^export PATH=|export PATH=$fake_commands:|" \
  "$acl_failure_deployment/preflight.sh"
if "$acl_failure_deployment/install.sh" \
  --package "$package_path" \
  --staging-root "$acl_failure_stage" >/dev/null 2>&1; then
  fail "preflight treated an ACL inspection error as an ACL-free object"
fi

if "$deployment/install.sh" \
  --package /tmp/not-a-store-path \
  --staging-root "$temporary_directory/rejected" >/dev/null 2>&1; then
  fail "installer accepted a package outside the Nix store"
fi

if grep -Fq 'swapon --all' \
  "$deployment/README.md" \
  "$repository_root/docs/ubuntu-rpi5-development-signing-ceremony.md"; then
  fail "a ceremony runbook unconditionally restores swap"
fi

if grep -ERq -- '(ykman|pcsc_scan|pkcs11-tool|opensc-tool)' \
  "$deployment/install.sh" \
  "$deployment/preflight.sh" \
  "$deployment/provision-pin-source.sh"; then
  fail "deployment scripts contain a token-enumeration or token-operation command"
fi

printf 'ubuntu signing-gate test: OK\n'
