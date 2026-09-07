#!/bin/bash
set -euo pipefail

export LC_ALL=C
umask 077

if (( $# != 2 )); then
  printf 'usage: %s /nix/store/<deployment> /nix/store/<loopback-deployment>\n' "$0" >&2
  exit 2
fi

deployment="$(readlink -e -- "$1")"
runtime_deployment="$(readlink -e -- "$2")"
for candidate in "$deployment" "$runtime_deployment"; do
  [[ "$candidate" =~ ^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+$ ]] || {
    printf 'ubuntu authority test: FAIL: deployment path is not canonical\n' >&2
    exit 1
  }
done

generator="$deployment/bin/kaiba-provision-authority-development-pki"
installer="$deployment/bin/kaiba-ubuntu-provisioning-authority-install"
preflight="$deployment/bin/kaiba-provision-authority-preflight"
for executable in "$generator" "$installer" "$preflight"; do
  [[ -x "$executable" ]] || {
    printf 'ubuntu authority test: FAIL: missing %s\n' "$executable" >&2
    exit 1
  }
done

temporary_directory="$(mktemp -d)"
control_pid=
audit_pid=
cleanup() {
  if [[ -n "$control_pid" ]]; then
    kill "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
  fi
  if [[ -n "$audit_pid" ]]; then
    kill "$audit_pid" 2>/dev/null || true
    wait "$audit_pid" 2>/dev/null || true
  fi
  chmod -R u+w -- "$temporary_directory" 2>/dev/null || true
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

test_path="${KAIBA_AUTHORITY_TEST_PATH:-$PATH}"
pki="$temporary_directory/pki"
stage="$temporary_directory/stage"
KAIBA_AUTHORITY_TEST_PATH="$test_path" "$generator" --output "$pki"

[[ ! -e "$pki/work" ]] || {
  printf 'ubuntu authority test: FAIL: PKI generator retained its CA workspace\n' >&2
  exit 1
}
[[ -f "$pki/authority/control-server-ca.crt" ]] || exit 1
[[ -f "$pki/authority/audit-server-ca.crt" ]] || exit 1
[[ -f "$pki/authority/client-ca.crt" ]] || exit 1
[[ ! -e "$pki/authority/control-server-ca.key" ]] || exit 1
[[ ! -e "$pki/authority/audit-server-ca.key" ]] || exit 1
[[ ! -e "$pki/authority/client-ca.key" ]] || exit 1
! cmp --silent \
  "$pki/authority/control-server-ca.crt" \
  "$pki/authority/audit-server-ca.crt" || {
  printf 'ubuntu authority test: FAIL: control and audit share one server CA\n' >&2
  exit 1
}
for packet in station/bridge station/lane-workflow approver; do
  (
    cd "$pki/$packet"
    sha256sum --check --strict SHA256SUMS >/dev/null
  ) || exit 1
done

bridge_san="$(
  openssl x509 -in "$pki/station/bridge/station-client.crt" \
    -noout -ext subjectAltName | sed '1d' | tr -d '[:space:]'
)"
workflow_san="$(
  openssl x509 -in "$pki/station/lane-workflow/station-client.crt" \
    -noout -ext subjectAltName | sed '1d' | tr -d '[:space:]'
)"
approver_san="$(
  openssl x509 -in "$pki/approver/client.crt" -noout -ext subjectAltName |
    sed '1d' | tr -d '[:space:]'
)"
[[ "$bridge_san" == \
  URI:spiffe://kaiba.network/station/kaiba-rpi5-provisioner/lane/lane-1 ]] || exit 1
[[ "$workflow_san" == \
  URI:spiffe://kaiba.network/station/kaiba-rpi5-provisioner/lane/lane-1 ]] || exit 1
[[ "$approver_san" == URI:spiffe://kaiba.network/approver/verifier ]] || exit 1

certificate_key_digest() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    sha256sum | awk '{ print $1 }'
}
bridge_key="$(certificate_key_digest "$pki/station/bridge/station-client.crt")"
workflow_key="$(certificate_key_digest "$pki/station/lane-workflow/station-client.crt")"
approver_key="$(certificate_key_digest "$pki/approver/client.crt")"
[[ "$bridge_key" != "$workflow_key" && "$bridge_key" != "$approver_key" && \
   "$workflow_key" != "$approver_key" ]] || {
  printf 'ubuntu authority test: FAIL: client roles share a private key\n' >&2
  exit 1
}

mkdir -m 0700 "$stage"
KAIBA_AUTHORITY_TEST_PATH="$test_path" "$installer" \
  --pki-directory "$pki" \
  --staging-root "$stage"
KAIBA_AUTHORITY_TEST_PATH="$test_path" "$preflight" \
  --staging-root "$stage" \
  --static

[[ ! -e "$stage/var/lib/kaiba-provision-control" ]] || exit 1
[[ ! -e "$stage/var/lib/kaiba-provision-audit" ]] || exit 1
[[ ! -e "$stage/etc/systemd/system/multi-user.target.wants/kaiba-provisioning-control.service" ]] ||
  exit 1
[[ ! -e "$stage/etc/systemd/system/multi-user.target.wants/kaiba-provisioning-audit.service" ]] ||
  exit 1
[[ "$(stat -c %a "$stage/etc/kaiba-provisioning/authority/control-server.key")" == 400 ]] ||
  exit 1
[[ "$(stat -c %a "$stage/etc/kaiba-provisioning/authority/audit-server.key")" == 400 ]] ||
  exit 1

tampered="$temporary_directory/tampered"
cp -a -- "$stage" "$tampered"
chmod u+w "$tampered/etc/systemd/system/kaiba-provisioning-control.service"
printf '\nPrivateDevices=no\n' >> \
  "$tampered/etc/systemd/system/kaiba-provisioning-control.service"
chmod 0644 "$tampered/etc/systemd/system/kaiba-provisioning-control.service"
if KAIBA_AUTHORITY_TEST_PATH="$test_path" "$preflight" \
  --staging-root "$tampered" --static >/dev/null 2>&1; then
  printf 'ubuntu authority test: FAIL: preflight accepted a changed control unit\n' >&2
  exit 1
fi

if KAIBA_AUTHORITY_TEST_PATH="$test_path" "$generator" \
  --output "$pki" >/dev/null 2>&1; then
  printf 'ubuntu authority test: FAIL: generator overwrote an existing PKI packet\n' >&2
  exit 1
fi

crlf_pki="$temporary_directory/crlf-pki"
crlf_stage="$temporary_directory/crlf-stage"
cp -a -- "$pki" "$crlf_pki"
chmod u+w "$crlf_pki/authority/client-ca.crt" "$crlf_pki/SHA256SUMS"
printf '\r\n' >>"$crlf_pki/authority/client-ca.crt"
cat "$pki/authority/client-ca.crt" >>"$crlf_pki/authority/client-ca.crt"
chmod 0444 "$crlf_pki/authority/client-ca.crt"
(
  cd "$crlf_pki"
  find authority station approver -type f -printf '%p\n' |
    sort |
    xargs sha256sum >SHA256SUMS
)
chmod 0444 "$crlf_pki/SHA256SUMS"
mkdir -m 0700 "$crlf_stage"
if KAIBA_AUTHORITY_TEST_PATH="$test_path" "$installer" \
  --pki-directory "$crlf_pki" \
  --staging-root "$crlf_stage" >/dev/null 2>&1; then
  printf 'ubuntu authority test: FAIL: installer accepted a CRLF-smuggled second CA\n' >&2
  exit 1
fi

# Start the exact binaries from a separately rendered loopback deployment and
# exercise the shipped read-only live smoke test against real TLS sockets.
runtime_assets="$runtime_deployment/share/kaiba/ubuntu-provisioning-authority"
runtime_config="$runtime_assets/deployment.conf"
runtime_generator="$runtime_deployment/bin/kaiba-provision-authority-development-pki"
runtime_smoke="$runtime_deployment/bin/kaiba-provision-authority-live-smoke"
for executable in "$runtime_generator" "$runtime_smoke"; do
  [[ -x "$executable" ]] || exit 1
done

config_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' "$runtime_config"
}
listen_address="$(config_value LISTEN_ADDRESS)"
control_port="$(config_value CONTROL_PORT)"
audit_port="$(config_value AUDIT_PORT)"
control_package="$(config_value CONTROL_PACKAGE)"
audit_package="$(config_value AUDIT_PACKAGE)"
[[ "$listen_address" == 127.0.0.1 ]] || exit 1

runtime_pki="$temporary_directory/runtime-pki"
KAIBA_AUTHORITY_TEST_PATH="$test_path" "$runtime_generator" --output "$runtime_pki"
mkdir -m 0700 "$temporary_directory/control-state" "$temporary_directory/audit-state"

"$control_package/bin/kaiba-provision-control" \
  --listen "$listen_address:$control_port" \
  --state "$temporary_directory/control-state/control.json" \
  --tls-cert "$runtime_pki/authority/control-server.crt" \
  --tls-key "$runtime_pki/authority/control-server.key" \
  --client-ca "$runtime_pki/authority/client-ca.crt" \
  >"$temporary_directory/control.log" 2>&1 &
control_pid=$!
"$audit_package/bin/kaiba-provision-audit" \
  --listen "$listen_address:$audit_port" \
  --state "$temporary_directory/audit-state/audit.json" \
  --tls-cert "$runtime_pki/authority/audit-server.crt" \
  --tls-key "$runtime_pki/authority/audit-server.key" \
  --client-ca "$runtime_pki/authority/client-ca.crt" \
  >"$temporary_directory/audit.log" 2>&1 &
audit_pid=$!

"$runtime_smoke" \
  --pki-directory "$runtime_pki" \
  --config "$runtime_config"

[[ ! -e "$temporary_directory/control-state/control.json" ]] || {
  printf 'ubuntu authority test: FAIL: read-only smoke created control state\n' >&2
  exit 1
}
[[ ! -e "$temporary_directory/audit-state/audit.json" ]] || {
  printf 'ubuntu authority test: FAIL: read-only smoke created audit state\n' >&2
  exit 1
}

printf 'ubuntu authority test: OK\n'
