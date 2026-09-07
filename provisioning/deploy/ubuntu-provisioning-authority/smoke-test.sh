#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
system_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test_mode=false
if [[ -n "${KAIBA_AUTHORITY_TEST_PATH:-}" ]]; then
  (( EUID != 0 )) || {
    printf 'authority smoke: FAIL: test PATH override is forbidden for root\n' >&2
    exit 1
  }
  export PATH="$KAIBA_AUTHORITY_TEST_PATH:$system_path"
  unset KAIBA_AUTHORITY_TEST_PATH
  test_mode=true
else
  export PATH=$system_path
  (( EUID == 0 )) || {
    printf 'authority smoke: FAIL: live smoke must run as root\n' >&2
    exit 1
  }
fi
readonly system_path test_mode
umask 077

readonly DEFAULT_CONFIG=/etc/kaiba-provisioning/authority-deployment.conf
readonly CURL=@CURL@

die() {
  printf 'authority smoke: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo kaiba-provision-authority-live-smoke \
    --pki-directory /run/ABSOLUTE_ROOT_OWNED_DEVELOPMENT_PKI_PACKET

Test-only configuration override:
  kaiba-provision-authority-live-smoke \
    --pki-directory ABSOLUTE_DEVELOPMENT_PKI_PACKET \
    --config ABSOLUTE_DEPLOYMENT_CONFIG

Perform read-only positive and negative mutual-TLS probes against both running
authority endpoints. No transaction, approval, event, or mutation is created.
EOF
}

pki_directory=
config_path=$DEFAULT_CONFIG
config_overridden=false
while (( $# > 0 )); do
  case "$1" in
    --pki-directory)
      (( $# >= 2 )) || die "--pki-directory requires a value"
      pki_directory=$2
      shift 2
      ;;
    --config)
      (( $# >= 2 )) || die "--config requires a value"
      config_path=$2
      config_overridden=true
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

if ! $test_mode && $config_overridden; then
  die "live smoke must use the installed fixed deployment configuration"
fi

[[ -n "$pki_directory" ]] || die "--pki-directory is required"
for path in "$pki_directory" "$config_path"; do
  [[ "$path" == /* && "$path" != / ]] || die "paths must be absolute and other than /"
done
[[ -d "$pki_directory" && ! -L "$pki_directory" ]] ||
  die "PKI packet must be a non-symlink directory"
pki_directory="$(readlink -f -- "$pki_directory")" || die "could not resolve PKI packet"
[[ -f "$config_path" && ! -L "$config_path" ]] || die "deployment configuration is unavailable"
config_path="$(readlink -f -- "$config_path")" || die "could not resolve deployment configuration"
[[ -x "$CURL" ]] || die "fixed curl executable is unavailable"
for command_name in awk chmod grep mktemp readlink rm sha256sum sleep stat; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command is unavailable: $command_name"
done
if ! $test_mode; then
  command -v findmnt >/dev/null 2>&1 || die "required command is unavailable: findmnt"
  [[ "$pki_directory" == /run/* ]] || die "live PKI packet must be beneath /run"
  [[ "$(stat -c '%u:%g:%a' "$pki_directory")" == 0:0:700 ]] ||
    die "live PKI packet must be root-owned with mode 0700"
  [[ "$(findmnt --noheadings --output FSTYPE --target "$pki_directory")" == tmpfs ]] ||
    die "live PKI packet must be backed by tmpfs"
fi

config_value() {
  local key=$1 count value
  count="$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$config_path")"
  [[ "$count" == 1 ]] || die "deployment configuration must contain exactly one $key"
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' "$config_path")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || die "invalid $key value"
  printf '%s\n' "$value"
}

listen_address="$(config_value LISTEN_ADDRESS)"
control_port="$(config_value CONTROL_PORT)"
audit_port="$(config_value AUDIT_PORT)"
[[ "$listen_address" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] ||
  die "listener is not a concrete IPv4 address"
[[ "$control_port" =~ ^[0-9]+$ && "$audit_port" =~ ^[0-9]+$ && \
   "$control_port" -ge 1 && "$control_port" -le 65535 && \
   "$audit_port" -ge 1 && "$audit_port" -le 65535 && \
   "$control_port" != "$audit_port" ]] || die "authority ports are invalid or equal"

bridge="$pki_directory/station/bridge"
workflow="$pki_directory/station/lane-workflow"
approver="$pki_directory/approver"
for file in \
  "$bridge/station-client.crt" "$bridge/station-client.key" \
  "$bridge/control-server-ca.crt" "$bridge/audit-server-ca.crt" \
  "$workflow/station-client.crt" "$workflow/station-client.key" \
  "$workflow/control-server-ca.crt" "$workflow/audit-server-ca.crt" \
  "$approver/client.crt" "$approver/client.key" \
  "$approver/control-server-ca.crt" "$approver/audit-server-ca.crt"; do
  [[ -f "$file" && ! -L "$file" ]] || die "required PKI file is unavailable: $file"
done
(
  cd "$pki_directory"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || die "complete PKI packet checksum verification failed"
for packet in station/bridge station/lane-workflow approver; do
  (
    cd "$pki_directory/$packet"
    sha256sum --check --strict SHA256SUMS >/dev/null
  ) || die "$packet packet checksum verification failed"
done

temporary_directory="$(mktemp -d)"
cleanup() {
  chmod -R u+w -- "$temporary_directory" 2>/dev/null || true
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

control_origin="https://$listen_address:$control_port"
audit_origin="https://$listen_address:$audit_port"

curl_base=(
  "$CURL"
  --connect-timeout 2
  --max-time 5
  --noproxy '*'
  --proto '=https'
  --silent
  --show-error
  --tlsv1.3
)

request_status() {
  local certificate=$1 private_key=$2 server_ca=$3 url=$4 body=$5
  "${curl_base[@]}" \
    --cert "$certificate" \
    --key "$private_key" \
    --cacert "$server_ca" \
    --output "$body" \
    --write-out '%{http_code}' \
    "$url"
}

wait_for_health() {
  local certificate=$1 private_key=$2 server_ca=$3 origin=$4 label=$5 body status attempt
  body="$temporary_directory/$label-health.json"
  for (( attempt = 1; attempt <= 30; attempt++ )); do
    status="$(request_status "$certificate" "$private_key" "$server_ca" \
      "$origin/healthz" "$body" 2>/dev/null || true)"
    if [[ "$status" == 200 ]] && grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' "$body"; then
      return 0
    fi
    sleep 0.2
  done
  die "$label endpoint did not become healthy"
}

expect_status() {
  local expected=$1 certificate=$2 private_key=$3 server_ca=$4 url=$5 label=$6 body status
  body="$temporary_directory/$label.json"
  status="$(request_status "$certificate" "$private_key" "$server_ca" "$url" "$body")" ||
    die "$label request failed before receiving HTTP status"
  [[ "$status" == "$expected" ]] || die "$label returned HTTP $status, expected $expected"
}

expect_tls_failure() {
  local label=$1
  shift
  if "${curl_base[@]}" "$@" --output /dev/null "$control_origin/healthz" >/dev/null 2>&1; then
    die "$label unexpectedly completed a TLS request"
  fi
}

wait_for_health \
  "$bridge/station-client.crt" "$bridge/station-client.key" \
  "$bridge/control-server-ca.crt" "$control_origin" control
wait_for_health \
  "$bridge/station-client.crt" "$bridge/station-client.key" \
  "$bridge/audit-server-ca.crt" "$audit_origin" audit

# The TLS layer must reject both an unauthenticated client and the wrong,
# independently generated server trust root.
expect_tls_failure no-client-certificate \
  --cacert "$bridge/control-server-ca.crt"
expect_tls_failure cross-server-ca \
  --cert "$bridge/station-client.crt" \
  --key "$bridge/station-client.key" \
  --cacert "$bridge/audit-server-ca.crt"

# These GETs exercise role binding without creating durable authority state.
expect_status 404 \
  "$workflow/station-client.crt" "$workflow/station-client.key" \
  "$workflow/control-server-ca.crt" \
  "$control_origin/api/v1/transactions/kaiba-smoke-missing" station-control
expect_status 401 \
  "$approver/client.crt" "$approver/client.key" \
  "$approver/control-server-ca.crt" \
  "$control_origin/api/v1/transactions/kaiba-smoke-missing" approver-control
expect_status 200 \
  "$workflow/station-client.crt" "$workflow/station-client.key" \
  "$workflow/audit-server-ca.crt" \
  "$audit_origin/api/v1/events" station-audit
expect_status 401 \
  "$approver/client.crt" "$approver/client.key" \
  "$approver/audit-server-ca.crt" \
  "$audit_origin/api/v1/events" approver-audit

printf 'authority smoke: OK: positive and negative mutual-TLS probes passed; no authority write was requested\n'
