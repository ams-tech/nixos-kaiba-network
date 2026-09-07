#!/bin/bash
set +x
set -euo pipefail

export LC_ALL=C
system_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [[ -n "${KAIBA_AUTHORITY_TEST_PATH:-}" ]]; then
  (( EUID != 0 )) || {
    printf 'development PKI: FAIL: test PATH override is forbidden for root\n' >&2
    exit 1
  }
  export PATH="$KAIBA_AUTHORITY_TEST_PATH:$system_path"
  unset KAIBA_AUTHORITY_TEST_PATH
else
  export PATH=$system_path
fi
readonly system_path
umask 077

die() {
  printf 'development PKI: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  kaiba-provision-authority-development-pki --output ABSOLUTE_NEW_DIRECTORY

Create one development-only mutual-TLS packet for the fixed deployment. The
output directory must not exist. The generator issues distinct bridge and
lane-workflow keys for the exact configured station/lane identity, plus the
independent approver identity. CA private keys are unlinked after issuance and
are not retained in the packet; this is not secure-erasure terminology.
EOF
}

output_directory=
while (( $# > 0 )); do
  case "$1" in
    --output)
      (( $# >= 2 )) || die "--output requires a value"
      output_directory=$2
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

[[ -n "$output_directory" ]] || die "--output is required"
[[ "$output_directory" == /* && "$output_directory" != / ]] ||
  die "--output must be an absolute path other than /"
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] ||
  die "output path already exists"

for command_name in awk cmp find openssl readlink sha256sum sort stat xargs; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command is unavailable: $command_name"
done

script_path="$(readlink -f -- "${BASH_SOURCE[0]}" || true)"
[[ -n "$script_path" ]] || die "could not resolve the generator path"
source_directory="$(dirname -- "$script_path")"
if [[ -f "$source_directory/deployment.conf" ]]; then
  config_path="$source_directory/deployment.conf"
else
  config_path=/etc/kaiba-provisioning/authority-deployment.conf
fi
[[ -f "$config_path" && ! -L "$config_path" ]] ||
  die "fixed deployment configuration is unavailable"

config_value() {
  local key=$1 count value
  count="$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$config_path")"
  [[ "$count" == 1 ]] || die "deployment configuration must contain exactly one $key"
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' "$config_path")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || die "invalid $key value"
  printf '%s\n' "$value"
}

listen_address="$(config_value LISTEN_ADDRESS)"
station_uri="$(config_value STATION_URI)"
approver_uri="$(config_value APPROVER_URI)"
[[ "$listen_address" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] ||
  die "the fixed listener is not a concrete IPv4 address"
[[ "$station_uri" =~ ^spiffe://kaiba\.network/station/[a-z0-9][a-z0-9._-]*/lane/[a-z0-9][a-z0-9._-]*$ ]] ||
  die "the fixed station URI is malformed"
[[ "$approver_uri" =~ ^spiffe://kaiba\.network/approver/[a-z0-9][a-z0-9._-]*$ ]] ||
  die "the fixed approver URI is malformed"

parent_directory="$(dirname -- "$output_directory")"
[[ -d "$parent_directory" && ! -L "$parent_directory" ]] ||
  die "output parent must be an existing non-symlink directory"
parent_directory="$(readlink -f -- "$parent_directory")" ||
  die "could not resolve output parent"
output_name="$(basename -- "$output_directory")"
[[ "$output_name" != . && "$output_name" != .. && "$output_name" != *[[:space:]]* ]] ||
  die "output directory name is unsafe"
output_directory="$parent_directory/$output_name"

cleanup_required=true
cleanup() {
  if $cleanup_required && [[ -d "$output_directory" ]]; then
    chmod -R u+w -- "$output_directory" 2>/dev/null || true
    rm -rf -- "$output_directory"
  fi
}
trap cleanup EXIT HUP INT TERM

install -d -m 0700 \
  "$output_directory" \
  "$output_directory/work" \
  "$output_directory/authority" \
  "$output_directory/station" \
  "$output_directory/station/bridge" \
  "$output_directory/station/lane-workflow" \
  "$output_directory/approver"

work="$output_directory/work"

make_ca() {
  local name=$1 common_name=$2
  openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out "$work/$name.key" >/dev/null 2>&1
  openssl req -new -x509 -sha256 -days 30 -set_serial 1 \
    -key "$work/$name.key" \
    -subj "/CN=$common_name" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "$work/$name.crt"
}

issue_certificate() {
  local ca_name=$1 name=$2 common_name=$3 san=$4 eku=$5 serial=$6

  openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out "$work/$name.key" >/dev/null 2>&1
  openssl req -new -sha256 \
    -key "$work/$name.key" \
    -subj "/CN=$common_name" \
    -out "$work/$name.csr"
  {
    printf '%s\n' 'basicConstraints=critical,CA:FALSE'
    printf '%s\n' 'keyUsage=critical,digitalSignature,keyEncipherment'
    printf 'extendedKeyUsage=%s\n' "$eku"
    printf 'subjectAltName=%s\n' "$san"
  } >"$work/$name.ext"
  openssl x509 -req -sha256 -days 30 -set_serial "$serial" \
    -in "$work/$name.csr" \
    -CA "$work/$ca_name.crt" \
    -CAkey "$work/$ca_name.key" \
    -extfile "$work/$name.ext" \
    -out "$work/$name.crt" >/dev/null 2>&1
}

make_ca control-server-ca 'Kaiba v0.1.6 development control server CA'
make_ca audit-server-ca 'Kaiba v0.1.6 development audit server CA'
make_ca client-ca 'Kaiba v0.1.6 development authority client CA'

issue_certificate \
  control-server-ca control-server 'Kaiba development control authority' \
  "IP:$listen_address" serverAuth 11
issue_certificate \
  audit-server-ca audit-server 'Kaiba development audit authority' \
  "IP:$listen_address" serverAuth 12
issue_certificate \
  client-ca station-bridge-client 'Kaiba development station authority bridge' \
  "URI:$station_uri" clientAuth 21
issue_certificate \
  client-ca station-operator-client 'Kaiba development station lane workflow' \
  "URI:$station_uri" clientAuth 22
issue_certificate \
  client-ca approver-client 'Kaiba development independent approver' \
  "URI:$approver_uri" clientAuth 23

install -m 0444 \
  "$work/control-server-ca.crt" \
  "$work/control-server.crt" \
  "$work/audit-server-ca.crt" \
  "$work/audit-server.crt" \
  "$work/client-ca.crt" \
  "$output_directory/authority/"
install -m 0400 \
  "$work/control-server.key" \
  "$work/audit-server.key" \
  "$output_directory/authority/"

install -m 0444 \
  "$work/station-bridge-client.crt" \
  "$output_directory/station/bridge/station-client.crt"
install -m 0400 \
  "$work/station-bridge-client.key" \
  "$output_directory/station/bridge/station-client.key"
install -m 0444 \
  "$work/control-server-ca.crt" \
  "$work/audit-server-ca.crt" \
  "$output_directory/station/bridge/"

install -m 0444 \
  "$work/station-operator-client.crt" \
  "$output_directory/station/lane-workflow/station-client.crt"
install -m 0400 \
  "$work/station-operator-client.key" \
  "$output_directory/station/lane-workflow/station-client.key"
install -m 0444 \
  "$work/control-server-ca.crt" \
  "$work/audit-server-ca.crt" \
  "$output_directory/station/lane-workflow/"

install -m 0444 "$work/approver-client.crt" "$output_directory/approver/client.crt"
install -m 0400 "$work/approver-client.key" "$output_directory/approver/client.key"
install -m 0444 \
  "$work/control-server-ca.crt" \
  "$work/audit-server-ca.crt" \
  "$output_directory/approver/"

rm -rf -- "$work"

write_packet_checksums() {
  local directory=$1
  shift
  (
    cd "$directory"
    printf '%s\n' "$@" | sort | xargs sha256sum >SHA256SUMS
  )
  chmod 0444 "$directory/SHA256SUMS"
}

write_packet_checksums "$output_directory/station/bridge" \
  audit-server-ca.crt \
  control-server-ca.crt \
  station-client.crt \
  station-client.key
write_packet_checksums "$output_directory/station/lane-workflow" \
  audit-server-ca.crt \
  control-server-ca.crt \
  station-client.crt \
  station-client.key
write_packet_checksums "$output_directory/approver" \
  audit-server-ca.crt \
  client.crt \
  client.key \
  control-server-ca.crt

cat >"$output_directory/manifest.conf" <<EOF
SCHEMA_VERSION=kaiba.provisioning.development-authority-pki/v1alpha2
LISTEN_ADDRESS=$listen_address
STATION_URI=$station_uri
APPROVER_URI=$approver_uri
STATION_CREDENTIAL_KEYS=distinct_bridge_and_lane_workflow
CONTROL_SERVER_CA=distinct_ephemeral_unlinked_not_retained
AUDIT_SERVER_CA=distinct_ephemeral_unlinked_not_retained
CLIENT_CA=shared_for_exact_role_separated_clients_ephemeral_unlinked_not_retained
CA_PRIVATE_KEYS_RETAINED=false
EOF
chmod 0444 "$output_directory/manifest.conf"

(
  cd "$output_directory"
  find authority station approver -type f -printf '%p\n' |
    sort |
    xargs sha256sum >SHA256SUMS
)
chmod 0444 "$output_directory/SHA256SUMS"
chmod 0700 \
  "$output_directory" \
  "$output_directory/authority" \
  "$output_directory/station" \
  "$output_directory/station/bridge" \
  "$output_directory/station/lane-workflow" \
  "$output_directory/approver"

cleanup_required=false
trap - EXIT HUP INT TERM
printf 'development PKI: OK: exact fixed packet created at %s; no CA private key is retained\n' \
  "$output_directory"
