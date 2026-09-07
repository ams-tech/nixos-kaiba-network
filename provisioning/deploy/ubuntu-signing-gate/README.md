# Ubuntu 24.04 signing-gate deployment

This bundle installs the repository's immutable, approval-gated development
YubiKey signer on a dedicated Ubuntu 24.04 control host. Installation is inert:
it does not enable or start the gate, read a PIN, enumerate a smartcard, invoke
PKCS#11, or submit a signing request.

The service accepts only the fixed authority compiled into the selected
`mkDevelopmentYubiKeySigning` Nix output. The package fixes the token serial,
PIV slot, public key, signer/cohort IDs, provider modules, grant registry,
socket, state directory, and systemd credential destination. The installer
accepts only the package store path; none of those selectors can be overridden
at runtime.

`--staging-root` is exclusively a non-root test mode. It writes a self-contained
in-image comparison baseline so the fixture is relocatable, but that baseline
is mutable by the test owner and is not a deployment trust anchor. Never boot
or deploy a staging root. Pre-create it as a caller-owned, ACL-free directory
with mode `0700`; the installer rejects root callers and unsafe root metadata.
Live installation accepts only the verified Nix deployment output.

## Fixed host boundary

| Object | Path and access |
| --- | --- |
| Service identity | `kaiba-signing:kaiba-signing`; locked system user, no supplementary groups |
| Reviewed grants | `/etc/kaiba-provisioning/signing-grants.json`; `root:kaiba-signing`, mode `0440`; parent mode `0750` |
| PIN source | `/run/kaiba-provision-signing-credentials/yubikey-pin`; `root:root`, mode `0400`, on tmpfs |
| PIN credential | `/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin`; systemd-created root ownership and one named-user read ACL |
| Durable state | `/var/lib/kaiba-provision-signing`; service-owned, mode `0700` |
| Receipt exports | `/var/lib/kaiba-provision-signing-exports`; service-owned, mode `0700`; outside durable gate state |
| Runtime/socket | `/run/kaiba-provision-signing` mode `0700`; `signing.sock` mode `0600`, both service-owned |
| PC/SC authorization | The two pcsc-lite actions are granted only to the `kaiba-signing` user by polkit |

The service sees the systemd credential copy, not the root-only source. Its
mount namespace makes the source directory inaccessible. `AF_UNIX` is the only
permitted address family, direct device access is closed, the capability sets
are empty, core dumps are disabled, and both reviewed Nix outputs are held by
direct GC roots. Static preflight compares every installed deployment asset
byte-for-byte with the pinned deployment output and rejects unit drop-ins.

## Host preparation

Install the host dependencies from Ubuntu 24.04. Do not add the service user to
`plugdev`, `scard`, or any operator group.

```console
sudo apt-get update
sudo apt-get install acl jq libccid pcscd polkitd
```

Nix must already contain both the exact configured signing output and the
immutable deployment bundle. Build them with named result links so the reviewed
paths remain available until installation:

```console
nix build path:.#development-signing \
  --out-link result-development-signing
nix build path:.#ubuntu-signing-gate-deployment \
  --out-link result-ubuntu-signing-gate-deployment
signing_path="$(readlink -e result-development-signing)"
deployment_path="$(readlink -e result-ubuntu-signing-gate-deployment)"
nix-store --query --hash "$signing_path"
nix-store --verify-path "$signing_path"
nix-store --query --hash "$deployment_path"
nix-store --verify-path "$deployment_path"
```

Before installing, review these public files in that exact output and compare
them with the release review:

```console
jq . "$signing_path/share/kaiba/signer-policy.json"
cat "$signing_path/share/kaiba/signer-policy-digest"
cat "$signing_path/share/kaiba/customer-key-hash"
```

Install the host boundary. The package path is public configuration, not a
secret. The installer creates a Nix GC root, but leaves both pcscd and the gate
untouched.

The live installer refuses a mutable source checkout. Run the copy in the
root-owned Nix deployment output:

```console
sudo "$deployment_path/share/kaiba/ubuntu-signing-gate/install.sh" \
  --package "$signing_path"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static
```

Installation is fail-closed but not transactional. A late error can leave the
locked identity, private directories, GC roots, or some static assets in place;
it never enables or starts the gate. Do not provision a PIN or start the unit
until the same reviewed installer completes and static preflight reports OK.
After a failure, inspect the reported object and either rerun the same verified
outputs after correcting the host condition or follow a separately reviewed
recovery procedure. Do not blindly remove or replace partial security objects.

Reinstalling with a different package or deployment fails while either direct
GC root names an old output. The roots are
`/nix/var/nix/gcroots/kaiba-provision-signing-gate` and
`/nix/var/nix/gcroots/kaiba-ubuntu-signing-gate-deployment`. Changing either
link is a separate reviewed authority change: stop the gate, review the new
outputs, remove only the corresponding old link explicitly, then rerun the
installer.

## Ceremony preparation

Install a separately reviewed v1alpha2 grant registry. The gate loads it once
at startup and independently validates its owner, parent, permissions, schema,
canonical ordering, request bindings, and expiry fields.

```console
sudo install -o root -g kaiba-signing -m 0440 \
  ./reviewed-signing-grants.json \
  /etc/kaiba-provisioning/signing-grants.json
sudo setfacl --remove-all -- /etc/kaiba-provisioning/signing-grants.json
```

Enable the Ubuntu pcscd activation socket. Starting the socket does not call a
token utility; pcscd itself remains policy-controlled and can auto-exit.

```console
sudo systemctl enable --now pcscd.socket
```

Provision the PIN from a controlling terminal. The helper disables shell
tracing and core dumps, accepts no secret argument or environment override,
prompts twice without echo, and atomically creates only the fixed tmpfs file.
It refuses to proceed while the gate is active or any swap is enabled, because
a tmpfs page or shell memory could otherwise be written to persistent swap.

```console
sudo swapoff --all
swap_state="$(swapon --show --noheadings)" || exit 1
test -z "$swap_state"
sudo /usr/local/sbin/kaiba-signing-gate-provision-pin
```

Run the full preflight before starting the gate. It checks metadata and the
public registry envelope but never reads the PIN value, opens PC/SC, enumerates
a reader, or invokes a signer.

```console
sudo /usr/local/sbin/kaiba-signing-gate-preflight
sudo systemctl start kaiba-provision-signing-gate.service
sudo /usr/local/sbin/kaiba-signing-gate-preflight
```

Starting the gate validates the registry, state, and systemd credential but
does not ask the YubiKey to sign. Each authorized artifact completed on its
first attempt causes two ordered private-key operations and, under the reviewed
always-touch policy, two touches: the artifact signature followed by the
gate-derived canonical receipt-attestation signature. If either operation or
the durable completion fails, intent state remains and permanently blocks
further private-key use for that grant. Stop, preserve the evidence, and begin
only a new independently authorized ceremony attempt; there is no same-grant
retry command. A new approval creates new grant identities, so all five inputs
must be signed under that registry; never combine receipts across attempts. Two
is a successful first-attempt minimum, not permission to repeat a request.
Follow the reviewed signing-plan workflow in
`docs/ubuntu-rpi5-development-signing-ceremony.md`; this deployment bundle does
not automate that ceremony.

## Close the boundary

After the ceremony, stop the service before deleting the ephemeral source.
The credential mount and private runtime/socket directory disappear with the
unit; durable anti-replay state remains mode `0700`.

```console
sudo systemctl stop kaiba-provision-signing-gate.service
sudo rm -f -- /run/kaiba-provision-signing-credentials/yubikey-pin
pin_entries="$(sudo find /run/kaiba-provision-signing-credentials \
  -mindepth 1 -maxdepth 1 -printf '%P\n')" || exit 1
test -z "$pin_entries"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static
```

The PIN source also disappears on reboot. Never move it to `/etc`, the Nix
store, a shell variable exported to the environment, a command argument, or a
log. Do not use `Environment=`, `EnvironmentFile=`, or `SetCredential=` for the
PIN. Keep this dedicated signing host swap-free. Any future decision to restore
swap belongs to a separately reviewed host-maintenance procedure after the
ceremony boundary has been closed; it is not a ceremony step.
