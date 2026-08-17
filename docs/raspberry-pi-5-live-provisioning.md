# Raspberry Pi 5 live secure-boot foundation

This document describes the first hardware-facing Kaiba provisioning
foundation. It is a development-cohort system for one dedicated Raspberry Pi
5 station, one fixed lane, and one sacrificial Raspberry Pi 5 target with NVMe
storage. It implements secure-boot preparation and bounded one-shot mutation,
reconciliation, and owned-device verification components without claiming a
complete deployment or production enrollment path.

The successful terminal lifecycle is `security_applied`. The implementation
cannot enter `enrollment_ready`: native Raspberry Pi secure boot accepts an
older correctly signed image, and this milestone has no independently
monotonic rollback state. A UI action, API request, or control-plane command
that attempts to bypass that gate must be rejected.

The existing metadata-only probe and browser demo retain their current safety
boundaries. The fresh-board profile is not changed to accept an owned key hash,
and the public transition graph is never a fallback for the live station.

## Deployment topology

```text
development control host                    dedicated Pi 5 station
+--------------------------------+          +-------------------------------+
| reference control + inventory  |  mTLS    | loopback operator UI          |
| independent audit service      |<-------->| state machine (no IPC bridge) |
| content-addressed artifacts    |          | root one-shot guard + journal |
| approval-gated signer          |          | RPIBOOT + UART + power relay  |
| development YubiKey, PIV 9c    |          +---------------+---------------+
+--------------------------------+                          |
                                                          v
                                              sacrificial Pi 5 + NVMe
```

The target lane and management network are not bridged or routed. The signer
runs on the control host, not the station. The station UI is loopback-only and
has no direct USB, UART, GPIO, PKCS#11, artifact-path, or key-selection access.

## Development boot-root ceremony

The development YubiKey contains one shared development-cohort RSA-2048 boot
key. This is not a device identity key, storage key, or per-device secret. Its
public key is installed in signed EEPROM artifacts and its canonical hash is
the irreversible value programmed into target OTP.

The Pi does not generate or retain this private key: BCM2712 OTP retains only
the customer public-key hash. There is therefore no device boot-signing private
key to export from the first Pi. A distinct externally held signing key could
be assigned to every board, but native secure boot does not require that and it
would turn every bootloader or OS update into a per-device signing operation.
This deliberately sacrificial milestone uses one cohort key; later device
identity and storage keys remain unique per device and separate from it.

Before generating the key, change the YubiKey's default PIN, PUK, and
management key through an interactive administrator ceremony. Do not place any
of those values in Git, Nix expressions, command arguments, environment
variables, service configuration, or logs. Generate the key on the token:

```console
ykman piv keys generate \
  --algorithm RSA2048 \
  --pin-policy ALWAYS \
  --touch-policy ALWAYS \
  9c development-boot-public.pem
```

Retain the public key, token serial, PIV attestation, YKCS11 object URI,
signer-policy digest, and both relevant public digests:

- the ordinary public-key fingerprint identifying the signer object; and
- the canonical Raspberry Pi customer-key hash produced by the pinned EEPROM
  tooling and expected in `CUSTOMER_KEY_HASH` readback.

Those values are not interchangeable. In particular, do not substitute a hash
of PEM text for the Raspberry Pi customer-key hash.

The private key is non-exportable. This development milestone intentionally
has no backup token or escrow copy. Loss or failure of the YubiKey makes every
board in this development cohort unable to accept newly signed boot, EEPROM,
or recovery artifacts. Such boards are sacrificial and must be labelled as
such. The production YubiKey is not used or initialized by this workflow.

## Unsigned and signed artifacts

`lib.mkRpi5SecureBootArtifacts` is the public Nix builder for the unsigned
artifact boundary. Callers provide a populated Pi firmware tree, an immutable
ext4 root image, an exact relative-path allowlist for every firmware-tree file,
the source revision, and the expected development customer-key hash. The
derivation rejects symlinks, unexpected files, non-NVMe verity devices, and a
boot image above the documented 96 MiB ceiling. The root Pi 5 target also
removes shared-builder files that Pi 5 does not consume (`bootcode.bin`,
`start*.elf`, `fixup*.dat`, and generation-link metadata). It produces:

```text
manifest.json
unsigned/boot.img
nvme/root-data.img
nvme/root-hash.img
```

The root data and dm-verity hash tree are deterministic. The verity root hash
is placed in the active, `os_prefix`-qualified command line
(`nixos/default/cmdline.txt` for this target) inside `boot.img`, so it becomes
trusted only after the outer image is signed. The manifest always declares:

- tmpfs-only mutable state;
- rollback unimplemented and enrollment blocked;
- development JTAG and EEPROM write protection left unlocked; and
- an unsigned signing status.

No signing key, PIN, PKCS#11 module state, or signature is allowed in a Nix
derivation. On the control host, the strict bundle model and root-managed
signing-grant registry bind artifact roles and digests to an approval before
passing bytes to the signer. The signer supports exactly Raspberry Pi's HSM
wrapper operation:

```console
kaiba-provision-signer -a rsa2048-sha256 INPUT_FILE
```

Its immutable build configuration fixes the approval-gated backend, YubiKey
PKCS#11 URI, signer and cohort identifiers, and public fingerprint. It accepts
no runtime key, slot, provider, executable, or algorithm selection. Each
signature requires a PIV PIN operation and physical touch. The signed bundle
must contain, and offline verification must cover, the EEPROM image, normal
`boot.img`/`boot.sig`, fresh-board commit bundle, and owned-device recovery
bundle before a transaction can receive commit approval.

The repository does not yet provide the release adapter that constructs that
complete signed bundle. In particular, it does not invoke the pinned Raspberry
Pi tooling to produce `boot.sig`, the signed EEPROM image, the fresh commit
bundle, or the owned recovery bundle; nor does it resolve every manifest entry
to artifact bytes. Those artifacts must be produced and independently checked
by a reviewed control-host release procedure before their immutable Nix-store
paths are supplied to `lib.mkRpi5PhysicalLaneGuard`.

Likewise, the artifact builder produces the three images but no current
component writes `boot.img`/`boot.sig`, `root-data.img`, or `root-hash.img` to
the target NVMe. Staging and cold readback of those exact digests is a separate
reviewed hardware step for this milestone. Do not infer that the lane guard or
loopback UI performs it.

## Nix entry points

The public construction boundaries are:

- root `lib.mkRpi5SecureBootTarget`, which evaluates the Pi target and exposes
  `firmwareTree`, `rootImage`, and `unsignedArtifacts`;
- provisioning-leaf `lib.mkDevelopmentYubiKeySigning`, which requires the
  reviewed public key, its SPKI fingerprint, its expected Raspberry Pi
  customer-key hash, token serial, signer/cohort IDs, and an external
  root-managed grant-registry path. Its build runs the pinned Raspberry Pi key
  converter and refuses to produce the signer package unless the SHA-256 of
  the resulting 264-byte key representation matches that expected hash;
- provisioning-leaf `lib.mkRpi5PhysicalLaneGuard`, which requires immutable
  store paths for every recovery/test bundle plus linker-fixed signed-release,
  guard-package, compiled-artifact-set, customer-key, EEPROM, and boot-image
  digests; and
- the `provisioning-signing-gate`, `provisioning-control`,
  `provisioning-audit`, and `provisioning-lane-guard` NixOS modules.

There is intentionally no checked-in deployment instance: the real token
serial, public key, customer-key hash, EEPROM digest, physical USB/UART/GPIO
selectors, TLS credentials, approvals, and recovery bundles are deployment
inputs. Generic signer and lane-guard packages fail closed until constructed
through their factories.

## Station and control-plane state

The control plane owns the transaction, inventory binding, renewable claim,
fence epoch, plan approval, quarantine state, and `security_applied` record.
Every mutation request carries the expected resource version, active claim,
fence epoch, target fingerprint, plan digest, operation digest, and
idempotency key. Reacquiring or transferring a claim increments the fence
epoch and invalidates prior approval.

The independent audit service stores a strict, secret-free hash chain and
returns a durable receipt. Its files and process identity are separate from
the coordinator. The station journal is a recovery replica, not authority for
inventory or audit history.

Every mutual-TLS station credential used with the reference control or audit
service must contain exactly one URI SAN in this canonical form:

```text
spiffe://kaiba.network/station/<station-id>/lane/<lane-id>
```

The services derive both identities only from the verified client-certificate
chain. A subject common name is never a fallback, and a missing, malformed, or
multiple URI SAN fails authentication. The control service compares claim
acquisition with the requested station and lane, and compares every
claim-scoped command and transaction read with the active claim. A transfer
must be authorized by the current claimant; it advances the fence and changes
the active station/lane binding. The old certificate is rejected immediately
afterward, and the new station/lane certificate is required for the next
claim-scoped command. The audit service compares each append with the event's
station and lane and limits reads to records for the authenticated pair. A
valid but mismatched identity is forbidden before state can change.

Plain HTTP remains available only on an explicit IPv4 or IPv6 loopback address
for local development, where there is deliberately no certificate identity to
bind. It is not a deployment mode: the CLI rejects plaintext on a non-loopback
address, and enabling TLS also enables the URI-SAN authorization policy even
when the TLS listener itself is on loopback.

### Current live-station boundary

`kaiba-provision-station` is currently a loopback UI and state-machine
foundation, not a mutation-capable orchestrator. It deliberately rejects
`--enable-mutations`. The privileged lane guard is a separate, manually
started one-shot service whose approved plan and request must be installed by
root below `/var/lib/kaiba-provision-lane-guard` before each invocation. It
recomputes the domain-separated digest of every operation and of the ordered
plan, and requires the plan's signed-release, guard-package,
compiled-artifact-set, key, EEPROM, and boot-image digests to match the
linker-fixed physical build before constructing the hardware adapter. The
physical package can report those public linker values for a build-time wiring
check. A value mismatch therefore fails closed, but the pending release adapter
must still derive the guard-package and artifact-set values from actual
path-and-content material. Those
consistency checks do not make a root-authored plan authoritative: root can
also construct a different plan and binary with matching digests.

Do not run the HTTP station process as root or give it direct access to the
lane-guard state directory or device nodes. Completing that bridge requires a
dedicated authenticated IPC service that translates already-approved control
and audit records into the guard's closed plan/request contract; the current
live backend interface does not carry enough of those bindings to do so
without weakening the privilege boundary.

The live station uses the following order for every irreversible operation:

```text
validate exact preconditions
-> fsync local intent
-> obtain durable remote audit receipt
-> execute exactly once through the lane guard
-> directly observe target state
-> fsync evidence and reconcile central state
```

An unknown result transitions to `reconciliation_required`. It never retries
the operation. A changed target, stale epoch, missing approval, audit outage,
or unverifiable owned state results in quarantine.

## Physical lane

Provision the station with one fixed lane configuration:

- one stable BCM2712 RPIBOOT USB topology path;
- one UART adapter selected by `/dev/serial/by-id`, not `ttyUSB` numbering;
- one electrically appropriate, isolated power relay driven by a fixed GPIO
  chip and line; and
- no hub, device, UART, GPIO, or payload selector exposed to the browser.

Qualify the relay and UART independently before connecting a target. Confirm
that removing lane power removes *all* target power, including back-power from
UART or USB. Confirm that UART ground and voltage levels are correct for the
Pi. A relay transition is not accepted as proof of power removal; the lane
guard must observe target disappearance and the configured cold interval.

## Transaction sequence

1. Admit the station only when its source revision, configuration, identity,
   journal, time, control services, audit export, and empty lane are healthy.
2. Create the central transaction, acquire its mutation claim, and bind the
   fixed station and lane.
3. Run the existing two-pass fresh qualification with complete target power
   removal and normal-boot confirmation between observations.
4. Close every deferred baseline check: storage, remaining OTP rows, EEPROM
   contents and policy, inventory history, firmware authenticity, and debug or
   alternate paths.
5. Resolve and verify the complete signed bundle. Perform offline signature
   checks and an unfused `boot_ramdisk=1` compatibility boot.
6. Through the separate reviewed NVMe procedure, write the exact approved
   boot, root-data, and root-hash artifacts to their fixed partitions; cold
   read them back and compare their digests. The current repository does not
   implement this writer.
7. Approve the exact target, current fence epoch, plan, expected key hash, and
   ordered operation set. The development exception permits one person to use
   separate named operator and approver sessions; this is forbidden for a
   production trust domain.
8. Re-identify the same zero-key target immediately before commit, fsync and
   export intent, then run the fresh commit bundle once.
9. Reconcile RPIBOOT metadata and require the expected customer-key hash,
   secure-boot provisioning result, EEPROM update result, and EEPROM digest.
10. Remove all power through the lane relay and cold-boot the signed NVMe image.
   Capture UART and verify customer-key bit 3 of the bootloader `signed`
   property plus the mandatory, manifest-matching `boot_img_sha256` value.
   Absence of that property is a preflight failure for this milestone.
11. Run the separately signed owned-device readback, prove authorized recovery,
    reject stock recovery, rerun owned readback, and test altered, unsigned,
    wrong-key, alternate-media, and dm-verity-tampered inputs.
12. Reconcile the terminal audit record and record `security_applied` with the
    explicit development release classification.

The first milestone does not program a BCM2712 device-private storage secret,
does not create persistent mutable state, does not lock VideoCore JTAG, and
does not apply EEPROM hardware write protection. These omissions are recorded
policy, not successful production postconditions.

## Required failure drills

Before using the mutation backend, the fake lane and then the physical rig must
exercise process crash, station reboot, power loss, USB replacement, UART
loss, relay failure, YubiKey removal, wrong token, PIN/touch timeout, expired
approval, transferred claim, stale fence epoch, signer mismatch, audit outage,
and failure before, during, and after the OTP command.

No drill may repeat a one-way operation based only on a timeout or missing
response. Any partially owned or uncertain board is permanently excluded from
the fresh-device path and remains `owned_quarantined` until a separately
authorized recovery or retirement procedure exists.

## Deferred production gates

The following are intentionally outside this implementation and block a
production claim:

- a monotonic anti-rollback mechanism;
- device-specific identity and operational key generation;
- certificate issuance, pending verification, activation, and production
  authentication;
- encrypted persistent mutable state and its recovery design;
- separate human operator and approver enforcement;
- production boot-root backup, rotation, incident, and cohort strategy;
- final JTAG, boot-order, and EEPROM write-protection qualification; and
- multi-lane scaling.
