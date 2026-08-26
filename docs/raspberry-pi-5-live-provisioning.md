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

## Approved one-unit development posture

For the single sacrificial target, the approved EEPROM configuration uses
`BOOT_ORDER=0xf216`. Raspberry Pi processes this value from right to left, so
the target tries NVMe (`6`), then SD (`1`), then network/TFTP (`2`), and then
restarts the sequence (`f`). `ENABLE_SELF_UPDATE=0` disables automatic
bootloader self-update scanning, but it does not disable a separately
authorized RPIBOOT update or make an unlocked EEPROM immutable.

VideoCore JTAG and EEPROM hardware write protection remain unlocked. The
fresh-board EEPROM/key change is exactly one transaction-bound RPIBOOT commit,
using an exact expected prestate and signed EEPROM, followed by authoritative
readback. A timeout, lost response, or other uncertainty never authorizes a
retry. Owned recovery is limited to a prebuilt, independently verified,
customer-key-signed RPIBOOT bundle with narrowly bounded capabilities. The
bundle must be ready before ownership, but it must not execute until the board
is owned by the customer key. The persistent root is read-only and dm-verity
protected; permitted mutable state is tmpfs-only. Anti-rollback is
unimplemented, so the unit stops at `security_applied` and cannot enter
enrollment.

Boot-media hardware identity is deliberately outside this policy. NVMe model,
serial, WWID, and `/dev/disk/by-id` are neither boot-trust inputs nor persistent
plan or evidence fields. The station's versioned, typed hardware configuration
supplies one linker-fixed raw whole-device or `/dev/disk/by-path` selector only
as local operational configuration. The checked-in sacrificial-development
configuration selects `/dev/nvme0n1`; neither that selector nor its
configuration ID enters canonical plans, receipts, or evidence. The media tools
still reject partitions, mounts, root/system/swap devices, holders, and slaves;
check exact per-run capacity and a 512-byte logical sector for layout
compatibility; and pin the opened attachment within each operation. They do not
appraise initial contents or establish media identity. Offline signed-artifact
verification remains a software foundation; live signed-system boot observation
and enforcement occur later in the hardware campaign.

The development boot order and unlocked VideoCore JTAG are **not
production-ready**. Their production values are undecided and require separate
review and qualification before provisioning any production device. The
existing `BOOT_UART=1` is an unreviewed development setting and production
blocker, not an approved production value. The unlocked EEPROM write-protection
posture and other deferred policies likewise remain production blockers.

## Deployment topology

```text
development control host                    dedicated Pi 5 station
+--------------------------------+          +-------------------------------+
| reference control + inventory  |  mTLS    | loopback UI + state machine   |
| independent audit service      |<-------->| authority bridge + private IPC|
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

No signing key, PIN, PKCS#11 module state, or private-key operation is allowed
in a Nix derivation. Public signatures may be imported only as fixed inputs to
an offline-verification derivation. On the control host, the strict bundle
model and root-managed signing-grant registry bind artifact roles and digests
to an approval before passing bytes to the signer. The signer supports exactly
Raspberry Pi's HSM wrapper operation:

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

The repository now provides the narrow normal-boot signing slice: a pure Nix
plan, a linker-fixed runtime adapter that obtains an approval-gated signature,
strict canonical Raspberry Pi `boot.sig` encoding, and a pure offline finalizer
that emits the unchanged `boot.img`, `boot.sig`, reviewed `public.pem`, and
public records. See the
[signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md).

The repository now constructs a complete, content-addressed signed-release
publication with the exact 18-role manifest and canonical RPIBOOT directory
trees. The offline finalizer resolves every role to immutable bytes, verifies
the complete public signature and release-intent lineage, and reopens the
published result. The physical lane factory accepts only that typed verified
publication, takes its six bundle paths from the retained verified bundle-set
provenance, and derives the four release expectations from the publication and
manifest. Its checked fixture is synthetic: reviewed production bytes and
live-token ceremony evidence must still be completed before an ownership
commit.

The production-media factory derives a plan-specialized device stager and an
independent verifier from that verified release and exact per-run layout
geometry. It consumes the selector through the typed hardware configuration
and fixes it outside its canonical plan, receipts, and evidence. The tools can
write and cold-read the manifest-bound boot, root-data, and root-hash bytes, but
that cold readback proves expected contents on a fresh attachment, not
continuity of one physical medium. The repository has not recorded that
physical campaign or a live signed boot. The lane guard and loopback UI still
do not stage media themselves.

## Nix entry points

The public construction boundaries are:

- provisioning-leaf `lib.hardwareConfigurations`, the versioned typed catalog
  of station-local hardware wiring used by capability-specialized factories;
- root `lib.mkRpi5SecureBootTarget`, which evaluates the Pi target and exposes
  `firmwareTree`, `rootImage`, and `unsignedArtifacts`;
- provisioning-leaf `lib.mkDevelopmentYubiKeySigning`, which requires the
  reviewed public key, its SPKI fingerprint, its expected Raspberry Pi
  customer-key hash, signer-policy digest, token serial, signer/cohort IDs, and
  an external root-managed grant-registry path. Its build runs the pinned
  Raspberry Pi key converter and refuses to produce the signer package unless
  the SHA-256 of the resulting 264-byte key representation matches that
  expected hash. It also exposes the configured `kaiba-provision-sign-boot`
  runtime adapter;
- provisioning-leaf `lib.mkRpi5BootSigningPlan`, which binds one immutable
  `boot.img` to the reviewed public key, signer policy, plan ID, and release
  timestamp without any signing authority;
- provisioning-leaf `lib.mkRpi5VerifiedSignedBoot`, which consumes a public
  runtime signing result, verifies every binding and the Raspberry Pi
  signature, and emits a self-contained public bundle without key access;
- provisioning-leaf `lib.mkRpi5PhysicalLaneGuard`, which accepts one typed
  `mkRpi5VerifiedSignedRelease` publication, takes the six recovery/test bundle
  paths from its verified bundle-set provenance, and derives signed-release,
  customer-key, EEPROM, and boot-image expectations from its publication and
  manifest during the build. It derives the guard-package and
  compiled-artifact-set identities from the actual executable, paths, file
  bytes, modes, sizes, and canonical directory trees; and
- the `provisioning-signing-gate`, `provisioning-control`,
  `provisioning-audit`, `provisioning-authority-bridge`, and
  `provisioning-lane-guard` NixOS modules.

The repository contains one checked-in, public-only deployment instance for
the explicitly sacrificial development prototype. It records the development
token serial, reviewed public key, customer-key hash, and signer-policy digest
under [`provisioning/signers/development-prototype`](../provisioning/signers/development-prototype/README.md).
That exception contains no credential or signing authority and is not approved
for production. A separate checked-in public-only hardware configuration under
[`provisioning/config/hardware`](../provisioning/config/hardware/) selects the
sacrificial station's target-media path; that path is operational wiring and is
not copied into plans, receipts, or evidence. Production target-media hardware
configurations, signer metadata, EEPROM digests, physical USB/UART/GPIO
selectors, TLS credentials, approvals, grants, and recovery bundles remain
external deployment inputs. Generic signer and lane-guard packages still fail
closed until constructed through their factories.

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
claim-scoped command. After release, transaction reads remain limited to the
highest-fence historical claimant; a never-claimed transaction has no mTLS
reader. The audit service compares each append with the event's station and
lane, and broad reads remain limited to records for the authenticated pair.
The authenticated bridge has one narrow exception for transferred-claim
reconciliation: it may request at most eight exact, canonical receipt IDs for
one required transaction. Those high-entropy receipt IDs act as read
capabilities, remain confined by the control-read policy, and must not be
logged or disclosed as public identifiers. A valid but mismatched identity is
forbidden before state can change.

Plan approval uses a separate certificate identity:

```text
spiffe://kaiba.network/approver/<approver-id>
```

The control `record_approval` command and audit `plan_approval` append require
that exact approver identity to match the recorded actor. Station credentials
cannot approve, and approver credentials cannot invoke station/lane endpoints.

Plain HTTP remains available only on an explicit IPv4 or IPv6 loopback address
for local development, where there is deliberately no certificate identity to
bind. It is not a deployment mode: the CLI rejects plaintext on a non-loopback
address, and enabling TLS also enables the URI-SAN authorization policy even
when the TLS listener itself is on loopback.

### Current live-station boundary

`kaiba-provision-station` remains an unprivileged loopback UI and state-machine
foundation, not a mutation-capable orchestrator. It deliberately rejects
`--enable-mutations`. The privileged lane guard is a separate, manually
started one-shot service. Root installs only an authority-free reviewed draft
below `/var/lib/kaiba-provision-lane-guard`; the guard obtains the current
executable plan/request pair from `kaiba-provision-authority-bridge` over its
private Unix socket. The bridge authenticates the control and audit services
with TLS 1.3, a fixed station/lane client certificate, and separate exclusive
server trust roots. It double-reads control around the audit read and rejects a
changed snapshot before binding the current operation. The lane guard then
recomputes the `v1alpha4` domain-separated digest of every operation and of the
ordered plan, reopens and hashes the actual guard executable and eight
immutable artifact paths, and requires the plan's six-field release binding to
match the derived result before constructing the hardware adapter. Each
operation's digest-bound `required_boot_mode` follows a closed policy:
`cold_power_cycle` requires `normal`, while the other six development
operations require `rpiboot`. Loading that validated plan only snapshots its
contents and restores durable journal lockout state; it neither powers nor
observes the target. Execution or reconciliation owns the first target-facing
observation and continues to perform physical I/O. The physical package can
print both the public binding and the complete canonical review material. A
byte, path, mode, size, directory-tree, or release-expectation mismatch
therefore fails closed; package and artifact-set digests are never accepted as
opaque factory arguments.

Do not run the HTTP station process as root or give it direct access to the
lane-guard state directory, bridge socket, or device nodes. The bridge exposes
no browser endpoint, executable path, payload selector, hardware selector, or
generic mutation request.

The authority bridge exposes separate, strict execute and reconciliation
contracts. After an unknown result, claim reconstruction advances the fence
and clears current forward-mutation approval. The operation record retains the
original approval snapshot, and reconciliation reconstructs the exact original
plan and attempt from that snapshot plus its durable approval and intent audit
receipts. A fresh, short-lived reconciliation claim authorizes observation
only; it cannot be converted into an execute request and the lane guard never
redispatches the operation. Exact owned state becomes confirmed-applied; the
exact original fresh prestate becomes terminal confirmed-not-applied. Neither
outcome authorizes replay of the old request, and current policy refuses a new
mutation claim after confirmed-not-applied until a separate retry protocol is
reviewed. The combined authenticated restart test exercises both outcomes
through reopened control, audit, and dedicated v1alpha1 attempt-journal stores
and the real physical adapter with only target-facing I/O simulated. The
current plan contract is `lane-guard/v1alpha4`; old plans, approvals, intents,
requests, and attempt records bound to `v1alpha3` digests are not reusable.
Prior shared `lane-guard/v1alpha3` journal envelopes are not auto-migrated.
This remains software-only evidence: uncertain live mutation recovery still
requires the documented sacrificial-hardware qualification before production
use.

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
4. Close every deferred baseline check: obtain explicit destructive-use
   authorization for the selected storage without appraising its contents or
   binding a storage identity, and close the remaining OTP rows, EEPROM contents
   and policy, inventory history, firmware authenticity, and debug or alternate
   paths.
5. Resolve and verify the complete signed bundle. Perform offline signature
   checks and an unfused `boot_ramdisk=1` compatibility boot.
6. Through the separate reviewed, plan-specialized NVMe stager, write the exact
   approved boot, root-data, and root-hash artifacts to their fixed partitions;
   cold-read them through the independent verifier and compare their complete
   manifest-bound layout and digests on a fresh attachment. Treat this as
   content evidence only, not storage identity or live signed-boot evidence.
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
    wrong-key, alternate-media, and dm-verity-tampered inputs. Isolate SD and
    network/TFTP in turn, testing each with unsigned and wrong-key images plus
    an older correctly development-key-signed image. Unsigned and wrong-key
    candidates must not execute; a correctly signed older candidate may
    execute and must demonstrate that enrollment remains blocked.
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
- final JTAG, `BOOT_UART`, boot-order, self-update, recovery, and EEPROM
  write-protection qualification; and
- multi-lane scaling.
