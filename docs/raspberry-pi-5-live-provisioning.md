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
as local operational configuration. The hostname-bound `malak` configuration
selects its fixed USB-reader by-path and protects malak's `/dev/nvme0n1`; the
separate Pi-local configuration selects `/dev/nvme0n1` only on
`kaiba-rpi5-provisioner`. A mandatory operational preflight binds that choice
and the current attachment before writable open; those fields do not enter
canonical plans or the stage, verification, and final receipts. The media tools
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
| approval-gated signer          |          | RPIBOOT + UART + fixed power  |
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
and fixes it outside its canonical plan and receipt chain while recording it in
the mandatory operational preflight. The tools can write and cold-read the
manifest-bound boot, root-data, and root-hash bytes, but that cold readback
proves expected contents on a fresh attachment, not continuity of one physical
medium. The repository has not recorded that physical campaign or a live signed
boot. The lane guard and loopback UI still do not stage media themselves.

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
copied only into the station-local operational preflight, not canonical plans or
the receipt chain. Production target-media hardware configurations, signer
metadata, EEPROM digests, physical USB/UART/GPIO selectors, TLS credentials,
approvals, grants, and recovery bundles remain external deployment inputs.
Generic signer and lane-guard packages still fail closed until constructed
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
recomputes every `v1alpha5` operation digest and the `v1alpha6` domain-separated
digest of the ordered plan, including its fixed `power_control_mode`, reopens
and hashes the actual guard executable and eight
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
redispatches the operation. An owned observation, whether it includes the
exact EEPROM digest or omits `EEPROM_HASH`, becomes confirmed-applied only when
the journal already contains the exact structured fresh-commit attestation
bound to this plan and target. The exact original fresh prestate becomes
confirmed-not-applied only when its EEPROM hash was directly observed. If the
approved fresh prestate recorded
`eeprom_hash_status: unavailable`, observing the same zero-key state cannot
prove that an interrupted commit left EEPROM unchanged: reconciliation remains
uncertain and the commit is never retried. Every conclusive and uncertain
result is a terminal stop for the old execute request. The combined
authenticated restart test exercises all three outcomes through reopened
control, audit, and current
`lane-guard-attempt-store/v1alpha5` journals containing
`lane-guard-attempt/v1alpha4` attempts and durable boot-transition records. It
uses the real physical adapter with only target-facing I/O simulated. The
current plan contract is `lane-guard/v1alpha6`; its authority-bound hardware
action uses `boot-transition-action/v1alpha2`. Mechanism-aware durable
transitions and completed evidence use `boot-transition/v1alpha3` and
`boot-transition-evidence/v1alpha3`; public references and outcomes use their
respective `v1alpha2` contracts so failed terminals cannot discard power
provenance. Digest-bound operator prompts use `operator-prompt/v1alpha2`; the
new schema closes each relay or manual prompt kind over both the boot mode and
authority-bound power-control mode. Old plans, approvals, intents,
requests, and attempts bound to older digests are not reusable. This remains
software-only evidence: uncertain live mutation recovery still requires the
documented sacrificial-hardware qualification and makes no live enforcement
claim.

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

### Nix one-shot and authenticated physical actions

The `provisioning-lane-guard` NixOS module fixes the station, lane, USB sysfs,
UART, power-control mode, journal, draft, bridge-socket, operator-socket,
attempt-directory, and execute-or-reconcile mode in one root `Type=oneshot`
unit. Relay mode additionally fixes its GPIO. Mutation remains off unless
`enableMutations = true`, and the unit has no automatic start target.
The same closed `power_control_mode` is part of the reviewed draft, canonical
plan digest, approval, intent, execute/reconcile request, and boot-transition
action. The guard rejects a plan whose mode differs from this immutable unit
configuration before target-facing I/O; changing the Nix option therefore
requires a new draft and approval rather than a runtime fallback.
The module installs only its fixed, no-argument
`kaiba-provision-lane-acknowledge` wrapper, creates
`kaiba-provision-operator`, and adds only the configured `operators` to that
group. The constrained underlying `operatorPackage` is not a separate
selector-bearing entry point in `PATH`. Deploy `kaiba-provision-lane-workflow`
separately for the station and approver authority sessions.

Install that workflow package declaratively on both authority-session hosts
from one shared, committed deployment flake and `flake.lock`. For example, the
same deployment repository can add this input and shared module to its existing
station and approver configurations:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    kaibaProvisioning.url = "github:ams-tech/nixos-kaiba-network";
  };

  outputs =
    { nixpkgs, kaibaProvisioning, ... }:
    let
      installLaneWorkflow =
        { pkgs, ... }:
        {
          environment.systemPackages = [
            kaibaProvisioning.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision-lane-workflow
            pkgs.coreutils
            pkgs.gawk
            pkgs.git
            pkgs.gnugrep
            pkgs.jq
            pkgs.openssh
          ];
        };
    in
    {
      nixosConfigurations.kaiba-provisioning-station = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        modules = [
          kaibaProvisioning.nixosModules.provisioning-lane-guard
          installLaneWorkflow
          ./station.nix
        ];
      };

      nixosConfigurations.kaiba-provisioning-approver = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          installLaneWorkflow
          ./approver.nix
        ];
      };
    };
}
```

Resolve and review the lock once, commit it, and deploy both hosts from that
same commit. On the corresponding hosts, the concrete deployment commands are:

```bash
nix flake lock

PINNED_KAIBA_REV="$(
  nix flake metadata --json \
    | jq -er '.locks.nodes.kaibaProvisioning.locked.rev | select(test("^[0-9a-f]{40}$"))'
)"
printf 'kaiba provisioning revision: %s\n' "$PINNED_KAIBA_REV"

# On the station, from this exact committed deployment checkout:
sudo nixos-rebuild switch --flake .#kaiba-provisioning-station

# On the approver, from the identical commit and flake.lock:
sudo nixos-rebuild switch --flake .#kaiba-provisioning-approver
```

On both hosts, require
`/run/current-system/sw/bin/kaiba-provision-lane-workflow`. On the station,
also require `/run/wrappers/bin/kaiba-provision-lane-acknowledge` and verify
that `kaiba-provision-lane-operator` is not separately in `PATH`. The lane-guard
module still contributes only the fixed acknowledgement wrapper to the
operator command surface; `environment.systemPackages` above is the separate,
explicit installation of the non-hardware workflow client used by the
transcript below.

Before each target-facing phase, relay mode releases the power lease; the
development-only manual mode instead presents a digest-bound disconnect prompt
and records the authenticated operator acknowledgement. Both modes require USB
absence and observe the minimum cold interval. For RPIBOOT, relay mode asks the
operator to hold BOOTSEL before applying relay power; manual mode uses one
combined prompt to hold BOOTSEL and connect the target's sole USB power/data
cable. The guard proves exactly one BCM2712 at the fixed sysfs path, persists
that observation, then issues a separate BOOTSEL-release prompt. For normal
boot, relay mode asks the operator to leave BOOTSEL untouched before relay
power. Manual mode arms UART and the USB watcher before presenting its combined
no-BOOTSEL and normal-PSU connection prompt. Both modes require
bounded UART evidence while continuously rejecting RPIBOOT enumeration.
After either the relay command or authenticated connection acknowledgement, the
transition persists status `power_established`, `power_establishment_basis` as
`relay_command` or `operator_attestation`, and `power_established_at`. For
manual mode that timestamp is the acknowledgement time and is never represented
as a directly measured electrical edge. Completion persists mode evidence and
either a relay-backed safe-off result or an explicitly operator-attributed
manual disconnect result. Interruption is
recovered only after the configured mechanism re-establishes its corresponding
safe-off boundary, or is permanently quarantined when that cannot be proved.
These are implemented software properties with simulated test coverage, not
live qualification.

The prompt socket authenticates the connecting process's **primary** GID.
Supplementary membership alone is insufficient, so invoke the module wrapper
once for each displayed prompt; it performs the fixed primary-group transition
and supplies the fixed socket internally:

```console
kaiba-provision-lane-acknowledge
```

Read the complete displayed station, lane, transaction, operation, sequence,
phase, mode, instructions, prompt ID, digest, and expiry; perform only those
instructions; then type the exact generated confirmation phrase. Run the same
command again when a later prompt becomes active. The wrapper accepts no
arguments, and the client has no target, operation, boot-mode, GPIO, UART, USB,
payload, or mutation selector.

### Exact reviewed authority and one-shot sequence

This transcript documents the implemented interface; it does **not** authorize
a live mutation. Use it only after the remaining pre-SB-08 gates below pass.
The released hardware-qualification image is deliberately non-administrative:
it has no `sudo` and is not this mutation-capable deployment. In the commands
below, `sudo` denotes an approved administrative/root session on a separately
reviewed live-lane NixOS deployment; the transcript will not work on the
existing qualification image.
All JSON input and output paths must be clean and absolute. Every output path,
including the installed draft, must be new. The certificate, private-key, and
CA paths must be absolute, outside `/nix/store`, and accessible only to the
appropriate named session. The variables below contain paths, not secret
contents. Run the first block in the station session:

```bash
set -euo pipefail
umask 077
RUN_DIR=/absolute/private/review-directory/transaction-id
DRAFT_INPUT="$RUN_DIR/draft-input.json"
DRAFT="$RUN_DIR/draft.json"
DRAFT_DEST=/var/lib/kaiba-provision-lane-guard/draft.json
APPROVER_SSH=provision-reviewer@approver.example
APPROVER_RUN_DIR=/absolute/private/approver-review-directory/transaction-id
APPROVER_APPROVAL_PROPOSAL="$APPROVER_RUN_DIR/approval.json"

test ! -e "$RUN_DIR"
install -d -m 0700 -- "$RUN_DIR"

CONTROL_URL=https://control.example:8443
AUDIT_URL=https://audit.example:8443
CONTROL_CA=/absolute/path/control-server-ca.pem
AUDIT_CA=/absolute/path/audit-server-ca.pem
STATION_CERT=/absolute/path/station-client-cert.pem
STATION_KEY=/absolute/path/station-client-key.pem
APPROVER_ID=development-approver

station_control=(
  --control-url "$CONTROL_URL"
  --tls-cert "$STATION_CERT"
  --tls-key "$STATION_KEY"
  --control-server-ca "$CONTROL_CA"
)
station_authorities=(
  "${station_control[@]}"
  --audit-url "$AUDIT_URL"
  --audit-server-ca "$AUDIT_CA"
)
```

Run this separate block only in the approver session. The approver private key
never moves to the station:

```bash
set -euo pipefail
umask 077
APPROVER_RUN_DIR=/absolute/private/approver-review-directory/transaction-id
APPROVER_APPROVAL_PROPOSAL="$APPROVER_RUN_DIR/approval.json"

test ! -e "$APPROVER_RUN_DIR"
install -d -m 0700 -- "$APPROVER_RUN_DIR"

CONTROL_URL=https://control.example:8443
AUDIT_URL=https://audit.example:8443
CONTROL_CA=/absolute/path/control-server-ca.pem
AUDIT_CA=/absolute/path/audit-server-ca.pem
APPROVER_CERT=/absolute/path/approver-client-cert.pem
APPROVER_KEY=/absolute/path/approver-client-key.pem

approver_authorities=(
  --control-url "$CONTROL_URL"
  --audit-url "$AUDIT_URL"
  --tls-cert "$APPROVER_CERT"
  --tls-key "$APPROVER_KEY"
  --control-server-ca "$CONTROL_CA"
  --audit-server-ca "$AUDIT_CA"
)
```

The reviewed `DraftInput` supplies transaction metadata, the fixed
`power_control_mode`, the six-digest
release binding, target observation, all-zero fresh state, approval expiry,
and exactly seven authorization IDs and duration budgets. It cannot supply an
operation list or boot modes. Before creating it, obtain and review these
values:

- `station_id` and `lane_id` from the deployed, fixed lane configuration;
- the unique transaction, inventory asset, and intended logical IDs from the
  ceremony package;
- `profile_id`, `policy_digest`, and `target_fingerprint` from the current
  accepted qualification record and its checked-in profile and policy—not
  from the historical example record; set the draft `observation_digest` to
  the accepted probe's `evidence_digest` (for the accepted v0.1.5 probe,
  `sha256:0ae79e6106c84acae606fc2808c54d2e147667f0db3254eceb470ae05d668780`);
- the fresh EEPROM status and digest from that same observation: use
  `observed` plus its canonical digest when present, or `unavailable` plus an
  empty digest when the accepted probe legitimately omitted `EEPROM_HASH`;
  never substitute the desired signed EEPROM digest for an unobserved
  prestate;
- the six release digests from the independently verified signed-release
  manifest and the deployed lane-guard release-binding output;
- a canonical UTC approval deadline no more than 24 hours away and long enough
  for the reviewed ceremony; and
- seven unique authorization IDs plus reviewed worst-case durations from 1 to
  3000 seconds, in the fixed operation order printed below.

The current fresh target must report the all-zero customer-key hash and be
directly observed powered off. This template produces the complete strict
`operator-draft-input/v1alpha3` object without exposing operation or boot-mode
fields. The selected power mode and initial observation digest are copied into
the lane plan and its canonical digest, so an approval cannot be detached from
either the fixed power mechanism or the observation that justified an
unavailable EEPROM hash. Set every placeholder variable from the reviewed
sources above; do not copy the example digests from tests or an older evidence
record:

```bash
STATION_ID=development-station
LANE_ID=lane-1
TRANSACTION_ID=transaction-id
# This must match the station's immutable lane-guard powerControl option.
POWER_CONTROL_MODE=manual
ASSET_ID=sacrificial-asset-id
INTENDED_LOGICAL_ID=kaiba-development-unit-id
PROFILE_ID=raspberry-pi-5-model-b-v1alpha1
POLICY_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX

SIGNED_RELEASE_MANIFEST_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX
LANE_GUARD_PACKAGE_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX
COMPILED_ARTIFACT_SET_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX
EXPECTED_CUSTOMER_KEY_HASH=sha256:REPLACE_WITH_64_LOWERCASE_HEX
EXPECTED_EEPROM_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX
EXPECTED_BOOT_IMAGE_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX

TARGET_FINGERPRINT=sha256:REPLACE_WITH_64_LOWERCASE_HEX
# Copy probes[].evidence_digest from the accepted qualification record.
OBSERVATION_DIGEST=sha256:REPLACE_WITH_64_LOWERCASE_HEX
# Use observed + sha256:<64 lowercase hex> only when EEPROM_HASH was present.
# For the accepted v0.1.5 null observation, use unavailable + an empty value.
FRESH_EEPROM_HASH_STATUS=unavailable
FRESH_EEPROM_HASH=
APPROVAL_EXPIRES_AT=REPLACE_WITH_CANONICAL_UTC_WITHIN_24_HOURS

AUTHORIZATION_ID_1=transaction-id-program
AUTHORIZATION_ID_2=transaction-id-cold-power-cycle
AUTHORIZATION_ID_3=transaction-id-owned-readback
AUTHORIZATION_ID_4=transaction-id-owned-recovery
AUTHORIZATION_ID_5=transaction-id-post-recovery-readback
AUTHORIZATION_ID_6=transaction-id-negative-boot
AUTHORIZATION_ID_7=transaction-id-root-integrity

# Replace these examples with the seven reviewed, qualified bounds.
MAXIMUM_DURATION_SECONDS='[60,90,60,120,60,120,120]'

case "$FRESH_EEPROM_HASH_STATUS" in
  observed)
    [[ "$FRESH_EEPROM_HASH" =~ ^sha256:[0-9a-f]{64}$ ]]
    ;;
  unavailable)
    test -z "$FRESH_EEPROM_HASH"
    ;;
  *)
    printf 'invalid FRESH_EEPROM_HASH_STATUS: %s\n' "$FRESH_EEPROM_HASH_STATUS" >&2
    exit 1
    ;;
esac

case "$POWER_CONTROL_MODE" in
  relay|manual) ;;
  *)
    printf 'invalid POWER_CONTROL_MODE: %s\n' "$POWER_CONTROL_MODE" >&2
    exit 1
    ;;
esac

test ! -e "$DRAFT_INPUT"
set -o noclobber
jq -n \
  --arg station_id "$STATION_ID" \
  --arg lane_id "$LANE_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --arg power_control_mode "$POWER_CONTROL_MODE" \
  --arg asset_id "$ASSET_ID" \
  --arg intended_logical_id "$INTENDED_LOGICAL_ID" \
  --arg profile_id "$PROFILE_ID" \
  --arg policy_digest "$POLICY_DIGEST" \
  --arg signed_release_manifest_digest "$SIGNED_RELEASE_MANIFEST_DIGEST" \
  --arg lane_guard_package_digest "$LANE_GUARD_PACKAGE_DIGEST" \
  --arg compiled_artifact_set_digest "$COMPILED_ARTIFACT_SET_DIGEST" \
  --arg expected_customer_key_hash "$EXPECTED_CUSTOMER_KEY_HASH" \
  --arg expected_eeprom_digest "$EXPECTED_EEPROM_DIGEST" \
  --arg expected_boot_image_digest "$EXPECTED_BOOT_IMAGE_DIGEST" \
  --arg target_fingerprint "$TARGET_FINGERPRINT" \
  --arg observation_digest "$OBSERVATION_DIGEST" \
  --arg fresh_eeprom_hash_status "$FRESH_EEPROM_HASH_STATUS" \
  --arg fresh_eeprom_hash "$FRESH_EEPROM_HASH" \
  --arg approval_expires_at "$APPROVAL_EXPIRES_AT" \
  --arg authorization_id_1 "$AUTHORIZATION_ID_1" \
  --arg authorization_id_2 "$AUTHORIZATION_ID_2" \
  --arg authorization_id_3 "$AUTHORIZATION_ID_3" \
  --arg authorization_id_4 "$AUTHORIZATION_ID_4" \
  --arg authorization_id_5 "$AUTHORIZATION_ID_5" \
  --arg authorization_id_6 "$AUTHORIZATION_ID_6" \
  --arg authorization_id_7 "$AUTHORIZATION_ID_7" \
  --argjson maximum_duration_seconds "$MAXIMUM_DURATION_SECONDS" \
  '{
    schema_version: "provisioning.kaiba.network/operator-draft-input/v1alpha3",
    station_id: $station_id,
    lane_id: $lane_id,
    transaction_id: $transaction_id,
    power_control_mode: $power_control_mode,
    asset_id: $asset_id,
    intended_logical_id: $intended_logical_id,
    profile_id: $profile_id,
    policy_digest: $policy_digest,
    release: {
      signed_release_manifest_digest: $signed_release_manifest_digest,
      lane_guard_package_digest: $lane_guard_package_digest,
      compiled_artifact_set_digest: $compiled_artifact_set_digest,
      expected_customer_key_hash: $expected_customer_key_hash,
      expected_eeprom_digest: $expected_eeprom_digest,
      expected_boot_image_digest: $expected_boot_image_digest
    },
    target_fingerprint: $target_fingerprint,
    observation_digest: $observation_digest,
    initial_state: {
      customer_key_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      eeprom_hash: $fresh_eeprom_hash,
      eeprom_hash_status: $fresh_eeprom_hash_status,
      security_state: "fresh",
      power_state: "powered_off"
    },
    approval_expires_at: $approval_expires_at,
    authorization_ids: [
      $authorization_id_1,
      $authorization_id_2,
      $authorization_id_3,
      $authorization_id_4,
      $authorization_id_5,
      $authorization_id_6,
      $authorization_id_7
    ],
    maximum_duration_seconds: $maximum_duration_seconds
  }' > "$DRAFT_INPUT"
set +o noclobber

jq -e . "$DRAFT_INPUT" > /dev/null
sha256sum -- "$DRAFT_INPUT"
```

The `sha256:` placeholder strings are intentionally invalid until replaced;
`prepare-draft` rejects them. In draft input, an empty EEPROM hash is valid
only with the explicit `unavailable` status and only for the initial fresh,
unowned state.
Review the complete JSON and its digest before continuing. In the station
session, create/resume the fixed
transaction, acquire its mutation claim, bind the reviewed target, compile the
fixed campaign, review the resulting draft, and install it at the exact path
configured in the NixOS module:

```bash
kaiba-provision-lane-workflow prepare-draft \
  --input "$DRAFT_INPUT" \
  --draft-out "$DRAFT" \
  "${station_control[@]}"

jq -e --arg mode "$POWER_CONTROL_MODE" \
  '.power_control_mode == $mode' "$DRAFT" > /dev/null

sudo kaiba-provision-lane-workflow install-draft \
  --draft "$DRAFT" \
  --destination "$DRAFT_DEST"
```

For the development milestone, an unavailable fresh EEPROM hash permits one
commit attempt; it does not become an expected or cached digest. The commit
must still return the expected customer-key hash, expected signed EEPROM digest,
`EEPROM_UPDATE=success`, and `SECURE_BOOT_PROVISION=success` before the lane can
create the structured `fresh-commit-attestation/v1alpha1` result. The result is
bound into the attempt result digest and normalizes an otherwise hash-less
owned readback to the plan's `commit_attested` state. That proof carries only
operations 1 and 2, allowing the signed cold boot. A lost, malformed, or
ambiguous commit response can never establish confirmed-applied. An exact,
fully observed original fresh prestate may establish confirmed-not-applied;
every other no-attestation outcome remains uncertain forever. Neither outcome
authorizes a retry.

Operation 3 deliberately transitions from `commit_attested` to `observed` and
requires a separately validated installed-EEPROM collector. The v0.1.5 signed
target contains no such collector, so stop after the verified signed cold boot
and do not authorize operation 3. Never fill that gap with the expected
artifact digest, a plan value, or an unbound cached value.

Every `propose-*` command first renews only the exact live claim appropriate to
that state and then constructs an immutable proposal from the returned
resource version. The proposal binds `expected_resource_version`, `claim_id`,
and `fence_epoch`. Its command summary reports the current `resource_version`,
`claim_id`, `claim_mode`, `fence_epoch`, and `claim_expires_at`; when a current
approval is present, it also reports `approval_expires_at`; the approval
proposal reports the proposed fixed expiry. Renewal and apply summaries expose
the same current authority context when present. Before its first application,
any intervening renewal or other resource-version change invalidates the
proposal. Once review begins, do **not** run a renewal command between that
review and `apply-*`; apply only the exact reviewed file. If a known renewal
occurred, preserve the stale file as review evidence and create and review a
new proposal. The sole higher-resource-version exception is idempotent replay
after that exact proposal may already have committed and its response was lost.

Claim renewal never renews the approval. Its expiry is fixed by the reviewed
draft, and there is no approval-renewal command. An expired claim is a hard
stop for renewal and proposal construction; none of these commands revives it
or silently acquires a replacement mutation claim. Before appending a new
audit record, each not-yet-committed apply uses a control-plane server-time
preflight for the exact current claim. Intent and finalization preflights also
require the current approval and plan digest. Approval application has its own
approver-authenticated, server-time preflight before audit append. Evidence
and reconciliation preflights require the current claim but cannot grant
forward authority. Approval-bound renewal requests carry the exact approval
and plan digest; the initial target-bound renewal carries the reviewed draft
deadline. The control server checks those values and its own clock inside the
same compare-and-set operation before changing the lease or resource version.
A rejection therefore leaves the complete durable transaction unchanged.
Evidence publication after an on-time intent and read-only reconciliation use
their intentionally separate approval-free renewal states.

The station session prepares the immutable approval proposal. That command
automatically renews the clean target-bound claim immediately before freezing
the proposal. Make no intervening renewal. Transfer this secret-free review
artifact over the authenticated administrative channel with a kernel-atomic
no-replace create, then compare its SHA-256 digest through a separate trusted
channel. An interrupted transfer leaves its partial destination in place; keep
that path as failure evidence and use a new approver review directory rather
than overwriting or resuming it.

Run on the station:

```bash
APPROVAL_PROPOSAL="$RUN_DIR/approval.json"

kaiba-provision-lane-workflow propose-approval \
  --draft "$DRAFT" \
  --approver-id "$APPROVER_ID" \
  --proposal-out "$APPROVAL_PROPOSAL" \
  "${station_control[@]}"

APPROVAL_PROPOSAL_SHA256="$(sha256sum -- "$APPROVAL_PROPOSAL" | awk '{print $1}')"
printf 'approval proposal sha256: %s\n' "$APPROVAL_PROPOSAL_SHA256"

[[ "$APPROVER_APPROVAL_PROPOSAL" =~ ^/[A-Za-z0-9._/-]+$ ]]
ssh "$APPROVER_SSH" \
  "umask 077; dd status=none of='$APPROVER_APPROVAL_PROPOSAL' conv=excl,fsync" \
  < "$APPROVAL_PROPOSAL"
```

Communicate `APPROVAL_PROPOSAL_SHA256` independently of that transfer. In the
approver session, set it to the independently received value, verify the exact
bytes, review the complete proposal, and apply that approver-local file with
the certificate whose SPIFFE ID matches `APPROVER_ID`:

```bash
APPROVAL_PROPOSAL_SHA256=REPLACE_WITH_INDEPENDENTLY_RECEIVED_HEX

test "$(sha256sum -- "$APPROVER_APPROVAL_PROPOSAL" | awk '{print $1}')" = \
  "$APPROVAL_PROPOSAL_SHA256"

kaiba-provision-lane-workflow apply-approval \
  --proposal "$APPROVER_APPROVAL_PROPOSAL" \
  "${approver_authorities[@]}"
```

If work will pause before the first intent proposal, renew the exact ready
campaign **before** pausing, while its claim and fixed approval are still
current. Do not run this after an intent proposal has been created:

```bash
kaiba-provision-lane-workflow renew-ready-campaign \
  --draft "$DRAFT" \
  "${station_control[@]}"
```

For a longer pause, renew again before each reported `claim_expires_at`, but
only while no proposal is under review. One renewal does not authorize an
indefinite pause. If the displayed expiry passes, stop.

The fixed claim lease is one hour. Each reviewed operation duration must be
between 1 and 3000 seconds, and the NixOS lease safety margin must be between 1
and 300 seconds. At the maximum duration and margin, a just-renewed claim
leaves only five minutes for unit activation and pre-execution observation.
Do not let a pause consume that window.

Return to the station session. Perform the following block once per operation.
`SEQ` names review files only; it is not passed to any authority or hardware
interface. `propose-next-intent` derives the sole next operation. Start with
`SEQ=1`, then use 2 through 7 only after the preceding verified evidence is
accepted. The expected order is `program_customer_key_and_eeprom`,
`cold_power_cycle`, `owned_readback`, `test_owned_recovery`,
`post_recovery_readback`, `test_negative_boot`, and `test_root_integrity`.

```bash
SEQ=1
INTENT_PROPOSAL="$RUN_DIR/intent-$SEQ.json"
EVIDENCE_PROPOSAL="$RUN_DIR/evidence-$SEQ.json"

kaiba-provision-lane-workflow propose-next-intent \
  --draft "$DRAFT" \
  --proposal-out "$INTENT_PROPOSAL" \
  "${station_control[@]}"

kaiba-provision-lane-workflow apply-intent \
  --proposal "$INTENT_PROPOSAL" \
  "${station_authorities[@]}"

kaiba-provision-lane-workflow renew-pending-intent \
  --draft "$DRAFT" \
  "${station_control[@]}"

sudo systemctl start --no-block kaiba-provisioning-lane-guard.service
```

`propose-next-intent` renews the exact ready campaign before deriving the sole
next operation. Review and apply that proposal without renewing in between.
After `apply-intent`, `renew-pending-intent` can renew only that already
recorded operation, requires its fixed approval still to be current, and
cannot select or authorize another operation. Run it immediately before
`systemctl start`, as shown. It is not the evidence renewal; the only narrow
post-execution use is the durable publication-retry case below.

While that one-shot is active, acknowledge each server-selected prompt with
the fixed wrapper above. A failure or interruption does not by itself authorize
a restart; after the unit terminates, inspect its output and follow the retry
and recovery matrix below:

```bash
sudo systemctl status --no-pager kaiba-provisioning-lane-guard.service
sudo journalctl --unit kaiba-provisioning-lane-guard.service \
  --boot --output cat --no-pager
```

The guard's terminal JSON summary contains `path`, `status`, `key`, and
`already_published`. Copy the exact absolute `path` value into `ATTEMPT`; never
guess the digest-derived filename or substitute a caller-owned copy. The
module publishes it beneath
`/var/lib/kaiba-provision-lane-guard/attempts/` as a root-owned, mode-0444,
no-replace receipt. A verified attempt is reviewed and recorded as follows;
`propose-evidence` runs as root because it accepts only that trusted receipt
boundary:

```bash
ATTEMPT=/var/lib/kaiba-provision-lane-guard/attempts/lane-attempt-DIGEST.json

sudo kaiba-provision-lane-workflow propose-evidence \
  --draft "$DRAFT" \
  --attempt "$ATTEMPT" \
  --proposal-out "$EVIDENCE_PROPOSAL" \
  "${station_control[@]}"

kaiba-provision-lane-workflow apply-evidence \
  --proposal "$EVIDENCE_PROPOSAL" \
  "${station_authorities[@]}"
```

`propose-evidence` performs an evidence-only renewal of the exact same live
mutation claim immediately before constructing the proposal. It validates the
immutable approval snapshot that authorized the pending intent but does not
require that approval still be current. Consequently, a terminal result from
an operation that began while authorized remains recordable after approval
expiry, provided its original claim is still live. This exception records an
outcome only: it cannot authorize execution, a retry, or the next operation.
Do not renew after reviewing the evidence proposal and before applying it. If
the claim expires before proposal construction or application, do not acquire
a new claim for the old receipt; stop and escalate the durable state for
review.

Require `status=verified` in the guard summary and a successfully closed
operation in the applied evidence summary before incrementing `SEQ`. After
each such successful `apply-evidence`, immediately preserve that exact ready
prefix while its approval and claim remain live:

```bash
kaiba-provision-lane-workflow renew-ready-campaign \
  --draft "$DRAFT" \
  "${station_control[@]}"
```

This creates no proposal; the next `propose-next-intent` or finalization
command will renew once more immediately before freezing its own proposal.
Never renew while holding a proposal under review. If evidence was recorded
after approval expiry, it is still durable, but this ready renewal must fail
and the campaign cannot advance.

The seventh successful evidence application makes the fixed software campaign
eligible for finalization; it is not itself the terminal transition. After the
ready renewal above, create, review, and apply the fixed terminal proposal
without an intervening renewal:

```bash
SECURITY_APPLIED_PROPOSAL="$RUN_DIR/security-applied.json"

kaiba-provision-lane-workflow propose-security-applied \
  --draft "$DRAFT" \
  --proposal-out "$SECURITY_APPLIED_PROPOSAL" \
  "${station_control[@]}"

kaiba-provision-lane-workflow apply-security-applied \
  --proposal "$SECURITY_APPLIED_PROPOSAL" \
  "${station_authorities[@]}"

kaiba-provision-lane-workflow release-terminal-claim \
  --draft "$DRAFT" \
  "${station_control[@]}"
```

`propose-security-applied` automatically renews the exact seven-operation
successful campaign before freezing the proposal. Require the applied summary
to report `transaction_status=security_applied`,
`rollback_status=rollback_unimplemented`, and
`release_classification=development_asset`. It must not report or imply
`enrollment_ready`. Run `release-terminal-claim` promptly, before the reported
claim expiry. It derives the exact current terminal claim from the reviewed
draft and control state; there is no claim, fence, status, or mode selector.
Require `status=terminal_claim_released`, the unchanged terminal transaction
status, and no active `claim_id` in its summary. An exact lost-response retry
is proved through the original server idempotency record. The command refuses
to release a later claim after any earlier terminal release. If the claim has
already expired, preserve that fact and stop: expiry removes effective lane
authority, but it is not rewritten as a durable `released` history record.

### Retry and recovery matrix

The journal and immutable receipt boundary determine the only permitted next
action. A local receipt replay is reachable only while the authenticated bridge
still accepts the same claim and fence with sufficient remaining lease. Its
no-I/O guarantee begins after the fixed unit reaches and verifies the durable
journal state; it is not an authority bypass.

| Observed condition | Only permitted action |
|---|---|
| The exact immutable receipt already exists for the current mode and authenticated request | Before any control-state advance, an exact rerun of the same fixed one-shot verifies the journal and receipt and republishes the summary only. It performs no hardware I/O and displays no operator prompt; require `already_published=true`. |
| An execute-mode durable publishable result exists, or a reconcile-mode durable `verified`, `confirmed_not_applied`, or `quarantined` result exists, but its receipt publication or terminal-summary output failed | Before any control-state advance, rerun the same fixed one-shot under the same current authority. It may publish the missing immutable receipt and summary, but it must not touch hardware or prompt the operator. |
| Reconcile mode has durable `AttemptUncertain` but no reconciliation-mode receipt | While the same reconciliation claim remains live, an exact rerun may perform another fixed read-only reconciliation observation. It may prompt and read the target, but it never calls hardware mutation. Do not describe this as publication-only replay. |
| The journal contains durable `AttemptStarted` but no durable terminal record or receipt | Never create evidence. Preserve all state, deploy the lane guard in reconcile mode first, then run `prepare-reconciliation` immediately before starting the fixed unit, as described below. |
| Execution was rejected before `AttemptStarted`, so there is no attempt | Investigate the failed precondition, control state, claim, and deployment. Do not blindly restart and do not manufacture a reconciliation attempt for hardware that was never dispatched. |
| An `apply-*` audit/control request may have committed but its response was lost | Retry only the exact immutable proposal file. Its fixed idempotency keys recover the committed result; do not renew, regenerate, or rebase it first. |

For an execute-mode publication retry only, if the same claim is live but no
longer covers the full operation budget, first positively establish that the
journal already contains the exact durable terminal attempt. While the fixed
approval is still current, `renew-pending-intent` may then refresh that same
claim immediately before rerunning the fixed unit. The journal prevents a
second hardware dispatch. Never use this exception for `AttemptStarted`, an
unknown journal state, an expired claim or approval, a changed fence, or after
control advanced. If the same authority cannot be made current, preserve the
journal and any receipt and stop; do not claim that publication replay
succeeded. A reconciliation-mode publication replay likewise requires the
same still-live reconciliation claim; do not acquire a new claim for its old
journal result.

On a lost apply response, retry the exact proposal promptly. If the control CAS
already committed, exact replay returns that durable result without creating a
new transition. If only the idempotent audit append committed, the outstanding
control transition still requires a current server-time claim and, for intent
or finalization, a current approval. Expiry then stops the transition and the
durable audit trace remains for review.

If a proposal is known to be stale because a renewal or other resource-version
change occurred, the lost-response rule does not reauthorize it: stop, read the
durable state, and follow a newly reviewed proposal ceremony only if that state
still permits one.

### Reconciliation-only alternative

For an `uncertain` execute receipt, run the same `propose-evidence` and
`apply-evidence` commands while the original mutation claim is still live so
control durably enters `reconciliation_required`. If that claim expired, the
evidence-only renewal must fail: preserve the execute receipt, do not acquire a
new mutation claim for it, and proceed directly to the reviewed reconcile-mode
deployment and fresh reconciliation observation below. The uncertain execute
receipt is evidence that observation is required; it is not the terminal
reconciliation receipt passed to `propose-reconciliation`. A quarantined
execute receipt is recorded with the evidence commands while its claim is live
and then stops; it is not a reconciliation shortcut. After its quarantined
control result is durable, run `release-terminal-claim --draft "$DRAFT"` with
`"${station_control[@]}"` promptly to relinquish that still-live mutation
claim.

For either an uncertain terminal receipt or durable `AttemptStarted` without a
terminal receipt, first commit and review a station-deployment change that
fixes:

```nix
services.kaiba-provisioning-lane-guard.mode = "reconcile";
```

From that exact committed deployment checkout, build and activate the station
configuration and verify the resulting fixed unit argument:

```bash
DEPLOYMENT_REV=REPLACE_WITH_REVIEWED_40_HEX_COMMIT

test "$(git rev-parse HEAD)" = "$DEPLOYMENT_REV"
test -z "$(git status --porcelain)"
sudo nixos-rebuild switch --flake .#kaiba-provisioning-station
systemctl show --property=ExecStart --value \
  kaiba-provisioning-lane-guard.service \
  | grep -F -- '--mode reconcile'
```

Do not invoke the guard manually with altered selectors. Only after reconcile
mode is deployed and verified, prepare the fixed read-only claim immediately
before starting the one-shot:

```bash
kaiba-provision-lane-workflow prepare-reconciliation \
  --draft "$DRAFT" \
  "${station_control[@]}"

sudo systemctl start --no-block kaiba-provisioning-lane-guard.service
```

`prepare-reconciliation` may transfer the still-live mutation claim or acquire
a fresh, observation-only reconciliation claim and fence after the old claim
expired. That explicit recovery transition does not revive mutation authority.
It clears forward approval and cannot dispatch hardware mutation. Acknowledge
only the server-selected RPIBOOT observation prompts.

Again copy `path` from the guard's terminal JSON summary, this time into
`RECONCILIATION_ATTEMPT`, and apply the attempt-derived resolution:

```bash
RECONCILIATION_ATTEMPT=/var/lib/kaiba-provision-lane-guard/attempts/lane-attempt-DIGEST.json
RECONCILIATION_PROPOSAL="$RUN_DIR/reconciliation-$SEQ.json"

sudo kaiba-provision-lane-workflow propose-reconciliation \
  --draft "$DRAFT" \
  --attempt "$RECONCILIATION_ATTEMPT" \
  --proposal-out "$RECONCILIATION_PROPOSAL" \
  "${station_control[@]}"

kaiba-provision-lane-workflow apply-reconciliation \
  --proposal "$RECONCILIATION_PROPOSAL" \
  "${station_authorities[@]}"
```

`propose-reconciliation` automatically renews only the same still-live
reconciliation claim that produced the trusted attempt, immediately before
freezing the proposal. It cannot acquire or transfer a claim. If that claim
expired, do not obtain a new claim and reuse the old receipt; the receipt is
bound to the old claim and fence. Do not renew between proposal review and
apply.

The CLI derives `confirmed_applied`, `confirmed_not_applied`, or unknown from
the trusted attempt; the operator cannot choose it. Reconciliation never
redispatches hardware mutation, and this workflow exposes no retry command.
Both confirmed outcomes are terminal stops under this development workflow:
neither authorizes another mutation or finalization. Unknown quarantines the
unit and also stops. For any successfully recorded confirmed or quarantined
outcome, promptly release the still-live reconciliation claim with the same
selector-free command:

```bash
kaiba-provision-lane-workflow release-terminal-claim \
  --draft "$DRAFT" \
  "${station_control[@]}"
```

The same expiry and exact-replay rules described after `security_applied`
apply. A delayed retry never selects a later reconciliation claim.

### Journal replacement and migration

The current guard strictly accepts only its current
`lane-guard-attempt-store/v1alpha5` envelope. It does not migrate an older
journal, even when individual records look compatible. Before replacing a
deployment, stop the lane and preserve the old journal, lock file, attempt
receipts, control record, and audit records. Any older **nonempty** journal is
resolved outside the new guard by direct board-state inspection and an
explicit reconciliation or quarantine decision; never copy, rewrite, or
replay its records into the new schema. Only a journal positively established
as empty, created before live use, and containing no attempt or boot transition
may be deleted under a reviewed replacement procedure so the current guard can
create a fresh journal.

## Physical lane

Provision the station with one fixed lane configuration:

- one stable BCM2712 RPIBOOT USB topology path;
- one UART adapter selected by `/dev/serial/by-id`, not `ttyUSB` numbering;
- one fixed power-control mode: the default qualified relay, or the explicit
  development-only manual mode; and
- no hub, device, UART, GPIO, power mode, or payload selector exposed to the
  browser or operator client.

Qualify UART independently before connecting a target. Confirm that its ground
and voltage levels are correct for the Pi and that its VCC lead cannot power the
target. In relay mode, independently qualify the electrically appropriate,
isolated relay and confirm that releasing it removes *all* target power,
including back-power from UART or USB. A relay transition is not accepted by
itself as proof of power removal; the lane guard must also observe target
disappearance and the configured cold interval. For relay mode, the station
must boot with Raspberry Pi `strict_gpiod` enabled and must expose
`/sys/module/pinctrl_rp1/parameters/persist_gpio_outputs` as exactly `N`.
The relay lane refuses startup otherwise, drives logical inactive before its
main process, drives inactive again after every exit, and the adapter drives
inactive during normal lease release. Returning a released line to an input is
still only one layer: the qualified active-high relay input needs a physical
normally-off bias and the target must use the relay's normally-open contact.

### Development-only manual-power deviation

Manual mode is permitted only for the explicitly authorized sacrificial
development campaign. It does not qualify automated fail-off and is not a
production power design. Select it explicitly in the provisioning-station
configuration; omitting this option retains the relay default:

```nix
services.kaiba-provisioning-lane-guard.powerControl = "manual";
```

The resulting unit must contain `--power-control manual`, and the reviewed
`operator-draft-input/v1alpha3` must contain `power_control_mode: manual`. The
unit must omit all
`--gpio-*` arguments, GPIO device permissions, and GPIO pre/post commands, and
retain the fixed acknowledgement-only operator wrapper. Use exactly one target
power source at a time:

- for RPIBOOT, the previously cut VBUS/data-only USB cable is forbidden because
  it cannot establish target power. Use a pre-qualified intact power-and-data
  USB path through a Raspberry Pi Powered USB Hub (the upstream `usbboot`
  recommendation), or another separately reviewed USB 3 source capable of
  supplying at least 900 mA without brownout. This path is the target's sole
  power and data source, and the normal target PSU is absent;
- for normal signed NVMe boot, remove the provisioning USB cable completely and
  use the target's normal PSU as its sole power source; and
- connect UART ground and target TX to adapter RX only for this receive-only
  proof; leave adapter VCC and adapter TX disconnected.

Qualify that intact RPIBOOT path under load before any OTP-capable run. A USB
reset, undervoltage indication, target disappearance, or other brownout symptom
is a stop condition: do not retry an irreversible operation until the source
and cable have been replaced or independently re-qualified. The manual-power
exception does not authorize OTP with the cut-VBUS cable, an unqualified hub,
or a marginal station USB port.

Every connect and disconnect is a separate digest-bound prompt acknowledged by
the authenticated operator. Transition evidence identifies `manual` power
control, records `power_establishment_basis: operator_attestation`, and sets
`power_established_at` to the authenticated connection acknowledgement time;
it does not claim to observe the physical power edge. The initial and final
power-off proof objects keep their prompt identity, digest, expiry,
authenticated peer, and acknowledgement time separate from the direct
USB-topology timestamps. Those timestamps therefore mean “operator confirmed
complete power removal and the station observed no RPIBOOT target,” not a direct
electrical measurement. In particular, USB absence during normal boot cannot
by itself prove power-off.

Process or station failure cannot automatically remove manually connected
power. After any interruption, disconnect every target power source before
attempting recovery. The guard must obtain a new authenticated disconnect
acknowledgement and re-establish USB absence; it never resumes the old prompt or
retries an uncertain one-way operation. Failure to obtain that acknowledgement
or to observe the expected topology quarantines the lane. Completed and failed
terminal references alike retain `power_control_mode`,
`power_establishment_basis`, both manual proof objects when obtained,
`safe_off_observed_at`, and a closed `safe_off_basis`. A proven manual terminal
uses `operator_disconnect_and_usb_absence`; failure to establish that boundary
uses `unproven`, never a synthetic safe-off timestamp or proof. Relay terminals
use `relay_inactive_and_usb_absence` only when both facts were established; the
word `inactive` is intentional because release may be a no-op when the retained
relay lease is already inactive.
Public evidence must retain this attribution and must not claim relay-backed
safe-off, automated emergency stop, or production physical-lane qualification.

Restart recovery also refuses to reinterpret an interrupted transition through
a newly configured power mechanism. If its persisted power mode differs from
the current immutable lane mode, the guard uses neither relay nor manual prompt;
it terminalizes the transition as quarantined with `safe_off_basis: unproven`
and requires external inspection.

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
10. Remove all target power using the fixed lane mechanism and cold-boot the
   signed NVMe image. In development-only manual mode, disconnect the
   provisioning USB completely before connecting the normal target PSU.
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
loss, YubiKey removal, wrong token, PIN/touch timeout, expired approval,
transferred claim, stale fence epoch, signer mismatch, audit outage, and failure
before, during, and after the OTP command. Relay mode additionally exercises
relay-control and relay fail-off. Manual mode instead proves that interruption
never causes automatic continuation or mutation redispatch, requires a new
authenticated disconnect before reconciliation, and retains the explicit
absence of an automated fail-off guarantee in its evidence.

No drill may repeat a one-way operation based only on a timeout or missing
response. Any partially owned or uncertain board is permanently excluded from
the fresh-device path and follows only the reconciliation procedure above.
Both confirmed outcomes stop this campaign; an unknown result remains
quarantined until a separately authorized recovery or retirement procedure
exists.

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

## Remaining live-only gates before SB-08

The local software transaction, manual-prompt, public-evidence review, and
private-evidence-boundary deliverables are complete, but they do not authorize
a sacrificial ownership mutation. The exact pushed merge/pre-ceremony revision
must still pass the repository's x86_64 and **native** AArch64 pipeline,
including its station-image build; that non-live, revision-bound release gate
is not replaced by local x86_64 results and is not counted below. Exactly these
five live gates remain:

1. Complete the development-token ceremony and assemble the exact signed
   release from authenticated live-token results, including PIN, touch,
   wrong-token, timeout, receipt-lineage, and independent offline-verification
   evidence. Follow the
   [Ubuntu development signing ceremony](ubuntu-rpi5-development-signing-ceremony.md)
   for the software-only signing and assembly portion. This is a development
   release, not a production release.
2. Select the typed hardware configuration for the machine that actually runs
   the writer. On `malak`, use only its fixed USB-reader configuration; use the
   Pi-local `/dev/nvme0n1` configuration only on `kaiba-rpi5-provisioner` while
   that Pi is booted from a separate medium. Review the mandatory attachment-
   bound preflight, stage the approved layout, remove power and reattach the
   medium, and complete independent cold readback of every manifest-bound byte
   and dm-verity result. Record content evidence only: do not verify or retain
   NVMe model, serial, WWID, `/dev/disk/by-id`, or any other boot-media identity.
3. Qualify the actual UART adapter's voltage, ground, settings, isolation, and
   stable `/dev/serial/by-id` identity, then prove bounded capture on the fixed
   lane. This pre-SB-08 work does not claim signed-system-image enforcement;
   that live enforcement observation remains a later owned-device goal.
4. Qualify the selected fixed power mode and all power paths. The default relay
   lane must prove no USB, UART, display, GPIO, or NVMe back-power; observed USB
   disappearance and the cold interval; and fail-off after relay-control loss,
   process death, kernel/station restart, complete station power loss, and
   emergency stop. The sacrificial-development manual exception instead
   requires the single-source USB-versus-normal-PSU topology above, authenticated
   connect/disconnect prompts, USB absence and the cold interval, and fail-closed
   interruption/recovery tests. It explicitly waives automated fail-off and
   cannot satisfy a production physical-power qualification.
5. First close every deferred baseline check for the exact candidate board:
   explicit destructive-use authorization for the selected storage without
   appraising contents or binding storage identity; the remaining customer-OTP
   and device-private-key rows; installed EEPROM contents, effective
   write-protection posture, and EEPROM/recovery authenticity; inventory
   ownership and prior-transaction history; and non-VideoCore debug or
   alternate execution paths. Then run the physical wrong-mode,
   absent/additional/moved/replaced-target, BOOTSEL timing, USB continuity,
   UART failure, restart/recovery, and source-isolation campaign with inert,
   explicitly non-OTP-capable payloads. Every ambiguous or unsafe result must
   cleanly abort or quarantine. The fixed actuator remains deferred and is not
   a gate for this manual campaign.

The development `BOOT_ORDER=0xf216`, unlocked VideoCore JTAG, `BOOT_UART=1`,
self-update, recovery, and EEPROM write-protection postures remain explicitly
non-production. No value, including `0xf6`, is asserted as a production-ready
replacement; production values require a separate decision and qualification.
