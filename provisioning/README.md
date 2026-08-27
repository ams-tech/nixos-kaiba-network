# Provisioning Go module

This module implements the non-mutating Raspberry Pi probe, the browser
simulation, and the fail-closed reference services for the hardware-facing Pi
5 secure-boot development-lane foundation. It has no Go dependency on the DNS
module and uses only the Go standard library.

## Commands

- `kaiba-provision probe` performs the non-persistent device preflight.
- `kaiba-provision qualify` strictly compares two private live-probe results
  and emits deterministic whitelist-redacted hardware evidence.
- `kaiba-provision-station-demo` serves the loopback-only station simulation.
- `kaiba-provision-station-graph` generates the browser simulation graph.
- `kaiba-provision-control` owns transactions, claims, fence epochs,
  approvals, quarantine, and the terminal `security_applied` record.
- `kaiba-provision-audit` persists an independent, secret-free hash chain.
- `kaiba-provision-authority-bridge` authenticates stable control/audit state
  and emits only the current closed lane plan/request over a private Unix
  socket.
- `kaiba-provision-lane-workflow` creates the fixed seven-operation draft and
  the narrowly typed approval, per-operation intent, evidence, and
  reconciliation proposals, then derives the fixed `security_applied`
  terminalization from all seven durable records. It accepts no operation,
  boot-mode, payload, evidence-digest, rollback, classification, or hardware
  selector.
- `kaiba-provision-lane-guard` is the root-only, one-shot physical adapter. It
  obtains current authority through the bridge, persists attempts and physical
  boot transitions in its execute-once journal, and publishes each terminal
  attempt as a root-owned, immutable receipt. Publication always reloads the
  durable record; an in-memory result is never evidence, and an exact receipt
  retry never reaches hardware.
- `kaiba-provision-lane-operator` is the acknowledgement-only client for the
  guard's private authenticated prompt socket. It displays the server-selected
  action and accepts only the exact bound confirmation phrase; it cannot select
  an operation, target, boot mode, or physical path.
- `kaiba-provision-signer`, `kaiba-provision-signing-client`, and
  `kaiba-provision-signing-gate` enforce the immutable approval boundary.
- `kaiba-provision-yubikey-wrapper` performs the fixed RSA-2048/SHA-256 PIV 9c
  operation through the pinned OpenSSL PKCS#11 provider chain.
- `kaiba-provision-sign-boot` submits one immutable public boot plan to the
  fixed signing gate and offline-finalizes its public result. The generic build
  has no signing authority and can only finalize.
- `kaiba-provision-sign-eeprom` runs only the pinned fresh-board `-f` EEPROM
  updater, requires exactly three release-intent-bound gate callbacks, and
  offline-finalizes the public EEPROM result. It cannot select recovery
  signing, access a device, program EEPROM, or change OTP.
- `kaiba-provision-media-stager` is the legacy mixed prototype that preflights,
  writes, and reopens exactly three digest-bound payload extents. Its
  regular-file fixture mode remains a safe regression path.
- `kaiba-provision-media-device-stager` is emitted only by
  `lib.mkRpi5ProductionMedia`; it is linker-fixed to one complete media plan and
  is the only production-media command here with block-device write capability.
- `kaiba-provision-media-device-verifier` is the separately built, read-only
  production verifier. It independently validates GPT, FAT, signed-release
  lineage, the complete device digest, and dm-verity after reattachment.
- `kaiba-provision-media-fixture-stager` and
  `kaiba-provision-media-verifier` exercise that same complete production
  layout against regular files without block-device authority.
- `kaiba-provision-media-contract` validates and correlates canonical media
  plans and receipts. `kaiba-provision-unfused-runtime-record` serializes two
  bounded plan-correlated UART records; it is not a hardware collector.
- `kaiba-provision-station` serves the separate live, loopback-only operator
  interface. It never falls back to the browser simulation.

The generic bridge, lane, and signer binaries are deliberately unconfigured and
fail closed. A deployment must instantiate `lib.mkRpi5PhysicalLaneGuard` and
`lib.mkDevelopmentYubiKeySigning`, then use the corresponding NixOS modules.
The authority bridge additionally requires runtime station mTLS credentials
and independent control/audit server trust roots.
The `provisioning-lane-guard` module installs only the fixed, no-argument
`kaiba-provision-lane-acknowledge` wrapper, creates the
`kaiba-provision-operator` group, fixes every device and socket path in the root
one-shot unit, and leaves that unit without an automatic start target. The
module uses the NixOS setgid security-wrapper boundary and a native fixed-argv
launcher to enter that authenticated GID and supply the module-owned socket to
the constrained client. A shell launcher is deliberately not used because it
would drop a mismatched effective group. Supplementary membership by itself is
not authority, and the supported command accepts no selector arguments.

Workflow claim renewal is deliberately narrow. Proposal commands may extend
only the same current claim in an exact compiler-derived state, immediately
before constructing a proposal. The proposal's resource version is immutable:
any later renewal or state change invalidates it, so renewal is forbidden
between review and apply. Intent execution has a separate fixed
`renew-pending-intent` step immediately before the one-shot starts, while
`renew-ready-campaign` preserves an exact successful prefix during a pause.
Approval itself is never renewed. Before a new audited transition, the control
server's clock must confirm the proposal's exact current claim; intent and
`security_applied` additionally require the exact current approval. Terminal
evidence from an operation authorized on time remains recordable after approval
expiry only while that exact mutation claim is still current. No renewal revives
an expired claim or rebases an immutable proposal. Approval-bound and clean
target-bound renewals validate their exact approval or reviewed deadline on the
server inside the same CAS before changing the lease or resource version.
After delayed physical pre-observation, the guard refreshes the authenticated
binding and requires server-confirmed minimum authority windows immediately
before it records `AttemptStarted` and dispatches hardware. An exact already
committed initial approval remains idempotently replayable after expiry, but an
audit-only or uncommitted approval does not. The selector-free
`release-terminal-claim` command promptly closes only the exact current claim
after `security_applied`, quarantine, clean abort, or conclusive reconciliation.
Its lost-response replay is tied to the original server idempotency record and
refuses to retarget any later claim.

The YubiKey PIN is a runtime systemd credential; it is never a Nix value.
Normal-boot signing additionally uses `lib.mkRpi5BootSigningPlan` and
`lib.mkRpi5VerifiedSignedBoot`. The shared cohort authorization is built with
`lib.mkRpi5ReleaseIntent`; EEPROM inputs and the public fresh-board plan use
`lib.mkRpi5EEPROMReleaseSigningInputs` and `lib.mkRpi5EEPROMSigningPlan`, while
`lib.mkRpi5VerifiedSignedEEPROM` admits only an offline-verified public result.
A signer-verified capsule can be wrapped in a
deterministic outer FAT/GPT regular-file rehearsal with
`lib.mkRpi5MediaStagingFixture`. A complete content-addressed signed release can
instead be bound to exact per-run capacity and 512-byte logical-sector geometry,
the full GPT/FAT/root/verity layout, and a plan-specialized writer/verifier pair
with `lib.mkRpi5ProductionMedia`. The station-local raw whole-device or
`/dev/disk/by-path` selector comes from the versioned, typed catalog in
`config/hardware/` and is linker-fixed into the writer and verifier. The
catalog is exposed as `lib.hardwareConfigurations`; its checked-in
`raspberryPi5SacrificialDevelopment` entry selects `/dev/nvme0n1`. The selector
and hardware-configuration ID are absent from canonical plans, receipts, and
evidence; storage model, serial, WWID, `/dev/disk/by-id`, physical sector size,
and initial contents are not trust inputs. See the
[signed-boot workflow](../docs/raspberry-pi-5-signed-boot-workflow.md) and
[target-media staging contracts](../docs/target-media-staging-prototype.md).

The current file journal accepts only
`lane-guard-attempt-store/v1alpha3` envelopes containing
`lane-guard-attempt/v1alpha2` attempts and current durable boot-transition
records. Older nonempty journals are not migrated or replayed: remove the lane
from service and resolve the target externally as a reconciliation or
quarantine case before replacing the deployment. Only a journal positively
known to be empty and created before any live operation may be deleted and
recreated. The exact reviewed operator sequence is in the
[live secure-boot foundation](../docs/raspberry-pi-5-live-provisioning.md).

An exact guard rerun that finds the same durable terminal journal record only
verifies or republishes its immutable receipt; it does not call hardware or
repeat a mutation. That publication retry still enters through the current
authenticated bridge and therefore must happen before its execution authority
expires. A durable `started` record, a failed terminal journal write, or any
other ambiguous physical result is never an execute retry: preserve the journal
and use the reviewed reconciliation-only branch. If claim expiry prevents an
uncertain receipt from entering control first, acquire a new read-only
reconciliation claim for direct observation; never acquire new mutation
authority for the old result.

Command entry points live under `cmd/`. Implementation packages and embedded
station assets live under `internal/`. Device-class profiles and their schema
live under `profiles/` and `schemas/`.

## Development

From this directory:

```console
go test ./...
go build ./cmd/...
```

From the repository root, the workspace supports:

```console
go test ./provisioning/...
```

From this directory, the corresponding Nix boundary is `../nix/provisioning`:

```console
nix flake check ../nix/provisioning -L
nix build ../nix/provisioning#kaiba-provision -L
```

See the [Raspberry Pi 5 probe](../docs/raspberry-pi-5-provisioning-probe.md),
[Raspberry Pi 5 secure-boot guide](../docs/raspberry-pi-5-secure-boot.md), and
[live secure-boot foundation](../docs/raspberry-pi-5-live-provisioning.md),
as well as the
[station kiosk](../docs/provisioning-station-kiosk.md) documentation for the
safety, lifecycle, and operator boundaries.
