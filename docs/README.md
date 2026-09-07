# Documentation map

This page separates observed state, implemented development tooling, active
delivery work, and proposed production direction. Those categories are not
interchangeable: a reproducible artifact or software test is not evidence that
an irreversible hardware ceremony ran.

## Current repository state

The repository currently establishes all of the following:

- the isolated `kaiba.test` DNS pilot, its provisioning contracts, and its
  automated x86_64 and AArch64 checks;
- a stable, read-only Raspberry Pi 5 classification profile and a checked
  **pre-fuse** hardware-qualification record containing two matching
  observations;
- checked-in public signed inputs for the sacrificial `v0.1.6` development
  payload, including five grants and authenticated signing receipts, signed boot
  and EEPROM results, owned recovery, and reproducible reconstruction of the
  complete 18-role release;
- build and release contracts for the fixed development station, the immutable
  qualification target, and the later development-access target; and
- software-only transaction, media, recovery, failure, and release-publication
  tests that retain explicit non-hardware evidence classifications.

The [current sacrificial-device state](raspberry-pi-5-sacrificial-state.md)
records the operator confirmation that the Pi has now been fused and boots a
signed development `target` image. It is permanently an owned device and must
never re-enter a fresh-board path. The checked qualification JSON predates that
transition and remains historical pre-fuse evidence; a reconciled public
post-fuse packet identifying the exact target digest is not yet checked in.

The repository does not yet implement the production stable verifier, online
release-authorization protocol, OTP-HMAC/LUKS state, production device identity,
or production enrollment path. The successful signed development boot does not
change those boundaries.

## Current direction

The [Raspberry Pi 5 production security follow-on] is the active production
roadmap. It proposes a no-TPM design with a customer-signed stable verifier,
delegated A/B releases, a fresh server policy decision before protected state,
OTP-HMAC-derived LUKS unlock, and a separately scoped device-authentication
role. Its workstreams and acceptance criteria are proposals, not current
capabilities.

The [self-hosted Forgejo and Hydra design] is a parallel infrastructure draft.
It may replace GitHub-specific source, CI, cache, and publication services, but
it does not change the device-security roadmap or grant signing, enrollment, or
mutation authority.

## Which document to use

| Need | Document role |
| --- | --- |
| Repository overview and ordinary build commands | [Root README](../README.md) |
| DNS pilot behavior and trust boundaries | [Pilot architecture](architecture.md) and [DNS module guide](../dns/README.md) |
| Historical pre-fuse qualification | [Provisioning probe](raspberry-pi-5-provisioning-probe.md) and the checked [qualification evidence](../tests/provisioning/evidence/sacrificial-pi-5.json) |
| Current sacrificial-device lifecycle and evidence gap | [Sacrificial-device state](raspberry-pi-5-sacrificial-state.md) |
| Native Pi secure-boot requirements | [Secure-boot design](raspberry-pi-5-secure-boot.md) |
| Historical sacrificial milestone and current reconciliation work | [Secure-boot execution plan](raspberry-pi-5-secure-boot-execution-plan.md) |
| Implemented development component boundaries | [Live secure-boot foundation](raspberry-pi-5-live-provisioning.md) |
| Version-bound irreversible operator procedure | [Development secure-boot station](raspberry-pi-5-development-secure-boot-station.md) |
| Current production direction | [Production security follow-on](raspberry-pi-5-production-security-follow-on.md) |
| Platform-neutral identity requirements | [Device identity lifecycle](device-identity.md) |
| Platform-neutral station requirements | [Provisioning-station design](provisioning-station.md) |
| Current command inventory | [Provisioning module guide](../provisioning/README.md) |
| Software-only rehearsal and compatibility work | [Non-fusing prototype](non-fusing-secure-boot-prototype.md), [standalone rehearsal](software-secure-boot-rehearsal.md), [unfused compatibility](raspberry-pi-5-unfused-compatibility.md), and [media contracts](target-media-staging-prototype.md) |
| Development signing and public release reconstruction | [Signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md), [Ubuntu signing ceremony](ubuntu-rpi5-development-signing-ceremony.md), and [v0.1.6 public inputs](../provisioning/releases/rpi5-v0.1.6/README.md) |
| CI migration direction | [Self-hosted Forgejo and Hydra design](self-hosted-git-ci.md) |

## Authority and precedence

When documents appear to disagree, use these boundaries:

1. Checked hardware evidence is authoritative only for the observations it
   records. It is not authentication, attestation, or mutation authorization.
2. Code, schemas, and tests define implemented software behavior; prose must not
   promote their synthetic results into physical evidence.
3. The secure-boot and device-identity designs retain their fail-closed security
   requirements. The production roadmap selects future mechanisms within those
   requirements rather than weakening them.
4. The execution plan retains the sacrificial milestone's original gates and
   tracks post-fuse reconciliation. The production roadmap is the current
   forward-looking plan.
5. Version-labelled release and operator documents remain historical contracts
   for those immutable artifacts. Do not silently retarget their commands or
   digests to a newer release.

Never derive an irreversible EEPROM, OTP, storage, or signing command from a
design document. Use only a frozen, reviewed, version-bound runbook after every
listed gate is satisfied.

[Raspberry Pi 5 production security follow-on]: raspberry-pi-5-production-security-follow-on.md
[self-hosted Forgejo and Hydra design]: self-hosted-git-ci.md
