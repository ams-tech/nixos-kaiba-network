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
- `kaiba-provision-lane-guard` is the root-only, one-shot physical adapter.
- `kaiba-provision-signer`, `kaiba-provision-signing-client`, and
  `kaiba-provision-signing-gate` enforce the immutable approval boundary.
- `kaiba-provision-yubikey-wrapper` performs the fixed RSA-2048/SHA-256 PIV 9c
  operation through the pinned OpenSSL PKCS#11 provider chain.
- `kaiba-provision-sign-boot` submits one immutable public boot plan to the
  fixed signing gate and offline-finalizes its public result. The generic build
  has no signing authority and can only finalize.
- `kaiba-provision-media-stager` preflights, writes, and reopens exactly three
  digest-bound payload extents. Its regular-file fixture mode is the safe
  rehearsal path; whole-device mode remains an explicit, root-only operation.
- `kaiba-provision-station` serves the separate live, loopback-only operator
  interface. It never falls back to the browser simulation.

The generic lane and signer binaries are deliberately unconfigured and fail
closed. A deployment must instantiate `lib.mkRpi5PhysicalLaneGuard` and
`lib.mkDevelopmentYubiKeySigning`, then use the corresponding NixOS modules.
The YubiKey PIN is a runtime systemd credential; it is never a Nix value.
Normal-boot signing additionally uses `lib.mkRpi5BootSigningPlan` and
`lib.mkRpi5VerifiedSignedBoot`. A signer-verified capsule can be wrapped in a
deterministic outer FAT/GPT regular-file rehearsal with
`lib.mkRpi5MediaStagingFixture`; see the
[signed-boot workflow](../docs/raspberry-pi-5-signed-boot-workflow.md) and
[media-staging prototype](../docs/target-media-staging-prototype.md).

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
