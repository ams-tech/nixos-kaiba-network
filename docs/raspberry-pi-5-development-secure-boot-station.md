# Raspberry Pi 5 development secure-boot station

This image was built for one purpose: move the fixed sacrificial development Pi
from its verified blank state to the already-signed v0.1.6 secure-boot state,
then prove that the signed system boots.

The sacrificial Pi has now been fused and boots a signed development `target`
image. This page retains the immutable release inputs and original operator
sequence; it is **not** authorization to run the fresh-board commit again. Read
the existing station `status` first and follow the state-specific table below;
invoke `reconcile` only for `commit_started`. The exact running target version
and post-fuse evidence packet are tracked as open items in the
[sacrificial-device state](raspberry-pi-5-sacrificial-state.md).

It does not contain a signer, a signing credential, a remote authority bridge,
or an approval workflow. The v0.1.6 signed release, target fingerprint,
RPIBOOT USB path, and receive-only UART path are compiled into one local
runner. The operator starts that runner in the foreground after the station
boots.

There is no provisioning systemd service. The installed wrapper has permission
to execute only the fixed runner, and the runner accepts no artifact, target,
USB-path, or UART-path overrides. It never asks for a typed
irreversible-operation phrase; direct observation of the fixed USB path advances
each physical transition.

## v0.1.13 provisioning-station image

The v0.1.13 GitHub release contains exactly:

```text
kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst
kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst.sha256
```

Download and verify both files before writing the compressed image with
Raspberry Pi Imager or another Zstandard-aware disk writer:

```console
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.13/kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.13/kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst.sha256
sha256sum --check --strict \
  kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst.sha256
zstd --test kaiba-rpi5-development-secure-boot-station-v0.1.13.img.zst
```

The station image does not stage target media and contains no private key or
signing capability.

## v0.1.14 qualification target image

The separate v0.1.14 release contains the flashable signed target media intended
for the v0.1.13 station's final qualified normal boot. Without the reconciled
post-fuse packet, the repository does not establish that this was the image
actually booted:

```text
kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst
kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst.sha256
```

It is a fixed 3 GiB whole-disk GPT image and therefore requires a nominal 4 GB
or larger SD card. It contains the exact public signed v0.1.6 payload from
source revision `8e9f1d5cd97ff46d8b56b1128251ca70b7fec598`, including the immutable
dm-verity root and hash tree. The archive and decompressed whole-disk image are
bound to fixed SHA-256 digests because a clean rebuild of the historical
unsigned boot filesystem is not byte-reproducible and therefore cannot be
paired safely with the existing signature. It contains no signing key or
signing capability.

Download and verify both target-image assets:

```console
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.14/kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.14/kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst.sha256
sha256sum --check --strict \
  kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst.sha256
zstd --test kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst
```

The original procedure wrote the compressed image directly with Raspberry Pi
Imager or another Zstandard-aware whole-disk writer without extracting or
copying individual partitions, then installed that card before the final normal
boot. Do not interpret this historical step as the identity of the image now
running.

## v0.1.15 development target image (publication pending)

The v0.1.15 tag defines a newly signed development payload with the USB SSH
management interface. As of 2026-09-07, its GitHub release is still a draft and
contains the image archive but not the checksum asset. It is not a public,
operator-verifiable download yet:

```text
kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst
kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst.sha256
```

Its annotated release tag binds the exact source revision, compressed archive
SHA-256, decompressed whole-disk SHA-256, and archive byte size. It contains no
signing key or signing capability. Do not install it until recovery has
published the non-draft release and both named assets below are present. At that
point, download and verify them before writing the whole-disk image:

```console
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.15/kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst
curl --fail --location --remote-name \
  https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.15/kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst.sha256
sha256sum --check --strict \
  kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst.sha256
zstd --test kaiba-rpi5-development-secure-boot-target-v0.1.15.img.zst
```

The v0.1.13 station does not qualify this later boot digest. After publication,
install v0.1.15 on the fused Pi only as a separately reviewed owned-device
update after the current release and post-fuse state are reconciled. Historical
pre-fuse qualification does not authorize the update.

## Physical interface

The sequence below documents the original fixed ceremony for a verified
hash-zero candidate. Do not perform steps 1–4 on the now-fused sacrificial Pi.
For that board, preserve the station journal and begin with `status` or the
owned-state reconciliation path.

Boot the station with the target disconnected. At the autologin shell, start
the foreground workflow:

```console
kaiba-secure-boot provision
```

Leave that command running and perform the physical transitions when its
`WAITING` messages describe the state it is observing:

1. Hold BOOTSEL and connect the target to the fixed provisioning USB lane for
   the read-only blank-state observation. Release BOOTSEL once RPIBOOT appears.
2. After that RPIBOOT session ends, completely disconnect the target. Hold
   BOOTSEL and reconnect it for the one-time commit.
3. After the commit session ends, completely disconnect it again. Hold BOOTSEL
   and reconnect it for the signed owned-state readback.
4. Disconnect provisioning USB, leave BOOTSEL untouched, and start the target
   normally with the verified signed v0.1.6 SD card installed.

The foreground command advances from direct USB disappearance and exact-path
reappearance, not from console input. The second exact RPIBOOT connection is
the physical trigger for applying the signed payload, but only after the first
connection returned the compiled target fingerprint and a blank customer-key
state.

The command succeeds only after it observes the expected customer-key hash,
rejects any conflicting EEPROM hash, and receives exactly one
`KAIBA_SECURE_BOOT_EVIDENCE=pass` record for the fixed boot-image digest with
the customer-key OTP bit set.

The read-only pre-observation and the commit never share an RPIBOOT session.
Metadata recovery consumes that session, so a complete disconnect and new
RPIBOOT connection remain necessary even though no keyboard input is required.

Durable progress and the final result are stored under:

```text
/var/lib/kaiba-development-secure-boot
```

Inspect progress with:

```console
kaiba-secure-boot status
```

For the known-fused sacrificial Pi, the durable state controls which read-only
continuation is safe. The runner's generic fresh path remains in the binary but
is policy-retired for this asset:

| Durable state | Allowed handling for this Pi |
| --- | --- |
| `complete` | Export and review the existing result; perform no commit action. |
| `readback_verified` | A reviewed `provision` continuation may capture only the signed normal boot and finalize the result. |
| `commit_verified` | A reviewed `provision` continuation may perform only the customer-signed owned readback and signed normal boot. |
| `commit_started` | Preserve the journal. A reviewed `reconcile` may observe the original attempt; it must never redispatch it. Continue with `provision` only after reconciliation explicitly establishes the owned state. |
| absent, mismatched, `preobserved`, or `commit_not_applied` | Stop. Do not run `provision`; the current binary would enter its fresh commit path. Treat this as missing or contradictory evidence and use owned-device quarantine/recovery review. |

The direct runner has no journal-independent owned-state collector. Until one
exists, a missing or incompatible station journal cannot be reconstructed by
trying the fresh bundle or starting a new transaction.

If the commit command is interrupted after its durable `commit_started`
record, it is never repeated automatically. Establish the actual state through
the same physical, no-input interface with:

```console
kaiba-secure-boot reconcile
```

The generic runner first tries the signed owned readback and may then try its
historical blank-state fallback. For this operator-confirmed fused asset, any
blank result means the target, journal, or evidence binding is wrong. Ignore any
generic prompt to make a new attempt, stop, preserve the evidence, and classify
the device for owned-state quarantine or separately reviewed recovery. Run
`kaiba-secure-boot provision` after reconciliation only when the status is
explicitly `readback_verified`, so it can finish signed-UART capture without
executing a commit. No boot-time service automatically reconciles or repeats an
uncertain commit.

`kaiba-secure-boot inventory` prints the compiled release and lane identity.
