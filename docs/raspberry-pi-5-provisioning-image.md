# Raspberry Pi 5 provisioning-station SD image

The repository root flake builds a bootable Raspberry Pi 5 SD image for the
station that runs the sacrificial-device hardware qualification. It is **not**
normal-boot media for the sacrificial target. The target remains attached to a
separate, labelled USB lane and uses its own known-good normal-boot media.

The image composes the Raspberry Pi 5 kernel, firmware, generation bootloader,
and SD-image modules from commit
`24b786fc4750abcce26eb8fc5e9e58632e358ad2` on the `kaiba` branch of the
[`ams-tech/nixos-raspberrypi` fork]. It deliberately does not use that fork's
generic installer module, because the installer includes EEPROM and OTP
programming utilities that this read-only qualification station must not place
in the operator environment.

## Image boundary

The image provides:

- the repository's tested AArch64 `kaiba-provision` package and Raspberry Pi 5
  profile;
- access to exactly USB `0a5c:2712` for the `kaiba-provision` operator group;
- the `provisioner` physical-console account, with no `sudo`, Nix daemon, or
  runtime configuration-switching or first-boot Nix-store registration
  authority;
- optional SSH restricted to public-key authentication for `provisioner`, with
  no key or credential baked into the image;
- `jq` and `usbutils` for the operator ceremony;
- a readiness command that derives the canonical `/run/current-system` closure
  and rejects an image whose source marker is not one clean 40- or 64-hex Git
  revision; and
- `/var/lib/kaiba-hardware-qual/private` as a 256 MiB, mode `0700`, no-exec
  `tmpfs`, with swap, persistent journals, and core dumps disabled.

The root partition receives 256 MiB of deterministic write headroom when the
image is built and is not automatically expanded or repartitioned on first
boot.

When the documented paths are used, private probe results remain in volatile
memory rather than reaching the image's unencrypted SD filesystem. The
operator shell still has ordinary file-copying tools, so this is an enforced
mount boundary, not data-loss prevention. The results are intentionally lost
if the station reboots or loses power. Keep the station powered for the entire
ceremony, transfer the final redacted record before shutdown, and restart from
probe 1 after any station restart. Power cycling the separate sacrificial
target does not affect this volume.

The operator's raw USB group remains a privileged role. This image removes the
known installer mutation tools and makes the supported command path
metadata-only, but it cannot make a shell user with raw device access
cryptographically incapable of misusing another program. Use this appliance
only for the controlled sacrificial-device ceremony.

## Build from the frozen revision

Commit every intended source and lock-file change before producing the image.
The root flake pins the Raspberry Pi fork and advertises its public Cachix
cache; `--accept-flake-config` opts into that cache for the command being run.
On a multi-user Nix installation, only a trusted Nix user can accept restricted
substituter and signing-key settings. If Nix reports that it ignored either
setting, have the administrator add this exact cache URL and key to the daemon
configuration, use an approved native builder, or let CI build the image.

```console
test -z "$(git status --porcelain=v1 --untracked-files=all)"

nix --accept-flake-config flake check --all-systems --no-build -L
nix --accept-flake-config build --no-link -L \
  .#checks.x86_64-linux.rpi5-provisioning-image-eval
nix --accept-flake-config build -L \
  .#packages.aarch64-linux.rpi5-provisioning-sd-image
```

The final command needs native AArch64, an AArch64 remote builder, or configured
emulation. CI builds it on the native `ubuntu-24.04-arm` runner. Its output is:

```text
result/sd-image/kaiba-rpi5-provisioning.img.zst
```

## Release the image

The release workflow accepts stable `vMAJOR.MINOR.PATCH` tags whose commits are
reachable from `main`. Wait for that commit's CI run to succeed, then create and
push an annotated tag from a clean, reviewed `main` checkout:

```console
git tag --annotate v0.1.0 --message "Kaiba provisioning image v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` rebuilds the exact tagged revision on native
ARM64 and creates a GitHub release with these assets:

```text
kaiba-rpi5-provisioning-v0.1.0.img.zst
kaiba-rpi5-provisioning-v0.1.0.img.zst.sha256
```

The build validates the Zstandard archive before publication, and the
publication job independently verifies the downloaded artifact against the
checksum. Download both files and verify them before flashing:

```console
sha256sum --check kaiba-rpi5-provisioning-v0.1.0.img.zst.sha256
zstd --test kaiba-rpi5-provisioning-v0.1.0.img.zst
```

GitHub requires each release asset to be smaller than 2 GiB, so the workflow
fails with an explicit error if the compressed image reaches that limit.
Protect the repository's `v*` tag pattern from updates and deletion with a
ruleset. The workflow verifies the remote tag against the built commit before
creating and again before publishing the release, while the ruleset prevents a
tag update in the remaining publication window.

## Flash and boot

Raspberry Pi Imager can write the compressed image as a custom image. For a
command-line write, first inspect the complete block-device inventory and set
`TARGET` to the whole SD-card device, not one of its partitions:

```console
lsblk --paths --output NAME,SIZE,MODEL,SERIAL,TRAN,MOUNTPOINTS
IMAGE=$(readlink -f result/sd-image/kaiba-rpi5-provisioning.img.zst)
TARGET=/dev/replace-with-verified-whole-sd-device
test -f "$IMAGE"
test -b "$TARGET"
```

The next command irreversibly overwrites the selected device. Re-check
`TARGET` immediately before running it, unmount any of that card's mounted
partitions, and never substitute the station's system disk:

```console
zstd -dc "$IMAGE" | sudo dd of="$TARGET" bs=4M conv=fsync status=progress
```

Boot the station Pi 5 with a display and keyboard. Root and `provisioner` are
locked, and the account is not a member of `wheel`. Physical consoles
automatically return to the operator account after logout so an accidental
shell exit does not destroy the volatile ceremony by forcing a reboot. Wired
Ethernet uses DHCP through `systemd-networkd`. SSH accepts only a public key;
to opt in from the physical console, add the operator's public key to
`~/.ssh/authorized_keys` with directory mode `0700` and file mode `0600`.
This deliberately lets the physical operator establish persistent remote
access; inspect or remove that key before reusing the station card.

## Enter the qualification environment

Before invoking the ceremony, complete the physical first-boot smoke test on
the station Pi 5: confirm the console returns after logout, the readiness
sequence succeeds, `/run/current-system` resolves to one store path, the
private path reports `tmpfs`, SSH host keys generate without errors, and a test
`0a5c:2712` device is visible to the operator. Also confirm the frozen revision
passed the required x86 and native AArch64 checks. CI builds and inspects the
image but cannot prove the board, bootloader, or USB behaviors. The guided
command requires an explicit `STATION-QUALIFIED` confirmation for these
prerequisites.

The preferred path is the image-integrated guided ceremony. It performs the
readiness checks, creates an isolated private session, discovers and binds the
RPIBOOT topology path only after observing an empty bus, runs both probes and
qualifier phases, and validates candidate records against the full schema. It
pauses for the physical operations and their operator confirmations:

```console
kaiba-qualification-ceremony --lane-id lane-1
```

The lane ID is a permanent label for the physical cable/port, not a USB device
number. Physically label the known-good target boot medium with a short opaque
identifier; the command records it in the private operator context and repeats
the exact criterion before and after probing. The command prints the path to
the only final record that may be transferred. Raw probe results, diagnostics,
state, operator context, and the incomplete preflight remain in the volatile
private session.

For readiness diagnosis or the auditable manual fallback, initialize the
environment directly:

```console
READY_ENV="$(kaiba-qualification-ready)" &&
eval "$READY_ENV" &&
unset READY_ENV
printf '%s\n' \
  "SOURCE_REVISION=$SOURCE_REVISION" \
  "SYSTEM_CLOSURE=$SYSTEM_CLOSURE" \
  "PROFILE=$PROFILE" \
  "PRIVATE=$PRIVATE"
```

The readiness sequence remains nonzero and does not evaluate an empty
environment when the image is dirty, the NixOS marker is absent, the system
closure is noncanonical, the private directory is not volatile and mode
`0700`, swap is active, or the operator lacks the exact probe USB group. It
also exports `QUALIFICATION_SCHEMA` and sets `umask 077`. `PROFILE` and
`QUALIFICATION_SCHEMA` resolve directly into the pinned `kaiba-provision`
package, so readiness does not depend on generic `/run/current-system/sw/share`
linking.

Continue with the [sacrificial-device operator runbook] when using the manual
fallback.

### After either workflow

Before powering the station off, transfer only the final
`hardware-qualification.json` path reported by the guided command. Treat it as
schema-valid, whitelist-redacted evidence, not as anonymous data: its stable
pseudonymous digests still require publication review. Never transfer the raw
probe results, diagnostics, operator context, state, incomplete preflight, or
an orphan `.partial` file.

On a clean review-workstation checkout of the exact frozen revision, validate
the transferred record independently:

```console
nix develop ./nix/provisioning --command check-jsonschema \
  --schemafile provisioning/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
  /path/to/hardware-qualification.json
```

Verify that its `source_revision` equals that frozen revision. For a reviewed
closeout, copy only this final record to
`tests/provisioning/evidence/sacrificial-pi-5.json` and update
`tests/provisioning/report-input.json` as described in the runbook. After a
successful transfer, reboot the station to clear all volatile evidence before
starting another ceremony.

[`ams-tech/nixos-raspberrypi` fork]: https://github.com/ams-tech/nixos-raspberrypi/tree/kaiba
[sacrificial-device operator runbook]: raspberry-pi-5-provisioning-probe.md#sacrificial-device-operator-runbook
