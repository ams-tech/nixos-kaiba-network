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

At the station console, run:

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
also exports
`QUALIFICATION_SCHEMA` and sets `umask 077`.

Before attaching the sacrificial target, complete a physical first-boot smoke
test on the station Pi 5: confirm the console returns after logout, the
readiness sequence succeeds, `/run/current-system` resolves to one store path,
the private path reports `tmpfs`, SSH host keys generate without errors, and a
test `0a5c:2712` device is visible to the operator. CI builds and inspects the
image but cannot prove these board, bootloader, or USB behaviors.

Continue with the [sacrificial-device operator runbook]. Transfer only
`hardware-qualification.json` for independent schema validation on the clean
review workstation. Never copy `probe-1.json`,
`probe-2.json`, or the preflight record to unencrypted media or into the
repository.

[`ams-tech/nixos-raspberrypi` fork]: https://github.com/ams-tech/nixos-raspberrypi/tree/kaiba
[sacrificial-device operator runbook]: raspberry-pi-5-provisioning-probe.md#sacrificial-device-operator-runbook
