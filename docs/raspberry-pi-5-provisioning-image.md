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
programming utilities that this target-read-only qualification station must not
place in the operator environment. The development image does expose the Pi 5
RP1 header controller for relay bench qualification; that exception can change
station GPIO state, but it does not add a target OTP or EEPROM mutation path.

## Image boundary

The image provides:

- the repository's tested AArch64 `kaiba-provision` package and Raspberry Pi 5
  profile;
- access to exactly USB `0a5c:2712` for the `kaiba-provision` operator group;
- `gpiodetect`, `gpioinfo`, and `gpioset`, plus
  `kaiba-relay-gpio-inventory`, for the development relay bench;
- access to only the gpiochip whose bound parent driver and post-enumeration
  kernel label are exactly `pinctrl-rp1`, via the `kaiba-relay-gpio` operator
  group and stable `/dev/gpiochip-kaiba-rp1` alias;
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

The operator's raw USB and RP1 GPIO groups remain privileged roles. Libgpiod
opens a gpiochip read/write even for inventory, so group membership necessarily
permits `gpioset` to request any otherwise-free RP1 line; the inventory helper
is a validation and convenience command, not an authority boundary. The image
keeps `provisioner` out of the broader inherited `gpio` group and grants no
access to the other SoC gpiochips, `gpiomem`, or PWM devices. It also removes
the known target installer mutation tools and keeps the supported target probe
metadata-only, but it cannot make a shell user with raw device access
cryptographically incapable of misuse. Use this appliance only for the
controlled sacrificial-device and relay-qualification work. Remove this raw
operator GPIO role in the later live mutation deployment; the root lane guard
must exclusively own its reviewed chip and line there.

## Relay GPIO inventory

The relay HAT belongs on the station Pi, never on the sacrificial target. Power
the station completely off before fitting the HAT, and leave all relay screw
terminals disconnected for the first boot. Then run:

```console
kaiba-relay-gpio-inventory
```

The udev rule matches the already-bound `pinctrl-rp1` parent driver because the
kernel emits the gpiochip add event before publishing the chip's `label`
attribute. The command then resolves the kernel-numbered gpiochip through the
stable alias, requires the exact post-enumeration `pinctrl-rp1` label and
operator access, prints the resolved `/dev/gpiochipN`, and reports only
candidate relay lines 4, 6, 22, and 26. Bare
`gpiodetect` may also inspect unrelated SoC gpiochips for which `provisioner`
deliberately has no access, so use the fixed inventory command for this image.
The helper validates `/dev/gpiochipN` through `/sys/class/gpio/chipN`; the
similarly named legacy `/sys/class/gpio/gpiochipM` uses a deprecated global
GPIO base, so `M` is not the character-device number.
The image also enables the Raspberry Pi `strict_gpiod` base-DT parameter and
the helper refuses to proceed unless the live RP1 driver reports
`persist_gpio_outputs=N`. Without that setting, the downstream Raspberry Pi
kernel may leave an asserted output electrically high after `gpioset` exits.
Strict release returns the line to an input; it does not replace the qualified
relay HAT's physical normally-off bias.
Do not connect a target load until the selected active-high line has passed
power-up, process-exit, reboot, and station-power-loss release tests with the
normally-open contact.

## Build from the frozen revision

Commit every intended source and lock-file change before producing the image.
The root flake pins the Raspberry Pi fork and advertises its public Cachix
cache; `--accept-flake-config` opts into that cache for the command being run.
CI additionally pulls reusable project outputs from the public
`nixos-kaiba-network` cache documented in the repository
[continuous-integration guide](../README.md#nix-binary-cache), using the
verified public signing key pinned in the workflows. A local builder may opt
into that project cache with `cachix use nixos-kaiba-network`; it is an
optimization and does not change the image derivation, but it does trust that
cache's signer for substituted project outputs.
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

The appliance disables the Nix daemon and configuration switching, so an
existing station cannot be upgraded in place. Flash the newly built image to
the station SD card and boot that card to obtain the GPIO tools and group
membership.

The final command needs native AArch64, an AArch64 remote builder, or configured
emulation. CI builds it on the native `ubuntu-24.04-arm` runner. Its output is:

```text
result/sd-image/kaiba-rpi5-provisioning.img.zst
```

## Release policy

This read-only qualification image remains buildable as
`packages.aarch64-linux.rpi5-provisioning-sd-image`, but stable releases from
v0.1.11 onward publish only the direct, mutation-capable development
secure-boot station. Starting with v0.1.13, the operator launches its fixed
runner in the foreground instead of a boot-time service. Use the [secure-boot
station release and physical boot
procedure](raspberry-pi-5-development-secure-boot-station.md) for the GitHub
asset that provisions the sacrificial Pi.

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
