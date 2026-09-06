# Raspberry Pi 5 development-target access

This document describes the development-only management interface built into
the signed Raspberry Pi 5 v0.1.15 target image. The published v0.1.14 target
image remains immutable and does not contain this access path.

The development target uses its USB-C power/RPIBOOT connector as a USB Ethernet
gadget during a normal signed boot. The same cable returns to BCM2712 RPIBOOT
after an authenticated administrator requests the one-shot transition.

## Fixed interface

| Property | Value |
| --- | --- |
| Target interface | `usb0` |
| Target address | `10.0.0.2/24` |
| Target gadget MAC | `02:4b:41:49:42:41` |
| Host-side gadget MAC | `02:4b:41:49:42:42` |
| Expected Linux host interface | `enx024b41494242` |
| SSH user | `codex` |
| UART on `malak` | `/dev/ttyACM0`, 115200 baud |

Only TCP port 22 is admitted on the USB interface. The target has no DHCP or
default route. Password, keyboard-interactive, and root SSH login are disabled.
The fixed `codex` public key is the only login credential. That user has
passwordless `sudo` because this image is deliberately a root-accessible,
sacrificial development target; this policy must not be inherited by a
production image.

The admitted public key has this fingerprint:

```text
SHA256:VMKz3Ehb1Qi3ETrpUI4eJjkzuMIr9hDXIATW/5+/EPU
```

The corresponding private key is kept only on `malak`, at
`/home/codex-remote/.ssh/kaiba-rpi5-development`, with mode `0600`. It is not in
Git, the Nix store, the unsigned artifact set, or the signed image.

## Connect from `malak`

Start the UART capture before powering or rebooting the target. Only one
process may consume the serial stream:

```console
stty -F /dev/ttyACM0 115200 raw -echo
stdbuf -oL cat /dev/ttyACM0 | tee /tmp/kaiba-rpi5-uart.log
```

During a valid signed boot, the existing target evidence appears first. SSH
readiness then appears in this canonical form:

```text
KAIBA_DEVELOPMENT_SSH=ready user=codex address=10.0.0.2 host_key=SHA256:...
```

The host key is generated in tmpfs on every boot. Treat the UART fingerprint as
the trusted binding for that boot rather than accepting an unauthenticated
network host key.

In another shell, configure the fixed host address:

```console
sudo ip link set enx024b41494242 up
sudo ip address replace 10.0.0.1/24 dev enx024b41494242
```

Fetch the presented Ed25519 host key and compare its fingerprint with the exact
fingerprint printed on UART:

```console
ssh-keyscan -T 5 -t ed25519 10.0.0.2 > /tmp/kaiba-rpi5-known-hosts
ssh-keygen -E sha256 -lf /tmp/kaiba-rpi5-known-hosts
```

After they match, connect with the private key held on `malak`:

```console
ssh -i /home/codex-remote/.ssh/kaiba-rpi5-development \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/tmp/kaiba-rpi5-known-hosts \
  codex@10.0.0.2
```

Confirm non-interactive administrative access once:

```console
sudo -n true
```

## Enter RPIBOOT without pressing BOOTSEL

From the authenticated SSH session, request the Raspberry Pi bootloader's
one-shot USB boot mode:

```console
sudo kaiba-enter-rpiboot
```

The helper writes the Raspberry Pi reboot-mode mailbox, flushes pending writes,
and reboots. The USB Ethernet device disappears and the BCM2712 RPIBOOT USB
device should enumerate on `malak` over the same cable. This is a one-shot
selection: a later reset or power cycle without another request follows the
normal boot order.

If the running OS or SSH path is broken, software cannot execute the mailbox
request. Hardware BOOTSEL control or a physical button press remains the
recovery path for that failure mode. Likewise, a USB host port may not provide
enough current for an unrestricted Raspberry Pi 5; keep this target headless,
minimize attached peripherals, and reject any UART undervoltage report.

## Security boundary

The SSH server and `codex` key are part of the dm-verity-protected root selected
by the signed boot image. They therefore require a new signed boot payload; they
could not be retrofitted into the already published v0.1.14 image without
breaking its signatures and verified-root digest. The v0.1.15 image carries a
new signature over the updated boot payload and its new verified-root digest.

This interface intentionally grants complete control after public-key
authentication. It is suitable for the designated development Pi only. A
production target must replace it with the narrower enrollment and operational
management policy before release.
