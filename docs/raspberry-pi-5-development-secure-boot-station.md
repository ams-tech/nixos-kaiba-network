# Raspberry Pi 5 development secure-boot station

This image exists for one purpose: move the fixed sacrificial development Pi
from its verified blank state to the already-signed v0.1.6 secure-boot state,
then prove that the signed system boots.

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

## v0.1.13 release image

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

The sacrificial Pi's verified signed v0.1.6 target media must already be
installed before the final normal boot. The station image does not stage that
target media and contains no private key or signing capability.

## Physical interface

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

If the commit command is interrupted after its durable `commit_started`
record, it is never repeated automatically. Establish the actual state through
the same physical, no-input interface with:

```console
kaiba-secure-boot reconcile
```

Reconciliation first tries the signed owned readback. If that cannot establish
the programmed state, it waits for a second physical reconnect and tries the
read-only fresh bundle. Only a complete, identity-matched blank observation
permits another explicitly started commit attempt; every other result remains
stopped.

Then run `kaiba-secure-boot provision` to finish the readback and signed UART
boot. No boot-time service automatically reconciles or repeats an uncertain
commit.

`kaiba-secure-boot inventory` prints the compiled release and lane identity.
