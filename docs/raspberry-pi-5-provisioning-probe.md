# Raspberry Pi 5 provisioning probe

This document describes the first implemented slice of the provisioning
station design: a probe that identifies one Raspberry Pi 5 Model B and
evaluates the part of its initial security posture that Raspberry Pi OTP
metadata exposes. It supports imported metadata for development and a
lane-bound live USB mode for a controlled provisioning station.

The result is correlation and partial preflight evidence. It is **not** device
authentication, remote attestation, a complete determination that a device is
unprovisioned, or authorization to change the device. The command always emits
`mutation_eligible: false` and `full_unprovisioned_state: not_established`.

The profile and adapter are experimental until the hardware qualification at
the end of this document has been completed and reviewed.

## Safety boundary

Live probing is read-only with respect to persistent target state, but it is
not passive inspection. The station uploads Raspberry Pi-signed
`recovery.bin` into volatile RAM through the BCM2712 RPIBOOT protocol. The
[Raspberry Pi recovery documentation] describes the stock `recovery5`
directory as an EEPROM updater, so the probe never runs that directory. A
[Raspberry Pi maintainer] separately confirms that the same signed recovery
program supports standalone OTP metadata retrieval when no EEPROM image is
provided.

The Nix package therefore constructs a separate immutable bundle containing
exactly:

```text
bootcode5.bin  # recovery.bin from the source pinned by pkgs.rpiboot
config.txt     # exactly: recovery_metadata=1
```

The package also records the SHA-256 digests of `rpiboot`, both bundle files,
and the complete bundle. The command checks those values and the exact file
set before every live probe. Symlinks, additional files, altered content, and
programming or erase directives fail before USB access. The command invokes
the pinned binary directly, with an exact USB path and without a shell,
`sudo`, loop mode, overlays, file-based metadata output, or a user-selected
payload:

```text
rpiboot -p <exact-usb-path> -d <probe-bundle>
```

The recovery program emits its metadata object on standard output by default;
the probe deliberately does not pass `rpiboot`'s `-j` file-output option.

This unsigned recovery program is usable only before a customer secure-boot
key is fused. BCM2712 requires recovery firmware to be counter-signed by that
customer key afterward. Owned-device reconciliation consequently requires a
separate, fleet-signed probe bundle and is outside this version. See the
[official Pi 5 secure-boot procedure].

## Station configuration

The NixOS module is disabled by default. A new station can consume the
provisioning leaf without importing the DNS packages or modules:

```nix
inputs.kaiba-provisioning = {
  url = "github:ams-tech/nixos-kaiba-network?dir=nix/provisioning";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

A minimal station configuration can use the module form below when the
surrounding `nixosSystem` passes `specialArgs = { inherit inputs; };`:

```nix
{ inputs, pkgs, ... }:

{
  imports = [ inputs.kaiba-provisioning.nixosModules.provisioning-probe ];

  services.kaiba-provisioning-probe = {
    enable = true;
    package = inputs.kaiba-provisioning.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision;
    operators = [ "provisioner" ];
  };
}
```

Keep the package assignment explicit so its provenance does not depend on a
module-specific default. The repository-root flake is a compatibility facade,
so an existing `inputs.kaiba` configuration can keep using
`inputs.kaiba.nixosModules.provisioning-probe` and
`inputs.kaiba.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision`.

The module installs `kaiba-provision`, creates the `kaiba-provision` group,
adds only the named operators to it, and grants that group mode `0660` access
to USB vendor/product `0a5c:2712`. It does not create a service or daemon.
Membership is a privileged station role: it permits raw access to an attached
BCM2712 target, not merely permission to run this probe.

Keep one target on one physically labelled USB lane. Determine its stable
sysfs USB path, such as `1-2.3`, before starting the transaction. Do not use a
changing `/dev/bus/usb` device number as the lane identity.

From a checkout, the provisioning boundary can be checked and its probe
package built independently:

```console
nix flake check ./nix/provisioning -L
nix build ./nix/provisioning#kaiba-provision -L
```

## Running the probe

Live mode requires the profile, permanent lane label, and exact USB path:

```console
kaiba-provision probe \
  --profile /run/current-system/sw/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json \
  --lane-id lane-1 \
  --usb-path 1-2.3
```

Disconnect all power from the target, hold its power button, and attach its
USB-C port to the controlled lane before running the command. The command
rejects an absent target, a second eligible BCM2712 target, or a target that is
not at the requested path. Target verification and the `rpiboot` subprocess
share a 60-second deadline. Local validation of the immutable Nix-store bundle
also occurs before execution; its regular-file hashing is not interruptible.

Offline mode parses a previously captured vendor metadata object and performs
no subprocess or USB access:

```console
kaiba-provision probe \
  --profile ./profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json \
  --metadata ./device-metadata.json
```

Use `--metadata -` to read the object from standard input. Imported evidence
does not carry live tool, bundle, lane, or transport provenance.

Successful parsing produces exactly one JSON result on standard output.
Operational diagnostics go to standard error. Exit status is:

| Status | Meaning |
| --- | --- |
| `0` | Device class and every currently observable baseline condition pass |
| `1` | Unexpected internal failure |
| `2` | Invalid command or device profile |
| `3` | Acquisition, integrity, continuity, or metadata-format failure |
| `4` | Valid evidence describes an incompatible device class |
| `5` | Device class matches, but an observable baseline condition failed or is indeterminate |

Class and policy failures still produce the structured result. An acquisition
or parsing failure does not fabricate an observation.

## Evidence and interpretation

The adapter normalizes the factory UUID, user serial, board revision and its
decoded fields, board attributes, boot ROM, Ethernet/Wi-Fi/Bluetooth MACs,
EEPROM hash, customer-key hash, signature mode, and VideoCore JTAG state. It
retains recognized operation-result fields as diagnostics and unknown vendor
fields as extensions. Raw imported metadata is not copied into output; only
its SHA-256 digest is retained.

The target-binding fingerprint is a domain-separated SHA-256 digest over the
factory UUID, user serial, and raw board revision. It correlates observations
within a provisioning transaction. It is not proof of private-key possession.
USB paths, MAC addresses, and the EEPROM hash are excluded because they are
transport evidence or mutable values.

The initial profile accepts only new-style revision codes whose processor is
BCM2712 and whose model is Raspberry Pi 5 Model B. Pi 500 and Compute Module 5
use the same processor family but fail the class conditions. The observable
fresh-device baseline additionally requires:

- a zero customer secure-boot key hash;
- unlocked VideoCore JTAG; and
- an observed EEPROM hash.

Any unknown vendor field makes the baseline indeterminate until the pinned
adapter and profile understand it. Operation results such as
`EEPROM_UPDATE=success` or `SECURE_BOOT_PROVISION=success` in live output are a
safety violation, not evidence that the probe succeeded.

The probe cannot inspect device-private-key rows, unrelated customer OTP,
EEPROM write protection, attached storage, all debug paths, inventory
ownership, or the authenticity of the current EEPROM contents. Those checks
remain explicitly deferred and prevent the result from authorizing later
mutations.

## Hardware qualification gate

Do not promote the profile from `experimental` to `stable` or merge a change
that enables the live path until a sacrificial fresh Pi 5 Model B passes this
ceremony:

1. Record the exact Git revision, Nix closure, profile digest, `rpiboot`
   digest, recovery-program digest, configuration digest, and bundle digest.
2. Run the probe and retain a redacted result. Do not redact hashes or board
   revision, but treat the serial, UUID, and MAC addresses as inventory data.
3. Remove all target power, reconnect it in RPIBOOT mode to the same lane, and
   run the probe again.
4. Compare user serial, factory UUID, raw board revision, boot ROM, EEPROM
   hash, zero customer-key hash, and unlocked JTAG. Every value must be stable.
5. Confirm that neither result reports a successful mutation operation.
6. Boot the target normally and confirm its pre-probe behavior is unchanged.

Stop qualification and quarantine the target if any persistent observation
changes, a mutation result appears, the target cannot boot normally, or the
second target-binding fingerprint differs. Attach the two redacted results and
comparison record to the pull request; hardware qualification cannot be
performed by repository CI.

[Raspberry Pi recovery documentation]: https://github.com/raspberrypi/usbboot/blob/master/recovery5/README.md
[Raspberry Pi maintainer]: https://github.com/raspberrypi/rpi-eeprom/issues/735
[official Pi 5 secure-boot procedure]: https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/README.md
