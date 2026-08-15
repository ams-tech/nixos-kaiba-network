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
bootcode5.bin  # recovery.bin from the unmodified source pinned by pkgs.rpiboot
config.txt     # exactly: recovery_metadata=1
```

Sacrificial Pi 5 testing established that this metadata-only recovery path can
legitimately omit `EEPROM_HASH`. The field is not evidence that must exist for
the OTP observation to pass, and its absence does not establish anything about
the EEPROM currently installed on the board. Do not add `pieeprom.bin` to force
the field to appear: recovery treats that file as an EEPROM update payload,
which would cross the probe's non-persistent safety boundary. There is no
`pieeprom.bin` workaround in this qualification procedure.

The same metadata-only path can omit `SIGNATURE_MODE` and `ADVANCED_BOOT`.
Their absence is an unavailable observation, not an implicit zero or disabled
state; the probe and qualifier must never invent either value.

The pinned Nixpkgs host tool predates stdout metadata support. Kaiba preserves
its recovery firmware byte-for-byte and applies only the `main.c` changes from
the upstream [stdout-output commit] and [stdout-default commit] to the host
binary. The patched `main.c` must match the exact SHA-256 recorded in the Nix
expression, and its build banner is fixed to the audited upstream revision
instead of the wall clock so executable digests are reproducible. A native
compatibility check drives its file server with scripted metadata, requires
exactly one JSON object on stdout, verifies that stdout remains open, and
proves that no JSON side file was created. CI runs that check on x86_64 and
AArch64.

The package records the SHA-256 digests of the patched `rpiboot` executable,
both bundle files, and the complete bundle. The command checks those values
and the exact file set before every live probe. Symlinks, additional files,
altered content, and programming or erase directives fail before USB access.
The command invokes the pinned binary directly, with an exact USB path and
without a shell, `sudo`, loop mode, overlays, file-based metadata output, or a
user-selected payload:

```text
rpiboot -p <exact-usb-path> -d <probe-bundle>
```

The recovery program sends metadata fields to the patched host tool, which
emits their JSON object on standard output by default. The probe deliberately
does not pass `rpiboot`'s `-j` file-output option. Do not substitute an
operator-created `-j` directory: it would move private metadata to an
additional serial-derived file outside the wrapper's bounded capture path.

This Raspberry Pi-signed recovery program lacks a customer counter-signature
and is usable only before a customer secure-boot key is fused. BCM2712 requires
recovery firmware to be counter-signed by that customer key afterward.
Owned-device reconciliation consequently requires a separate, fleet-signed
probe bundle and is outside this version. See the
[Kaiba Pi 5 secure-boot guide] and the [official Pi 5 secure-boot procedure].

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
  --profile ./provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json \
  --metadata ./device-metadata.json
```

Use `--metadata -` to read the object from standard input. Imported evidence
does not carry live tool, bundle, lane, or transport provenance.

Successful parsing produces exactly one JSON result on standard output. Treat
a live result as private inventory data: it contains a timestamp, lane and USB
path, serial, factory UUID, MAC addresses, and a stable target fingerprint.
Store both live results outside the source tree with mode `0600`.
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

`kaiba-provision qualify` is an offline comparison and redaction command. It
never accesses USB or invokes `rpiboot`. Its exit status is:

| Status | Meaning |
| --- | --- |
| `0` | Two valid live results are consistent and normal boot is confirmed unchanged |
| `1` | Unexpected internal failure |
| `2` | Invalid command, profile, or operator-supplied ceremony context |
| `3` | A private result is malformed, unsafe, or not comparable |
| `6` | A valid comparison or normal-boot result requires quarantine |
| `7` | Both probe results are consistent, but post-probe normal boot is still pending |

Status `6` and `7` still emit a whitelist-redacted JSON record. Status `2` or
`3` emits no record; stop the ceremony and resolve the input or provenance
error before deciding whether the target must be quarantined.

## Evidence and interpretation

The adapter normalizes the factory UUID, user serial, board revision and its
decoded fields, board attributes, boot ROM, Ethernet/Wi-Fi/Bluetooth MACs,
customer-key hash, and VideoCore JTAG state. When upstream metadata supplies
them, it also normalizes signature mode, advanced-boot state, and an EEPROM
hash. It retains recognized operation-result fields as diagnostics and unknown
vendor fields as extensions. Raw imported metadata is not copied into output;
only its SHA-256 digest is retained.

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
- unlocked VideoCore JTAG.

The EEPROM contents and their hash are explicitly deferred. When both probe
results omit `EEPROM_HASH`, the public summaries encode `eeprom_hash: null` and
the comparison status is `not_observed`; this is an allowed qualification
outcome, not a fabricated match. A hash present in only one result, or two
different observed hashes, is a changed comparison and requires quarantine.

`SIGNATURE_MODE` and `ADVANCED_BOOT` are also optional observations because the
metadata-only recovery path may legitimately omit them. The qualifier treats
each optional field independently: absence from both results is
`not_observed`, presence in only one result is `changed`, and presence in both
results is `match` only when the two canonical values are identical. Different
observed values are `changed`. Any `changed` comparison requires quarantine.
Paired absence does not establish a zero, disabled, or otherwise safe value;
never synthesize a default for either field in qualification evidence. Every
comparison other than `eeprom_hash`, `signature_mode`, and `advanced_boot` must
be observed in both results.

Any unknown vendor field makes the baseline indeterminate until the pinned
adapter and profile understand it. Operation results such as
`EEPROM_UPDATE=success` or `SECURE_BOOT_PROVISION=success` in live output are a
safety violation, not evidence that the probe succeeded.

The probe cannot inspect device-private-key rows, unrelated customer OTP,
EEPROM write protection, the installed EEPROM contents or a dependable hash of
them, attached storage, all debug paths, inventory ownership, or firmware
authenticity. Those checks remain explicitly deferred and prevent the result
from authorizing later mutations.

## Hardware qualification gate

Do not promote the profile from `experimental` to `stable` or merge a change
that enables the live path until a sacrificial fresh Pi 5 Model B passes this
ceremony:

The hardware findings above changed the profile and qualification contract.
Any probe result or comparison record produced before this revision is
obsolete, including results from contracts that required `EEPROM_HASH` as a
baseline fact or rejected absent `SIGNATURE_MODE` and `ADVANCED_BOOT`. After
freezing and installing this revised contract, retain an old result only as
private diagnostic evidence and restart the qualification sequence from probe
1. Never combine a result from the old contract with one from this revision.
Hardware retries still require the complete target power removal and RPIBOOT
re-entry described below.

1. Freeze a clean Git revision whose x86 and native AArch64 checks pass. Build
   and install the station from that revision. Record its exact
   `/run/current-system` store target. Both architectures must have passed the
   `rpiboot-metadata-stdout` compatibility check.
2. Before entering RPIBOOT mode, boot the target normally from named,
   known-good media. Define and record an observable success criterion, such as
   reaching a local console with the expected board model and storage visible.
   Shut the target down and remove every power source.
3. Run the first live probe and retain its private result.
4. Remove every target power source, observe the target disappear from the USB
   bus, reconnect it in RPIBOOT mode to the same labelled lane, and run the
   second live probe.
5. Run `kaiba-provision qualify` over the two private results with normal boot
   still `pending`. It validates the exact profile and live provenance,
   recomputes the assessment, requires every mandatory signal (including both
   wireless MACs) to match, compares stable target observations, and emits a
   deterministic whitelist-redacted record. For EEPROM hash, signature mode,
   and advanced-boot state, two absent observations produce `not_observed` and
   do not fail this preflight; one-sided presence or different observed values
   produce `changed` and require quarantine. Exit `7` means the two probes are
   consistent but normal boot is not yet observed; exit `6` means stop and
   quarantine.
6. Boot the target normally from the same media and repeat the exact success
   criterion from step 2. Run the qualifier again with the result `unchanged`
   or `failed`. Only `unchanged`, with every mandatory comparison matching and
   each optional comparison (EEPROM hash, signature mode, and advanced-boot
   state) either matching or consistently unobserved, can emit a passed record
   and exit `0`.

Stop qualification and quarantine the target if any persistent observation
changes, a mutation result appears, the target cannot boot normally, or the
second target-binding fingerprint differs. A live acquisition error that
mentions a mutation safety violation is also an immediate quarantine event;
there may be no complete result to compare in that case.

The qualifier's one aggregate record contains two redacted probe summaries and
the fixed-order comparison record. It omits timestamps, serials, UUIDs, MAC
values, lane and USB identifiers, the potentially name-bearing NixOS closure
path, and arbitrary vendor extensions. It retains a domain-separated digest of
that closure path, other hashes, board revision, immutable probe-input
provenance, the station Nix system, a status-independent profile-policy digest,
assessment summaries, operator confirmations, and status-only comparisons. An
observed EEPROM hash is retained; an absent one is represented by JSON `null`
and the paired absence by comparison status `not_observed`. Signature mode and
advanced-boot values are not retained in the public record; their comparisons
report only `match`, `changed`, or `not_observed`.
The target fingerprint and evidence digests are stable
pseudonymous identifiers even though they are not raw inventory values; review
their publication with the same care as other hardware evidence. Attach the
final redacted record to the pull request. Hardware qualification cannot be
performed by repository CI.

### Sacrificial-device operator runbook

Use a fresh, unfused Pi 5 Model B, a labelled data-capable cable and lane, and a
station installed from the frozen revision. Confirm that exactly one
`0a5c:2712` RPIBOOT device is present at the selected sysfs path. Keep private
results outside the repository on encrypted station storage or on a bounded
volatile volume. The dedicated [Pi 5 provisioning-station image] supplies the
latter as a no-swap `tmpfs`; keep that station powered throughout the ceremony
and restart from probe 1 if it reboots. On another approved station, the
commands below use placeholders which the operator must set from its frozen
record:

```console
umask 077
install -d -m 0700 /var/lib/kaiba-hardware-qual/private

SOURCE_REVISION=<frozen-lowercase-40-or-64-hex-revision>
SYSTEM_CLOSURE=$(readlink -f /run/current-system)
PROFILE=/run/current-system/sw/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json
PRIVATE=/var/lib/kaiba-hardware-qual/private
```

On the dedicated image, replace that setup block with the readiness command,
which validates the image provenance, closure, private volume, and operator
group before exporting all five variables:

```console
READY_ENV="$(kaiba-qualification-ready)" &&
eval "$READY_ENV" &&
unset READY_ENV
```

The operator must already have permission to create that private directory, or
an administrator must create and hand it over before the ceremony. Do not run
the probe through `sudo`; group-scoped USB access is the intended boundary.

After recording a successful pre-probe normal boot, fully power down and enter
RPIBOOT mode. Run probe 1:

```console
kaiba-provision probe \
  --profile "$PROFILE" \
  --lane-id lane-1 \
  --usb-path 1-2.3 \
  > "$PRIVATE/probe-1.json"
chmod 0600 "$PRIVATE/probe-1.json"
```

Remove all power, observe USB disconnection, reconnect the same target in
RPIBOOT mode on the same lane, and run probe 2:

```console
kaiba-provision probe \
  --profile "$PROFILE" \
  --lane-id lane-1 \
  --usb-path 1-2.3 \
  > "$PRIVATE/probe-2.json"
chmod 0600 "$PRIVATE/probe-2.json"
```

Do not continue after either probe returns nonzero. Preserve diagnostics and
quarantine immediately if they report a mutation safety violation. Otherwise,
perform the comparison preflight before normal boot:

```console
kaiba-provision qualify \
  --profile "$PROFILE" \
  --first-result "$PRIVATE/probe-1.json" \
  --second-result "$PRIVATE/probe-2.json" \
  --source-revision "$SOURCE_REVISION" \
  --system-closure "$SYSTEM_CLOSURE" \
  --power-cycle-confirmation complete \
  --pre-probe-normal-boot confirmed \
  --normal-boot-confirmation pending \
  > "$PRIVATE/comparison-preflight.json"
```

The expected preflight exit is `7` and its status is `incomplete`. Exit `6` or
any validation error means stop and quarantine. After a clean preflight, boot
normally from the original media and apply the same success criterion. Produce
the final public-safe record with exactly one of these outcomes:

```console
kaiba-provision qualify \
  --profile "$PROFILE" \
  --first-result "$PRIVATE/probe-1.json" \
  --second-result "$PRIVATE/probe-2.json" \
  --source-revision "$SOURCE_REVISION" \
  --system-closure "$SYSTEM_CLOSURE" \
  --power-cycle-confirmation complete \
  --pre-probe-normal-boot confirmed \
  --normal-boot-confirmation unchanged \
  > "$PRIVATE/hardware-qualification.json"
```

Use `--normal-boot-confirmation failed` instead if the criterion fails. That
emits a redacted failed/quarantine record and exits `6`. A passed record exits
`0`. On a review workstation with a clean checkout of the same revision,
validate the transferred public-safe record before review:

```console
nix develop ./nix/provisioning --command check-jsonschema \
  --schemafile provisioning/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
  /path/to/hardware-qualification.json
```

Keep both raw probe files private. Copy only the final qualifier output into
`tests/provisioning/evidence/sacrificial-pi-5.json` during the reviewed closeout
change. That change must also update the checked canonical snapshot in
`tests/provisioning/report-input.json`; the Nix expression derives status and
the evidence path from the completed record and binds it to the current profile
policy and pinned probe inputs. The executable digest is checked by the CI job
whose Nix system matches the recorded station; architecture-independent probe
inputs are checked by both jobs. A subsequent, reviewed
`experimental`-to-`stable` status-only promotion is allowed only while the
policy digest remains unchanged. Reviewers must separately verify that
`source_revision` is the frozen ceremony revision. The report is public on
GitHub Pages; never add raw results or an `incomplete` preflight record.

[Raspberry Pi recovery documentation]: https://github.com/raspberrypi/usbboot/blob/master/recovery5/README.md
[Raspberry Pi maintainer]: https://github.com/raspberrypi/rpi-eeprom/issues/735
[official Pi 5 secure-boot procedure]: https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/README.md
[Kaiba Pi 5 secure-boot guide]: raspberry-pi-5-secure-boot.md
[stdout-output commit]: https://github.com/raspberrypi/usbboot/commit/163cc6e5e69c92f39666ad40c496bcd917c1a0d8
[stdout-default commit]: https://github.com/raspberrypi/usbboot/commit/f64fa310afd45eb7c5b46ec4f9319e5404a48e6a
[Pi 5 provisioning-station image]: raspberry-pi-5-provisioning-image.md
