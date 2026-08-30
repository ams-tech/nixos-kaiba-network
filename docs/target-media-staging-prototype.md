# Target-media staging contracts

There are two deliberately separate media paths:

- `lib.mkRpi5MediaStagingFixture` and the legacy mixed
  `kaiba-provision-media-stager` provide a synthetic three-extent rehearsal.
- `lib.mkRpi5ProductionMedia` consumes one complete, content-addressed,
  offline-verified signed release and derives the production GPT, exact FAT,
  full-media plan, plan-specialized device writer, and independent read-only
  verifier.

The first path is useful regression coverage, but it is not an authorization
to write a device. The second path is the software contract intended for the
physical SB-04 ceremony. Its software check has no block-device access and
makes no hardware, cold-power, unfused-boot, OTP, or enforcement claim.

## Legacy safe-fixture regression

`lib.mkRpi5MediaStagingFixture` consumes one typed output from
`mkRpi5VerifiedUnfusedCapsule` and builds the synthetic outer FAT, deterministic
GPT skeleton, staging-plan inputs, and a fixture-only initializer and verifier.
The outer FAT allowlist is closed: `config.txt` contains the single
`boot_ramdisk=1` setting, and the only other entries are `boot.img` and
`boot.sig`. The inner image and signature remain byte-for-byte bound to the
verified capsule.

The `media-staging-fixture` check initializes a new regular-file workspace,
runs `fixture-dry-run`, `fixture-stage`, and `fixture-readback`, and performs the
final GPT/FAT/dm-verity inspection. Run the closed regression directly:

```console
nix build ./nix/provisioning#checks.x86_64-linux.media-staging-fixture \
  --no-link -L
```

The old mixed stager binary has fixture and block-device modes, so it is
deliberately not exported as a provisioning-flake package or included in the
fixture output. The Nix check is the supported legacy regression boundary; do
not reconstruct a manual device command from its internal test invocation.

Fixture mode rejects `/dev`, symbolic links, special files, target/source
aliasing, size changes, source digest changes, and advisory-lock conflicts. The
final verification takes an exclusively locked, no-follow snapshot of the
regular-file target, checks immutable digests for the complete primary and
backup GPT metadata regions and every complete partition (including alignment
padding), inspects the exact FAT allowlist and payloads, and verifies the staged
extents and dm-verity root-data/hash-tree relationship.

The Linux snapshot helper requires procfs at `/proc/self/fd` to reopen only an
already `O_PATH`-validated regular inode. It fails closed when procfs is not
available.

Every result carries a domain-separated plan digest and receipt digest. The
safety fields distinguish reopening from facts the program cannot observe:

```json
{
  "reopened_target": true,
  "cold_power_cycle_observed": false,
  "one_time_settings_changed": false
}
```

## Production media contract

`lib.mkRpi5ProductionMedia` accepts only a store-backed output from
`mkRpi5VerifiedSignedRelease` whose exact 18-role publication and deterministic
EEPROM and owned-recovery replay have already passed. Its v1alpha2 contract also
requires one transaction ID plus the runtime-observed exact capacity and a
512-byte logical sector size. Those two geometry values make the per-run GPT and
complete-media layout compatible with the selected device; they are not a
hardware identity or a boot-trust input.

The canonical plan and every receipt deliberately omit the boot medium's model,
serial, WWID, physical sector size, persistent path, and initial-content digest.
In particular, `/dev/disk/by-id` is not accepted as an identity or selector.
The versioned, typed hardware-configuration catalog under
`provisioning/config/hardware/` supplies one local operational selector naming
either an immediate raw whole-device node or one
`/dev/disk/by-path/<whole-device>` alias. There is deliberately no generic
sacrificial-device entry. The two checked-in choices are:

- `malakRaspberryPi5SacrificialDevelopmentUsbSd`, hostname-bound to `malak`,
  selects the fixed USB-reader by-path and protects malak's `/dev/nvme0n1`;
- `raspberryPi5SacrificialDevelopmentPiLocalNvme`, hostname-bound to
  `kaiba-rpi5-provisioner`, selects `/dev/nvme0n1` for a Pi running from a
  separate boot medium.

This split does not alter the signed media or its boot contract. The boot and
root-integrity configuration uses the plan-bound PARTUUIDs, so the same medium
may enumerate as `/dev/sda` through malak's USB reader and `/dev/nvme0n1` when
installed in the Pi.

The factory validates the selected configuration and linker-fixes its host,
selector, protected-device set, and configuration ID into the writer and
verifier; it rejects loose runtime overrides. The operational preflight records
those station-local values and the resolved attachment. They do not appear in
the canonical plan or stage, verification, cold-observation, and final
receipts. The selector determines where an explicitly authorized destructive
operation is attempted; it does not attest what hardware is present.

For example, expose the immutable assets and the capability-separated binaries
from the flake that owns the reviewed release and station configuration:

```nix
let
  productionMedia = kaiba.lib.mkRpi5ProductionMedia {
    system = "x86_64-linux";
    verifiedSignedRelease = verifiedSignedRelease;
    transactionID = "transaction:rpi5-sacrificial-001:1";
    hardwareConfiguration =
      kaiba.lib.hardwareConfigurations.malakRaspberryPi5SacrificialDevelopmentUsbSd;
    target = {
      sizeBytes = <exact-observed-capacity>;
      logicalSectorSizeBytes = 512;
    };
  };
in {
  packages.x86_64-linux.production-media = productionMedia;
  packages.x86_64-linux.production-media-device-stager =
    productionMedia.kaibaRpi5ProductionMedia.deviceStager;
  packages.x86_64-linux.production-media-device-verifier =
    productionMedia.kaibaRpi5ProductionMedia.deviceVerifier;
}
```

This is an evaluation example, not a selector-discovery procedure. Review the
selected hardware configuration for the station and change the versioned
configuration, rather than the factory call, if that station's operational
path changes. Observe the capacity and logical sector size again for the
current run, and obtain explicit destructive authorization before staging. Do
not copy placeholder values. The software does not appraise existing media
contents or decide whether they should be retained.

### Frozen layout

The plan covers every byte from offset zero through the exact target capacity
with six consecutive regions:

1. the complete primary GPT area;
2. one canonical FAT32 boot filesystem;
3. the root-data image followed only by zero alignment padding;
4. the dm-verity hash-tree image followed only by zero alignment padding;
5. a zero-filled tail; and
6. the complete backup GPT area.

The GPT contains exactly three partitions named `kaiba-boot`, `kaiba-root`, and
`kaiba-root-verity`. Their partition GUIDs, type GUIDs, offsets, sizes, used
lengths, padded-partition digests, and the disk GUID are all plan-bound. The
root-data and root-hash PARTUUIDs must be the values already embedded in the
signed boot/root-integrity lineage.

The FAT filesystem is a repository-owned canonical serialization, not merely
a directory allowlist. It contains exactly these four files in the frozen
normal form:

```text
boot.img
boot.sig
config.txt
kaiba-media-binding.json
```

`config.txt` contains only `boot_ramdisk=1`. The non-circular media binding
ties the transaction, release and manifest, capsule, boot and root payloads,
root-integrity record, dm-verity root hash, and all three partition GUIDs
together. Reserved FAT sectors, both FAT copies, directory entries, allocation
chains, file slack, free clusters, and trailing bytes also have one accepted
representation. The plan separately binds the six region digests and the
SHA-256 digest of the complete final device.

### Capability separation and safe sequence

Build the assets and the two specialized binaries from the same flake
evaluation. Each binary has the approved plan fixed into it at link time. A
`--plan` argument is still required, but its canonical bytes must match that
fixed store plan exactly; a generic build or substituted plan fails closed.

```console
nix build path:.#production-media --out-link result-production-media
nix build path:.#production-media-device-stager \
  --out-link result-production-media-device-stager
nix build path:.#production-media-device-verifier \
  --out-link result-production-media-device-verifier
```

Before staging, create one new root-owned evidence directory whose final parent
is not writable by group or other users. Every path component must be
root-owned and must not be a symbolic link; only sticky root-owned writable
ancestors such as `/tmp` are tolerated. Receipt names must not already exist:

```console
sudo install -d -o root -g root -m 0700 \
  /var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001

plan="$(readlink -f result-production-media/plan.json)"
stager="$(readlink -f result-production-media-device-stager)"
verifier="$(readlink -f result-production-media-device-verifier)"
evidence=/var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001
preflight="$evidence/device-preflight.json"

sudo "$stager/bin/kaiba-provision-media-device-stager" dry-run \
  --plan "$plan" \
  --preflight "$preflight"

sudo jq '{
  hardware_configuration_id,
  execution_hostname,
  requested_device_selector,
  resolved_device_path,
  attachment_boot_id,
  attachment_sequence,
  target,
  sources_verified,
  target_usage_clear,
  target_locked,
  write_performed
}' "$preflight"
```

Review the selector resolved from the typed hardware configuration, runtime
geometry, and successful device preflight against the approved transaction
before crossing the mutation boundary. That reviewed preflight plus the
deliberate, transaction-bound `stage` invocation is the current explicit
destructive-authorization boundary. The production writer has no runtime
target override, source flag, fixture mode, force switch, or automatic retry.
The preflight is a root-owned, exact-mode `0444`, station-local operational
binding. `stage` accepts only its canonical bytes and requires the same plan,
hardware configuration, hostname, requested and resolved paths, boot ID, and
disk sequence before opening the target writable. A reboot, reattachment, or
selector change requires a new reviewed preflight:

```console
sudo "$stager/bin/kaiba-provision-media-device-stager" stage \
  --plan "$plan" \
  --preflight "$preflight" \
  --receipt "$evidence/stage.json"
```

The writer resolves the configured selector, requires one raw whole device with
the plan's exact capacity and 512-byte logical sector size, and rejects a
partition, mounted device, root or system device, swap, holders, or slaves. It
locks the device and pins `(boot_id, diskseq)`, `dev_t`, sysfs resolution, and
the opened file descriptor throughout the operation so a selector or attachment
change fails closed. These are overwrite and intra-operation TOCTOU protections,
not persistent identity checks. The writer does not read or bind an initial
whole-media digest and makes no judgment about existing data.

Its crash ordering is: invalidate both GPT copies and `fsync`; zero the rest and
write all payloads and `fsync`; write the backup GPT and `fsync`; then write the
primary GPT and `fsync`. It reopens and hashes the complete result before
publishing a new, root-owned, exact-mode `0444` receipt without replacement. If
publication fails after mutation, quarantine the selected device and do not
retry automatically.

The next commands are a physical procedure, not something the software check
has performed. Remove all power, independently record that manual boundary,
reattach storage, and require a fresh kernel attachment whose `(boot_id,
diskseq)` pair differs from staging. Then run the separate read-only verifier:

```console
sudo "$verifier/bin/kaiba-provision-media-device-verifier" verify \
  --plan "$plan" \
  --stage-receipt "$evidence/stage.json" \
  --receipt "$evidence/verification.json"
```

The verifier trusts only a root-owned, non-symlink stage receipt with exact
`0444` permissions under the trusted directory chain. It applies the same
runtime whole-device, usage, geometry, locking, and attachment-pinning checks,
then independently checks GPT CRCs and semantics, the canonical FAT bytes and
four payloads, offline signed-release and signature lineage, every used and
padded partition digest, zero tail, complete-media digest, and direct
`veritysetup verify` over the read-only root-data and root-hash partition
descriptors. It does not import the writer.

That cold readback proves that the freshly attached, operationally selected
medium contains the expected bytes. Because model, serial, and WWID are not
collected, and the typed hardware-configuration selector is omitted from
canonical plans and receipts, it does not prove that this is the same physical
medium used during staging. The station-local preflight is overwrite-safety
evidence, not persistent media identity. Offline verification of the
staged signed artifacts likewise does not prove that a Pi bootloader executed
them. Live signed-system boot observation and enforcement are later hardware
goals.

The generic `kaiba-provision-media-contract finalize` command can correlate
the stage and verification receipts with a separately reviewed canonical
manual cold-power observation. That observation deliberately records
`capture_authenticated=false` and `freshness_established=false`; the repository
does not implement an authenticated power-boundary collector. Consequently the
final receipt also keeps `hardware_observed=false`, `security_enforced=false`,
`mutation_eligible=false`, and `one_time_settings_changed=false`. A receipt
chain is content and operation correlation evidence, not media identity, signed
boot enforcement, or authority to proceed to OTP mutation.

## Legacy mixed stager boundary

The retained `kaiba-provision-media-stager` code can write only the old three
declared payload extents. Its plan does not authorize the production GPT,
canonical four-file FAT, complete zero regions, signed-release binding, or
final whole-media digest. Because the same binary also contains a root-only
block-device mode, it is deliberately not exported by the provisioning flake,
included in the software-only integrated rehearsal, or installed in a default
station image. It must not be used for the SB-04 physical ceremony. Use only
the plan-specialized production writer and independent verifier above.

## Remaining physical boundary

The production factory, writer, verifier, receipt contracts, and regular-file
tamper matrix close the software-definition portion of SB-04. They have not
written or cold-read a sacrificial NVMe device. The legacy initializer, all
three `fixture-*` commands, both regular-file verifiers, and every Nix build are
synthetic software tests: they do not select a block device, access a Pi, cross
an external power boundary, observe a live signed boot, or read or change EEPROM
or OTP settings.

The unfused runtime-record command is also serialization-only. It validates a
canonical runtime-facts object against the independent media plan and emits
exactly one bounded `KAIBA_UNFUSED_COMPATIBILITY=pass ...` record followed by
one bounded `KAIBA_DM_VERITY=active ...` record. The target runtime must still
derive those facts from read-only boot/FAT, device-mapper, mount, and
signed-release state and place them on UART. The serializer is not a collector,
does not authenticate a UART capture, and does not prove a real unfused boot or
runtime enforcement.

The Nix-built four-role unfused capsule itself is still not a whole-device
image. Its `boot.img` is the inner boot ramdisk. The separate media fixture
wraps that payload in the synthetic outer FAT and GPT layout; it does not turn
`capsule/boot.img` into whole-device flashing media. Never pass that inner image
to a whole-device flashing command.
