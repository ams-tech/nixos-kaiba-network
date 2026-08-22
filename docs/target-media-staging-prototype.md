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
EEPROM and owned-recovery replay have already passed. The factory also requires
one transaction ID, the complete SHA-256 digest of the target's current bytes,
and these immutable facts for one whole physical device:

- a clean `/dev/disk/by-id/<whole-device>` path, never a `-partN` path;
- exact model, serial, and WWID strings;
- exact capacity; and
- a 512-byte logical sector size and the observed physical sector size.

For example, expose the immutable assets and the capability-separated binaries
from the flake that owns the reviewed release and target facts:

```nix
let
  productionMedia = kaiba.lib.mkRpi5ProductionMedia {
    system = "x86_64-linux";
    verifiedSignedRelease = verifiedSignedRelease;
    transactionID = "transaction:rpi5-sacrificial-001:1";
    initialMediaDigest = "sha256:<complete-current-device-sha256>";
    target = {
      byIDPath = "/dev/disk/by-id/<reviewed-whole-device>";
      model = "<exact-observed-model>";
      serial = "<exact-observed-serial>";
      wwid = "<exact-observed-wwid>";
      sizeBytes = <exact-observed-capacity>;
      logicalSectorSizeBytes = 512;
      physicalSectorSizeBytes = <exact-observed-physical-sector-size>;
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

This is an evaluation example, not a source of target facts. Record and review
those facts and the complete prestate digest through the physical runbook
before instantiating the factory. Do not copy placeholder values.

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

sudo "$stager/bin/kaiba-provision-media-device-stager" dry-run \
  --plan "$plan"
```

Review the dry-run output against the approved transaction before crossing the
mutation boundary. The production writer has no target override, source flag,
fixture mode, force switch, or automatic retry:

```console
sudo "$stager/bin/kaiba-provision-media-device-stager" stage \
  --plan "$plan" \
  --receipt /var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001/stage.json
```

The writer exclusively opens the exact whole device, rejects mounts, the
system/root device, swap, holders, slaves, partitions, identity drift, capacity
drift, or prestate drift, and hashes all fixed sources. Its crash ordering is:
invalidate both GPT copies and `fsync`; zero the rest and write all payloads and
`fsync`; write the backup GPT and `fsync`; then write the primary GPT and
`fsync`. It reopens and hashes the complete result before publishing a new,
root-owned, exact-mode `0444` receipt without replacement. If publication
fails after mutation, quarantine the target and do not retry automatically.

The next commands are a physical procedure, not something the software check
has performed. Remove all power from the target, independently record that
manual boundary, reattach the same physical device, and confirm that its
kernel `(boot_id, diskseq)` pair differs from staging. Then run the separate
read-only verifier:

```console
sudo "$verifier/bin/kaiba-provision-media-device-verifier" verify \
  --plan "$plan" \
  --stage-receipt /var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001/stage.json \
  --receipt /var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001/verification.json
```

The verifier trusts only a root-owned, non-symlink stage receipt with exact
`0444` permissions under the trusted directory chain. It independently checks
target identity, GPT CRCs and semantics, the canonical FAT bytes and four
payloads, signed-release and signature lineage, every used and padded partition
digest, zero tail, complete-media digest, and direct `veritysetup verify` over
the read-only root-data and root-hash partition descriptors. It does not import
the writer.

The generic `kaiba-provision-media-contract finalize` command can correlate
the stage and verification receipts with a separately reviewed canonical
manual cold-power observation. That observation deliberately records
`capture_authenticated=false` and `freshness_established=false`; the repository
does not implement an authenticated power-boundary collector. Consequently the
final receipt also keeps `hardware_observed=false`, `security_enforced=false`,
`mutation_eligible=false`, and `one_time_settings_changed=false`. A receipt
chain is correlation evidence, not authority to proceed to OTP mutation.

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
an external power boundary, or read or change EEPROM or OTP settings.

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
