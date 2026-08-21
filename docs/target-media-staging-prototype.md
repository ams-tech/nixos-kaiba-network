# Target-media staging prototype

`kaiba-provision-media-stager` writes three approved, non-overlapping extents
to one exact target and verifies them through a separately reopened handle:

- an outer FAT boot-filesystem image containing exactly `config.txt`, the
  approved inner `boot.img`, and its `boot.sig`;
- the persistent root-data image; and
- its dm-verity hash-tree image.

The strict plan binds each source by clean absolute path, canonical SHA-256
digest, exact size, and aligned target offset. It also binds the target path,
identity, and exact capacity. Unknown, missing, duplicated, or case-changed JSON
fields are rejected.

## Safe fixture rehearsal

`lib.mkRpi5MediaStagingFixture` consumes one typed output from
`mkRpi5VerifiedUnfusedCapsule` and builds the synthetic outer FAT, deterministic
GPT skeleton, staging-plan inputs, and a fixture-only initializer and verifier.
The outer FAT allowlist is closed: `config.txt` contains the single
`boot_ramdisk=1` setting, and the only other entries are `boot.img` and
`boot.sig`. The inner image and signature remain byte-for-byte bound to the
verified capsule.

Expose the fixture from a local flake that already defines
`verifiedUnfusedCapsule`:

```nix
packages.x86_64-linux.media-staging-fixture =
  kaiba.lib.mkRpi5MediaStagingFixture {
    system = "x86_64-linux";
    verifiedCapsule = verifiedUnfusedCapsule;
  };
```

Build it, then initialize a new workspace at an explicit absolute path outside
`/dev`. Initialization creates the writable regular-file `target.img` with the
fixture GPT and creates `fixture-plan.json` for that exact path and file name.
It does not open a block device:

```console
nix build path:.#media-staging-fixture \
  --out-link result-media-staging-fixture
media_fixture="$(readlink -f result-media-staging-fixture)"

"$media_fixture/bin/kaiba-provision-media-fixture" \
  init --workspace /absolute/new/workspace

nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-dry-run --plan /absolute/new/workspace/fixture-plan.json

nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-stage --plan /absolute/new/workspace/fixture-plan.json

nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-readback --plan /absolute/new/workspace/fixture-plan.json

"$media_fixture/bin/kaiba-provision-media-fixture" \
  verify --workspace /absolute/new/workspace
```

Fixture mode rejects `/dev`, symbolic links, special files, target/source
aliasing, size changes, source digest changes, and advisory-lock conflicts. It
is the recommended prototype path because it cannot select a block device. The
final fixture verification takes an exclusively locked, no-follow snapshot of
the regular-file target, checks immutable digests for the complete primary and
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

## Dedicated-device mode

Device mode is intentionally destructive to ordinary storage bytes and
requires root. It accepts only one clean immediate
`/dev/disk/by-id/<whole-device>` path. It rejects a partition, changed identity
or capacity, a mounted dependent device, the system/root device, and active
swap. The target is opened with no-follow, Linux block-device exclusive-open,
and a nonblocking exclusive lock before source hashing, which pins that kernel
disk attachment through the operation. Its by-id mapping, device number,
capacity, and Linux disk sequence are revalidated after hashing and before any
write. The disk sequence is a boot-local attachment identifier, not persisted
identity; device-mode staging fails closed when the kernel cannot provide it.
Source images are opened without following links and fully hashed; the bytes
actually copied are hashed again. Only the declared extents are written,
followed by `fsync`.

```console
sudo nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  dry-run --plan /absolute/path/device-plan.json

sudo nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  stage --plan /absolute/path/device-plan.json
```

After `stage`, remove all target power, re-enumerate the same physical device,
and only then run `readback` with the same plan. The tool proves a fresh open
and matching extent digests; it does not claim to observe the external power
boundary.

```console
sudo nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  readback --plan /absolute/path/device-plan.json
```

This package has block-device write capability but contains no Pi OTP, EEPROM,
RPIBOOT, GPIO, or lane-guard implementation. It is not included in the
software-only integrated rehearsal closure or any default station image.

## Prototype limitation

The Nix fixture constructs and checks one deterministic GPT/FAT regular-file
example, but the media stager still stages and receipts only the three declared
payload extents. Its plan and receipt do not bind the primary or backup GPT
bytes, partition-table digest, FAT directory, production transaction, or final
signed-release manifest. Device mode does not construct or independently parse
GPT, inspect the FAT allowlist, run `veritysetup verify`, or prove cold-power
removal. Those remain SB-04 exit gates.

The initializer, all three `fixture-*` commands, and the final verifier are
synthetic software tests. These commands do not select a block-device target,
access a Pi, cross an external power boundary, or read or change EEPROM or OTP
settings. Their outputs are not ceremony evidence and do not authorize
device-mode staging.

The Nix-built four-role unfused capsule itself is still not a whole-device
image. Its `boot.img` is the inner boot ramdisk. The separate media fixture
wraps that payload in the synthetic outer FAT and GPT layout; it does not turn
`capsule/boot.img` into whole-device flashing media. Never pass that inner image
to a whole-device flashing command.
