# Target-media staging prototype

`kaiba-provision-media-stager` writes three approved, non-overlapping extents
to one exact target and verifies them through a separately reopened handle:

- a complete boot-filesystem image, expected to contain the approved
  `boot.img`, `boot.sig`, and allowlisted metadata;
- the persistent root-data image; and
- its dm-verity hash-tree image.

The strict plan binds each source by clean absolute path, canonical SHA-256
digest, exact size, and aligned target offset. It also binds the target path,
identity, and exact capacity. Unknown, missing, duplicated, or case-changed JSON
fields are rejected.

## Safe fixture rehearsal

Use the `fixture-*` commands with an explicitly created regular file outside
`/dev`:

```console
nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-dry-run --plan /absolute/path/fixture-plan.json

nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-stage --plan /absolute/path/fixture-plan.json

nix run ./nix/provisioning#kaiba-provision-media-stager -- \
  fixture-readback --plan /absolute/path/fixture-plan.json
```

Fixture mode rejects `/dev`, symbolic links, special files, target/source
aliasing, size changes, source digest changes, and advisory-lock conflicts. It
is the recommended prototype path because it cannot select a block device.

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

The current tool stages fixed payload extents. It does not yet construct or
independently parse the primary and backup GPT, inspect a FAT allowlist, run
`veritysetup verify`, bind a production transaction and release manifest into
the receipt, or prove cold-power removal. Those are SB-04 exit gates and must
be completed before this tool is used as ceremony evidence.
