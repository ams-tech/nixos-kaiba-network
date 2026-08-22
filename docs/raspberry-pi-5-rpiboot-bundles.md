# Raspberry Pi 5 owned recovery and RPIBOOT bundles

This repository provides a public, offline path from a verified fresh-board
EEPROM result to a separately customer-counter-signed owned recovery and six
immutable RPIBOOT or acceptance-test directory trees. None of these builders
can access USB, GPIO, a block device, EEPROM, OTP, or a private key.

## Owned-recovery signing

`lib.mkRpi5OwnedRecoverySigningPlan` consumes the exact fresh EEPROM signing
plan and the output of `lib.mkRpi5VerifiedSignedEEPROM`. The resulting plan
embeds and revalidates that lineage and authorizes one new input only:
`rpi5.owned_recovery_bootcode`.

The control-host command is deliberately separate from Nix evaluation:

```text
kaiba-provision-sign-eeprom sign-owned-recovery \
  --plan /absolute/owned-recovery-plan \
  --output /absolute/owned-recovery-signed
```

The adapter runs the pinned vendor updater in `-fr` mode. The first callback is
the newly approved recovery preimage. The remaining bootcode, bootsys, and
configuration callbacks reuse signatures independently recovered, verified,
and replayed from the fresh EEPROM result; they do not create three additional
gate requests.

Import the public result and finalize it with
`lib.mkRpi5VerifiedOwnedRecovery`. Finalization verifies the signed recovery,
replays the pinned `-fr` updater without contacting the gate, and requires the
resulting `pieeprom.bin` and `pieeprom.sig` to be byte-identical to the already
verified fresh result.

## Canonical bundle set

`lib.mkRpi5VerifiedRPIBootBundles` consumes verified signed boot, signed EEPROM,
owned recovery, and unsigned root artifacts. It first reruns all three public
component finalizers, then produces exactly these directories:

- `fresh-commit`: unsigned fresh recovery, signed EEPROM, update metadata, and
  the only `config.txt` containing `program_pubkey=1`;
- `fresh-readback`: unsigned fresh recovery with metadata-only configuration;
- `owned-readback`: customer-counter-signed recovery with metadata-only
  configuration;
- `owned-recovery`: customer-counter-signed recovery plus the byte-identical
  signed EEPROM and update metadata;
- `negative-boot`: the unsigned recovery selected as an explicitly
  unauthorized owned-device test input;
- `root-integrity-test`: the verified signed capsule and unchanged hash tree
  paired with an exact first-byte mutation of the root-data image.

Every tree has an exact file allowlist and immutable modes. `bundle-set.json`
records sorted file paths, types, modes, sizes, SHA-256 digests, and the
domain-separated tree digest. The builder reopens and verifies the complete
set before an atomic no-replace publication. The standalone verifier repeats
the filesystem snapshots and public boot-signature and EEPROM-metadata checks.

The two rejection fixtures set `hardware_observed` to `false`. They are
deterministic test inputs, not evidence that all required boot-source,
signature, recovery, and dm-verity failure modes have run on a board. In
particular, a generic UART marker is not enough to promote them to hardware
evidence. That promotion happens only in the later, transaction-bound physical
campaign.

## Automated coverage

The `rpi5-rpiboot-bundle-set` report row covers strict parsing, no-follow input
handling, public signature verification, exact tree construction, deterministic
mutation, tamper rejection, schema validation, and capability-boundary checks.
The report intentionally uses `not-observed` on systems where CI did not run
the derivation and never turns software fixtures into hardware claims.
