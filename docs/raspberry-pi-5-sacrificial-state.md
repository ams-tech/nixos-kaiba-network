# Raspberry Pi 5 sacrificial-device state

## Current operator-confirmed state

As of 2026-09-07, the sacrificial Raspberry Pi 5 has crossed the irreversible
customer-key boundary and boots a signed development `target` image.

These two facts are sufficient to impose the owned-device safety boundary:

- the board is permanently excluded from every fresh, blank, unfused, or
  first-commit path;
- no operation may attempt to program the customer key again;
- stock or unsigned recovery is not an authorized path for this board;
- future boot, EEPROM, and recovery artifacts must be authorized by the fused
  development key; and
- uncertainty about any later step is reconciled as an owned device and can
  never make the board fresh again.

The board remains a sacrificial development asset. Booting a signed image does
not provide OS anti-rollback, production identity, encrypted mutable state,
production enrollment, or permission to reuse its development key for a
production cohort.

## Evidence status

The checked
[`sacrificial-pi-5.json`](../tests/provisioning/evidence/sacrificial-pi-5.json)
record is the historical **pre-fuse** qualification snapshot. Its all-zero
customer-key hash, unlocked JTAG state, and `mutation_eligible: false` fields
must not be presented as the board's current lifecycle state.

The repository does not yet contain a checked, reconciled post-fuse evidence
packet identifying the exact currently booted target. Until that packet is
imported, the strongest repository statement is the operator confirmation
above. Do not infer completion of every `security_applied` or owned-state
acceptance criterion from the boot observation alone.

Record these items when the private station journal and hardware are next
available:

- ceremony date and final runner disposition;
- exact station image/revision, immutable runner identity, and whether the fixed
  direct runner or the generic control/bridge/lane-guard flow performed the
  mutation; evidence from one flow must not be attributed retroactively to the
  other;
- fused customer-key hash and signed EEPROM hash;
- signed target version, source revision, boot-image digest, and media digest;
- owned readback and authorized-recovery results;
- signed normal-boot UART evidence;
- altered, unsigned, wrong-key, fallback-source, and dm-verity rejection
  results; and
- the reconciled `security_applied` or `owned_quarantined` terminal record.

Keep private probe output, serials not approved for publication, credentials,
and station journals outside Git. Add only the schema-validated, whitelist-
redacted evidence record intended for public reconciliation.

No post-fuse public schema, importer, validator, or report namespace exists
yet. The first reconciliation implementation must define them together. The
versioned record must whitelist the bindings above, distinguish observed,
failed, and not-observed checks, cross-bind the station, transaction, customer
key, EEPROM, target, media, and terminal disposition, and reject altered or
mixed packets in tests. Do not improvise an ad hoc JSON record or place
post-fuse output in the pre-fuse hardware-qualification namespace.

## Current next step

Preserve the board and every retained station, control, and audit record. Before
any new hardware action, use those records to identify which provisioning flow
performed the mutation. If it was the direct station, run only its read-only
`status` command first. If it was the generic control/bridge/lane-guard flow, do
not synthesize a missing transaction, claim, or approval. Reconcile through the
matching owned-state path and never initialize either flow for this board. Once
the public evidence packet is checked in, update this page and the sacrificial
execution plan together.

The direct runner has no journal-independent owned-state collector. If that
runner was used and its retained journal is absent or does not bind this known-
owned board, do not fall back to its fresh/blank path. Record the gap and use a
separately reviewed, customer-signed owned-state collector or quarantine
procedure when one exists.

Production engineering proceeds separately under the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).
