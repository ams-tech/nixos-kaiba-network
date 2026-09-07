# Hardware qualification evidence

This directory is the private-to-public boundary for physical provisioning
evidence. Keep raw `kaiba-provision probe` results outside the repository.

The original completed read-only qualification ceremony placed the
deterministic whitelist-redacted JSON emitted by `kaiba-provision qualify` here
as `sacrificial-pi-5.json`. The current importer permits exactly that record and
copies it into the reserved public report namespace
`evidence/provisioning/hardware-qualification/`.

The checked record is the sacrificial Pi's historical **pre-fuse** baseline.
The board has since been fused and boots a signed development target, so its
all-zero customer-key hash is not a current lifecycle assertion. Do not replace
or reinterpret this qualification record as post-fuse evidence. A reconciled
owned-state packet requires its own schema and review boundary; until that
exists, the current operator-confirmed state and missing evidence are tracked in
the [sacrificial-device state](../../../docs/raspberry-pi-5-sacrificial-state.md).
There is currently no importer, validation check, or report row for that
packet. Do not add post-fuse output under the hardware-qualification namespace.

`tests/provisioning/packages.nix` derives the report status, description, and
evidence path from the checked record. The build rejects a
record whose profile policy/adapter or pinned probe inputs differ from the
current packaged inputs. The checked ceremony record retains the exact
profile digest and `experimental` status it captured. The current `stable`
profile accepts that record only through the one-way status-only promotion
rule and only while the status-independent policy digest is unchanged. The
probe executable digest is checked on the CI system matching the record's
`station_system`; both systems check the tool version and platform-independent
bundle, firmware, and config digests. `source_revision` identifies the frozen
ceremony revision; reviewers must verify that provenance whenever a change
touches this record or its importer. Update the checked canonical snapshot in
`tests/provisioning/report-input.json` in the same reviewed commit. A pending
qualification must continue to cite no evidence, and an `incomplete` preflight
record must never be added here.
