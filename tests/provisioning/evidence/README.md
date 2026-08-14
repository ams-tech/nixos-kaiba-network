# Hardware qualification evidence

This directory is the private-to-public boundary for physical provisioning
evidence. Keep raw `kaiba-provision probe` results outside the repository.

After a completed sacrificial-device ceremony, place only the deterministic
whitelist-redacted JSON emitted by `kaiba-provision qualify` here, named
`sacrificial-pi-5.json`. The provisioning test result copies that exact file
into the reserved public report namespace
`evidence/provisioning/hardware-qualification/`.

Adding the completed record makes `tests/provisioning/packages.nix` derive the
report status, description, and evidence path from it. The build rejects a
record whose profile policy/adapter or pinned probe inputs differ from the
current packaged inputs. Exact profile bytes and status must match while the
profile is experimental; a later experimental-to-stable status-only promotion
is accepted only when the status-independent policy digest is unchanged. The
probe executable digest is checked on the CI system matching the record's
`station_system`; both systems check the tool version and platform-independent
bundle, firmware, and config digests. `source_revision` identifies the frozen
ceremony revision; reviewers must verify that provenance when the later
closeout commit adds this record. Update the checked canonical snapshot in
`tests/provisioning/report-input.json` in the same reviewed commit. A pending
qualification must continue to cite no evidence, and an `incomplete` preflight
record must never be added here.
