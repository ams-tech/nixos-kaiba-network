# Software-only secure-boot rehearsal

`kaiba-provision-rehearsal` runs the complete seven-operation development
campaign against a deterministic software model. It is the smallest prototype
boundary: it exercises campaign order, terminal dispositions, and
evidence production without opening a device, invoking RPIBOOT, controlling
power, staging media, or carrying an OTP-capable artifact.

Run the happy path from a checkout:

```console
nix run ./nix/provisioning#kaiba-provision-rehearsal -- \
  --rehearsal-id local-happy-path
```

The command writes one deterministic JSON report. A successful report uses
`rehearsal_passed`, `software_only_no_otp`, and
`rehearsal_only_non_authoritative`. Its physical-action booleans remain false
and its OTP write count remains zero. It cannot emit `security_applied`, update
inventory, or authorize a production operation.

Failure and uncertain-result paths are deterministic and have distinct exit
codes:

```console
nix run ./nix/provisioning#kaiba-provision-rehearsal -- \
  --rehearsal-id local-failure --inject-at 4 --inject-outcome failed

nix run ./nix/provisioning#kaiba-provision-rehearsal -- \
  --rehearsal-id local-uncertain --inject-at 1 --inject-outcome uncertain
```

The package is built in a separate derivation rather than selected by a
runtime flag on the physical lane guard. Nix checks inspect both its declared
safety marker and linked Go package strings to reject a dependency on the
physical Pi adapter, lane guard, or RPIBOOT implementation.

This command proves only that the software campaign behaves as modeled. It is
not hardware evidence and must never be imported into a real asset lifecycle.

For the runnable end-to-end prototype that also exercises durable control,
audit, approval, intent, plan compilation, and restart binding before invoking
this same simulator, use
[the non-fusing secure-boot prototype](non-fusing-secure-boot-prototype.md).
