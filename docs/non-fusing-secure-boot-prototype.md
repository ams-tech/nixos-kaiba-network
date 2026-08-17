# Non-fusing secure-boot prototype

The repository now contains a runnable prototype path that exercises the real
control, audit, approval, plan-compilation, restart, and seven-operation
campaign contracts without executing a physical operation or changing a
one-time setting. Its terminal result is deliberately non-authoritative.

## Start here

Choose a new state path for each run. Reusing a prior path fails closed.

```console
nix run ./nix/provisioning#kaiba-provision-integrated-rehearsal -- \
  --state-dir /tmp/kaiba-integrated-rehearsal-1 \
  --rehearsal-id first-integrated-run
```

The command creates mode-`0600` control and append-only audit stores, records a
synthetic fresh target with the all-zero customer-key hash, derives the exact
seven-operation release-bound plan, authenticates the approval and initial
intent against their durable audit records, closes and reopens both stores,
and rebinds the same authority. Only then does it run the deterministic
software simulator.

A successful report must include:

```json
{
  "execution_mode": "software_only",
  "authority_class": "non_authoritative",
  "control_audit_exercised": true,
  "persistence_revalidated": true,
  "hardware_observed": false,
  "security_enforced": false,
  "mutation_eligible": false
}
```

Failure and uncertain-result exercises use distinct exit codes:

```console
nix run ./nix/provisioning#kaiba-provision-integrated-rehearsal -- \
  --state-dir /tmp/kaiba-integrated-rehearsal-failure \
  --rehearsal-id failure-at-recovery \
  --inject-at 4 \
  --inject-outcome failed

nix run ./nix/provisioning#kaiba-provision-integrated-rehearsal -- \
  --state-dir /tmp/kaiba-integrated-rehearsal-uncertain \
  --rehearsal-id uncertain-at-intent \
  --inject-at 1 \
  --inject-outcome uncertain
```

## Prototype layers

| Layer | Tool | What it can change | Claim produced |
| --- | --- | --- | --- |
| Integrated authority rehearsal | `kaiba-provision-integrated-rehearsal` | Fresh local JSON stores only | Software-only, non-authoritative |
| Standalone campaign model | `kaiba-provision-rehearsal` | Nothing | Synthetic campaign evidence |
| Signed capsule verification | `kaiba-provision-unfused-compat` | Nothing | Offline signature and exact-tree verification |
| Media fixture staging | `kaiba-provision-media-stager fixture-*` | One explicitly named regular file | Reopened extent-digest receipt |
| Device media staging | `kaiba-provision-media-stager` | One explicitly approved whole block device | Reopened extent-digest receipt; no cold-power claim |
| Unfused boot evidence | `kaiba-provision-unfused-evidence` | Nothing; consumes captured files | Operator-observed compatibility, never enforcement |

The integrated package is a separate Nix closure from the physical lane guard.
It contains no RPIBOOT binary, Pi adapter, GPIO selector, UART selector, block
device selector, subprocess runner, or network listener. It cannot emit
`security_applied` or invoke `laneguard.Guard`.

## Optional read-only and reversible next layers

Once a real development capsule exists, verify its exact file tree and detached
signature with the procedure in
[Raspberry Pi 5 unfused compatibility prototype](raspberry-pi-5-unfused-compatibility.md).
This is read-only.

Exercise media staging against a sparse regular-file fixture before considering
a dedicated device. The fixture path runs the same extent preflight, write,
fsync, reopen, and digest comparison while rejecting every path beneath
`/dev`. See [Target-media staging prototype](target-media-staging-prototype.md).

An optional physical compatibility run uses a fresh unfused Pi, never supplies
an OTP- or EEPROM-programming bundle, and records the all-zero customer-key
hash before and after the run. The passive verifier accepts exact operator and
UART evidence as described in the unfused compatibility document. It continues
to emit `security_enforced:false` because an unfused board cannot prove
customer-key enforcement.

## Boundary before any real ownership ceremony

This prototype does not complete SB-03 through SB-07 and does not authorize
SB-08. Before any one-time setting is changed, the project still needs the
complete signed release and role vocabulary, canonical RPIBOOT directory-tree
digests, verified GPT/FAT and dm-verity media layout, a qualified BOOTSEL/power
lane, authenticated service transport around the compiler, the complete
crash/failure campaign, live development-token evidence, and an explicit
go/no-go review for one sacrificial board.

