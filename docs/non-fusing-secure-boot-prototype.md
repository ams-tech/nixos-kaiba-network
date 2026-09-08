# Non-fusing secure-boot prototype

The repository now contains a runnable prototype path that exercises the real
control, audit, approval, plan-compilation, restart, and seven-operation
campaign contracts without executing a physical operation or changing a
one-time setting. Its terminal result is deliberately non-authoritative.

This prototype remains useful for regression and failure testing, but it no
longer describes the sacrificial Pi's lifecycle state. That board is fused and
boots a signed development target. Never use this synthetic fresh-target state
or its local stores to resume, recreate, or authorize work on the known-owned
board; see the [sacrificial-device state].

## Start here

Choose a new state path for each run. Reusing a prior path fails closed.

The current control store is `v1alpha4`: it requires the all-zero unowned
customer-key prestate and a distinct nonzero intended owned key, and it retains
the original approval snapshot with each recorded operation so authenticated
restart reconciliation can reconstruct the exact non-repeatable attempt.
Older control stores are not auto-migrated into this stronger authority model.
Archive and remove old software-only rehearsal directories before rerunning.
If an older store was ever associated with physical work, do not convert or
resume it; retain it as evidence and require manual reconciliation or
quarantine.

```console
nix run github:PseudoDesign/kaiba-provisioning#kaiba-provision-integrated-rehearsal -- \
  --state-dir /tmp/kaiba-integrated-rehearsal-1 \
  --rehearsal-id first-integrated-run
```

The command creates mode-`0600` control and append-only audit stores, records a
synthetic fresh target with the all-zero customer-key hash, derives the exact
seven-operation release-bound plan, verifies the approval and initial intent
against their durable audit records under an explicitly rehearsal-only actor
policy, closes and reopens both stores, and verifies the same authority. The
rehearsal verifier returns scalar summary evidence and zero executable lane
requests. Only then does it run the deterministic software simulator.

A successful report must include:

```json
{
  "execution_mode": "software_only",
  "authority_class": "non_authoritative",
  "control_audit_exercised": true,
  "persistence_revalidated": true,
  "hardware_observed": false,
  "security_enforced": false,
  "mutation_eligible": false,
  "authority": {
    "plan_operation_count": 7,
    "validated_intent_count": 1,
    "executable_request_count": 0,
    "pending_sequence": 1
  }
}
```

Failure and uncertain-result exercises use distinct exit codes:

```console
nix run github:PseudoDesign/kaiba-provisioning#kaiba-provision-integrated-rehearsal -- \
  --state-dir /tmp/kaiba-integrated-rehearsal-failure \
  --rehearsal-id failure-at-recovery \
  --inject-at 4 \
  --inject-outcome failed

nix run github:PseudoDesign/kaiba-provisioning#kaiba-provision-integrated-rehearsal -- \
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
| Signed capsule verification | signer-anchored `kaiba-provision-unfused-compat` | Nothing | Offline signature and exact-tree verification |
| Media fixture construction | `mkRpi5MediaStagingFixture` and `kaiba-provision-media-fixture` | One new regular-file workspace | Synthetic GPT/FAT and dm-verity verification only |
| Media fixture staging | `kaiba-provision-media-stager fixture-*` | One explicitly named regular file | Reopened extent-digest receipt; no GPT or cold-power binding |
| Device media staging | `kaiba-provision-media-stager` | One explicitly approved whole block device | Reopened extent-digest receipt; no cold-power claim |
| Unfused boot correlation | signer-anchored `kaiba-provision-unfused-evidence` | Nothing; consumes captured files | Consistent offline records; no hardware or enforcement claim |

The integrated package is a separate Nix closure from the physical lane guard.
It contains no RPIBOOT binary, Pi adapter, GPIO selector, UART selector, block
device selector, subprocess runner, or network listener. It cannot emit
`security_applied`, construct a production `BoundPlan`, emit an
`ExecuteRequest`, or invoke `laneguard.Guard`.

## Optional read-only and reversible layers

For a new development release, build a deterministic public signing plan,
obtain an approval-gated YubiKey signature at runtime, and admit the two-file
public result into an offline-verification derivation using the
[Raspberry Pi 5 signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md).
That path exercises the real key only for signing and cannot write a Pi, NVMe,
EEPROM, or OTP.

The repository already contains the public authenticated signing results and
complete 18-role reconstruction for development release `v0.1.6`. Those
checked inputs should be verified and reused as immutable historical release
evidence, not signed again.

Once the public signing result has been admitted, assemble the signed boot pair
and the reviewed dm-verity root images with `mkRpi5VerifiedUnfusedCapsule`.
That derivation verifies the exact four-role tree, the root-data/hash
relationship, and the detached signature using the signer-pinned verifier. Its
fixture remains explicitly synthetic and its result makes no hardware or
enforcement claim. See
[Raspberry Pi 5 unfused compatibility prototype](raspberry-pi-5-unfused-compatibility.md).

Build the regular-file rehearsal from the verified capsule with
`mkRpi5MediaStagingFixture`. Its fixture command initializes a deterministic GPT
target and an outer FAT containing exactly `config.txt`, `boot.img`, and
`boot.sig`. Run `fixture-dry-run`, `fixture-stage`, and `fixture-readback` with
the generated plan, then run the fixture verifier. This exercises the real
extent preflight, write, fsync, reopen, digest comparison, FAT inspection, GPT
inspection, complete-partition digest verification, and dm-verity verification
while rejecting every path beneath `/dev`. See
[Target-media staging prototype](target-media-staging-prototype.md).

This closes only the synthetic outer-media rehearsal gap. The repository does
not contain an authenticated physical unfused-compatibility record. If that
experiment is still needed for a future release, it requires a separately
approved fresh unfused Pi; the fused sacrificial board is permanently
ineligible. The exercise must never supply an OTP- or EEPROM-programming bundle
and must record the all-zero customer-key hash before and after the run. The
passive verifier can correlate the operator-authored record and UART transcript
with an in-process, signer-anchored capsule verification, but unauthenticated
capture still keeps `hardware_observed:false`, `security_enforced:false`, and
`mutation_eligible:false`.

## Historical ownership boundary and current use

This prototype did not authorize the sacrificial ownership ceremony. Since it
was written, the repository gained the complete checked `v0.1.6` development
release and fixed station/target paths, and the sacrificial board crossed the
irreversible boundary. Missing historical pre-commit evidence cannot be
recreated by running this prototype and cannot authorize a repeat. It must be
handled through post-fuse reconciliation or owned-device quarantine.

The synthetic fixture does not satisfy any physical staging, cold-power,
hardware-observation, secure-boot-enforcement, EEPROM, or OTP gate.

[sacrificial-device state]: raspberry-pi-5-sacrificial-state.md
