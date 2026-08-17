# Raspberry Pi 5 secure-boot execution plan

This plan defines the work required to move exactly one sacrificial Raspberry
Pi 5 Model B from the repository's completed, non-mutating hardware
qualification to the development terminal state `security_applied`.

It is an engineering delivery plan, not an operator command transcript. The
exact irreversible ceremony must be generated as a separate, frozen, reviewed
runbook after every prerequisite in this plan is complete. Do not derive ad hoc
`rpiboot`, EEPROM, OTP, signing, or block-device commands from this document.

The normative security requirements remain in the [Pi 5 secure-boot design].
The current component boundaries and intentionally deferred work remain in the
[live provisioning runbook]. The non-mutating qualification procedure remains
in the [Pi 5 provisioning-probe runbook].

## Objective and boundary

The first milestone has one narrow objective:

> Irreversibly bind one clearly labelled sacrificial Pi 5 to the development
> boot-signing key, prove the implemented signed-boot, recovery, negative-boot,
> and persistent-root-integrity properties, reconcile the complete evidence,
> and stop at `security_applied`.

This milestone does not:

- create or activate a device identity;
- issue a production certificate or authorize production access;
- claim independently monotonic anti-rollback;
- protect mutable persistent secrets;
- lock VideoCore JTAG or apply final EEPROM write protection;
- use a production signing key; or
- declare the device `enrollment_ready`.

The target remains a sacrificial development asset even after a successful
ceremony. Native Pi secure boot accepts older correctly signed images, so the
implemented target must continue to report rollback as unimplemented and
`enrollment_ready=false`.

## Current baseline

The read-only hardware-qualification milestone is complete. The checked
[qualification record] reports two matching observations, complete power-cycle
and normal-boot confirmations, an all-zero customer-key hash, unlocked
VideoCore JTAG, status `passed`, and no quarantine finding.

That result deliberately does not authorize mutation. The same record says:

```text
mutation_eligible: false
full_unprovisioned_state: not_established
```

The profile also remains `experimental` and lists the storage, remaining OTP
and key rows, EEPROM, firmware-authenticity, inventory, and other debug checks
that the metadata-only probe cannot close. Those checks must be resolved for
the exact transaction-bound board before ownership commit.

The repository already contains useful foundations:

- deterministic Pi 5 `boot.img` and dm-verity artifact construction;
- approval-gated external YubiKey PIV signing components;
- durable control and independent audit services;
- a root-only execute-once lane guard and physical Pi adapter;
- a loopback live-station state machine; and
- tests for the individual contracts and simulated failure behavior;
- one canonical seven-operation development campaign, enforced independently at
  control-plane approval, lane-plan validation, persisted-state loading, and
  `security_applied` finalization; and
- domain-separated, deterministic operation and plan digests that the lane
  guard independently recomputes before observing a target;
- one canonical six-digest release binding carried by both the control approval
  and lane plan, while the plan separately binds the approval expiry; and
- a physical guard build that embeds the declared release binding, can report
  it for build-time verification, and rejects a mismatch before constructing
  the hardware adapter.

The repository does not yet contain a complete signed-release adapter, target
NVMe writer, mutation-capable station backend, authenticated control-to-guard
bridge, authoritative control-side plan construction, or a proven
RPIBOOT-to-normal-boot lane transition.

## Safety invariants

These rules apply to every work item and rehearsal:

1. No OTP-capable bundle may reach a target until every pre-commit gate in this
   plan has passed on the frozen source revision.
2. The owned-device recovery bundle must be built, signed, independently
   verified, and physically available before `program_pubkey=1` is authorized.
3. Exactly one target and one permanently labelled lane are bound to a
   transaction. USB enumeration order is never an identity.
4. Every irreversible intent is durable locally and remotely before execution.
5. A one-way operation is executed at most once. A timeout, process failure,
   missing response, or uncertain result never authorizes a retry.
6. The first possible OTP write changes the failure domain permanently. Any
   changed target, unexpected key hash or EEPROM, missing authoritative
   readback, or failed post-commit test produces `owned_quarantined`.
7. A quarantined or partially owned board never re-enters the fresh-board path.
8. The browser and loopback HTTP process never receive device-node, artifact
   selection, signing-key, or root lane-guard authority.
9. Private probe results, PINs, credentials, and signing-key material never
   enter Git, the Nix store, command arguments, environment variables, logs, or
   published evidence.
10. The development key, production key, device-identity keys, and storage keys
    remain separate trust domains.

## Milestones

| ID | Milestone | Initial status | Exit condition |
| --- | --- | --- | --- |
| SB-00 | Read-only hardware qualification | Complete | Reviewed record is checked in and bound to the frozen profile and probe inputs. |
| SB-01 | Baseline and documentation closeout | Not started | The profile decision, deferred target checks, documentation, and current-revision CI evidence are reviewed. |
| SB-02 | Development signing root | Not started | The development YubiKey and signing service pass the live key, PIN, touch, token-binding, and failure tests. |
| SB-03 | Complete signed release | Not started | Every required artifact exists, resolves to bytes, verifies offline, and is bound to one canonical manifest. |
| SB-04 | Target-media staging | Not started | The exact NVMe layout is written and cold-read back with matching digests. |
| SB-05 | Enforced transaction plan | In progress | The control plane and lane guard require the complete ordered campaign and verify all plan, approval, and artifact bindings. |
| SB-06 | Qualified physical lane | Not started | USB, UART, power, and boot-selection behavior pass the combined physical acceptance tests. |
| SB-07 | Rehearsal and failure campaign | Not started | Fake-lane and non-OTP physical rehearsals pass every required failure drill. |
| SB-08 | Sacrificial ownership ceremony | Blocked by SB-01 through SB-07 | One approved one-shot commit completes or the target is quarantined; no retry path exists. |
| SB-09 | Owned-state acceptance | Blocked by SB-08 | All positive, recovery, negative, root-integrity, and evidence-reconciliation gates pass and the board stops at `security_applied`. |
| SB-10 | Production readiness | Explicitly deferred | Every production gate in the final section is implemented and separately accepted. |

## Workstream 1: close the qualified baseline

### Deliverables

- [ ] Independently verify the qualification record's source revision,
  station-system closure digest, profile policy digest, adapter version, and
  probe input digests.
- [ ] Confirm the checked record remains the only public, redacted evidence;
  retain raw probe results only under the approved private-evidence policy.
- [ ] Decide whether to promote the device-class profile from `experimental` to
  `stable`. A promotion must be status-only and must preserve the qualification
  policy digest.
- [ ] Update repository text that still describes physical qualification as
  pending or the physical foundation as wholly unqualified.
- [ ] Close, for the exact candidate board, every deferred check in the device
  profile:
  - attached-storage contents and prior protected material;
  - remaining customer OTP and device-private-key rows;
  - installed EEPROM contents and effective write-protection posture;
  - EEPROM and recovery-firmware authenticity;
  - inventory ownership and prior-transaction history; and
  - non-VideoCore debug and alternate execution paths.
- [ ] Record the approved development posture for JTAG, boot order, EEPROM
  updates, EEPROM write protection, recovery, self-update, root integrity, and
  rollback.
- [ ] Obtain green x86_64 and native AArch64 checks for the final pre-ceremony
  revision, including the provisioning result, secure-boot target evaluation,
  artifact checks, station image, and `rpiboot` metadata contract.

### Exit criteria

The exact board is an approved `qualified_fresh_candidate` for this one
development transaction. The decision is based on the complete transaction
preconditions, not on changing the probe's intentionally false
`mutation_eligible` field.

## Workstream 2: establish the development signing root

### Deliverables

- [ ] Use a dedicated development YubiKey that is visibly and operationally
  distinct from every production token.
- [ ] Change the default PIN, PUK, and management key through an interactive
  administrator ceremony.
- [ ] Generate the RSA-2048 key in PIV slot 9c with the required always-PIN and
  always-touch policy.
- [ ] Retain and independently review the public key, token serial, PIV
  attestation, fixed PKCS#11 object URI, signer-policy digest, ordinary public
  fingerprint, and canonical Raspberry Pi customer-key hash.
- [ ] Prove that the pinned Raspberry Pi key converter produces the expected
  264-byte representation and customer-key hash. Never substitute a digest of
  PEM text.
- [ ] Instantiate `mkDevelopmentYubiKeySigning` with the reviewed public inputs
  and an external root-managed signing-grant registry.
- [ ] Exercise a real token through the complete wrapper, signing gate, and
  client chain. Cover success plus wrong token, token removal, PIN failure,
  touch timeout, expired grant, digest mismatch, signer mismatch, and service
  restart.
- [ ] Document the development exception that this cohort has no backup token.
  Loss or failure of the token strands the sacrificial cohort and requires its
  retirement.

### Exit criteria

The private key has never left the token, every signing operation is bound to
an immutable approved request, and the team can distinguish the ordinary key
fingerprint from the irreversible Raspberry Pi customer-key hash.

## Workstream 3: build and verify a complete signed release

Implement a control-host release adapter or an equivalently reproducible,
reviewed procedure around the pinned Raspberry Pi tools. A one-off collection
of shell history is not a release process.

### Required artifact roles

The release manifest must require exactly the applicable complete role set,
including:

- device profile and platform adapter;
- boot public key;
- EEPROM configuration and `bootsys` inputs;
- signed EEPROM image;
- normal `boot.img` and `boot.sig`;
- persistent-root integrity metadata, root-data image, and root-hash-tree image;
- fresh-board readback bundle;
- fresh-board commit bundle;
- owned-device readback bundle;
- owned-device recovery bootcode and bundle; and
- separate immutable negative-boot and root-integrity test bundles used by the
  lane plan.

### Deliverables

- [ ] Extend release-level validation so a manifest with only an arbitrary
  non-empty subset of known roles cannot be approved as complete.
- [ ] Extend the closed artifact-role vocabulary and schema to represent every
  immutable lane input, including fresh and owned readback, negative-boot, and
  root-integrity bundles, plus the separate root-data and root-hash-tree image
  bytes.
- [ ] Define one canonical directory-tree representation for each RPIBOOT
  bundle. It must sort relative paths, record file type, mode, size, and digest,
  reject symlinks and special files, and produce a domain-separated digest over
  the canonical tree. A byte-file `digest` and `size` pair is not sufficient for
  the directories consumed by `rpiboot -d`.
- [ ] Produce the signed EEPROM image with the pinned firmware, configuration,
  signing tools, public key, and customer counter-signature.
- [ ] Pin an EEPROM release that emits the signed boot-image SHA-256
  device-tree property. Absence of `boot_img_sha256` is a preflight failure for
  this target, not an optional capability downgrade.
- [ ] Produce and verify the detached signature for the exact normal
  `boot.img`.
- [ ] Produce the fresh-board commit bundle for a hash-zero BCM2712 board. Its
  recovery program must follow the vendor's fresh-board signing rules.
- [ ] Produce the separately customer-counter-signed owned-device readback and
  recovery bundles before the ownership commit.
- [ ] Produce narrow, deterministic test artifacts for altered image, altered
  signature, wrong key, unsigned and alternate boot sources, unauthorized
  recovery, and persistent-root tampering. Do not treat one generic marker as
  proof that every required source and failure mode was exercised.
- [ ] Resolve every manifest entry to immutable bytes and verify its size and
  SHA-256 digest before approval.
- [ ] Split release authorization from execution-plan authorization to avoid a
  signing cycle:
  1. compute a `release_intent_digest` over the canonical unsigned inputs,
     required output roles, signing policy, and applicable transaction, target,
     and fence context;
  2. bind every signing grant and receipt to that release intent;
  3. assemble and verify the signed outputs, then compute the final
     `signed_release_manifest_digest`; and
  4. only then compute the lane execution-plan digest that binds the final
     signed release.
  Do not reuse one ambiguous `plan_digest` before and after signatures exist.
- [ ] Verify every signature offline against the reviewed development public
  key and independently inspect the complete boot-image allowlist and size.
- [ ] Scan every artifact for signing material, shared enrollment secrets,
  production credentials, unintended mutable state, and unapproved recovery
  capability.
- [ ] Store the final artifacts at immutable content-addressed paths and record
  the exact source revision and tool versions.

### Exit criteria

One canonical manifest binds every byte needed for preparation, commit,
normal boot, owned readback, recovery, and the complete acceptance campaign.
Two independent verification paths agree on every digest and signature.

## Workstream 4: stage and verify target NVMe

### Deliverables

- [ ] Define the exact GPT or fixed-partition layout, device selectors, expected
  sizes, filesystem roles, and overwrite protections for the sacrificial
  target's NVMe device.
- [ ] Select the whole NVMe only through an approved `/dev/disk/by-id` path and
  reconcile its serial, model, capacity, existing partition table, and
  transaction binding immediately before staging.
- [ ] Implement a staging tool or frozen procedure that refuses ambiguous,
  mounted, unexpected, or system block devices and never accepts a partition
  selector where the whole device is required, or the reverse.
- [ ] Freeze the exact layout: a boot FAT containing only the approved
  `boot.img`, `boot.sig`, and explicitly allowed metadata, plus fixed raw
  root-data and dm-verity hash-tree partitions.
- [ ] Write the approved `boot.img`, `boot.sig`, root-data image, and dm-verity
  hash image to their fixed destinations.
- [ ] Remove power, cold-read the staged bytes through an independent path, and
  compare their digests with the approved manifest.
- [ ] Flush all writes, remove power, re-enumerate the same by-id device, verify
  the GPT and boot-FAT allowlist, read the exact approved byte lengths, recompute
  every SHA-256 digest, and run `veritysetup verify` over the staged root-data
  and hash-tree pair.
- [ ] Produce a canonical staging receipt bound to the transaction, target,
  by-id device facts, final signed-release manifest, partition layout, byte
  lengths, digests, verity result, and cold-readback observation. Approval of
  the irreversible plan occurs only after this receipt exists.
- [ ] Boot the same capsule on an unfused board with `boot_ramdisk=1` and prove
  that the kernel, initramfs, dm-verity mapping, and pre-enrollment runtime work.
- [ ] Confirm that the pre-enrollment runtime contains public trust and policy
  only, starts no enrollment or production-identity service, and exposes no
  mutable protected state.

### Exit criteria

The exact signed capsule has passed the unfused compatibility boot, and the
powered-off NVMe contains exactly the manifest-bound bytes expected by the
post-fuse target.

## Workstream 5: enforce the complete transaction

The existing services validate many individual bindings, but the final system
must also prove that those bindings were derived rather than copied as opaque
strings and that no shortened campaign can produce `security_applied`.

### Deliverables

- [x] Define one canonical serialization and domain-separated digest algorithm
  for the complete lane plan and for each operation.
- [x] Define the non-circular digest payloads explicitly. An operation digest
  covers the immutable operation body but excludes its own
  `operation_digest`. The plan digest covers the immutable plan body and
  ordered operation digests but excludes its own `plan_digest` and later
  `approval_id` and `intent_receipt` values. Approval and durable intent bind
  the recomputed plan digest in a separate execution envelope.
- [x] Recompute and compare plan and operation digests at the trusted boundary;
  do not accept syntactically valid caller-supplied digests as proof of content.
- [x] Publish golden digest vectors and mutate every covered field in tests.
  Every mutation must change the corresponding digest or fail canonical
  decoding. Golden material also pins JSON escaping for control characters,
  HTML-sensitive characters, backslashes, quotes, and non-ASCII text.
- [ ] Authenticate excluded `approval_id` and `intent_receipt` envelope fields
  against their independent authorities. The lane rejects a request-only
  change, but a coordinated root edit of both the plan and request remains
  possible until the authenticated bridge exists.

The release-bound `v1alpha2` digest contract serializes fixed-order JSON
structs without whitespace. It deliberately supersedes the earlier pre-release
`v1alpha1` contract rather than changing canonical material under an existing
version. Operation material contains `sequence`, `operation`,
`classification`, `authorization_id`, then `customer_key_hash`, `eeprom_hash`,
`security_state`, and `power_state` within `expected_prestate` and
`expected_poststate`, followed by `maximum_duration_nanoseconds`; it excludes
`operation_digest`. Plan material contains `schema_version`, `station_id`,
`lane_id`, `transaction_id`, the six-field `release` binding,
`target_fingerprint`, `fence_epoch`, canonical UTC `approval_expires_at`, and
the ordered operation digests freshly derived from their bodies; it excludes
`plan_digest`, `approval_id`, and `intent_receipt`. Every release-binding field
is a canonical lowercase SHA-256 value. The lowercase plan SHA-256 value is
computed over the ASCII domain, one NUL byte, and the JSON bytes. The domains
are
`kaiba.provisioning.lane-guard.operation-digest.v1alpha2` and
`kaiba.provisioning.lane-guard.plan-digest.v1alpha2`. The lane guard snapshots
the caller-owned operation slice, validates this contract, and compares every
plan and operation digest claimed by the plan before any target observation.
The one-shot command also validates all static request bindings against that
plan before constructing the hardware adapter; the guard repeats the comparison
and separately checks lease sufficiency immediately before execution. Control
rejects a reapproval that reuses a plan digest while changing its release or
expiry. Every operation intent persists that plan/release/expiry anchor, so a
claim transfer or reconciliation cannot erase it, and persisted approvals fail
closed if their lifetime exceeds 24 hours.

- [x] Carry and enforce one declared plan binding covering the signed-release
  manifest digest, lane-guard package digest, compiled artifact-set digest,
  expected customer-key hash, expected EEPROM digest, expected boot-image
  digest, target fingerprint, station, lane, transaction, fence epoch, and
  approval expiry. Persist the same six-digest release binding in the control
  approval, require its manifest and key hashes to match the transaction, and
  require an exact match with the linker-fixed physical guard before
  hardware-adapter construction.
- [ ] Define and independently derive the compiled artifact-set and guard
  package digests from canonical, reviewed path-and-content-digest material.
  The current factory embeds, reports, and enforces declared digest values, but
  does not prove that they describe its actual closure or bundle bytes. The
  complete signed-release adapter must derive those values rather than accept
  an opaque declaration; SB-05 remains incomplete until it does.
- [x] Require the development operation sequence to contain, in order:
  1. `program_customer_key_and_eeprom`;
  2. `cold_power_cycle`, including complete power removal and signed cold boot;
  3. `owned_readback`;
  4. `test_owned_recovery`;
  5. `post_recovery_readback`;
  6. `test_negative_boot`, covering the complete negative-source campaign; and
  7. `test_root_integrity`.
- [x] Reject a missing, duplicate, reordered, or extra operation.
- [x] Enforce that exact campaign independently when approval is recorded, when
  the lane guard loads a plan, and when the terminal state is requested.
- [x] Change the `security_applied` transition so it requires successful,
  authoritative evidence for the policy-defined complete sequence, not merely
  every operation in an arbitrary approved subset.
- [ ] Implement a dedicated authenticated IPC or capability bridge that
  converts current control and audit records into the lane guard's closed
  `Plan` and `ExecuteRequest` contracts.
- [ ] Keep the HTTP station unprivileged. The bridge must not expose executable
  paths, bundle selection, device selectors, GPIO selectors, or a generic
  mutation primitive.
- [ ] Verify the control identity, active claim, fence epoch, approval,
  remaining lease, durable audit receipt, target fingerprint, operation order,
  and idempotency key immediately before every guarded operation.
- [ ] Add combined tests that exercise control, audit, bridge, lane guard,
  physical-adapter state, restart, and reconciliation together rather than
  substituting fake hardware at every boundary.

### Manual boundary limitation

Root-installed plan and request JSON may be used for non-mutating development
and failure rehearsal, but it cannot satisfy SB-05 or authorize SB-08. A root
operator can construct a different self-consistent plan, recompute its content
digests, and invent approval-envelope identifiers. The lane guard now detects
stale or forged digest claims, but a digest proves consistency rather than
authorization. The authenticated bridge and an independently approved digest
are therefore required before a real ownership commit. Any separate experiment
that accepts root as the approval authority is outside this plan and must not
claim its milestones or terminal state.

### Exit criteria

No unauthenticated UI, root-edited self-consistent plan, shortened operation
list, stale approval, or stale fence can cause a device write or a successful
terminal classification.

## Workstream 6: qualify the complete physical lane

### Required lane components

- one stable BCM2712 RPIBOOT USB topology path;
- one UART adapter selected through `/dev/serial/by-id`;
- one electrically appropriate, isolated, normally-off target power relay;
- one fixed GPIO chip and line for that relay; and
- a deterministic way to select RPIBOOT versus normal boot.

The last item is not currently represented by the lane contract. The physical
adapter powers the target, expects RPIBOOT for direct observation, removes
power, and later needs a normal signed cold boot. On Pi 5, RPIBOOT entry requires
the power-button/BOOTSEL action. That transition must not depend on an operator
guessing when to press or release a button during an internal guard call.

### Deliverables

- [ ] Add and qualify a fixed BOOTSEL/power-button actuator, or redesign the
  operation boundary to include an explicit, durable, audited operator
  handshake with a safe timeout and direct mode observation.
- [ ] Model the selected boot mode as part of the guard's expected prestate and
  poststate where it affects execution.
- [ ] Prove that a normal-boot operation cannot accidentally enter RPIBOOT and
  that an owned readback or recovery operation cannot accidentally normal-boot.
- [ ] Confirm correct UART voltage, grounding, settings, isolation, and stable
  device identity.
- [ ] Confirm that relay release removes every target power source, including
  USB, UART, display, GPIO, and NVMe back-power.
- [ ] Require observed USB disappearance plus the minimum cold interval; a GPIO
  transition alone is not evidence of power removal.
- [ ] Reject absent, additional, moved, or replaced BCM2712 targets before any
  plan can load or operation can execute.
- [ ] Verify fail-off behavior after process death, station power loss, kernel
  restart, relay-control loss, and emergency stop.

### Exit criteria

The complete guard-plus-adapter sequence can alternate deterministically
between RPIBOOT and normal boot without timing-dependent human action, target
ambiguity, or residual power.

## Workstream 7: rehearsal and failure campaign

Run the campaign first with a fake lane and then on the qualified physical rig
without an OTP-capable commit bundle.

### Required drills

- process crash and forced termination before intent, after intent, during the
  hardware call, after return, and during authoritative readback;
- station reboot and complete station power loss at the same boundaries;
- target removal, replacement, moved USB path, second eligible target, and UART
  replacement;
- target power that fails on, fails off, or remains through a back-power path;
- missing, noisy, truncated, duplicated, oversized, or forged UART evidence;
- YubiKey removal, wrong token, PIN failure, touch timeout, and signer mismatch;
- expired or revoked approval, transferred claim, stale fence epoch, insufficient
  remaining lease, and control or audit outage;
- altered manifest, artifact bytes, bundle path, expected key hash, EEPROM
  digest, boot-image digest, operation order, or plan digest;
- failure before, during, and after the modeled first OTP write; and
- reconciliation after every distinguishable and indistinguishable outcome.

### Acceptance rules

- [ ] A failure before the irreversible intent produces a proven clean abort or
  a conservative quarantine decision.
- [ ] Once the execute-once journal contains `AttemptStarted`, the same
  operation's `Hardware.Execute` is never invoked again. Reconciliation is
  observation-only. Even evidence that the expected mutation is absent does not
  authorize redispatch under the current protocol; a future retry design would
  require a separately reviewed pre-dispatch journal state and protocol.
- [ ] A changed target or conclusive unexpected owned state produces
  `owned_quarantined`.
- [ ] Restart cannot erase the execute-once journal, restore stale authority, or
  skip a required operation.
- [ ] A shortened plan cannot reach `security_applied`.
- [ ] Every negative candidate proves non-execution for its isolated boot
  source, rather than merely observing that an approved fallback later booted.

### CI exit gate

The frozen revision must add and pass:

- schema and parser tests for the exact signed-release role set and canonical
  directory-tree manifests;
- complete release fixtures plus wrong-key, altered-byte, altered-signature,
  missing-role, extra-role, and digest-corruption tests;
- loopback block-image tests for device-selection rejection, exact GPT and FAT
  contents, cold-readback digest comparison, and `veritysetup verify`;
- golden-vector and mutate-every-field tests for release intent, artifacts,
  operations, plans, approvals, intents, and staging receipts;
- exact-campaign truncation, insertion, duplication, and reordering tests at
  approval, lane-plan load, and `security_applied` finalization;
- authenticated bridge integration tests for mTLS identity, wrong lane, stale
  claim, stale fence, expired approval, audit outage, and altered records;
- ordered-trace tests spanning BOOTSEL, power, USB, RPIBOOT, UART, normal boot,
  and post-operation observation;
- crash and restart tests proving that `AttemptStarted` is never redispatched;
  and
- x86_64 and native AArch64 builds and checks bound to the exact source
  revision. Automated output continues to label physical enforcement as not
  observed until the matching rig evidence is attached.

### Exit criteria

The exact release candidate, station configuration, physical rig, operator
workflow, and recovery/quarantine procedure pass the full campaign. Any code,
artifact, wiring, firmware, or policy change invalidates the affected results
and requires targeted repetition before the go/no-go review.

## Frozen ceremony deliverable

After SB-01 through SB-07 pass, produce a separate immutable ceremony package.
It must contain:

- the exact clean source revision and successful CI run identifiers;
- the station system closure and configuration digests;
- target inventory binding and pre-commit fingerprint;
- the complete signed manifest and independent verification record;
- the development signer identity and expected customer-key hash;
- the expected EEPROM and boot-image digests;
- the exact NVMe staging and cold-readback evidence;
- the canonical complete operation plan and per-operation digests;
- approval, claim, fence, expiry, and durable intent requirements;
- exact operator prompts and expected observations at every physical boundary;
- explicit pre-OTP clean-abort branches;
- explicit post-OTP reconciliation and quarantine branches;
- the evidence schema and export destinations; and
- the names of the operator, approver, incident lead, and person authorized to
  declare quarantine.

The package must not contain a reusable unrestricted mutation command, private
key, PIN, TLS private key, shared secret, or unbounded recovery capability.

## Final go/no-go review

The reviewer answers every item before enabling the mutation-capable lane
guard:

- [ ] The source tree is clean, frozen, reviewed, and green on x86_64 and native
  AArch64.
- [ ] The target is the exact qualified sacrificial board and every deferred
  baseline check is closed.
- [ ] The development key, public-key conversion, canonical customer-key hash,
  and token failure policy are approved.
- [ ] Every required release artifact exists and passes independent digest and
  signature verification.
- [ ] Authorized owned recovery is present and tested as far as an unfused
  board permits.
- [ ] The exact target capsule passed the unfused `boot_ramdisk=1`
  compatibility test.
- [ ] NVMe cold-readback digests match the manifest.
- [ ] The complete plan is canonical, policy-complete, approved, audit-bound,
  target-bound, lane-bound, and fence-bound.
- [ ] The RPIBOOT/normal-boot selector and normally-off power lane passed
  qualification without back-power.
- [ ] The pinned EEPROM release emits `boot_img_sha256`, and the target and
  physical adapter require it.
- [ ] The full fake-lane and physical failure campaigns passed on the frozen
  release.
- [ ] The quarantine and retirement procedures can handle an owned but
  unbootable board without returning it to the fresh path.
- [ ] No production key, device credential, enrollment secret, or protected
  mutable state is present.
- [ ] Everyone accepts that the first fused unit is the first full hardware
  enforcement test of this development key and that failure may permanently
  consume the board.

Any unchecked item is a **no-go**. Schedule pressure, hardware availability,
or confidence from simulation does not waive a gate.

## Sacrificial ceremony sequence

The frozen runbook expands this sequence into exact typed requests, expected
evidence, timeouts, and abort or quarantine actions. This section defines order
only.

1. Admit the station and verify its revision, closure, configuration, identity,
   trusted time, journal, control service, audit service, and empty lane.
2. Create the transaction, reserve the sacrificial asset, acquire the mutation
   claim, and bind the fixed station and lane.
3. Re-establish the fresh-board observation and exact target continuity, then
   close every deferred baseline check.
4. Verify the complete signed manifest and all artifact bytes and signatures.
5. Stage NVMe, remove power, and reconcile the cold-readback digests.
6. Complete the unfused compatibility boot and return the same target to the
   approved fresh prestate.
7. Approve the complete ordered plan for the exact transaction, target, current
   fence epoch, key hash, artifacts, and expected postconditions.
8. Re-identify the same all-zero-key target on the exclusive RPIBOOT lane
   immediately before commit.
9. Persist and export the irreversible intent, obtain the durable audit receipt,
   and revalidate approval and lease lifetime.
10. Execute the ownership commit exactly once through the immutable lane guard.
11. Directly read back and reconcile the customer-key hash, secure-boot
    provisioning result, EEPROM update result, EEPROM digest, and target
    fingerprint.
12. Remove all power, select normal boot, and cold-boot the exact signed NVMe
    capsule. Reconcile UART, customer-key bit 3 of the bootloader `signed`
    property, and the mandatory `boot_img_sha256` value against the manifest.
13. Select authorized RPIBOOT and perform the owned-device readback.
14. Prove authorized recovery works, prove stock or unauthorized recovery does
    not execute, and repeat the owned-device readback afterward.
15. Exercise every required altered, unsigned, wrong-key, recovery, alternate
    media, boot-order, and partition-walk candidate with isolated evidence.
16. Demonstrate that persistent-root tampering fails before enrollment services
    or protected material can become available.
17. Reconcile the complete station journal, central transaction, independent
    audit chain, inventory state, and exported evidence manifest.
18. Mark the board `security_applied` with release classification
    `development_asset`, rollback explicitly unimplemented, and enrollment
    explicitly blocked.

## Terminal outcomes

### Clean abort

A clean abort is available only before irreversible intent and only when direct
evidence proves the board remains in the approved reusable prestate. Preserve
the aborted transaction and audit record.

### Security applied

Success means the exact development board passed every implemented gate and is
recorded as `security_applied`. It remains a non-production asset and cannot
enter identity enrollment.

### Reconciliation required

An uncertain outcome after irreversible intent pauses all new operations. The
lane guard performs direct observation only; it does not repeat the interrupted
operation. If direct state cannot distinguish execution from non-execution, the
result remains uncertain until a separately authorized disposition is made.

### Owned quarantined

Any conclusive post-OTP mismatch, target change, unauthorized execution,
recovery failure, missing evidence, or failed acceptance test permanently
excludes the board from the fresh path. Quarantine has no reset action. Recovery,
diagnosis, retirement, and disposal require a separate approved procedure.

## Evidence retained

The final secret-free record must include:

- qualification record and target fingerprint continuity;
- source revision, station closure, configuration, tool, and firmware versions;
- public key, signer identity, canonical customer-key hash, and signing-policy
  digest;
- complete manifest and every artifact digest and size;
- offline signature and unfused compatibility-boot results;
- NVMe staging and cold-readback evidence;
- the recomputed release-intent, signed-release-manifest, operation, and plan
  digests plus approval, intent, claim, fence, and audit identifiers;
- commit metadata with the exact expected `CUSTOMER_KEY_HASH`,
  `EEPROM_UPDATE=success`, `SECURE_BOOT_PROVISION=success`, and `EEPROM_HASH`;
- seven `AttemptVerified` records whose result-binding digests and audit
  receipts match the approved plan;
- fresh-to-owned target-fingerprint continuity and both owned readbacks;
- signed cold-boot UART evidence, bit 3 of the bootloader `signed` property, and
  the mandatory manifest-matching `boot_img_sha256` value;
- authorized owned-recovery success, stock and unauthorized recovery rejection,
  and the matching post-recovery readback;
- separate non-execution evidence for every altered-image, altered-signature,
  wrong-key, unsigned, alternate-media, `BOOT_ORDER`, and partition-walk case;
- dm-verity tamper rejection before enrollment or protected-material services
  can start;
- every failure, retry decision, reconciliation action, and quarantine reason;
  and
- final inventory lifecycle `security_applied`, release classification
  `development_asset`, rollback `rollback_unimplemented`, and enrollment false.

The evidence must be canonical, bounded, schema-validated, independently
manifested, and free of raw target serials, target MAC addresses, private keys,
PINs, credentials, and arbitrary target output.

Any missing, contradictory, or unverifiable required evidence prevents
`security_applied` and produces `owned_quarantined` after the OTP boundary.

## Implementation touchpoints

The main code and policy boundaries expected to change while executing this
plan are:

- the [secure-boot bundle manifest] and [artifact-role vocabulary];
- the [lane-guard plan contract];
- the [control-plane terminal workflow];
- the [physical Pi 5 adapter];
- the [live-station entry point];
- the [experimental Pi 5 device profile]; and
- the [hardware-evidence handling rules].

Changes to these boundaries should update their focused tests and add the
combined control-to-hardware tests required by Workstream 5.

## Production follow-on

The sacrificial milestone does not reduce these production requirements:

- independently monotonic anti-rollback enforced before protected material or
  enrollment services are available;
- encrypted mutable state and a tested recovery design;
- device-specific identity and operational key generation;
- certificate issuance, pending verification, activation, rotation, recovery,
  and retirement;
- separate human operator and approver enforcement;
- production HSM custody, tested split-custody backup, cohort strategy, key-loss
  and compromise response, and board-replacement policy;
- final JTAG, boot-order, recovery, self-update, and EEPROM write-protection
  policy with post-finalization retests;
- production station build, monitoring, update, incident, revocation, and
  retirement procedures; and
- multi-lane isolation and scaling only after the single-lane campaign passes.

Until those gates are implemented and tested, every API, UI, and control-plane
path must continue to reject `enrollment_ready`.

[Pi 5 secure-boot design]: ./raspberry-pi-5-secure-boot.md
[live provisioning runbook]: ./raspberry-pi-5-live-provisioning.md
[Pi 5 provisioning-probe runbook]: ./raspberry-pi-5-provisioning-probe.md
[qualification record]: ../tests/provisioning/evidence/sacrificial-pi-5.json
[secure-boot bundle manifest]: ../provisioning/internal/provisioning/bundle/manifest.go
[artifact-role vocabulary]: ../provisioning/internal/provisioning/bundle/role.go
[lane-guard plan contract]: ../provisioning/internal/provisioning/laneguard/contracts.go
[control-plane terminal workflow]: ../provisioning/internal/provisioning/controlplane/workflow.go
[physical Pi 5 adapter]: ../provisioning/internal/provisioning/physicalrpi5/adapter.go
[live-station entry point]: ../provisioning/cmd/kaiba-provision-station/main.go
[experimental Pi 5 device profile]: ../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json
[hardware-evidence handling rules]: ../tests/provisioning/evidence/README.md
