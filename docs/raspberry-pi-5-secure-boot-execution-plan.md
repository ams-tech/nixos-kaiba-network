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

The profile is now `stable` through a reviewed status-only promotion. Its
adapter, status-independent policy digest, and eight deferred checks are
unchanged. Stability covers the qualified read-only classification contract
only; it neither establishes a fully unprovisioned board nor authorizes
mutation. The deferred checks must be resolved for the exact
transaction-bound board before ownership commit.

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
  the hardware adapter;
- an authority-checking plan compiler and durable integrated software
  rehearsal;
- a pure normal-boot signing plan, linker-fixed approval-gated runtime adapter,
  canonical Raspberry Pi `boot.sig` codec, and pure offline signed-bundle
  finalizer;
- a canonical cohort-scoped release intent that fixes five signing inputs and
  all 18 required outputs before any signature exists;
- v1alpha2 release-intent lineage through signing grants and requests,
  v1alpha3 gate wire responses and receipts, the normal-boot plan and result,
  and the complete signed-release manifest; each receipt carries a
  domain-separated canonical metadata attestation, and v1alpha2 receipt export
  and verification check it together with the artifact signature;
- a public fresh-board EEPROM signing plan, approval-gated adapter, and offline
  finalizer exercised only with synthetic/offline evidence; and
- an isolated fixed-extent media-staging prototype, a deterministic synthetic
  outer FAT/GPT regular-file fixture, a signer-anchored capsule verifier, and an
  offline unfused record correlator that makes no hardware claim.

The repository now contains a complete offline signed-release assembler and
Nix factory, a complete software-only production-media writer and independent
verifier contract, and authenticated execute-side control-to-guard transport.
These remain foundations backed by synthetic or offline evidence: there is no
production release assembled from reviewed live-token results, recorded
physical NVMe stage and cold readback, live-hardware authenticated
post-mutation reconciliation evidence, fully qualified mutation-capable
station, or proven
RPIBOOT-to-normal-boot lane transition. In particular, the EEPROM foundation
is not a production signed EEPROM, owned-recovery signature, hardware write,
or OTP result.

## Approved sacrificial-development posture

The following policy is approved only for the one sacrificial development
unit. It is not a production profile and does not resolve any of the deferred
exact-board checks:

- `BOOT_ORDER=0xf216`, interpreted from right to left, tries NVMe (`6`), then
  SD (`1`), then network/TFTP (`2`), and finally restarts the sequence (`f`);
- `ENABLE_SELF_UPDATE=0` disables automatic bootloader self-update scanning,
  but does not disable an explicitly authorized RPIBOOT update or otherwise
  make an unlocked EEPROM immutable;
- VideoCore JTAG and EEPROM hardware write protection remain unlocked;
- the initial EEPROM/key operation is one transaction-bound, one-shot
  fresh-board RPIBOOT commit with an exact expected prestate and signed EEPROM;
  an uncertain outcome is reconciled by readback and is never retried;
- the recovery bundle is built and independently verified before ownership,
  but execution is forbidden until the board is owned by the customer key;
  owned-device recovery then uses only that narrowly bounded,
  customer-key-signed RPIBOOT bundle;
- the persistent root is read-only and dm-verity protected, while permitted
  mutable state is tmpfs-only; and
- monotonic anti-rollback is unimplemented, so the terminal state remains
  `security_applied` and every path to `enrollment_ready` stays blocked.

Boot-media hardware identity is not part of this posture. NVMe model, serial,
WWID, and `/dev/disk/by-id` are neither boot-trust inputs nor persistent plan or
evidence fields. A versioned, typed hardware configuration supplies the
station-local selector. The `malak` configuration is hostname-bound to its
fixed USB-reader by-path and protects malak's `/dev/nvme0n1`; a separate
Pi-local configuration selects `/dev/nvme0n1` only on
`kaiba-rpi5-provisioner`. The mandatory operational preflight binds that
configuration and current attachment before any writable open; those fields
remain outside canonical plans and the receipt chain. The media writer retains
only runtime overwrite-safety and layout-compatibility checks. Offline signature
and release-lineage verification remain software foundations; observing and
enforcing a live signed-system boot is a later hardware gate.

The development boot order and unlocked VideoCore JTAG posture are **not
production-ready**. Their production values are undecided and require a new
review and qualification before any production device is provisioned. The
existing `BOOT_UART=1` configuration is likewise an unreviewed development
setting and production blocker, not an approved production value. In
particular, `0xf6` is not asserted to be the eventual production `BOOT_ORDER`.
EEPROM write protection, recovery, and the remaining production policies also
require their separate production decisions and post-finalization tests.

Because both fallback sources are enabled, the post-commit owned-state
acceptance campaign in SB-09 must isolate SD and network/TFTP in turn and test
each with unsigned and wrong-key images plus an older correctly
development-key-signed image. The unsigned and wrong-key candidates must not
execute. Native secure boot may accept the correctly signed older candidate;
that case must prove the anti-rollback limitation is recorded and that
enrollment remains blocked, rather than being misreported as a secure-boot
rejection. Pre-SB-08 physical rehearsals exercise the same source-selection,
isolation, and evidence mechanics only with inert, explicitly non-OTP-capable
payloads; they make no customer-key-enforcement claim.

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

| ID | Milestone | Current status | Exit condition |
| --- | --- | --- | --- |
| SB-00 | Read-only hardware qualification | Complete | Reviewed record is checked in and bound to the frozen profile and probe inputs. |
| SB-01 | Baseline and documentation closeout | In progress; public closeout complete, exact-board and merge-revision gates pending | The profile decision, deferred target checks, documentation, and current-revision CI evidence are reviewed. |
| SB-02 | Development signing root | Not started | The development YubiKey and signing service pass the live key, PIN, touch, token-binding, and failure tests. |
| SB-03 | Complete signed release | In progress | Every required artifact exists, resolves to bytes, verifies offline, and is bound to one canonical manifest. |
| SB-04 | Target-media staging | In progress | The exact NVMe layout is written and cold-read back with matching digests. |
| SB-05 | Enforced transaction plan | Complete (software gate) | The fixed operator workflow, control, audit, bridge, compiler, guard, trusted receipts, and Nix service boundary require the complete ordered campaign and verify every plan, approval, intent, attempt, and artifact binding. This status is not live-hardware qualification. |
| SB-06 | Qualified physical lane | In progress; software complete, live qualification pending | The selected fixed relay or sacrificial-development manual power mode, authenticated physical prompts, USB, UART, and boot-selection behavior pass their applicable combined physical acceptance tests without overstating manual fail-off. |
| SB-07 | Rehearsal and failure campaign | In progress; live drills pending | Automated fake/simulated failure coverage exists, but the non-OTP physical failure-mechanics campaign has not passed. |
| SB-08 | Sacrificial ownership ceremony | Blocked by SB-01 through SB-07 | One approved one-shot commit completes or the target is quarantined; no retry path exists. |
| SB-09 | Owned-state acceptance | Blocked by SB-08 | All positive, recovery, negative, root-integrity, and evidence-reconciliation gates pass and the board stops at `security_applied`. |
| SB-10 | Production readiness | Explicitly deferred | Every production gate in the final section is implemented and separately accepted. |

### Non-fusing prototype checkpoint

The in-progress statuses above reflect implementation, not milestone exit. The
repository now has a signed four-role capsule verifier, the legacy fixed-extent
regular-file rehearsal, a `mkRpi5MediaStagingFixture` factory, a complete
software-only `mkRpi5ProductionMedia` contract, offline unfused record
serialization, a complete offline signed-release assembler, and a runnable
software-only orchestrator. The legacy fixture constructs an outer FAT
containing exactly `config.txt`, `boot.img`, and `boot.sig`, plus deterministic
GPT fixture metadata and a safe initializer/verifier. Its contract runs
initialization, the stager's `fixture-dry-run`, `fixture-stage`, and
`fixture-readback`, and final GPT/FAT and dm-verity verification against one
regular file.

The production-media factory instead consumes the complete content-addressed
18-role release. Its v1alpha2 contract freezes only the runtime-observed exact
capacity and required 512-byte logical sector size for layout compatibility,
plus a three-partition GPT, the six regions covering every target byte, an exact
four-file FAT containing `boot.img`, `boot.sig`, `config.txt`, and
`kaiba-media-binding.json`, root-data and root-hash partitions, zero padding and
tail, and both GPT copies. A station-local raw whole-device or
`/dev/disk/by-path` selector comes from the typed hardware configuration and is
recorded in the operational preflight but absent from the canonical plan and
receipt chain; model, serial, WWID, `/dev/disk/by-id`, physical sector size, and
initial contents are not bound. The factory emits a plan-specialized device
writer, a separate read-only verifier, and canonical
stage, verification, manual cold-power, and final receipt contracts. The
software check independently validates GPT, FAT, offline release/signature
lineage, full-media digests, and dm-verity using a regular file; it does not
perform the physical ceremony or observe signed boot enforcement.

The repository also exposes a clean-revision Pi 5 target, unsigned root/boot
artifacts, a cohort-scoped release intent, a signer-profile-bound v1alpha2
public signing plan, and a concrete release review that verifies the artifact digests,
release-intent lineage, dm-verity tree, public key, and signer-policy binding
without signing or hardware access. The orchestrator uses
the real durable control and audit services, derives the closed seven-operation
plan, verifies both approval and initial-intent audit records under a distinct
rehearsal actor policy, reopens and revalidates persisted state, emits no
executable lane request, and executes only the non-authoritative simulator.

These pieces are packaged in separate capability closures and are described in
the [non-fusing prototype runbook](non-fusing-secure-boot-prototype.md). A
synthetic contract now resolves the full release role set, replays both EEPROM
updater finalizers, and verifies and tampers the resulting content-addressed
publication. It does not resolve those roles from reviewed live-token outputs,
prove a physical device write or cold readback, provide authenticated power or
UART capture, qualify the physical lane, or complete the required failure
matrix, and it cannot authorize SB-08. The public EEPROM and production-media
foundations establish software/offline file, updater, signature, lineage,
layout, writer, verifier, and receipt contracts. None makes a cold-power,
hardware-observation, EEPROM, recovery-signing, OTP, or secure-boot-enforcement
claim.

## Workstream 1: close the qualified baseline

### Deliverables

- [x] Independently verify the qualification record's source revision,
  station-system closure digest, profile policy digest, adapter version, and
  probe input digests. The reviewed source revision resolves to the frozen Git
  commit, the record and closure digest are canonical, and the provisioning
  result revalidates the profile-policy/status-promotion rule, adapter, tool,
  bundle, firmware, and configuration bindings.
- [x] Confirm the checked record remains the only public, redacted evidence;
  retain raw probe results only under the approved private-evidence policy.
  The evidence directory rejects every entry other than its policy README and
  the single whitelist-redacted qualification record; raw probe files remain
  outside Git by policy.
- [x] Promote the device-class profile from `experimental` to `stable` in a
  status-only change that preserves the qualification policy digest.
- [x] Update repository text that still describes physical qualification as
  pending or the physical foundation as wholly unqualified.
- [ ] Close, for the exact candidate board, every deferred check in the device
  profile. This is the exact-board precondition portion of live-only gate 5 in
  the live runbook:
  - explicit destructive-use authorization for the selected storage; existing
    contents are not appraised or bound and storage hardware identity is not a
    trust input;
  - remaining customer OTP and device-private-key rows;
  - installed EEPROM contents and effective write-protection posture;
  - EEPROM and recovery-firmware authenticity;
  - inventory ownership and prior-transaction history; and
  - non-VideoCore debug and alternate execution paths.
- [x] Record the approved development posture for JTAG, boot order, EEPROM
  updates, EEPROM write protection, recovery, self-update, root integrity, and
  rollback.
- [ ] After this branch is pushed, obtain green x86_64 and **native** AArch64
  checks for the exact merge/pre-ceremony revision, including the provisioning
  result, secure-boot target evaluation, artifact checks, station image, and
  `rpiboot` metadata contract. Local x86_64 race, vet, report-build, and flake
  evaluation results do not substitute for that revision-bound native job.

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
  restart. Each of the five grants requires two ordered token operations and
  touches—one artifact signature followed by one gate-derived canonical
  receipt-attestation signature—for a minimum of ten private-key operations
  and touches on the failure-free path. A failed or ambiguous attempt stops for
  review; ten is not an upper bound and does not authorize a blind retry.
- [ ] Document the development exception that this cohort has no backup token.
  Loss or failure of the token strands the sacrificial cohort and requires its
  retirement.

### Exit criteria

The private key has never left the token, every artifact signature is bound to
an immutable approved request, every v1alpha3 receipt authenticates its
canonical metadata, and the team can distinguish the ordinary key fingerprint
from the irreversible Raspberry Pi customer-key hash.

## Workstream 3: build and verify a complete signed release

Implement a control-host release adapter or an equivalently reproducible,
reviewed procedure around the pinned Raspberry Pi tools. A one-off collection
of shell history is not a release process.

### Required artifact roles

The release intent and v1alpha2 signed-release manifest require exactly these
18 final roles in canonical order:

```text
boot_public_key
device_profile
platform_adapter
root_integrity
rpi5.boot_image
rpi5.boot_signature
rpi5.eeprom_bootsys
rpi5.eeprom_config
rpi5.fresh_commit_bundle
rpi5.fresh_readback_bundle
rpi5.negative_boot_bundle
rpi5.owned_readback_bundle
rpi5.owned_recovery_bootcode
rpi5.owned_recovery_bundle
rpi5.root_data_image
rpi5.root_hash_tree_image
rpi5.root_integrity_test_bundle
rpi5.signed_eeprom_image
```

Before signatures exist, the v1alpha1 release intent separately fixes exactly
these five signable input records in canonical order:

```text
rpi5.boot_image
rpi5.eeprom_bootcode
rpi5.eeprom_bootsys
rpi5.eeprom_config
rpi5.owned_recovery_bootcode
```

The EEPROM bootcode record is a signing preimage, not a final release role.
The release cannot grow an implicit nineteenth output or substitute another
signable role.

### Cohort release authorization and per-device execution authorization

The `cohort_release` intent authorizes signing only for the exact public source
identity, unsigned-artifact and EEPROM-release digests, key and policy, five
input digests and sizes, and 18 required outputs above. It deliberately omits
transaction, station, lane, target, claim, fence, and expiry fields. Including
those fields before signatures exist would recreate the cycle in which the
device plan needs the final signed release while signing needs the device plan.
The same reviewed cohort release may ultimately be staged on more than one
separately approved board, but the intent itself cannot authorize any device
execution.

Every v1alpha2 signing grant, request, normal-boot plan, and normal-boot result,
and every v1alpha3 gate wire response and receipt, carries the
`release_intent_digest`. The v1alpha3 receipt's second RSA signature covers
domain-separated canonical grant, request, request-digest, backend,
artifact-signature, and `signed_at` metadata; the v1alpha2 exporter and
verification record require both that attestation and the artifact signature.
`signed_at` is authenticated gate-clock metadata, not an external timestamp
authority. The v1alpha2 complete signed-release manifest also requires the
lineage digest and rejects v1alpha1 manifests without lineage. Only after all
18 outputs are resolved and verified may its `signed_release_manifest_digest`
enter a per-device lane plan and control approval. That later authorization
binds the exact transaction, target, station and lane, current claim and fence,
ordered operations, and expiry; it does not retroactively broaden the cohort
signing grant.

### Deliverables

- [x] Extend release-level validation so a manifest with only an arbitrary
  non-empty subset of known roles cannot be approved as complete.
- [x] Extend the closed artifact-role vocabulary and schema to represent every
  immutable lane input, including fresh and owned readback, negative-boot, and
  root-integrity bundles, plus the separate root-data and root-hash-tree image
  bytes.
- [x] Define one canonical directory-tree representation for each RPIBOOT
  bundle. It must sort relative paths, record file type, mode, size, and digest,
  reject symlinks and special files, and produce a domain-separated digest over
  the canonical tree. A byte-file `digest` and `size` pair is not sufficient for
  the directories consumed by `rpiboot -d`.
- [x] Define and test the canonical v1alpha1 `cohort_release` intent, including
  all source, EEPROM-release, signer, and customer-key bindings plus the exact
  five signing inputs and 18 required output roles.
- [x] Carry and validate `release_intent_digest` through the v1alpha2 signing
  grant, request, result, normal-boot plan and result, v1alpha3 gate response
  and receipt, and v1alpha2 signed-release manifest. Older signed-boot,
  gate-response, receipt, and signed-release records without the current
  lineage and attestation fail closed.
- [x] Implement the bounded public fresh-board EEPROM signing plan, adapter,
  result, and offline finalizer foundation for the pinned `-f` workflow and
  synthetic fixtures. This completed item is a contract/tooling foundation,
  not the production EEPROM deliverable below.
- [x] Implement the separately authorized owned-device recovery plan and
  result, one-new-request pinned `-fr` adapter, offline replay finalizer, and
  canonical fresh/owned RPIBOOT bundle-set builder. The negative recovery and
  root-integrity trees are deterministic test inputs and explicitly record
  `hardware_observed=false`; this software foundation is not a live-token
  signature or board observation.
- [x] Implement the strict offline complete-release assembler,
  `mkRpi5VerifiedSignedRelease` factory, publication schema, and
  content-addressed no-replace layout. The focused synthetic contract builds
  all 18 roles from one release intent and one canonical RPIBOOT bundle-set,
  requires linker-pinned EEPROM and owned-recovery replay, reopens the result,
  and rejects signature, publication, object, and unexpected-entry tampering.

The repository now defines a v1alpha2 signed-release contract that requires
the exact 18-role Raspberry Pi 5 artifact set and its cohort release-intent
lineage. Its RPIBOOT directory-tree contract sorts canonical relative paths,
binds type, mode, size, and content digest, and rejects symbolic links and
special files. The offline assembler independently verifies the boot, EEPROM,
owned-recovery, root-integrity, and canonical RPIBOOT boundaries;
deterministically replays fresh EEPROM and owned-recovery finalization; and
publishes immutable objects, trees, lineage records, and the complete manifest
under digest-derived paths.
Its synthetic test assembles and tampers a complete fixture, but it does not
supply reviewed production bytes or verify live-token ceremony evidence. SB-03
therefore remains in progress.

- [ ] Produce the signed EEPROM image with the pinned firmware, configuration,
  signing tools, public key, and customer counter-signature.
- [x] Pin an EEPROM release with upstream-declared support for the signed
  boot-image SHA-256 device-tree property. Missing source/configuration support
  is a pre-commit failure; absence of `boot_img_sha256` on the owned target is
  an SB-09 acceptance failure, not an optional capability downgrade.

The public EEPROM contract pins rpi-eeprom tag
[`v2026.05.17-2711-0138c0`][pinned EEPROM source tag] at commit
[`05d94be4554ce44a057bfce8d0dd37d951703dab`][pinned EEPROM source commit]
and selects the default Pi 5 `pieeprom-2026-05-26.bin`. The required
`boot_img_sha256` capability entered upstream at commit
[`7918c84b4b9d7695c3b734e628139dd78b14a6b3`][boot-image-hash capability commit].
The recovery payload is independently pinned from
[`firmware-2712/latest/recovery.bin`][pinned Pi 5 recovery payload]; the manifest
records both upstream paths and channels so a reproducer cannot substitute
`default/recovery.bin`.
The A/B-aware signing-tool workflow is pinned at usbboot commit
[`42ca50932f67f4571951a11da3c3161561cb49c2`][pinned A/B signing workflow],
including the `bootsys` signing feature introduced by
[`08d4060ecfd85d402d2134572fe1e11d8b1b2dc8`][A/B bootsys signing feature].
The workflow's rpi-eeprom submodule is separately attributed to
[rpi-eeprom commit `25f837ab8009a643ed85b9aad94d911baddaf0c4`][EEPROM helper compatibility commit];
the selected release contains byte-identical helper files.
This proves public source, digest, and capability contracts only. Actual target
emission of the property cannot be observed until the post-commit signed cold
boot in SB-09; it is not a pre-SB-08 gate. Its absence there fails acceptance
and quarantines the owned board. The signed EEPROM deliverable above remains
incomplete.

The public EEPROM foundation narrows fresh signing to `-f` and owned recovery
to a separately authorized `-fr` plan. Owned recovery makes exactly one new
gate request, which creates one new artifact signature and its canonical
receipt attestation. It reuses the three independently verified fresh-EEPROM
artifact signatures without extra recovery signatures or attestations for
those reused artifacts, and requires the replayed EEPROM image and update
metadata to remain byte-identical. The canonical bundle-set finalizer creates
exact fresh commit, fresh and owned readback, owned recovery,
unauthorized-recovery, and root-integrity fixture trees. It binds every path,
mode, size, and digest and keeps `program_pubkey=1` confined to the fresh commit
tree. Its current evidence remains synthetic/offline: it does not establish
production token outputs, write EEPROM or target media, enter a hardware lane,
change OTP, or observe a board.

- [x] Implement the non-mutating normal-boot signing slice: immutable v1alpha2
  public plan and result, fixed approval-gated adapter, canonical `boot.sig`,
  release-intent/policy/key/image binding, offline verification, and public Nix
  bundle finalization.
- [ ] Produce and verify the detached signature for the exact normal
  release-candidate `boot.img` with the reviewed live development token and
  retain its gate receipt as private operational evidence.
- [ ] Produce the production fresh-board commit bundle for a hash-zero BCM2712
  board from reviewed live-token outputs. The software builder now enforces
  the vendor's fresh-board signing rules and exact tree layout.
- [ ] Produce the production customer-counter-signed owned-device readback and
  recovery bundles before the ownership commit. The separate plan, one-request
  adapter, replay finalizer, and bundle layouts are implemented; live signing
  evidence is still required.
- [ ] Produce narrow, deterministic test artifacts for altered image, altered
  signature, wrong key, unsigned and alternate boot sources, unauthorized
  recovery, and persistent-root tampering. Do not treat one generic marker as
  proof that every required source and failure mode was exercised.
- [ ] Resolve every manifest entry to immutable bytes and verify its size and
  SHA-256 digest before approval.
- [ ] Exercise the completed authorization-lineage foundation for one real
  release: issue independently reviewed cohort grants for every exact signing
  input, authenticate and retain their live v1alpha3 gate receipts, verify each
  artifact and receipt-attestation signature, assemble and verify all 18
  outputs, compute the final `signed_release_manifest_digest`, and only then
  authorize a per-device lane plan. Do not reuse one ambiguous `plan_digest`
  before and after signatures exist.
- [ ] Verify every artifact signature and canonical receipt-attestation
  signature offline against the reviewed development public key and
  independently inspect the complete boot-image allowlist and size.
- [ ] Scan every artifact for signing material, shared enrollment secrets,
  production credentials, unintended mutable state, and unapproved recovery
  capability.
- [ ] Store the final artifacts at immutable content-addressed paths and record
  the exact source revision and tool versions.

See [owned recovery and RPIBOOT bundles] for the implemented public workflow,
the exact six-directory set, and its software-evidence boundary.

### Exit criteria

One canonical manifest binds every byte needed for preparation, commit,
normal boot, owned readback, recovery, and the complete acceptance campaign.
Two independent verification paths agree on every digest, artifact signature,
and receipt-attestation signature.

## Workstream 4: stage and verify target NVMe

The repository now has both the legacy three-extent regular-file fixture and a
complete software definition for production media. The production v1alpha2
contract binds a complete signed release, per-run capacity and 512-byte logical
sector geometry, every byte of the final GPT/FAT/root/verity layout, the
plan-specialized writer, the independent verifier, and the canonical receipt
chain. It does not bind or verify storage model, serial, WWID, persistent path,
physical sector size, or initial contents. Its deterministic regular-file build
and tamper tests cross no block-device or power boundary and observe no hardware
or one-time setting. SB-04 therefore remains in progress until the unchecked
physical gates below are completed.

### Deliverables

- [x] Define the exact GPT or fixed-partition layout, runtime geometry,
  filesystem roles, and overwrite protections for the sacrificial target's NVMe
  device.
- [x] Source the station-local selector from a versioned, typed hardware
  configuration while keeping its selector and configuration ID out of the
  canonical plan and receipt chain while recording them in the mandatory
  operational preflight. Permit only a configured immediate raw whole-device
  node or `/dev/disk/by-path` selector; reject
  `/dev/disk/by-id` and never collect or reconcile model, serial, or WWID.
- [x] Implement a staging tool or frozen procedure that requires explicit
  destructive authorization; rejects a partition, mounted, root, system, or
  swap device plus holders and slaves; verifies the exact runtime capacity and
  512-byte logical sector geometry; and pins `(boot_id, diskseq)`, `dev_t`,
  sysfs resolution, and the open file descriptor within each operation.
- [x] Freeze the exact layout: primary and backup GPT, a canonical boot FAT
  containing exactly `boot.img`, `boot.sig`, `config.txt`, and
  `kaiba-media-binding.json`, fixed raw root-data and dm-verity hash-tree
  partitions, their zero padding, and the complete zero tail.
- [x] Implement a plan-specialized writer with a fixed source closure,
  explicit GPT invalidation/commit ordering, durability barriers, complete
  reopened readback, and no runtime target override, force, retry, or fixture
  switch. It neither appraises nor binds initial media contents.
- [x] Implement a separate read-only verifier that checks the complete media
  digest, GPT CRCs and semantics, canonical FAT bytes and payloads, partition
  padding and tail, signed-release and signature lineage, and direct
  `veritysetup verify` over independently resolved partitions.
- [x] Define canonical stage, independent-verification, manual cold-power, and
  final staging receipts bound to the transaction, runtime geometry,
  signed-release manifest, layout, complete-media digest, transient attachment
  epochs, and prior receipt digests. They contain no storage selector or
  hardware identifier. Manual power evidence remains explicitly unauthenticated
  and the final receipt makes no hardware or enforcement claim.
- [ ] Write the approved `boot.img`, `boot.sig`, root-data image, and dm-verity
  hash image, canonical FAT, and GPT to their fixed destinations on the
  explicitly authorized, runtime-safety-checked whole device.
- [ ] Remove power, cold-read the staged bytes through an independent path, and
  compare their digests with the approved manifest.
- [ ] Flush all writes, remove power, obtain a fresh attachment through the
  selector from the typed hardware configuration, verify the GPT and boot-FAT
  allowlist, read the exact approved byte lengths, recompute every SHA-256
  digest, and run `veritysetup verify` over the staged root-data and hash-tree
  pair. Record that this proves expected bytes on the selected fresh
  attachment, not continuity of one physical medium.
- [ ] Produce and independently review the physical instance of the canonical
  receipt chain, including the manual cold-power observation. The software
  receipt definitions and finalizer alone do not satisfy this gate.
- [ ] Boot the same capsule on an unfused board with `boot_ramdisk=1` and prove
  that the kernel, initramfs, dm-verity mapping, and pre-enrollment runtime work.
- [ ] Confirm that the pre-enrollment runtime contains public trust and policy
  only, starts no enrollment or production-identity service, and exposes no
  mutable protected state.

### Exit criteria

The exact signed capsule has passed the unfused compatibility boot, and a
freshly attached, operationally selected NVMe contains exactly the
manifest-bound bytes expected by the post-fuse target. This exit criterion does
not establish NVMe hardware identity. Live signed-system boot observation and
enforcement remain later hardware gates.

## Workstream 5: enforce the complete transaction

The completed software chain validates the individual bindings, proves that
they were derived rather than copied as opaque strings, and prevents a
shortened campaign from producing `security_applied`.

### Deliverables

- [x] Define one canonical serialization and domain-separated digest algorithm
  for the complete lane plan and for each operation.
- [x] Define the non-circular digest payloads explicitly. An operation digest
  covers the immutable operation body but excludes its own
  `operation_digest`. The plan digest covers the immutable plan body and
  ordered operation digests but excludes its own `plan_digest` and later
  `approval_id`, `intent_receipt`, and `intent_sequence` values. Approval and
  durable intent bind the recomputed plan digest in a separate execution
  envelope.
- [x] Bind the fixed `power_control_mode` into the reviewed draft and canonical
  plan digest. The independently approved plan, executable request, immutable
  lane configuration, and every transition action must agree before physical
  I/O; switching between `relay` and `manual` requires a new approval.
- [x] Recompute and compare plan and operation digests at the trusted boundary;
  do not accept syntactically valid caller-supplied digests as proof of content.
- [x] Publish golden digest vectors and mutate every covered field in tests.
  Every mutation must change the corresponding digest or fail canonical
  decoding. Golden material also pins JSON escaping for control characters,
  HTML-sensitive characters, backslashes, quotes, and non-ASCII text.
- [x] Authenticate the excluded `{plan_digest, approval_id, intent_receipt,
  intent_sequence}` execution envelope against its independent authorities.
  The authenticated bridge double-reads the control transaction around the
  independent audit record, rejects a changed snapshot, and passes only the
  reconstructed current plan/request pair through its private Unix socket. The
  compiler and lane both validate that pair; a root-edited draft cannot replace
  the independently approved digest or durable intent receipt.

The release-bound `v1alpha6` plan and digest contract serializes fixed-order JSON
structs without whitespace. It deliberately supersedes the earlier pre-release
contracts rather than changing canonical material under an existing version.
Operation material contains `sequence`, `operation`,
`classification`, `required_boot_mode`, `authorization_id`, then
`customer_key_hash`, `eeprom_hash`, `eeprom_hash_status`, `security_state`, and
`power_state` within `expected_prestate` and `expected_poststate`, followed by
`maximum_duration_nanoseconds`; it excludes `operation_digest`.
`observed` requires a canonical EEPROM digest. `unavailable` requires an empty
digest and is accepted as the first fresh, all-zero-key prestate.
`commit_attested` requires the release EEPROM digest and owned key hash, but it
can be resolved only from a structured `fresh-commit-attestation/v1alpha1`
whose target, key, EEPROM digest, `EEPROM_UPDATE=success`, and
`SECURE_BOOT_PROVISION=success` fields match the plan exactly. The complete
attestation is included in the operation-result binding digest. Operation 1
ends in this state, operation 2 carries it through the signed cold boot, and
operation 3 must replace it with a current `observed` EEPROM digest before the
remaining campaign can proceed. An interrupted irreversible operation with no
durable exact attestation can therefore never be classified as applied; when
its original EEPROM was unavailable it also cannot be classified as
confirmed-not-applied or retried.
`required_boot_mode` is not caller policy: the closed compiler and guard policy
requires `normal` for `cold_power_cycle` and `rpiboot` for each of the other six
development operations. Plan material contains `schema_version`, `station_id`,
`lane_id`, `transaction_id`, `power_control_mode`, the six-field `release`
binding, `target_fingerprint`, `initial_observation_digest`, `fence_epoch`,
canonical UTC `approval_expires_at`, and the ordered operation digests freshly
derived from their bodies; it excludes
`plan_digest`, `approval_id`, `intent_receipt`, and `intent_sequence`. Every
release-binding field is a canonical lowercase SHA-256 value. The lowercase
plan SHA-256 value is computed over the ASCII domain, one NUL byte, and the
JSON bytes. The domains are
`kaiba.provisioning.lane-guard.operation-digest.v1alpha5` and
`kaiba.provisioning.lane-guard.plan-digest.v1alpha6`. `LoadPlan` snapshots the
caller-owned operation slice, validates this contract and every claimed plan
and operation digest, and restores durable journal lockout state. It is a
validation-only boundary and performs no target-facing I/O; `Execute` or
`Reconcile` owns the first target observation. The one-shot command also
validates all static request bindings against that plan before constructing the
hardware adapter; the guard repeats the comparison and separately checks lease
sufficiency immediately before execution. Control rejects a reapproval that
reuses a plan digest while changing its release or expiry. Every operation
intent persists that plan/release/expiry anchor, so a claim transfer or
reconciliation cannot erase it, and persisted approvals fail closed if their
lifetime exceeds 24 hours.

The execute-once journal now uses the dedicated
`lane-guard-attempt-store/v1alpha5` envelope,
`lane-guard-attempt/v1alpha4` records, and current durable boot-transition
records. Every attempt persists the approval ID, current intent receipt,
current intent sequence, phase-specific transition evidence, and a terminal
distinction between verified-applied, confirmed-not-applied, and quarantined
outcomes. Each terminal attempt is also published at a new digest-derived path
as a root-owned, mode-0444 trusted receipt; caller-owned copies cannot enter
the evidence workflow. The `v1alpha6` plan retains the EEPROM-hash availability
and initial-observation bindings and additionally binds the power-control mode.
These fields change the applicable operation or plan digest, so older drafts,
approvals, intents, requests, and attempts are not reusable.

There is deliberately no in-place journal migration. The current decoder
rejects an older envelope. Before replacement, stop the lane and preserve its
journal, lock file, receipts, control state, and audit state. A nonempty older
journal must be resolved externally after direct board-state inspection as a
manual reconciliation or quarantine case; its records must never be copied,
rewritten, or replayed through the new guard. Only a pre-live journal
positively established as empty, with no attempt or boot-transition records,
may be deleted under a reviewed replacement procedure and recreated in the
current schema.

- [x] Carry and enforce one declared plan binding covering the signed-release
  manifest digest, lane-guard package digest, compiled artifact-set digest,
  expected customer-key hash, expected EEPROM digest, expected boot-image
  digest, target fingerprint, station, lane, transaction, fence epoch, and
  approval expiry. Persist the same six-digest release binding in the control
  approval, require its manifest and key hashes to match the transaction, and
  require an exact match with the linker-fixed physical guard before
  hardware-adapter construction.
- [x] Define and independently derive the compiled artifact-set and guard
  package digests from canonical, reviewed path-and-content-digest material.
  The compiled identity covers exactly patched `rpiboot`, `gpioset`, and the
  six closed bundle roles. The acyclic guard-package identity covers the actual
  guard executable, that compiled identity, and the four release expectations.
  Production validation reopens every canonical Nix-store path, rejects
  symlinks and special files, and hashes file bytes or canonical directory-tree
  material; neither digest is accepted from a caller.
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
- [x] Implement a dedicated authenticated IPC or capability bridge that
  converts current control and audit records into the lane guard's closed
  `Plan` and `ExecuteRequest` contracts.
- [x] Keep the HTTP station unprivileged. The bridge must not expose executable
  paths, bundle selection, device selectors, GPIO selectors, or a generic
  mutation primitive.
- [x] Verify the control identity, active claim, fence epoch, approval,
  remaining lease, durable audit receipt, target fingerprint, operation order,
  and idempotency key immediately before every guarded operation. After the
  delayed physical pre-observation, re-read authenticated authority and require
  server-confirmed minimum claim and approval windows before the guard records
  `AttemptStarted` or dispatches hardware.
- [x] Permit only exact same-claim renewal in one compiler-derived workflow
  state before proposal construction. Bind each immutable proposal to the
  resulting resource version, reject any intervening renewal or state change,
  and never rebase reviewed material. The control server checks an exact
  current approval or reviewed target-bound deadline inside the renewal CAS
  before changing the lease or resource version; evidence publication and
  read-only reconciliation remain deliberately approval-free.
- [x] Before every new audited transition, use the control server's clock to
  preflight the proposal's exact resource version, current claim, and fence.
  Intent and `security_applied` also preflight the exact current approval.
  Approval application uses its separate approver-only typed preflight.
- [x] Keep terminal evidence recordable after an on-time intent crosses
  approval expiry, but only while the exact mutation claim remains current.
  Neither this evidence-only path nor any other renewal revives an expired
  claim. Exact control-committed proposal replay remains idempotent and emits
  no new transition, including an exact initial approval replay after its
  original claim and approval expire; audit-only or otherwise uncommitted
  approval attempts still stop at server-time expiry.
- [x] Provide the fixed `kaiba-provision-lane-workflow` transcript for draft,
  separate approval proposal/application, derived per-operation intent,
  execute-once dispatch, trusted attempt evidence, and observation-only
  reconciliation. No workflow command accepts an operation or physical
  selector.
- [x] Promptly release the exact current terminal claim after
  `security_applied`, quarantine, conclusive reconciliation, or proven clean
  abort. The workflow exposes no claim or fence selector, proves a lost
  response through the original server idempotency record, and refuses to
  retarget a later claim.
- [x] Publish every terminal lane attempt as a new root-owned immutable receipt
  and require the evidence and reconciliation proposal commands to ingest only
  that trusted path.
- [x] Package the root guard as a manually started NixOS one-shot and expose
  only the module-generated, no-argument
  `kaiba-provision-lane-acknowledge` wrapper to operators. The wrapper fixes
  the socket and enters the peer-authenticated primary group; it grants no
  selection or mutation authority.
- [x] Add a combined software integration test that exercises durable control,
  audit, the authenticated bridge, plan compilation, lane guard, the production
  physical-adapter implementation, restart, and observation-only
  reconciliation together. Target-facing OS interfaces remain simulated, so
  this is not live-hardware or security-enforcement evidence.

The `kaiba-provision-authority-bridge` now closes the execute-side conversion
boundary. It uses a station/lane client certificate and separate exclusive
server trust roots to read the control transaction twice around one audit read,
rejects any changed snapshot, reconstructs the two durable audit receipts, and
passes the result through `plancompiler`. A group-restricted mode-0660 Unix
socket in a mode-0750 bridge-owned directory emits only the paired current
`Plan` and exactly one `ExecuteRequest` or `ReconcileRequest`; its client and
the lane guard revalidate the selected pair. Requests cannot carry executable
paths, bundle or device selectors, GPIO/UART values, or an operation selector.
The one-shot guard obtains that same exact binding again after delayed target
pre-observation and immediately before dispatch. The control server requires
enough remaining claim time for the complete bounded operation plus margin and
enough remaining approval time for the dispatch margin. A rejected recheck
creates no `AttemptStarted` record and calls no mutation hardware. Durable
terminal publication replay returns before this callback and performs no target
I/O. The one-shot guard must also obtain fresh authority again after every
successful operation.

Approval provenance is independent of that station identity. Under mutual TLS,
`record_approval` and `plan_approval` require exactly one canonical
`spiffe://kaiba.network/approver/<approver-id>` certificate identity matching
the recorded approver. Station/lane credentials are rejected at those approval
endpoints, and approver credentials are rejected at station endpoints.

The fixed workflow ceremony renews only before constructing an approval,
intent, evidence, finalization, or reconciliation proposal. The displayed
resource version, claim/fence, claim expiry, and current approval expiry are
review material. No renewal is allowed between proposal review and apply; a
changed resource version invalidates the file. The renewal CAS itself uses the
control server's clock to reject an expired exact approval or target-bound
review window before changing either lease or resource version. Immediately
before a new audit append, the control server—not station wall time—confirms
the exact current claim and, where mutation or finalization authority is
needed, the exact current approval. An exact initial approval that already
committed remains replayable through its original control and audit
idempotency records after expiry; an audit-only or uncommitted approval does
not. Expiry or a new fence after proposal creation is otherwise a hard stop
rather than an instruction to regenerate or rebase the proposal. Once a
terminal state is durable, the selector-free workflow closes the still-live
claim and refuses to release any later claim on delayed replay.

The `plancompiler` derives
the exact operation classes, state chain, operation digests, and plan digest;
requires the all-zero fresh prestate and release-bound owned powered-off
poststate; and validates the persisted transaction, active claim, target,
approval, approval audit record, the current per-operation intent, and its audit
record before emitting exactly the one request backed by that pending intent.
A successful operation must be recorded and a fresh per-operation intent bound
before the next request can be emitted. The integrated software rehearsal uses
a separate verifier that covers durable restart but cannot return a lane plan
or request.

The `authenticated-restart-reconciliation` integration check now covers the
combined software boundary. It dispatches the first irreversible operation
once through the production Raspberry Pi 5 adapter implementation and runs
two lost-response cases: one where ownership committed and one where it did
not. Each case discards the in-memory control, audit, bridge, guard, and adapter
objects and advances beyond the original mutation claim and approval expiry.
After reopening all three durable stores and acquiring a new read-only
reconciliation claim, it authenticates the control and audit reads over mTLS,
reconstructs the immutable original approval and intent through the Unix
bridge, and uses the guard's atomic reconciliation-only entry point. ModeAuto
observes the owned poststate or falls back to the exact fresh prestate. The
journal and control service record `confirmed_applied` or
`confirmed_not_applied` respectively, while execute and simulated commit
counters prove that `Hardware.Execute` was not called again. The no-op branch
also proves that current policy refuses a new mutation claim: any retry needs
a separately reviewed protocol.

This check uses real control, audit, bridge, compiler, lane-guard journal, and
physical-adapter code, but replaces the adapter's command runner, filesystem,
GPIO, UART, and timing interfaces with deterministic simulations. It therefore
closes the authenticated software restart/reconciliation gap only. A physical
rig must still prove USB, power, RPIBOOT, UART, target continuity, and cold-boot
behavior before a sacrificial mutation, and the result makes no production
security-enforcement claim.

These completed deliverables close SB-05 as a **software** gate. They do not
close SB-06 or SB-07, authorize SB-08, qualify physical wiring or timing, or
prove that a live target enforced the expected customer key. The exact
reviewed command sequence is maintained in the [live provisioning runbook].

### Manual boundary limitation

The mutation-capable lane guard no longer accepts root-installed executable
plan or request JSON. Root installs only the authority-free draft reviewed for
approval; changing it changes the plan digest, and the bridge rejects it unless
the current independently authenticated approval and durable audit intent bind
that exact digest. Root-authored executable envelopes remain valid only in
separate non-mutating test harnesses and cannot satisfy SB-05 or authorize
SB-08.

### Exit criteria

No unauthenticated UI, root-edited self-consistent plan, shortened operation
list, stale approval, or stale fence can cause a device write or a successful
terminal classification.

## Workstream 6: qualify the complete physical lane

### Required lane components

- one stable BCM2712 RPIBOOT USB topology path;
- one UART adapter selected through `/dev/serial/by-id`;
- one fixed power-control mode: an electrically appropriate, isolated,
  normally-off relay with a fixed GPIO, or the explicitly authorized
  sacrificial-development manual mode; and
- a deterministic, directly observed way to select RPIBOOT versus normal boot.

The `v1alpha6` lane contract carries both the digest-bound closed
`required_boot_mode` policy and one approved `power_control_mode`. The latter
must match the immutable lane-service configuration and every execute or
reconciliation action; a mismatch fails before target-facing I/O. The
sacrificial-development implementation now uses an explicit, durable,
authenticated operator handshake. In relay mode the guard releases the relay;
in manual mode it presents a digest-bound disconnect prompt. It then requires
USB absence, persists the requested transition and exact evidence, waits the
minimum cold interval, and accepts acknowledgements only over its private Unix
socket from the configured primary operator group. For RPIBOOT, relay mode
persists a hold acknowledgement before relay assertion; manual mode uses a
combined hold-BOOTSEL and sole-USB-power/data connection prompt. It then
directly observes exactly one BCM2712 at the fixed sysfs path, persists that
observation, and issues a distinct BOOTSEL-release prompt. For normal boot,
relay mode persists a no-action acknowledgement before assertion; manual mode
arms UART and the USB watcher before its combined no-BOOTSEL and normal-PSU
connection prompt. Both reject any RPIBOOT enumeration while capturing bounded
UART evidence. After the relay command or manual connection acknowledgement,
the state machine persists `power_established` with a closed
`power_establishment_basis` (`relay_command` or `operator_attestation`) and
`power_established_at`. The manual timestamp is operator-attested rather than a
direct observation of an electrical edge. Every phase ends in persisted
mechanism-aware safe-off evidence or durable quarantine; restart never resumes
an old prompt. A persisted/configured power-mode mismatch on restart invokes
neither mechanism; it quarantines with unproven safe-off for external
inspection. The authority-bound hardware-action contract is
`boot-transition-action/v1alpha2`. The corresponding durable transition and
completed-evidence contracts are `boot-transition/v1alpha3` and
`boot-transition-evidence/v1alpha3`; public terminal references and outcomes
are `v1alpha2` so failure paths retain the same power provenance needed for
review. The new manual and relay prompt kinds are closed over both modes by
`operator-prompt/v1alpha2`.

The NixOS module installs only the fixed no-argument
`kaiba-provision-lane-acknowledge` wrapper. It enters the authenticated primary
group and supplies the module-owned socket; the operator cannot select an
operation, mode, target, physical path, power-control mode, or payload. The
module fixes either the default relay mode or the development-only manual mode
in the unit configuration. A fixed BOOTSEL/power-button actuator remains in
scope as a later station enhancement. All current GPIO, USB, UART, power,
timeout, cancellation, restart, and safe-off results are simulated or
fake-backed software evidence, not physical qualification.

The relay lane refuses to start unless the RP1 driver reports
`persist_gpio_outputs=N`, then uses its release-bound immutable `gpioset` to
establish logical inactive both before the guard and after every guard exit.
The adapter separately drives logical inactive during normal release instead
of treating process termination as an electrical transition. These software
controls do not replace a physical pull-down, normally-open contacts, or the
live fail-off and back-power campaign below. Manual mode has no GPIO access and
no automated fail-off guarantee; process or station failure can leave a target
powered until the operator disconnects it.

For the authorized sacrificial-development manual lane, the previously cut
VBUS/data-only cable is forbidden for RPIBOOT because it cannot establish
target power. RPIBOOT uses one pre-qualified intact power-and-data path through
a Raspberry Pi Powered USB Hub (the upstream `usbboot` recommendation), or
another separately reviewed USB 3 source capable of supplying at least 900 mA
without brownout, as the target's sole power and data source; the normal PSU is
absent.
Qualify that path under load before an OTP-capable run. Any undervoltage, USB
reset, target disappearance, or other brownout symptom is a stop condition,
and an unqualified or marginal source must not be used for OTP. Normal signed
NVMe boot uses the normal target PSU only, with the provisioning USB cable
completely removed. UART is receive-only from the station's perspective:
target TX and ground are connected, while adapter VCC and adapter TX remain
disconnected. `power_control_mode: manual` evidence
contains `power_establishment_basis: operator_attestation`, its generic
`power_established_at` acknowledgement timestamp, and separate
`initial_power_off_proof` and `final_safe_off_proof` objects binding the prompt
ID, digest, expiry, authenticated operator, and acknowledgement time. USB
absence remains a separate direct topology observation and must not be
described as direct electrical power measurement, especially during normal
boot. Completed and failed terminal references retain the power mode,
establishment basis, proofs obtained, `safe_off_observed_at`, and a closed
`safe_off_basis`: `relay_inactive_and_usb_absence`,
`operator_disconnect_and_usb_absence`, or `unproven`. An unproven terminal never
fabricates a safe-off proof or timestamp. This exception can authorize only the
reviewed sacrificial development campaign; it cannot support a production-lane,
automatic emergency-stop, or relay-backed fail-off claim.

### Deliverables

- [x] Bind a closed `required_boot_mode` policy into each operation, execute
  request, operation digest, plan digest, and authenticated bridge response.
  `cold_power_cycle` requires `normal`; the other six operations require
  `rpiboot`. Keep this transient transition out of powered-off `DirectState`.
- [x] Bind the selected `power_control_mode` into the reviewed draft, plan
  digest, approval, intent, execute/reconciliation request, configured lane,
  transition action, and terminal evidence. Reject any mismatch before I/O.
- [x] Implement explicit, durable, authenticated BOOTSEL and fixed-power-mode
  handshakes with bounded prompts and direct software mode observation. Keep a
  fixed actuator as deferred station automation.
- [x] Persist the requested transition and directly observed mode evidence with
  each pre-observation, operation result, post-observation, and reconciliation.
- [x] Publish trusted immutable attempt receipts that bind the completed
  transition evidence, and retain incomplete/recovered/quarantined transition
  records in the same durable journal. Failed public terminal references retain
  the mechanism and safe-off basis rather than collapsing to an ambiguous
  status-only result.
- [ ] Qualify the selected power-mode handshake, prompt timing, fixed USB path,
  and direct mode observations on the actual lane.
- [ ] Prove on the physical rig that a normal-boot operation cannot accidentally
  enter RPIBOOT and that an owned readback or recovery operation cannot
  accidentally normal-boot.
- [ ] Confirm correct UART voltage, grounding, settings, isolation, and stable
  device identity.
- [ ] In relay mode, confirm release removes every target power source,
  including USB, UART, display, GPIO, and NVMe back-power. In manual mode,
  qualify the exact single-source wiring and retain authenticated disconnect
  attribution without claiming that USB absence is an electrical measurement.
- [ ] Require observed USB disappearance plus the minimum cold interval; neither
  a GPIO transition nor an operator acknowledgement alone is direct evidence of
  complete electrical power removal.
- [ ] Reject absent, additional, moved, or replaced BCM2712 targets before any
  target-facing operation can execute or reconciliation can advance.
- [ ] In relay mode, verify fail-off after process death, station power loss,
  kernel restart, relay-control loss, and emergency stop. In manual mode, verify
  that interruption never resumes a prompt or redispatches mutation, requires a
  new authenticated disconnect before recovery, and preserves the explicit
  absence of automated fail-off in terminal evidence.

### Exit criteria

The complete guard-plus-adapter sequence can alternate deterministically
between RPIBOOT and normal boot without an operator guessing timing or acting
outside a persisted prompt, target ambiguity, or unrecorded residual-power
assumption. Manual-mode acceptance remains development-only and cannot close a
production automated-fail-off requirement.

## Workstream 7: rehearsal and failure campaign

Run the pre-commit campaign first with a fake lane and then on the qualified
physical rig without an OTP-capable commit bundle. The fake lane exercises the
complete state machine, including modeled irreversible outcomes and modeled
negative-source decisions. The pre-SB-08 physical campaign exercises power,
boot-mode selection, source isolation, topology, UART, restart, and fail-closed
evidence mechanics only. It must not claim that an unfused board enforced the
customer key.

The automated software portion now covers the fixed operator workflow,
authenticated prompts, audit-before-control writes, immutable attempt
ingestion, transition-journal restart recovery, observation-only
reconciliation, wrong-mode and ambiguity rejection, and fake GPIO, USB, UART,
power, timeout, cancellation, and safe-off failures. SB-07 remains incomplete
until the same applicable failure mechanics pass on the qualified physical rig
with inert, explicitly non-OTP-capable payloads.

Actual customer-key enforcement negatives require an owned board. They run
only after the SB-08 commit, as part of SB-09 steps 14 through 16, and are not
prerequisites for authorizing the first ownership mutation. The same is true of
target-emitted `boot_img_sha256`, which is first observable during the SB-09
signed cold boot.

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
- fake-lane modeling of isolated SD and network/TFTP fallback attempts using
  unsigned, wrong-key, and older correctly development-key-signed images,
  including the rule that the correctly signed rollback case cannot enable
  enrollment;
- physical isolation of SD and network/TFTP source-selection and evidence paths
  using inert, explicitly non-OTP-capable payloads, with no secure-boot
  enforcement conclusion;
- fake-lane failure before, during, and after the modeled first OTP write; and
- reconciliation after every distinguishable and indistinguishable outcome.

### Acceptance rules

- [x] Software failure injection before the irreversible intent produces a
  proven clean abort or conservative quarantine decision. The corresponding
  physical drills remain part of the SB-07 exit criteria.
- [x] Once the execute-once journal contains `AttemptStarted`, the same
  operation's `Hardware.Execute` is never invoked again. Reconciliation is
  observation-only. Even evidence that the expected mutation is absent does not
  authorize redispatch under the current protocol; a future retry design would
  require a separately reviewed pre-dispatch journal state and protocol.
- [x] A changed target or conclusive unexpected owned state produces
  `owned_quarantined`.
- [x] Restart cannot erase the execute-once journal, restore stale authority, or
  skip a required operation.
- [x] A shortened plan cannot reach `security_applied`.
- [ ] Every pre-commit physical source-selection drill proves that only the
  intended source and evidence path were active and that no OTP-capable payload
  was available; ambiguity produces a clean abort or quarantine.

The following is an SB-09 acceptance rule, not an SB-07 or pre-SB-08 gate:

- [ ] Every actual unsigned, wrong-key, altered, recovery, and alternate-source
  negative candidate proves non-execution for its isolated boot source, rather
  than merely observing that an approved fallback later booted.

### CI exit gate

The frozen revision must add and pass:

- schema and parser tests for the exact signed-release role set and canonical
  directory-tree manifests;
- complete release fixtures plus wrong-key, altered-byte, altered-signature,
  missing-role, extra-role, and digest-corruption tests;
- loopback block-image tests for unsafe-selector and in-use-device rejection,
  exact GPT and FAT contents, cold-readback digest comparison, and
  `veritysetup verify`, including proof that no media hardware identity enters
  a canonical plan or receipt;
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
  observed until the matching post-commit SB-09 rig evidence is attached.

### Exit criteria

The exact release candidate, station configuration, physical rig, operator
workflow, and recovery/quarantine procedure pass the complete pre-commit
failure-mechanics campaign. This closes SB-07 without claiming customer-key
enforcement. Any code, artifact, wiring, firmware, or policy change invalidates
the affected results and requires targeted repetition before the go/no-go
review. The post-commit enforcement campaign remains an SB-09 acceptance gate.

## Frozen ceremony deliverable

After SB-01 through SB-07 pass, produce a separate immutable ceremony package.
It must contain:

- the exact clean source revision and successful CI run identifiers;
- the station system closure and configuration digests;
- target inventory binding and pre-commit fingerprint;
- the cohort release intent, authenticated v1alpha3 signing receipts, complete
  v1alpha2 signed manifest, and v1alpha2 independent receipt-verification
  record;
- the development signer identity and expected customer-key hash;
- the expected EEPROM and boot-image digests;
- the exact NVMe staging and cold-readback content evidence, explicitly without
  a persistent media selector or hardware identifier;
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
- [ ] NVMe cold-readback digests match the manifest on a fresh attachment; this
  is content evidence, not proof of physical-medium identity or live boot.
- [ ] The complete plan is canonical, policy-complete, approved, audit-bound,
  target-bound, lane-bound, and fence-bound.
- [ ] The RPIBOOT/normal-boot selector and normally-off power lane passed
  qualification without back-power.
- [ ] The pinned EEPROM release and signed configuration support
  `boot_img_sha256`, the manifest binds its expected value, and the physical
  adapter treats a missing or mismatched post-commit observation as an SB-09
  acceptance failure.
- [ ] The full fake-lane and non-OTP physical failure-mechanics campaigns passed
  on the frozen release, without claiming customer-key enforcement.
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
4. Verify the cohort release intent, its v1alpha3 signing-receipt lineage and
   canonical receipt attestations, the complete v1alpha2 signed manifest, and
   all artifact bytes and signatures.
5. Stage the explicitly authorized, runtime-safety-checked NVMe, remove power,
   and reconcile the cold-readback digests on a fresh attachment. Do not infer
   physical-medium identity from this result.
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
    For both the SD and network/TFTP fallbacks, include unsigned, wrong-key,
    and older correctly development-key-signed candidates; record the expected
    signed-image rollback limitation and prove that it cannot enable
    enrollment.
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
- NVMe staging and cold-readback content evidence, with no model, serial, WWID,
  `/dev/disk/by-id`, or other persistent storage selector;
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
manifested, and free of boot-media model, serial, WWID, or persistent selector
fields. Public evidence must also remain free of raw board serials, target MAC
addresses, private keys, PINs, credentials, and arbitrary target output.

Any missing, contradictory, or unverifiable required evidence prevents
`security_applied` and produces `owned_quarantined` after the OTP boundary.

## Implementation touchpoints

The main code and policy boundaries expected to change while executing this
plan are:

- the [signed-release manifest contract], [secure-boot bundle manifest], and
  [artifact-role vocabulary];
- the [signed-release assembler] and [signed-release Nix factory];
- the [release-intent contract], [signed-boot lineage contract], and
  [EEPROM signing foundation];
- the [lane-guard plan contract];
- the [control-plane terminal workflow];
- the [physical Pi 5 adapter];
- the [live-station entry point];
- the [Pi 5 device profile]; and
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
- final JTAG, `BOOT_UART`, boot-order, recovery, self-update, and EEPROM
  write-protection policy with post-finalization retests;
- a production decision on retaining the audited manual BOOTSEL/power-button
  handshake or replacing it with a fixed, electrically qualified actuator;
- production station build, monitoring, update, incident, revocation, and
  retirement procedures; and
- multi-lane isolation and scaling only after the single-lane campaign passes.

Until those gates are implemented and tested, every API, UI, and control-plane
path must continue to reject `enrollment_ready`.

[Pi 5 secure-boot design]: ./raspberry-pi-5-secure-boot.md
[live provisioning runbook]: ./raspberry-pi-5-live-provisioning.md
[Pi 5 provisioning-probe runbook]: ./raspberry-pi-5-provisioning-probe.md
[qualification record]: ../tests/provisioning/evidence/sacrificial-pi-5.json
[pinned EEPROM source tag]: https://github.com/raspberrypi/rpi-eeprom/releases/tag/v2026.05.17-2711-0138c0
[pinned EEPROM source commit]: https://github.com/raspberrypi/rpi-eeprom/commit/05d94be4554ce44a057bfce8d0dd37d951703dab
[pinned Pi 5 recovery payload]: https://github.com/raspberrypi/rpi-eeprom/blob/05d94be4554ce44a057bfce8d0dd37d951703dab/firmware-2712/latest/recovery.bin
[boot-image-hash capability commit]: https://github.com/raspberrypi/rpi-eeprom/commit/7918c84b4b9d7695c3b734e628139dd78b14a6b3
[pinned A/B signing workflow]: https://github.com/raspberrypi/usbboot/commit/42ca50932f67f4571951a11da3c3161561cb49c2
[A/B bootsys signing feature]: https://github.com/raspberrypi/usbboot/commit/08d4060ecfd85d402d2134572fe1e11d8b1b2dc8
[EEPROM helper compatibility commit]: https://github.com/raspberrypi/rpi-eeprom/commit/25f837ab8009a643ed85b9aad94d911baddaf0c4
[signed-release manifest contract]: ../provisioning/internal/provisioning/bundle/release.go
[signed-release assembler]: ../provisioning/internal/provisioning/signedrelease/verify.go
[signed-release Nix factory]: ../nix/provisioning/signed-release.nix
[secure-boot bundle manifest]: ../provisioning/internal/provisioning/bundle/manifest.go
[artifact-role vocabulary]: ../provisioning/internal/provisioning/bundle/role.go
[release-intent contract]: ../provisioning/internal/provisioning/releaseintent/release_intent.go
[signed-boot lineage contract]: ../provisioning/internal/provisioning/signedboot/types.go
[EEPROM signing foundation]: ../provisioning/internal/provisioning/eepromsigning/types.go
[owned recovery and RPIBOOT bundles]: raspberry-pi-5-rpiboot-bundles.md
[lane-guard plan contract]: ../provisioning/internal/provisioning/laneguard/contracts.go
[control-plane terminal workflow]: ../provisioning/internal/provisioning/controlplane/workflow.go
[physical Pi 5 adapter]: ../provisioning/internal/provisioning/physicalrpi5/adapter.go
[live-station entry point]: ../provisioning/cmd/kaiba-provision-station/main.go
[Pi 5 device profile]: ../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json
[hardware-evidence handling rules]: ../tests/provisioning/evidence/README.md
