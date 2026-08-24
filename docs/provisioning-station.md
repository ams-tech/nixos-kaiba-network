# Provisioning station design

This document defines the target production architecture for a dedicated,
platform-neutral provisioning station. The station executes the
[per-device provisioning transaction](device-identity.md#per-device-software-transaction)
against a physically attached device, but it is not the authority for device
identity, certificate issuance, fleet authorization, artifacts, or audit
history.

A dedicated station is justified because provisioning combines physical target
access, bootstrap authority, and potentially irreversible security changes.
Keeping that intersection off general-purpose operator and development
machines makes its software, identities, network paths, custody, and audit
requirements small enough to qualify and monitor as one production boundary.

The design is intentionally independent of any particular processor,
one-time-programmable memory, secure element, trusted platform module, debug
interface, boot chain, or storage technology. Hardware-specific behavior is
supplied by a signed device-class profile and a pinned platform adapter.

This remains the target design rather than a complete implemented station. The
hardware-qualified, read-only
[Raspberry Pi 5 provisioning probe](raspberry-pi-5-provisioning-probe.md)
implements one deliberately non-persistent adapter slice: target observation
and partial unprovisioned-baseline evaluation. It cannot authorize or perform a
device mutation. The separate
[provisioning-station interface demo](provisioning-station-kiosk.md) renders
mock operator states on a loopback-only service; it has no probe or target
privilege and is not an implementation of the production station components.

## Objectives and invariants

The station must:

- execute one approved transaction against exactly one claimed target per
  provisioning lane;
- perform all reversible validation before crossing the first irreversible
  device-security boundary;
- execute only the ordered operations authorized for the observed device,
  profile, artifacts, policy, station, lane, and transaction;
- establish device-unique keys inside the target's final protection boundary
  whenever the device profile supports it;
- independently observe the postcondition of every device mutation;
- keep issued credentials staged and production-denied until verification and
  central activation succeed;
- leave a crash-safe, secret-free local journal and independently retained
  audit trail; and
- fail closed and quarantine uncertain devices rather than attempting an
  unauthenticated or default path.

The following invariants define the station's authority boundary:

- The provisioning coordinator and inventory, not the station, own the
  physical-asset binding, logical device ID, transaction state, credential
  generations, and active authorization state.
- The device registration authority (RA), not the station or target, assigns
  the canonical identity and authorizes a certificate profile.
- The certification authority (CA), reached through the RA, owns certificate
  issuance and its serial ledger.
- A separate artifact and policy authority approves provisioning bundles. The
  station may resolve immutable contents but may not create a production
  bundle or authorize a mutable local override.
- An independent audit service owns durable fleet provenance. Loss of a
  station cannot erase the record of devices it processed.
- No station action by itself can make a credential active. Activation is an
  atomic inventory decision over one exact device, slot, key generation,
  issuer, and certificate serial after verification.
- The generic orchestrator and persistent station state never receive a device
  root secret or private authentication key. The preferred workflow receives
  only public material and proofs of possession (PoPs). A profile that permits
  secret injection uses the isolated exceptional path defined below and is
  assigned an explicitly lower assurance level.
- The station contains no offline-root, issuing-CA, fleet software-signing,
  fleet boot-signing, or unrestricted RA private key.
- Production and test stations use different credentials, policies,
  inventories, issuers, artifacts, and trust domains.

A fully compromised station can damage or misconfigure the currently attached
target and can misuse authorization already granted to it. Host hardening
cannot eliminate that fact. This architecture instead limits the station's
fleet-wide authority, bounds credentials by transaction and time, makes
irreversible work independently auditable, and allows the station, lane, and
affected devices to be fenced separately.

## Threat model and trust assumptions

Treat the following as untrusted:

- the candidate device, all self-reported identity and lifecycle fields, and
  every byte received through the target-facing transport;
- serial numbers, MAC addresses, removable-media metadata, asset labels, and
  operating-system device names as authentication evidence;
- the network between the station and every provisioning control service;
- identity-bearing CSR fields and any claim that a successful command changed
  device state;
- cached artifacts until their digests, signatures, authorization, expiry,
  dependencies, and rollback constraints are checked; and
- routine operator input beyond the exact action authorized for the operator's
  authenticated role.

The design assumes that provisioning control services authenticate one
another, protect transport integrity and confidentiality where required, and
enforce their own authorization and idempotency rules. It also assumes that
the approval authority, RA, CA, artifact authority, inventory, and audit
service are independently administered to the degree required by the
deployment's assurance profile. Co-location must not collapse their
credentials or policy decisions into station authority.

A malicious target must not be able to compromise the management plane, reach
control services through the station, consume unbounded resources, select a
different adapter, or influence another transaction. A network attacker must
not be able to impersonate a service, replay an authorization, substitute an
artifact, or roll back trust policy. A mistaken or malicious routine operator
must not be able to change the approved plan, bypass a postcondition, assign an
identity, issue a certificate, or activate a credential alone.

Residual risks are explicit: a fully compromised station can operate the
physical interfaces available to its attached target, invasive attacks may
defeat device protections outside the device profile's stated threat model,
and denial of service can stop provisioning. Compromise or collusion spanning
the station and enough separated control authorities can also defeat the
design. Those conditions trigger containment and recovery; they are not claims
that station software can prevent.

## Terminology

- **Provisioning station**: the dedicated managed host that runs the operator
  interface and provisioning software.
- **Provisioning lane**: one isolated physical target connection, its
  privileged executor, target network or transport, and per-lane state. The
  initial design has one lane per station.
- **Provisioning coordinator**: the control service that owns transactions,
  inventory, claims, fence epochs, and activation. This name avoids confusion
  with the Kaiba runtime controller.
- **Provisioning control services**: the coordinator and inventory, approval
  service, device RA, artifact and policy service, pending-credential verifier,
  audit service, and their supporting time and update services.
- **Generic orchestrator**: the station component that implements the
  platform-neutral transaction state machine.
- **Device-class profile**: signed declarative policy describing an allowed
  baseline, required capabilities, key roles, ordered operations,
  classifications, and observable postconditions.
- **Platform adapter**: a pinned, sandboxed executable that converts typed
  profile operations into device-specific actions and observations.
- **Provisioning bundle**: a signed manifest that references immutable
  software, firmware, configuration, device-class profile, platform adapter,
  validation bundles, certificate profiles, tests, and policy versions.
- **Target-binding fingerprint**: the canonical set of observations used to
  correlate one physical candidate with a transaction. Before creation of a
  protected identity, it may not be cryptographic and is not an authentication
  credential.
- **Provisioning claim lease**: a renewable, exclusive claim over a
  transaction, asset, station, and lane. It is unrelated to the DNS endpoint
  lease in the pilot architecture.
- **Fence epoch**: a monotonically increasing generation attached to a claim.
  Stale epochs cannot mutate central state through a compliant lane.
- **Commit approval**: approval for one exact destructive plan. It is distinct
  from RA authorization to issue a certificate.
- **Activation**: the coordinator's atomic transition that allows one exact
  credential tuple in production. Certificate installation and X.509 validity
  are not activation.

## Logical topology

```text
 named operator                  independent approver
       |                                  |
       v                                  v
+---------------------- provisioning station -----------------------+
| operator UI -> generic orchestrator -> crash-safe local journal   |
|                       |        |                  |                 |
| signed bundle cache   |        |                  +-> audit outbox |
|                       |        v                                    |
| station identity      |  sandboxed platform adapter                |
| broker                |        |                                    |
|                       +-> privileged lane guard                     |
+--------------------------------|-----------------------------------+
                                 |
                                 v
                         exactly one target
                         in an isolated lane

 station mTLS and scoped transaction capabilities
                                 |
                                 v
+-------------------- provisioning control services ----------------+
| coordinator + inventory | approval | artifact and policy service  |
| device RA -> issuing CA  | pending verifier | append-only audit    |
+-------------------------------------------------------------------+

 offline root, artifact-signing keys, and fleet-signing keys remain
 outside the station and outside routine per-device enrollment
```

Conceptual roles may share infrastructure, but their identities, policies,
authorization decisions, and audit records remain separate. In particular,
the station does not connect directly to the routine issuing key; it submits a
transaction-bound enrollment request to the device RA.

## Authority and state ownership

There is no generic last-writer-wins rule. Recovery reconciles each fact with
the component authoritative for that fact:

| State or decision | Authority |
| --- | --- |
| Physical lifecycle and security state | The target, established through profile-defined direct observation and readback |
| Target private material | The target's intended protection boundary |
| Transaction and logical-ID/asset binding | Provisioning coordinator and inventory |
| Device lifecycle, credential slots, key generations, and active authorization | Provisioning coordinator and inventory |
| Provisioning claim lease and fence epoch | Provisioning coordinator |
| Commit approval | Independent approval service and named approver policy |
| Bootstrap authentication and issuance authorization | Device RA |
| Certificate issuance and serial | CA issuance ledger |
| Approved bundle and policy versions | Artifact and policy service |
| Pending operational proof | Pending-credential verifier |
| In-flight intent and station-local observations | Crash-safe station journal |
| Immutable provisioning provenance | Independent audit service |

The generic orchestrator owns workflow semantics, but it is not authoritative
for the records or security decisions it coordinates. Its local journal is a
recovery replica and audit outbox, not a substitute for inventory, the CA
ledger, or the independent audit service.

## Initial deployment profile

The first implementation should use one station, one lane, one attached target,
and online provisioning control services. It should not implement disconnected
irreversible provisioning.

The station is a dedicated production system:

- Install it from an authenticated, pinned, reproducible baseline on managed
  hardware with verified boot, rollback controls, encrypted local state, a
  protected machine identity where available, and a production debug policy.
- Run a minimal operating system and only the software needed for station
  admission, provisioning, monitoring, maintenance, and recovery.
- Do not use it for email, general web browsing, source development, builds,
  arbitrary removable media, or ordinary administration.
- Disable unattended operator login, shared accounts, unrestricted shells,
  unencrypted swap, automatic media mounting, broad packet capture, and
  secret-bearing crash dumps or diagnostic bundles.
- Place the management interface and target lane in separate security zones.
  Never bridge, route, or perform network address translation between them.
- Limit management egress to authenticated provisioning control services and
  approved time, monitoring, and update endpoints.
- Permit a target network to reach only explicitly required bootstrap or
  pending-verification services. It cannot use the station as a route to
  management, production, the RA, inventory, or the CA.
- Disable remote maintenance while a lane is crossing or reconciling an
  irreversible boundary. Maintenance requires a separate, visible station
  lifecycle state.
- Place the station and attached target in a physically controlled work area
  with custody procedures appropriate to the assurance profile.

The station admission gate fails closed when the coordinator, inventory, RA,
artifact service, pending verifier, audit service, trusted time, or required
station-health evidence is unavailable. An offline mode would require bounded
signed grants, quotas, expiration, monotonic replay protection, local
activation rules, and a separately reviewed lower-assurance profile; it is
outside this design.

## Station components

### Station health and fence agent

The health agent continuously verifies the approved boot, software,
configuration, trust-bundle, time, disk, audit-export, credential, and lane
state. It obtains the station's current authorization state and prevents new
admission when the station or lane is fenced, in maintenance, outside its
approved configuration, unable to export audit data, or near credential
expiry.

Configuration drift does not merely generate an alert. It removes permission
to begin a transaction until the station is reconciled and, where required,
requalified.

### Station identity broker

Each station has a unique, revocable bootstrap identity enrolled during a
controlled station ceremony. A protected non-exportable key is preferred. The
bootstrap identity is used only for station lifecycle operations and for
obtaining short-lived, audience-restricted workload credentials.

The identity broker exposes narrow authentication or signing operations to
specific station services. It does not expose raw key bytes or allow the
provisioning orchestrator to sign arbitrary data. Reimaging or replacing a
station normally creates a new station identity; a restored disk image never
restores transaction authority by itself.

### Operator interface

Routine operators use a constrained workflow interface, not a privileged
shell. Before commit it displays:

- station and lane identities;
- asset, intended logical ID, and target-binding fingerprint;
- observed unprovisioned baseline and any deviations;
- exact bundle, adapter, policy, validation-bundle, and certificate-profile
  identifiers and hashes;
- every ordered operation, its classification, expected postcondition, and
  point of no return; and
- the transaction digest that the approval service will authorize.

The interface cannot invoke arbitrary adapter operations, edit a CSR identity,
select an unapproved certificate profile, alter a signed bundle, or activate a
credential directly.

### Generic orchestrator

The orchestrator enforces the canonical per-device state machine in
[the device identity lifecycle](device-identity.md#per-device-software-transaction).
It validates station admission, resolves the signed plan, coordinates control
services, checks claim and approval validity, invokes only typed adapter
operations, and performs retry and crash reconciliation.

It never infers successful progress solely from a local stage marker,
certificate file, or successful command return. It compares the local journal,
central state, CA ledger results, audit receipts, verifier receipts, and direct
target observations according to the authority table above.

### Bundle resolver and verifier

The resolver fetches contents only by immutable digest and validates the signed
provisioning-bundle manifest before use. The manifest pins:

- compatible device classes and allowed starting states;
- device-class profile and platform-adapter identifiers and digests;
- every software, firmware, configuration, and dependency digest;
- ordered operations, classifications, and required postconditions;
- key roles, algorithms, protection requirements, and generation or injection
  policy;
- validation-bundle and certificate-profile versions;
- required positive, negative, restart, and optional attestation tests;
- policy compatibility and minimum security or rollback versions; and
- manifest expiration and revocation information.

Mutable tags, implicit latest versions, unsigned local overrides, expired or
revoked manifests, incomplete dependency closures, and artifacts outside the
approved cache are rejected. Cached data is untrusted until its digest and
manifest authorization are revalidated for the current transaction.

### Sandboxed platform adapter

The adapter and target protocol parser process hostile input. They run with the
least privilege needed for one lane and have no RA, CA, inventory, artifact,
audit-read, or arbitrary network access. The orchestrator supplies a typed
target handle and one declarative operation, not shell text.

The adapter cannot add operations, reorder them, change their classification,
weaken a postcondition, or select a secret or identity outside the profile. Its
interface is conceptually:

```text
Probe(target_handle) -> target_observation
ValidateBaseline(profile, observation) -> evidence
ResolvePlan(profile, observation) -> ordered_operations
Execute(target_handle, operation, expected_prestate) -> operation_result
Observe(target_handle, postcondition) -> evidence
GenerateOrDerive(target_handle, key_role) -> public_key_reference
ProvePossession(target_handle, key_role, challenge, transaction_digest) -> proof
InstallPublicMaterial(target_handle, material_set) -> result
Finalize(target_handle) -> result
RestartAndObserve(target_handle) -> evidence
EraseTransient(target_handle) -> evidence
```

All inputs and outputs have bounded schemas, sizes, and deadlines. Adapter
state, protocol sessions, temporary target mappings, and sandboxes are reset
before accepting another device.

If secret injection is unavoidable, it uses a separate exceptional interface.
A protected broker passes a target-bound encrypted envelope directly to the
adapter or target protection boundary. The generic orchestrator, journal,
logs, packet captures, and audit service never receive plaintext.

### Privileged lane guard

The lane guard exclusively owns the physical target handle. It allows a device
mutation only when all of the following match:

- station and lane identities;
- transaction and target-binding fingerprint;
- current claim lease and fence epoch;
- approved plan and operation digest;
- expected direct prestate;
- current stage and preceding postconditions; and
- operation-specific authorization and remaining lease time.

The guard rejects multiple eligible targets, target removal or replacement,
an unexpected device class, stale epochs, out-of-order operations, and a plan
that has changed since approval. It rechecks target continuity before each
mutation and after any reconnect or restart.

A compliant lane guard limits accidents and stale actors. It cannot prevent a
fully compromised station with physical access from sending unauthorized
signals. Central services therefore reject stale or unscoped consequences even
when physical containment has failed.

### Crash-safe journal and audit exporter

The station journal records stage preconditions, intent, input and output
digests, structured observations, evidence hashes, central resource versions,
fence epochs, external authorization identifiers, audit receipts, and results.
It contains no private keys, raw device roots, plaintext injected secrets,
tokens, PINs, storage keys, CA credentials, or operator authenticators.

Every mutation follows this ordering:

```text
validate exact preconditions
-> durably record and export intent
-> obtain the required remote audit receipt
-> execute once
-> directly observe the postcondition
-> durably record and export evidence and result
```

For the initial design, an acknowledged remote intent receipt is required
before the first irreversible mutation and before each separately approved
one-way operation. Successful physical release requires a receipt covering the
terminal result. The audit exporter hash-chains events or otherwise binds them
to their order and retains a local encrypted outbox until the independent
service confirms durable receipt.

The audit schema rejects secret-bearing fields rather than relying only on
later redaction. Station wall-clock time is supporting evidence; the audit
service's sequence, timestamp, and receipt establish external ordering.

## Access and authorization

### Operator roles

Use named accounts, phishing-resistant hardware-backed authentication,
short-lived sessions, and distinct roles for:

- station administration;
- routine provisioning operation;
- irreversible commit approval;
- device and certificate policy approval;
- artifact publication; and
- audit and incident review.

Shared accounts and password-only production access are prohibited. Production
policy should require an independent second approver for irreversible device
security changes, trust-policy changes, HSM or external-signer administration,
and exceptional recovery. Two approvals entered through the same potentially
compromised station interface are not independent; commit approval is issued
through the external approval service.

Approval binds the station, lane, transaction digest, fence epoch,
target-binding fingerprint, intended asset and logical ID, bundle and policy
hashes, exact ordered plan, expiry, and allowed operation set. A transferred
claim or any changed input invalidates it.

### Station credentials and capabilities

The station may hold or obtain only:

- its protected station bootstrap identity;
- short-lived station workload credentials separated by service audience;
- named operator and approver assertions for the current action;
- expiring per-transaction capabilities bound to the station, lane, asset,
  logical ID, profile, allowed stages, claim epoch, and rate or issuance limit;
- read-only artifact authorization;
- append-only audit authorization; and
- a narrow pending-verifier client authorization.

It must not hold:

- offline-root, issuing-CA, artifact-signing, or fleet software- or boot-signing
  private keys;
- RA administrator or inventory-wide mutation authority;
- credentials for another station, lane, or transaction;
- persistent fleet-wide bearer or bootstrap tokens;
- a target's root secret or private authentication key; or
- credentials that can activate an arbitrary inventory tuple.

When a target-specific public artifact requires an external signature, the
station submits its digest and authorized transaction context to a separate
signing service and receives only the signed artifact. Access to a protected
signer limits extraction but does not prevent misuse by a compromised station;
the signing service still enforces audience, operation, artifact type,
transaction, approval, rate, and audit policy.

## Provisioning claims and fencing

A provisioning claim uses both a renewable lease and a monotonic fence epoch:

1. Claim acquisition atomically reserves the transaction and physical asset
   for one station and lane and increments the epoch.
2. The returned capability binds the transaction, station, lane, asset,
   optional target-binding fingerprint, epoch, expiry, and allowed stages.
3. Renewal extends the expiry without changing the epoch.
4. Reacquisition or transfer always increments the epoch. Commit approval for
   the previous epoch becomes invalid.
5. Every central mutation and compliant lane-guard mutation carries the
   current epoch. An older epoch is rejected even if its lease time has not
   elapsed locally.
6. Before a long device mutation, the lane guard requires more remaining lease
   time than the profile's worst-case operation duration plus a safety margin.
7. Lease loss prevents new mutations immediately. A command already sent to
   the target may finish, so its stage remains `in_progress` until direct
   reconciliation establishes the result.
8. A read-only reconciliation claim may inspect the target after failure. It
   cannot perform repair or continue provisioning without a current mutation
   claim, matching state, and fresh approval where required.
9. The claim is released only after transaction completion, a proven clean
   abort, or recorded quarantine.

Fencing has three independent scopes:

- **Device quarantine** denies production use of the target and its
  credentials while permitting only explicitly authorized recovery or
  retirement.
- **Lane fence** prevents new work through one target attachment.
- **Station revocation** prevents the host from acquiring or renewing any
  provisioning claim.

## Control-service interfaces

The following names describe required semantics, not a required wire protocol.

### Coordinator and inventory

```text
CreateTransaction
AcquireClaim / RenewClaim / TransferClaim / ReleaseClaim
BindTarget
RecordStageIntent / RecordStageEvidence
StageKeyGeneration / RecordCertificate
ActivateExactTuple
AbortTransaction / QuarantineDevice
FenceLane / RevokeStation
CompleteTransaction
GetTransactionForReconciliation
```

Every mutation includes the transaction and idempotency IDs, station and lane
identities, claim epoch and expiry, expected resource version, stage, canonical
input digest, target-binding fingerprint after binding, and a signed scoped
authorization. The coordinator rejects an expired or stale epoch, illegal
transition, mismatched digest, changed target, unexpected resource version, or
idempotency-key reuse with different inputs.

### Device RA and CA

The enrollment challenge and response bind:

- canonical transaction digest and fresh nonce;
- bootstrap authentication or approved ceremony evidence;
- operational SPKI and PoP;
- logical ID assigned from inventory;
- credential slot and key generation;
- certificate profile, policy, and artifact identity; and
- RA and CA audience.

The RA ignores or replaces identity-bearing CSR fields. The station cannot
select a SAN, broaden key usage or extended key usage, or choose another device
identity. Issuance is idempotent, and the CA ledger is authoritative if the
station loses the response.

### Pending-credential verifier

The verifier accepts staged credentials through a dedicated endpoint that is
not production authorization. It returns a signed receipt binding the
challenge result to the transaction, logical ID, SPKI, issuer and serial, slot,
key generation, verifier audience, and test policy. Inventory requires that
receipt for atomic activation.

Production must reject the staged credential before activation. After
activation, production authentication must succeed for that exact credential
and inventory tuple.

### Audit service

Each event includes its schema and policy version, previous-event hash or
equivalent ordering reference, transaction, station and lane, stage, fence
epoch, canonical input and output digests, actor identities, time evidence,
result, and references to structured non-secret observations. The service
returns a durable receipt. Inventory stores the receipt and evidence digests;
the independent audit service retains the full access-controlled record.

## Station execution of a device transaction

Before entering the per-device state machine, the station admission gate:

1. verifies approved station software, configuration, identity, credentials,
   time, disk, audit export, and lane health;
2. confirms that required control services are available and authenticated;
3. confirms that the station and lane are active, empty, and unfenced; and
4. authenticates the named operator and verifies their current role.

The station then applies the lifecycle document's stages as follows:

| Transaction stage | Station responsibility and external gate |
| --- | --- |
| `created` | Obtain the central transaction, reservation, pinned bundle, and scoped admission capability. |
| `target_bound` | Claim exactly one target through the lane guard and bind its observations to the transaction and current fence epoch. |
| `preflight_passed` | Use read-only or reversible adapter operations to validate the signed profile's allowed baseline. |
| `commit_approved` | Resolve the exact plan, export its digest and prestate, and validate independent approval for the current target and epoch. |
| `trust_established` | Prove both target-to-domain and domain-to-target initial trust using the transaction-bound protocol. |
| `security_applied` | Journal each approved mutation before execution and accept it only after profile-defined direct readback. |
| `identity_ready` | Request target-local generation or derivation, receive public references only, check uniqueness, and obtain transaction-bound PoP. |
| `credentials_staged` | Submit the bound enrollment request, validate the returned public certificate and chain, and reconcile it with inventory and the CA ledger. |
| `installed` | Atomically install public material and scoped post-enrollment credentials, erase transient material, finalize controls, restart where required, and read back state. |
| `verified` | Prove the installed key at the pending verifier and run all required positive, negative, replay, substitution, and alternate-identity tests. |
| `activated` | Submit the verifier receipt and request compare-and-set activation of the exact staged tuple, then prove production authentication. |
| `complete` | Export the terminal audit event, reconcile authoritative state, verify transient erasure, release the claim, clear the lane, and permit physical release. |

Certificate issuance, installation, or pending verification alone never permits
physical release as a successful device. If activation succeeds but the station
misses the response, it queries inventory and completes the record rather than
issuing again or attempting an automatic rollback.

## Secret and sensitive-material handling

| Material | Station treatment |
| --- | --- |
| Station bootstrap private key | Unique to the station; preferably non-exportable; used only through the identity broker for station lifecycle |
| Short-lived workload credentials | Audience-restricted, rotated automatically, and unusable after station revocation |
| Operator and approval assertions | Short-lived, action-bound, excluded from general logs, and invalidated on transaction or epoch change |
| Transaction capabilities and enrollment tokens | Single transaction, target, audience, and operation set; held only as long as needed and erased after use |
| Provisioning bundles, certificates, and trust bundles | Not secret, but signature-, integrity-, version-, and rollback-sensitive |
| Target-generated device root and private keys | Generated or derived in the target boundary; never exported to station memory, disk, journal, audit, logs, or backups |
| Exceptional injected secret | Unique, target-bound encrypted envelope handled by the narrow injection broker; plaintext never reaches generic components; transient handling and erasure are verified |
| Journal and audit evidence | Secret-free but access-controlled, integrity-protected, and privacy-sensitive |
| Diagnostic output | Schema-constrained and reviewed so it cannot become an archive of tokens, packet payloads, memory, or device secrets |

Per-device workspaces are encrypted or memory-only, never reused across
transactions, and cleared before the lane accepts another target. Secrets are
prohibited from process arguments, broad environment variables, shell history,
swap, logs, telemetry, packet captures, crash reports, immutable build stores,
support bundles, and backups.

## Failure, retry, and quarantine

The transaction and retry model in
[the device lifecycle](device-identity.md#retry-and-abort-behavior) is
normative. Station-specific consequences are:

- Before the first irreversible effect, the station may abort only after it
  proves the target returned to an allowed reusable baseline, erases transient
  authorization, releases the claim, and records the result centrally.
- At or after the first irreversible effect, an unknown command result,
  unverifiable postcondition, target change, lease loss during mutation,
  restart mismatch, or missing required audit evidence quarantines the device.
- A timeout or lost response causes direct observation and authoritative
  reconciliation. It never authorizes blind repetition of a mutation or
  issuance request.
- Central-service loss before commit pauses or safely aborts. Loss after commit
  pauses new mutation and starts reconciliation; it does not enable offline
  continuation.
- An issued but unverified certificate remains staged. Abandonment invokes the
  configured revocation or bounded-expiry policy.
- A verification or post-activation failure immediately quarantines the exact
  device and credential tuple. The station does not create a replacement
  identity to conceal the failure.
- A different target, key, logical-ID binding, artifact, adapter, policy,
  approval, profile, or fence epoch cannot be repaired within the original
  transaction.

At minimum, a wrong target, conflicting ownership, public-key collision,
failed PoP, out-of-profile certificate, unknown irreversible outcome,
post-restart mismatch, suspected secret exposure, or audit gap quarantines the
device. An invalid approved artifact, public-key collision, policy-violating CA
issuance, suspected station compromise, or evidence that secrets entered logs
also fences the lane or station pending review.

## Station lifecycle and operations

Station lifecycle is separate from every device transaction:

```text
unenrolled -> enrolled -> qualified -> active <-> maintenance
                                      |             |
                                      +-> fenced <--+
                                            |
                                            v
                                         retired
```

### Build, enroll, and qualify

1. Install the approved baseline and verify boot, update, rollback, storage,
   debug, peripheral, and network policy.
2. Register the station asset, owner, location, hardware and software profile,
   lane identifiers, and initial configuration hashes.
3. Generate or establish a unique station identity through an
   administrator-controlled ceremony. Never clone that credential in a disk
   image.
4. Install service trust and policy through an authenticated,
   rollback-resistant path.
5. Run qualification with test-only PKI, artifacts, inventory, policies, and
   sacrificial targets. Exercise every mutation boundary, restart, retry,
   negative test, quarantine, and audit path.
6. Promote the station to production only after independent review and
   approval. Promotion grants bounded production roles; it does not copy test
   credentials or history.

### Updates and maintenance

Updates drain active work, fence admission, enter maintenance state, install an
approved signed and rollback-constrained generation, reboot where required,
verify station posture, and re-run the applicable qualification suite before
returning to active state. Changes to provisioning logic, adapters, crypto,
drivers, firmware, trust bundles, audit schemas, or security policy require
stronger requalification than ordinary data-only changes.

Routine operators cannot approve station software or policy changes. Privileged
maintenance events use separate identities and are exported to the independent
audit service. In-place emergency modifications do not become a supported
production baseline; rebuild or incorporate them through the reviewed artifact
process.

### Backup and recovery

Back up declarative configuration, public trust material, bundle references,
central transaction references, and the encrypted journal or audit outbox
needed for reconciliation. Do not back up raw target secrets, exportable
production signing keys, broad bearer tokens, or unredacted diagnostics.

Backups are authenticated, encrypted under separate custody, versioned, and
restore-tested. External signers or HSMs use their own approved wrapped and
split-custody recovery procedure; their keys are not station backups.

After a crash or restore, the station queries central state and directly
re-observes every attached incomplete target. Local success markers never
activate a device. Restoring to replacement hardware normally requires a new
station identity, fresh qualification, explicit claim transfer, target
rebinding, and new approval for remaining destructive work.

### Monitoring

Export and alert on:

- station boot and posture failures, configuration drift, maintenance, and
  unexpected software or peripheral changes;
- station, operator, approver, and administrator authentication;
- target connection, replacement, lane assignment, claim renewal, lease loss,
  fencing, and physical release;
- bundle resolution, signature checks, cache selection, expiry, revocation,
  and rollback decisions;
- every intent, mutation, readback, retry, abort, quarantine, enrollment,
  issuance, verification, activation, and audit receipt;
- abnormal transaction or signing rates, repeated failures, public-key
  collisions, policy exceptions, and requests outside service scope; and
- station credential expiry, clock quality, disk and journal health, and audit
  export gaps.

### Incident response

On suspected station compromise:

1. fence the station and every lane;
2. revoke station workload credentials and invalidate unexpired transaction
   capabilities and approvals;
3. stop related issuance and activation;
4. preserve central audit, external-signer, artifact, inventory, disk, and
   available volatile evidence;
5. establish the earliest plausible exposure window and review or quarantine
   every device processed during it;
6. revoke or replace affected device credentials according to whether keys,
   issuance, artifacts, or activation could have been abused;
7. rotate exposed operator, maintenance, approval, and signer-authorization
   credentials; and
8. rebuild from the approved baseline, enroll under a new station identity,
   and requalify before production use.

Do not trust in-place cleanup of a compromised production station. Break-glass
credentials and recovery keys remain offline under split custody rather than
resident on the station.

### Decommissioning

Drain, transfer, or quarantine every incomplete transaction; revoke station and
lane credentials; remove coordinator, RA, verifier, signer, and artifact
authorization; export the final audit record; securely erase local credentials,
tokens, cached sensitive state, journals, encryption keys, and storage under the
applicable sanitization policy; and retire the asset record. Retired station and
lane identifiers are not reassigned.

## Scaling beyond one lane

Do not introduce parallel provisioning until the single-lane implementation
passes all acceptance criteria, including wrong-target, disconnect, restart,
uncertain-write, audit-loss, and recovery tests.

Each additional lane needs its own:

- permanent physical identifier and target mapping;
- privileged executor identity or independently enforceable sub-identity;
- target transport or network namespace;
- transaction claim and fence epoch;
- journal, workspace, protocol state, and rate limits; and
- target-presence, continuity, and release checks.

Policy, bundle distribution, inventory activation, RA, verification, and audit
remain centralized. Responses and device observations are always bound to a
lane and transaction, never to unstable operating-system device numbering.
Test cable or target swaps, simultaneous reconnects, station restart, hub or
transport failure, responses arriving on the wrong lane, and one lane
attempting to use another lane's capability during qualification.

A local lane failure should not contaminate another lane. A station-level
posture failure, invalid approved artifact, public-key collision,
policy-violating issuance, suspected credential misuse, or audit integrity
failure fences every lane. Throughput never weakens target binding, approval,
post-write observation, secret isolation, activation, or quarantine policy.

## Acceptance criteria

A future implementation must demonstrate that:

- More than one eligible target, target replacement, or a changed
  target-binding fingerprint prevents mutation.
- No device write occurs without a central transaction, current claim, matching
  epoch, approved bundle, and legal state transition.
- No irreversible operation occurs without an externally retained intent,
  exact commit approval, and sufficient remaining claim time.
- A stale station or fence epoch is rejected by every central mutation and by
  the compliant lane guard.
- Crashing before, during, and after each mutation resumes through observation
  and reconciliation without blindly repeating a one-way operation.
- Repeated enrollment with identical idempotency inputs returns the original
  certificate, while changed SPKI or transaction context fails.
- A malicious target or CSR cannot select another logical ID, SAN, key usage,
  extended key usage, certificate profile, or key generation.
- Station credentials cannot sign certificates, publish artifacts, alter
  unrelated inventory, activate an arbitrary tuple, operate another
  transaction, or read audit history beyond their required scope.
- Device-generated roots and private keys never appear in station storage,
  swap, generic-orchestrator memory, logs, audit, packet captures, crash output,
  diagnostic bundles, or backups.
- Any exceptional injected secret is unique, target-bound, absent from generic
  components, and demonstrably erased after installation.
- A staged certificate is accepted only by the pending verifier and rejected
  by production before activation.
- Activation changes only the exact staged tuple named by a valid verifier
  receipt and current inventory compare-and-set.
- Replayed transcripts, substituted keys, alternate identities, untrusted
  issuers, and another device's certificate fail.
- Audit loss, evidence mismatch, unknown irreversible outcome, missing
  post-restart evidence, or failed production proof prevents successful
  completion and invokes quarantine or fencing policy.
- Device quarantine, lane fencing, and station revocation are independently
  enforced and tested.
- A partially provisioned or quarantined device can never be reported as
  unprovisioned.
- An artifact mutation, unsigned adapter replacement, expired approval,
  transferred claim, or changed plan invalidates commit authorization.
- A control-service outage before commit pauses or cleanly aborts; after commit
  the station pauses and reconciles instead of continuing offline.
- Reimaging, restoring, or replacing a station cannot restore stale claim,
  approval, issuance, or activation authority.

## Kaiba implementation boundary

The current repository has a hardware-qualified, read-only Raspberry Pi 5
probe backed by a stable device-class profile. It also has development
foundations for durable control and audit, authenticated execute-side
bridging, a one-shot lane guard, an offline signed-release assembler and Nix
factory, and software-only production-media writer and verifier contracts. It
still has no qualified production station, general production coordinator,
device RA, inventory
activation service, production bundle authority, or pending-credential
verifier. The probe and these development foundations grant no mutation or
activation authority. The integration PKI and file-backed agent key remain
test fixtures.

Completing a production implementation following this design will require, at
minimum, production qualification or integration of:

- the generic transaction orchestrator and durable journal;
- a signed device-class profile and platform-adapter interface;
- protected station identity and scoped service credentials;
- coordinator, inventory, claim, fencing, approval, and audit APIs;
- constrained RA and idempotent CA issuance integration;
- pending-credential verification and exact-tuple activation;
- a signed, content-addressed provisioning-bundle pipeline; and
- station build, qualification, monitoring, incident, and retirement
  procedures.
