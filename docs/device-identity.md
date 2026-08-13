# Device identity and credential lifecycle

This document defines a target production security contract for provisioning,
enrolling, operating, rotating, recovering, and retiring Kaiba device
credentials. It is deliberately platform-neutral: a hardware security module,
secure element, trusted execution environment, operating-system keystore, or
protected software key can implement the contract at different assurance
levels.

The production workflow described here is not implemented by the pilot. The
current implementation boundary is summarized in [Kaiba mapping and gaps](#kaiba-mapping-and-gaps).

## Security objective

When a device connects, the controller needs evidence that:

1. the peer currently possesses the private key for an active credential;
2. the registration authority assigned that credential exactly one canonical
   device identity; and
3. the certificate instance, key generation, device record, and issuing
   authority are still acceptable under current policy.

For Kaiba, that canonical identity is a URI such as
`spiffe://kaiba.network/device/001`. Authorization derives
`pi-001.kaiba.network` from the authenticated identity. A serial number,
hostname, MAC address, certificate common name, or request-body field is not an
authentication factor and cannot select the identity.

Authentication and attestation are different claims:

- **Authentication** proves possession of a credential that is authorized for
  an identity.
- **Attestation** supplies fresh, appraisable evidence about the environment
  holding or using a credential.

A valid mutual TLS (mTLS) connection does not, by itself, prove the device's
boot or runtime state. A device-signed statement is not sufficient for a
trustworthy attestation result unless a verifier can establish how the claims
were collected, how the evidence was protected, whether it is fresh, and which
applicable endorsements, reference values, and policies were used. This
separation follows the architecture in [RFC 9334].

## Terminology

- **Logical device ID**: the stable operator-assigned identifier, such as
  `001`. It names an inventory record, not a piece of hardware by itself.
- **Device root secret**: a long-lived device-unique secret or private key that
  anchors stronger claims about the device. It is distinct from the PKI root
  CA key. A Device Identifier Composition Engine (DICE) Unique Device Secret
  (UDS) is one symmetric example and never appears in a protocol transcript.
- **Bootstrap identity**: a narrowly authorized identity used to enter an
  operator domain, recover a device, or request an operational credential. It
  is analogous to a manufacturer or factory device identity, but need not be
  manufacturer-installed.
- **Operational identity**: the replaceable key and certificate used by a
  deployed service, such as the Kaiba agent's mTLS credential. A device may
  have several operational identities, each scoped to one protocol and role.
- **Attestation identity**: a restricted key used only to authenticate
  evidence. It is not an ordinary TLS or arbitrary-data signing key.
- **Credential slot**: one operational role for one logical device, such as
  `(device 001, agent client)` or `(device 001, inbound HTTPS)`. Roles rotate
  independently.
- **Operational key generation**: the monotonically increasing generation of a
  private key within one credential slot.
- **Certificate instance**: one issuer-and-serial certificate for an
  operational key generation. Same-key renewal changes the certificate
  instance but not the key generation.
- **SubjectPublicKeyInfo (SPKI)**: the standard public-key structure whose
  fingerprint identifies the key being enrolled.
- **Proof of possession (PoP)**: cryptographic evidence that the requester
  controls the private key corresponding to an enrolled public key.
- **Validation bundle**: the public trust anchors and intermediates used to
  validate peers. A validation bundle is not secret, but its integrity is
  critical. A SPIFFE bundle is a more specific standardized object containing
  the authoritative keys for one SPIFFE trust domain.
- **Enrollment**: the policy decision and protocol that bind a public key to a
  logical identity and issue an operational credential.
- **Provisioning**: the wider controlled process that prepares the device,
  establishes initial trust, performs enrollment, configures protection, and
  records the result.

## Device-resident material

The word *secret* should be reserved for values whose disclosure enables an
attacker to impersonate the device, decrypt protected data, or cross another
security boundary. Certificates and public trust anchors require integrity and
availability, but not confidentiality.

| Material | Secret? | Purpose and expected protection |
| --- | --- | --- |
| Device root secret | Yes | Device-lifetime bootstrap or derivation root. Prefer non-exportable use, never expose it to ordinary applications, and do not use it as a general network credential. |
| Bootstrap private key | Yes | Authenticate enrollment or constrained recovery. Accept it only at enrollment and recovery services. |
| Operational mTLS private key | Yes | Authenticate the deployed agent. Make it unique per device, restrict it to one service and purpose, and rotate it independently of the logical identity. |
| Operational certificate | No | Binds an operator-assigned identity to the operational public key. Protect against unauthorized replacement and support atomic updates. |
| Application service private key | Yes | Authenticate an inbound device service, such as HTTPS. Keep it separate from the agent's control-plane key and rotate it under the service's own certificate policy. |
| Application service certificate | No | Binds the service name to its public key. It may use a private or public PKI distinct from device enrollment. |
| Controller validation bundle | No | Authenticates the controller and enrollment service. Update it only through an authenticated, rollback-resistant path. |
| Attestation private key | Yes | Signs structured evidence only. Keep it isolated from the environment it is intended to describe. |
| Storage and data-encryption keys | Yes | Protect local or application data. Keep them separate from identity, signing, and attestation keys. |
| Signer authorization material | Yes, if present | A PIN, authorization value, or unlock credential controls use of a protected key. Make secret values device-specific and expose them only to the narrow broker that needs them. |
| Network and application credentials | Yes | Wi-Fi, VPN, API, database, and service credentials must be per-device or narrowly scoped, delivered only after authentication, and rotated independently of device identity. |
| Enrollment or recovery token | Yes | Short-lived, single-device, single-use bootstrap authorization. Erase it after use and never ship a fleet-wide default token. |
| Hardware identifiers | Usually no | Correlate manufacturing and inventory records. They may be privacy-sensitive, but they are not proof of key possession. |
| Software verification keys | No | Authenticate software or configuration. Their integrity is critical; private software-signing keys remain off-device. |
| Idempotency and transaction state | No | Prevent replay and unsafe retry. Its integrity and durability matter even though it is not an authentication secret. |

These rows describe security roles, not a requirement to store every item. A
profile may derive a bootstrap key from a device root, omit attestation, or keep
an operational key only in memory. Logical separation still requires distinct
keys or domain-separated derivations for distinct purposes.

Under Kaiba's separation boundary, a deployed device must not contain:

- root or issuing CA private keys;
- fleet software-signing private keys;
- provisioning-station or device-RA administrator credentials;
- another device's secrets;
- DNS-provider credentials or DNS update keys; or
- a fleet-shared symmetric bootstrap secret.

## Threat boundary and protection choices

Terms such as *secure storage*, *hardware-backed*, and *non-exportable* are
meaningful only when the protected attacker boundary is stated. Every device
profile must say whether it is intended to resist:

- copied, removed, or modified storage;
- a hostile network and replayed enrollment traffic;
- compromise of an unprivileged application;
- compromise of the network-facing device agent;
- administrator or kernel compromise;
- debug access and non-invasive physical access;
- invasive extraction, fault injection, or side channels; and
- supply-chain or provisioning-station compromise.

Common protection choices have different boundaries:

| Mechanism | Useful protection | Important limitation |
| --- | --- | --- |
| File permissions plus encrypted storage | Offline storage theft and accidental cross-service access | A running privileged process can normally copy the decrypted key. |
| OS keystore or isolated signer service | Separates the network process from raw key bytes and narrows allowed operations | Its guarantee is only as strong as the OS privilege boundary. |
| Hardware-backed non-exportable signer | Makes storage cloning ineffective and can prevent permanent key extraction across a stronger boundary | Compromised software may still use an authorized signing oracle while it controls the device. |
| Hardware-rooted derivation or sealing | Produces purpose- or state-bound child keys without storing each child key directly | The root must remain inside its claimed boundary. A one-time handoff design must also lock or erase the parent before untrusted code runs. |
| Short-lived in-memory credential | Limits acceptance time and can avoid persisting a key | Expiry only invalidates the credential. The private key disappears only when volatile storage is cleared or it is explicitly zeroized. |
| Unique per-device pre-shared key | Simple bootstrap for constrained devices | The device RA holds an impersonation secret; rotation and large-fleet containment are harder than with public-key credentials. |

An implementation may combine these mechanisms. For example, full-disk
encryption protects offline device state and software-held secrets while an
isolated signer protects the identity key during operation. The implementation
must not claim resistance to administrator, kernel, or physical compromise
merely because the key is stored outside a normal file.

## Secure-device requirements

### Key and identity requirements

- Every device authentication key must be unique. An image, backup, or factory
  batch must never clone it to another device.
- Private keys should be generated on the device inside their final protection
  boundary with a cryptographically secure random source. If injection is
  unavoidable, the station must use an authenticated confidential channel,
  audit uniqueness, and securely delete every transient copy.
- The device must prove possession of each new private key before its public key
  is authorized.
- One key must have one purpose. Bootstrap, operational authentication,
  inbound service authentication, attestation, storage encryption, software
  signing, and CA issuance use separate keys or strongly domain-separated
  derivations.
- The registration authority, not the device or its certificate signing
  request (CSR), assigns the canonical logical identity and authorization
  attributes.
- The operational certificate must constrain intended use through its profile,
  including basic constraints, key usage, extended key usage, and issuer
  policy. Kaiba's agent-client slot additionally requires exactly one URI
  Subject Alternative Name (SAN) containing the authoritative device identity.
- Algorithms, key sizes, certificate profiles, and signer interfaces must be
  replaceable without renaming the logical device.

### Access and execution requirements

- The network-facing process should receive only a constrained signing
  interface. It should not receive raw root, bootstrap, attestation, storage,
  or unrelated application keys.
- Access to a signer must be limited by service identity, operation, key ID,
  algorithm, rate, and message size where the platform supports those
  restrictions.
- Secure or verified boot, rollback protection, debug lifecycle, and update
  authorization must match the claimed key-protection boundary. Verified boot
  is still not remote attestation.
- Secrets must not appear in process arguments, environment dumps, logs, crash
  reports, telemetry, build outputs, world-readable images, or immutable
  package stores.
- Failures must be closed: an unavailable protected signer, expired
  certificate, stale validation bundle, or failed status check must not cause a
  fallback to an unprotected key or unauthenticated connection.

### Fleet and service requirements

- The inventory must bind the logical device ID to its bootstrap public identity
  or a public identity derived or endorsed from the device root, credential
  slots, operational key generations, certificate instances, lifecycle state,
  and provisioning history.
- The relying service must check both PKI validity and current inventory
  authorization. A CA-valid certificate for a quarantined, retired, or
  non-active device, key generation, or certificate instance is not sufficient.
- Production device, controller, enrollment, attestation-verifier, and test
  identities should use separate issuing intermediates or equivalently strict
  issuance and EKU policy. The offline trust root should not perform routine
  issuance.
- All lifecycle operations must be authenticated, authorized, idempotent, and
  attributable to an operator or service identity.
- Recovery, revocation, CA compromise, ownership transfer, and decommissioning
  must be designed before the first device is provisioned.

## Provisioning and enrollment roles

The logical roles are:

- **Device**: generates or contains the key and proves possession.
- **[Provisioning station](provisioning-station.md)**: controls physical or
  bootstrap access and runs the approved provisioning bundle.
- **Device registration authority (device RA)**: authenticates the device and
  operator, assigns the logical ID, and applies issuance policy. This role is
  distinct from the domain-name registrar discussed in [the architecture
  notes](architecture.md).
- **Certification authority (CA)**: signs certificates after RA authorization.
- **Inventory**: records identity bindings, credential slots, operational key
  generations, certificate instances, device state, and audit evidence.
- **Relying service**: authenticates the operational certificate and applies
  current inventory authorization.
- **Verifier**: when attestation is required, appraises evidence independently
  of the relying service.

One deployment may co-locate roles, but their credentials and authorization
policies remain separate. In particular, a provisioning station should not
hold the offline root CA key, and the CA should not infer a device identity from
untrusted CSR fields. [NIST IR 8350]'s network-layer onboarding roles provide
applicable guidance for mutual device/network authentication, unique
credentials, protected delivery, and lifecycle replacement; [NIST SP 1800-36]
demonstrates several implementations of that model.

## Controlled provisioning ceremony

The generic information flow is:

```text
device                    provisioning station       device RA, inventory, CA
  |                               |                            |
  |<-- transaction, nonce, -------|                            |
  |    and device-RA auth         |                            |
  |-- bootstrap authentication -->|-- verify bootstrap ------->|
  |-- operational SPKI + PoP ---->|-- bind and authorize ----->|
  |                               |<-- certificate + policy ----|
  |<-- certificate + validation --|                            |
  |    bundle                     |                            |
  |------ operational mTLS ------>|-- activate key/cert ------>|
  |                               |                            |
```

Bootstrap authentication and operational-key proof of possession are separate
checks. The protocol must cryptographically bind both checks to one canonical
hash of the complete transaction, including the nonce, intended logical ID,
operational SPKI, certificate profile and policy version, and device RA or
audience. An explicitly validated, signature-capable PKCS#10 CSR proves
possession of its signing key, but its self-signature does not bind surrounding
transaction state. The device RA must also verify a signed transaction-hash
attribute, a separate challenge-response, or an equivalent protocol binding.
The CSR neither authenticates a bootstrap identity nor authorizes its requested
names. Other key types require an appropriate PoP mechanism.

### Per-device software transaction

Provisioning software must implement the ceremony as a durable transaction,
not as a script that infers progress from whichever certificate or device state
it happens to observe. The generic orchestrator enforces transaction ordering,
authorization gates, retry, audit, and activation workflow semantics;
authoritative policy decisions and records remain with the applicable control
services. A signed device-class profile declares the required behavior, and a
platform adapter supplies hardware-specific capabilities and operations
without changing those semantics. The
[provisioning station design](provisioning-station.md) defines the execution
environment and separates its authority from the coordinator, inventory, RA,
CA, artifact authority, verifier, and audit service.

Each device-class profile must:

- define the allowed unprovisioned baseline as observable state;
- expose stable public observations for target binding and state
  reconciliation;
- declare ordered operations and classify each as read-only, reversible,
  irreversible, or authorization-affecting;
- define independently observable postconditions for every mutation; and
- state which secrets can be generated, derived, injected, used, erased, or
  locked without exposing them to the generic orchestrator.

The generic workflow must not assume a particular secure-boot mechanism,
keystore, debug interface, storage technology, or attestation format. It runs
the following stages once for every device:

1. **Create the transaction.** Reserve the intended logical ID and physical
   asset in inventory, acquire an exclusive provisioning claim lease and its
   monotonically increasing fence epoch, and bind a unique idempotency key to
   the device class, credential slots, operator and approver identities, nonce,
   expiry, policy version, tool version, approved artifacts, and intended RA or
   audience. No device write occurs in this stage.
2. **Claim and identify the target.** Open an exclusive session to exactly one
   candidate, collect its target-binding fingerprint, capabilities, lifecycle
   observations, and existing public identities, and require them to match the
   transaction. Before creation of a protected identity, this fingerprint may
   not be cryptographic. Physical identifiers correlate an asset; they do not
   prove possession of a private key.
3. **Validate the unprovisioned baseline.** Use read-only or reversible checks
   to establish that the candidate has no conflicting owner, logical-ID
   binding, active credential, transaction, residual owner data, or
   fleet-default secret, and that its lifecycle, boot, update, rollback,
   debug, recovery, key-slot, storage, entropy, and restart capabilities match
   the device profile. *Unprovisioned* is a policy-defined baseline, not merely
   the absence of a certificate. Unknown or unverifiable state fails this
   stage.
4. **Resolve and authorize the commit plan.** Calculate the exact ordered
   operations and postconditions, distinguish reversible work from every
   one-way or authorization-affecting change, and persist the pre-change
   observations. Bind explicit approval to the transaction digest, target
   fingerprint, policy and artifact hashes, and operation list. Any change to
   those inputs invalidates approval.
5. **Establish initial trust.** Authenticate and authorize both directions:
   the RA or operator domain must accept the candidate's permitted bootstrap
   evidence, and the device must authenticate and authorize the intended
   provisioning or enrollment domain. Physical custody alone supplies neither
   direction automatically.
6. **Apply the security foundation.** Install or stage the approved software
   and configuration, then establish the profile's required boot and update
   authorization, rollback, storage, debug, recovery, lifecycle, and protected
   signer posture in its declared order. Durably record intent immediately
   before each irreversible operation and read back its effective state; a
   successful command return is not a sufficient postcondition. Controls that
   must remain open until identity installation are finalized in stage 9.
7. **Establish device-unique material.** Prefer generating or deriving each
   root and private key inside its final protection boundary. Use distinct keys
   or explicitly domain-separated derivations for bootstrap, operational
   authentication, application, attestation, storage, and other roles. Export
   only public keys, identifiers, endorsements, and fingerprints; check public
   key uniqueness and obtain fresh PoP for every enrolled asymmetric key.
   Never retrieve a symmetric device root. If injection is unavoidable, the
   profile must use a target-bound authenticated confidential channel, account
   for uniqueness, avoid persistent station copies, and verify erasure of
   transient copies.
8. **Enroll and stage credentials.** Bind bootstrap authentication and
   operational-key PoP to the same transaction digest and fresh nonce. The RA
   assigns the canonical identity, inventory records the key generation as
   pending, and the CA returns a constrained certificate recorded as staged.
   Before installation, verify its issuer, chain, SPKI, SAN, algorithms, basic
   constraints, key usage, EKU, validity, profile, and transaction binding.
   Repeating an issuance call with the same idempotency key returns the recorded
   result rather than creating another certificate.
9. **Install and finalize.** Atomically install the certificate, validation
   bundle, public policy metadata, and non-secret inventory identifiers. Only
   after authenticated enrollment may the workflow deliver separately scoped
   per-device network or application credentials. Erase one-time bootstrap
   tokens and transient secret copies, apply final key-access, lifecycle,
   debug, boot, update, recovery, and storage controls, restart when required,
   and read back the resulting state. The operational credential remains
   production-denied.
10. **Verify and activate.** Prove the installed private key to a controlled
    endpoint that accepts pending credentials and confirm the expected
    transaction, logical identity, SPKI, issuer, serial, and key generation.
    Confirm that production still rejects the pending credential and that an
    untrusted issuer, substituted key, replayed transcript, or alternate
    device-supplied identity fails. After every positive and negative check
    passes, atomically activate the exact device, key generation, and
    certificate tuple in inventory, then prove production authentication.
11. **Commit and release.** Export the complete secret-free audit record to its
    independent destination, reconcile the authoritative inventory and RA
    result, clear station-local transient data, release the provisioning claim
    lease, and release the physical device. Successful certificate issuance
    alone is not completion; the terminal success state is an active credential
    plus confirmed audit export.

The following sections expand the security requirements that apply across
those execution stages.

### Preparation requirements

- Create a unique, expiring provisioning transaction containing the expected
  physical asset, intended device class, intended logical ID, approved software
  or configuration, operator identity, and policy version.
- Pin the provisioning bundle, firmware or software hashes, issuer,
  validation-bundle version, and tool version.
- Perform all reversible preflight checks before any one-way key, lifecycle,
  debug, ownership, or boot-policy change.
- Present an exact plan and bind explicit commit approval to the transaction
  and observed device fingerprint. A broad "provision whichever device is
  attached" operation is not acceptable for irreversible changes.

### Initial-trust requirements

Provisioning must answer two separate questions even when one protocol supplies
both answers:

- **How the device RA authenticates and authorizes the device**: examples
  include controlled physical custody tied to an inspected device, a
  manufacturer or operator bootstrap certificate, a unique out-of-band secret,
  or appraised hardware-rooted evidence.
- **How the device authenticates and authorizes the enrollment registrar or
  domain**:
  examples include a trust anchor in the approved provisioning image, a mutual
  protocol using a unique out-of-band secret, explicit physical confirmation,
  or manufacturer-authorized voucher data that pins the permitted registrar or
  domain.

Physical custody or attestation alone does not authenticate the enrollment
registrar back to the device. Likewise, authenticating either party does not by
itself authorize the requested ownership or identity binding.

Trust on first use over an untrusted network is not equivalent. If a deployment
accepts it, the resulting risk and required out-of-band fingerprint check must
be explicit. [RFC 8995] describes a standardized voucher-based bootstrap model
and separates pledge authentication from authorization and pinning of the
registrar or domain.

### Inspection and key-generation requirements

- Confirm lifecycle, ownership, debug, boot-policy, rollback, entropy, clock,
  key-slot, and storage state against the device-class policy.
- Generate each required root or operational key within its intended protection
  boundary. A profile with a symmetric device root, such as a DICE UDS, keeps
  that root inside the boundary and derives or endorses a separate asymmetric
  bootstrap or operational key.
- Retrieve, fingerprint, and check uniqueness only for the resulting public
  key; never retrieve or transmit a symmetric device root.
- Obtain fresh PoP for the asymmetric key being enrolled. If attestation is
  required, bind its nonce, Evidence, and Attestation Result to that public key
  and the provisioning transaction.

### Authorization and issuance requirements

- The RA derives the canonical logical identity from the approved transaction
  and inventory policy. It ignores or replaces identity-bearing CSR fields.
- Record the new key as a pending operational key generation in its credential
  slot before issuance.
- Issue the constrained operational certificate and required intermediate
  certificates. The device certificate and validation bundle are public
  material.
- Record the issued certificate as a staged certificate instance associated
  with that key generation.
- Prefer short-lived operational certificates. Their exact lifetime and
  renewal window are policy choices based on device connectivity, clock
  quality, revocation latency, and recovery capability.

Enrollment over Secure Transport (EST) is one standardized protocol for initial
enrollment and re-enrollment; it supports client-generated keys, proof of
possession through certification requests, CA certificate distribution,
renewal, and rekey. See [RFC 7030]. A controlled local utility does not inherit
EST's security properties merely by following a similar sequence. It must
explicitly specify and review server authentication, enrollment authorization,
proof of possession, transcript binding, CSR processing, response validation,
TLS policy, and safe retry behavior. [RFC 7030 updates] lists later
clarifications and the deprecation of obsolete TLS versions.

### Installation, locking, and acceptance requirements

- Install the operational certificate, controller validation bundle, policy
  metadata, and non-secret inventory identifiers atomically.
- Erase one-time bootstrap tokens and transient copies.
- Apply final key-read, key-write, debug, boot, and storage controls before
  production use. Verify the effective state after a cold restart where the
  platform's guarantees require it.
- Prove the new operational identity to a controlled test endpoint.
- Run negative tests: an untrusted issuer, replayed transcript, substituted
  key, or device-supplied alternate identity must fail. Another device's
  credential must never be accepted as this transaction's logical identity,
  and the superseded credential must fail after cutover.
- Activate the inventory key generation and certificate instance only after
  every required test succeeds. Until activation, a technically valid
  certificate remains unauthorized.

### Audit-record requirements

The provisioning record must contain no secret values, but it is not public.
Stable identifiers, operator identities, versions, and security-state details
remain privacy- and security-sensitive and require access control. The record
should contain:

- transaction, logical device, asset, and device-class identifiers;
- device-root-derived public identity or bootstrap public-key fingerprint, and
  the operational SPKI fingerprint;
- credential slot, operational key generation, and certificate issuer, serial,
  profile, and validity;
- exact provisioning bundle, software, firmware, configuration, and tool hashes
  or versions;
- observed lifecycle, boot, rollback, debug, signer, and storage-protection
  state;
- validation-bundle and policy versions;
- station, operator, RA, and approver identities;
- timestamps and each positive and negative test result; and
- transaction result and resulting device, key-generation, and
  certificate-instance states.

Private keys, raw device-root secrets, enrollment tokens, storage keys, PINs,
and administrator credentials must never enter the audit record. Records should
be append-only or signed and exported from the station so a station failure
does not erase fleet provenance.

### Retry and abort behavior

Provisioning records transaction progress separately from device lifecycle and
from each credential slot's key generations and certificate instances:

```text
transaction: created -> target_bound -> preflight_passed -> commit_approved
             -> trust_established -> security_applied -> identity_ready
             -> credentials_staged -> installed -> verified -> activated
             -> complete

terminal exceptions: aborted | quarantined
```

Every stage has a durable `not_started`, `in_progress`, `succeeded`, or `failed`
record containing its input and output hashes and observed postconditions, but
no secrets. Every mutation follows the same pattern:

```text
check exact preconditions -> record intent -> execute once
-> observe authoritative state -> record evidence and result
```

The profile identifies the first irreversible effect. Before that boundary, a
transaction may become `aborted` only after the software proves that the device
has returned to an allowed reusable baseline and that no pending credential or
unique secret remains. At or after that boundary, an uncertain, mismatched, or
partially committed result becomes `quarantined`; it must never be reported as
unprovisioned again.

The related lifecycle states are:

```text
device:      unregistered -> staged -> active <-> quarantined -> retired

key generation (per slot): pending | active | superseded | revoked
certificate instance:      staged | active | superseded | revoked | expired
```

- An active device may have generation `N` active while generation `N+1` is
  pending in the same credential slot. Kaiba normally authorizes at most one
  active key generation and one active certificate instance per slot; any
  dual-active exception must be explicit and time-bounded.
- Same-key renewal stages a new certificate instance against the existing key
  generation, tests it at the enrollment endpoint, and atomically switches the
  accepted serial. The previous instance becomes superseded, revoked, or
  expired according to policy.
- A retry with the same transaction and public-key fingerprint returns the
  recorded result or resumes the next safe step only after reconciling observed
  state. A timeout or lost response never authorizes blind repetition.
- A retry that observes a different device fingerprint, logical-ID binding,
  public key, policy, artifact, tool version, approval, or irreversible state
  stops for review and normally quarantines the device.
- Losing the provisioning claim lease or presenting a stale fence epoch
  prevents further mutation. If authority is lost during an operation with an
  uncertain outcome, the station must reconcile state and quarantine when it
  cannot establish the postcondition.
- An issued but unverified certificate remains staged and production-denied. If
  the transaction is abandoned, revoke it or allow it to expire under the
  documented abandoned-transaction policy.
- If activation succeeded but the station missed the response, inventory is
  authoritative. Query it and finish the audit record; do not issue a second
  certificate or attempt an automatic rollback.
- A partially provisioned device is quarantined and denied production access;
  it never falls back to a default identity.
- Reprovisioning cannot silently replace an existing logical device binding.
  It requires an authorized re-enrollment or ownership-transfer operation.
- Unexpected prior ownership or security state, a public-key collision, failed
  PoP, a certificate identity or profile mismatch, an unverifiable irreversible
  operation, a failed post-restart or post-activation check, suspected secret
  exposure, or missing required audit evidence triggers quarantine.
- A public-key collision, invalid approved artifact, out-of-policy CA issuance,
  suspected station compromise, or evidence that secrets entered logs fences
  the affected lane and, for a fleet-significant failure, the station pending
  review, rather than failing only the current device.

## Steady-state authentication

For each full TLS authentication, the transport must:

1. require the intended TLS version and mutual authentication;
2. validate the certificate path, validity, algorithm policy, basic
   constraints, key usage, and client-authentication EKU;
3. require exactly one URI SAN, validate it as a permitted device identity, and
   ignore the common name for device authorization; and
4. enforce the certificate-revocation and session-resumption policy.

A resumed session may reuse that transport-authentication result only under an
explicit bounded policy. It must not outlive the credential or accepted
revocation state, and quarantine must invalidate the corresponding application
authorization state.

For each application authorization, or within a short bounded cache that is
invalidated by quarantine events, the controller must:

1. map the URI to a canonical logical device and resource owner;
2. confirm that the device, credential slot, key generation, and presented
   certificate instance are active in inventory; and
3. apply any separately required fresh attestation result.

The certificate proves a PKI binding; inventory decides whether that binding
is currently authorized. This online check provides immediate quarantine even
when certificate revocation information is cached or unavailable.

An inbound HTTPS or application identity is a separate operational role. Its
DNS SAN, issuer, EKU, private key, renewal protocol, and relying parties differ
from the agent's client identity. The two roles must not share a private key
merely because they run on the same device.

The preferred design reserves a device root or bootstrap identity for
enrollment and recovery, while replaceable operational keys perform routine
mTLS. If a platform exposes only one protected signing key, using it directly
for operational TLS may be an explicit lower-flexibility profile. That sole key
is designated for the operational slot; bootstrap must use physical custody,
an out-of-band factor, or another identity. Reusing the same key for bootstrap
and operational authentication is a weaker exception to the one-key/one-purpose
rule and must never expose a device-root or attestation key as a general TLS
credential. Certificates can still be renewed, but compromise of an immutable
operational key requires retirement or a separately supported key migration.

## Renewal, rotation, and rollover

These operations are not interchangeable:

| Operation | Key changes? | Purpose |
| --- | --- | --- |
| Certificate renewal | No | Replace an expiring certificate or update its non-identity policy while retaining the same key. |
| Operational rekey | Yes | Replace the routine authentication key and increment its accepted generation. |
| Bootstrap or device-root rotation | Yes | Replace the long-lived enrollment root after planned migration or compromise. Often requires physical or recovery authorization. |
| Issuing-CA rotation | CA key changes | Replace an online issuer while preserving the trust domain. |
| Trust-anchor rollover | Trust root changes | Migrate every relying party and device to a new root without a flag day. |
| Storage or application-key rotation | Yes | Limit data-key cryptoperiod or recover from exposure; independent of identity-key rotation. |

Same-key certificate renewal does not rotate a secret. It stages and validates
a new certificate instance for the active key generation, atomically switches
the accepted serial under the slot's overlap policy, and retires the previous
instance. Routine risk-limiting rotation should use operational rekey.

### Routine operational rekey

1. Begin before certificate expiry with randomized fleet jitter and enough time
   for intermittently connected devices.
2. Generate a new key in the intended protection boundary.
3. Authenticate the request with the current credential and separately prove
   possession of the new key. When policy requires device-state assurance,
   bind a fresh attestation result to the new SPKI.
4. Issue generation `N+1` as pending in the same credential slot while
   generation `N` remains active for a bounded installation and validation
   window.
5. Have the device prove mTLS possession of `N+1` to an enrollment endpoint
   authorized to test pending credentials.
6. Atomically mark `N+1` active and `N` superseded. Production authorization
   never accepts both unless the deployment explicitly selects a bounded
   dual-active policy.
7. Revoke `N` or allow it to expire under the documented PKI policy, then
   delete its private key after the bounded rollback window. Retain the public
   certificate and audit history, not the private key, for investigation.

If generation `N` may already be compromised, possession of `N` alone cannot
authorize `N+1`. Use the bootstrap or recovery path plus operator policy.

Renewal schedules must account for devices without trustworthy clocks. The
solution is secure time establishment, a sufficiently early renewal window,
and explicit recovery—not disabling certificate-time validation.

### Validation-bundle and CA rollover

The two authentication directions roll independently:

- **Device-side server trust** validates controller and enrollment-server
  certificates. Distribute a device validation bundle containing old and new
  server trust, confirm adoption, switch the servers to the new chain, wait
  through the offline-device recovery window, then remove old trust.
- **Controller-side device trust** validates device certificates. Add the new
  device issuer to the controller, begin issuing and activating device
  credentials under it, wait through the device-certificate migration window,
  then remove the old issuer after its remaining credentials are superseded,
  revoked, or expired.

Validation-bundle versions must be monotonic or rollback-protected. A normal
new-with-old transition is insufficient if the old CA key is compromised; that
case requires an independent recovery trust path. SPIFFE bundles likewise
support overlap by publishing multiple authoritative keys before removing the
old one.

### Revocation and quarantine

Short-lived certificates reduce, but do not eliminate, the need for immediate
response. On suspected loss or compromise:

1. quarantine the device, credential slot, key generation, or certificate
   instance in the online inventory at the narrowest safe scope;
2. deny ordinary enrollment and automatic renewal while permitting only a
   separately authorized recovery or re-enrollment transaction;
3. revoke affected certificates and publish the configured CRL or status
   information;
4. identify the earliest plausible compromise time and all affected keys,
   certificates, signatures, data, and descendants; and
5. use a stronger bootstrap or recovery path to establish any replacement.

Compromise scope determines recovery:

- **Operational key**: replace its generation after trustworthy recovery.
- **Bootstrap or device-root key**: distrust the physical identity; a new child
  certificate does not repair the root compromise.
- **Attestation key**: stop accepting evidence from that attester until its key
  trust and any applicable endorsements and reference records are
  re-established.
- **Issuing intermediate CA**: revoke it through the uncompromised parent,
  replace the issuer, reissue affected credentials, audit issuance, and
  distribute updated chain and revocation material.
- **Trust anchor or anchor-update path**: use the independent recovery trust
  path to replace the anchor and re-establish affected descendants.
- **Provisioning station or device RA**: review every transaction in the exposure
  window and rotate its administrative credentials.
- **Storage wrapping key**: rewrap child keys if they were not exposed. If a
  data-encryption key was exposed, re-encrypt the affected data under a new key;
  identity-key rotation does not restore data confidentiality.

## Recovery, reset, transfer, and retirement

Recovery must not depend solely on the expired, lost, or compromised
operational key. Acceptable recovery factors include a protected bootstrap
identity, controlled physical custody, a single-device recovery credential,
operator approval, and fresh appraised evidence. Recovery issues a new
operational key generation; it does not restore a compromised signing key from
backup.

Authentication and attestation private keys generally should not be escrowed
for availability. Losing a non-exportable authentication key should trigger
re-enrollment. Recoverable encryption keys are a different problem and may use
an envelope-encryption hierarchy with split or offline custody. [NIST SP
800-57] discusses these different backup and recovery needs.

A factory reset or ownership transfer must:

1. quarantine the previous operational identity before clearing the device;
2. revoke or disable all owner-domain certificates and enrollment grants;
3. erase operational, application, network, storage-wrapping, and cached
   credentials plus the previous owner's data and trust anchors;
4. preserve or explicitly retire any immutable hardware identity according to
   policy; and
5. require a fresh ownership authorization before enrollment into another
   domain.

Permanent retirement disables the device, every credential slot, and every key
generation and certificate instance in inventory; revokes remaining
certificates; destroys recoverable secrets; sanitizes storage under the
applicable media policy, such as [NIST SP 800-88 Rev. 2]; and closes the audit
record. If an immutable root cannot be erased, it remains deny-listed. Physical
destruction may be required when the residual hardware secret is outside the
accepted disposal threat model.

## Non-PKI secrets and cross-platform considerations

- **Storage encryption**: use separate data-encryption and key-encryption keys.
  Rotating a wrapping key should not require reusing an identity key or exposing
  every data key. Define recovery before relying on a non-exportable root to
  unlock irreplaceable data.
- **Network and application credentials**: deliver them only after device
  authentication, scope them to one device and service, and prefer short-lived
  credentials. Never use one fleet-wide Wi-Fi, VPN, API, or bootstrap secret
  when per-device credentials are possible.
- **Entropy**: test the random source in the earliest environment that creates
  keys. Provisioning many devices from an identical early-boot state must not
  produce repeated keys.
- **Time**: define how a device with an empty, reset, or attacker-controlled
  clock authenticates time without bypassing certificate validation.
- **Rollback**: old but correctly signed software may retain access to secrets
  or old credentials. Enforce security versions or another anti-rollback policy
  appropriate to the platform.
- **Debug and repair**: production and repair lifecycle states need explicit
  key-access behavior. Enabling debug must not silently expose a production
  root, and repaired devices require revalidation before activation.
- **Algorithm agility**: inventory records must include algorithms, profiles,
  credential slots, key generations, and certificate profiles. Devices need
  capacity for overlap during algorithm and CA migrations. [NIST crypto-agility
  guidance] describes the wider transition planning required across protocols,
  software, hardware, and infrastructure.
- **Privacy**: stable hardware and SPIFFE identities can enable tracking.
  Expose them only to the intended trust domain and keep descriptive metadata
  in access-controlled inventory rather than certificates where possible.
- **Availability**: cache current public certificates and validation bundles
  safely, renew early, and provide controlled offline recovery. Do not trade an
  enrollment outage for an unauthenticated fallback.
- **Supply chain**: constrain station and RA credentials, use short-lived
  administrative authorization and dual approval for high-impact actions, and
  make issuance and inventory logs independently reviewable.
- **Multi-environment separation**: production, staging, development, and
  customer domains need separate issuers or trust domains. Test roots and
  credentials must never be accepted in production.

## Optional attestation

Attestation is an additional authorization input, not a stronger name for
device authentication. A vendor-neutral design follows the RATS roles in [RFC
9334]:

- an Attesting Environment produces Evidence whose authenticity and freshness
  are protected from the relevant attacker;
- a Verifier validates that protection and freshness, uses applicable
  Endorsements and Reference Values, and applies an appraisal policy;
- the Verifier returns an Attestation Result; and
- the controller, as Relying Party, applies its own policy to that result.

If Kaiba adopts attestation, its evidence profile should bind an unpredictable
nonce, intended audience and operation, operational CSR or SPKI hash, and
relevant software, configuration, debug, rollback, and lifecycle claims. Any
evidence-signing key must be protected from the environment it describes.
Signing user-supplied measurements with an ordinary operational key is not
sufficient for a trustworthy attestation result.

TPM-style measured boot and DICE-style derived identities are two possible
implementations. A DICE design requires exclusive access to a device-unique
secret, measurement before execution, one-way derivation of a state-bound
  identity, and protection that prevents higher layers from recovering the UDS,
  root or parent Compound Device Identifiers (CDIs), or parent private keys.
Public parent certificates and identity chains may remain visible. Erasure,
access disabling, or continued isolation can protect the secret material. See
the [TCG DICE hardware
requirements], [TCG DICE layering architecture], and [TCG DICE attestation
architecture]. A future hardware-specific Kaiba profile must document which
claims and attacker boundaries it actually satisfies.

## Kaiba mapping and gaps

The pilot currently provides:

- TLS 1.3 mutual authentication between device and controller;
- a URI-SAN policy that maps
  `spiffe://kaiba.network/device/<three-or-more-digits>` to a canonical device
  and DNS owner;
- runtime credential paths in the NixOS module; and
- service isolation that keeps DNS publication credentials off the device.

Within the current Kaiba agent protocol, the device-side PKI secret is its
file-backed mTLS private key. Its certificate and controller CA bundle are
public, integrity-critical material. A separately hosted HTTPS application has
its own server private key and certificate lifecycle. The agent's durable
idempotency state is replay- and integrity-sensitive, but is not an
authentication secret.

The production target still requires:

- a controlled provisioning and enrollment utility;
- a protected-signer abstraction instead of requiring a PEM private-key file;
- a constrained signer broker or narrowly scoped device policy compatible with
  the agent's current `DevicePolicy=closed` and `PrivateDevices=true` sandbox;
- authoritative inventory binding plus credential-slot, key-generation, and
  certificate-instance state;
- full certificate-profile enforcement, constrained issuance, and automated
  renewal/rekey;
- immediate quarantine plus a documented CRL, status, or short-lived
  certificate policy;
- atomic credential reload and overlap activation;
- validation-bundle and CA rollover in both authentication directions;
- hardware-specific assurance profiles and negative extraction tests; and
- a verifier and appraisal policy if boot-state attestation becomes a
  requirement.

The integration PKI is intentionally a fixture: it generates private keys into
the Nix store, uses long-lived certificates, and uses one test CA for multiple
roles. None of those choices defines the production PKI topology.

## Acceptance criteria for a future implementation

A production provisioning and lifecycle implementation should demonstrate
that:

- for profiles claiming hardware binding or non-exportability, copying the
  device filesystem does not create a second accepted device; lower-assurance
  profiles explicitly do not claim that property;
- no shared or build image, log, audit record, crash artifact, station output,
  or location outside the intended device-specific protected store contains
  recoverable private-key material;
- a CSR or request cannot select another device's logical ID;
- key substitution and replayed enrollment transcripts fail;
- retrying a transaction is idempotent and a changed device or key stops it;
- a device, key generation, or certificate instance that is not active for the
  presented credential slot is rejected even when its certificate chain is
  otherwise valid;
- routine operational rekey succeeds with a bounded installation window,
  atomic authorization cutover, and no identity change;
- trust-anchor rollover succeeds without accepting an unauthorized root;
- loss of the active operational key enters the documented recovery path; and
- reset, transfer, and retirement remove the previous authorization and leave
  an auditable final state.

## References

- [NIST SP 800-57 Part 1 Rev. 5] provides general cryptographic key-management,
  cryptoperiod, protection, inventory, backup, compromise, and recovery
  guidance.
- [NISTIR 8259A] defines a core baseline of device identification,
  configuration, data protection, interface access, software update,
  and cybersecurity-state awareness.
- [NIST IR 8350] defines generic trusted network-layer device onboarding, its
  roles, mutual-authentication properties, and lifecycle considerations;
  [NIST SP 1800-36] provides implementation examples.
- [NIST SP 800-88 Rev. 2] defines risk-based media sanitization and disposal
  guidance, while [NIST crypto-agility guidance] addresses planned algorithm
  and infrastructure transitions.
- [RFC 5280] defines the Internet X.509 certificate and CRL profile and
  path-validation model. Its [RFC 5280 status page] lists updates, including
  [RFC 10007].
- [RFC 7030] defines Enrollment over Secure Transport, including initial
  enrollment, renewal, rekey, and CA certificate distribution. [RFC 7030
  updates] lists its updates and errata status.
- [RFC 8995] defines BRSKI's manufacturer-identity and voucher model for
  authorizing and pinning a registrar or domain before domain enrollment.
- [RFC 9334] defines vendor-neutral remote-attestation roles, evidence,
  endorsements, reference values, freshness, appraisal, and attestation
  results.
- The [SPIFFE X.509-SVID specification] defines the URI-SAN workload identity
  profile used as the model for Kaiba device identities, and the [SPIFFE
  trust-domain and bundle specification] describes authoritative keys and
  trust-anchor rotation within a SPIFFE trust domain.
- The [TCG DICE hardware requirements], [TCG DICE layering architecture], and
  [TCG DICE attestation architecture] describe hardware-rooted, layered device
  identity and attestation designs that do not require a TPM.

[NIST SP 800-57 Part 1 Rev. 5]: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
[NIST SP 800-57]: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
[NISTIR 8259A]: https://csrc.nist.gov/pubs/ir/8259/a/final
[NIST IR 8350]: https://csrc.nist.gov/pubs/ir/8350/final
[NIST SP 1800-36]: https://csrc.nist.gov/pubs/sp/1800/36/final
[NIST SP 800-88 Rev. 2]: https://csrc.nist.gov/pubs/sp/800/88/r2/final
[NIST crypto-agility guidance]: https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final
[RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280.html
[RFC 5280 status page]: https://www.rfc-editor.org/info/rfc5280
[RFC 10007]: https://www.rfc-editor.org/rfc/rfc10007.html
[RFC 7030]: https://www.rfc-editor.org/rfc/rfc7030.html
[RFC 7030 updates]: https://www.rfc-editor.org/info/rfc7030
[RFC 8995]: https://www.rfc-editor.org/rfc/rfc8995.html
[RFC 9334]: https://www.rfc-editor.org/rfc/rfc9334.html
[SPIFFE X.509-SVID specification]: https://spiffe.io/docs/latest/spiffe-specs/x509-svid/
[SPIFFE trust-domain and bundle specification]: https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/
[TCG DICE hardware requirements]: https://trustedcomputinggroup.org/resource/hardware-requirements-for-a-device-identifier-composition-engine/
[TCG DICE layering architecture]: https://trustedcomputinggroup.org/resource/dice-layering-architecture/
[TCG DICE attestation architecture]: https://trustedcomputinggroup.org/resource/dice-attestation-architecture/
