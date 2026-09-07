# Raspberry Pi 5 production security follow-on

## Status and scope

This document proposes the engineering path from the current sacrificial
Raspberry Pi 5 development unit to a production-oriented appliance built on the
same native Raspberry Pi secure-boot and NixOS dm-verity architecture. The
sacrificial unit is fused and boots a signed development `target` image. The
checked qualification JSON is its historical pre-fuse snapshot; the repository
still needs a reconciled public post-fuse evidence packet for the exact running
target. See the
[sacrificial-device state](raspberry-pi-5-sacrificial-state.md).

Everything after that current-state statement is proposed future work. It does
not claim that the hardware interfaces, key uses, protocol, or implementation
have passed qualification until the acceptance campaign in this document has
completed. The existing secure-boot design remains normative for the native
chain and fail-closed safety rules. The execution plan remains the normative
reconciliation and acceptance record only for the sacrificial milestone; this
document is the current production mechanism roadmap. Production enrollment
still requires an independently monotonic anti-rollback decision before
protected material becomes available.

The plan evaluates a design that deliberately does not add a TPM. It uses the
BCM2712 device-private-key OTP region and Raspberry Pi firmware cryptography for
automatic LUKS unlock, and evaluates a separately scoped device-authentication
mechanism. The target is strong verified boot, offline-storage confidentiality,
and online-gated enrollment. The design does not provide hardware-rooted
measured-boot attestation, and its anti-rollback claim depends on a fresh policy
decision enforced by the stable verifier before it starts the selected release.

The current sacrificial unit remains a development asset. Its development
customer key and every image signed by that key remain permanently authorized
by the board. It must never re-enter the fresh-board path. A production cohort
must instead start with a new production customer key and a fresh board whose
first ordinary customer-signed image is the stable verifier defined below.

That permanent development authorization limits what the sacrificial unit can
prove about the future design. Older development-key-signed images can bypass a
new stable verifier and may predate the firmware-key locks required below. The
board is therefore suitable for disposable functional testing of verifier,
update, HMAC, LUKS, and enrollment mechanics, but it cannot establish that the
stable verifier is the only route to protected state or firmware-key use. Do
not place confidentiality-sensitive data or reusable identity material behind a
device-private key programmed on this board. The non-bypassability,
confidentiality, and bootstrap-isolation claims require a fresh canary whose Pi
customer root authorizes only the stable verifier, narrow recovery, and signed
EEPROM paths.

This plan assumes that loss of a board or its storage may destroy local data.
There is no offline escrowed LUKS recovery key. Persistent application state
must therefore be reconstructable from an authoritative service or explicitly
classified as disposable.

## Intended outcome

The production boot and service path is:

```text
immutable BCM2712 Boot ROM
  -> production-customer-signed EEPROM bootloader
  -> stable production-customer-signed boot verifier
  -> rotatable release-policy and release-signing keys
  -> fresh server policy bound to verifier version, release digest, and epoch
  -> verifier-enforced release authorization before protected material
  -> signed kernel, initramfs, DTB, command line, and release manifest
  -> read-only dm-verity NixOS system root
  -> OTP-HMAC-derived unlock of LUKS mutable state
  -> separately scoped device authentication
  -> enrollment and restricted production networking
```

The completed acceptance campaign must demonstrate:

- native Raspberry Pi secure boot rooted in an OTP customer-key hash;
- a signed and hardened EEPROM configuration;
- a stable first-stage verifier that accepts only currently authorized,
  delegated signed releases;
- release-key rotation and revocation without changing the Pi OTP customer key,
  subject to the online verifier gate described below;
- authenticated kernel, initramfs, device tree, command line, and root hash;
- a read-only dm-verity system root;
- an encrypted mutable-state volume automatically unlocked from a per-device
  OTP secret without exporting that secret through the normal unlock path;
- destructive replacement-drive initialization with a new storage generation;
- A/B signed system updates with power-loss recovery;
- a qualified device-authentication mechanism and short-lived operational
  certificates;
- server-authored release freshness enforced by the stable verifier before
  LUKS state, operational credentials, or protected services become available;
- a narrowly capable customer-signed recovery path; and
- production boot-order, UART, JTAG, EEPROM-update, and write-protection
  settings.

## Security boundary without a TPM

After the complete hardware campaign passes, the design may claim:

- Altered, unsigned, and wrong-key EEPROM or boot images do not execute.
- Altered release components do not execute after the stable verifier.
- Persistent NixOS system bytes are authenticated by dm-verity.
- Removed storage does not disclose LUKS-protected mutable data.
- A copied volume does not automatically unlock on a different Pi. Binding to a
  different storage device is claimed only if the storage identifier described
  below passes authenticity and spoof-resistance qualification.
- Obsolete and revoked releases cannot reach protected mutable state or obtain
  current service authorization while the required online verifier gate is
  available and enforced.
- Raw OTP-key export and unused firmware HMAC operations are locked during
  normal boot.

Even after acceptance, the design does not claim:

- strong offline OS anti-rollback;
- independent hardware measurement of the running Pi software;
- TPM-style quotes or PCR-bound key release;
- protection after an authorized kernel is compromised;
- recovery of unreplicated local data after board or storage failure;
- in-place replacement of the Pi customer key; or
- resistance to invasive extraction, fault injection, or side-channel attacks.

An offline device cannot make the required fresh anti-rollback decision. It
must remain in a restricted recovery/update state without opening protected
mutable storage or starting protected functions. A product requirement for
indefinite protected offline operation would need a TPM, a secure element with
monotonic state, or another separately qualified hardware counter.

An old image correctly signed by the production Pi customer key remains
acceptable to native Pi secure boot. The production customer key must therefore
sign only the stable verifier, signed EEPROM updates, and narrow recovery
payloads. It must not become the routine OS release-signing key.

## Key hierarchy

Production uses distinct signing roles:

```text
Pi customer root key
  -> signed EEPROM, stable verifier, and narrow recovery only

Release-policy root keys
  -> signed delegation and revocation metadata

Delegated release keys
  -> signed release manifests and boot bundles

Per-device BCM2712 OTP key
  -> firmware HMAC for LUKS unlock

Separate device-authentication role
  -> separate hardware key, or a strongly domain-separated child key
  -> short-lived operational keys and certificates
```

Directly using the same OTP key for both firmware HMAC and firmware ECDSA is an
unresolved research option, not the production default. It is permitted only if
the vendor's intended use, key lifetime, lock behavior, and cross-protocol risk
pass focused cryptographic and hardware review and the one-key/one-purpose
policy is explicitly reconciled. Otherwise the implementation must use a
separate hardware slot or a strongly domain-separated derived child key and
record the resulting assurance level.

The Pi customer private key and release-policy private keys must remain outside
Git, the Nix store, CI runners, target images, and provisioning-station images.
Production signing uses an HSM interface. Public keys, grants, receipts,
manifests, and signature outputs remain reproducible and independently
verifiable.

The release-policy metadata must bind at least:

- key role and key identifier;
- delegation threshold;
- allowed device cohort;
- release security epoch;
- minimum verifier version;
- kernel, initramfs, DTB, overlay, configuration, and command-line digests;
- dm-verity root hash and partition identifiers;
- update and recovery classification; and
- source revision and reproducible artifact inventory.

## Storage architecture

The immutable system and mutable data have separate protection mechanisms:

```text
boot/verifier
  customer-key-signed stable verifier

release slot A
  delegated-signed kernel/initramfs/configuration
  dm-verity root-data A
  dm-verity root-hash A

release slot B
  delegated-signed kernel/initramfs/configuration
  dm-verity root-data B
  dm-verity root-hash B

mutable state
  LUKS2 kaiba-state volume
```

The NixOS system root remains public but tamper evident. LUKS is reserved for
device identity state, issued certificates, application data, and other
mutable material that requires confidentiality. Temporary files, journals,
core dumps, and caches remain volatile unless a documented application need
requires persistence.

### LUKS unlock derivation

The device does not read the raw OTP key during normal unlock. It requests an
HMAC-SHA-256 operation from Raspberry Pi firmware:

```text
unlock_secret = HMAC-SHA-256(
  K_OTP,
  canonical_encode(
    "kaiba:luks:mutable-state:v1",
    storage_innate_id,
    volume_nonce,
    storage_generation
  )
)
```

The HMAC input must use an unambiguous canonical encoding rather than direct
string concatenation. `volume_nonce` is a newly generated public 256-bit value
stored with the LUKS metadata. It changes on every destructive initialization,
including reformatting the same physical drive. `storage_generation` is a
monotonically increasing control-plane record, but is not a hardware monotonic
value.

For every normal unlock, the control plane must authorize the complete active
storage-instance tuple before the firmware HMAC is requested. At minimum that
tuple contains the logical device instance, `storage_generation`,
`volume_nonce`, LUKS UUID, and a canonical digest of the expected LUKS header or
other authenticated storage descriptor. The server compares it with the active
inventory generation and includes the same values in its fresh signed response.
A current release authorization for one storage instance must never be reusable
with an older nonce, generation, header, or volume. Locally stored metadata is
attacker-controlled input until it matches that fresh server authorization.

Destructive initialization is the only exception: its header digest does not
exist before `luksFormat`. It therefore uses the two-phase, one-shot pending
protocol below. A pending tuple is never valid normal-unlock authorization and
cannot become active until its formatted header and release bytes have been
read back and bound into the server record.

`storage_innate_id` is a qualification placeholder, not an authenticated media
identity. NVMe model, serial, WWID, and `/dev/disk/by-id` values are normally
spoofable operational identifiers and must not silently become trust inputs.
Before implementation, the storage workstream must name the exact identifier
source, supported devices, read API, spoofability assumptions, and failure
behavior. If no qualifying source exists, omit this field from the derivation
and limit the security claim to board binding plus destructive reinitialization.

The HMAC result is a high-entropy LUKS keyslot passphrase. It is not the LUKS
volume master key. `cryptsetup luksFormat` generates a new random volume master
key for every initialization.

The customer-root-signed verifier environment must own the complete pre-handoff
sequence. If the selected design uses Linux, this means a minimal verifier
initramfs that is part of the stable verifier—not the delegated release's
initramfs. If U-Boot cannot carry the authorization and protected-state
continuation safely, it must hand off to such a root-signed verifier initramfs
or be rejected.

That verifier environment must:

1. obtain and verify a fresh, signed control-plane authorization bound to the
   exact verifier version, release digest, security epoch, logical device
   instance, storage generation, volume nonce, LUKS UUID, and authenticated
   storage-descriptor digest;
2. reject an unauthorized or offline boot before starting the release or
   requesting a storage derivation;
3. verify the complete boot and dm-verity policy;
4. resolve exactly one expected block device and, if qualified, its canonical
   storage identifier;
5. obtain the volume nonce, generation, UUID, and descriptor digest from bounded
   metadata and require an exact match with the fresh authorization;
6. request the firmware HMAC operation;
7. deliver the result to cryptsetup through a private pipe or socket, never
   argv, environment, disk, or logs;
8. clear temporary buffers after the volume opens;
9. lock further HMAC operations for the remainder of the boot;
10. hand the delegated OS only the already-open mapping and scoped ephemeral
    credential, with no firmware crypto device or API; and
11. mount only explicitly permitted mutable paths.

Every production signed boot image must set `lock_device_private_key=1` so the
firmware disables raw private-key export before userspace starts. HMAC use is
left available only long enough to open the approved volume and is then
separately locked.

### No-escrow replacement behavior

Loss of the board, OTP key, LUKS header, or storage can make local data
permanently unrecoverable. The supported recovery operation is destructive
replacement, not data recovery:

1. Boot an approved customer-signed recovery environment.
2. Verify the board's owned state and exact recovery authorization.
3. Identify the replacement storage and ensure the old volume is not mounted.
4. Allocate a new volume nonce, preselected LUKS UUID, storage generation, and
   logical device-instance identifier.
5. Create a server-side `pending` storage-instance record that cannot authorize
   a normal unlock.
6. Obtain a fresh, one-shot initialization authorization bound to the device,
   recovery digest, destructive action, request digest, pending generation,
   nonce, UUID, and every target-storage fact that can be established before
   formatting. The absent header digest is explicit, not a wildcard.
7. Request the firmware HMAC and pass it privately to `cryptsetup luksFormat`,
   forcing the authorized UUID.
8. Cold-read and validate the new header, record its canonical descriptor
   digest, install and cold-read the currently approved signed release, and
   move the pending record through `formatted` and `verified`.
9. Submit the exact descriptor and release bindings. The server atomically
   activates the new device/storage generation and retires the old tuple; it
   never accepts both generations.
10. Revoke the previous instance's certificates and service credentials.
11. Re-enroll the same hardware as the newly activated logical device instance.

The initialization request is idempotent only before its destructive action is
consumed. After an ambiguous format result, recovery may inspect the expected
UUID and header and continue the exact completion if they validate; it must not
format the tuple again. If no valid formatted state can be established, retire
that pending record and allocate a new generation and nonce under a new
authorization. Power loss at any pre-activation point leaves normal protected
boot locked.

The hardware identity and OTP HMAC key do not change. The storage and logical
device generations do.

Changing the volume nonce does not revoke an old derivation. If an old drive
and its metadata later reappear on the original Pi, the firmware HMAC can still
derive the old passphrase. The stable verifier must prevent that derivation by
requiring a fresh server authorization for the exact active storage-instance
tuple before calling HMAC. The server must reject every retired generation and
mixed tuple, not merely its old certificates. Without the online decision or an
independent hardware monotonic counter, local cryptographic rejection of every
old volume is not claimed.

### Customer-root recovery permanence

A recovery payload signed directly by the Pi customer root is as permanent as
an old stable verifier: native secure boot cannot revoke it. Production should
therefore root-sign one minimal, stable recovery verifier or dispatcher and put
changeable recovery behavior behind delegated signatures. Every root-signed
recovery digest remains in a complete cohort inventory and is treated as
permanently bootable.

Recovery receives a fresh, one-shot server action authorization bound to the
device, active storage tuple, requested operation, recovery digest, expiry, and
challenge transcript. It may inspect owned state, install an approved signed
release, or destructively initialize a replacement volume. It must not open an
existing LUKS volume, expose the firmware crypto API to a shell or delegated
payload, or bypass the stable verifier's freshness policy. Offline recovery may
repair only public boot state and must not release protected state.

If a cohort ever root-signs an overbroad or vulnerable recovery payload, its
capabilities are a non-revocable residual risk for every board in that cohort.
The canary campaign must replay every historical root-signed recovery image and
prove its exact bounded behavior; signer policy makes new recovery-root signing
an exceptional, independently approved operation.

## Stable verifier and delegated boot

The first engineering milestone must exercise a stable verifier on the
sacrificial board and later prove it on a fresh canary. Two bounded
implementations are acceptable for the spike:

- a minimal customer-key-signed Linux/initramfs verifier that validates a
  complete release manifest and securely loads verified second-stage bytes; or
- a customer-key-signed U-Boot verified-boot image with required public keys in
  its trusted control DTB and required signatures on selected FIT
  configurations.

The selected implementation must have one non-interactive boot path and no
unsigned fallback. It must authenticate every byte that influences the
second-stage kernel, initramfs, DTB, overlays, command line, and dm-verity root
selection.

It must also retain control through the online authorization, storage-tuple
validation, HMAC request, LUKS open, bootstrap/HMAC locks, and ephemeral-
credential handoff. A design that exposes the firmware crypto interface to the
delegated OS or hands off before those locks are applied fails the spike.

The development spike passes its functional checks only if:

- the approved release boots;
- an altered manifest fails;
- each independently altered boot component fails;
- a missing signature fails;
- a wrong-key signature fails;
- an unreferenced or legacy image format cannot bypass verification;
- a revoked delegated key fails under newer policy metadata; and
- an accepted replacement delegated key boots without reprogramming Pi OTP.

After selection, the verifier implementation, configuration, embedded policy
roots, and boot script become one reviewed artifact signed by the Pi customer
root key.

On the sacrificial board, these checks demonstrate the selected verifier path;
they do not prove that older development-key-signed images cannot bypass it.
That negative security property is a production-canary acceptance gate.

## Release freshness without a TPM

Every release carries a signed integer `security_epoch`. The control plane holds
the independently monotonic minimum accepted verifier version and release epoch
for each cohort and device instance.

At each production boot, the stable verifier must use only the restricted
enrollment/update network to obtain a fresh, signed authorization. The request
and response bind a server nonce, device instance, verifier version, complete
release-manifest digest, security epoch, active storage generation, volume
nonce, LUKS UUID, authenticated storage-descriptor digest, expiry, and a
one-boot operational public key. The verifier checks that response and refuses
to start the selected release or request the LUKS derivation unless every bound
value matches. The server refuses authorization below either minimum or for a
retired, unknown, or mixed storage tuple.

### Freshness transcript, endpoint trust, and time

The verifier must authenticate the policy endpoint without depending on an
attacker-controlled local clock or mutable DNS. Its immutable configuration
must pin the policy authority, protocol, endpoint identity, and trust root or
raw public key. The bootstrap transport and signed policy envelope must have a
documented certificate/time-validation strategy; disabling certificate time
checks is not acceptable. A signed server-time envelope or a separately
qualified secure time source may establish time, but only after it is
authenticated by the pinned policy authority.

Each boot requires qualified early entropy. The verifier creates a fresh boot
nonce and one-boot operational key, obtains a single-use server challenge, and
returns a bootstrap proof of possession over the challenge, boot nonce,
one-boot SPKI, verifier/release/epoch values, and complete device/storage tuple.
The authorization response binds the request digest, both nonces, policy
sequence, issue time, expiry, and all requested values. The server consumes the
challenge once and returns the same result only for an idempotent replay of the
exact request. A changed field, changed key, reused challenge with another
request, response from an earlier boot, or response outside its bounded
monotonic-in-boot lifetime fails closed.

The protocol must qualify the early random source and monotonic timer, bound
the maximum authorization lifetime independently of wall-clock rollback, and
define server replay retention. If endpoint authentication, entropy, signed
time, or replay state is unavailable, the verifier remains in restricted
update/recovery mode and does not request HMAC or release protected state.

A released OS reporting its own version or signing its own state is not remote
attestation and is not sufficient for this decision. The control instead
depends on the customer-signed stable verifier being the only component able to
use the qualified bootstrap identity before its operation is locked, enforcing
the server-authored policy locally, and passing only the authorized one-boot
credential to the selected release. Hardware qualification must prove that a
released OS cannot invoke that bootstrap operation, forge or replay an
authorization for another digest, or obtain a LUKS derivation after a rejected
decision. If those properties cannot be enforced, this no-TPM design cannot
reach `enrollment_ready`.

Short-lived operational certificates and leases limit use after authorization
expires. Local storage may record the highest observed epoch as defense in
depth, but storage rollback can also roll back that record and therefore is not
an independent security boundary.

The BCM2712 private firmware-version mechanism should be separately qualified
and used for EEPROM rollback protection if it meets the production policy. Its
small version space applies to bootloader firmware and does not replace OS
release anti-rollback.

The server-side policy is the independent monotonic state in this design, so
protected boot is fail-closed when it is unavailable. Products that must perform
protected functions indefinitely while offline cannot satisfy strong
anti-rollback with this design. Such a requirement would require a TPM, secure
element with monotonic state, or another qualified hardware counter.

## Device identity and enrollment

The preferred no-TPM result uses a bootstrap identity separate from the LUKS
unlock key role: either a separate hardware key or a strongly domain-separated
child key whose public half is bound during provisioning. Direct firmware ECDSA
with the BCM2712 device-private OTP key remains a conditional research option
under the key-policy gate above, not an assumed capability.

An exportable software identity generated inside LUKS can serve as a lower
assurance operational identity after unlock. It cannot satisfy the verifier's
pre-unlock bootstrap requirement and provides only at-rest key protection.

### One-boot operational credential lifecycle

The one-boot key is an ephemeral operational generation, not the long-lived
bootstrap identity. The verifier generates it from qualified early entropy and
binds its SPKI into the bootstrap proof, freshness request, device and storage
tuple, verifier and release digests, security epoch, and both nonces. The
control plane records a boot-session identifier and moves that exact key through
`pending`, `staged`, `verified`, and short-lived `active` states before
production services accept it.

Issuance is idempotent for the exact request digest: a retry returns the same
certificate and serial, while a changed nonce or SPKI creates a new session and
cannot reuse the old authorization. Activating a newer boot session denies the
prior session except for an explicitly bounded overlap required by a protocol;
ordinary reboot has no overlap. Expiry, revocation, failed handoff, or loss of
the ephemeral private key requires a new boot and key. The verifier and release
zeroize obsolete copies on handoff failure and shutdown as far as the platform
allows, and the audit/inventory record retains only public key, certificate,
session, authorization, and disposition data.

The delegated OS receives only the scoped ephemeral signer or key material
needed for that boot. This design limits duration and replay; it does not claim
to protect the session private key after an authorized delegated kernel is
compromised.

Enrollment must:

1. bind the qualified bootstrap public key to the provisioning transaction and
   hardware inventory;
2. require a fresh server nonce and a domain-separated signature;
3. bind the logical device-instance and storage generation;
4. require the stable-verifier authorization for the exact verifier, release
   digest, and security epoch;
5. issue a short-lived client certificate;
6. store public certificate state and application credentials in LUKS; and
7. support revocation, renewal, replacement-drive re-enrollment, retirement,
   and board replacement.

This proves control of the provisioned device key and, after qualification,
that the stable verifier enforced one fresh authorization before handoff. It is
not hardware-rooted proof of the complete running software state because
Raspberry Pi firmware does not extend the boot chain into TPM PCRs and the
platform has no equivalent quote mechanism.

## A/B release updates

Ordinary updates never replace the stable verifier. They write the inactive
delegated release slot:

1. Download the signed manifest and artifacts into a staging area.
2. Verify release policy, key status, epoch, sizes, and hashes.
3. Write the inactive kernel/initramfs bundle and dm-verity pair.
4. Cold-read and verify every written byte.
5. Select the inactive slot for one trial boot.
6. Require verifier success, dm-verity success, application health, and server
   epoch acceptance.
7. Commit the slot only after every check passes.
8. Fall back to the previous valid slot after an incomplete write, power loss,
   or unsuccessful trial.

Raspberry Pi `tryboot` or an equivalently bounded verifier slot-selection
mechanism may provide the one-shot availability transition. It does not provide
security anti-rollback.

The update metadata must not permit an attacker to select an unsigned image,
change a root hash, introduce a legacy boot path, or turn a data rollback into
an accepted control-plane generation.

A verifier security update is exceptional, not an ordinary A/B release. It
requires the Pi customer root's offline approval and signing ceremony, an owned
recovery path, complete regression and negative testing, and a control-plane
minimum-verifier-version transition. Because old customer-signed verifiers
remain bootable by the native Pi chain, that server minimum is an online gate,
not offline verifier rollback protection. A vulnerability that lets an old
verifier misrepresent or bypass the protocol is therefore an explicit residual
risk and production decision.

## Network and service gating

Normal application networking is disabled until the stable verifier has
enforced a fresh release authorization and enrollment checks succeed.

The pre-enrollment verifier or recovery environment permits only what is
required to reach fixed enrollment, update, time, and revocation authorities.
It has no inbound SSH, general administrative login, or unrestricted egress.
Its trust roots and endpoint policy are authenticated by the customer-signed
stable verifier.

Application services depend on a local `kaiba-enrollment-ready.target` that is
reached only after:

- secure-boot runtime state matches policy;
- the expected verifier and release digest are active;
- the verifier-enforced, one-boot release authorization is current;
- dm-verity is mounted read-only;
- LUKS mutable state is open;
- device authentication succeeds;
- the release epoch is accepted by the server; and
- the current certificate and service lease are valid.

Failure before release handoff leaves the device in the restricted verifier
update/recovery path without opening LUKS. Expiry, revocation, or a later lease
failure stops protected services and returns the device to a restricted state.

## Production hardware posture

The final production EEPROM and OTP posture is applied only after update and
owned-recovery tests pass. It must include:

- a reviewed production `BOOT_ORDER` containing only required sources;
- network/TFTP and partition-walk fallback disabled unless explicitly part of
  the product recovery design;
- `BOOT_UART=0`;
- automatic EEPROM self-update disabled or constrained by an approved signed
  update policy;
- VideoCore JTAG permanently locked;
- EEPROM hardware write protection enabled and physically qualified;
- raw device-private-key export locked before userspace;
- the bootstrap signing operation locked before release handoff and HMAC locked
  immediately after the approved derivations; and
- a prebuilt, independently verified, customer-signed owned recovery bundle.

Recovery must be narrow. It may verify state, install an approved signed
release, initialize replacement storage, and re-enter enrollment. It must not
contain a generic shell, signing authority, private fleet key, unrestricted
storage browser, or arbitrary OTP/EEPROM mutation primitive.

## Engineering workstreams

### Workstream 1: production policy and keys

- [ ] Add the production posture and lifecycle schemas.
- [ ] Define the production cohort and generate its Pi customer key in an HSM.
- [ ] Establish split-custody backup and key-loss/compromise procedures.
- [ ] Define release-policy root and delegated release roles.
- [ ] Extend signing grants, receipts, and independent verification for those
      roles.
- [ ] Prove private keys cannot enter the repository, Nix store, CI, station,
      or target closures.

### Workstream 2: stable verifier

- [ ] Build and test the Linux-verifier and U-Boot/FIT spike on the sacrificial
      Pi.
- [ ] Select one implementation and remove every alternative boot path.
- [ ] Implement delegated policy, revocation, and release verification.
- [ ] Bind kernel, initramfs, DTB, overlays, command line, root hash, and epoch.
- [ ] Implement the fresh server-policy exchange before release handoff.
- [ ] Keep policy, storage validation, HMAC/LUKS, and per-boot lock operations
      inside the customer-root-signed verifier environment; deny the delegated
      OS the firmware crypto interface.
- [ ] Bind a one-boot operational key using a replaceable test bootstrap provider;
      defer hardware-key and lock claims to Workstream 5.
- [ ] Add mutate-every-field and wrong-key tests.
- [ ] Produce a root-signing request and independently verified signed result.

### Workstream 3: OTP-HMAC and LUKS

- [ ] Pin or vendor the Raspberry Pi firmware crypto and cryptsetup-agent
      implementation used by the target.
- [ ] Add an irreversible, transaction-bound device-private-key provisioning
      operation with device-private-key blank-prestate and post-write checks.
- [ ] On the already-owned sacrificial board, perform that operation only
      through a narrowly capable development-customer-key-signed owned-recovery
      transaction bound to the current customer-key hash, EEPROM hash, target,
      station journal, and approval; never use the stock pre-fuse probe.
- [ ] For the sacrificial board, classify any programmed device-private key and
      encrypted data as disposable test material and prevent reuse of its
      derived secrets or credentials outside the development campaign.
- [ ] Add `lock_device_private_key=1` to the signed boot configuration.
- [ ] Define and test the canonical HMAC derivation contract.
- [ ] Qualify the exact storage identifier source or remove it from the
      derivation and narrow the binding claim.
- [ ] Add the LUKS2 mutable-state partition and mount policy.
- [ ] Lock HMAC after unlock and verify raw export remains unavailable.
- [ ] Implement destructive replacement-drive initialization.
- [ ] Implement and test the `pending` → `formatted` → `verified` → `active`
      initialization protocol, including ambiguous-format inspection,
      abandonment under a new nonce/generation, and atomic retirement of the
      previous tuple.
- [ ] Document and test the no-escrow data-loss behavior.

### Workstream 4: signed A/B releases

- [ ] Define the A/B disk layout and deterministic image builder.
- [ ] Add delegated-signed release manifests and bundles.
- [ ] Implement inactive-slot writing and cold-readback verification.
- [ ] Implement trial boot, health confirmation, commit, and fallback.
- [ ] Test interruption at every persistent update transition.
- [ ] Ensure ordinary updates cannot replace the stable verifier.

### Workstream 5: identity and control-plane freshness

- [ ] Resolve the separate-key or strongly domain-separated child-key design;
      treat direct HMAC/ECDSA dual use as blocked until explicitly approved.
- [ ] Bind the qualified bootstrap public identity to provisioning evidence and
      inventory.
- [ ] Implement canonical nonce challenge signing.
- [ ] Lock the qualified bootstrap operation before release handoff.
- [ ] Prove that released OS code cannot use the bootstrap operation after
      verifier handoff.
- [ ] Add logical device-instance and storage-generation records.
- [ ] Bind the active storage generation, volume nonce, LUKS UUID, and
      authenticated descriptor digest into each fresh authorization; reject
      retired and mix-and-match tuples before HMAC.
- [ ] Implement certificate issuance, renewal, revocation, and retirement.
- [ ] Add signed release epochs and cohort/device minimum-epoch policy.
- [ ] Restrict pre-enrollment networking and gate operational services.
- [ ] Prove old epochs cannot obtain new credentials or leases.

### Workstream 6: hardening and recovery

- [ ] Remove SSH, autologin, unused accounts, compilers, package managers, and
      unnecessary firmware interfaces from the target.
- [ ] Disable unrestricted kexec, module loading, debugfs, core dumps, swap,
      and unnecessary kernel features.
- [ ] Apply service capability, namespace, filesystem, syscall, and device
      restrictions.
- [ ] Finalize boot order, partition walk, UART, JTAG, self-update, and EEPROM
      write-protection settings.
- [ ] Build and verify the narrow production owned-recovery bundle.
- [ ] Inventory and test every customer-root-signed recovery digest, require
      one-shot online action authorization, and prove recovery cannot open an
      existing LUKS volume or expose firmware crypto operations.
- [ ] Test recovery before applying irreversible finalization settings.

### Workstream 7: release and operations

- [ ] Make every unsigned artifact reproducible from pinned sources.
- [ ] Require independent signature and release-lineage verification.
- [ ] Publish exact image, checksum, manifest, SBOM, and provenance artifacts.
- [ ] Add canary, staged rollout, incident, revocation, and retirement
      procedures.
- [ ] Monitor enrollment failures, rollback attempts, update failures, and
      unexpected recovery use.
- [ ] Prove destructive re-enrollment leaves the previous instance retired.

## Development campaign and production acceptance

The sacrificial unit will first exercise the complete design with
development-only, disposable secrets. Its campaign covers functional behavior:

- approved delegated release boots through the stable verifier;
- altered, unsigned, wrong-key, and revoked release bundles fail behind the
  selected verifier path;
- each boot source selected by that verifier exercises the same delegated
  verification policy;
- dm-verity corruption prevents the system root from mounting;
- removed storage does not disclose LUKS data;
- copied storage fails on another Pi; failure on a different medium is required
  only if the storage identifier passes the stated qualification gate;
- raw OTP-key export and HMAC lock behavior are observed on the selected test
  path, without claiming that older development-signed images cannot bypass
  that path;
- the selected verifier path prevents its delegated release from using the
  bootstrap operation after handoff, without claiming board-wide isolation;
- replacement storage creates a new nonce, LUKS key, generation, and logical
  device instance;
- interruption at every initialization phase either resumes exact verified
  completion or abandons the pending tuple without enabling normal unlock;
- old instance certificates and leases are rejected;
- an old, retired, or mix-and-match storage tuple remains locked even when the
  board and selected software release are otherwise current;
- an old delegated release epoch is rejected by the selected stable verifier
  before LUKS unlock and cannot obtain protected network service;
- a historical development-customer-root-signed direct image is expected to
  bypass the new verifier on this board, and that limitation is recorded rather
  than misreported as a passing negative test;
- A/B updates recover from power loss at every write and commit boundary;
- signed owned recovery works and unauthorized recovery fails;
- final boot order, UART, JTAG, EEPROM update, and write-protection state reads
  back exactly; and
- no image or evidence export contains a signing key, OTP secret, derived LUKS
  passphrase, or active device credential.

After the sacrificial functional campaign passes, provision one fresh
production canary with the new production Pi customer key. Repeat the complete
acceptance suite on that canary and additionally prove that no customer-root-
signed legacy or general-purpose image is authorized, raw OTP-key export is
locked before userspace, HMAC is unavailable after approved unlock, and a
released OS cannot use the bootstrap operation. Every enabled physical boot
source must enter the same stable-verifier or narrow-recovery policy. Only the
fresh canary can close the confidentiality, verifier-non-bypass, and bootstrap-
isolation claims before the cohort expands.

## Milestones

### Milestone 1: stable-verifier development spike

This milestone is complete when the fused sacrificial development unit
demonstrates that a development-key-signed stable verifier boots an authorized
delegated release, rejects mutated inputs on that path, obtains and enforces
fresh server policy before release handoff, and binds a one-boot operational key
using an explicitly non-production test bootstrap identity. Because older
development-signed images remain authorized, this milestone does not prove
verifier non-bypassability, firmware-backed identity, confidentiality, or
hardware lock.

### Milestone 2: encrypted and updateable development appliance

This milestone is complete after the existing owned state is reconciled, a
separate irreversible device-private-key operation is reviewed and approved,
and the sacrificial Pi provisions a disposable test OTP key, exercises LUKS
unlock through firmware HMAC after verifier authorization, observes derivation-
interface locking on the selected path, and destructively initializes a
replacement drive. It also exercises the candidate bootstrap-key design.
Delegated-signed A/B releases exercise revocation, authenticate the complete
kernel-to-root path, and safely handle interrupted updates. Security claims
about lock enforcement, confidentiality, and bypass resistance remain deferred
to the fresh production canary.

### Milestone 3: enrolled appliance

This milestone is complete when the development device authenticates with a
disposable test bootstrap identity, receives a short-lived test certificate
bound to a one-boot operational key, and exercises protected-service gating
after verifier-enforced server authorization. Production identity acceptance
remains part of the fresh-canary milestone.

### Milestone 4: hardened production canary

This milestone is complete when a fresh board uses the production customer key,
final debug and EEPROM posture, narrow recovery, HSM signing, and the complete
production acceptance suite.

### Milestone 5: production release

This milestone is complete when the release pipeline publishes reproducible,
independently verified images and evidence and operations can update, revoke,
destructively re-enroll, quarantine, and retire devices without weakening the
trust chain.

## References

The external links below are non-normative discovery inputs. Before they become
engineering dependencies, pin exact reviewed commits or tags and record the
review date. The referenced NixOS integration is an unmerged pull request, not
an accepted platform contract.

- [Raspberry Pi 5 secure-boot design](raspberry-pi-5-secure-boot.md)
- [Raspberry Pi 5 secure-boot execution plan](raspberry-pi-5-secure-boot-execution-plan.md)
- [Development secure-boot station](raspberry-pi-5-development-secure-boot-station.md)
- [Raspberry Pi secure-boot documentation](https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md)
- [Raspberry Pi firmware cryptography API](https://github.com/raspberrypi/utils/blob/master/rpifwcrypto/rpifwcrypto.h)
- [Raspberry Pi cryptsetup passphrase agent](https://github.com/raspberrypi/cryptsetup-passphrase-agent)
- [NixOS Raspberry Pi OTP-derived key integration PR](https://github.com/nvmd/nixos-raspberrypi/pull/179)
- [Linux dm-verity documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [U-Boot FIT signature verification](https://docs.u-boot.org/en/latest/usage/fit/signature.html)
