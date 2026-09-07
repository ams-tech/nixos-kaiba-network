# Raspberry Pi 5 production security follow-on

## Status and scope

This document proposes the engineering path from the current sacrificial
Raspberry Pi 5 development candidate to a production-oriented appliance built
on the same native Raspberry Pi secure-boot and NixOS dm-verity architecture.
The repository currently records a hardware-qualified read-only probe, not a
completed irreversible secure-boot ceremony or a booting owned device.

Everything after that current-state statement is proposed future work. It does
not claim that the hardware interfaces, key uses, protocol, or implementation
have passed qualification until the acceptance campaign in this document has
completed. The existing secure-boot design and execution plan remain normative;
in particular, production enrollment still requires an independently monotonic
anti-rollback decision before protected material becomes available.

The plan evaluates a design that deliberately does not add a TPM. It uses the
BCM2712 device-private-key OTP region and Raspberry Pi firmware cryptography for
automatic LUKS unlock, and evaluates a separately scoped device-authentication
mechanism. The target is strong verified boot, offline-storage confidentiality,
and online-gated enrollment. The design does not provide hardware-rooted
measured-boot attestation, and its anti-rollback claim depends on a fresh policy
decision enforced by the stable verifier before it starts the selected release.

The current sacrificial unit remains a development asset. If its irreversible
development ceremony is eventually approved and completed, its development
customer key and every image signed by that key will remain permanently
authorized by the board. A production cohort must instead start with a new
production customer key and a fresh board whose first ordinary
customer-signed image is the stable verifier defined below.

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

The initramfs must:

1. obtain and verify a fresh, signed control-plane authorization bound to the
   exact verifier version, release digest, and security epoch;
2. reject an unauthorized or offline boot before starting the release or
   requesting a storage derivation;
3. verify the complete boot and dm-verity policy;
4. resolve exactly one expected block device and, if qualified, its canonical
   storage identifier;
5. obtain the volume nonce and generation from bounded metadata;
6. request the firmware HMAC operation;
7. deliver the result to cryptsetup through a private pipe or socket, never
   argv, environment, disk, or logs;
8. clear temporary buffers after the volume opens;
9. lock further HMAC operations for the remainder of the boot; and
10. mount only explicitly permitted mutable paths.

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
4. Allocate a new volume nonce, LUKS UUID, storage generation, and logical
   device-instance identifier.
5. Derive a new unlock secret and format a new LUKS2 volume.
6. Install the currently approved signed release.
7. Revoke the previous instance's certificates and service credentials.
8. Re-enroll the same hardware as a new logical device instance.

The hardware identity and OTP HMAC key do not change. The storage and logical
device generations do.

Changing the volume nonce does not revoke an old derivation. If an old drive
and its metadata later reappear on the original Pi, the firmware HMAC can
derive the old passphrase again. The production control plane must therefore
retire the old device instance and reject its certificates and generation.
Without an independent hardware monotonic counter, local cryptographic
rejection of every old volume is not claimed.

## Stable verifier and delegated boot

The first engineering milestone must prove a stable verifier on the
sacrificial board. Two bounded implementations are acceptable for the spike:

- a minimal customer-key-signed Linux/initramfs verifier that validates a
  complete release manifest and securely loads verified second-stage bytes; or
- a customer-key-signed U-Boot verified-boot image with required public keys in
  its trusted control DTB and required signatures on selected FIT
  configurations.

The selected implementation must have one non-interactive boot path and no
unsigned fallback. It must authenticate every byte that influences the
second-stage kernel, initramfs, DTB, overlays, command line, and dm-verity root
selection.

The hardware spike passes only if:

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

## Release freshness without a TPM

Every release carries a signed integer `security_epoch`. The control plane holds
the independently monotonic minimum accepted verifier version and release epoch
for each cohort and device instance.

At each production boot, the stable verifier must use only the restricted
enrollment/update network to obtain a fresh, signed authorization. The request
and response bind a server nonce, device instance, verifier version, complete
release-manifest digest, security epoch, expiry, and a one-boot operational
public key. The verifier checks that response and refuses to start the selected
release or request the LUKS derivation unless every bound value matches. The
server refuses authorization below either minimum.

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
- [ ] Bind a one-boot operational key using a replaceable test bootstrap provider;
      defer hardware-key and lock claims to Workstream 5.
- [ ] Add mutate-every-field and wrong-key tests.
- [ ] Produce a root-signing request and independently verified signed result.

### Workstream 3: OTP-HMAC and LUKS

- [ ] Pin or vendor the Raspberry Pi firmware crypto and cryptsetup-agent
      implementation used by the target.
- [ ] Add an irreversible, transaction-bound device-private-key provisioning
      operation with blank-prestate and post-write checks.
- [ ] Add `lock_device_private_key=1` to the signed boot configuration.
- [ ] Define and test the canonical HMAC derivation contract.
- [ ] Qualify the exact storage identifier source or remove it from the
      derivation and narrow the binding claim.
- [ ] Add the LUKS2 mutable-state partition and mount policy.
- [ ] Lock HMAC after unlock and verify raw export remains unavailable.
- [ ] Implement destructive replacement-drive initialization.
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

## Hardware acceptance campaign

The sacrificial unit must pass the complete design before a production key is
used:

- approved delegated release boots through the stable verifier;
- altered, unsigned, wrong-key, and revoked release bundles fail;
- each enabled boot source enforces the same verification policy;
- dm-verity corruption prevents the system root from mounting;
- removed storage does not disclose LUKS data;
- copied storage fails on another Pi; failure on a different medium is required
  only if the storage identifier passes the stated qualification gate;
- raw OTP-key export fails before userspace;
- HMAC requests fail after the approved unlock;
- a released OS cannot use the bootstrap signing operation;
- replacement storage creates a new nonce, LUKS key, generation, and logical
  device instance;
- old instance certificates and leases are rejected;
- an old correctly signed OS epoch is rejected by the stable verifier before
  LUKS unlock and cannot obtain protected network service;
- A/B updates recover from power loss at every write and commit boundary;
- signed owned recovery works and unauthorized recovery fails;
- final boot order, UART, JTAG, EEPROM update, and write-protection state reads
  back exactly; and
- no image or evidence export contains a signing key, OTP secret, derived LUKS
  passphrase, or active device credential.

After the sacrificial campaign passes, provision one fresh production canary
with the new production Pi customer key. Repeat the complete acceptance suite
on that canary before expanding the cohort.

## Milestones

### Milestone 1: stable-verifier development spike

The unfused sacrificial candidate proves that the stable verifier boots only an
authorized delegated release, rejects every mutated input, obtains and enforces
fresh server policy before release handoff, and binds a one-boot operational key
using an explicitly non-production test bootstrap identity. This milestone does
not claim a firmware-backed identity or hardware lock.

### Milestone 2: encrypted and updateable development appliance

After the relevant irreversible development ceremony is separately approved,
the sacrificial Pi provisions a device OTP key, opens LUKS mutable state through
firmware HMAC only after verifier authorization, locks the derivation interface,
and can destructively initialize a replacement drive. It also implements the
qualified bootstrap-key design and proves its operation is locked before release
handoff. Delegated-signed A/B releases enforce revocation, authenticate the
complete kernel-to-root path, and safely handle interrupted updates.

### Milestone 3: enrolled appliance

The device authenticates with the qualified bootstrap identity, receives a
short-lived certificate bound to a one-boot operational key, and starts
protected services only after verifier-enforced server authorization.

### Milestone 4: hardened production canary

A fresh board uses the production customer key, final debug and EEPROM posture,
narrow recovery, HSM signing, and the complete production acceptance suite.

### Milestone 5: production release

The release pipeline publishes reproducible, independently verified images and
evidence; operations can update, revoke, destructively re-enroll, quarantine,
and retire devices without weakening the trust chain.

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
