# Raspberry Pi 5 secure boot

This document explains the native secure-boot chain on a Raspberry Pi 5 Model
B and defines the minimum Kaiba gate for moving one qualified, apparently
fresh board to an owned state that will execute only Kaiba-authorized boot
firmware and OS boot images. It ends immediately before device-identity
enrollment. “Factory fresh” is convenient operator shorthand here, not a claim
of supply-chain provenance or complete absence of earlier state.

This is the production security design and ceremony specification. The
repository now contains a separate, fail-closed development-cohort reference
implementation for building the target and unsigned artifacts, external
approval-gated signing, transaction/audit state, and a one-shot physical lane
guard. See the [live implementation runbook]. It has not been qualified on the
physical rig and deliberately does not claim production enrollment. Do not
translate this checklist into ad hoc shell commands.

The primary sources were checked on 2026-08-15. Raspberry Pi's maintained
documentation and repositories are authoritative for the hardware mechanism;
the implementation must additionally pin the exact `usbboot`, EEPROM firmware,
signing-tool, and boot-image inputs used for a device transaction.

## Intended production outcome and current stop

Raspberry Pi documentation uses *customer* for the owner whose key authorizes
firmware and OS images. In this document that customer is Kaiba.

The production terminal state described here is **ready for enrollment**,
which means:

- the expected Kaiba public-key hash is irreversibly programmed in OTP;
- the installed EEPROM firmware and configuration are authorized by that key;
- the board cold-boots the approved `boot.img` and rejects altered, unsigned,
  and wrong-key boot and recovery images across every enabled boot source;
- code in the signed boot image authenticates the system it will execute from
  persistent storage before any enrollment or production-identity service can
  start;
- an approved rollback policy is enforced before protected device material can
  be used; native Pi secure boot alone does not supply that policy;
- the signed pre-enrollment runtime contains the approved public trust and
  policy needed to authenticate the intended enrollment domain, but no shared
  enrollment secret or active production credential;
- the configured recovery, boot-order, debug, and EEPROM write-protection state
  matches policy and has been read back; and
- the complete secret-free evidence has been reconciled with inventory.

It does **not** mean that a device identity has been created, a certificate has
been issued, or the device is authorized for production. Those are later,
separately gated lifecycle operations.

There is no UEFI `SetupMode` in the native Pi chain. Kaiba should model the
board lifecycle explicitly:

```text
qualified_fresh_candidate -> prepared -> commit_in_progress
                                      -> security_applied -> enrollment_ready
                                      -> owned_quarantined
```

The implemented development milestone terminates at `security_applied`.
Because native Pi secure boot will accept an older correctly signed image and
this milestone has no independent monotonic state, every attempt to enter
`enrollment_ready` is rejected. The development boot key is one external,
non-exportable YubiKey PIV cohort key; the Pi stores only its public-key hash in
OTP and has no boot-signing private key to export. Per-device identity and
storage keys are separate future operations.

`qualified_fresh_candidate` means only that the board passed the current
profile's observable baseline: the customer-key hash is exactly zero and
VideoCore JTAG is unlocked. The current probe does not establish other customer
OTP, device-private-key rows, EEPROM contents or write protection, attached
storage, inventory ownership, firmware authenticity, or every debug path.
Those are separate preconditions for a real transaction. A non-zero unexpected
customer-key hash is foreign ownership and must cause quarantine; it is not an
acceptable variant of fresh.

## What native Pi secure boot does

The Raspberry Pi 5 uses the BCM2712 boot ROM and EEPROM bootloader rather than
UEFI Secure Boot. The official [secure-boot overview] describes this chain:

```text
immutable BCM2712 BootROM
  -> EEPROM second stage (`bootsys`)
     Raspberry-Pi signature + Kaiba counter-signature
     customer public key checked against its OTP hash
  -> EEPROM `bootmain`
  -> `boot.img` checked against `boot.sig`
     Kaiba RSA-2048/SHA-256 signature
  -> config, device trees, kernel, and initramfs from verified `boot.img`
  -> initramfs authenticates and mounts the persistent system
  -> NixOS userspace
```

The stages have distinct responsibilities:

1. The immutable BootROM verifies Raspberry Pi's signature on the EEPROM
   second stage. On BCM2712 in secure-boot mode, it also requires a customer
   counter-signature. This lets Kaiba authorize the particular Raspberry Pi
   EEPROM firmware that may execute.
2. The verified `bootsys` obtains the customer public key from EEPROM, requires
   its SHA-256 digest to match the value programmed into OTP, and only then
   loads `bootmain`.
3. The bootloader obtains `boot.img` and `boot.sig` from an enabled boot source,
   verifies the image digest and RSA signature, and then reads boot files from
   that verified FAT image. Raspberry Pi 5 has its runtime firmware within the
   EEPROM bootloader and, unlike earlier models, has no `start.elf`. The boot
   image still needs the complete `config.txt`, kernel command line, device
   trees and overlays, kernel, initramfs, and every other file consumed before
   the persistent system is authenticated.
4. A verification failure aborts the current boot mode and advances to the next
   mode in `BOOT_ORDER`. Secure boot therefore authenticates every attempted
   image, but the complete boot order must still be reviewed for availability,
   recovery, and unexpected fallback behavior.

The maintained [boot ramdisk documentation] currently specifies `boot.img`
as a raw FAT image without an MBR and currently limits the ramdisk to 96 MiB.
The production builder must enforce both an exact file allowlist
and the limit applicable to its pinned firmware, rather than discover either at
the irreversible ceremony.

`rpi-eeprom-digest` signs the image with RSA-2048, SHA-256, and PKCS#1 v1.5.
The [official signing documentation] also defines an HSM wrapper interface so
the signing operation need not expose the private key as a PEM file.

## What it does not do

The claim must stop at the actual hardware boundary:

- Secure boot authenticates the EEPROM boot chain and files loaded from
  `boot.img`; it does not automatically authenticate a Nix store or another
  root filesystem mounted afterward. Kaiba's signed initramfs must enforce a
  persistent-system integrity design, such as a dm-verity root whose expected
  root hash is inside the signed boot image, before enrollment code runs.
- It does not encrypt storage. Secret mutable state needs a separate encryption
  and recovery design. Raspberry Pi documents LUKS as a separate layer and
  explicitly notes that the platform has no secure hardware enclave.
- It enforces a key-level authorization policy, not an exact release allowlist.
  An old or otherwise different but correctly Kaiba-signed `boot.img` can run.
  Availability rollback with `tryboot` and security anti-rollback are different
  problems; the latter needs a separately designed monotonic policy.
- It is verified boot, not remote attestation. A value reported by the running
  OS is useful local reconciliation evidence but is not independent proof to a
  remote verifier.
- It does not protect against a compromised authorized kernel, invasive
  extraction, fault injection, side channels, denial of service, or compromise
  of the Kaiba signing authority.

Consequently, “only boots our signed images” means that no unauthorized
second-stage firmware or OS boot capsule reaches execution through the native
boot chain. It is not a claim that every byte read after the kernel starts is
automatically signed.

## Keys and required artifacts

Nothing should be fused until all of these artifacts exist and their hashes
are bound to one transaction.

| Artifact | Purpose and required handling |
| --- | --- |
| Kaiba boot-signing key | RSA-2048 private key used to authorize EEPROM firmware/configuration, normal boot images, and deliberately approved recovery code. It must not enter Git, the Nix store, a target image, or the provisioning station. Use an HSM-backed signing interface for production and maintain a tested split-custody backup. |
| Public key and fingerprint | Public half embedded in the signed EEPROM image; its expected canonical SHA-256 digest is the irreversible value authorized for OTP. Record the canonical public key and digest emitted or consumed by the pinned Raspberry Pi tooling in the transaction and fleet key inventory. Do not substitute a hash of the PEM file's text encoding. |
| Signed EEPROM image | Pinned Raspberry Pi EEPROM firmware with an exact signed configuration and a customer-counter-signed BCM2712 second stage. Record the source version, complete configuration, digest, and signing result. |
| Normal `boot.img` and `boot.sig` | Complete boot capsule and detached signature. Record an exact file manifest, image digest, signature-verification result, root-integrity reference, public enrollment-trust version, source revision, and size. |
| Fresh-board commit bundle | RPIBOOT bundle that can execute while the customer-key hash is still zero and that carries the approved signed EEPROM image plus `program_pubkey=1`. Build the EEPROM with the official [update-pieeprom script] `-f` path; do not counter-sign the fresh-board `recovery.bin`. A customer-counter-signed recovery program will not run on a hash-zero BCM2712 board. |
| Owned-device recovery bundle | Separately approved recovery program counter-signed by the same Kaiba key, built and verified before commit with the official `-fr` path. It must exist before the fuse operation because the current qualification probe and stock recovery payload lack the customer counter-signature and are rejected afterward. Keep its capabilities narrow; a signed recovery shell or mass-storage image is authorized code and can defeat higher-level secret isolation. |
| Transaction manifest | Secret-free record binding the target fingerprint, expected OTP hash, EEPROM/configuration/boot artifacts, boot order, rollback, debug, storage, and recovery policies, tool versions, signer identity, operator and approver, and every required postcondition. |

The OTP key binding is permanent. The [Pi 5 programming guide] states that
secure boot cannot be disabled and a different customer key cannot later be
programmed. Losing the private key makes future authorized firmware, normal
boot, and recovery updates impossible. Compromise of that key authorizes
malicious code on every board fused to it; there is no in-place migration to a
new native root. Development, staging, and production must therefore use
different keys, and production may use cohorts to bound the blast radius.

## The irreversible boundary

`program_pubkey=1` in the RPIBOOT recovery configuration writes the public-key
hash from the signed EEPROM image into OTP. The similarly named `config.txt`
inside the OS boot filesystem is a different file and does not perform this
operation. Raspberry Pi restricts these OTP changes to RPIBOOT so a stale OS
image cannot request them during normal boot. On Pi 5, programming the key also
prevents the ROM from loading `recovery.bin` from SD or eMMC; subsequent
bootloader recovery is through customer-authorized RPIBOOT or an intentionally
authorized self-update policy.

BCM2712 has an important testing constraint: according to the [Pi 5 programming
guide], a customer-signed EEPROM image will not run until the matching public
key is already in OTP, and the full customer-signature enforcement path cannot
be exercised without making the irreversible change. Before commit, Kaiba can
and must:

- verify `boot.sig` against the expected public key offline;
- inspect and hash the complete contents of `boot.img`;
- boot the capsule as a ramdisk on an unfused board with `boot_ramdisk=1` to
  prove that its layout, kernel, and initramfs work; and
- validate the signed EEPROM, fresh-board bundle, and owned recovery bundle as
  artifacts.

That ramdisk boot proves compatibility, not signature enforcement. The first
fused engineering unit is necessarily the first end-to-end hardware test of
the Kaiba key.

VideoCore JTAG locking is a separate irreversible choice. Raspberry Pi's
[secure-boot configuration reference] warns that `program_jtag_lock=1` can
prevent failure analysis and should be applied only after the device is fully
tested. Keep it as an explicit, separately approved finalization step. Apply
the same discipline to EEPROM hardware write protection and boot-order
restriction: define the intended recovery path first, then set and read back
the final posture before enrollment.

## Qualified candidate to enrollment-ready checklist

This is the short operator-level sequence. The future provisioning tool must
expand each checkbox into exact preconditions, an intent record, one bounded
operation, authoritative readback, and a secret-free result.

### Prepare without mutation

- [ ] Qualify and bind exactly one Pi 5 Model B; require the current observable
  fresh-board policy, including an all-zero customer-key hash, resolve its
  deferred preconditions, and confirm no inventory owner or earlier transaction
  exists.
- [ ] Approve the expected Kaiba public-key fingerprint and prove that its
  private key, authorization policy, and tested backup are available.
- [ ] Pin and hash the EEPROM firmware/configuration, signing tools, normal
  `boot.img`/`boot.sig`, persistent-root integrity reference, fresh-board
  commit bundle, and owned-device recovery bundle in one transaction manifest.
- [ ] Verify every signature offline, inspect the boot-image allowlist and size,
  and successfully boot the same capsule with `boot_ramdisk=1`; confirm no
  fleet signing key, shared enrollment secret, or production private key is
  present in any artifact.
- [ ] Approve the exact boot order and partition-walk behavior, recovery,
  self-update and enforced rollback policies, JTAG/debug posture, EEPROM
  write-protection posture, postconditions, negative tests, and quarantine
  response. Enrollment remains blocked until the rollback gate is implemented
  and tested; native secure boot is not that gate.

### Commit ownership

- [ ] Re-identify the same target on the exclusive RPIBOOT lane, record mutation
  intent, and run the approved fresh-board bundle once with
  `program_pubkey=1`. Do not blindly repeat an operation after a timeout or
  uncertain result.
- [ ] Capture recovery metadata and require the expected customer-key hash,
  successful secure-boot provisioning and EEPROM update, and the approved
  EEPROM digest. Any mismatch or unverifiable result after the first OTP write
  quarantines the board permanently from the fresh-device path.

### Prove the owned state

- [ ] Remove all power, then cold-boot the exact approved signed OS image.
  Reconcile UART signature-verification evidence and, on supported EEPROM
  firmware, `/proc/device-tree/chosen/bootloader/boot_img_sha256` against the
  approved image digest.
- [ ] Use the customer-counter-signed owned-device probe to read back the key
  hash, EEPROM/security state, and target identity; require an exact match to
  the transaction and the pre-commit target. Require bit 3 of the bootloader's
  `/proc/device-tree/chosen/bootloader/signed` value, rather than relying on the
  undocumented example `SIGNATURE_MODE` field as the secure-boot gate.
- [ ] Prove the customer-counter-signed RPIBOOT recovery path works, then prove
  the current qualification recovery and stock recovery payload, which lack
  the customer counter-signature, no longer execute. Re-run the authorized
  readback afterward.
- [ ] Demonstrate that altered `boot.img`, altered `boot.sig`, a wrong-key image,
  unsigned alternate SD/USB/NVMe or network media, and RPIBOOT recovery without
  a customer counter-signature never execute. Isolate each candidate source or
  reconcile the digest of the image that actually ran; an approved fallback OS
  may legitimately boot after the bad candidate is rejected. Exercise every
  enabled `BOOT_ORDER` path and partition-walk candidate.
- [ ] Demonstrate that persistent-system tampering fails before enrollment
  services and protected device material become available.
- [ ] Demonstrate that the approved rollback gate rejects an older but validly
  Kaiba-signed release before enrollment services or protected device material
  become available.
- [ ] Apply any separately approved final JTAG, EEPROM write-protection, and
  boot-order controls only after the first positive and negative tests pass;
  cold restart, read them back, and repeat every boot, recovery, and rollback
  acceptance test affected by the final posture.
- [ ] Export and reconcile the complete audit record and mark the transaction
  `security_applied`. Mark the device `enrollment_ready` only when the
  independently monotonic rollback gate is implemented and its rejection test
  passed; the current reference implementation always blocks that transition.

There is no successful “mostly complete” result after the OTP boundary. An
unknown key hash, changed target, unexpected EEPROM, missing audit evidence,
failed cold boot, available unsigned fallback, or failed negative test leaves
the board owned but quarantined. It must never be presented to the fresh-board
workflow again.

## Evidence to retain

The final record contains no secret values. At minimum retain:

- the qualification record and pre-commit target fingerprint;
- the canonical boot public key and expected/programmed key hash;
- exact source revisions, tool versions, signer identity, and SHA-256 digests
  for the EEPROM image/configuration, normal boot capsule, root-integrity
  reference, commit bundle, and owned recovery bundle;
- the approved `BOOT_ORDER`, rollback, debug, JTAG, EEPROM write-protection,
  storage, and recovery policies;
- pre-commit offline signature and boot-compatibility results;
- RPIBOOT metadata including `CUSTOMER_KEY_HASH`, `EEPROM_UPDATE`,
  `SECURE_BOOT_PROVISION`, and `EEPROM_HASH` when emitted;
- cold-boot UART evidence, bit 3 of the bootloader `signed` property, and the
  mandatory bootloader-provided `boot_img_sha256` value matching the approved
  manifest;
- each positive, negative, rollback, and post-finalization retest result; and
- operator, approver, station, lane, transaction, timestamps, final lifecycle
  state, and any quarantine reason.

Raspberry Pi added the signed `boot.img` SHA-256 device-tree property in the
2025-01-22 BCM2712 bootloader release. Its presence must be a capability of the
pinned firmware, not silently assumed for an older image. It is local
reconciliation evidence, not remote attestation.

## Updates and recovery after ownership

Ownership changes every later boot operation:

- EEPROM firmware and configuration updates must remain Kaiba-signed, and the
  BCM2712 second stage must remain Raspberry-Pi-signed and Kaiba-counter-signed.
- Normal and `tryboot` OS capsules must have valid signatures under the fused
  key. Raspberry Pi's [tryboot documentation] provides a one-shot availability
  rollback mechanism, not protection against replay of an older signed release.
- RPIBOOT recovery programs must be counter-signed by the fused key. The
  official tooling uses the `-r` signing path for recovery on an already owned
  device; the resulting capability must not be generally distributed.
- Pi 5 ROM recovery from SD/eMMC is unavailable after `program_pubkey`; the
  authorized RPIBOOT bundle and any enabled signed self-update path are the
  bootloader recovery mechanisms.
- Signing-key loss, signing-key compromise, recovery failure, old-image
  rollback, and board/storage replacement need rehearsed responses before any
  production identity is enrolled.

Secure boot establishes which early code may run. It does not by itself decide
which signed release is still authorized, recover encrypted data, preserve a
logical identity across board replacement, or activate a device credential.

## Kaiba implementation boundary

The qualification profile and probe remain the authoritative fresh-board
observation path and are not widened to accept an owned key hash. The current
development reference now supplies the deterministic Pi 5 target and
`boot.img`/dm-verity builder, external approval-gated signing chain, durable
control and independent audit services, and journaled target-bound physical
adapter. Generic binaries and modules stay non-mutating until instantiated
with fixed store paths, digests, lane devices, and an explicit mutation flag.

Production still requires hardware execution and evidence on the qualified
rig, a distinct owned-device profile and signed probe bundle, independently
monotonic anti-rollback, encrypted mutable state, device identity enrollment,
production key backup/rotation, final debug/write-protection policy, and the
complete positive, negative, power-loss, recovery, and quarantine campaign.

The official [Raspberry Pi Secure Boot Provisioner] is a useful maintained
reference for the vendor-supported provisioning flow, HSM signing, encrypted
storage, and manufacturing records. Its image transformations target Raspberry
Pi OS and `rpi-image-gen`; compatibility with NixOS must be established rather
than assumed.

## Primary sources

- [Raspberry Pi `usbboot` secure-boot overview][secure-boot overview]: native
  chain of trust, Pi 5 counter-signing, `boot.img`, signature format, HSM
  interface, storage boundary, and signing verification.
- [Raspberry Pi 5 secure-boot programming guide][Pi 5 programming guide]:
  fresh-versus-owned recovery signing, RPIBOOT procedure, BCM2712 pre-fuse test
  limitation, UART evidence, metadata, `program_pubkey`, and JTAG locking.
- [Raspberry Pi 5 recovery configuration]: effect of `program_pubkey` on
  SD/eMMC ROM recovery and the separate JTAG-lock warning.
- [Raspberry Pi `update-pieeprom.sh`][update-pieeprom script]: exact `-f`
  EEPROM-firmware and `-r` recovery counter-signing semantics.
- [Raspberry Pi `config.txt` reference][secure-boot configuration reference]:
  RPIBOOT-only irreversible properties and JTAG warning.
- [Raspberry Pi `boot_ramdisk` reference][boot ramdisk documentation]:
  `boot.img` format, current size limit, `tryboot.img` selection, and the Pi 5
  `start.elf` distinction.
- [Raspberry Pi bootloader documentation]: `BOOT_ORDER`, boot-mode fallback,
  diagnostics, and Pi 5 boot-flow differences.
- [Raspberry Pi bootloader device-tree properties]: the runtime `signed`
  bit-field and its customer-key-OTP bit.
- [Official BCM2712 chain-of-trust diagram]: visual reference for the Pi 5 ROM,
  customer-counter-signed second stage, and signed-boot flow.
- [BCM2712 EEPROM release notes]: signed-boot image-hash device-tree property
  and the firmware version in which it appeared.
- [Raspberry Pi Secure Boot Provisioner]: current official higher-level
  provisioning reference implementation.

[secure-boot overview]: https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md
[official signing documentation]: https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md#signing-the-boot-image
[Pi 5 programming guide]: https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/README.md
[Raspberry Pi 5 recovery configuration]: https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/config.txt
[update-pieeprom script]: https://github.com/raspberrypi/usbboot/blob/master/tools/update-pieeprom.sh
[secure-boot configuration reference]: https://www.raspberrypi.com/documentation/computers/config_txt.html#secure-boot-configuration-properties
[boot ramdisk documentation]: https://www.raspberrypi.com/documentation/computers/config_txt.html#boot_ramdisk
[tryboot documentation]: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#fail-safe-os-updates-tryboot
[Raspberry Pi bootloader documentation]: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#raspberry-pi-bootloader-configuration
[Raspberry Pi bootloader device-tree properties]: https://www.raspberrypi.com/documentation/computers/configuration.html#bcm2711-and-bcm2712-specific-bootloader-properties-chosenbootloader
[Official BCM2712 chain-of-trust diagram]: https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot-chain-of-trust-2712.pdf
[BCM2712 EEPROM release notes]: https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md
[Raspberry Pi Secure Boot Provisioner]: https://github.com/raspberrypi/rpi-sb-provisioner
[live implementation runbook]: ./raspberry-pi-5-live-provisioning.md
