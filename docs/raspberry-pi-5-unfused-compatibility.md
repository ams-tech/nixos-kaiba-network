# Raspberry Pi 5 unfused compatibility prototype

`kaiba-provision-unfused-compat` verifies the immutable inputs and synthetic
fixture for a Raspberry Pi 5 compatibility run without claiming that secure
boot was enforced. It is intentionally separate from the physical lane guard
and has no RPIBOOT, GPIO, UART, block-device, subprocess, or network boundary.

The capsule manifest requires four distinct immutable roles:

- `boot.img`;
- its detached boot signature;
- the dm-verity root-data image; and
- the dm-verity root hash-tree image.

Every regular file beneath the capsule root is sorted and bound by path, size,
and SHA-256 digest. Extra files or directories, symbolic links, special files,
changed content, duplicate JSON keys, unknown JSON fields, and trailing JSON
values are rejected.

Signed verification is available only from a verifier built with
`mkRpi5UnfusedVerifier`. That factory pins the reviewed signer's canonical
SPKI SHA-256 fingerprint into both offline binaries. The supplied public key
must be one RSA-2048 `PUBLIC KEY` PEM block using exponent 65537, and its
fingerprint must match that immutable anchor.

In Nix, derive that verifier anchor from the same public metadata as the
development signing package rather than copying a runtime flag. The repository
profile in [`nix/development-signing.nix`](../nix/development-signing.nix)
does that and exposes a signer-pinned verifier directly. Materialize the named
result used by both commands in this runbook:

```console
nix build path:.#rpi5-unfused-verifier \
  --out-link result-rpi5-unfused-verifier
verifier_path="$(readlink -f result-rpi5-unfused-verifier)"
reviewed_public_key="$(readlink -f \
  provisioning/signers/development-prototype/reviewed-boot-public.pem)"
```

Other deployments must instantiate `mkDevelopmentYubiKeySigning` with their
independently reviewed public metadata and pass
`signing.kaibaSigning.publicKeyFingerprint` to `mkRpi5UnfusedVerifier` in the
same way. A runtime flag must never select the trust anchor.

## Nix-built four-role capsule

`mkRpi5VerifiedUnfusedCapsule` is the fail-closed assembly boundary for the
offline prototype. It accepts only typed Nix-store outputs from
`mkRpi5VerifiedSignedBoot` and `mkRpi5SecureBootArtifacts`, plus an
independently reviewed signer fingerprint. The factory constructs the pinned
verifier itself, and the reviewed fingerprint must match the fingerprint
retained by the signed-boot signing plan.

The derivation checks that the signed `boot.img` is byte-for-byte identical to
the boot image in the unsigned artifact set, revalidates that artifact set's
domain-separated manifest digest, checks all three declared artifact digests,
extracts the root-integrity record and active command line from the signed FAT
image, and requires both to select the same dm-verity root hash and devices.
It runs `veritysetup verify` over the final copied root-data and root-hash
images, then emits this exact tree:

```text
capsule/
├── boot.img
├── boot.sig
└── nvme/
    ├── root-data.img
    └── root-hash.img
```

The public key and evidence stay outside `capsule/`, because any extra entry in
the capsule tree is rejected:

```text
capsule-manifest.json
compatibility-result.json
public.pem
unfused-fixture.json
```

The repository profile exposes a release-bound helper that selects its reviewed
signing plan, unsigned artifact set, and development signer metadata. Instantiate
it only after the two-file public `signedOutput` from the signing ceremony has
been placed in the Nix store as shown in the signed-boot workflow:

```nix
packages.x86_64-linux.verified-unfused-capsule =
  kaiba.lib.mkRpi5PrototypeVerifiedUnfusedCapsule {
    inherit signedOutput;
  };
```

Other deployments can use `mkRpi5VerifiedUnfusedCapsule` directly, but must
supply their independently reviewed `trustedPublicKeyFingerprint` as well as
the typed verified-boot and unsigned-artifact outputs. The factory constructs
the signer-pinned verifier internally.

Build the resulting package and inspect its already verified result:

```console
nix build path:.#verified-unfused-capsule \
  --out-link result-verified-unfused-capsule
jq . result-verified-unfused-capsule/compatibility-result.json
```

The fixture deliberately sets the complete compatibility sequence to true so
the offline contract can be exercised. It is synthetic, is named as such, and
cannot establish that any Pi booted. The derivation metadata and result keep
hardware observation, security enforcement, mutation eligibility, block-device
access, EEPROM programming, and OTP capability false.

## Synthetic outer-media fixture

The four-role capsule is not directly bootable whole-device media. After it is
verified, `mkRpi5MediaStagingFixture` can wrap its inner `boot.img` and
`boot.sig` in a deterministic outer FAT and construct a regular-file GPT
rehearsal:

```nix
packages.x86_64-linux.media-staging-fixture =
  kaiba.lib.mkRpi5MediaStagingFixture {
    system = "x86_64-linux";
    verifiedCapsule = verifiedUnfusedCapsule;
  };
```

The outer FAT contains exactly these three regular files:

```text
config.txt
boot.img
boot.sig
```

`config.txt` contains only `boot_ramdisk=1`. The factory binds the other two
files to the verified capsule, constructs deterministic primary and backup GPT
metadata around fixed boot, root-data, and root-hash extents, and exposes the
fixture-only `kaiba-provision-media-fixture` command. Its safe sequence is:

1. `init --workspace /absolute/new/workspace` to create `target.img` and its
   exact `fixture-plan.json`;
2. run the generic media stager's `fixture-dry-run`, `fixture-stage`, and
   `fixture-readback` commands with that plan; and
3. `verify --workspace /absolute/new/workspace` to take a locked regular-file
   snapshot and inspect its raw GPT regions, complete partition digests, FAT
   allowlist and payloads, extent digests, and dm-verity pair.

The detailed commands are in the [target-media staging prototype]. The factory
and fixture commands accept only regular-file rehearsal state; they do not
select or write a block device. Although the final fixture verifier checks the
expected GPT structure, the generic staging plan and receipt bind only the three
payload extents, not GPT metadata. A successful run makes no cold-power,
hardware-observation, live-boot, secure-boot-enforcement, EEPROM, or OTP claim.
It is not SB-04 ceremony evidence.

The signer-pinned command requires the canonical three-line Raspberry Pi
`boot.sig`, checks that its first line is the manifest-bound SHA-256 of
`boot.img`, and verifies its RSA-2048 PKCS#1 v1.5/SHA-256 signature with the
reviewed key. It emits a domain-separated receipt that includes the
signer-policy digest:

```console
"$verifier_path/bin/kaiba-provision-unfused-compat" verify-signed-offline-fixture \
  --manifest /absolute/path/capsule-manifest.json \
  --capsule-root /absolute/path/capsule \
  --fixture /absolute/path/unfused-fixture.json \
  --public-key "$reviewed_public_key"
```

A successful result is always limited to:

```text
status: compatibility_passed
evidence_mode: offline_fixture
signature_verified: true
signer_trust_anchored: true
hardware_observed: false
security_enforced: false
mutation_eligible: false
```

The generic `kaiba-provision-unfused-compat` and
`kaiba-provision-unfused-evidence` packages have no signer anchor. Signed
compatibility verification and all evidence verification therefore fail
closed in those generic builds. The compatibility binary's
`verify-offline-fixture` mode remains available for deliberately synthetic
fixture tests and emits
`signature_verified:false` and `signer_trust_anchored:false`; it is not
sufficient for a signed capsule acceptance record. Neither mode can emit a
production approval, `security_applied`, or an enrollment state. The packages
are dedicated derivations, and their contract checks reject a linked production
lane, physical Pi adapter, RPIBOOT, or GPIO implementation. In particular, do
not substitute the repository's generic evidence output for the signer-pinned
prototype verifier.

## Offline unfused record correlation

After the signed offline result exists, a fresh unfused board may be booted
manually without supplying any ownership, OTP, or EEPROM programming bundle.
Capture the bounded UART output and create the strict operator record described
by the verifier. It must bind the signer policy, capsule and role digests, one
lane and target fingerprint, the all-zero customer-key hash before and after,
explicit manual BOOTSEL and normal-boot confirmations, and complete power
removal at all three mode boundaries.

The UART transcript must contain exactly one capsule-bound compatibility record
and exactly one root-data/root-hash-bound dm-verity record. Then run:

```console
"$verifier_path/bin/kaiba-provision-unfused-evidence" verify-operator-observation \
  --manifest /absolute/path/capsule-manifest.json \
  --capsule-root /absolute/path/capsule \
  --fixture /absolute/path/unfused-fixture.json \
  --public-key "$reviewed_public_key" \
  --observation /absolute/path/operator-observation.json \
  --uart-capture /absolute/path/uart.txt
```

The evidence command re-verifies the raw signed capsule inputs in-process; a
previous compatibility-result JSON is archival output and is never accepted as
authority input. A successful result is deliberately correlation-only:

```text
status: record_consistent
evidence_mode: offline_operator_correlation
record_consistent: true
capture_authenticated: false
freshness_established: false
hardware_observed: false
security_enforced: false
mutation_eligible: false
```

The operator record and UART transcript can be self-consistent without proving
who captured them, when they were captured, or that they came from live
hardware. The verifier therefore never turns these files into a hardware
observation claim. It has no live UART, USB, GPIO, block-device, subprocess, or
network boundary. A future fixed-lane collector needs an independently anchored
station evidence key and a fresh, single-use control-plane challenge before it
can emit `hardware_observed:true`.

This offline layer is followed by a separately privileged media stager that can
overwrite only an operator-selected dedicated disk. Neither offline verifier is
allowed to carry an OTP or EEPROM programming bundle. The current unfused files
can support operator correlation, but live hardware provenance and
customer-signature enforcement remain unproven until the authenticated
collector and separately reviewed irreversible ceremony exist.

[target-media staging prototype]: target-media-staging-prototype.md
