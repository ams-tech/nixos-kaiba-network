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
development signing package rather than copying a runtime flag. For example,
the following complete consuming flake exposes one signer-pinned verifier
package. Replace the revision and marked deployment values; the customer-key
hash must match the reviewed public key:

```nix
{
  inputs = {
    kaiba.url = "github:ams-tech/nixos-kaiba-network/<PINNED_REVISION>";
    nixpkgs.follows = "kaiba/nixpkgs";
  };

  outputs = { kaiba, ... }:
    let
      system = "x86_64-linux";
      developmentSigning = kaiba.lib.mkDevelopmentYubiKeySigning {
        inherit system;
        name = "kaiba-prototype-signing";
        cohortID = "cohort:prototype";
        signerID = "signer:prototype";
        tokenSerial = "<YUBIKEY_DECIMAL_SERIAL>";
        publicKeyPEM = ./reviewed-boot-public.pem;
        publicKeyFingerprint = "sha256:<64_LOWERCASE_HEX_DIGITS>";
        expectedCustomerKeyHash = "<64_LOWERCASE_HEX_DIGITS>";
        grantRegistryPath = "/etc/kaiba-provisioning/signing-grants.json";
      };
    in
    {
      packages.${system}.unfused-verifier =
        kaiba.lib.mkRpi5UnfusedVerifier {
          inherit system;
          trustedPublicKeyFingerprint =
            developmentSigning.kaibaSigning.publicKeyFingerprint;
        };
    };
}
```

Save that expression as `flake.nix` beside `reviewed-boot-public.pem`, then
materialize the `./result` used by both commands in this runbook:

```console
nix build .#unfused-verifier
```

The signer-pinned command verifies the manifest-bound `boot.sig` as RSA PKCS#1
v1.5/SHA-256 over `boot.img` and emits a domain-separated receipt that includes
the signer-policy digest:

```console
./result/bin/kaiba-provision-unfused-compat verify-signed-offline-fixture \
  --manifest /absolute/path/capsule-manifest.json \
  --capsule-root /absolute/path/capsule \
  --fixture /absolute/path/unfused-fixture.json \
  --public-key /absolute/path/reviewed-boot-public.pem
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
./result/bin/kaiba-provision-unfused-evidence verify-operator-observation \
  --manifest /absolute/path/capsule-manifest.json \
  --capsule-root /absolute/path/capsule \
  --fixture /absolute/path/unfused-fixture.json \
  --public-key /absolute/path/reviewed-boot-public.pem \
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
