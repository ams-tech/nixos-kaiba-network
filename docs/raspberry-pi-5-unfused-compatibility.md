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

Run the signed offline verifier with absolute paths. The public key must be one
RSA-2048 `PUBLIC KEY` PEM block using exponent 65537; the command verifies the
manifest-bound `boot.sig` as RSA PKCS#1 v1.5/SHA-256 over `boot.img` and emits a
domain-separated verification receipt:

```console
nix run ./nix/provisioning#kaiba-provision-unfused-compat -- \
  verify-signed-offline-fixture \
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
hardware_observed: false
security_enforced: false
mutation_eligible: false
```

`verify-offline-fixture` remains available for deliberately synthetic fixture
tests and emits `signature_verified:false`; it is not sufficient for a signed
capsule acceptance record. Neither mode can emit a production approval,
`security_applied`, or an enrollment state. The Nix package is built in a dedicated derivation and its
contract check rejects a linked production lane, physical Pi adapter, RPIBOOT,
or GPIO implementation.

## Passive unfused hardware evidence

After the signed offline result exists, a fresh unfused board may be booted
manually without supplying any ownership, OTP, or EEPROM programming bundle.
Capture the bounded UART output and create the strict operator observation
described by the verifier. It must bind the signed compatibility outcome,
capsule and role digests, one lane and target fingerprint, the all-zero
customer-key hash before and after, explicit manual BOOTSEL and normal-boot
confirmations, and complete power removal at all three mode boundaries.

The UART transcript must contain exactly one capsule-bound compatibility record
and exactly one root-data/root-hash-bound dm-verity record. Then run:

```console
nix run ./nix/provisioning#kaiba-provision-unfused-evidence -- \
  verify-operator-observation \
  --compatibility-outcome /absolute/path/signed-compatibility-result.json \
  --observation /absolute/path/operator-observation.json \
  --uart-capture /absolute/path/uart.txt
```

The successful physical result changes only `hardware_observed` to `true`.
`security_enforced` and `mutation_eligible` remain false. The verifier reads
the three named regular files; it has no live UART, USB, GPIO, block-device,
subprocess, or network boundary.

This offline layer is followed by two separately privileged tools: an explicit
media stager that can overwrite only an operator-selected dedicated disk, and
a passive/manual boot-evidence collector. Neither is allowed to carry an OTP
or EEPROM programming bundle. An unfused physical run can establish capsule
and dm-verity compatibility, but customer-signature enforcement remains
unproven until the separately reviewed irreversible ceremony.
