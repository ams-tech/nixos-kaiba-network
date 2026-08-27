# Development prototype boot signer

This directory contains the public trust anchor for the sacrificial Raspberry
Pi 5 signed-boot development cohort. It grants no signing authority. The
ceremony generated the private RSA-2048 key in YubiKey PIV slot `9c`; the token
reported generated-on-device origin, PIN-always policy, touch-always policy,
and no private-key export path.

The repository profile is intentionally non-production:

- signer ID: `signer:prototype`;
- cohort ID: `cohort:prototype`;
- YubiKey serial: `35454358`;
- public PEM SHA-256:
  `93923fb1b289c39e8b336b90defb881f5d15ce3832c74655b295e1a35bfdab80`;
- canonical SPKI SHA-256:
  `sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9`;
- Raspberry Pi customer-key hash:
  `b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895`;
- canonical signer-policy digest:
  `sha256:c49608752c7aaf96da1976e174fb0e9f853b517bfc6df3a7f91f907ff9ca0db9`.

Checking in this profile intentionally publishes the unique development-token
serial. That identifier grants no token access, but it can be used to correlate
the physical development token with this repository.

The 2026-08-19 dry-run ceremony verified the Yubico attestation chain and
matched the attested public key to this PEM. Its external evidence archive is
bound by these historical SHA-256 file digests:

- leaf slot attestation:
  `c7fb478ed8d19912d7a26a6865307e8b0abac4729a2610db07cbffeec92de856`;
- token attestation intermediate:
  `4ca6aa761371243d61355fd43b37de7b78552aedcc879e7a4e060e66b9da950e`;
- downloaded Yubico root:
  `9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887`;
- downloaded Yubico intermediate bundle:
  `ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1`.

On 2026-08-27, a second review from a fresh checkout under a separate
unprivileged account independently rebuilt the exact `v0.1.3` public release,
verified a fresh slot attestation through the current Yubico chain, decoded
the token serial, firmware and usage-policy extensions, and byte-compared its
RSA-2048 SPKI with this PEM. The reusable signer-review result is recorded in
`independent-review-2026-08-27.json`; its evidence packet remains in the
external access-controlled archive. A fresh attestation has a different certificate
serial and therefore a different whole-file digest from the historical leaf.

This completes independent review only for the sacrificial development
signer. Every public release, including any release after `v0.1.3`, still
requires a separate exact release approval and grants. This record does not
approve the signer for production, issue a signing grant, prove current token custody or presence,
or authorize any Pi, media, EEPROM, or OTP mutation. PIN, PUK, management-key
material, systemd credentials, signing grants, private-key material, derived
policy files, and derived Raspberry Pi key binaries must never be added here.

Build the public-only contracts from the repository root:

```console
nix build .#development-signing --out-link result-development-signing
nix build .#rpi5-unfused-verifier --out-link result-rpi5-unfused-verifier
nix build .#packages.aarch64-linux.rpi5-prototype-unsigned-artifacts \
  --out-link result-rpi5-prototype-unsigned-artifacts
nix build .#rpi5-prototype-signing-plan \
  --out-link result-rpi5-prototype-signing-plan
nix build .#rpi5-prototype-release-review \
  --out-link result-rpi5-prototype-release-review
```

The final three outputs bind a clean repository revision to the development
customer-key hash, construct an unsigned Pi 5 boot/root artifact set, and
validate its public signing plan. They neither contact the YubiKey nor sign or
write anything. See the
[signed-boot workflow](../../../docs/raspberry-pi-5-signed-boot-workflow.md#build-the-repository-prototype-release-inputs)
for output inspection and host requirements.
