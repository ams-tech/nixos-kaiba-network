# Raspberry Pi 5 v0.1.6 public signed inputs

This directory contains the already-signed, public inputs for the development
Raspberry Pi 5 v0.1.6 payload. It intentionally contains no private key,
signer, PIN, or signing provider.

The root flake passes these files through the v0.1.6 signed-release recovery
verifier before the development secure-boot station can be built.
That verifier binds the signatures, grants, receipts, payload source revision,
customer-key hash, EEPROM hash, boot image, and RPIBOOT bundles.

`SHA256SUMS` covers every checked-in input file and the exact operational
payload manifest. Native ARM image assembly verifies that inventory before it
copies the three required RPIBOOT bundles. The x86 verification check
independently reconstructs the complete signed release and byte-compares those
bundles and their signed-release manifest binding.
