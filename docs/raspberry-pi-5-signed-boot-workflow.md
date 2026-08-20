# Raspberry Pi 5 signed-boot workflow

This workflow produces and verifies a signed `boot.img` without writing target
media, programming EEPROM, or changing OTP. Nix builds only public artifacts.
The private key remains behind the fixed, approval-gated YubiKey service and is
used only by an explicit runtime command.

## Boundaries and outputs

`mkRpi5BootSigningPlan` is a pure derivation. Its inputs are an already-built
`boot.img`, a reviewed RSA-2048 public key, that key's canonical SPKI SHA-256
fingerprint, the reviewed signer-policy digest, a release ID, and a fixed
timestamp. It emits exactly:

```text
boot.img
plan.json
public.pem
```

`mkDevelopmentYubiKeySigning` builds the runtime adapter. The package fixes the
signing-gate socket, signer/cohort IDs, YKCS11 URI, public-key path, and public
fingerprint at link time. The `sign` command accepts only a plan directory and
a new output directory; it has no runtime key, URI, provider, module, socket,
algorithm, or PIN selector. It emits exactly:

```text
boot.sig
signing-result.json
```

`mkRpi5VerifiedSignedBoot` is another pure derivation. It admits the public
runtime result back into Nix, checks every plan/result/image/key/signature
binding, verifies the Raspberry Pi signature, and emits exactly:

```text
boot.img
boot.sig
manifest.json
public.pem
signing-plan.json
signing-result.json
```

The canonical `boot.sig` is the three-line Raspberry Pi format: image SHA-256,
`ts: <decimal>`, and `rsa2048: <signature hex>`. The RSA signature authenticates
the image digest. The timestamp and Kaiba policy records are independently
bound by the reviewed plan and final Nix output; the Raspberry Pi signature
format itself does not cryptographically authenticate those metadata fields.
Similarly, `gate_receipt_digest` is correlation metadata unless the associated
root-managed gate receipt is obtained and checked separately.

## Review the public signer metadata

If the signing key does not exist yet, first complete the interactive token
ceremony in [live provisioning](raspberry-pi-5-live-provisioning.md#development-boot-root-ceremony).
Generate the RSA-2048 key on the YubiKey and export only its public half; key
generation and private-key material do not belong in Nix.

Compute the ordinary SPKI fingerprint from the canonical reviewed public key:

```console
openssl pkey -pubin -in reviewed-boot-public.pem -outform DER \
  | sha256sum
```

The signer-policy digest covers public metadata only. The following reproduces
the Go/Nix canonical policy for the example values; substitute the reviewed
serial and fingerprint before recording the result:

```console
signer_id='signer:prototype'
cohort_id='cohort:prototype'
token_serial='<YUBIKEY_DECIMAL_SERIAL>'
public_fingerprint='sha256:<64_LOWERCASE_HEX_DIGITS>'
pkcs11_uri="pkcs11:serial=${token_serial};id=%02;type=private"

policy_json="$(jq --null-input --compact-output \
  --arg schema_version 'kaiba.provisioning.yubikey-signing-policy/v1alpha1' \
  --arg signer_id "$signer_id" \
  --arg cohort_id "$cohort_id" \
  --arg provider 'yubikey-piv' \
  --arg piv_slot '9c' \
  --arg pkcs11_uri "$pkcs11_uri" \
  --arg public_key_fingerprint "$public_fingerprint" \
  --arg key_algorithm 'rsa-2048' \
  '{schema_version:$schema_version,signer_id:$signer_id,cohort_id:$cohort_id,provider:$provider,piv_slot:$piv_slot,pkcs11_uri:$pkcs11_uri,public_key_fingerprint:$public_key_fingerprint,key_algorithm:$key_algorithm,pin_required:true,touch_required:true,private_key_exportable:false}')"

policy_digest="sha256:$({
  printf '%s\0' 'kaiba.provisioning.yubikey-signing-policy.v1alpha1'
  printf '%s' "$policy_json"
} | sha256sum | cut -d ' ' -f 1)"

printf '%s\n%s\n' "$policy_json" "$policy_digest"
```

Have a second reviewer reproduce both values. The Raspberry Pi customer-key
hash is a different digest over the vendor's 264-byte key representation; the
`mkDevelopmentYubiKeySigning` build checks that separately and refuses a PEM
text hash.

## Nix construction

This repository owns one public-only, sacrificial development profile in
[`nix/development-signing.nix`](../nix/development-signing.nix). Build its
configured runtime package directly from the repository root:

```console
nix build path:.#development-signing --out-link result-development-signing
signing_path="$(readlink -f result-development-signing)"
```

That build regenerates and checks the Raspberry Pi customer-key representation
and canonical signer policy without opening PC/SC or invoking the private key.
The checked-in profile is not production-approved and its initial ceremony has
not completed the required independent second review.

Another deployment can expose its unsigned plan and configured runtime package
with the factories below. Replace every marked deployment value.
`sourceDateEpoch` must be a fixed release value, not the evaluation time.

```nix
{
  inputs = {
    kaiba.url = "github:ams-tech/nixos-kaiba-network/<PINNED_REVISION>";
    nixpkgs.follows = "kaiba/nixpkgs";
  };

  outputs = { kaiba, ... }:
    let
      system = "x86_64-linux";

      signing = kaiba.lib.mkDevelopmentYubiKeySigning {
        inherit system;
        name = "kaiba-prototype-signing";
        signerID = "signer:prototype";
        cohortID = "cohort:prototype";
        tokenSerial = "<YUBIKEY_DECIMAL_SERIAL>";
        publicKeyPEM = ./reviewed-boot-public.pem;
        publicKeyFingerprint = "sha256:<64_LOWERCASE_HEX_DIGITS>";
        signerPolicyDigest = "sha256:<64_LOWERCASE_HEX_DIGITS>";
        expectedCustomerKeyHash = "<64_LOWERCASE_HEX_DIGITS>";
        grantRegistryPath = "/etc/kaiba-provisioning/signing-grants.json";
      };

      target = kaiba.lib.mkRpi5SecureBootTarget {
        expectedCustomerKeyHash = "<64_LOWERCASE_HEX_DIGITS>";
        sourceRevision = "<40_OR_64_LOWERCASE_HEX_GIT_REVISION>";
      };

      plan = kaiba.lib.mkRpi5BootSigningPlan {
        inherit system;
        bootImage = "${target.unsignedArtifacts}/unsigned/boot.img";
        planID = "release:rpi5-prototype:1";
        reviewedPublicKeyPEM = ./reviewed-boot-public.pem;
        publicKeyFingerprint = signing.kaibaSigning.publicKeyFingerprint;
        signerPolicyDigest = signing.kaibaSigning.signerPolicyDigest;
        sourceDateEpoch = 1786968000;
      };
    in
    {
      packages.${system} = {
        development-signing = signing;
        boot-signing-plan = plan;
      };
    };
}
```

The supplied signer-policy digest is an independently reviewed expectation.
The signing package reconstructs the exact canonical policy from the signer
ID, cohort ID, token serial, fixed PIV slot and provider, and public
fingerprint; its build fails if the reconstructed digest differs. The same
package exposes the checked policy at
`kaibaSigning.signerPolicyJSON` and its digest at
`kaibaSigning.signerPolicyDigestFile`.

On the NixOS control host, the `provisioning-signing-gate` module enables
PC/SC and polkit together. Its local policy grants
`org.debian.pcsc-lite.access_pcsc` and
`org.debian.pcsc-lite.access_card` to the dedicated `kaiba-signing` service
identity, so the headless systemd service can reach the YubiKey without a
human service group or root.
It also refuses PC/SC daemon arguments that could disable polkit or enable APDU
logging.
The module does not replace upstream policy for active local-console sessions;
control-host operators must review that policy separately.

Build the two public/configured inputs. Keep named output links for the whole
review and signing ceremony so Nix garbage collection cannot remove the exact
artifacts that were reviewed:

```console
nix build path:.#boot-signing-plan --out-link result-boot-signing-plan
nix build path:.#development-signing --out-link result-development-signing
plan_path="$(readlink -f result-boot-signing-plan)"
signing_path="$(readlink -f result-development-signing)"
```

Review `plan.json`, `public.pem`, the signer policy, the public fingerprint,
and the exact `boot.img` digest before authorizing a grant. The root-managed
grant registry must contain an unexpired grant for that image digest, and the
configured signing-gate service must be running with the PIN supplied through
its systemd credential.

## Runtime signature

The gate socket is intentionally private to the `kaiba-signing` service user.
Create a fresh public handoff directory under the service state directory and
run the configured adapter as that user:

```console
sudo install -d -m 0700 -o kaiba-signing -g kaiba-signing \
  /var/lib/kaiba-provision-signing/exports

sudo -u kaiba-signing \
  "$signing_path/bin/kaiba-provision-sign-boot" sign \
  --plan "$plan_path" \
  --output /var/lib/kaiba-provision-signing/exports/rpi5-prototype-1
```

The command fails closed if the output already exists, the plan changes during
the touch wait, the configured public key changes, the plan names another
signer policy, the gate rejects the digest, or the returned signature fails
verification. The operation invokes the private key but performs no Pi, NVMe,
EEPROM, or OTP mutation.

Copy the two public output files to the release workspace through the reviewed
handoff procedure. For a local prototype, place them in `./signed-output` and
extend the flake with:

```nix
let
  signedOutput = builtins.path {
    path = ./signed-output;
    name = "kaiba-rpi5-prototype-1-signing-output";
  };
in
{
  packages.${system}.verified-signed-boot =
    kaiba.lib.mkRpi5VerifiedSignedBoot {
      inherit system;
      signingPlan = plan;
      signedOutput = signedOutput;
    };
}
```

Then build the offline-verified public bundle:

```console
nix build path:.#verified-signed-boot --out-link result-signed-boot
find -L result-signed-boot -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort
```

Using `path:.` in this local prototype includes the public, untracked
`signed-output` directory. A shared release should instead fetch that public
directory from a content-addressed artifact source with a reviewed hash.

## Safety status

Completing this workflow proves that the selected `boot.img` verifies under
the reviewed public key and that the public records are internally bound. It
does not prove a live YubiKey ceremony unless the root-managed receipt and
operator evidence are reviewed. It also does not produce a signed EEPROM,
recovery/commit bundles, a complete release manifest, target-media cold
readback, or secure-boot enforcement on hardware. Those remain prerequisites
before any one-time setting may be changed.
