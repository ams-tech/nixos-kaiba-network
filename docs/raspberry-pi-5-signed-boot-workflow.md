# Raspberry Pi 5 signed-boot workflow

This workflow constructs the public release-intent lineage, then produces and
verifies a signed `boot.img` without writing target media, programming EEPROM,
or changing OTP. Nix builds only public artifacts. The private key remains
behind the fixed, approval-gated YubiKey service and is used only by an
explicit runtime command.

## Boundaries and outputs

`mkRpi5ReleaseIntent` is the pure, pre-signature authorization boundary. Its
v1alpha1 document binds the release ID, device class, clean source revision,
fixed source epoch, unsigned-artifact-set digest, pinned EEPROM-release
manifest digest, public-key fingerprint, signing-policy digest, expected
customer-key hash, exact signing inputs, and exact required signed-release
roles. It fixes `authorization_scope` to `cohort_release` and emits exactly:

```text
release-intent.json
```

The signing inputs are exactly these five immutable byte records, in canonical
role order:

```text
rpi5.boot_image
rpi5.eeprom_bootcode
rpi5.eeprom_bootsys
rpi5.eeprom_config
rpi5.owned_recovery_bootcode
```

The required final outputs are exactly these 18 roles, also in canonical role
order:

```text
boot_public_key
device_profile
platform_adapter
root_integrity
rpi5.boot_image
rpi5.boot_signature
rpi5.eeprom_bootsys
rpi5.eeprom_config
rpi5.fresh_commit_bundle
rpi5.fresh_readback_bundle
rpi5.negative_boot_bundle
rpi5.owned_readback_bundle
rpi5.owned_recovery_bootcode
rpi5.owned_recovery_bundle
rpi5.root_data_image
rpi5.root_hash_tree_image
rpi5.root_integrity_test_bundle
rpi5.signed_eeprom_image
```

`rpi5.eeprom_bootcode` is deliberately a signing-only intermediate; it does
not add a nineteenth role to the final signed-release manifest.

`mkRpi5BootSigningPlan` is a pure derivation. Its inputs are an already-built
`boot.img`, the canonical release-intent output, a reviewed RSA-2048 public
key, that key's canonical SPKI SHA-256 fingerprint, the reviewed signer-policy
digest, a plan ID, and the same fixed timestamp. Its v1alpha2 plan verifies
that the release intent authorizes the exact boot-image digest and size and
emits exactly:

```text
boot.img
plan.json
public.pem
release-intent.json
```

`mkDevelopmentYubiKeySigning` builds the runtime adapter. The package fixes the
signing-gate socket, signer/cohort IDs, YKCS11 URI, public-key path, and public
fingerprint at link time. The `sign` command accepts only a plan directory and
a new output directory; it has no runtime key, URI, provider, module, socket,
algorithm, or PIN selector. The v1alpha2 grant, signing request, gate response,
and signing result must all carry the same `release_intent_digest`, artifact
role, and artifact digest. It emits exactly:

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
release-intent.json
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

The v1alpha2 signed-boot plan and result reject v1alpha1 records instead of
silently treating them as lineage-aware. The offline finalizer revalidates the
embedded release intent, its domain-separated digest, the boot input, signer
metadata, plan/result lineage, and signature before copying
`release-intent.json` into the public bundle. That bundle's `manifest.json` is
still the narrow signed-boot slice; it is not the complete 18-role
`rpi5-signed-release-manifest/v1alpha2`.

### Release authorization is not device execution authorization

The release intent answers a cohort-level question: may this exact set of five
public byte strings be signed under this reviewed key and policy, with all 18
outputs required before the release is complete? It intentionally contains no
station, lane, target, transaction, claim, fence, or execution expiry. A valid
release intent and signing receipt therefore grant no authority to write a
device or change OTP.

Per-device execution authorization is created later, after all signed outputs
exist. The complete signed-release manifest v1alpha2 includes the same
`release_intent_digest`; only its final manifest digest can then be bound into
the lane plan and control approval for one exact transaction, target, lane,
fence, and expiry. Keeping the order
`release intent -> signing grants and receipts -> signed-release manifest ->
device execution plan` avoids a cycle while keeping release signing separate
from one-shot hardware authority.

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

### Build the repository prototype release inputs

The root flake now binds that development profile to one concrete Pi 5 target.
Run these commands from a clean Git checkout; evaluation fails closed when the
source revision is dirty or unavailable:

```console
nix build path:.#packages.aarch64-linux.rpi5-prototype-unsigned-artifacts \
  --out-link result-rpi5-prototype-unsigned-artifacts
nix build path:.#rpi5-prototype-signing-plan \
  --out-link result-rpi5-prototype-signing-plan
nix build path:.#rpi5-prototype-release-review \
  --out-link result-rpi5-prototype-release-review
```

On an x86_64 host, all three builds require Nix to be configured with an
AArch64 builder or `aarch64-linux` emulation. The target-system closure, raw
root image, dm-verity hash tree, and 96 MiB FAT boot image make the first build
substantially slower and larger than the public signer-contract build.

The signing plan ID contains the first 12 hexadecimal characters of the clean
source revision, and its timestamp is the flake's fixed commit timestamp. A
source change therefore creates a different release identity instead of
silently reusing a plan ID. Inspect the completed public review with:

```console
jq . result-rpi5-prototype-unsigned-artifacts/manifest.json
jq . result-rpi5-prototype-signing-plan/plan.json
jq . result-rpi5-prototype-signing-plan/release-intent.json
jq . result-rpi5-prototype-release-review/review.json
cmp \
  result-rpi5-prototype-unsigned-artifacts/unsigned/boot.img \
  result-rpi5-prototype-signing-plan/boot.img
```

The review revalidates the JSON schemas, every artifact digest, the canonical
unsigned-bundle and release-intent digests, the exact five signing inputs and
18 required output roles, the dm-verity tree and boot command line, the
reviewed PEM and SPKI fingerprint, the Raspberry Pi customer-key
representation, and the signer-policy digest. These builds have no PC/SC,
YubiKey, private-key, signing-grant, block-device, EEPROM-device, or OTP
access. Their result is still an unsigned artifact set, a cohort-scoped public
release intent, and a public signing plan—not a signed release or authority to
change a board.

Another deployment can expose its reviewed release intent, unsigned plan, and
configured runtime package with the factories below. Replace every marked
deployment value. `releaseIntent` must be a fixed output of
`mkRpi5ReleaseIntent`, not hand-authored JSON; the abbreviated binding below
assumes that reviewed output is available as `releaseIntent`.
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

      # Construct this with mkRpi5ReleaseIntent from the target's unsigned
      # artifacts, the pinned EEPROM release, and the exact five signing
      # inputs listed above.
      releaseIntent = ./reviewed-release-intent;

      plan = kaiba.lib.mkRpi5BootSigningPlan {
        inherit system;
        bootImage = "${target.unsignedArtifacts}/unsigned/boot.img";
        planID = "release:rpi5-prototype:1";
        inherit releaseIntent;
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

Review `release-intent.json`, `plan.json`, `public.pem`, the signer policy, the
public fingerprint, and the exact `boot.img` digest and size before authorizing
a grant. The root-managed v1alpha2 grant registry must contain an unexpired
grant whose release-intent digest, role `rpi5.boot_image`, and artifact digest
all match the plan. A grant for only the image digest is insufficient. The
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

The command fails closed if the output already exists, the plan or release
intent changes during the touch wait, the configured public key changes, the
plan names another signer policy, the gate returns another release-intent
lineage, the grant does not bind the boot role and digest, or the returned
signature fails verification. The operation invokes the private key but
performs no Pi, NVMe, EEPROM, or OTP mutation.

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

The verified bundle is not yet the four-role unfused capsule. Assemble it with
the exact root-data and root-hash images from the same reviewed unsigned
artifact set by using `mkRpi5VerifiedUnfusedCapsule`. That derivation refuses a
signer anchor that differs from the signing plan, constructs the pinned
verifier internally, and refuses a signed boot image that differs from the
unsigned artifact set or embeds a different dm-verity root hash. It emits the
strict capsule manifest, a clearly synthetic fixture, and the signer-anchored
offline result described in the
[Raspberry Pi 5 unfused compatibility prototype](raspberry-pi-5-unfused-compatibility.md).

This is still an offline public build. It neither contacts the YubiKey nor
touches a Pi, EEPROM, OTP, removable medium, or block device. Changing the boot
or root artifacts invalidates the bindings and requires review and a new
signature rather than silently reusing this result.

## EEPROM fresh-board foundation boundary

The repository also contains a public EEPROM fresh-board signing plan,
approval-gated adapter, and offline finalizer. They bind the same
`release_intent_digest` and model the pinned updater's `-f` path over exactly
`rpi5.eeprom_bootcode`, `rpi5.eeprom_bootsys`, and `rpi5.eeprom_config`. The
finalizer reopens the public plan and result, verifies the signatures and
derived files, and admits only that verified public snapshot.

This is a synthetic/offline foundation only. Current repository evidence does
not establish that a reviewed production input was signed with a live approved
token, and an output named `pieeprom.bin` from a synthetic fixture is not the
production signed-EEPROM deliverable. The fresh-board plan deliberately copies
the pinned unsigned recovery payload; it does not customer-counter-sign owned
recovery. It also does not produce the fresh commit or owned recovery bundles,
write EEPROM or target media, enter RPIBOOT, change OTP, or report any hardware
result. The separately authorized `rpi5.owned_recovery_bootcode` input remains
for a later recovery-signing workflow.

## Safety status

Completing this workflow proves that the selected `boot.img` verifies under
the reviewed public key and that the v1alpha2 public records carry one valid
release-intent lineage. It does not prove a live YubiKey ceremony unless the
root-managed receipt and operator evidence are reviewed. The repository's
v1alpha2 exact 18-role signed-release manifest and canonical RPIBOOT
directory-tree contracts do not change that boundary: this workflow does not
produce a production signed EEPROM, signed recovery/commit bundles, an
assembled complete signed release with every role resolved to immutable bytes,
target-media cold readback, per-device execution authorization, or secure-boot
enforcement on hardware. Those remain prerequisites before any one-time
setting may be changed.
