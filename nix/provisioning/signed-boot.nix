{
  pkgs,
  lib,
  signedBootTool,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalIdentifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
  cleanAbsolute =
    value:
    builtins.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !(lib.hasInfix "//" value)
    && !(lib.hasInfix "/./" value)
    && !(lib.hasInfix "/../" value)
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value);
  storeBacked =
    value: cleanAbsolute (toString value) && lib.hasPrefix "${builtins.storeDir}/" (toString value);
  canonicalEpoch = value: builtins.isInt value && value >= 0 && value <= 253402300799;

  # A signing plan is public, deterministic build output. It contains the boot
  # image and reviewed public key, but no key locator, credential, private key,
  # or signing authority. The signature is produced later by an explicit
  # runtime operation outside the Nix build sandbox.
  mkRpi5BootSigningPlan =
    {
      bootImage,
      planID,
      publicKeyFingerprint,
      reviewedPublicKeyPEM,
      signerPolicyDigest,
      sourceDateEpoch,
      name ? "kaiba-rpi5-boot-signing-plan",
    }:
    assert lib.assertMsg (storeBacked bootImage) "bootImage must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked reviewedPublicKeyPEM)
      "reviewedPublicKeyPEM must be a fixed Nix-store path";
    assert lib.assertMsg (canonicalIdentifier planID) "planID must be a canonical identifier";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest signerPolicyDigest)
      "signerPolicyDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalEpoch sourceDateEpoch)
      "sourceDateEpoch must be an integer Unix timestamp from 0 through 253402300799";
    let
      bootImageArgument = lib.escapeShellArg (toString bootImage);
      reviewedPublicKeyArgument = lib.escapeShellArg (toString reviewedPublicKeyPEM);
    in
    pkgs.runCommand name
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.jq
          pkgs.openssl
        ];
        passthru.kaibaBootSigningPlan = {
          inherit
            bootImage
            planID
            publicKeyFingerprint
            reviewedPublicKeyPEM
            signerPolicyDigest
            sourceDateEpoch
            ;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          schemaVersion = "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1";
          signingAuthorityConfigured = false;
        };
        meta = {
          description = "Deterministic public Raspberry Pi 5 boot signing plan";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        test -f ${bootImageArgument}
        test ! -L ${bootImageArgument}
        test -s ${bootImageArgument}
        test -f ${reviewedPublicKeyArgument}
        test ! -L ${reviewedPublicKeyArgument}
        test -s ${reviewedPublicKeyArgument}

        mkdir -p "$out"
        install -m 0444 ${bootImageArgument} "$out/boot.img"

        # `openssl rsa` rejects non-RSA public keys. Re-emitting and comparing
        # it also requires the reviewed input to be one canonical PUBLIC KEY
        # PEM block with no ignored headers or trailing data.
        openssl rsa \
          -pubin \
          -in ${reviewedPublicKeyArgument} \
          -pubout \
          -out "$out/public.pem"
        cmp ${reviewedPublicKeyArgument} "$out/public.pem"
        test "$(
          openssl pkey -pubin -in "$out/public.pem" -text -noout | sed -n '1p'
        )" = 'Public-Key: (2048 bit)'
        openssl pkey -pubin -in "$out/public.pem" -text -noout \
          | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
        chmod 0444 "$out/public.pem"

        actual_public_key_fingerprint="sha256:$(
          openssl pkey -pubin -in "$out/public.pem" -outform DER \
            | sha256sum | cut -d ' ' -f 1
        )"
        test "$actual_public_key_fingerprint" = '${publicKeyFingerprint}'

        boot_image_digest="sha256:$(sha256sum "$out/boot.img" | cut -d ' ' -f 1)"
        boot_image_size_bytes="$(stat --format=%s "$out/boot.img")"
        test "$boot_image_size_bytes" -gt 0
        test "$boot_image_size_bytes" -le 100663296

        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1' \
          --arg plan_id '${planID}' \
          --arg boot_image_digest "$boot_image_digest" \
          --argjson boot_image_size_bytes "$boot_image_size_bytes" \
          --arg public_key_fingerprint "$actual_public_key_fingerprint" \
          --arg signer_policy_digest '${signerPolicyDigest}' \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            boot_image_digest: $boot_image_digest,
            boot_image_size_bytes: $boot_image_size_bytes,
            public_key_fingerprint: $public_key_fingerprint,
            signer_policy_digest: $signer_policy_digest,
            source_date_epoch: $source_date_epoch
          }' > "$out/plan.json"
        chmod 0444 "$out/plan.json"

        find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' boot.img plan.json public.pem \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"
      '';

  # Finalization admits only a public, externally produced signed result into
  # the Nix store. The Go verifier checks the plan/result/signature bindings
  # and emits a self-contained bundle; this derivation never invokes a signer.
  mkRpi5VerifiedSignedBoot =
    {
      signingPlan,
      signedOutput,
      name ? "kaiba-rpi5-verified-signed-boot",
    }:
    assert lib.assertMsg (storeBacked signingPlan) "signingPlan must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked signedOutput) "signedOutput must be a fixed Nix-store path";
    let
      signingPlanArgument = lib.escapeShellArg (toString signingPlan);
      signedOutputArgument = lib.escapeShellArg (toString signedOutput);
      signedBootToolArgument = lib.escapeShellArg (toString signedBootTool);
    in
    pkgs.runCommand name
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
        ];
        passthru.kaibaVerifiedSignedBoot = {
          inherit signedBootTool signedOutput signingPlan;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          signatureVerificationRequired = true;
          signingAuthorityConfigured = false;
          verificationMode = "pure_offline";
        };
        meta = {
          description = "Verified public Raspberry Pi 5 signed-boot bundle";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        test -d ${signingPlanArgument}
        test ! -L ${signingPlanArgument}
        test -d ${signedOutputArgument}
        test ! -L ${signedOutputArgument}

        ${signedBootToolArgument}/bin/kaiba-provision-sign-boot finalize \
          --plan ${signingPlanArgument} \
          --signed ${signedOutputArgument} \
          --output "$out"

        find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-bundle-files"
        printf '%s\n' \
          boot.img \
          boot.sig \
          manifest.json \
          public.pem \
          signing-plan.json \
          signing-result.json \
          > "$TMPDIR/expected-bundle-files"
        cmp "$TMPDIR/expected-bundle-files" "$TMPDIR/actual-bundle-files"
        chmod 0444 "$out"/*
      '';
in
{
  inherit mkRpi5BootSigningPlan mkRpi5VerifiedSignedBoot;
}
