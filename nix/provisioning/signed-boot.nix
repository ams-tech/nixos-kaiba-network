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
      releaseIntent,
      reviewedPublicKeyPEM,
      signerPolicyDigest,
      sourceDateEpoch,
      name ? "kaiba-rpi5-boot-signing-plan",
    }:
    assert lib.assertMsg (storeBacked bootImage) "bootImage must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked reviewedPublicKeyPEM)
      "reviewedPublicKeyPEM must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked releaseIntent) "releaseIntent must be a fixed Nix-store path";
    assert lib.assertMsg (canonicalIdentifier planID) "planID must be a canonical identifier";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest signerPolicyDigest)
      "signerPolicyDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalEpoch sourceDateEpoch)
      "sourceDateEpoch must be an integer Unix timestamp from 0 through 253402300799";
    pkgs.runCommand name
      {
        # Keep both public inputs in the derivation environment as well as the
        # generated script.  Shell escaping can discard Nix string context for
        # a path nested below a flake source, which would otherwise leave that
        # path unavailable inside the build sandbox.
        bootImageInput = bootImage;
        releaseIntentInput = releaseIntent;
        reviewedPublicKeyInput = reviewedPublicKeyPEM;
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
            releaseIntent
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
          schemaVersion = "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2";
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

        test -f "$bootImageInput"
        test ! -L "$bootImageInput"
        test -s "$bootImageInput"
        test -f "$reviewedPublicKeyInput"
        test ! -L "$reviewedPublicKeyInput"
        test -s "$reviewedPublicKeyInput"
        test -d "$releaseIntentInput"
        test ! -L "$releaseIntentInput"
        test -f "$releaseIntentInput/release-intent.json"
        test ! -L "$releaseIntentInput/release-intent.json"

        release_intent_json="$(cat "$releaseIntentInput/release-intent.json")"
        test "$(printf '%s' "$release_intent_json" | jq --compact-output .)" = \
          "$release_intent_json"
        test "$(printf '%s' "$release_intent_json" | jq -r .schema_version)" = \
          'kaiba.provisioning.rpi5-release-intent/v1alpha1'
        test "$(printf '%s' "$release_intent_json" | jq -r .source_date_epoch)" = \
          '${toString sourceDateEpoch}'
        test "$(printf '%s' "$release_intent_json" | jq -r .public_key_fingerprint)" = \
          '${publicKeyFingerprint}'
        test "$(printf '%s' "$release_intent_json" | jq -r .signing_policy_digest)" = \
          '${signerPolicyDigest}'
        release_intent_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-release-intent.v1alpha1'
          printf '%s' "$release_intent_json"
        } | sha256sum | cut -d ' ' -f 1)"

        mkdir -p "$out"
        install -m 0444 "$bootImageInput" "$out/boot.img"
        install -m 0444 \
          "$releaseIntentInput/release-intent.json" \
          "$out/release-intent.json"

        # `openssl rsa` rejects non-RSA public keys. Re-emitting and comparing
        # it also requires the reviewed input to be one canonical PUBLIC KEY
        # PEM block with no ignored headers or trailing data.
        openssl rsa \
          -pubin \
          -in "$reviewedPublicKeyInput" \
          -pubout \
          -out "$out/public.pem"
        cmp "$reviewedPublicKeyInput" "$out/public.pem"
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
        jq -e \
          --arg digest "$boot_image_digest" \
          --argjson size_bytes "$boot_image_size_bytes" \
          '[.signing_inputs[] | select(.role == "rpi5.boot_image")]
           == [{role: "rpi5.boot_image", digest: $digest, size_bytes: $size_bytes}]' \
          "$out/release-intent.json" > /dev/null

        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2' \
          --arg plan_id '${planID}' \
          --arg release_intent_digest "$release_intent_digest" \
          --arg boot_image_digest "$boot_image_digest" \
          --argjson boot_image_size_bytes "$boot_image_size_bytes" \
          --arg public_key_fingerprint "$actual_public_key_fingerprint" \
          --arg signer_policy_digest '${signerPolicyDigest}' \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            release_intent_digest: $release_intent_digest,
            boot_image_digest: $boot_image_digest,
            boot_image_size_bytes: $boot_image_size_bytes,
            public_key_fingerprint: $public_key_fingerprint,
            signer_policy_digest: $signer_policy_digest,
            source_date_epoch: $source_date_epoch
          }' > "$out/plan.json"
        chmod 0444 "$out/plan.json"

        find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' boot.img plan.json public.pem release-intent.json \
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
          release-intent.json \
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
