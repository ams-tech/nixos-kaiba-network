{
  pkgs,
  lib,
  eepromRelease,
  eepromSigningTool,
  eepromToolRuntime,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalIdentifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
  canonicalEpoch = value: builtins.isInt value && value > 0 && value <= 253402300799;
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
  eepromBootConfigValidator = pkgs.writeShellScript "kaiba-validate-rpi5-eeprom-boot-config" ''
    set -euo pipefail
    test "$#" -eq 1
    test -f "$1"
    test ! -L "$1"
    readonly size="$(${pkgs.coreutils}/bin/stat --format=%s "$1")"
    test "$size" -ge 1
    test "$size" -le 4076
  '';
  eepromPublicKeyValidator = pkgs.writeShellScript "kaiba-validate-rpi5-eeprom-public-key" ''
    set -euo pipefail
    test "$#" -eq 1
    test -f "$1"
    test ! -L "$1"
    test "$(
      ${pkgs.openssl}/bin/openssl pkey -pubin -in "$1" -text -noout \
        | ${pkgs.gnused}/bin/sed -n '1p'
    )" = 'Public-Key: (2048 bit)'
    test "$(
      ${pkgs.openssl}/bin/openssl pkey -pubin -in "$1" -text -noout \
        | ${pkgs.gnused}/bin/sed -n 's/^Exponent: //p'
    )" = '65537 (0x10001)'
  '';

  # This derivation contains only public inputs. It fixes the exact `-f`
  # updater mode and hashes the three callback byte strings, but never invokes
  # a signer or the updater.
  mkRpi5EEPROMSigningPlan =
    {
      bootConfig,
      customerKeyHash,
      eepromSigningInputs,
      planID,
      publicKeyFingerprint,
      releaseIntent,
      reviewedPublicKeyPEM,
      signerPolicyDigest,
      sourceDateEpoch,
      name ? "kaiba-rpi5-eeprom-signing-plan",
    }:
    assert lib.assertMsg (canonicalIdentifier planID) "planID must be a canonical identifier";
    assert lib.assertMsg (canonicalDigest customerKeyHash) "customerKeyHash must be canonical";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must be canonical";
    assert lib.assertMsg (canonicalDigest signerPolicyDigest) "signerPolicyDigest must be canonical";
    assert lib.assertMsg (canonicalEpoch sourceDateEpoch)
      "sourceDateEpoch must be a positive canonical Unix timestamp";
    assert lib.assertMsg (lib.all storeBacked [
      bootConfig
      eepromSigningInputs
      releaseIntent
      reviewedPublicKeyPEM
    ]) "every EEPROM signing-plan input must be a fixed Nix-store path";
    pkgs.runCommand name
      {
        bootConfigInput = bootConfig;
        eepromReleaseInput = eepromRelease;
        eepromSigningInputsInput = eepromSigningInputs;
        releaseIntentInput = releaseIntent;
        reviewedPublicKeyInput = reviewedPublicKeyPEM;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
        ];
        passthru.kaibaRpi5EEPROMSigningPlan = {
          inherit
            bootConfig
            customerKeyHash
            eepromSigningInputs
            planID
            publicKeyFingerprint
            releaseIntent
            reviewedPublicKeyPEM
            signerPolicyDigest
            sourceDateEpoch
            ;
          eepromRelease = eepromRelease;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          recoverySigningPerformed = false;
          schemaVersion = "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1";
          signedEEPROMProduced = false;
          signingAuthorityConfigured = false;
          updaterFlags = [ "-f" ];
          updaterMode = "fresh-board";
        };
        passthru.eepromBootConfigValidator = eepromBootConfigValidator;
        passthru.eepromPublicKeyValidator = eepromPublicKeyValidator;
        meta = {
          description = "Deterministic public Raspberry Pi 5 fresh-board EEPROM signing plan";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        readonly release_manifest="$eepromReleaseInput/release.json"
        readonly intent_source="$releaseIntentInput/release-intent.json"
        readonly bootcode_source="$eepromReleaseInput/firmware/components/bootcode.bin"
        readonly bootsys_source="$eepromReleaseInput/firmware/components/bootsys"
        readonly eeprom_source="$eepromReleaseInput/firmware/pieeprom.original.bin"
        readonly recovery_source="$eepromReleaseInput/firmware/recovery.original.bin"
        for input in \
          "$release_manifest" \
          "$intent_source" \
          "$bootcode_source" \
          "$bootsys_source" \
          "$eeprom_source" \
          "$recovery_source" \
          "$bootConfigInput" \
          "$reviewedPublicKeyInput"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done
        test -d "$eepromSigningInputsInput"
        test ! -L "$eepromSigningInputsInput"
        ${eepromBootConfigValidator} "$bootConfigInput"
        find "$eepromSigningInputsInput" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
          | sort > "$TMPDIR/actual-input-files"
        printf '%s\n' \
          eeprom-bootcode.signing-input \
          eeprom-bootsys.signing-input \
          eeprom-config.signing-input \
          owned-recovery-bootcode.signing-input \
          > "$TMPDIR/expected-input-files"
        cmp "$TMPDIR/expected-input-files" "$TMPDIR/actual-input-files"

        mkdir "$out"
        install -m 0444 "$eeprom_source" "$out/pieeprom.original.bin"
        install -m 0444 "$recovery_source" "$out/recovery.original.bin"
        install -m 0444 "$bootcode_source" "$out/bootcode.original.bin"
        install -m 0444 "$bootsys_source" "$out/bootsys.original"
        install -m 0444 "$bootConfigInput" "$out/boot.conf"
        install -m 0444 "$intent_source" "$out/release-intent.json"

        cmp "$out/boot.conf" "$eepromSigningInputsInput/eeprom-config.signing-input"
        ${pkgs.python3}/bin/python3 - \
          "$out/bootcode.original.bin" "$TMPDIR/eeprom-bootcode.signing-input" \
          "$out/bootsys.original" "$TMPDIR/eeprom-bootsys.signing-input" \
          "$out/recovery.original.bin" "$TMPDIR/owned-recovery-bootcode.signing-input" <<'PY'
        import pathlib
        import struct
        import sys

        arguments = sys.argv[1:]
        for index in range(0, len(arguments), 2):
            original = pathlib.Path(arguments[index]).read_bytes()
            pathlib.Path(arguments[index + 1]).write_bytes(
                original + struct.pack("<III", len(original), 16, 0)
            )
        PY
        cmp \
          "$TMPDIR/eeprom-bootcode.signing-input" \
          "$eepromSigningInputsInput/eeprom-bootcode.signing-input"
        cmp \
          "$TMPDIR/eeprom-bootsys.signing-input" \
          "$eepromSigningInputsInput/eeprom-bootsys.signing-input"
        cmp \
          "$TMPDIR/owned-recovery-bootcode.signing-input" \
          "$eepromSigningInputsInput/owned-recovery-bootcode.signing-input"

        openssl pkey \
          -pubin \
          -in "$reviewedPublicKeyInput" \
          -pubout \
          -out "$out/public.pem"
        cmp "$reviewedPublicKeyInput" "$out/public.pem"
        ${eepromPublicKeyValidator} "$out/public.pem"
        actual_public_key_fingerprint="sha256:$({
          openssl pkey -pubin -in "$out/public.pem" -outform DER
        } | sha256sum | cut -d ' ' -f 1)"
        test "$actual_public_key_fingerprint" = '${publicKeyFingerprint}'
        ${eepromToolRuntime}/bin/rpi-bootloader-key-convert \
          "$out/public.pem" \
          --output "$TMPDIR/customer-public-key.bin"
        test "$(stat --format=%s "$TMPDIR/customer-public-key.bin")" -eq 264
        actual_customer_key_hash="sha256:$(
          sha256sum "$TMPDIR/customer-public-key.bin" | cut -d ' ' -f 1
        )"
        test "$actual_customer_key_hash" = '${customerKeyHash}'

        release_intent_json="$(cat "$out/release-intent.json")"
        test "$(printf '%s' "$release_intent_json" | jq --compact-output .)" = \
          "$release_intent_json"
        release_intent_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-release-intent.v1alpha1'
          printf '%s' "$release_intent_json"
        } | sha256sum | cut -d ' ' -f 1)"
        eeprom_release_manifest_digest="sha256:$(
          sha256sum "$release_manifest" | cut -d ' ' -f 1
        )"
        test "$eeprom_release_manifest_digest" = \
          '${eepromRelease.kaibaRpi5EEPROMRelease.releaseManifestDigest}'

        file_record() {
          local path="$1"
          jq \
            --null-input \
            --compact-output \
            --arg digest "sha256:$(sha256sum "$path" | cut -d ' ' -f 1)" \
            --argjson size_bytes "$(stat --format=%s "$path")" \
            '{digest: $digest, size_bytes: $size_bytes}'
        }
        signing_input() {
          local role="$1"
          local path="$2"
          jq \
            --null-input \
            --compact-output \
            --arg role "$role" \
            --arg digest "sha256:$(sha256sum "$path" | cut -d ' ' -f 1)" \
            --argjson size_bytes "$(stat --format=%s "$path")" \
            '{role: $role, digest: $digest, size_bytes: $size_bytes}'
        }
        signing_inputs="$(jq \
          --null-input \
          --compact-output \
          --argjson bootcode "$(signing_input \
            rpi5.eeprom_bootcode \
            "$eepromSigningInputsInput/eeprom-bootcode.signing-input")" \
          --argjson bootsys "$(signing_input \
            rpi5.eeprom_bootsys \
            "$eepromSigningInputsInput/eeprom-bootsys.signing-input")" \
          --argjson config "$(signing_input \
            rpi5.eeprom_config \
            "$eepromSigningInputsInput/eeprom-config.signing-input")" \
          '[$bootcode, $bootsys, $config]')"
        owned_recovery_input="$(signing_input \
          rpi5.owned_recovery_bootcode \
          "$eepromSigningInputsInput/owned-recovery-bootcode.signing-input")"
        jq -e \
          --arg release_intent_digest "$release_intent_digest" \
          --arg eeprom_release_manifest_digest "$eeprom_release_manifest_digest" \
          --arg public_key_fingerprint "$actual_public_key_fingerprint" \
          --arg signing_policy_digest '${signerPolicyDigest}' \
          --arg customer_key_hash "$actual_customer_key_hash" \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          --argjson signing_inputs "$signing_inputs" \
          --argjson owned_recovery_input "$owned_recovery_input" \
          '
            .schema_version == "kaiba.provisioning.rpi5-release-intent/v1alpha1"
            and .source_date_epoch == $source_date_epoch
            and .eeprom_release_manifest_digest == $eeprom_release_manifest_digest
            and .public_key_fingerprint == $public_key_fingerprint
            and .signing_policy_digest == $signing_policy_digest
            and .expected_customer_key_hash == $customer_key_hash
            and [.signing_inputs[] | select(
              .role == "rpi5.eeprom_bootcode"
              or .role == "rpi5.eeprom_bootsys"
              or .role == "rpi5.eeprom_config"
            )] == $signing_inputs
            and [.signing_inputs[] | select(.role == "rpi5.owned_recovery_bootcode")]
              == [$owned_recovery_input]
          ' "$out/release-intent.json" > /dev/null

        firmware_build_epoch="$(jq -r .firmware.build_epoch "$release_manifest")"
        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1' \
          --arg plan_id '${planID}' \
          --arg release_intent_digest "$release_intent_digest" \
          --arg eeprom_release_manifest_digest "$eeprom_release_manifest_digest" \
          --arg signer_policy_digest '${signerPolicyDigest}' \
          --arg public_key_fingerprint "$actual_public_key_fingerprint" \
          --arg customer_key_hash "$actual_customer_key_hash" \
          --argjson firmware_build_epoch "$firmware_build_epoch" \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          --arg updater_mode 'fresh-board' \
          --argjson updater_flags '["-f"]' \
          --argjson original_eeprom "$(file_record "$out/pieeprom.original.bin")" \
          --argjson original_recovery "$(file_record "$out/recovery.original.bin")" \
          --argjson original_bootcode "$(file_record "$out/bootcode.original.bin")" \
          --argjson original_bootsys "$(file_record "$out/bootsys.original")" \
          --argjson boot_config "$(file_record "$out/boot.conf")" \
          --argjson public_key_pem "$(file_record "$out/public.pem")" \
          --argjson signing_inputs "$signing_inputs" \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            release_intent_digest: $release_intent_digest,
            eeprom_release_manifest_digest: $eeprom_release_manifest_digest,
            signer_policy_digest: $signer_policy_digest,
            public_key_fingerprint: $public_key_fingerprint,
            customer_key_hash: $customer_key_hash,
            firmware_build_epoch: $firmware_build_epoch,
            source_date_epoch: $source_date_epoch,
            updater_mode: $updater_mode,
            updater_flags: $updater_flags,
            original_eeprom: $original_eeprom,
            original_recovery: $original_recovery,
            original_bootcode: $original_bootcode,
            original_bootsys: $original_bootsys,
            boot_config: $boot_config,
            public_key_pem: $public_key_pem,
            signing_inputs: $signing_inputs
          }' > "$out/plan.json"
        chmod 0444 "$out/plan.json" "$out/public.pem"

        find "$out" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' \
          boot.conf \
          bootcode.original.bin \
          bootsys.original \
          pieeprom.original.bin \
          plan.json \
          public.pem \
          recovery.original.bin \
          release-intent.json \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"
      '';

  # Finalization admits externally produced public bytes only after the CLI
  # re-extracts the EEPROM with the pinned helper and verifies every embedded
  # signature and lineage binding.
  mkRpi5VerifiedSignedEEPROM =
    {
      signedOutput,
      signingPlan,
      name ? "kaiba-rpi5-verified-signed-eeprom",
    }:
    assert lib.assertMsg (storeBacked signedOutput) "signedOutput must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked signingPlan) "signingPlan must be a fixed Nix-store path";
    pkgs.runCommand name
      {
        signedOutputInput = signedOutput;
        signingPlanInput = signingPlan;
        nativeBuildInputs = [ pkgs.findutils ];
        passthru.kaibaVerifiedSignedEEPROM = {
          inherit signedOutput signingPlan;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          recoverySigningPerformed = false;
          signatureVerificationRequired = true;
          signingAuthorityConfigured = false;
          verificationMode = "pure_offline";
        };
        meta = {
          description = "Verified public Raspberry Pi 5 signed-EEPROM bundle";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        ${eepromSigningTool}/bin/kaiba-provision-sign-eeprom finalize \
          --plan "$signingPlanInput" \
          --signed "$signedOutputInput" \
          --output "$out"

        find "$out" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
          > "$TMPDIR/actual-files"
        printf '%s\n' \
          boot.conf \
          bootcode.original.bin \
          bootcode.signed.bin \
          bootcode5.bin \
          bootconf.sig \
          bootconf.signed.txt \
          bootsys.original \
          bootsys.signed \
          cacert.der \
          pieeprom.bin \
          pieeprom.original.bin \
          pieeprom.sig \
          plan.json \
          pubkey.bin \
          public.pem \
          recovery.original.bin \
          release-intent.json \
          result.json \
          updatetime \
          > "$TMPDIR/expected-files"
        cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
        chmod 0444 "$out"/*
      '';
in
{
  inherit mkRpi5EEPROMSigningPlan mkRpi5VerifiedSignedEEPROM;
}
