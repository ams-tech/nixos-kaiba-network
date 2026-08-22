{
  pkgs,
  lib,
  eepromSigningTool,
}:

let
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

  mkRpi5OwnedRecoverySigningPlan =
    {
      freshSigningPlan,
      planID,
      verifiedSignedEEPROM,
      name ? "kaiba-rpi5-owned-recovery-signing-plan",
    }:
    assert lib.assertMsg (canonicalIdentifier planID) "planID must be a canonical identifier";
    assert lib.assertMsg (lib.all storeBacked [
      freshSigningPlan
      verifiedSignedEEPROM
    ]) "owned-recovery plan inputs must be fixed Nix-store paths";
    assert lib.assertMsg (
      freshSigningPlan ? kaibaRpi5EEPROMSigningPlan
    ) "freshSigningPlan must be produced by mkRpi5EEPROMSigningPlan";
    assert lib.assertMsg (
      verifiedSignedEEPROM ? kaibaVerifiedSignedEEPROM
    ) "verifiedSignedEEPROM must be produced by mkRpi5VerifiedSignedEEPROM";
    assert lib.assertMsg (
      toString verifiedSignedEEPROM.kaibaVerifiedSignedEEPROM.signingPlan == toString freshSigningPlan
    ) "verifiedSignedEEPROM must finalize the exact freshSigningPlan";
    pkgs.runCommand name
      {
        freshSigningPlanInput = freshSigningPlan;
        verifiedSignedEEPROMInput = verifiedSignedEEPROM;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          pkgs.python3
        ];
        passthru.kaibaRpi5OwnedRecoverySigningPlan = {
          inherit freshSigningPlan planID verifiedSignedEEPROM;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          newSigningInputCount = 1;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          recoverySigningPerformed = false;
          reusedFreshSignatureCount = 3;
          schemaVersion = "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1";
          signingAuthorityConfigured = false;
          updaterFlags = [
            "-f"
            "-r"
          ];
          updaterMode = "owned-recovery";
        };
        meta = {
          description = "Public one-input Raspberry Pi 5 owned-recovery signing plan";
          platforms = [
            "x86_64-linux"
            "aarch64-linux"
          ];
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        readonly fresh_plan="$freshSigningPlanInput/plan.json"
        readonly fresh_result="$verifiedSignedEEPROMInput/result.json"
        for input in \
          "$fresh_plan" \
          "$freshSigningPlanInput/release-intent.json" \
          "$freshSigningPlanInput/pieeprom.original.bin" \
          "$freshSigningPlanInput/recovery.original.bin" \
          "$freshSigningPlanInput/bootcode.original.bin" \
          "$freshSigningPlanInput/bootsys.original" \
          "$freshSigningPlanInput/boot.conf" \
          "$freshSigningPlanInput/public.pem" \
          "$fresh_result" \
          "$verifiedSignedEEPROMInput/pieeprom.bin" \
          "$verifiedSignedEEPROMInput/pieeprom.sig" \
          "$verifiedSignedEEPROMInput/bootcode5.bin"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done

        fresh_plan_json="$(jq --compact-output . "$fresh_plan")"
        fresh_result_json="$(jq --compact-output . "$fresh_result")"
        test "$fresh_plan_json" = "$(cat "$fresh_plan")"
        test "$fresh_result_json" = "$(cat "$fresh_result")"
        test "$(jq -r .schema_version "$fresh_plan")" = \
          'kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1'
        test "$(jq -r .schema_version "$fresh_result")" = \
          'kaiba.provisioning.rpi5-eeprom-signing-result/v1alpha1'
        test "$(jq -r .recovery_mode "$fresh_result")" = 'unsigned-copy'
        fresh_plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1'
          printf '%s' "$fresh_plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq -e \
          --arg plan_digest "$fresh_plan_digest" \
          --argjson plan "$fresh_plan_json" \
          '
            .plan_id == $plan.plan_id
            and .plan_digest == $plan_digest
            and .release_intent_digest == $plan.release_intent_digest
            and .eeprom_release_manifest_digest
              == $plan.eeprom_release_manifest_digest
            and .signer_policy_digest == $plan.signer_policy_digest
            and .public_key_fingerprint == $plan.public_key_fingerprint
            and .customer_key_hash == $plan.customer_key_hash
            and .source_date_epoch == $plan.source_date_epoch
            and .updater_mode == $plan.updater_mode
            and ([.signatures[] | {
              role,
              input_digest,
              input_size_bytes
            }] == [$plan.signing_inputs[] | {
              role,
              input_digest: .digest,
              input_size_bytes: .size_bytes
            }])
            and .signed_eeprom.size_bytes == $plan.original_eeprom.size_bytes
            and .fresh_recovery_bootcode == $plan.original_recovery
          ' "$fresh_result" > /dev/null

        release_intent_json="$(cat "$freshSigningPlanInput/release-intent.json")"
        test "$(printf '%s' "$release_intent_json" | jq --compact-output .)" = \
          "$release_intent_json"
        release_intent_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-release-intent.v1alpha1'
          printf '%s' "$release_intent_json"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$release_intent_digest" = \
          "$(jq -r .release_intent_digest "$fresh_plan")"

        file_matches() {
          local path="$1"
          local record="$2"
          test "sha256:$(sha256sum "$path" | cut -d ' ' -f 1)" = \
            "$(jq -r .digest <<<"$record")"
          test "$(stat --format=%s "$path")" = "$(jq -r .size_bytes <<<"$record")"
        }
        file_matches "$verifiedSignedEEPROMInput/pieeprom.bin" \
          "$(jq -c .signed_eeprom "$fresh_result")"
        file_matches "$verifiedSignedEEPROMInput/pieeprom.sig" \
          "$(jq -c .eeprom_update_metadata "$fresh_result")"
        file_matches "$verifiedSignedEEPROMInput/bootcode5.bin" \
          "$(jq -c .fresh_recovery_bootcode "$fresh_result")"
        cmp "$verifiedSignedEEPROMInput/bootcode5.bin" \
          "$freshSigningPlanInput/recovery.original.bin"

        ${pkgs.python3}/bin/python3 - \
          "$freshSigningPlanInput/recovery.original.bin" \
          "$TMPDIR/owned-recovery.signing-input" <<'PY'
        import pathlib
        import struct
        import sys

        source = pathlib.Path(sys.argv[1]).read_bytes()
        pathlib.Path(sys.argv[2]).write_bytes(
            source + struct.pack("<III", len(source), 16, 0)
        )
        PY
        owned_input="$(jq \
          --null-input \
          --compact-output \
          --arg role 'rpi5.owned_recovery_bootcode' \
          --arg digest "sha256:$(sha256sum "$TMPDIR/owned-recovery.signing-input" | cut -d ' ' -f 1)" \
          --argjson size_bytes "$(stat --format=%s "$TMPDIR/owned-recovery.signing-input")" \
          '{role: $role, digest: $digest, size_bytes: $size_bytes}')"
        jq -e --argjson owned_input "$owned_input" '
          [.signing_inputs[] | select(.role == "rpi5.owned_recovery_bootcode")]
            == [$owned_input]
        ' "$freshSigningPlanInput/release-intent.json" > /dev/null

        mkdir "$out"
        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1' \
          --arg plan_id '${planID}' \
          --arg updater_mode 'owned-recovery' \
          --argjson updater_flags '["-f","-r"]' \
          --argjson fresh_eeprom_plan "$fresh_plan_json" \
          --argjson fresh_eeprom_result "$fresh_result_json" \
          --argjson owned_recovery_signing_input "$owned_input" \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            updater_mode: $updater_mode,
            updater_flags: $updater_flags,
            fresh_eeprom_plan: $fresh_eeprom_plan,
            fresh_eeprom_result: $fresh_eeprom_result,
            owned_recovery_signing_input: $owned_recovery_signing_input
          }' > "$out/plan.json"
        install -m 0444 "$freshSigningPlanInput/release-intent.json" \
          "$out/release-intent.json"
        install -m 0444 "$freshSigningPlanInput/pieeprom.original.bin" \
          "$out/pieeprom.original.bin"
        install -m 0444 "$freshSigningPlanInput/recovery.original.bin" \
          "$out/recovery.original.bin"
        install -m 0444 "$freshSigningPlanInput/bootcode.original.bin" \
          "$out/bootcode.original.bin"
        install -m 0444 "$freshSigningPlanInput/bootsys.original" \
          "$out/bootsys.original"
        install -m 0444 "$freshSigningPlanInput/boot.conf" "$out/boot.conf"
        install -m 0444 "$freshSigningPlanInput/public.pem" "$out/public.pem"
        install -m 0444 "$verifiedSignedEEPROMInput/pieeprom.bin" \
          "$out/pieeprom.expected.bin"
        install -m 0444 "$verifiedSignedEEPROMInput/pieeprom.sig" \
          "$out/pieeprom.expected.sig"
        install -m 0444 "$verifiedSignedEEPROMInput/bootcode5.bin" \
          "$out/bootcode5.fresh.bin"
        chmod 0444 "$out/plan.json"
      '';

  mkRpi5VerifiedOwnedRecovery =
    {
      signedOutput,
      signingPlan,
      name ? "kaiba-rpi5-verified-owned-recovery",
    }:
    assert lib.assertMsg (lib.all storeBacked [
      signedOutput
      signingPlan
    ]) "owned-recovery finalizer inputs must be fixed Nix-store paths";
    assert lib.assertMsg (
      signingPlan ? kaibaRpi5OwnedRecoverySigningPlan
    ) "signingPlan must be produced by mkRpi5OwnedRecoverySigningPlan";
    pkgs.runCommand name
      {
        signedOutputInput = signedOutput;
        signingPlanInput = signingPlan;
        nativeBuildInputs = [ pkgs.findutils ];
        passthru.kaibaVerifiedOwnedRecovery = {
          inherit signedOutput signingPlan;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          ownedRecoveryProduced = true;
          privateKeyAccess = false;
          recoverySigningPerformed = true;
          signatureVerificationRequired = true;
          signingAuthorityConfigured = false;
          verificationMode = "pure_offline_replay";
        };
        meta = {
          description = "Offline-replayed Raspberry Pi 5 customer-signed owned recovery";
          platforms = [
            "x86_64-linux"
            "aarch64-linux"
          ];
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        ${eepromSigningTool}/bin/kaiba-provision-sign-eeprom \
          finalize-owned-recovery \
          --plan "$signingPlanInput" \
          --signed "$signedOutputInput" \
          --output "$out"

        find "$out" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
          > "$TMPDIR/actual-files"
        printf '%s\n' \
          bootcode5.bin \
          pieeprom.bin \
          pieeprom.sig \
          plan.json \
          public.pem \
          recovery.original.bin \
          release-intent.json \
          result.json \
          > "$TMPDIR/expected-files"
        cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
        chmod 0444 "$out"/*
      '';
in
{
  inherit mkRpi5OwnedRecoverySigningPlan mkRpi5VerifiedOwnedRecovery;
}
