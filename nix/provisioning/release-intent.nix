{
  pkgs,
  lib,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalIdentifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
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

  requiredOutputRoles = [
    "boot_public_key"
    "device_profile"
    "platform_adapter"
    "root_integrity"
    "rpi5.boot_image"
    "rpi5.boot_signature"
    "rpi5.eeprom_bootsys"
    "rpi5.eeprom_config"
    "rpi5.fresh_commit_bundle"
    "rpi5.fresh_readback_bundle"
    "rpi5.negative_boot_bundle"
    "rpi5.owned_readback_bundle"
    "rpi5.owned_recovery_bootcode"
    "rpi5.owned_recovery_bundle"
    "rpi5.root_data_image"
    "rpi5.root_hash_tree_image"
    "rpi5.root_integrity_test_bundle"
    "rpi5.signed_eeprom_image"
  ];

  # Derive every EEPROM-related signing byte string from the pinned public
  # release. The first three are consumed by the fresh-board updater; the
  # owned-recovery input is authorized now but signed only by the later,
  # separately controlled recovery workflow.
  mkRpi5EEPROMReleaseSigningInputs =
    {
      bootConfig,
      eepromRelease,
      name ? "kaiba-rpi5-eeprom-release-signing-inputs",
    }:
    assert lib.assertMsg (storeBacked bootConfig) "bootConfig must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked eepromRelease) "eepromRelease must be a fixed Nix-store path";
    pkgs.runCommand name
      {
        bootConfigInput = bootConfig;
        eepromReleaseInput = eepromRelease;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.python3
        ];
        passthru.kaibaRpi5EEPROMReleaseSigningInputs = {
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          recoverySigningPerformed = false;
          signingAuthorityConfigured = false;
        };
        meta = {
          description = "Exact public Raspberry Pi 5 EEPROM release signing inputs";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        readonly bootcode="$eepromReleaseInput/firmware/components/bootcode.bin"
        readonly bootsys="$eepromReleaseInput/firmware/components/bootsys"
        readonly recovery="$eepromReleaseInput/firmware/recovery.original.bin"
        for input in "$bootcode" "$bootsys" "$recovery" "$bootConfigInput"; do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done
        test "$(stat --format=%s "$bootConfigInput")" -le 4076

        mkdir "$out"
        ${pkgs.python3}/bin/python3 - \
          "$bootcode" "$out/eeprom-bootcode.signing-input" \
          "$bootsys" "$out/eeprom-bootsys.signing-input" \
          "$recovery" "$out/owned-recovery-bootcode.signing-input" <<'PY'
        import pathlib
        import struct
        import sys

        arguments = sys.argv[1:]
        for index in range(0, len(arguments), 2):
            source = pathlib.Path(arguments[index])
            destination = pathlib.Path(arguments[index + 1])
            original = source.read_bytes()
            preimage = original + struct.pack("<III", len(original), 16, 0)
            if len(preimage) > 112120:
                raise SystemExit(
                    f"signing input exceeds the 112120-byte signed-firmware preimage limit: {source}"
                )
            destination.write_bytes(preimage)
        PY
        install -m 0444 "$bootConfigInput" "$out/eeprom-config.signing-input"
        chmod 0444 "$out"/*.signing-input
      '';

  # This public derivation fixes the only pre-signature authorization identity
  # used by release signing. It hashes exact store-backed signing inputs and
  # contains neither device transaction fields nor signing authority.
  mkRpi5ReleaseIntent =
    {
      bootImage,
      eepromBootcodeSigningInput,
      eepromBootsysSigningInput,
      eepromConfigSigningInput,
      eepromRelease,
      ownedRecoveryBootcodeSigningInput,
      expectedCustomerKeyHash,
      publicKeyFingerprint,
      releaseID,
      signerPolicyDigest,
      sourceDateEpoch,
      sourceRevision,
      unsignedArtifacts,
      name ? "kaiba-rpi5-release-intent",
    }:
    assert lib.assertMsg (canonicalIdentifier releaseID) "releaseID must be a canonical identifier";
    assert lib.assertMsg (canonicalRevision sourceRevision)
      "sourceRevision must contain exactly 40 or 64 lowercase hexadecimal characters";
    assert lib.assertMsg (canonicalEpoch sourceDateEpoch)
      "sourceDateEpoch must be a positive canonical Unix timestamp";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must be canonical";
    assert lib.assertMsg (canonicalDigest signerPolicyDigest) "signerPolicyDigest must be canonical";
    assert lib.assertMsg (canonicalDigest expectedCustomerKeyHash)
      "expectedCustomerKeyHash must be canonical";
    assert lib.assertMsg (lib.all storeBacked [
      bootImage
      eepromBootcodeSigningInput
      eepromBootsysSigningInput
      eepromConfigSigningInput
      eepromRelease
      ownedRecoveryBootcodeSigningInput
      unsignedArtifacts
    ]) "every release signing input must be a fixed Nix-store path";
    let
      inputs = [
        {
          role = "rpi5.boot_image";
          path = bootImage;
        }
        {
          role = "rpi5.eeprom_bootcode";
          path = eepromBootcodeSigningInput;
        }
        {
          role = "rpi5.eeprom_bootsys";
          path = eepromBootsysSigningInput;
        }
        {
          role = "rpi5.eeprom_config";
          path = eepromConfigSigningInput;
        }
        {
          role = "rpi5.owned_recovery_bootcode";
          path = ownedRecoveryBootcodeSigningInput;
        }
      ];
      inputLines = lib.concatMapStringsSep "\n" (input: ''
        add_input ${lib.escapeShellArg input.role} ${lib.escapeShellArg (toString input.path)}
      '') inputs;
    in
    pkgs.runCommand name
      {
        eepromReleaseInput = eepromRelease;
        signingInputPaths = map (input: input.path) inputs;
        unsignedArtifactsInput = unsignedArtifacts;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.gnugrep
          pkgs.jq
        ];
        passthru.kaibaRpi5ReleaseIntent = {
          inherit
            expectedCustomerKeyHash
            publicKeyFingerprint
            releaseID
            signerPolicyDigest
            sourceDateEpoch
            sourceRevision
            ;
          authorizationScope = "cohort_release";
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          requiredOutputRoles = requiredOutputRoles;
          schemaVersion = "kaiba.provisioning.rpi5-release-intent/v1alpha1";
          signingAuthorityConfigured = false;
        };
        meta = {
          description = "Canonical public Raspberry Pi 5 release-signing intent";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        test -d "$unsignedArtifactsInput"
        test ! -L "$unsignedArtifactsInput"
        test -f "$unsignedArtifactsInput/manifest.json"
        test ! -L "$unsignedArtifactsInput/manifest.json"
        test -d "$eepromReleaseInput"
        test ! -L "$eepromReleaseInput"
        test -f "$eepromReleaseInput/release.json"
        test ! -L "$eepromReleaseInput/release.json"

        test "$(jq -r .schema "$unsignedArtifactsInput/manifest.json")" = \
          'provisioning.kaiba.network/unsigned-artifact-set/v1alpha1'
        test "$(jq -r .source_revision "$unsignedArtifactsInput/manifest.json")" = \
          '${sourceRevision}'
        test "$(jq -r .expected_customer_key_hash "$unsignedArtifactsInput/manifest.json")" = \
          '${expectedCustomerKeyHash}'
        unsigned_artifact_set_digest="$(
          jq -r .bundle_digest "$unsignedArtifactsInput/manifest.json"
        )"
        printf '%s\n' "$unsigned_artifact_set_digest" \
          | grep -Eq '^sha256:[0-9a-f]{64}$'
        jq --sort-keys --compact-output 'del(.bundle_digest)' \
          "$unsignedArtifactsInput/manifest.json" > "$TMPDIR/unsigned-manifest-canonical.json"
        actual_unsigned_artifact_set_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
          cat "$TMPDIR/unsigned-manifest-canonical.json"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$actual_unsigned_artifact_set_digest" = "$unsigned_artifact_set_digest"

        test "$(jq -r .schema_version "$eepromReleaseInput/release.json")" = \
          'kaiba.provisioning.rpi5-eeprom-release/v1alpha1'
        eeprom_release_manifest_digest="sha256:$(
          sha256sum "$eepromReleaseInput/release.json" | cut -d ' ' -f 1
        )"

        boot_image_digest="sha256:$(sha256sum '${toString bootImage}' | cut -d ' ' -f 1)"
        boot_image_size="$(stat --format=%s '${toString bootImage}')"
        test "$(jq -r .artifacts.boot_image.digest "$unsignedArtifactsInput/manifest.json")" = \
          "$boot_image_digest"
        test "$(jq -r .boot_image_size_bytes "$unsignedArtifactsInput/manifest.json")" = \
          "$boot_image_size"

        signing_inputs='[]'
        add_input() {
          local role="$1"
          local path="$2"
          test -f "$path"
          test ! -L "$path"
          test -s "$path"
          local size
          size="$(stat --format=%s "$path")"
          test "$size" -le 100663296
          local digest
          digest="sha256:$(sha256sum "$path" | cut -d ' ' -f 1)"
          signing_inputs="$(
            jq \
              --compact-output \
              --arg role "$role" \
              --arg digest "$digest" \
              --argjson size_bytes "$size" \
              '. + [{role: $role, digest: $digest, size_bytes: $size_bytes}]' \
              <<< "$signing_inputs"
          )"
        }

        ${inputLines}

        mkdir "$out"
        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-release-intent/v1alpha1' \
          --arg release_id '${releaseID}' \
          --arg device_class 'raspberry-pi-5-model-b-v1alpha1' \
          --arg source_revision '${sourceRevision}' \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          --arg unsigned_artifact_set_digest "$unsigned_artifact_set_digest" \
          --arg eeprom_release_manifest_digest "$eeprom_release_manifest_digest" \
          --arg public_key_fingerprint '${publicKeyFingerprint}' \
          --arg signing_policy_digest '${signerPolicyDigest}' \
          --arg expected_customer_key_hash '${expectedCustomerKeyHash}' \
          --arg authorization_scope 'cohort_release' \
          --argjson signing_inputs "$signing_inputs" \
          --argjson required_output_roles '${builtins.toJSON requiredOutputRoles}' \
          '{
            schema_version: $schema_version,
            release_id: $release_id,
            device_class: $device_class,
            source_revision: $source_revision,
            source_date_epoch: $source_date_epoch,
            unsigned_artifact_set_digest: $unsigned_artifact_set_digest,
            eeprom_release_manifest_digest: $eeprom_release_manifest_digest,
            public_key_fingerprint: $public_key_fingerprint,
            signing_policy_digest: $signing_policy_digest,
            expected_customer_key_hash: $expected_customer_key_hash,
            authorization_scope: $authorization_scope,
            signing_inputs: $signing_inputs,
            required_output_roles: $required_output_roles
          }' > "$out/release-intent.json"
        chmod 0444 "$out/release-intent.json"
      '';
in
{
  inherit
    mkRpi5EEPROMReleaseSigningInputs
    mkRpi5ReleaseIntent
    requiredOutputRoles
    ;
}
