{
  developmentSigning,
  eepromSigningPlan,
  lib,
  metadata,
  pkgs,
  releaseIntent,
  signingPlan,
  unsignedArtifacts,
}:

let
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  signingContract = developmentSigning.signing.kaibaSigning;
  planContract = signingPlan.kaibaBootSigningPlan;
  eepromPlanContract = eepromSigningPlan.kaibaRpi5EEPROMSigningPlan;
  releaseIntentContract = releaseIntent.kaibaRpi5ReleaseIntent;
  unsignedContract = unsignedArtifacts.kaibaUnsignedArtifacts;
  reviewedPublicKeyPEM = developmentSigning.reviewedPublicKeyPEM;
  mutationCapabilities = [
    planContract.blockDeviceWriteCapable
    planContract.directHardwareAccess
    planContract.eepromProgrammingCapable
    planContract.mutationCapable
    planContract.oneTimeSettingCapable
    planContract.otpCapable
    planContract.privateKeyAccess
    planContract.signingAuthorityConfigured
    eepromPlanContract.blockDeviceWriteCapable
    eepromPlanContract.directHardwareAccess
    eepromPlanContract.eepromProgrammingCapable
    eepromPlanContract.mutationCapable
    eepromPlanContract.oneTimeSettingCapable
    eepromPlanContract.otpCapable
    eepromPlanContract.privateKeyAccess
    eepromPlanContract.recoverySigningPerformed
    eepromPlanContract.signedEEPROMProduced
    eepromPlanContract.signingAuthorityConfigured
    releaseIntentContract.blockDeviceWriteCapable
    releaseIntentContract.directHardwareAccess
    releaseIntentContract.eepromProgrammingCapable
    releaseIntentContract.mutationCapable
    releaseIntentContract.oneTimeSettingCapable
    releaseIntentContract.otpCapable
    releaseIntentContract.privateKeyAccess
    releaseIntentContract.signingAuthorityConfigured
    unsignedContract.blockDeviceWriteCapable
    unsignedContract.directHardwareAccess
    unsignedContract.eepromProgrammingCapable
    unsignedContract.mutationCapable
    unsignedContract.oneTimeSettingCapable
    unsignedContract.otpCapable
    unsignedContract.privateKeyAccess
    unsignedContract.signingAuthorityConfigured
  ];
in
assert lib.assertMsg (lib.all (value: value == false)
  mutationCapabilities
) "the Raspberry Pi 5 prototype public release path gained a mutation or signing capability";
assert lib.assertMsg (
  planContract.bootImage == "${unsignedArtifacts}/unsigned/boot.img"
  && planContract.releaseIntent == releaseIntent
) "the prototype signing plan is not bound to the prototype unsigned boot image";
assert lib.assertMsg (
  planContract.planID == metadata.planID
  && planContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && planContract.reviewedPublicKeyPEM == reviewedPublicKeyPEM
  && planContract.signerPolicyDigest == metadata.signerPolicyDigest
  && planContract.sourceDateEpoch == metadata.sourceDateEpoch
) "the prototype signing plan differs from its reviewed release metadata";
assert lib.assertMsg (
  eepromPlanContract.planID == metadata.eepromPlanID
  && eepromPlanContract.releaseIntent == releaseIntent
  && eepromPlanContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && eepromPlanContract.signerPolicyDigest == metadata.signerPolicyDigest
  && eepromPlanContract.customerKeyHash == "sha256:${metadata.expectedCustomerKeyHash}"
  && eepromPlanContract.sourceDateEpoch == metadata.sourceDateEpoch
  && eepromPlanContract.updaterMode == "fresh-board"
  && eepromPlanContract.updaterFlags == [ "-f" ]
) "the prototype EEPROM signing plan differs from its reviewed release metadata";
assert lib.assertMsg (
  unsignedContract.expectedCustomerKeyHash == metadata.expectedCustomerKeyHash
  && unsignedContract.sourceRevision == metadata.sourceRevision
  && unsignedContract.bootOrderPolicy == developmentPosture.boot_order.policy
  && unsignedContract.signingStatus == "unsigned"
) "the prototype unsigned artifact set differs from its reviewed release metadata";
assert lib.assertMsg (
  releaseIntentContract.releaseID == metadata.planID
  && releaseIntentContract.expectedCustomerKeyHash == "sha256:${metadata.expectedCustomerKeyHash}"
  && releaseIntentContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && releaseIntentContract.signerPolicyDigest == metadata.signerPolicyDigest
  && releaseIntentContract.sourceDateEpoch == metadata.sourceDateEpoch
  && releaseIntentContract.sourceRevision == metadata.sourceRevision
  && releaseIntentContract.authorizationScope == "cohort_release"
) "the prototype release intent differs from its reviewed release metadata";
pkgs.runCommand "kaiba-rpi5-prototype-release-review"
  {
    # Preserve the Nix path context for every public input consumed below.
    # In particular, the reviewed key is nested under the flake source and
    # must be mounted explicitly in the sandbox.
    unsignedArtifactsInput = unsignedArtifacts;
    eepromSigningPlanInput = eepromSigningPlan;
    releaseIntentInput = releaseIntent;
    signingPlanInput = signingPlan;
    reviewedPublicKeyInput = reviewedPublicKeyPEM;
    customerPublicKeyBinaryInput = signingContract.customerPublicKeyBinary;
    customerKeyHashFileInput = signingContract.customerKeyHashFile;
    signerPolicyJSONInput = signingContract.signerPolicyJSON;
    signerPolicyDigestFileInput = signingContract.signerPolicyDigestFile;
    nativeBuildInputs = with pkgs; [
      check-jsonschema
      coreutils
      cryptsetup
      findutils
      gnugrep
      gnused
      jq
      mtools
      openssl
    ];
    passthru.kaibaPrototypeReleaseReview = {
      inherit (metadata)
        eepromPlanID
        planID
        sourceDateEpoch
        sourceRevision
        ;
      inherit releaseIntent;
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
    };
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    readonly unsigned="$unsignedArtifactsInput"
    readonly eeprom_plan="$eepromSigningPlanInput"
    readonly release_intent="$releaseIntentInput"
    readonly plan="$signingPlanInput"
    readonly reviewed_key="$reviewedPublicKeyInput"
    readonly customer_key_binary="$customerPublicKeyBinaryInput"
    readonly customer_key_hash_file="$customerKeyHashFileInput"
    readonly signer_policy_json_path="$signerPolicyJSONInput"
    readonly signer_policy_digest_file="$signerPolicyDigestFileInput"

    test -d "$unsigned"
    test ! -L "$unsigned"
    test -z "$(find "$unsigned" -type l -print -quit)"
    test -z "$(find "$unsigned" ! -type d ! -type f -print -quit)"
    find "$unsigned" -type f -printf '%P\n' | sort > "$TMPDIR/actual-unsigned-files"
    printf '%s\n' \
      manifest.json \
      nvme/root-data.img \
      nvme/root-hash.img \
      unsigned/boot.img \
      > "$TMPDIR/expected-unsigned-files"
    cmp "$TMPDIR/expected-unsigned-files" "$TMPDIR/actual-unsigned-files"

    test -d "$plan"
    test ! -L "$plan"
    test -z "$(find "$plan" -type l -print -quit)"
    test -z "$(find "$plan" ! -type d ! -type f -print -quit)"
    find "$plan" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
      > "$TMPDIR/actual-plan-files"
    printf '%s\n' boot.img plan.json public.pem release-intent.json \
      > "$TMPDIR/expected-plan-files"
    cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"

    test -d "$eeprom_plan"
    test ! -L "$eeprom_plan"
    test -z "$(find "$eeprom_plan" -type l -print -quit)"
    test -z "$(find "$eeprom_plan" ! -type d ! -type f -print -quit)"
    find "$eeprom_plan" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
      > "$TMPDIR/actual-eeprom-plan-files"
    printf '%s\n' \
      boot.conf \
      bootcode.original.bin \
      bootsys.original \
      pieeprom.original.bin \
      plan.json \
      public.pem \
      recovery.original.bin \
      release-intent.json \
      > "$TMPDIR/expected-eeprom-plan-files"
    cmp "$TMPDIR/expected-eeprom-plan-files" "$TMPDIR/actual-eeprom-plan-files"

    check-jsonschema \
      --schemafile ${../provisioning/schemas/unsigned-artifact-set-v1alpha1.schema.json} \
      "$unsigned/manifest.json"
    check-jsonschema \
      --schemafile ${../provisioning/schemas/rpi5-boot-signing-plan-v1alpha2.schema.json} \
      "$plan/plan.json"
    check-jsonschema \
      --schemafile ${../provisioning/schemas/rpi5-release-intent-v1alpha1.schema.json} \
      "$release_intent/release-intent.json"
    check-jsonschema \
      --schemafile ${../provisioning/schemas/rpi5-eeprom-signing-plan-v1alpha1.schema.json} \
      "$eeprom_plan/plan.json"
    cmp "$release_intent/release-intent.json" "$plan/release-intent.json"
    cmp "$release_intent/release-intent.json" "$eeprom_plan/release-intent.json"
    cmp "$reviewed_key" "$eeprom_plan/public.pem"
    cmp ${../provisioning/config/rpi5-prototype-eeprom/boot.conf} "$eeprom_plan/boot.conf"

    jq -e \
      --arg source_revision '${metadata.sourceRevision}' \
      --arg customer_key_hash 'sha256:${metadata.expectedCustomerKeyHash}' \
      --arg boot_order_policy '${developmentPosture.boot_order.policy}' \
      '
        .schema == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
        and .source_revision == $source_revision
        and .expected_customer_key_hash == $customer_key_hash
        and .boot_order_policy == $boot_order_policy
        and .boot_command_line_path == "nixos/default/cmdline.txt"
        and .boot_image_size_bytes == 100663296
        and .firmware_allowlist == [
          "config.txt",
          "kaiba-root-integrity.json",
          "nixos/default/bcm2712-rpi-5-b.dtb",
          "nixos/default/cmdline.txt",
          "nixos/default/initrd",
          "nixos/default/kernel.img",
          "nixos/default/overlays/README",
          "nixos/default/overlays/bcm2712d0.dtbo",
          "nixos/default/overlays/overlay_map.dtb"
        ]
        and .persistent_mutable_state == "tmpfs-only"
        and .rollback_policy == "unimplemented-block-enrollment-ready"
        and .debug_policy == "videocore-jtag-unlocked-development"
        and .eeprom_write_protection_policy == "unlocked-development"
        and .signing_status == "unsigned"
        and .artifacts.boot_image.path == "unsigned/boot.img"
        and .artifacts.root_data.path == "nvme/root-data.img"
        and .artifacts.root_hash_tree.path == "nvme/root-hash.img"
        and .verity.algorithm == "sha256"
        and .verity.data_device == "PARTUUID=${unsignedContract.rootDataPartitionGUID}"
        and .verity.hash_device == "PARTUUID=${unsignedContract.rootHashPartitionGUID}"
        and .verity.mapper == "/dev/mapper/root"
      ' "$unsigned/manifest.json" > /dev/null

    verify_digest() {
      local expected="$1"
      local file="$2"
      local actual
      actual="sha256:$(sha256sum "$file" | cut -d ' ' -f 1)"
      test "$actual" = "$expected"
    }
    verify_digest \
      "$(jq -r .artifacts.boot_image.digest "$unsigned/manifest.json")" \
      "$unsigned/unsigned/boot.img"
    verify_digest \
      "$(jq -r .artifacts.root_data.digest "$unsigned/manifest.json")" \
      "$unsigned/nvme/root-data.img"
    verify_digest \
      "$(jq -r .artifacts.root_hash_tree.digest "$unsigned/manifest.json")" \
      "$unsigned/nvme/root-hash.img"

    canonical_manifest="$(jq --compact-output --sort-keys \
      'del(.bundle_digest)' "$unsigned/manifest.json")"
    expected_bundle_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
      printf '%s' "$canonical_manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -r .bundle_digest "$unsigned/manifest.json")" = \
      "$expected_bundle_digest"

    root_hash="$(jq -r .root_integrity_digest "$unsigned/manifest.json")"
    root_hash="''${root_hash#sha256:}"
    test "''${#root_hash}" -eq 64
    veritysetup verify \
      "$unsigned/nvme/root-data.img" \
      "$unsigned/nvme/root-hash.img" \
      "$root_hash"

    mtype -i "$unsigned/unsigned/boot.img" ::nixos/default/cmdline.txt \
      > "$TMPDIR/cmdline.txt"
    grep -F \
      "root=fstab rd.systemd.verity=1 roothash=$root_hash" \
      "$TMPDIR/cmdline.txt" > /dev/null
    grep -F 'systemd.verity_root_data=PARTUUID=${unsignedContract.rootDataPartitionGUID}' \
      "$TMPDIR/cmdline.txt" > /dev/null
    grep -F 'systemd.verity_root_hash=PARTUUID=${unsignedContract.rootHashPartitionGUID}' \
      "$TMPDIR/cmdline.txt" > /dev/null
    if grep -F '/dev/nvme' "$TMPDIR/cmdline.txt" > /dev/null; then
      echo 'signed boot command line contains an enumeration-dependent NVMe path' >&2
      exit 1
    fi
    if grep -Eq '(^|[[:space:]])rootfstype=' "$TMPDIR/cmdline.txt"; then
      echo 'signed boot command line bypasses the sealed initrd fstab filesystem type' >&2
      exit 1
    fi
    mtype -i "$unsigned/unsigned/boot.img" ::kaiba-root-integrity.json \
      > "$TMPDIR/root-integrity.json"
    jq -e \
      --arg root_hash "$root_hash" \
      '
        .schema == "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1"
        and .root_hash == $root_hash
        and .data_device == "PARTUUID=${unsignedContract.rootDataPartitionGUID}"
        and .hash_device == "PARTUUID=${unsignedContract.rootHashPartitionGUID}"
        and .no_superblock == false
      ' "$TMPDIR/root-integrity.json" > /dev/null

    cmp "$unsigned/unsigned/boot.img" "$plan/boot.img"
    cmp "$reviewed_key" "$plan/public.pem"
    test "$(sha256sum "$reviewed_key" | cut -d ' ' -f 1)" = \
      '${developmentSigning.metadata.publicKeyFileSHA256}'

    boot_digest="sha256:$(sha256sum "$plan/boot.img" | cut -d ' ' -f 1)"
    boot_size="$(stat --format=%s "$plan/boot.img")"
    release_intent_json="$(jq --compact-output . "$release_intent/release-intent.json")"
    test "$release_intent_json" = "$(cat "$release_intent/release-intent.json")"
    release_intent_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-release-intent.v1alpha1'
      printf '%s' "$release_intent_json"
    } | sha256sum | cut -d ' ' -f 1)"
    eeprom_plan_json="$(jq --compact-output . "$eeprom_plan/plan.json")"
    test "$eeprom_plan_json" = "$(cat "$eeprom_plan/plan.json")"
    eeprom_plan_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1'
      printf '%s' "$eeprom_plan_json"
    } | sha256sum | cut -d ' ' -f 1)"
    jq -e \
      --arg release_id '${metadata.planID}' \
      --arg source_revision '${metadata.sourceRevision}' \
      --arg boot_digest "$boot_digest" \
      --arg public_key_fingerprint '${metadata.publicKeyFingerprint}' \
      --arg signer_policy_digest '${metadata.signerPolicyDigest}' \
      --arg customer_key_hash 'sha256:${metadata.expectedCustomerKeyHash}' \
      --argjson boot_size "$boot_size" \
      --argjson source_date_epoch '${toString metadata.sourceDateEpoch}' \
      '
        .schema_version == "kaiba.provisioning.rpi5-release-intent/v1alpha1"
        and .release_id == $release_id
        and .source_revision == $source_revision
        and .source_date_epoch == $source_date_epoch
        and .public_key_fingerprint == $public_key_fingerprint
        and .signing_policy_digest == $signer_policy_digest
        and .expected_customer_key_hash == $customer_key_hash
        and .authorization_scope == "cohort_release"
        and [.signing_inputs[] | select(.role == "rpi5.boot_image")]
          == [{role: "rpi5.boot_image", digest: $boot_digest, size_bytes: $boot_size}]
        and (.signing_inputs | map(.role)) == [
          "rpi5.boot_image",
          "rpi5.eeprom_bootcode",
          "rpi5.eeprom_bootsys",
          "rpi5.eeprom_config",
          "rpi5.owned_recovery_bootcode"
        ]
        and (.required_output_roles | length) == 18
      ' "$release_intent/release-intent.json" > /dev/null
    jq -e \
      --arg plan_id '${metadata.eepromPlanID}' \
      --arg release_intent_digest "$release_intent_digest" \
      --arg public_key_fingerprint '${metadata.publicKeyFingerprint}' \
      --arg signer_policy_digest '${metadata.signerPolicyDigest}' \
      --arg customer_key_hash 'sha256:${metadata.expectedCustomerKeyHash}' \
      --argjson source_date_epoch '${toString metadata.sourceDateEpoch}' \
      '
        .schema_version == "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1"
        and .plan_id == $plan_id
        and .release_intent_digest == $release_intent_digest
        and .public_key_fingerprint == $public_key_fingerprint
        and .signer_policy_digest == $signer_policy_digest
        and .customer_key_hash == $customer_key_hash
        and .source_date_epoch == $source_date_epoch
        and .firmware_build_epoch == 1779807685
        and .updater_mode == "fresh-board"
        and .updater_flags == ["-f"]
        and (.signing_inputs | map(.role)) == [
          "rpi5.eeprom_bootcode",
          "rpi5.eeprom_bootsys",
          "rpi5.eeprom_config"
        ]
      ' "$eeprom_plan/plan.json" > /dev/null
    jq -e \
      --arg plan_id '${metadata.planID}' \
      --arg boot_digest "$boot_digest" \
      --arg public_key_fingerprint '${metadata.publicKeyFingerprint}' \
      --arg signer_policy_digest '${metadata.signerPolicyDigest}' \
      --arg release_intent_digest "$release_intent_digest" \
      --argjson boot_size "$boot_size" \
      --argjson source_date_epoch '${toString metadata.sourceDateEpoch}' \
      '
        .schema_version == "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2"
        and .plan_id == $plan_id
        and .release_intent_digest == $release_intent_digest
        and .boot_image_digest == $boot_digest
        and .boot_image_size_bytes == $boot_size
        and .public_key_fingerprint == $public_key_fingerprint
        and .signer_policy_digest == $signer_policy_digest
        and .source_date_epoch == $source_date_epoch
      ' "$plan/plan.json" > /dev/null

    actual_public_key_fingerprint="sha256:$({
      openssl pkey -pubin -in "$plan/public.pem" -outform DER
    } | sha256sum | cut -d ' ' -f 1)"
    test "$actual_public_key_fingerprint" = '${metadata.publicKeyFingerprint}'
    test "$(
      openssl pkey -pubin -in "$plan/public.pem" -text -noout | sed -n '1p'
    )" = 'Public-Key: (2048 bit)'
    openssl pkey -pubin -in "$plan/public.pem" -text -noout \
      | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null

    test "$(stat --format=%s "$customer_key_binary")" -eq 264
    customer_key_hash="$(sha256sum "$customer_key_binary" | cut -d ' ' -f 1)"
    test "$customer_key_hash" = '${metadata.expectedCustomerKeyHash}'
    test "$(tr -d '\n' < "$customer_key_hash_file")" = "$customer_key_hash"
    test "$(tr -d '\n' < "$signer_policy_digest_file")" = \
      '${metadata.signerPolicyDigest}'
    signer_policy_json="$(jq --compact-output . "$signer_policy_json_path")"
    actual_signer_policy_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.yubikey-signing-policy.v1alpha1'
      printf '%s' "$signer_policy_json"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$actual_signer_policy_digest" = '${metadata.signerPolicyDigest}'

    mkdir -p "$out"
    jq \
      --null-input \
      --sort-keys \
      --arg status passed \
      --arg scope public-unsigned-prototype \
      --arg source_revision '${metadata.sourceRevision}' \
      --arg plan_id '${metadata.planID}' \
      --argjson source_date_epoch '${toString metadata.sourceDateEpoch}' \
      --arg unsigned_bundle_digest "$expected_bundle_digest" \
      --arg signing_plan_digest "sha256:$(sha256sum "$plan/plan.json" | cut -d ' ' -f 1)" \
      --arg eeprom_signing_plan_digest "$eeprom_plan_digest" \
      --arg release_intent_digest "$release_intent_digest" \
      --arg boot_image_digest "$boot_digest" \
      --arg root_data_digest "$(jq -r .artifacts.root_data.digest "$unsigned/manifest.json")" \
      --arg root_hash_tree_digest "$(jq -r .artifacts.root_hash_tree.digest "$unsigned/manifest.json")" \
      --arg root_integrity_digest "sha256:$root_hash" \
      --arg customer_key_hash "sha256:$customer_key_hash" \
      --arg public_key_fingerprint "$actual_public_key_fingerprint" \
      --arg signer_policy_digest "$actual_signer_policy_digest" \
      '{
        status: $status,
        scope: $scope,
        source_revision: $source_revision,
        plan_id: $plan_id,
        source_date_epoch: $source_date_epoch,
        unsigned_bundle_digest: $unsigned_bundle_digest,
        signing_plan_digest: $signing_plan_digest,
        eeprom_signing_plan_digest: $eeprom_signing_plan_digest,
        release_intent_digest: $release_intent_digest,
        artifacts: {
          boot_image: $boot_image_digest,
          root_data: $root_data_digest,
          root_hash_tree: $root_hash_tree_digest
        },
        root_integrity_digest: $root_integrity_digest,
        customer_key_hash: $customer_key_hash,
        public_key_fingerprint: $public_key_fingerprint,
        signer_policy_digest: $signer_policy_digest,
        private_key_access: false,
        hardware_access: false,
        mutation_capable: false,
        one_time_setting_capable: false
      }' > "$out/review.json"
    touch "$out/passed"
    chmod 0444 "$out/review.json" "$out/passed"
  ''
