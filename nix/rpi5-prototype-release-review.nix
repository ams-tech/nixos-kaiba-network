{
  developmentSigning,
  lib,
  metadata,
  pkgs,
  signingPlan,
  unsignedArtifacts,
}:

let
  signingContract = developmentSigning.signing.kaibaSigning;
  planContract = signingPlan.kaibaBootSigningPlan;
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
) "the prototype signing plan is not bound to the prototype unsigned boot image";
assert lib.assertMsg (
  planContract.planID == metadata.planID
  && planContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && planContract.reviewedPublicKeyPEM == reviewedPublicKeyPEM
  && planContract.signerPolicyDigest == metadata.signerPolicyDigest
  && planContract.sourceDateEpoch == metadata.sourceDateEpoch
) "the prototype signing plan differs from its reviewed release metadata";
assert lib.assertMsg (
  unsignedContract.expectedCustomerKeyHash == metadata.expectedCustomerKeyHash
  && unsignedContract.sourceRevision == metadata.sourceRevision
  && unsignedContract.signingStatus == "unsigned"
) "the prototype unsigned artifact set differs from its reviewed release metadata";
pkgs.runCommand "kaiba-rpi5-prototype-release-review"
  {
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
      inherit (metadata) planID sourceDateEpoch sourceRevision;
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

    readonly unsigned=${lib.escapeShellArg (toString unsignedArtifacts)}
    readonly plan=${lib.escapeShellArg (toString signingPlan)}
    readonly reviewed_key=${lib.escapeShellArg (toString reviewedPublicKeyPEM)}
    readonly customer_key_binary=${lib.escapeShellArg signingContract.customerPublicKeyBinary}
    readonly customer_key_hash_file=${lib.escapeShellArg signingContract.customerKeyHashFile}
    readonly signer_policy_json_path=${lib.escapeShellArg signingContract.signerPolicyJSON}
    readonly signer_policy_digest_file=${lib.escapeShellArg signingContract.signerPolicyDigestFile}

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
    printf '%s\n' boot.img plan.json public.pem > "$TMPDIR/expected-plan-files"
    cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"

    check-jsonschema \
      --schemafile ${../provisioning/schemas/unsigned-artifact-set-v1alpha1.schema.json} \
      "$unsigned/manifest.json"
    check-jsonschema \
      --schemafile ${../provisioning/schemas/rpi5-boot-signing-plan-v1alpha1.schema.json} \
      "$plan/plan.json"

    jq -e \
      --arg source_revision '${metadata.sourceRevision}' \
      --arg customer_key_hash 'sha256:${metadata.expectedCustomerKeyHash}' \
      '
        .schema == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
        and .source_revision == $source_revision
        and .expected_customer_key_hash == $customer_key_hash
        and .boot_order_policy == "nvme-only"
        and .boot_command_line_path == "nixos/default/cmdline.txt"
        and .boot_image_size_bytes == 100663296
        and .firmware_allowlist == [
          "config.txt",
          "kaiba-root-integrity.json",
          "nixos/default/bcm2712-rpi-5-b.dtb",
          "nixos/default/cmdline.txt",
          "nixos/default/initrd",
          "nixos/default/kernel.img"
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
        and .verity.data_device == "/dev/nvme0n1p2"
        and .verity.hash_device == "/dev/nvme0n1p3"
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

    jq --compact-output --sort-keys 'del(.bundle_digest)' \
      "$unsigned/manifest.json" > "$TMPDIR/canonical-manifest"
    expected_bundle_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
      cat "$TMPDIR/canonical-manifest"
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
      "root=/dev/mapper/root rootfstype=ext4 rd.systemd.verity=1 roothash=$root_hash" \
      "$TMPDIR/cmdline.txt" > /dev/null
    grep -F 'systemd.verity_root_data=/dev/nvme0n1p2' \
      "$TMPDIR/cmdline.txt" > /dev/null
    grep -F 'systemd.verity_root_hash=/dev/nvme0n1p3' \
      "$TMPDIR/cmdline.txt" > /dev/null
    mtype -i "$unsigned/unsigned/boot.img" ::kaiba-root-integrity.json \
      > "$TMPDIR/root-integrity.json"
    jq -e \
      --arg root_hash "$root_hash" \
      '
        .schema == "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1"
        and .root_hash == $root_hash
        and .data_device == "/dev/nvme0n1p2"
        and .hash_device == "/dev/nvme0n1p3"
        and .no_superblock == false
      ' "$TMPDIR/root-integrity.json" > /dev/null

    cmp "$unsigned/unsigned/boot.img" "$plan/boot.img"
    cmp "$reviewed_key" "$plan/public.pem"
    test "$(sha256sum "$reviewed_key" | cut -d ' ' -f 1)" = \
      '${developmentSigning.metadata.publicKeyFileSHA256}'

    boot_digest="sha256:$(sha256sum "$plan/boot.img" | cut -d ' ' -f 1)"
    boot_size="$(stat --format=%s "$plan/boot.img")"
    jq -e \
      --arg plan_id '${metadata.planID}' \
      --arg boot_digest "$boot_digest" \
      --arg public_key_fingerprint '${metadata.publicKeyFingerprint}' \
      --arg signer_policy_digest '${metadata.signerPolicyDigest}' \
      --argjson boot_size "$boot_size" \
      --argjson source_date_epoch '${toString metadata.sourceDateEpoch}' \
      '
        .schema_version == "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1"
        and .plan_id == $plan_id
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
