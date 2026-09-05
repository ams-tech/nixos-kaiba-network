{
  bootSignedOutput,
  expectedArchiveDigest,
  expectedBootImageDigest,
  expectedBootSignatureDigest,
  expectedMediaDigest,
  expectedRootDataDigest,
  expectedRootHashDigest,
  expectedRootIntegrityDigest,
  imageFileName ? "kaiba-rpi5-development-secure-boot-target.img.zst",
  name ? "kaiba-rpi5-development-secure-boot-target-image",
  payloadSourceRevision,
  pkgs,
  unsignedArtifacts,
}:

let
  unsignedContract = unsignedArtifacts.kaibaUnsignedArtifacts or { };
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
  authorityFlags = [
    (unsignedContract.blockDeviceWriteCapable or null)
    (unsignedContract.directHardwareAccess or null)
    (unsignedContract.eepromProgrammingCapable or null)
    (unsignedContract.mutationCapable or null)
    (unsignedContract.oneTimeSettingCapable or null)
    (unsignedContract.otpCapable or null)
    (unsignedContract.privateKeyAccess or null)
    (unsignedContract.signingAuthorityConfigured or null)
  ];
in
assert builtins.isAttrs unsignedContract;
assert
  unsignedContract.schemaVersion or null
  == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1";
assert unsignedContract.sourceRevision or null == payloadSourceRevision;
assert unsignedContract.signingStatus or null == "unsigned";
assert unsignedContract.rootDataPartitionGUID or null == "bdd5be20-f7ea-56e7-ae90-4465ae950596";
assert unsignedContract.rootHashPartitionGUID or null == "62616022-71fb-5036-8cc4-b7949cc6e52c";
assert builtins.all (value: value == false) authorityFlags;
assert builtins.all canonicalDigest [
  expectedArchiveDigest
  expectedBootImageDigest
  expectedBootSignatureDigest
  expectedMediaDigest
  expectedRootDataDigest
  expectedRootHashDigest
  expectedRootIntegrityDigest
];
assert canonicalRevision payloadSourceRevision;
assert builtins.match "[a-z0-9.-]+\\.img\\.zst" imageFileName != null;
pkgs.runCommand name
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.gptfdisk
      pkgs.jq
      pkgs.python3
      pkgs.zstd
    ];
    preferLocalBuild = true;
    passthru.kaibaRpi5SignedTargetImage = {
      inherit
        expectedArchiveDigest
        expectedBootImageDigest
        expectedBootSignatureDigest
        expectedMediaDigest
        expectedRootDataDigest
        expectedRootHashDigest
        expectedRootIntegrityDigest
        imageFileName
        payloadSourceRevision
        unsignedArtifacts
        ;
      compressed = true;
      directHardwareAccess = false;
      imageSizeBytes = 3 * 1024 * 1024 * 1024;
      inputVerificationMode = "pinned_unsigned_artifacts_plus_checked_signed_boot";
      logicalSectorSizeBytes = 512;
      minimumTargetCapacityBytes = 3 * 1024 * 1024 * 1024;
      mutationCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
      signingCapable = false;
      wholeDeviceImage = true;
    };
    meta = {
      description = "Flashable Raspberry Pi 5 signed v0.1.6 target SD image";
      platforms = [ "aarch64-linux" ];
    };
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export TZ=UTC
    umask 022

    readonly unsigned=${unsignedArtifacts}
    readonly unsigned_manifest="$unsigned/manifest.json"
    readonly boot_image="$unsigned/unsigned/boot.img"
    readonly root_data="$unsigned/nvme/root-data.img"
    readonly root_hash="$unsigned/nvme/root-hash.img"
    readonly signed=${bootSignedOutput}
    readonly boot_signature="$signed/boot.sig"
    readonly signing_result="$signed/signing-result.json"

    readonly expected_boot=${pkgs.lib.escapeShellArg expectedBootImageDigest}
    readonly expected_signature=${pkgs.lib.escapeShellArg expectedBootSignatureDigest}
    readonly expected_root_data=${pkgs.lib.escapeShellArg expectedRootDataDigest}
    readonly expected_root_hash=${pkgs.lib.escapeShellArg expectedRootHashDigest}
    readonly expected_root_integrity=${pkgs.lib.escapeShellArg expectedRootIntegrityDigest}
    readonly expected_media=${pkgs.lib.escapeShellArg expectedMediaDigest}
    readonly expected_archive=${pkgs.lib.escapeShellArg expectedArchiveDigest}
    readonly payload_revision=${pkgs.lib.escapeShellArg payloadSourceRevision}

    readonly target_size=3221225472
    readonly alignment=1048576
    readonly boot_size=134217728
    readonly root_data_partition_size=2360344576
    readonly root_hash_partition_size=18874368
    readonly backup_offset=3220176896
    readonly tail_size=705691648
    readonly transaction_id='release:rpi5-v0.1.6-signed-target:1'
    readonly release_id='release:rpi5-prototype:8e9f1d5cd97f'
    readonly manifest_digest='sha256:c4bf57fe369a22b685876c70558da6261ee3fda2107be814119e7717411fc541'
    readonly expected_capsule='sha256:7b14a007bcf016a3a8f7842e1fa7cbf542acf44cc4aa23296f7c657b6b82fd3c'
    readonly expected_verity_root='sha256:4bc857ac93d3199de098d818981cdf4e9d405ea9f3044c375a21fb2b1a850a1f'
    readonly data_guid='bdd5be20-f7ea-56e7-ae90-4465ae950596'
    readonly hash_guid='62616022-71fb-5036-8cc4-b7949cc6e52c'
    readonly expected_boot_guid='c2dbdc53-8c5f-406e-8609-627f25b1667d'
    readonly expected_disk_guid='fa252948-9b95-49f1-8dc0-92a52e104273'

    verify_regular() {
      local path="$1"
      local size="$2"
      local digest="$3"
      local actual_size actual_digest
      test -f "$path"
      test ! -L "$path"
      actual_size="$(stat --format=%s "$path")"
      actual_digest="sha256:$(sha256sum "$path" | cut -d ' ' -f 1)"
      printf 'verified public input: %s expected=%s/%s actual=%s/%s\n' \
        "$(basename "$path")" "$size" "$digest" "$actual_size" "$actual_digest"
      test "$actual_size" -eq "$size"
      test "$actual_digest" = "$digest"
    }

    verify_regular "$unsigned_manifest" 2099 \
      'sha256:0917665b7d849b81051b80b4e9419858740b84f631d5cf4f20fe7f326e37c176'
    verify_regular "$boot_image" 100663296 "$expected_boot"
    verify_regular "$root_data" 2360344576 "$expected_root_data"
    verify_regular "$root_hash" 18595840 "$expected_root_hash"
    verify_regular "$boot_signature" 602 "$expected_signature"
    verify_regular "$signing_result" 889 \
      'sha256:052efa4d2b4be64af63c19b24b5fa3e5cf3afb68dd88b617b5901f03c95822b5'

    jq -e \
      --arg revision "$payload_revision" \
      --arg boot "$expected_boot" \
      --arg data "$expected_root_data" \
      --arg hash "$expected_root_hash" \
      --arg verity "$expected_verity_root" '
        .schema == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
        and .source_revision == $revision
        and .expected_customer_key_hash == "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895"
        and .signing_status == "unsigned"
        and .artifacts.boot_image.path == "unsigned/boot.img"
        and .artifacts.boot_image.digest == $boot
        and .artifacts.root_data.path == "nvme/root-data.img"
        and .artifacts.root_data.digest == $data
        and .artifacts.root_hash_tree.path == "nvme/root-hash.img"
        and .artifacts.root_hash_tree.digest == $hash
        and .root_integrity_digest == $verity
        and .verity.data_device == "PARTUUID=bdd5be20-f7ea-56e7-ae90-4465ae950596"
        and .verity.hash_device == "PARTUUID=62616022-71fb-5036-8cc4-b7949cc6e52c"
      ' "$unsigned_manifest" > /dev/null

    jq -e \
      --arg boot "$expected_boot" \
      --arg signature "$expected_signature" '
        .schema_version == "kaiba.provisioning.rpi5-boot-signing-result/v1alpha2"
        and .plan_id == "release:rpi5-prototype:8e9f1d5cd97f"
        and .boot_image_digest == $boot
        and .boot_image_size_bytes == 100663296
        and .boot_signature_digest == $signature
        and .boot_signature_size_bytes == 602
        and .public_key_fingerprint == "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9"
      ' "$signing_result" > /dev/null
    test "$(sed -n '1p' "$boot_signature")" = "$(printf '%s' "$expected_boot" | cut -d : -f 2)"
    test "$(grep -c '^ts: [0-9][0-9]*$' "$boot_signature")" -eq 1
    test "$(grep -c '^rsa2048: [0-9a-f]\{512\}$' "$boot_signature")" -eq 1

    veritysetup verify "$root_data" "$root_hash" \
      "$(printf '%s' "$expected_verity_root" | cut -d : -f 2)"

    readonly capsule_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.unfused-capsule.v1'
      printf '%s\0%s\0%s\0' 'boot.img' 100663296 "$expected_boot"
      printf '%s\0%s\0%s\0' 'boot.sig' 602 "$expected_signature"
      printf '%s\0%s\0%s\0' 'nvme/root-data.img' 2360344576 "$expected_root_data"
      printf '%s\0%s\0%s\0' 'nvme/root-hash.img' 18595840 "$expected_root_hash"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$capsule_digest" = "$expected_capsule"

    derive_uuid() {
      local domain="$1"
      local hex
      hex="$({
        printf '%s\0' "$domain"
        printf '%s\0%s\0%s\0%s\0' \
          "$manifest_digest" "$transaction_id" 'per-run-geometry' "$target_size"
      } | sha256sum | cut -d ' ' -f 1)"
      printf '%s-%s-4%s-8%s-%s' \
        "$(printf '%s' "$hex" | cut -c 1-8)" \
        "$(printf '%s' "$hex" | cut -c 9-12)" \
        "$(printf '%s' "$hex" | cut -c 14-16)" \
        "$(printf '%s' "$hex" | cut -c 18-20)" \
        "$(printf '%s' "$hex" | cut -c 21-32)"
    }
    readonly disk_guid="$(derive_uuid kaiba.provisioning.production-media.disk.v1)"
    readonly boot_guid="$(derive_uuid kaiba.provisioning.production-media.partition.boot.v1)"
    test "$disk_guid" = "$expected_disk_guid"
    test "$boot_guid" = "$expected_boot_guid"

    readonly config="$TMPDIR/config.txt"
    printf '%s\n' 'boot_ramdisk=1' > "$config"
    verify_regular "$config" 15 \
      'sha256:c4318a93991476d98c3f14b096578c3e0da836e2a755a86043b535073e8b4f45'

    readonly media_binding="$TMPDIR/media-binding.json"
    jq -cjn \
      --arg schema_version 'kaiba.provisioning.rpi5-media-binding/v1alpha1' \
      --arg transaction_id "$transaction_id" \
      --arg release_id "$release_id" \
      --arg manifest_digest "$manifest_digest" \
      --arg capsule_digest "$capsule_digest" \
      --arg boot_image_digest "$expected_boot" \
      --arg boot_signature_digest "$expected_signature" \
      --arg root_data_digest "$expected_root_data" \
      --arg root_hash_digest "$expected_root_hash" \
      --arg root_integrity_digest "$expected_root_integrity" \
      --arg verity_root_hash "$expected_verity_root" \
      --arg boot_guid "$boot_guid" \
      --arg data_guid "$data_guid" \
      --arg hash_guid "$hash_guid" \
      '{
        schema_version: $schema_version,
        transaction_id: $transaction_id,
        release_id: $release_id,
        signed_release_manifest_digest: $manifest_digest,
        capsule_digest: $capsule_digest,
        boot_image_digest: $boot_image_digest,
        boot_signature_digest: $boot_signature_digest,
        root_data_digest: $root_data_digest,
        root_hash_tree_digest: $root_hash_digest,
        root_integrity_digest: $root_integrity_digest,
        verity_root_hash: $verity_root_hash,
        boot_partition_guid: $boot_guid,
        data_partition_guid: $data_guid,
        hash_partition_guid: $hash_guid
      }' > "$media_binding"
    verify_regular "$media_binding" 1128 \
      'sha256:aa3ba5a5fa8744f4053785991c74778c0964b8a252f74ba920d578824405bd4f'

    readonly boot_filesystem="$TMPDIR/boot-filesystem.img"
    python3 ${./provisioning/build-canonical-fat.py} \
      --size-bytes "$boot_size" \
      --output "$boot_filesystem" \
      --boot-image "$boot_image" \
      --boot-signature "$boot_signature" \
      --config "$config" \
      --media-binding "$media_binding"
    verify_regular "$boot_filesystem" "$boot_size" \
      'sha256:50b4cf6e0677a8e4787f0cec5942dbf59014242fda0cfbd5660310e1c05c51d3'

    readonly gpt_template="$TMPDIR/gpt-template.img"
    readonly primary_gpt="$TMPDIR/primary-gpt.img"
    readonly backup_gpt="$TMPDIR/backup-gpt.img"
    truncate --size="$target_size" "$gpt_template"
    sgdisk \
      --clear \
      --set-alignment=2048 \
      --disk-guid="$disk_guid" \
      --new=1:2048:264191 \
      --typecode=1:ef00 \
      --change-name=1:kaiba-boot \
      --partition-guid=1:"$boot_guid" \
      --new=2:264192:4874239 \
      --typecode=2:8305 \
      --change-name=2:kaiba-root \
      --partition-guid=2:"$data_guid" \
      --new=3:4874240:4911103 \
      --typecode=3:830e \
      --change-name=3:kaiba-root-verity \
      --partition-guid=3:"$hash_guid" \
      "$gpt_template" > /dev/null
    sgdisk --verify "$gpt_template" > /dev/null
    dd if=/dev/zero of="$gpt_template" bs=1 seek=447 count=3 conv=notrunc status=none
    dd if=/dev/zero of="$gpt_template" bs=1 seek=451 count=3 conv=notrunc status=none
    dd if="$gpt_template" of="$primary_gpt" bs=1M count=1 status=none
    dd if="$gpt_template" of="$backup_gpt" \
      iflag=skip_bytes,count_bytes skip="$backup_offset" \
      count="$alignment" status=none
    verify_regular "$primary_gpt" "$alignment" \
      'sha256:0c9d5f9f8b17a2b1273828189ccfabe3c3e6750a265841190f7ff1187b13d330'
    verify_regular "$backup_gpt" "$alignment" \
      'sha256:dc5932bfc3f9602934a40f05a52d1ef65d788af8a5ab24625764a01f5d6a684f'
    rm "$gpt_template"

    emit_image() {
      cat "$primary_gpt"
      cat "$boot_filesystem"
      cat "$root_data"
      head --bytes=$((root_data_partition_size - 2360344576)) /dev/zero
      cat "$root_hash"
      head --bytes=$((root_hash_partition_size - 18595840)) /dev/zero
      head --bytes="$tail_size" /dev/zero
      cat "$backup_gpt"
    }

    readonly actual_media="sha256:$(emit_image | sha256sum | cut -d ' ' -f 1)"
    test "$actual_media" = "$expected_media"

    mkdir -p "$out"
    readonly archive="$out/${imageFileName}"
    emit_image | zstd --compress --threads=2 -10 --no-progress -o "$archive"
    zstd --test "$archive"
    test "sha256:$(sha256sum "$archive" | cut -d ' ' -f 1)" = "$expected_archive"
    readonly decompressed_digest="sha256:$(
      zstd --decompress --stdout "$archive" | sha256sum | cut -d ' ' -f 1
    )"
    readonly decompressed_size="$(zstd --decompress --stdout "$archive" | wc --bytes)"
    printf 'verified archive digest: %s\n' "$decompressed_digest"
    printf 'verified archive size: %s bytes\n' "$decompressed_size"
    test "$decompressed_digest" = "$expected_media"
    test "$decompressed_size" -eq "$target_size"

    chmod 0444 "$archive"
    test -f "$archive"
    test ! -L "$archive"
    readonly output_entries="$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n')"
    test "$output_entries" = ${pkgs.lib.escapeShellArg imageFileName}
    echo 'signed target image archive verification complete'
  ''
