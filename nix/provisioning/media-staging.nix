{
  pkgs,
  lib,
  mediaContractTool,
  moduleRoot,
  version ? "0.1.0",
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
  printable = value: builtins.isString value && builtins.match "[ -~]{1,128}" value != null;
  trimmedPrintable =
    value:
    printable value
    && (builtins.match "[!-~]" value != null || builtins.match "[!-~][ -~]*[!-~]" value != null);
  canonicalByID =
    value:
    cleanAbsolute value
    && builtins.match "/dev/disk/by-id/[A-Za-z0-9][A-Za-z0-9._:+-]{0,254}" value != null
    && builtins.match ".*-part[0-9]+" value == null;
  canonicalGUID =
    value:
    builtins.isString value
    && builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" value != null
    && value != "00000000-0000-0000-0000-000000000000";

  # Nixpkgs exposes `mtype` as a symlink to the multi-call `mtools` binary,
  # while the verifier deliberately rejects linker-fixed executable symlinks.
  # Materialize the same reviewed executable as one regular store file; argv0
  # remains `mtype`, so the multi-call dispatch is unchanged.
  fixedMType = pkgs.runCommand "kaiba-fixed-mtype" { } ''
    mkdir -p "$out/bin"
    install -m 0555 ${pkgs.mtools}/bin/mtype "$out/bin/mtype"
    test -f "$out/bin/mtype"
    test ! -L "$out/bin/mtype"
  '';

  mkRpi5ProductionMedia =
    {
      verifiedSignedRelease,
      transactionID,
      target,
      initialMediaDigest,
      bootFilesystemSizeMiB ? 128,
      name ? "kaiba-rpi5-production-media",
    }:
    assert lib.assertMsg (storeBacked verifiedSignedRelease)
      "verifiedSignedRelease must be one fixed Nix-store path";
    assert lib.assertMsg (
      builtins.isAttrs verifiedSignedRelease && verifiedSignedRelease ? kaibaVerifiedSignedRelease
    ) "verifiedSignedRelease must be produced by mkRpi5VerifiedSignedRelease";
    assert lib.assertMsg (canonicalIdentifier transactionID)
      "transactionID must be one canonical lowercase identifier";
    assert lib.assertMsg (canonicalDigest initialMediaDigest)
      "initialMediaDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (builtins.isAttrs target)
      "target must be the exact typed physical-media binding";
    assert lib.assertMsg
      (
        builtins.attrNames target == [
          "byIDPath"
          "logicalSectorSizeBytes"
          "model"
          "physicalSectorSizeBytes"
          "serial"
          "sizeBytes"
          "wwid"
        ]
      )
      "target must contain exactly byIDPath, model, serial, wwid, sizeBytes, logicalSectorSizeBytes, and physicalSectorSizeBytes";
    assert lib.assertMsg (canonicalByID target.byIDPath)
      "target.byIDPath must name one canonical whole device below /dev/disk/by-id";
    assert lib.assertMsg (lib.all trimmedPrintable [
      target.model
      target.serial
      target.wwid
    ]) "target model, serial, and wwid must be trimmed non-empty printable ASCII";
    assert lib.assertMsg (
      builtins.isInt target.sizeBytes
      && target.sizeBytes >= 8 * 1024 * 1024
      && target.sizeBytes <= 9223372036854775807
      && builtins.isInt target.logicalSectorSizeBytes
      && target.logicalSectorSizeBytes == 512
      && builtins.isInt target.physicalSectorSizeBytes
      && lib.elem target.physicalSectorSizeBytes [
        512
        1024
        2048
        4096
        8192
        16384
        32768
        65536
      ]
      && lib.mod target.sizeBytes target.logicalSectorSizeBytes == 0
    ) "target capacity and sector sizes must use the frozen 512-byte logical-sector contract";
    assert lib.assertMsg (
      builtins.isInt bootFilesystemSizeMiB && bootFilesystemSizeMiB >= 64 && bootFilesystemSizeMiB <= 256
    ) "bootFilesystemSizeMiB must be an integer from 64 through 256";
    let
      releaseContract = verifiedSignedRelease.kaibaVerifiedSignedRelease;
      unsignedArtifacts = releaseContract.unsignedArtifacts or null;
      unsignedContract =
        if unsignedArtifacts != null && unsignedArtifacts ? kaibaUnsignedArtifacts then
          unsignedArtifacts.kaibaUnsignedArtifacts
        else
          null;
      rootDataPath =
        if unsignedArtifacts == null then "" else "${toString unsignedArtifacts}/nvme/root-data.img";
      rootHashPath =
        if unsignedArtifacts == null then "" else "${toString unsignedArtifacts}/nvme/root-hash.img";
      dataGUID = if unsignedContract == null then "" else unsignedContract.rootDataPartitionGUID or "";
      hashGUID = if unsignedContract == null then "" else unsignedContract.rootHashPartitionGUID or "";
      verifiedReleaseContract =
        (releaseContract.artifactRoleCount or null) == 18
        && (releaseContract.contentAddressedPublication or false)
        && (releaseContract.deterministicEEPROMReplayRequired or false)
        && (releaseContract.deterministicOwnedRecoveryReplayRequired or false)
        &&
          (releaseContract.publicationSchemaVersion or "")
          == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
        &&
          (releaseContract.signedReleaseManifestSchemaVersion or "")
          == "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha2"
        && (releaseContract.verificationMode or "") == "pure_offline_replay"
        && lib.all (value: value == false) [
          (releaseContract.blockDeviceWriteCapable or null)
          (releaseContract.directHardwareAccess or null)
          (releaseContract.eepromProgrammingCapable or null)
          (releaseContract.fixtureHardwareObserved or null)
          (releaseContract.mutationCapable or null)
          (releaseContract.oneTimeSettingCapable or null)
          (releaseContract.otpCapable or null)
          (releaseContract.privateKeyAccess or null)
          (releaseContract.signingAuthorityConfigured or null)
        ];
      unsignedProvenanceContract =
        unsignedContract != null
        &&
          (unsignedContract.schemaVersion or "")
          == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
        && (unsignedContract.signingStatus or "") == "unsigned"
        && (unsignedContract.rootDataPartitionGUID or "") == dataGUID
        && (unsignedContract.rootHashPartitionGUID or "") == hashGUID
        && lib.all (value: value == false) [
          (unsignedContract.blockDeviceWriteCapable or null)
          (unsignedContract.directHardwareAccess or null)
          (unsignedContract.eepromProgrammingCapable or null)
          (unsignedContract.mutationCapable or null)
          (unsignedContract.oneTimeSettingCapable or null)
          (unsignedContract.otpCapable or null)
          (unsignedContract.privateKeyAccess or null)
          (unsignedContract.signingAuthorityConfigured or null)
        ];

      assets =
        assert lib.assertMsg verifiedReleaseContract
          "verifiedSignedRelease nominal contract is incomplete or carries prohibited authority";
        assert lib.assertMsg unsignedProvenanceContract
          "verifiedSignedRelease must retain exact authority-free unsigned-artifact provenance";
        assert lib.assertMsg (lib.all storeBacked [
          unsignedArtifacts
          rootDataPath
          rootHashPath
        ]) "root data and hash sources must be fixed Nix-store paths";
        assert lib.assertMsg (
          canonicalGUID dataGUID && canonicalGUID hashGUID && dataGUID != hashGUID
        ) "verified release must carry distinct preselected root-data and root-hash PARTUUIDs";
        pkgs.runCommand "${name}-assets"
          {
            verifiedReleaseInput = verifiedSignedRelease;
            rootDataInput = rootDataPath;
            rootHashInput = rootHashPath;
            nativeBuildInputs = [
              pkgs.check-jsonschema
              pkgs.coreutils
              pkgs.findutils
              pkgs.gptfdisk
              pkgs.jq
              pkgs.python3
            ];
            preferLocalBuild = true;
            passthru.kaibaRpi5ProductionMediaAssets = {
              inherit
                bootFilesystemSizeMiB
                initialMediaDigest
                transactionID
                target
                verifiedSignedRelease
                ;
              rootDataPartitionGUID = dataGUID;
              rootHashPartitionGUID = hashGUID;
              schemaVersion = "kaiba.provisioning.rpi5-media-staging-plan/v1alpha1";
            };
          }
          ''
            set -euo pipefail
            export LC_ALL=C
            export TZ=UTC
            umask 022

            readonly release="$verifiedReleaseInput"
            readonly publication="$release/publication.json"
            readonly alignment_bytes=1048576
            readonly sector_size_bytes=512
            readonly boot_size_bytes=$((${toString bootFilesystemSizeMiB} * alignment_bytes))
            readonly target_size_bytes=${toString target.sizeBytes}
            readonly provenance_data_guid=${lib.escapeShellArg dataGUID}
            readonly provenance_hash_guid=${lib.escapeShellArg hashGUID}

            test -f "$publication"
            test ! -L "$publication"
            jq -e '
              .schema_version == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
              and (.signed_release_manifest_digest | test("^sha256:[0-9a-f]{64}$"))
              and (.manifest_path | test("^manifests/sha256/[0-9a-f]{64}\\.json$"))
            ' "$publication" > /dev/null

            readonly manifest_digest="$(jq -er .signed_release_manifest_digest "$publication")"
            readonly manifest_path="$(jq -er .manifest_path "$publication")"
            test "$manifest_path" = "manifests/sha256/''${manifest_digest#sha256:}.json"
            readonly manifest="$release/$manifest_path"
            test -f "$manifest"
            test ! -L "$manifest"
            readonly release_id="$(jq -er .release_id "$manifest")"
            test "$(jq -er .schema_version "$manifest")" = \
              'kaiba.provisioning.rpi5-signed-release-manifest/v1alpha2'

            artifact_field() {
              local role="$1"
              local field="$2"
              jq -er \
                --arg role "$role" \
                --arg field "$field" \
                '[.artifacts[] | select(.role == $role and .kind == "regular_file")]
                 | if length == 1 then .[0][$field] else error("missing or duplicate regular artifact") end' \
                "$publication"
            }
            bind_artifact() {
              local role="$1"
              local path digest size
              path="$(artifact_field "$role" path)"
              digest="$(artifact_field "$role" digest)"
              size="$(artifact_field "$role" size_bytes)"
              test "$path" = "objects/sha256/''${digest#sha256:}"
              test "$digest" = "sha256:$(sha256sum "$release/$path" | cut -d ' ' -f 1)"
              test "$size" = "$(stat --format=%s "$release/$path")"
              printf '%s\t%s\t%s' "$release/$path" "$digest" "$size"
            }
            field() {
              printf '%s' "$1" | cut -f "$2"
            }
            digest_file() {
              printf 'sha256:%s' "$(sha256sum "$1" | cut -d ' ' -f 1)"
            }
            digest_padded_file() {
              local source="$1"
              local padded_size="$2"
              local source_size
              source_size="$(stat --format=%s "$source")"
              test "$source_size" -le "$padded_size"
              {
                cat "$source"
                head --bytes=$((padded_size - source_size)) /dev/zero
              } | sha256sum | sed 's/^/sha256:/' | cut -d ' ' -f 1
            }
            digest_zeroes() {
              head --bytes="$1" /dev/zero | sha256sum | sed 's/^/sha256:/' | cut -d ' ' -f 1
            }
            align_up() {
              printf '%d' $(( ($1 + alignment_bytes - 1) / alignment_bytes * alignment_bytes ))
            }
            derive_uuid() {
              local domain="$1"
              local hex
              hex="$({
                printf '%s\0' "$domain"
                printf '%s\0%s\0%s\0%s\0' \
                  "$manifest_digest" \
                  ${lib.escapeShellArg transactionID} \
                  ${lib.escapeShellArg target.byIDPath} \
                  "$target_size_bytes"
              } | sha256sum | cut -d ' ' -f 1)"
              printf '%s-%s-4%s-8%s-%s' \
                "''${hex:0:8}" "''${hex:8:4}" "''${hex:13:3}" \
                "''${hex:17:3}" "''${hex:20:12}"
            }

            readonly boot_record="$(bind_artifact rpi5.boot_image)"
            readonly signature_record="$(bind_artifact rpi5.boot_signature)"
            readonly data_record="$(bind_artifact rpi5.root_data_image)"
            readonly hash_record="$(bind_artifact rpi5.root_hash_tree_image)"
            readonly integrity_record="$(bind_artifact root_integrity)"
            readonly boot_image="$(field "$boot_record" 1)"
            readonly boot_image_digest="$(field "$boot_record" 2)"
            readonly boot_image_size="$(field "$boot_record" 3)"
            readonly boot_signature="$(field "$signature_record" 1)"
            readonly boot_signature_digest="$(field "$signature_record" 2)"
            readonly boot_signature_size="$(field "$signature_record" 3)"
            readonly publication_root_data="$(field "$data_record" 1)"
            readonly root_data_digest="$(field "$data_record" 2)"
            readonly root_data_size="$(field "$data_record" 3)"
            readonly publication_root_hash="$(field "$hash_record" 1)"
            readonly root_hash_digest="$(field "$hash_record" 2)"
            readonly root_hash_size="$(field "$hash_record" 3)"
            readonly root_integrity="$(field "$integrity_record" 1)"
            readonly root_integrity_digest="$(field "$integrity_record" 2)"
            readonly root_integrity_size="$(field "$integrity_record" 3)"

            cmp "$publication_root_data" "$rootDataInput"
            cmp "$publication_root_hash" "$rootHashInput"
            test "$root_data_size" -gt 0
            test "$root_hash_size" -gt 0
            test $((root_data_size % 4096)) -eq 0
            test $((root_hash_size % 4096)) -eq 0

            jq -e \
              --arg data "PARTUUID=$provenance_data_guid" \
              --arg hash "PARTUUID=$provenance_hash_guid" \
              '.schema == "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1"
               and .algorithm == "sha256"
               and .data_block_size == 4096
               and .hash_block_size == 4096
               and .no_superblock == false
               and (.root_hash | test("^[0-9a-f]{64}$"))
               and .data_device == $data
               and .hash_device == $hash
               and (keys == ["algorithm", "data_block_size", "data_device", "hash_block_size", "hash_device", "no_superblock", "root_hash", "schema"])' \
              "$root_integrity" > /dev/null
            readonly verity_root_hash="sha256:$(jq -er .root_hash "$root_integrity")"

            readonly capsule_digest="sha256:$({
              printf '%s\0' 'kaiba.rpi5.unfused-capsule.v1'
              printf '%s\0%s\0%s\0' 'boot.img' "$boot_image_size" "$boot_image_digest"
              printf '%s\0%s\0%s\0' 'boot.sig' "$boot_signature_size" "$boot_signature_digest"
              printf '%s\0%s\0%s\0' 'nvme/root-data.img' "$root_data_size" "$root_data_digest"
              printf '%s\0%s\0%s\0' 'nvme/root-hash.img' "$root_hash_size" "$root_hash_digest"
            } | sha256sum | cut -d ' ' -f 1)"

            readonly disk_guid="$(derive_uuid kaiba.provisioning.production-media.disk.v1)"
            readonly boot_guid="$(derive_uuid kaiba.provisioning.production-media.partition.boot.v1)"
            test "$disk_guid" != "$boot_guid"
            test "$disk_guid" != "$provenance_data_guid"
            test "$disk_guid" != "$provenance_hash_guid"
            test "$boot_guid" != "$provenance_data_guid"
            test "$boot_guid" != "$provenance_hash_guid"

            mkdir -p "$out"
            readonly config="$TMPDIR/config.txt"
            printf '%s\n' 'boot_ramdisk=1' > "$config"
            readonly config_digest="$(digest_file "$config")"
            readonly config_size="$(stat --format=%s "$config")"

            jq -cjn \
              --arg schema_version 'kaiba.provisioning.rpi5-media-binding/v1alpha1' \
              --arg transaction_id ${lib.escapeShellArg transactionID} \
              --arg release_id "$release_id" \
              --arg manifest_digest "$manifest_digest" \
              --arg capsule_digest "$capsule_digest" \
              --arg boot_image_digest "$boot_image_digest" \
              --arg boot_signature_digest "$boot_signature_digest" \
              --arg root_data_digest "$root_data_digest" \
              --arg root_hash_digest "$root_hash_digest" \
              --arg root_integrity_digest "$root_integrity_digest" \
              --arg verity_root_hash "$verity_root_hash" \
              --arg boot_guid "$boot_guid" \
              --arg data_guid "$provenance_data_guid" \
              --arg hash_guid "$provenance_hash_guid" \
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
              }' > "$out/media-binding.json"
            readonly media_binding_digest="$(digest_file "$out/media-binding.json")"
            readonly media_binding_size="$(stat --format=%s "$out/media-binding.json")"

            python3 ${./build-canonical-fat.py} \
              --size-bytes "$boot_size_bytes" \
              --output "$out/boot-filesystem.img" \
              --boot-image "$boot_image" \
              --boot-signature "$boot_signature" \
              --config "$config" \
              --media-binding "$out/media-binding.json"
            readonly boot_filesystem_digest="$(digest_file "$out/boot-filesystem.img")"

            readonly boot_offset_bytes="$alignment_bytes"
            readonly root_data_offset_bytes=$((boot_offset_bytes + boot_size_bytes))
            readonly root_data_partition_size="$(align_up "$root_data_size")"
            readonly root_hash_offset_bytes=$((root_data_offset_bytes + root_data_partition_size))
            readonly root_hash_partition_size="$(align_up "$root_hash_size")"
            readonly payload_end_bytes=$((root_hash_offset_bytes + root_hash_partition_size))
            readonly backup_gpt_offset_bytes=$((target_size_bytes - alignment_bytes))
            test "$target_size_bytes" -ge $((payload_end_bytes + alignment_bytes))
            readonly tail_zero_size=$((backup_gpt_offset_bytes - payload_end_bytes))
            readonly first_usable_lba=34
            readonly last_usable_lba=$((target_size_bytes / sector_size_bytes - 34))

            readonly gpt_template="$TMPDIR/gpt-template.img"
            truncate --size="$target_size_bytes" "$gpt_template"
            readonly boot_start=$((boot_offset_bytes / sector_size_bytes))
            readonly boot_end=$((boot_start + boot_size_bytes / sector_size_bytes - 1))
            readonly root_start=$((root_data_offset_bytes / sector_size_bytes))
            readonly root_end=$((root_start + root_data_partition_size / sector_size_bytes - 1))
            readonly hash_start=$((root_hash_offset_bytes / sector_size_bytes))
            readonly hash_end=$((hash_start + root_hash_partition_size / sector_size_bytes - 1))
            sgdisk \
              --clear \
              --set-alignment=$((alignment_bytes / sector_size_bytes)) \
              --disk-guid="$disk_guid" \
              --new=1:"$boot_start":"$boot_end" \
              --typecode=1:ef00 \
              --change-name=1:kaiba-boot \
              --partition-guid=1:"$boot_guid" \
              --new=2:"$root_start":"$root_end" \
              --typecode=2:8305 \
              --change-name=2:kaiba-root \
              --partition-guid=2:"$provenance_data_guid" \
              --new=3:"$hash_start":"$hash_end" \
              --typecode=3:830e \
              --change-name=3:kaiba-root-verity \
              --partition-guid=3:"$provenance_hash_guid" \
              "$gpt_template" > /dev/null
            sgdisk --verify "$gpt_template" > /dev/null
            # CHS is semantically ignored for a protective GPT entry. Freeze
            # both three-byte CHS fields to zero so they cannot carry hidden
            # per-build metadata while the LBA view remains unchanged.
            dd if=/dev/zero of="$gpt_template" bs=1 seek=447 count=3 conv=notrunc status=none
            dd if=/dev/zero of="$gpt_template" bs=1 seek=451 count=3 conv=notrunc status=none
            dd if="$gpt_template" of="$out/primary-gpt.img" bs=1M count=1 status=none
            dd if="$gpt_template" of="$out/backup-gpt.img" \
              iflag=skip_bytes,count_bytes skip="$backup_gpt_offset_bytes" \
              count="$alignment_bytes" status=none
            readonly primary_gpt_digest="$(digest_file "$out/primary-gpt.img")"
            readonly backup_gpt_digest="$(digest_file "$out/backup-gpt.img")"
            readonly root_data_partition_digest="$(digest_padded_file "$rootDataInput" "$root_data_partition_size")"
            readonly root_hash_partition_digest="$(digest_padded_file "$rootHashInput" "$root_hash_partition_size")"
            readonly empty_digest="$(digest_zeroes 0)"
            readonly tail_zero_digest="$(digest_zeroes "$tail_zero_size")"
            readonly expected_media_digest="sha256:$({
              cat "$out/primary-gpt.img"
              cat "$out/boot-filesystem.img"
              cat "$rootDataInput"
              head --bytes=$((root_data_partition_size - root_data_size)) /dev/zero
              cat "$rootHashInput"
              head --bytes=$((root_hash_partition_size - root_hash_size)) /dev/zero
              head --bytes="$tail_zero_size" /dev/zero
              cat "$out/backup-gpt.img"
            } | sha256sum | cut -d ' ' -f 1)"

            jq -cjn \
              --arg schema_version 'kaiba.provisioning.rpi5-device-media-layout/v1alpha1' \
              --arg disk_guid "$disk_guid" \
              --arg boot_image_digest "$boot_image_digest" \
              --arg boot_signature_digest "$boot_signature_digest" \
              --arg root_data_digest "$root_data_digest" \
              --arg root_hash_digest "$root_hash_digest" \
              --arg root_integrity_digest "$root_integrity_digest" \
              --arg media_binding_digest "$media_binding_digest" \
              --arg boot_filesystem_digest "$boot_filesystem_digest" \
              --arg primary_gpt_digest "$primary_gpt_digest" \
              --arg backup_gpt_digest "$backup_gpt_digest" \
              --arg root_data_partition_digest "$root_data_partition_digest" \
              --arg root_hash_partition_digest "$root_hash_partition_digest" \
              --arg config_digest "$config_digest" \
              --arg empty_digest "$empty_digest" \
              --arg tail_zero_digest "$tail_zero_digest" \
              --arg verity_root_hash "$verity_root_hash" \
              --arg boot_guid "$boot_guid" \
              --arg data_guid "$provenance_data_guid" \
              --arg hash_guid "$provenance_hash_guid" \
              --argjson sector_size "$sector_size_bytes" \
              --argjson alignment "$alignment_bytes" \
              --argjson first_lba "$first_usable_lba" \
              --argjson last_lba "$last_usable_lba" \
              --argjson boot_image_size "$boot_image_size" \
              --argjson boot_signature_size "$boot_signature_size" \
              --argjson root_data_size "$root_data_size" \
              --argjson root_hash_size "$root_hash_size" \
              --argjson root_integrity_size "$root_integrity_size" \
              --argjson media_binding_size "$media_binding_size" \
              --argjson boot_size "$boot_size_bytes" \
              --argjson alignment_size "$alignment_bytes" \
              --argjson config_size "$config_size" \
              --argjson boot_offset "$boot_offset_bytes" \
              --argjson root_data_offset "$root_data_offset_bytes" \
              --argjson root_data_partition_size "$root_data_partition_size" \
              --argjson root_hash_offset "$root_hash_offset_bytes" \
              --argjson root_hash_partition_size "$root_hash_partition_size" \
              --argjson payload_end "$payload_end_bytes" \
              --argjson tail_size "$tail_zero_size" \
              --argjson backup_offset "$backup_gpt_offset_bytes" \
              '{
                schema_version: $schema_version,
                sector_size_bytes: $sector_size,
                alignment_bytes: $alignment,
                disk_guid: $disk_guid,
                first_usable_lba: $first_lba,
                last_usable_lba: $last_lba,
                payloads: {
                  boot_image: {digest: $boot_image_digest, size_bytes: $boot_image_size},
                  boot_signature: {digest: $boot_signature_digest, size_bytes: $boot_signature_size},
                  root_data: {digest: $root_data_digest, size_bytes: $root_data_size},
                  root_hash_tree: {digest: $root_hash_digest, size_bytes: $root_hash_size},
                  root_integrity: {digest: $root_integrity_digest, size_bytes: $root_integrity_size},
                  media_binding: {digest: $media_binding_digest, size_bytes: $media_binding_size},
                  outer_boot_fat: {digest: $boot_filesystem_digest, size_bytes: $boot_size},
                  primary_gpt: {digest: $primary_gpt_digest, size_bytes: $alignment_size},
                  backup_gpt: {digest: $backup_gpt_digest, size_bytes: $alignment_size}
                },
                sources: [
                  {role: "primary-gpt", digest: $primary_gpt_digest, size_bytes: $alignment_size},
                  {role: "boot-filesystem", digest: $boot_filesystem_digest, size_bytes: $boot_size},
                  {role: "root-data", digest: $root_data_digest, size_bytes: $root_data_size},
                  {role: "root-hash", digest: $root_hash_digest, size_bytes: $root_hash_size},
                  {role: "backup-gpt", digest: $backup_gpt_digest, size_bytes: $alignment_size}
                ],
                regions: [
                  {role: "primary-gpt", content_kind: "exact-file", source_role: "primary-gpt", offset_bytes: 0, size_bytes: $alignment_size, source_size_bytes: $alignment_size, source_digest: $primary_gpt_digest, content_digest: $primary_gpt_digest},
                  {role: "boot-filesystem", content_kind: "exact-file", source_role: "boot-filesystem", offset_bytes: $boot_offset, size_bytes: $boot_size, source_size_bytes: $boot_size, source_digest: $boot_filesystem_digest, content_digest: $boot_filesystem_digest},
                  {role: "root-data", content_kind: "file-zero-padded", source_role: "root-data", offset_bytes: $root_data_offset, size_bytes: $root_data_partition_size, source_size_bytes: $root_data_size, source_digest: $root_data_digest, content_digest: $root_data_partition_digest},
                  {role: "root-hash", content_kind: "file-zero-padded", source_role: "root-hash", offset_bytes: $root_hash_offset, size_bytes: $root_hash_partition_size, source_size_bytes: $root_hash_size, source_digest: $root_hash_digest, content_digest: $root_hash_partition_digest},
                  {role: "tail-zero", content_kind: "zero", source_role: "zero", offset_bytes: $payload_end, size_bytes: $tail_size, source_size_bytes: 0, source_digest: $empty_digest, content_digest: $tail_zero_digest},
                  {role: "backup-gpt", content_kind: "exact-file", source_role: "backup-gpt", offset_bytes: $backup_offset, size_bytes: $alignment_size, source_size_bytes: $alignment_size, source_digest: $backup_gpt_digest, content_digest: $backup_gpt_digest}
                ],
                partitions: [
                  {number: 1, role: "boot-filesystem", name: "kaiba-boot", type_guid: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", unique_guid: $boot_guid, attributes: 0, offset_bytes: $boot_offset, size_bytes: $boot_size, used_size_bytes: $boot_size, used_digest: $boot_filesystem_digest, partition_digest: $boot_filesystem_digest},
                  {number: 2, role: "root-data", name: "kaiba-root", type_guid: "b921b045-1df0-41c3-af44-4c6f280d3fae", unique_guid: $data_guid, attributes: 0, offset_bytes: $root_data_offset, size_bytes: $root_data_partition_size, used_size_bytes: $root_data_size, used_digest: $root_data_digest, partition_digest: $root_data_partition_digest},
                  {number: 3, role: "root-hash", name: "kaiba-root-verity", type_guid: "df3300ce-d69f-4c92-978c-9bfb0f38d820", unique_guid: $hash_guid, attributes: 0, offset_bytes: $root_hash_offset, size_bytes: $root_hash_partition_size, used_size_bytes: $root_hash_size, used_digest: $root_hash_digest, partition_digest: $root_hash_partition_digest}
                ],
                fat: {
                  filesystem: "fat32",
                  label: "KAIBA_BOOT",
                  volume_id: "4b414942",
                  allowlist: [
                    {path: "boot.img", digest: $boot_image_digest, size_bytes: $boot_image_size},
                    {path: "boot.sig", digest: $boot_signature_digest, size_bytes: $boot_signature_size},
                    {path: "config.txt", digest: $config_digest, size_bytes: $config_size},
                    {path: "kaiba-media-binding.json", digest: $media_binding_digest, size_bytes: $media_binding_size}
                  ]
                },
                verity: {
                  algorithm: "sha256",
                  root_hash: $verity_root_hash,
                  data_block_size_bytes: 4096,
                  hash_block_size_bytes: 4096,
                  data_partition_guid: $data_guid,
                  hash_partition_guid: $hash_guid,
                  mapper: "/dev/mapper/root"
                },
                layout_digest: ""
              }' > "$TMPDIR/layout-material.json"
            readonly layout_digest="sha256:$({
              printf '%s\0' 'kaiba.provisioning.rpi5-device-media-layout.v1alpha1'
              cat "$TMPDIR/layout-material.json"
            } | sha256sum | cut -d ' ' -f 1)"
            jq -cj --arg digest "$layout_digest" '.layout_digest = $digest' \
              "$TMPDIR/layout-material.json" > "$out/layout.json"

            jq -cjn \
              --slurpfile layout "$out/layout.json" \
              --arg schema_version 'kaiba.provisioning.rpi5-media-staging-plan/v1alpha1' \
              --arg transaction_id ${lib.escapeShellArg transactionID} \
              --arg release_id "$release_id" \
              --arg manifest_digest "$manifest_digest" \
              --arg capsule_digest "$capsule_digest" \
              --arg by_id_path ${lib.escapeShellArg target.byIDPath} \
              --arg model ${lib.escapeShellArg target.model} \
              --arg serial ${lib.escapeShellArg target.serial} \
              --arg wwid ${lib.escapeShellArg target.wwid} \
              --arg initial_digest ${lib.escapeShellArg initialMediaDigest} \
              --arg expected_digest "$expected_media_digest" \
              --argjson size_bytes ${toString target.sizeBytes} \
              --argjson logical_sector ${toString target.logicalSectorSizeBytes} \
              --argjson physical_sector ${toString target.physicalSectorSizeBytes} \
              '{
                schema_version: $schema_version,
                transaction_id: $transaction_id,
                release: {
                  release_id: $release_id,
                  signed_release_manifest_digest: $manifest_digest,
                  capsule_digest: $capsule_digest
                },
                target: {
                  by_id_path: $by_id_path,
                  model: $model,
                  serial: $serial,
                  wwid: $wwid,
                  size_bytes: $size_bytes,
                  logical_sector_size_bytes: $logical_sector,
                  physical_sector_size_bytes: $physical_sector
                },
                layout: $layout[0],
                initial_media_digest: $initial_digest,
                expected_media_digest: $expected_digest,
                plan_digest: ""
              }' > "$TMPDIR/plan-material.json"
            readonly plan_digest="sha256:$({
              printf '%s\0' 'kaiba.provisioning.rpi5-media-staging-plan.v1alpha1'
              cat "$TMPDIR/plan-material.json"
            } | sha256sum | cut -d ' ' -f 1)"
            jq -cj --arg digest "$plan_digest" '.plan_digest = $digest' \
              "$TMPDIR/plan-material.json" > "$out/plan.json"
            printf '%s\n' "$plan_digest" > "$out/plan-digest"
            printf '%s\n' "$expected_media_digest" > "$out/expected-media-digest"

            ${mediaContractTool}/bin/kaiba-provision-media-contract validate-plan \
              --plan "$out/plan.json" > "$TMPDIR/validated-plan.json"
            test "$(jq -er .plan_digest "$TMPDIR/validated-plan.json")" = "$plan_digest"
            test "$(jq -cj .layout "$out/plan.json")" = "$(cat "$out/layout.json")"
            check-jsonschema \
              --schemafile ${moduleRoot}/schemas/rpi5-media-binding-v1alpha1.schema.json \
              "$out/media-binding.json"
            check-jsonschema \
              --schemafile ${moduleRoot}/schemas/rpi5-device-media-layout-v1alpha1.schema.json \
              "$out/layout.json"
            check-jsonschema \
              --base-uri file://${moduleRoot}/schemas/ \
              --schemafile ${moduleRoot}/schemas/rpi5-media-staging-plan-v1alpha1.schema.json \
              "$out/plan.json"

            chmod 0444 \
              "$out/backup-gpt.img" \
              "$out/boot-filesystem.img" \
              "$out/expected-media-digest" \
              "$out/layout.json" \
              "$out/media-binding.json" \
              "$out/plan-digest" \
              "$out/plan.json" \
              "$out/primary-gpt.img"
            test "$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
              $'backup-gpt.img\nboot-filesystem.img\nexpected-media-digest\nlayout.json\nmedia-binding.json\nplan-digest\nplan.json\nprimary-gpt.img'
          '';

      commonAssetLDFlags = [
        "-X=main.approvedPlanPath=${assets}/plan.json"
        "-X=main.primaryGPTPath=${assets}/primary-gpt.img"
        "-X=main.bootFilesystemPath=${assets}/boot-filesystem.img"
        "-X=main.rootDataPath=${rootDataPath}"
        "-X=main.rootHashPath=${rootHashPath}"
        "-X=main.backupGPTPath=${assets}/backup-gpt.img"
      ];
      verifierLDFlags = [
        "-X=main.approvedPlanPath=${assets}/plan.json"
        "-X=main.veritysetupPath=${pkgs.cryptsetup}/bin/veritysetup"
        "-X=main.signedReleasePath=${verifiedSignedRelease}"
        "-X=main.mtypePath=${fixedMType}/bin/mtype"
      ];

      deviceStager = pkgs.buildGoModule {
        pname = "${name}-device-stager";
        inherit version;
        src = moduleRoot;
        subPackages = [ "cmd/kaiba-provision-media-device-stager" ];
        ldflags = commonAssetLDFlags;
        vendorHash = null;
        doCheck = false;
        passthru.kaibaMediaDeviceStager = {
          approvedPlan = "${assets}/plan.json";
          blockDeviceWriteCapable = true;
          fixtureModeAvailable = false;
          mutationScope = "one_linker_fixed_whole_device";
          oneTimeSettingCapable = false;
          otpCapable = false;
          eepromProgrammingCapable = false;
        };
        meta = {
          mainProgram = "kaiba-provision-media-device-stager";
          description = "Plan-specialized fail-closed Raspberry Pi 5 block-device stager";
          platforms = lib.platforms.linux;
        };
      };

      deviceVerifier = pkgs.buildGoModule {
        pname = "${name}-device-verifier";
        inherit version;
        src = moduleRoot;
        subPackages = [ "cmd/kaiba-provision-media-device-verifier" ];
        ldflags = verifierLDFlags;
        vendorHash = null;
        doCheck = false;
        passthru.kaibaMediaDeviceVerifier = {
          approvedPlan = "${assets}/plan.json";
          blockDeviceReadCapable = true;
          blockDeviceWriteCapable = false;
          independentAttachmentRequired = true;
          releaseLineageVerifier = verifiedSignedRelease;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          eepromProgrammingCapable = false;
        };
        meta = {
          mainProgram = "kaiba-provision-media-device-verifier";
          description = "Plan-specialized independent read-only Raspberry Pi 5 media verifier";
          platforms = lib.platforms.linux;
        };
      };

      fixtureStager = pkgs.buildGoModule {
        pname = "${name}-fixture-stager";
        inherit version;
        src = moduleRoot;
        subPackages = [ "cmd/kaiba-provision-media-fixture-stager" ];
        ldflags = commonAssetLDFlags;
        vendorHash = null;
        doCheck = false;
        passthru.kaibaMediaFixtureStager = {
          approvedPlan = "${assets}/plan.json";
          blockDeviceAccess = false;
          evidenceMode = "regular_file_fixture";
          mutationEligible = false;
        };
        meta = {
          mainProgram = "kaiba-provision-media-fixture-stager";
          description = "Plan-specialized regular-file-only media fixture stager";
          platforms = lib.platforms.linux;
        };
      };

      regularVerifier = pkgs.buildGoModule {
        pname = "${name}-regular-verifier";
        inherit version;
        src = moduleRoot;
        subPackages = [ "cmd/kaiba-provision-media-verifier" ];
        ldflags = verifierLDFlags;
        vendorHash = null;
        doCheck = false;
        passthru.kaibaMediaRegularVerifier = {
          approvedPlan = "${assets}/plan.json";
          blockDeviceAccess = false;
          evidenceMode = "regular_file_fixture";
          releaseLineageVerifier = verifiedSignedRelease;
          mutationCapable = false;
        };
        meta = {
          mainProgram = "kaiba-provision-media-verifier";
          description = "Plan-specialized regular-file full-media verifier";
          platforms = lib.platforms.linux;
        };
      };

      softwareCheck =
        pkgs.runCommand "${name}-software-check"
          {
            nativeBuildInputs = [
              pkgs.check-jsonschema
              pkgs.coreutils
              pkgs.gnugrep
              pkgs.jq
              fixtureStager
              regularVerifier
            ];
            preferLocalBuild = true;
          }
          ''
              set -euo pipefail
              export LC_ALL=C
              readonly target="$TMPDIR/fixture-media.img"
              readonly target_size=${toString target.sizeBytes}
              truncate --size="$target_size" "$target"

              # Exercise the actual linker-specialized staging path, including
              # complete prestate hashing, immutable source validation, ordered
              # durable writes, close/reopen, and full-media readback.
              ${fixtureStager}/bin/kaiba-provision-media-fixture-stager stage \
                --plan ${assets}/plan.json \
                --target "$target" \
                --result "$TMPDIR/fixture-result.json"
              check-jsonschema \
                --schemafile ${moduleRoot}/schemas/rpi5-media-fixture-result-v1alpha1.schema.json \
                "$TMPDIR/fixture-result.json"
              jq -e \
                --arg expected "$(cat ${assets}/expected-media-digest)" '
                  .status == "fixture_staged_and_reopened"
                  and .evidence_mode == "regular_file_fixture"
                  and .full_media_digest == $expected
                  and .reopened_target == true
                  and .block_device_access == false
                  and .hardware_observed == false
                  and .cold_power_cycle_observed == false
                  and .security_enforced == false
                  and .mutation_eligible == false
                ' "$TMPDIR/fixture-result.json" > /dev/null

              ${regularVerifier}/bin/kaiba-provision-media-verifier verify-regular-file \
                --plan ${assets}/plan.json \
                --target "$target" > "$TMPDIR/verification-report.json"
              jq -e '
                .schema_version == "kaiba.provisioning.rpi5-media-verification-report/v1alpha1"
                and .gpt_verified == true
                and .fat_verified == true
                and .partition_digests_verified == true
                and .dm_verity_verified == true
                and .boot_signature_verified == true
                and .release_lineage_verified == true
                and .hardware_observed == false
                and .cold_power_cycle_observed == false
                and .security_enforced == false
                and .mutation_eligible == false
              ' "$TMPDIR/verification-report.json" > /dev/null
              check-jsonschema \
                --schemafile ${moduleRoot}/schemas/rpi5-media-verification-report-v1alpha1.schema.json \
                "$TMPDIR/verification-report.json"

              cp --reflink=auto --sparse=always "$target" "$TMPDIR/clean-media.img"
              expect_verifier_rejection() {
                local label="$1"
                local offset="$2"
                cp --reflink=auto --sparse=always \
                  "$TMPDIR/clean-media.img" "$TMPDIR/$label.img"
                printf '\001' | dd of="$TMPDIR/$label.img" bs=1 seek="$offset" \
                  conv=notrunc status=none
                if ${regularVerifier}/bin/kaiba-provision-media-verifier verify-regular-file \
                  --plan ${assets}/plan.json \
                  --target "$TMPDIR/$label.img" \
                  > "$TMPDIR/$label.stdout" 2> "$TMPDIR/$label.stderr"
                then
                  echo "regular verifier accepted tampered media: $label" >&2
                  exit 1
                fi
                grep -F 'verify regular-file media:' "$TMPDIR/$label.stderr" > /dev/null
              }

              readonly boot_offset="$(jq -er '.layout.partitions[] | select(.role == "boot-filesystem") | .offset_bytes' ${assets}/plan.json)"
              readonly boot_size="$(jq -er '.layout.partitions[] | select(.role == "boot-filesystem") | .size_bytes' ${assets}/plan.json)"
              readonly root_data_offset="$(jq -er '.layout.partitions[] | select(.role == "root-data") | .offset_bytes' ${assets}/plan.json)"
              readonly root_hash_offset="$(jq -er '.layout.partitions[] | select(.role == "root-hash") | .offset_bytes' ${assets}/plan.json)"
              readonly root_hash_used="$(jq -er '.layout.partitions[] | select(.role == "root-hash") | .used_size_bytes' ${assets}/plan.json)"
              readonly root_hash_size="$(jq -er '.layout.partitions[] | select(.role == "root-hash") | .size_bytes' ${assets}/plan.json)"
              readonly tail_offset="$(jq -er '.layout.regions[] | select(.role == "tail-zero") | .offset_bytes' ${assets}/plan.json)"
              readonly backup_offset="$(jq -er '.layout.regions[] | select(.role == "backup-gpt") | .offset_bytes' ${assets}/plan.json)"

            # End-to-end integrity coverage: mutations in primary metadata,
            # hidden FAT slack, payload bytes, padded root-hash bytes, zero tail,
            # and backup metadata are all rejected from cloned valid media.
            # Parser-specific rebinding cases are covered by the Go tests above.
              expect_verifier_rejection primary-gpt-chs 447
              expect_verifier_rejection fat-hidden-slack "$((boot_offset + boot_size - 1))"
              expect_verifier_rejection root-data "$root_data_offset"
              expect_verifier_rejection root-hash "$root_hash_offset"
              test "$root_hash_used" -lt "$root_hash_size"
              expect_verifier_rejection root-hash-padding "$((root_hash_offset + root_hash_used))"
              expect_verifier_rejection tail-zero "$tail_offset"
              expect_verifier_rejection backup-gpt-padding "$backup_offset"

              cp "$TMPDIR/verification-report.json" "$out"
          '';

      # Return the asset derivation itself so `$result/plan.json` is a regular
      # file.  All plan consumers open with O_NOFOLLOW; a symlinkJoin would
      # make the most obvious operator path unusable even though its bytes are
      # identical to the linker-approved plan.
      result = assets.overrideAttrs (old: {
        passthru = (old.passthru or { }) // {
          kaibaRpi5ProductionMedia = {
            inherit
              assets
              deviceStager
              deviceVerifier
              fixtureStager
              initialMediaDigest
              regularVerifier
              softwareCheck
              target
              transactionID
              verifiedSignedRelease
              ;
            plan = "${assets}/plan.json";
            rootDataSource = rootDataPath;
            rootHashSource = rootHashPath;
            blockDeviceWriteCapable = false;
            contentAddressedReleaseRequired = true;
            directHardwareAccess = false;
            fixtureHardwareObserved = false;
            mutationCapable = false;
            oneTimeSettingCapable = false;
            otpCapable = false;
            schemaVersion = "kaiba.provisioning.rpi5-media-staging-plan/v1alpha1";
            signingAuthorityConfigured = false;
            verificationMode = "pure_offline_plan_derivation";
          };
        };
        meta = {
          description = "Typed immutable Raspberry Pi 5 production-media plan and source set";
          platforms = lib.platforms.linux;
        };
      });
    in
    assert lib.assertMsg verifiedReleaseContract
      "verifiedSignedRelease nominal contract is incomplete or carries prohibited authority";
    assert lib.assertMsg unsignedProvenanceContract
      "verifiedSignedRelease must retain exact authority-free unsigned-artifact provenance";
    assert lib.assertMsg (lib.all storeBacked [
      unsignedArtifacts
      rootDataPath
      rootHashPath
    ]) "root data and hash sources must be fixed Nix-store paths";
    assert lib.assertMsg (
      canonicalGUID dataGUID && canonicalGUID hashGUID && dataGUID != hashGUID
    ) "verified release must carry distinct preselected root-data and root-hash PARTUUIDs";
    result;
in
{
  inherit mkRpi5ProductionMedia;
}
