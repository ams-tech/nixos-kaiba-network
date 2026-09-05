{
  expectedBootImageDigest,
  imageFileName ? "kaiba-rpi5-development-secure-boot-target.img.zst",
  name ? "kaiba-rpi5-development-secure-boot-target-image",
  payloadSourceRevision,
  pkgs,
  productionMedia,
}:

let
  contract = productionMedia.kaibaRpi5ProductionMedia or { };
  targetGeometry = contract.targetGeometry or { };
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
in
assert builtins.isAttrs contract;
assert contract.verificationMode or null == "pure_offline_plan_derivation";
assert contract.blockDeviceWriteCapable or null == false;
assert contract.directHardwareAccess or null == false;
assert contract.signingAuthorityConfigured or null == false;
assert builtins.isInt (targetGeometry.sizeBytes or null);
assert targetGeometry.sizeBytes == 3 * 1024 * 1024 * 1024;
assert targetGeometry.logicalSectorSizeBytes or null == 512;
assert contract.fixtureStager or null != null;
assert contract.regularVerifier or null != null;
assert canonicalDigest expectedBootImageDigest;
assert canonicalRevision payloadSourceRevision;
assert builtins.match "[a-z0-9.-]+\\.img\\.zst" imageFileName != null;
pkgs.runCommand name
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.jq
      pkgs.zstd
    ];
    preferLocalBuild = true;
    passthru.kaibaRpi5SignedTargetImage = {
      inherit
        expectedBootImageDigest
        imageFileName
        payloadSourceRevision
        productionMedia
        ;
      compressed = true;
      directHardwareAccess = false;
      imageSizeBytes = targetGeometry.sizeBytes;
      logicalSectorSizeBytes = targetGeometry.logicalSectorSizeBytes;
      minimumTargetCapacityBytes = targetGeometry.sizeBytes;
      mutationCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
      signingCapable = false;
      wholeDeviceImage = true;
    };
    meta = {
      description = "Flashable Raspberry Pi 5 signed v0.1.6 target SD image";
      platforms = pkgs.lib.platforms.linux;
    };
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export TZ=UTC
    umask 022

    readonly plan=${productionMedia}/plan.json
    readonly target_size=${toString targetGeometry.sizeBytes}
    readonly primary_gpt=${productionMedia}/primary-gpt.img
    readonly boot_filesystem=${productionMedia}/boot-filesystem.img
    readonly root_data=${contract.rootDataSource}
    readonly root_hash=${contract.rootHashSource}
    readonly backup_gpt=${productionMedia}/backup-gpt.img

    test -f "$plan"
    test ! -L "$plan"
    test "$(jq -er .target.size_bytes "$plan")" -eq "$target_size"
    test "$(jq -er .target.logical_sector_size_bytes "$plan")" -eq 512
    test "$(jq -er '
      .layout.fat.allowlist[]
      | select(.path == "boot.img")
      | .digest
    ' "$plan")" = ${pkgs.lib.escapeShellArg expectedBootImageDigest}

    readonly expected_media_digest="$(cat ${productionMedia}/expected-media-digest)"
    readonly primary_size="$(stat --format=%s "$primary_gpt")"
    readonly boot_size="$(stat --format=%s "$boot_filesystem")"
    readonly root_data_size="$(stat --format=%s "$root_data")"
    readonly root_hash_size="$(stat --format=%s "$root_hash")"
    readonly backup_size="$(stat --format=%s "$backup_gpt")"
    readonly root_data_partition_size="$(jq -er '
      .layout.partitions[] | select(.role == "root-data") | .size_bytes
    ' "$plan")"
    readonly root_hash_partition_size="$(jq -er '
      .layout.partitions[] | select(.role == "root-hash") | .size_bytes
    ' "$plan")"
    readonly tail_size="$(jq -er '
      .layout.regions[] | select(.role == "tail-zero") | .size_bytes
    ' "$plan")"

    verify_source() {
      local role="$1"
      local path="$2"
      local expected_size expected_digest
      expected_size="$(jq -er --arg role "$role" '
        .layout.sources[] | select(.role == $role) | .size_bytes
      ' "$plan")"
      expected_digest="$(jq -er --arg role "$role" '
        .layout.sources[] | select(.role == $role) | .digest
      ' "$plan")"
      test -f "$path"
      test ! -L "$path"
      test "$(stat --format=%s "$path")" -eq "$expected_size"
      test "sha256:$(sha256sum "$path" | cut -d ' ' -f 1)" = "$expected_digest"
    }
    verify_source primary-gpt "$primary_gpt"
    verify_source boot-filesystem "$boot_filesystem"
    verify_source root-data "$root_data"
    verify_source root-hash "$root_hash"
    verify_source backup-gpt "$backup_gpt"

    test "$root_data_size" -le "$root_data_partition_size"
    test "$root_hash_size" -le "$root_hash_partition_size"
    test $((
      primary_size
      + boot_size
      + root_data_partition_size
      + root_hash_partition_size
      + tail_size
      + backup_size
    )) -eq "$target_size"

    readonly verity_root_hash="$(jq -er '
      .layout.verity.root_hash | sub("^sha256:"; "")
    ' "$plan")"
    veritysetup verify "$root_data" "$root_hash" "$verity_root_hash"

    emit_image() {
      cat "$primary_gpt"
      cat "$boot_filesystem"
      cat "$root_data"
      head --bytes=$((root_data_partition_size - root_data_size)) /dev/zero
      cat "$root_hash"
      head --bytes=$((root_hash_partition_size - root_hash_size)) /dev/zero
      head --bytes="$tail_size" /dev/zero
      cat "$backup_gpt"
    }

    readonly actual_media_digest="sha256:$(emit_image | sha256sum | cut -d ' ' -f 1)"
    test "$actual_media_digest" = "$expected_media_digest"

    mkdir -p "$out"
    readonly archive="$out/${imageFileName}"
    emit_image | zstd --compress --threads=2 -10 --no-progress -o "$archive"
    zstd --test "$archive"
    readonly decompressed_digest="sha256:$(
      zstd --decompress --stdout "$archive" | sha256sum | cut -d ' ' -f 1
    )"
    readonly decompressed_size="$(zstd --decompress --stdout "$archive" | wc --bytes)"
    printf 'verified archive digest: %s\n' "$decompressed_digest"
    printf 'verified archive size: %s bytes\n' "$decompressed_size"
    test "$decompressed_digest" = "$expected_media_digest"
    test "$decompressed_size" -eq "$target_size"

    chmod 0444 "$archive"
    test -f "$archive"
    test ! -L "$archive"
    readonly output_entries="$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n')"
    printf 'verified output entry: %s\n' "$output_entries"
    test "$output_entries" = ${pkgs.lib.escapeShellArg imageFileName}
    echo 'signed target image archive verification complete'
  ''
