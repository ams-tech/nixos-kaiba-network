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
  fixtureStager = contract.fixtureStager or null;
  regularVerifier = contract.regularVerifier or null;
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
assert fixtureStager != null;
assert regularVerifier != null;
assert canonicalDigest expectedBootImageDigest;
assert canonicalRevision payloadSourceRevision;
assert builtins.match "[a-z0-9.-]+\\.img\\.zst" imageFileName != null;
pkgs.runCommand name
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.jq
      pkgs.zstd
      fixtureStager
      regularVerifier
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
    readonly target="$TMPDIR/kaiba-rpi5-development-secure-boot-target.img"
    readonly fixture_result="$TMPDIR/fixture-result.json"
    readonly verification_report="$TMPDIR/verification-report.json"
    readonly target_size=${toString targetGeometry.sizeBytes}

    test -f "$plan"
    test ! -L "$plan"
    test "$(jq -er .target.size_bytes "$plan")" -eq "$target_size"
    test "$(jq -er .target.logical_sector_size_bytes "$plan")" -eq 512
    test "$(jq -er '
      .layout.fat.allowlist[]
      | select(.path == "boot.img")
      | .digest
    ' "$plan")" = ${pkgs.lib.escapeShellArg expectedBootImageDigest}

    truncate --size="$target_size" "$target"
    kaiba-provision-media-fixture-stager stage \
      --plan "$plan" \
      --target "$target" \
      --result "$fixture_result"

    jq -e \
      --arg expected "$(cat ${productionMedia}/expected-media-digest)" '
        .status == "fixture_staged_and_reopened"
        and .evidence_mode == "regular_file_fixture"
        and .full_media_digest == $expected
        and .reopened_target == true
        and .block_device_access == false
        and .hardware_observed == false
        and .security_enforced == false
        and .mutation_eligible == false
      ' "$fixture_result" > /dev/null

    kaiba-provision-media-verifier verify-regular-file \
      --plan "$plan" \
      --target "$target" > "$verification_report"
    jq -e '
      .gpt_verified == true
      and .fat_verified == true
      and .partition_digests_verified == true
      and .dm_verity_verified == true
      and .boot_signature_verified == true
      and .release_lineage_verified == true
      and .hardware_observed == false
      and .security_enforced == false
      and .mutation_eligible == false
    ' "$verification_report" > /dev/null

    readonly actual_media_digest="sha256:$(sha256sum "$target" | cut -d ' ' -f 1)"
    readonly expected_media_digest="$(cat ${productionMedia}/expected-media-digest)"
    test "$actual_media_digest" = "$expected_media_digest"

    mkdir -p "$out"
    readonly archive="$out/${imageFileName}"
    zstd --compress --threads=2 -10 --no-progress "$target" --output "$archive"
    zstd --test "$archive"
    test "sha256:$(zstd --decompress --stdout "$archive" | sha256sum | cut -d ' ' -f 1)" = \
      "$expected_media_digest"

    chmod 0444 "$archive"
    test -f "$archive"
    test ! -L "$archive"
    test "$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\\n')" = \
      ${pkgs.lib.escapeShellArg imageFileName}
  ''
