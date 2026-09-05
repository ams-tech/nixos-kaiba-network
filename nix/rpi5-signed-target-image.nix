{
  expectedArchiveDigest,
  expectedArchiveSizeBytes,
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
  sourceArchive,
  sourceURL,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
in
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
assert builtins.isInt expectedArchiveSizeBytes && expectedArchiveSizeBytes > 0;
assert builtins.isString sourceURL && builtins.match "https://[^ ]+" sourceURL != null;
assert builtins.match "[a-z0-9.-]+\\.img\\.zst" imageFileName != null;
pkgs.runCommand name
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.zstd
    ];
    preferLocalBuild = true;
    passthru.kaibaRpi5SignedTargetImage = {
      inherit
        expectedArchiveDigest
        expectedArchiveSizeBytes
        expectedBootImageDigest
        expectedBootSignatureDigest
        expectedMediaDigest
        expectedRootDataDigest
        expectedRootHashDigest
        expectedRootIntegrityDigest
        imageFileName
        payloadSourceRevision
        sourceArchive
        sourceURL
        ;
      compressed = true;
      directHardwareAccess = false;
      imageSizeBytes = 3 * 1024 * 1024 * 1024;
      inputVerificationMode = "fixed_published_archive";
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

    readonly source=${sourceArchive}
    readonly expected_archive=${pkgs.lib.escapeShellArg expectedArchiveDigest}
    readonly expected_media=${pkgs.lib.escapeShellArg expectedMediaDigest}
    readonly expected_archive_size=${toString expectedArchiveSizeBytes}
    readonly expected_media_size=${toString (3 * 1024 * 1024 * 1024)}

    test -f "$source"
    test ! -L "$source"
    test "$(stat --format=%s "$source")" -eq "$expected_archive_size"
    test "sha256:$(sha256sum "$source" | cut -d ' ' -f 1)" = "$expected_archive"
    zstd --test "$source"

    readonly decompressed_digest="sha256:$(${pkgs.zstd}/bin/zstd --decompress --stdout "$source" \
      | sha256sum | cut -d ' ' -f 1)"
    readonly decompressed_size="$(${pkgs.zstd}/bin/zstd --decompress --stdout "$source" | wc --bytes)"
    test "$decompressed_digest" = "$expected_media"
    test "$decompressed_size" -eq "$expected_media_size"

    mkdir -p "$out"
    install --mode=0444 "$source" "$out/${imageFileName}"
    test "$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n')" = \
      ${pkgs.lib.escapeShellArg imageFileName}
    echo 'fixed signed target image archive verification complete'
  ''
