{
  expectedBootImageDigest,
  image,
  lib,
  payloadSourceRevision,
  pkgs,
}:

let
  contract = image.kaibaRpi5SignedTargetImage;
  imageContract =
    lib.isDerivation image
    && contract.imageFileName == "kaiba-rpi5-development-secure-boot-target.img.zst"
    && contract.imageSizeBytes == 3 * 1024 * 1024 * 1024
    && contract.minimumTargetCapacityBytes == contract.imageSizeBytes
    && contract.logicalSectorSizeBytes == 512
    && contract.wholeDeviceImage
    && contract.compressed
    && contract.payloadSourceRevision == payloadSourceRevision
    && contract.expectedBootImageDigest == expectedBootImageDigest
    &&
      contract.expectedArchiveDigest
      == "sha256:c82a0fad4aa859ba51cd31f35f041450b4b96d767060c9da31cdae98cd36bf8a"
    &&
      contract.expectedMediaDigest
      == "sha256:9ba3e880a81d35b2fef237840f3791a81bd79c095a3b6f19c44b3f142a22d4b5"
    && contract.expectedArchiveSizeBytes == 1166253581
    &&
      contract.sourceURL
      == "https://github.com/ams-tech/nixos-kaiba-network/releases/download/v0.1.14/kaiba-rpi5-development-secure-boot-target-v0.1.14.img.zst";
  authorityContract =
    !contract.directHardwareAccess
    && !contract.mutationCapable
    && !contract.privateKeyAccess
    && !contract.signingAuthorityConfigured
    && !contract.signingCapable;
  sourceContractValid =
    lib.isDerivation contract.sourceArchive
    && contract.inputVerificationMode == "fixed_published_archive";
in
assert lib.assertMsg imageContract "the v0.1.6 signed target image identity or geometry changed";
assert lib.assertMsg authorityContract
  "the v0.1.6 signed target image unexpectedly carries authority";
assert lib.assertMsg sourceContractValid
  "the v0.1.6 signed target image lost its pinned target-only input lineage";
pkgs.runCommand "kaiba-rpi5-v016-signed-target-image-eval" { } ''
  mkdir -p "$out"
  touch "$out/passed"
''
