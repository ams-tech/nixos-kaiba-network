{
  expectedBootImageDigest,
  image,
  lib,
  payloadSourceRevision,
  pkgs,
}:

let
  contract = image.kaibaRpi5SignedTargetImage;
  mediaContract = contract.productionMedia.kaibaRpi5ProductionMedia;
  imageContract =
    lib.isDerivation image
    && contract.imageFileName == "kaiba-rpi5-development-secure-boot-target.img.zst"
    && contract.imageSizeBytes == 3 * 1024 * 1024 * 1024
    && contract.minimumTargetCapacityBytes == contract.imageSizeBytes
    && contract.logicalSectorSizeBytes == 512
    && contract.wholeDeviceImage
    && contract.compressed
    && contract.payloadSourceRevision == payloadSourceRevision
    && contract.expectedBootImageDigest == expectedBootImageDigest;
  authorityContract =
    !contract.directHardwareAccess
    && !contract.mutationCapable
    && !contract.privateKeyAccess
    && !contract.signingAuthorityConfigured
    && !contract.signingCapable
    && !mediaContract.blockDeviceWriteCapable
    && !mediaContract.directHardwareAccess
    && !mediaContract.signingAuthorityConfigured;
  mediaContractValid =
    mediaContract.transactionID == "release:rpi5-v0.1.6-signed-target:1"
    && mediaContract.targetGeometry.sizeBytes == contract.imageSizeBytes
    && mediaContract.targetGeometry.logicalSectorSizeBytes == contract.logicalSectorSizeBytes
    && mediaContract.verificationMode == "pure_offline_plan_derivation"
    && lib.isDerivation mediaContract.fixtureStager
    && lib.isDerivation mediaContract.regularVerifier
    && lib.isDerivation mediaContract.softwareCheck;
in
assert lib.assertMsg imageContract "the v0.1.6 signed target image identity or geometry changed";
assert lib.assertMsg authorityContract
  "the v0.1.6 signed target image unexpectedly carries authority";
assert lib.assertMsg mediaContractValid
  "the v0.1.6 signed target image lost its verified production-media lineage";
pkgs.runCommand "kaiba-rpi5-v016-signed-target-image-eval" { } ''
  mkdir -p "$out"
  touch "$out/passed"
''
