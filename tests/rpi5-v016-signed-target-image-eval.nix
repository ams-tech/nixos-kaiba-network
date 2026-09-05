{
  expectedBootImageDigest,
  image,
  lib,
  payloadSourceRevision,
  pkgs,
}:

let
  contract = image.kaibaRpi5SignedTargetImage;
  unsignedContract = contract.unsignedArtifacts.kaibaUnsignedArtifacts;
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
      == "sha256:9ba3e880a81d35b2fef237840f3791a81bd79c095a3b6f19c44b3f142a22d4b5";
  authorityContract =
    !contract.directHardwareAccess
    && !contract.mutationCapable
    && !contract.privateKeyAccess
    && !contract.signingAuthorityConfigured
    && !contract.signingCapable
    && !unsignedContract.blockDeviceWriteCapable
    && !unsignedContract.directHardwareAccess
    && !unsignedContract.signingAuthorityConfigured;
  sourceContractValid =
    lib.isDerivation contract.unsignedArtifacts
    && unsignedContract.schemaVersion == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
    && unsignedContract.sourceRevision == payloadSourceRevision
    && unsignedContract.signingStatus == "unsigned"
    && contract.inputVerificationMode == "pinned_unsigned_artifacts_plus_checked_signed_boot";
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
