{
  developmentSigning,
  lib,
  mkRpi5SecureBootTarget,
  pkgs,
  provisioning,
  sourceDateEpoch,
  sourceRevision,
  system,
}:

assert lib.assertMsg (
  builtins.isString sourceRevision
  && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null
) "the Raspberry Pi 5 prototype release requires a canonical clean source revision";
assert lib.assertMsg (
  builtins.isInt sourceDateEpoch && sourceDateEpoch >= 0 && sourceDateEpoch <= 253402300799
) "the Raspberry Pi 5 prototype release requires a canonical fixed source epoch";
let
  signingContract = developmentSigning.signing.kaibaSigning;
  planID = "release:rpi5-prototype:${builtins.substring 0 12 sourceRevision}";

  target = mkRpi5SecureBootTarget {
    inherit sourceRevision;
    expectedCustomerKeyHash = signingContract.expectedCustomerKeyHash;
  };

  unsignedArtifacts = target.unsignedArtifacts;
  signingPlan = provisioning.lib.mkRpi5BootSigningPlan {
    inherit system;
    name = "kaiba-rpi5-prototype-boot-signing-plan";
    bootImage = "${unsignedArtifacts}/unsigned/boot.img";
    inherit planID sourceDateEpoch;
    publicKeyFingerprint = signingContract.publicKeyFingerprint;
    reviewedPublicKeyPEM = developmentSigning.reviewedPublicKeyPEM;
    signerPolicyDigest = signingContract.signerPolicyDigest;
  };

  metadata = {
    inherit planID sourceDateEpoch sourceRevision;
    inherit (signingContract)
      expectedCustomerKeyHash
      publicKeyFingerprint
      signerPolicyDigest
      ;
  };

  review = import ./rpi5-prototype-release-review.nix {
    inherit
      developmentSigning
      lib
      metadata
      pkgs
      signingPlan
      unsignedArtifacts
      ;
  };
in
{
  inherit
    metadata
    review
    signingPlan
    target
    unsignedArtifacts
    ;
}
