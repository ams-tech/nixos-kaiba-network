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
  eepromPlanID = "${planID}:eeprom";

  target = mkRpi5SecureBootTarget {
    inherit sourceRevision;
    expectedCustomerKeyHash = signingContract.expectedCustomerKeyHash;
  };

  unsignedArtifacts = target.unsignedArtifacts;
  eepromRelease = provisioning.packages.${system}.rpi5-eeprom-release;
  eepromSigningInputs = provisioning.lib.mkRpi5EEPROMReleaseSigningInputs {
    inherit eepromRelease system;
    name = "kaiba-rpi5-prototype-eeprom-signing-inputs";
    bootConfig = ../provisioning/config/rpi5-prototype-eeprom/boot.conf;
  };
  releaseIntent = provisioning.lib.mkRpi5ReleaseIntent {
    inherit
      eepromRelease
      sourceDateEpoch
      sourceRevision
      system
      unsignedArtifacts
      ;
    name = "kaiba-rpi5-prototype-release-intent";
    releaseID = planID;
    bootImage = "${unsignedArtifacts}/unsigned/boot.img";
    eepromBootcodeSigningInput = "${eepromSigningInputs}/eeprom-bootcode.signing-input";
    eepromBootsysSigningInput = "${eepromSigningInputs}/eeprom-bootsys.signing-input";
    eepromConfigSigningInput = "${eepromSigningInputs}/eeprom-config.signing-input";
    ownedRecoveryBootcodeSigningInput = "${eepromSigningInputs}/owned-recovery-bootcode.signing-input";
    expectedCustomerKeyHash = "sha256:${signingContract.expectedCustomerKeyHash}";
    publicKeyFingerprint = signingContract.publicKeyFingerprint;
    signerPolicyDigest = signingContract.signerPolicyDigest;
  };
  signingPlan = provisioning.lib.mkRpi5BootSigningPlan {
    inherit system;
    name = "kaiba-rpi5-prototype-boot-signing-plan";
    bootImage = "${unsignedArtifacts}/unsigned/boot.img";
    inherit planID sourceDateEpoch;
    publicKeyFingerprint = signingContract.publicKeyFingerprint;
    inherit releaseIntent;
    reviewedPublicKeyPEM = developmentSigning.reviewedPublicKeyPEM;
    signerPolicyDigest = signingContract.signerPolicyDigest;
  };
  eepromSigningPlan = provisioning.lib.mkRpi5EEPROMSigningPlan {
    inherit
      eepromSigningInputs
      releaseIntent
      sourceDateEpoch
      system
      ;
    name = "kaiba-rpi5-prototype-eeprom-signing-plan";
    planID = eepromPlanID;
    bootConfig = ../provisioning/config/rpi5-prototype-eeprom/boot.conf;
    customerKeyHash = "sha256:${signingContract.expectedCustomerKeyHash}";
    publicKeyFingerprint = signingContract.publicKeyFingerprint;
    reviewedPublicKeyPEM = developmentSigning.reviewedPublicKeyPEM;
    signerPolicyDigest = signingContract.signerPolicyDigest;
  };

  metadata = {
    inherit
      eepromPlanID
      planID
      sourceDateEpoch
      sourceRevision
      ;
    inherit (signingContract)
      expectedCustomerKeyHash
      publicKeyFingerprint
      signerPolicyDigest
      ;
  };

  review = import ./rpi5-prototype-release-review.nix {
    inherit
      developmentSigning
      eepromSigningPlan
      lib
      metadata
      pkgs
      releaseIntent
      signingPlan
      unsignedArtifacts
      ;
  };
in
{
  inherit
    metadata
    eepromRelease
    eepromSigningInputs
    eepromSigningPlan
    releaseIntent
    review
    signingPlan
    target
    unsignedArtifacts
    ;
}
