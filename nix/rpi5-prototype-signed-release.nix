{
  lib,
  pkgs,
  prototype,
  provisioning,
  signingProfile,
}:

{
  bootSignedOutput,
  eepromSignedOutput,
  ownedRecoverySignedOutput,
  signingGrantRegistry,
  signingReceiptExport,
  name ? "kaiba-rpi5-prototype-signed-release",
}:

let
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

  system = "x86_64-linux";
  platformAdapterSource = ../provisioning/config/rpi5-prototype-release/platform-adapter-v1alpha1.json;
  platformAdapterSchema = ../provisioning/schemas/rpi5-platform-adapter-v1alpha1.schema.json;
  deviceProfile = ../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json;

  platformAdapter =
    pkgs.runCommand "${name}-platform-adapter.json" { nativeBuildInputs = [ pkgs.check-jsonschema ]; }
      ''
        set -euo pipefail
        check-jsonschema --check-metaschema ${platformAdapterSchema}
        check-jsonschema --schemafile ${platformAdapterSchema} ${platformAdapterSource}
        install -m 0444 ${platformAdapterSource} "$out"
      '';

  rootIntegrity = (import ./rpi5-root-integrity-record.nix { inherit pkgs; }) {
    bootImage = "${prototype.unsignedArtifacts}/unsigned/boot.img";
    name = "${name}-root-integrity.json";
  };

  verifiedSignedBoot = provisioning.lib.mkRpi5VerifiedSignedBoot {
    inherit system;
    name = "${name}-verified-boot";
    signedOutput = bootSignedOutput;
    signingPlan = prototype.signingPlan;
  };
  verifiedSignedEEPROM = provisioning.lib.mkRpi5VerifiedSignedEEPROM {
    inherit system;
    name = "kaiba-rpi5-prototype-live-verified-eeprom";
    signedOutput = eepromSignedOutput;
    signingPlan = prototype.eepromSigningPlan;
  };
  ownedRecoverySigningPlan = provisioning.lib.mkRpi5OwnedRecoverySigningPlan {
    inherit system;
    name = "kaiba-rpi5-prototype-live-owned-recovery-plan";
    freshSigningPlan = prototype.eepromSigningPlan;
    planID = "${prototype.metadata.eepromPlanID}:owned-recovery";
    inherit verifiedSignedEEPROM;
  };
  verifiedOwnedRecovery = provisioning.lib.mkRpi5VerifiedOwnedRecovery {
    inherit system;
    name = "${name}-verified-owned-recovery";
    signedOutput = ownedRecoverySignedOutput;
    signingPlan = ownedRecoverySigningPlan;
  };
  verifiedSigningReceipts = provisioning.lib.mkRpi5VerifiedSigningReceipts {
    inherit
      signingGrantRegistry
      signingReceiptExport
      system
      verifiedOwnedRecovery
      verifiedSignedBoot
      verifiedSignedEEPROM
      ;
    name = "${name}-verified-signing-receipts.json";
    reviewedPublicKeyPEM = signingProfile.reviewedPublicKeyPEM;
  };
  verifiedRPIBootBundles = provisioning.lib.mkRpi5VerifiedRPIBootBundles {
    inherit
      system
      verifiedOwnedRecovery
      verifiedSignedBoot
      verifiedSignedEEPROM
      ;
    name = "${name}-verified-rpiboot-bundles";
    unsignedArtifacts = prototype.unsignedArtifacts;
  };
  release = provisioning.lib.mkRpi5VerifiedSignedRelease {
    inherit
      deviceProfile
      platformAdapter
      rootIntegrity
      system
      verifiedOwnedRecovery
      verifiedRPIBootBundles
      verifiedSignedBoot
      verifiedSignedEEPROM
      ;
    name = name;
    eepromRelease = prototype.eepromRelease;
    signingReceiptVerification = verifiedSigningReceipts;
    unsignedArtifacts = prototype.unsignedArtifacts;
  };
in
assert lib.assertMsg (lib.all storeBacked [
  bootSignedOutput
  eepromSignedOutput
  ownedRecoverySignedOutput
  signingGrantRegistry
  signingReceiptExport
]) "every prototype signing input must be imported into the Nix store";
assert lib.assertMsg signingProfile.metadata.independentReviewComplete
  "the prototype signer must have a completed independent review";
assert lib.assertMsg (
  !signingProfile.metadata.productionApproved
) "the sacrificial development signer must not claim production approval";
{
  inherit
    deviceProfile
    ownedRecoverySigningPlan
    platformAdapter
    release
    rootIntegrity
    signingGrantRegistry
    signingReceiptExport
    verifiedOwnedRecovery
    verifiedRPIBootBundles
    verifiedSignedBoot
    verifiedSignedEEPROM
    verifiedSigningReceipts
    ;

  metadata = prototype.metadata // {
    artifactRoleCount = 18;
    liveSigningInputCount = 5;
    minimumArtifactSignatureOperationCount = 5;
    minimumReceiptAttestationOperationCount = 5;
    minimumPrivateKeyOperationCount = 10;
    minimumLiveTokenTouchCount = 10;
    operationCountSemantics = "minimum_successful_path";
    privateKeyOperationUpperBoundDeclared = false;
    authenticatedSigningReceiptCount = 5;
    ownedRecoveryPlanID = "${prototype.metadata.eepromPlanID}:owned-recovery";
    privateKeyAccess = false;
    hardwareAccess = false;
    mutationCapable = false;
  };
}
