{
  lib,
  prototype,
  provisioning,
  signingProfile,
}:

{
  eepromSignedOutput,
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
  verifiedSignedEEPROM = provisioning.lib.mkRpi5VerifiedSignedEEPROM {
    inherit system;
    name = "kaiba-rpi5-prototype-live-verified-eeprom";
    signedOutput = eepromSignedOutput;
    signingPlan = prototype.eepromSigningPlan;
  };
  ownedRecoverySigningPlan = provisioning.lib.mkRpi5OwnedRecoverySigningPlan {
    inherit system verifiedSignedEEPROM;
    name = "kaiba-rpi5-prototype-live-owned-recovery-plan";
    freshSigningPlan = prototype.eepromSigningPlan;
    planID = "${prototype.metadata.eepromPlanID}:owned-recovery";
  };
in
assert lib.assertMsg (storeBacked eepromSignedOutput)
  "the EEPROM signed-output directory must be imported into the Nix store";
assert lib.assertMsg signingProfile.metadata.independentReviewComplete
  "the prototype signer must have a completed independent review";
{
  inherit ownedRecoverySigningPlan verifiedSignedEEPROM;
  metadata = prototype.metadata // {
    liveSigningInputCountCompleted = 4;
    liveSigningInputCountRemaining = 1;
    minimumArtifactSignatureOperationCountCompleted = 4;
    minimumArtifactSignatureOperationCountRemaining = 1;
    minimumReceiptAttestationOperationCountCompleted = 4;
    minimumReceiptAttestationOperationCountRemaining = 1;
    minimumPrivateKeyOperationCountCompleted = 8;
    minimumPrivateKeyOperationCountRemaining = 2;
    minimumLiveTokenTouchCountCompleted = 8;
    minimumLiveTokenTouchCountRemaining = 2;
    operationCountSemantics = "minimum_successful_path";
    privateKeyOperationUpperBoundDeclared = false;
    ownedRecoveryPlanID = "${prototype.metadata.eepromPlanID}:owned-recovery";
    privateKeyAccess = false;
    hardwareAccess = false;
    mutationCapable = false;
  };
}
