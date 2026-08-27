{
  lib,
  mkRpi5PrototypeOwnedRecoveryPlan,
  mkRpi5PrototypeSignedRelease,
  pkgs,
  prototype,
}:

let
  emptySignedOutput = pkgs.runCommand "kaiba-empty-live-signed-output-evaluation" { } ''
    mkdir "$out"
  '';
  emptySigningGrantRegistry = pkgs.writeText "kaiba-empty-signing-grant-registry-evaluation.json" "{}\n";
  emptySigningReceiptExport = pkgs.writeText "kaiba-empty-signing-receipt-export-evaluation.json" "{}\n";
  assembled = mkRpi5PrototypeSignedRelease {
    bootSignedOutput = emptySignedOutput;
    eepromSignedOutput = emptySignedOutput;
    ownedRecoverySignedOutput = emptySignedOutput;
    signingGrantRegistry = emptySigningGrantRegistry;
    signingReceiptExport = emptySigningReceiptExport;
    name = "kaiba-rpi5-prototype-live-release-evaluation";
  };
  recoveryPreparation = mkRpi5PrototypeOwnedRecoveryPlan {
    eepromSignedOutput = emptySignedOutput;
  };
  releaseContract = assembled.release.kaibaVerifiedSignedRelease;
  bundleContract = assembled.verifiedRPIBootBundles.kaibaVerifiedRPIBootBundles;
  recoveryContract = assembled.verifiedOwnedRecovery.kaibaVerifiedOwnedRecovery;
in
assert lib.assertMsg (lib.all lib.isDerivation [
  assembled.ownedRecoverySigningPlan
  assembled.platformAdapter
  assembled.release
  assembled.rootIntegrity
  assembled.verifiedOwnedRecovery
  assembled.verifiedRPIBootBundles
  assembled.verifiedSignedBoot
  assembled.verifiedSignedEEPROM
  assembled.verifiedSigningReceipts
]) "the prototype live-output factory did not expose the complete derivation graph";
assert lib.assertMsg (
  recoveryPreparation.verifiedSignedEEPROM == assembled.verifiedSignedEEPROM
  && recoveryPreparation.ownedRecoverySigningPlan == assembled.ownedRecoverySigningPlan
  && recoveryPreparation.metadata.liveSigningInputCountCompleted == 4
  && recoveryPreparation.metadata.liveSigningInputCountRemaining == 1
  && recoveryPreparation.metadata.minimumArtifactSignatureOperationCountCompleted == 4
  && recoveryPreparation.metadata.minimumArtifactSignatureOperationCountRemaining == 1
  && recoveryPreparation.metadata.minimumReceiptAttestationOperationCountCompleted == 4
  && recoveryPreparation.metadata.minimumReceiptAttestationOperationCountRemaining == 1
  && recoveryPreparation.metadata.minimumPrivateKeyOperationCountCompleted == 8
  && recoveryPreparation.metadata.minimumPrivateKeyOperationCountRemaining == 2
  && recoveryPreparation.metadata.minimumLiveTokenTouchCountCompleted == 8
  && recoveryPreparation.metadata.minimumLiveTokenTouchCountRemaining == 2
  && recoveryPreparation.metadata.operationCountSemantics == "minimum_successful_path"
  && recoveryPreparation.metadata.privateKeyOperationUpperBoundDeclared == false
) "the two-phase owned-recovery preparation does not rejoin the final release graph";
assert lib.assertMsg (
  assembled.metadata.liveSigningInputCount == 5
  && assembled.metadata.minimumArtifactSignatureOperationCount == 5
  && assembled.metadata.minimumReceiptAttestationOperationCount == 5
  && assembled.metadata.minimumPrivateKeyOperationCount == 10
  && assembled.metadata.minimumLiveTokenTouchCount == 10
  && assembled.metadata.operationCountSemantics == "minimum_successful_path"
  && assembled.metadata.privateKeyOperationUpperBoundDeclared == false
  && assembled.metadata.artifactRoleCount == 18
  && assembled.metadata.authenticatedSigningReceiptCount == 5
  && releaseContract.authenticatedSigningReceiptCount == 5
  && assembled.metadata.ownedRecoveryPlanID == "${prototype.metadata.eepromPlanID}:owned-recovery"
) "the prototype live-output factory changed the canonical release cardinalities";
assert lib.assertMsg (
  releaseContract.verifiedSignedBoot == assembled.verifiedSignedBoot
  && releaseContract.verifiedSignedEEPROM == assembled.verifiedSignedEEPROM
  && releaseContract.verifiedOwnedRecovery == assembled.verifiedOwnedRecovery
  && releaseContract.verifiedRPIBootBundles == assembled.verifiedRPIBootBundles
  && bundleContract.verifiedOwnedRecovery == assembled.verifiedOwnedRecovery
  && recoveryContract.signingPlan == assembled.ownedRecoverySigningPlan
  && releaseContract.signingReceiptVerification == assembled.verifiedSigningReceipts
) "the prototype live-output factory mixed signed component provenance";
assert lib.assertMsg (lib.all (value: value == false) [
  assembled.metadata.privateKeyAccess
  assembled.metadata.hardwareAccess
  assembled.metadata.mutationCapable
  releaseContract.privateKeyAccess
  releaseContract.directHardwareAccess
  releaseContract.mutationCapable
  releaseContract.oneTimeSettingCapable
]) "the prototype live-output finalizer gained signing or hardware authority";
pkgs.runCommand "kaiba-rpi5-prototype-signed-release-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'five-live-signing-inputs: pass' \
    'minimum-ten-live-private-key-operations: pass' \
    'minimum-ten-live-token-touches: pass' \
    'five-authenticated-signing-receipts: pass' \
    'two-phase-owned-recovery-plan: pass' \
    'eighteen-release-roles: pass' \
    'single-release-lineage: pass' \
    'offline-finalization-only: pass' \
    > "$out/results.txt"
''
