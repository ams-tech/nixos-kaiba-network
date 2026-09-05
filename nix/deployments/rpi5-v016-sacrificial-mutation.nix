{
  bootSignedOutput,
  eepromSignedOutput,
  fixed,
  fixedSourceRevision,
  manualLaneQualificationDigest,
  ownedRecoverySignedOutput,
  payload,
  publicSignedInputSource,
  rpibootSysfsPath,
  signingGrantRegistry,
  signingReceiptExport,
}:

let
  payloadSourceRevision = "8e9f1d5cd97ff46d8b56b1128251ca70b7fec598";
  recoveredSignedRelease = fixed.lib.mkRpi5PrototypeSignedReleaseRecovery {
    inherit
      bootSignedOutput
      eepromSignedOutput
      ownedRecoverySignedOutput
      payload
      payloadSourceRevision
      signingGrantRegistry
      signingReceiptExport
      ;
    name = "kaiba-rpi5-v0.1.6-recovery-signed-release";
  };
  releaseContract = recoveredSignedRelease.kaibaVerifiedSignedRelease;
  releaseIntentContract = releaseContract.releaseIntent.kaibaRpi5ReleaseIntent;
  unsignedContract = releaseContract.unsignedArtifacts.kaibaUnsignedArtifacts;
  operationalPayload = fixed.lib.mkRpi5DevelopmentSecureBootOperationalPayload {
    system = "aarch64-linux";
    inherit payloadSourceRevision publicSignedInputSource;
    name = "kaiba-rpi5-v016-development-secure-boot-operational-payload";
  };
  mutationStation = fixed.lib.mkRpi5DevelopmentDirectMutationStation {
    acceptedTargetFingerprint = "sha256:e7e61cab9b971a61207fcb17b15971c208d2374d14d62c9506e3b1717fb576dd";
    hardwareQualificationDigest = "sha256:a1ba7a356616a7e18a0e2abad17fc0152255ab29e0af8a81f6bc0e41566d637d";
    stationID = "kaiba-rpi5-provisioner";
    laneID = "lane-1";
    inherit manualLaneQualificationDigest operationalPayload rpibootSysfsPath;
    manualLaneQualificationSourceRevision = payloadSourceRevision;
    inherit payloadSourceRevision;
    uartPath = "/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E663B035973F3F26-if01";
    unfusedCompatibilityUARTDigest = "sha256:b22b0967e90ed6f86b56a510f939bf49eb570e18caa90bed313977808889a598";
    sourceRevision = fixedSourceRevision;
    verifiedSignedRelease = recoveredSignedRelease;
  };
in
assert builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" fixedSourceRevision != null;
assert fixed.sourceInfo.rev == fixedSourceRevision;
assert payload.sourceInfo.rev == payloadSourceRevision;
assert
  recoveredSignedRelease.kaibaPrototypeSignedReleaseRecovery.payloadSourceRevision
  == payloadSourceRevision;
assert releaseIntentContract.sourceRevision == payloadSourceRevision;
assert unsignedContract.sourceRevision == payloadSourceRevision;
assert
  releaseIntentContract.expectedCustomerKeyHash
  == "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
assert
  unsignedContract.expectedCustomerKeyHash
  == "b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
assert
  releaseIntentContract.publicKeyFingerprint
  == "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9";
{
  inherit mutationStation recoveredSignedRelease;
  image = mutationStation.sdImage;
  secureBootRunner = mutationStation.secureBootRunner;
  system = mutationStation.system;
}
