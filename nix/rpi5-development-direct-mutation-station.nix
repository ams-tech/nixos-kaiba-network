{
  acceptedTargetFingerprint,
  hardwareQualificationDigest,
  laneID,
  lib,
  manualLaneQualificationDigest,
  manualLaneQualificationSourceRevision,
  nixos-raspberrypi,
  operatorName ? "provisioner",
  payloadSourceRevision,
  provisioning,
  rpibootSysfsPath,
  sourceRevision,
  stationID,
  uartPath,
  unfusedCompatibilityUARTDigest,
  verifiedSignedRelease,
}:

let
  sourceRevisionIsCanonical =
    builtins.isString sourceRevision
    && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;
  payloadSourceRevisionIsCanonical =
    builtins.isString payloadSourceRevision
    && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" payloadSourceRevision != null;
  recoveryContract = verifiedSignedRelease.kaibaPrototypeSignedReleaseRecovery or { };
  releaseContract = verifiedSignedRelease.kaibaVerifiedSignedRelease or { };
  releaseIntentContract = (releaseContract.releaseIntent or { }).kaibaRpi5ReleaseIntent or { };
  unsignedContract = (releaseContract.unsignedArtifacts or { }).kaibaUnsignedArtifacts or { };
  operationalPayload = provisioning.lib.mkRpi5DevelopmentSecureBootOperationalPayload {
    system = "aarch64-linux";
    inherit payloadSourceRevision verifiedSignedRelease;
    name = "kaiba-rpi5-v016-development-secure-boot-operational-payload";
  };
  secureBootRunner = provisioning.lib.mkRpi5DevelopmentSecureBootRunner {
    system = "aarch64-linux";
    inherit
      hardwareQualificationDigest
      laneID
      manualLaneQualificationDigest
      operationalPayload
      payloadSourceRevision
      stationID
      ;
    expectedTargetFingerprint = acceptedTargetFingerprint;
    fixedRPIBootSysfsPath = rpibootSysfsPath;
    fixedUARTPath = uartPath;
    stationSourceRevision = sourceRevision;
    inherit unfusedCompatibilityUARTDigest;
    name = "kaiba-rpi5-v016-development-secure-boot";
  };
  nixosSystem = nixos-raspberrypi.lib.nixosSystem {
    trustCaches = false;
    modules = [
      nixos-raspberrypi.nixosModules.sd-image
      nixos-raspberrypi.nixosModules.raspberry-pi-5.base
      nixos-raspberrypi.nixosModules.raspberry-pi-5.page-size-16k
      (import ./images/rpi5-development-direct-mutation-station.nix {
        inherit
          acceptedTargetFingerprint
          hardwareQualificationDigest
          laneID
          manualLaneQualificationDigest
          manualLaneQualificationSourceRevision
          operatorName
          payloadSourceRevision
          rpibootSysfsPath
          secureBootRunner
          sourceRevision
          stationID
          uartPath
          unfusedCompatibilityUARTDigest
          ;
      })
    ];
  };
in
assert lib.assertMsg sourceRevisionIsCanonical
  "the direct development mutation station requires a canonical station source revision";
assert lib.assertMsg payloadSourceRevisionIsCanonical
  "the direct development mutation station requires a canonical payload source revision";
assert lib.assertMsg
  (
    builtins.isAttrs recoveryContract
    && (recoveryContract.payloadSourceRevision or null) == payloadSourceRevision
    && (recoveryContract.privateKeyAccess or null) == false
    && (recoveryContract.signingAuthorityConfigured or null) == false
    && (recoveryContract.hardwareAccess or null) == false
    && (recoveryContract.mutationCapable or null) == false
  )
  "the direct development mutation station requires the exact public, no-authority recovered payload";
assert lib.assertMsg (
  (releaseIntentContract.sourceRevision or null) == payloadSourceRevision
  && (unsignedContract.sourceRevision or null) == payloadSourceRevision
) "the recovered release is not bound to the expected payload revision";
{
  inherit nixosSystem operationalPayload secureBootRunner;
  sdImage = nixosSystem.config.system.build.sdImage;
  system = nixosSystem.config.system.build.toplevel;
  metadata = {
    inherit
      acceptedTargetFingerprint
      hardwareQualificationDigest
      laneID
      manualLaneQualificationDigest
      manualLaneQualificationSourceRevision
      operationalPayload
      operatorName
      payloadSourceRevision
      rpibootSysfsPath
      sourceRevision
      stationID
      uartPath
      unfusedCompatibilityUARTDigest
      ;
    command = "kaiba-secure-boot provision";
    automaticAtBoot = true;
    enableMutations = true;
    powerControl = "manual";
    remoteAuthorityRequired = false;
    signingCapable = false;
  };
}
