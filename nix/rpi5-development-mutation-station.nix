{
  acceptedTargetFingerprint,
  auditAddress,
  auditPort ? 8092,
  controlAddress,
  controlPort ? 8091,
  hardwareQualificationDigest,
  laneID,
  lib,
  manualLaneQualificationDigest,
  manualLaneQualificationSourceRevision,
  nixos-raspberrypi,
  operatorName ? "provisioner",
  payloadSourceRevision,
  physicalLaneGuard,
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
  nixosSystem = nixos-raspberrypi.lib.nixosSystem {
    trustCaches = false;
    modules = [
      nixos-raspberrypi.nixosModules.sd-image
      nixos-raspberrypi.nixosModules.raspberry-pi-5.base
      nixos-raspberrypi.nixosModules.raspberry-pi-5.page-size-16k
      provisioning.nixosModules.provisioning-lane-guard
      (import ./images/rpi5-development-mutation-station.nix {
        inherit
          auditAddress
          auditPort
          acceptedTargetFingerprint
          controlAddress
          controlPort
          hardwareQualificationDigest
          laneID
          manualLaneQualificationDigest
          manualLaneQualificationSourceRevision
          operatorName
          payloadSourceRevision
          physicalLaneGuard
          rpibootSysfsPath
          sourceRevision
          stationID
          uartPath
          unfusedCompatibilityUARTDigest
          ;
        authorityBridgePackage = provisioning.packages.aarch64-linux.kaiba-provision-authority-bridge;
        laneOperatorPackage = provisioning.packages.aarch64-linux.kaiba-provision-lane-operator;
        laneWorkflowPackage = provisioning.packages.aarch64-linux.kaiba-provision-lane-workflow;
      })
    ];
  };
in
assert lib.assertMsg sourceRevisionIsCanonical
  "the development mutation station requires a canonical station source revision";
assert lib.assertMsg payloadSourceRevisionIsCanonical
  "the development mutation station requires a canonical payload source revision";
assert lib.assertMsg (
  physicalLaneGuard.system == "aarch64-linux"
) "the development mutation station requires a native aarch64-linux physical lane guard";
assert lib.assertMsg
  (
    builtins.isAttrs recoveryContract
    && (recoveryContract.payloadSourceRevision or null) == payloadSourceRevision
    && (recoveryContract.recoveryToolSourceRevision or null) == sourceRevision
    && (recoveryContract.privateKeyAccess or null) == false
    && (recoveryContract.signingAuthorityConfigured or null) == false
    && (recoveryContract.hardwareAccess or null) == false
    && (recoveryContract.mutationCapable or null) == false
  )
  "the development mutation station requires the exact public, no-authority recovered payload lineage";
assert lib.assertMsg
  (
    (releaseIntentContract.sourceRevision or null) == payloadSourceRevision
    && (unsignedContract.sourceRevision or null) == payloadSourceRevision
  )
  "the recovered release intent and unsigned artifacts are not bound to the expected payload source revision";
assert lib.assertMsg (
  toString physicalLaneGuard.kaibaPhysicalLaneGuard.verifiedSignedRelease
  == toString verifiedSignedRelease
) "the physical lane guard is not bound to the selected recovered signed release";
{
  inherit nixosSystem physicalLaneGuard;
  sdImage = nixosSystem.config.system.build.sdImage;
  system = nixosSystem.config.system.build.toplevel;

  metadata = {
    inherit
      auditAddress
      auditPort
      acceptedTargetFingerprint
      controlAddress
      controlPort
      hardwareQualificationDigest
      laneID
      manualLaneQualificationDigest
      manualLaneQualificationSourceRevision
      operatorName
      payloadSourceRevision
      rpibootSysfsPath
      sourceRevision
      stationID
      uartPath
      unfusedCompatibilityUARTDigest
      ;
    enableMutations = true;
    guardAutoStart = false;
    powerControl = "manual";
  };
}
