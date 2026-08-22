{
  pkgs,
  lib,
  signedReleaseTool,
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

  canonicalBundlePaths = {
    freshCommit = "fresh-commit";
    freshReadback = "fresh-readback";
    negativeBoot = "negative-boot";
    ownedReadback = "owned-readback";
    ownedRecovery = "owned-recovery";
    rootIntegrityTest = "root-integrity-test";
  };

  # Assemble a complete release from already verified, public build products.
  # The executable re-verifies every signature/digest/lineage boundary, replays
  # EEPROM finalization with its linker-fixed helper, and publishes one exact,
  # content-addressed, no-replace directory. It cannot contact a signer or a
  # device and cannot mutate EEPROM, media, or OTP.
  mkRpi5VerifiedSignedRelease =
    {
      unsignedArtifacts,
      eepromRelease,
      verifiedSignedBoot,
      verifiedSignedEEPROM,
      verifiedOwnedRecovery,
      verifiedRPIBootBundles,
      deviceProfile,
      platformAdapter,
      rootIntegrity,
      name ? "kaiba-rpi5-verified-signed-release",
    }:
    assert lib.assertMsg (lib.all storeBacked [
      unsignedArtifacts
      eepromRelease
      verifiedSignedBoot
      verifiedSignedEEPROM
      verifiedOwnedRecovery
      verifiedRPIBootBundles
      deviceProfile
      platformAdapter
      rootIntegrity
    ]) "every signed-release input must be a fixed Nix-store path";
    assert lib.assertMsg (
      unsignedArtifacts ? kaibaUnsignedArtifacts
    ) "unsignedArtifacts must be produced by mkRpi5SecureBootArtifacts";
    assert lib.assertMsg (
      eepromRelease ? kaibaRpi5EEPROMRelease
    ) "eepromRelease must be produced by mkRpi5EEPROMRelease";
    assert lib.assertMsg (
      verifiedSignedBoot ? kaibaVerifiedSignedBoot
    ) "verifiedSignedBoot must be produced by mkRpi5VerifiedSignedBoot";
    assert lib.assertMsg (
      verifiedSignedEEPROM ? kaibaVerifiedSignedEEPROM
    ) "verifiedSignedEEPROM must be produced by mkRpi5VerifiedSignedEEPROM";
    assert lib.assertMsg (
      verifiedOwnedRecovery ? kaibaVerifiedOwnedRecovery
    ) "verifiedOwnedRecovery must be produced by mkRpi5VerifiedOwnedRecovery";
    assert lib.assertMsg (
      verifiedRPIBootBundles ? kaibaVerifiedRPIBootBundles
    ) "verifiedRPIBootBundles must be produced by mkRpi5VerifiedRPIBootBundles";
    let
      bootProvenance = verifiedSignedBoot.kaibaVerifiedSignedBoot;
      bootPlan = bootProvenance.signingPlan.kaibaBootSigningPlan;
      eepromProvenance = verifiedSignedEEPROM.kaibaVerifiedSignedEEPROM;
      eepromPlan = eepromProvenance.signingPlan.kaibaRpi5EEPROMSigningPlan;
      recoveryProvenance = verifiedOwnedRecovery.kaibaVerifiedOwnedRecovery;
      recoveryPlan = recoveryProvenance.signingPlan.kaibaRpi5OwnedRecoverySigningPlan;
      bundleProvenance = verifiedRPIBootBundles.kaibaVerifiedRPIBootBundles;
      releaseIntent = bootPlan.releaseIntent;
    in
    assert lib.assertMsg (
      toString eepromPlan.releaseIntent == toString releaseIntent
    ) "boot and EEPROM inputs must bind the exact same release intent";
    assert lib.assertMsg (
      toString recoveryPlan.freshSigningPlan == toString eepromProvenance.signingPlan
    ) "owned recovery must extend the selected EEPROM signing plan";
    assert lib.assertMsg (
      toString recoveryPlan.verifiedSignedEEPROM == toString verifiedSignedEEPROM
    ) "owned recovery must extend the selected verified signed EEPROM";
    assert lib.assertMsg (
      toString eepromPlan.eepromRelease == toString eepromRelease
    ) "the EEPROM signing plan must bind the selected EEPROM release";
    assert lib.assertMsg (
      bundleProvenance.bundlePaths == canonicalBundlePaths
    ) "the RPIBOOT bundle set must expose the six canonical sibling paths";
    assert lib.assertMsg (lib.all (pair: toString pair.left == toString pair.right) [
      {
        left = bundleProvenance.unsignedArtifacts;
        right = unsignedArtifacts;
      }
      {
        left = bundleProvenance.verifiedSignedBoot;
        right = verifiedSignedBoot;
      }
      {
        left = bundleProvenance.verifiedSignedEEPROM;
        right = verifiedSignedEEPROM;
      }
      {
        left = bundleProvenance.verifiedOwnedRecovery;
        right = verifiedOwnedRecovery;
      }
    ]) "the RPIBOOT bundle set must bind the selected verified component set";
    pkgs.runCommand name
      {
        nativeBuildInputs = [ pkgs.findutils ];
        passthru.kaibaVerifiedSignedRelease = {
          inherit
            deviceProfile
            eepromRelease
            platformAdapter
            releaseIntent
            rootIntegrity
            unsignedArtifacts
            verifiedOwnedRecovery
            verifiedRPIBootBundles
            verifiedSignedBoot
            verifiedSignedEEPROM
            ;
          artifactRoleCount = 18;
          blockDeviceWriteCapable = false;
          contentAddressedPublication = true;
          deterministicEEPROMReplayRequired = true;
          deterministicOwnedRecoveryReplayRequired = true;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          fixtureHardwareObserved = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          publicationSchemaVersion = "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1";
          signedReleaseManifestSchemaVersion = "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha2";
          signingAuthorityConfigured = false;
          verificationMode = "pure_offline_replay";
        };
        meta = {
          description = "Verified content-addressed Raspberry Pi 5 signed-release publication";
          platforms = [
            "x86_64-linux"
            "aarch64-linux"
          ];
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        ${signedReleaseTool}/bin/kaiba-provision-finalize-release finalize \
          --release-intent ${lib.escapeShellArg "${toString releaseIntent}/release-intent.json"} \
          --unsigned-artifacts-manifest ${lib.escapeShellArg "${toString unsignedArtifacts}/manifest.json"} \
          --eeprom-release-manifest ${lib.escapeShellArg "${toString eepromRelease}/release.json"} \
          --signed-boot ${lib.escapeShellArg (toString verifiedSignedBoot)} \
          --signed-eeprom ${lib.escapeShellArg (toString verifiedSignedEEPROM)} \
          --eeprom-replay-plan ${lib.escapeShellArg (toString eepromProvenance.signingPlan)} \
          --eeprom-replay-signed ${lib.escapeShellArg (toString eepromProvenance.signedOutput)} \
          --owned-recovery ${lib.escapeShellArg (toString verifiedOwnedRecovery)} \
          --owned-replay-plan ${lib.escapeShellArg (toString recoveryProvenance.signingPlan)} \
          --owned-replay-signed ${lib.escapeShellArg (toString recoveryProvenance.signedOutput)} \
          --device-profile ${lib.escapeShellArg (toString deviceProfile)} \
          --platform-adapter ${lib.escapeShellArg (toString platformAdapter)} \
          --root-integrity ${lib.escapeShellArg (toString rootIntegrity)} \
          --fresh-commit-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/fresh-commit"} \
          --fresh-readback-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/fresh-readback"} \
          --negative-boot-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/negative-boot"} \
          --owned-readback-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/owned-readback"} \
          --owned-recovery-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/owned-recovery"} \
          --root-integrity-test-bundle ${lib.escapeShellArg "${toString verifiedRPIBootBundles}/root-integrity-test"} \
          --root-data-image ${lib.escapeShellArg "${toString unsignedArtifacts}/nvme/root-data.img"} \
          --root-hash-tree-image ${lib.escapeShellArg "${toString unsignedArtifacts}/nvme/root-hash.img"} \
          --output "$out"

        test "$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
          $'manifests\nobjects\npublication-digest\npublication.json\nrecords\ntree-records\ntrees'
      '';
in
{
  inherit mkRpi5VerifiedSignedRelease;
}
