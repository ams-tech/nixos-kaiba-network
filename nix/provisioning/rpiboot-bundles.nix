{
  pkgs,
  lib,
  eepromSigningTool,
  rpibootBundleTool,
  signedBootTool,
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

  # Re-run every component finalizer before constructing the six canonical
  # directory trees. This factory consumes public artifacts only and cannot
  # contact a signer, access a board, program EEPROM, stage media, or change
  # OTP. The two rejection trees are deterministic fixtures, not observations.
  mkRpi5VerifiedRPIBootBundles =
    {
      unsignedArtifacts,
      verifiedOwnedRecovery,
      verifiedSignedBoot,
      verifiedSignedEEPROM,
      name ? "kaiba-rpi5-verified-rpiboot-bundles",
    }:
    assert lib.assertMsg (lib.all storeBacked [
      unsignedArtifacts
      verifiedOwnedRecovery
      verifiedSignedBoot
      verifiedSignedEEPROM
    ]) "every RPIBOOT bundle input must be a fixed Nix-store path";
    assert lib.assertMsg (
      unsignedArtifacts ? kaibaUnsignedArtifacts
    ) "unsignedArtifacts must be produced by mkRpi5SecureBootArtifacts";
    assert lib.assertMsg (
      verifiedSignedBoot ? kaibaVerifiedSignedBoot
    ) "verifiedSignedBoot must be produced by mkRpi5VerifiedSignedBoot";
    assert lib.assertMsg (
      verifiedSignedEEPROM ? kaibaVerifiedSignedEEPROM
    ) "verifiedSignedEEPROM must be produced by mkRpi5VerifiedSignedEEPROM";
    assert lib.assertMsg (
      verifiedOwnedRecovery ? kaibaVerifiedOwnedRecovery
    ) "verifiedOwnedRecovery must be produced by mkRpi5VerifiedOwnedRecovery";
    let
      bootProvenance = verifiedSignedBoot.kaibaVerifiedSignedBoot;
      eepromProvenance = verifiedSignedEEPROM.kaibaVerifiedSignedEEPROM;
      recoveryProvenance = verifiedOwnedRecovery.kaibaVerifiedOwnedRecovery;
      recoveryPlan = recoveryProvenance.signingPlan.kaibaRpi5OwnedRecoverySigningPlan;
    in
    assert lib.assertMsg (
      toString recoveryPlan.verifiedSignedEEPROM == toString verifiedSignedEEPROM
    ) "owned recovery must extend the exact verified signed EEPROM";
    pkgs.runCommand name
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.findutils
          pkgs.jq
        ];
        passthru.kaibaVerifiedRPIBootBundles = {
          inherit
            unsignedArtifacts
            verifiedOwnedRecovery
            verifiedSignedBoot
            verifiedSignedEEPROM
            ;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          fixtureHardwareObserved = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          schemaVersion = "kaiba.provisioning.rpi5-rpiboot-bundle-set/v1alpha1";
          signingAuthorityConfigured = false;
          verificationMode = "pure_offline_replay";
          bundlePaths = {
            freshCommit = "fresh-commit";
            freshReadback = "fresh-readback";
            negativeBoot = "negative-boot";
            ownedReadback = "owned-readback";
            ownedRecovery = "owned-recovery";
            rootIntegrityTest = "root-integrity-test";
          };
        };
        meta = {
          description = "Verified immutable Raspberry Pi 5 RPIBOOT and acceptance bundle set";
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

        mkdir "$TMPDIR/reverified-eeprom" "$TMPDIR/reverified-recovery" \
          "$TMPDIR/reverified-boot"
        rmdir "$TMPDIR/reverified-eeprom" "$TMPDIR/reverified-recovery" \
          "$TMPDIR/reverified-boot"

        ${eepromSigningTool}/bin/kaiba-provision-sign-eeprom finalize \
          --plan ${lib.escapeShellArg (toString eepromProvenance.signingPlan)} \
          --signed ${lib.escapeShellArg (toString eepromProvenance.signedOutput)} \
          --output "$TMPDIR/reverified-eeprom"
        ${eepromSigningTool}/bin/kaiba-provision-sign-eeprom finalize-owned-recovery \
          --plan ${lib.escapeShellArg (toString recoveryProvenance.signingPlan)} \
          --signed ${lib.escapeShellArg (toString recoveryProvenance.signedOutput)} \
          --output "$TMPDIR/reverified-recovery"
        ${signedBootTool}/bin/kaiba-provision-sign-boot finalize \
          --plan ${lib.escapeShellArg (toString bootProvenance.signingPlan)} \
          --signed ${lib.escapeShellArg (toString bootProvenance.signedOutput)} \
          --output "$TMPDIR/reverified-boot"

        diff --recursive --no-dereference \
          ${lib.escapeShellArg (toString verifiedSignedEEPROM)} "$TMPDIR/reverified-eeprom"
        diff --recursive --no-dereference \
          ${lib.escapeShellArg (toString verifiedOwnedRecovery)} "$TMPDIR/reverified-recovery"
        diff --recursive --no-dereference \
          ${lib.escapeShellArg (toString verifiedSignedBoot)} "$TMPDIR/reverified-boot"

        readonly intent_digest="$(jq -r .release_intent_digest \
          "$TMPDIR/reverified-boot/signing-result.json")"
        test "$intent_digest" = "$(jq -r .release_intent_digest \
          "$TMPDIR/reverified-eeprom/result.json")"
        test "$intent_digest" = "$(jq -r .release_intent_digest \
          "$TMPDIR/reverified-recovery/result.json")"
        cmp "$TMPDIR/reverified-boot/release-intent.json" \
          "$TMPDIR/reverified-eeprom/release-intent.json"
        cmp "$TMPDIR/reverified-boot/release-intent.json" \
          "$TMPDIR/reverified-recovery/release-intent.json"

        ${rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles build \
          --release-intent-digest "$intent_digest" \
          --fresh-recovery "$TMPDIR/reverified-eeprom/bootcode5.bin" \
          --owned-recovery "$TMPDIR/reverified-recovery/bootcode5.bin" \
          --signed-eeprom "$TMPDIR/reverified-eeprom/pieeprom.bin" \
          --eeprom-metadata "$TMPDIR/reverified-eeprom/pieeprom.sig" \
          --boot-image "$TMPDIR/reverified-boot/boot.img" \
          --boot-signature "$TMPDIR/reverified-boot/boot.sig" \
          --boot-public-key "$TMPDIR/reverified-boot/public.pem" \
          --root-data ${lib.escapeShellArg "${toString unsignedArtifacts}/nvme/root-data.img"} \
          --root-hash-tree ${lib.escapeShellArg "${toString unsignedArtifacts}/nvme/root-hash.img"} \
          --output "$out" > "$TMPDIR/bundle-set-digest"

        ${rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles verify \
          --input "$out" > "$TMPDIR/reverified-bundle-set-digest"
        cmp "$TMPDIR/bundle-set-digest" "$TMPDIR/reverified-bundle-set-digest"
        test "$(find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
          $'bundle-set.json\nfresh-commit\nfresh-readback\nnegative-boot\nowned-readback\nowned-recovery\nroot-integrity-test'
      '';
in
{
  inherit mkRpi5VerifiedRPIBootBundles;
}
