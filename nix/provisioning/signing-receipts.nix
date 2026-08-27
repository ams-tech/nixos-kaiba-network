{
  pkgs,
  lib,
  signingReceiptsTool,
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

  # Authenticate the complete receipt export against the reviewed registry and
  # public key, using receipt digests captured from the independently verified
  # signing results.  The output is a typed build product so later release
  # composition can require its exact input lineage instead of trusting an
  # arbitrary JSON document whose status field merely says "valid".
  mkRpi5VerifiedSigningReceipts =
    {
      reviewedPublicKeyPEM,
      signingGrantRegistry,
      signingReceiptExport,
      verifiedOwnedRecovery,
      verifiedSignedBoot,
      verifiedSignedEEPROM,
      name ? "kaiba-rpi5-verified-signing-receipts.json",
    }:
    assert lib.assertMsg (lib.all storeBacked [
      reviewedPublicKeyPEM
      signingGrantRegistry
      signingReceiptExport
      verifiedOwnedRecovery
      verifiedSignedBoot
      verifiedSignedEEPROM
    ]) "every signing-receipt verification input must be a fixed Nix-store path";
    assert lib.assertMsg (
      builtins.isAttrs verifiedSignedBoot && verifiedSignedBoot ? kaibaVerifiedSignedBoot
    ) "verifiedSignedBoot must be produced by mkRpi5VerifiedSignedBoot";
    assert lib.assertMsg (
      builtins.isAttrs verifiedSignedEEPROM && verifiedSignedEEPROM ? kaibaVerifiedSignedEEPROM
    ) "verifiedSignedEEPROM must be produced by mkRpi5VerifiedSignedEEPROM";
    assert lib.assertMsg (
      builtins.isAttrs verifiedOwnedRecovery && verifiedOwnedRecovery ? kaibaVerifiedOwnedRecovery
    ) "verifiedOwnedRecovery must be produced by mkRpi5VerifiedOwnedRecovery";
    let
      bootProvenance = verifiedSignedBoot.kaibaVerifiedSignedBoot;
      bootPlan = bootProvenance.signingPlan.kaibaBootSigningPlan;
      eepromProvenance = verifiedSignedEEPROM.kaibaVerifiedSignedEEPROM;
      eepromPlan = eepromProvenance.signingPlan.kaibaRpi5EEPROMSigningPlan;
      recoveryProvenance = verifiedOwnedRecovery.kaibaVerifiedOwnedRecovery;
      recoveryPlan = recoveryProvenance.signingPlan.kaibaRpi5OwnedRecoverySigningPlan;
      releaseIntent = bootPlan.releaseIntent;
    in
    assert lib.assertMsg (
      toString eepromPlan.releaseIntent == toString releaseIntent
    ) "boot and EEPROM receipt inputs must bind the exact same release intent";
    assert lib.assertMsg (
      toString recoveryPlan.freshSigningPlan == toString eepromProvenance.signingPlan
      && toString recoveryPlan.verifiedSignedEEPROM == toString verifiedSignedEEPROM
    ) "owned-recovery receipt input must extend the selected verified signed EEPROM";
    assert lib.assertMsg (lib.all (candidate: toString candidate == toString reviewedPublicKeyPEM) [
      bootPlan.reviewedPublicKeyPEM
      eepromPlan.reviewedPublicKeyPEM
    ]) "every receipt input must use the selected reviewed public key";
    pkgs.runCommand name
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.jq
          signingReceiptsTool
        ];
        reviewedPublicKeyInput = reviewedPublicKeyPEM;
        signingGrantRegistryInput = signingGrantRegistry;
        signingReceiptExportInput = signingReceiptExport;
        verifiedOwnedRecoveryInput = verifiedOwnedRecovery;
        verifiedSignedBootInput = verifiedSignedBoot;
        verifiedSignedEEPROMInput = verifiedSignedEEPROM;
        passthru.kaibaVerifiedSigningReceipts = {
          inherit
            releaseIntent
            reviewedPublicKeyPEM
            signingGrantRegistry
            signingReceiptExport
            verifiedOwnedRecovery
            verifiedSignedBoot
            verifiedSignedEEPROM
            ;
          exactReceiptCount = 5;
          privateKeyAccess = false;
          receiptAttestationRequired = true;
          receiptAttestationSchemaVersion = "kaiba.provisioning.signing-gate-receipt-attestation/v1alpha1";
          schemaVersion = "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2";
          signingAuthorityConfigured = false;
          verificationMode = "authenticated_offline";
        };
        meta = {
          description = "Authenticated offline verification of five Raspberry Pi 5 signing receipts";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        for input in \
          "$signingGrantRegistryInput" \
          "$signingReceiptExportInput" \
          "$reviewedPublicKeyInput" \
          "$verifiedSignedBootInput/signing-result.json" \
          "$verifiedSignedEEPROMInput/result.json" \
          "$verifiedOwnedRecoveryInput/result.json"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done

        boot_receipt="$(
          jq --exit-status --raw-output \
            '.gate_receipt_digest | select(type == "string")' \
            "$verifiedSignedBootInput/signing-result.json"
        )"
        mapfile -t eeprom_receipts < <(
          jq --exit-status --raw-output '
            .signatures
            | if length == 3 then .[].gate_receipt_digest
              else error("expected exactly three EEPROM signing receipts")
              end
          ' "$verifiedSignedEEPROMInput/result.json"
        )
        test "''${#eeprom_receipts[@]}" -eq 3
        owned_recovery_receipt="$(
          jq --exit-status --raw-output \
            '.signature.gate_receipt_digest | select(type == "string")' \
            "$verifiedOwnedRecoveryInput/result.json"
        )"

        printf '%s\n' \
          "$boot_receipt" \
          "''${eeprom_receipts[0]}" \
          "''${eeprom_receipts[1]}" \
          "''${eeprom_receipts[2]}" \
          "$owned_recovery_receipt" \
          > "$TMPDIR/independently-captured-receipt-digests"
        test "$(wc -l < "$TMPDIR/independently-captured-receipt-digests")" -eq 5
        test "$(sort -u "$TMPDIR/independently-captured-receipt-digests" | wc -l)" -eq 5

        kaiba-provision-signing-receipts verify \
          --export "$signingReceiptExportInput" \
          --registry "$signingGrantRegistryInput" \
          --public-key "$reviewedPublicKeyInput" \
          --expected-receipt-digest "$boot_receipt" \
          --expected-receipt-digest "''${eeprom_receipts[0]}" \
          --expected-receipt-digest "''${eeprom_receipts[1]}" \
          --expected-receipt-digest "''${eeprom_receipts[2]}" \
          --expected-receipt-digest "$owned_recovery_receipt" \
          > "$out"

        jq -e '
          .schema_version == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
          and .status == "valid"
          and (.receipt_digests | length == 5)
          and (.receipt_digests | unique | length == 5)
        ' "$out" > /dev/null
        check-jsonschema \
          --schemafile ${signingReceiptsTool}/share/kaiba/schemas/signing-gate-receipt-verification-v1alpha2.schema.json \
          "$out"
        chmod 0444 "$out"
      '';
in
{
  inherit mkRpi5VerifiedSigningReceipts;
}
