{
  pkgs,
  lib,
  built,
  hardwareConfigurations,
  kaibaModules,
}:

let
  secureBootArtifactBuilder = import ../../nix/provisioning/secure-boot-artifacts.nix {
    inherit lib pkgs;
  };
  secureBootFixtureFirmware = pkgs.runCommand "kaiba-secure-boot-fixture-firmware" { } ''
    mkdir -p "$out/overlays"
    printf '%s\n' 'console=serial0,115200' > "$out/cmdline.txt"
    printf '%s\n' 'fixture-kernel' > "$out/kernel_2712.img"
    printf '%s\n' 'fixture-initramfs' > "$out/initramfs_2712"
    printf '%s\n' 'fixture-device-tree' > "$out/bcm2712-rpi-5-b.dtb"
    printf '%s\n' 'fixture-overlay' > "$out/overlays/README"
  '';
  mkSecureBootFixtureRoot =
    name:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.e2fsprogs ]; } ''
      set -euo pipefail
      export E2FSPROGS_FAKE_TIME=315532800
      export LC_ALL=C
      export SOURCE_DATE_EPOCH=315532800
      export TZ=UTC

      printf '%s\n' 'kaiba dm-verity fixture' > "$TMPDIR/README"
      truncate --size=16M "$out"
      mkfs.ext4 \
        -F \
        -L KAIBA_ROOT \
        -U 4b414942-4152-4f4f-9400-000000000001 \
        -E hash_seed=4b414942-4152-4f4f-9400-000000000002,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0 \
        "$out" \
        > /dev/null

      # e2fsprogs otherwise selects signed or unsigned directory hashing from
      # the host architecture's plain-char signedness.  Normalize the primary
      # and backup superblocks before adding files so this fixture is identical
      # on x86_64 and aarch64.  flags=1 is EXT2_FLAGS_SIGNED_HASH; close -a
      # propagates it to every backup superblock.
      printf '%s\n' \
        'set_super_value flags 1' \
        'close -a' \
        | debugfs -w "$out" > /dev/null

      # Import through debugfs under a fixed e2fsprogs clock instead of using
      # mkfs.ext4 -d, which preserves nondeterministic host ctime/ownership.
      debugfs -w -R "write $TMPDIR/README /README" "$out" > /dev/null
      debugfs -w -R 'set_inode_field /README uid 0' "$out" > /dev/null
      debugfs -w -R 'set_inode_field /README gid 0' "$out" > /dev/null
      debugfs -w -R 'set_inode_field /README mode 0100644' "$out" > /dev/null
      for field in atime ctime mtime crtime; do
        debugfs -w -R "set_inode_field /README $field @315532800" "$out" > /dev/null
      done
      e2fsck -fn "$out" > /dev/null
    '';
  secureBootFixtureRootA = mkSecureBootFixtureRoot "kaiba-secure-boot-fixture-root-a.img";
  secureBootFixtureRootB = mkSecureBootFixtureRoot "kaiba-secure-boot-fixture-root-b.img";
  canonicalSourceRevision40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  canonicalSourceRevision64 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  signingCeremonyPackage = import ../../nix/development-signing-ceremony.nix {
    inherit pkgs;
    sourceRevision = canonicalSourceRevision40;
    sourceTreeClean = true;
  };
  signingCeremonyAutomationCheck = import ../signing-ceremony.nix {
    ceremony = signingCeremonyPackage;
    inherit pkgs;
  };
  secureBootRootDataPartitionGUID = "bdd5be20-f7ea-56e7-ae90-4465ae950596";
  secureBootRootHashPartitionGUID = "62616022-71fb-5036-8cc4-b7949cc6e52c";
  mkSecureBootFixture =
    {
      name,
      rootImage ? secureBootFixtureRootA,
      sourceRevision ? canonicalSourceRevision40,
    }:
    secureBootArtifactBuilder {
      inherit name;
      expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      firmwareAllowlist = [
        "bcm2712-rpi-5-b.dtb"
        "cmdline.txt"
        "initramfs_2712"
        "kernel_2712.img"
        "overlays/README"
      ];
      firmwareTree = secureBootFixtureFirmware;
      inherit rootImage;
      rootDataPartitionGUID = secureBootRootDataPartitionGUID;
      rootHashPartitionGUID = secureBootRootHashPartitionGUID;
      inherit sourceRevision;
    };
  secureBootFixtureA = mkSecureBootFixture { name = "kaiba-secure-boot-artifacts-fixture-a"; };
  secureBootFixtureB = mkSecureBootFixture {
    name = "kaiba-secure-boot-artifacts-fixture-b";
    rootImage = secureBootFixtureRootB;
  };
  sourceRevisionAccepted =
    sourceRevision:
    (builtins.tryEval (
      (mkSecureBootFixture {
        name = "kaiba-secure-boot-artifacts-source-revision-evaluation";
        inherit sourceRevision;
      }).drvPath
    )).success;
  validSourceRevisions = [
    canonicalSourceRevision40
    canonicalSourceRevision64
  ];
  invalidSourceRevisions = [
    ""
    "uncommitted"
    "release-candidate"
    "${canonicalSourceRevision40}-dirty"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    (builtins.substring 0 39 canonicalSourceRevision40)
    "${canonicalSourceRevision40}a"
  ];
  partitionGUIDsAccepted =
    rootDataPartitionGUID: rootHashPartitionGUID:
    (builtins.tryEval (
      (secureBootArtifactBuilder {
        name = "kaiba-secure-boot-artifacts-partition-guid-evaluation";
        expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        firmwareAllowlist = [ "cmdline.txt" ];
        firmwareTree = secureBootFixtureFirmware;
        rootImage = secureBootFixtureRootA;
        inherit rootDataPartitionGUID rootHashPartitionGUID;
        sourceRevision = canonicalSourceRevision40;
      }).drvPath
    )).success;
  signingGrantFixture = pkgs.writeText "kaiba-signing-grant-registry-fixture.json" (
    builtins.toJSON {
      schema_version = "kaiba.provisioning.signing-grant-registry/v1alpha2";
      grants = [
        {
          schema_version = "kaiba.provisioning.signing-grant/v1alpha2";
          grant_id = "grant:boot-image:1";
          expires_at = "2099-01-01T00:00:00Z";
          request = {
            schema_version = "kaiba.provisioning.signing-request/v1alpha2";
            request_id = "request:boot-image:1";
            algorithm = "rsa2048-sha256";
            role = "rpi5.boot_image";
            artifact_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            approval = {
              approval_id = "approval:development:1";
              approval_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
              release_intent_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
              role = "rpi5.boot_image";
              artifact_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            };
          };
        }
      ];
    }
  );
  developmentYubiKeyCustomerKeyHash = "f06d7ff084a6c69d60d7ca5a7554afa199132c31b54f9366d2852711053fa7de";
  developmentYubiKeyPublicKeyFingerprint = "sha256:21bfca39f5db869c81f1fdab5f1d2569bdd5e67ef07ccfe0e3b6ddd792a6cfe1";
  developmentYubiKeySignerPolicyDigest = "sha256:498534e04cf7a511356fbec7fac4ad994a692e352fa0db65e99e8ba0bdbc5d61";
  developmentYubiKeyPublicKeyPEM = pkgs.writeText "kaiba-development-boot-public-key.pem" (
    builtins.readFile ./fixtures/development-boot-public.pem
  );
  emptySigningGrantRegistryEvaluationFixture = pkgs.writeText "kaiba-empty-signing-grant-registry-evaluation.json" "{}\n";
  emptySigningReceiptExportEvaluationFixture = pkgs.writeText "kaiba-empty-signing-receipt-export-evaluation.json" "{}\n";
  releaseIntentEEPROMBootcodeInput = pkgs.writeText "kaiba-release-intent-eeprom-bootcode-input" ''
    synthetic EEPROM bootcode signing preimage
  '';
  releaseIntentEEPROMBootsysInput = pkgs.writeText "kaiba-release-intent-eeprom-bootsys-input" ''
    synthetic EEPROM bootsys signing preimage
  '';
  releaseIntentEEPROMConfigInput = pkgs.writeText "kaiba-release-intent-eeprom-config-input" ''
    BOOT_UART=1
    BOOT_ORDER=0xf2461
  '';
  releaseIntentOwnedRecoveryInput = pkgs.writeText "kaiba-release-intent-owned-recovery-input" ''
    synthetic owned-recovery signing preimage
  '';
  releaseIntentEEPROMRelease = pkgs.runCommand "kaiba-release-intent-eeprom-release-fixture" { } ''
    mkdir "$out"
    printf '%s' ${
      lib.escapeShellArg (
        builtins.toJSON {
          schema_version = "kaiba.provisioning.rpi5-eeprom-release/v1alpha1";
        }
      )
    } > "$out/release.json"
    chmod 0444 "$out/release.json"
  '';
  mkReleaseIntentUnsignedArtifacts =
    {
      bootImage,
      expectedCustomerKeyHash,
      name,
      sourceRevision,
    }:
    pkgs.runCommand name
      {
        bootImageInput = bootImage;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        mkdir -p "$out/unsigned"
        install -m 0444 "$bootImageInput" "$out/unsigned/boot.img"
        boot_digest="sha256:$(sha256sum "$out/unsigned/boot.img" | cut -d ' ' -f 1)"
        boot_size="$(stat --format=%s "$out/unsigned/boot.img")"
        jq \
          --null-input \
          --arg schema 'provisioning.kaiba.network/unsigned-artifact-set/v1alpha1' \
          --arg source_revision '${sourceRevision}' \
          --arg expected_customer_key_hash '${expectedCustomerKeyHash}' \
          --arg boot_digest "$boot_digest" \
          --argjson boot_size "$boot_size" \
          '{
            schema: $schema,
            source_revision: $source_revision,
            expected_customer_key_hash: $expected_customer_key_hash,
            boot_image_size_bytes: $boot_size,
            artifacts: {boot_image: {digest: $boot_digest}}
          }' > "$TMPDIR/manifest-without-digest.json"
        canonical_manifest="$(jq --sort-keys --compact-output . \
          "$TMPDIR/manifest-without-digest.json")"
        bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
          printf '%s' "$canonical_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --arg bundle_digest "$bundle_digest" \
          '. + {bundle_digest: $bundle_digest}' \
          "$TMPDIR/manifest-without-digest.json" > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';
  mkTestReleaseIntent =
    {
      bootImage,
      name,
      publicKeyFingerprint,
      releaseID,
      signerPolicyDigest,
      sourceDateEpoch,
      expectedCustomerKeyHash ? "sha256:${developmentYubiKeyCustomerKeyHash}",
    }:
    let
      sourceRevision = canonicalSourceRevision40;
      unsignedArtifacts = mkReleaseIntentUnsignedArtifacts {
        inherit bootImage expectedCustomerKeyHash sourceRevision;
        name = "${name}-unsigned-artifacts";
      };
    in
    built.mkRpi5ReleaseIntent {
      bootImage = "${unsignedArtifacts}/unsigned/boot.img";
      inherit
        name
        publicKeyFingerprint
        releaseID
        signerPolicyDigest
        sourceDateEpoch
        sourceRevision
        unsignedArtifacts
        ;
      eepromBootcodeSigningInput = releaseIntentEEPROMBootcodeInput;
      eepromBootsysSigningInput = releaseIntentEEPROMBootsysInput;
      eepromConfigSigningInput = releaseIntentEEPROMConfigInput;
      eepromRelease = releaseIntentEEPROMRelease;
      ownedRecoveryBootcodeSigningInput = releaseIntentOwnedRecoveryInput;
      inherit expectedCustomerKeyHash;
    };
  developmentYubiKeySigning = built.mkDevelopmentYubiKeySigning {
    name = "kaiba-development-yubikey-signing-fixture";
    signerID = "signer:development-fixture";
    cohortID = "cohort:development-fixture";
    tokenSerial = "12345678";
    publicKeyPEM = developmentYubiKeyPublicKeyPEM;
    publicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
    signerPolicyDigest = developmentYubiKeySignerPolicyDigest;
    expectedCustomerKeyHash = developmentYubiKeyCustomerKeyHash;
    grantRegistryPath = "/etc/kaiba-provisioning/signing-grants.json";
  };
  unfusedVerifierFixture = built.mkRpi5UnfusedVerifier {
    name = "kaiba-rpi5-unfused-verifier-fixture";
    trustedPublicKeyFingerprint = developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint;
  };
  bootReleaseIntentFixture = mkTestReleaseIntent {
    name = "kaiba-rpi5-boot-release-intent-fixture";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    releaseID = "release:rpi5-development-fixture:1";
    publicKeyFingerprint = developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint;
    signerPolicyDigest = developmentYubiKeySigning.kaibaSigning.signerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  bootSigningPlanFixture = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-boot-signing-plan-fixture";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    planID = "plan:rpi5-development-fixture:1";
    publicKeyFingerprint = developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint;
    releaseIntent = bootReleaseIntentFixture;
    # Exercise a key nested directly below the flake source.  The factory must
    # preserve its Nix path context so the sandbox mounts it as an input.
    reviewedPublicKeyPEM = ./fixtures/development-boot-public.pem;
    signerPolicyDigest = developmentYubiKeySigning.kaibaSigning.signerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  bootSigningPlanInputAccepted =
    overrides:
    (builtins.tryEval (
      (built.mkRpi5BootSigningPlan (
        {
          name = "kaiba-rpi5-boot-signing-plan-evaluation";
          bootImage = "${secureBootFixtureA}/unsigned/boot.img";
          planID = "plan:rpi5-development-fixture:1";
          publicKeyFingerprint = developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint;
          releaseIntent = bootReleaseIntentFixture;
          reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
          signerPolicyDigest = developmentYubiKeySigning.kaibaSigning.signerPolicyDigest;
          sourceDateEpoch = 1786968000;
        }
        // overrides
      )).drvPath
    )).success;
  eepromReleaseSigningInputsFixture = built.mkRpi5EEPROMReleaseSigningInputs {
    name = "kaiba-rpi5-eeprom-release-signing-inputs-fixture";
    eepromRelease = built.rpi5EEPROMRelease;
    bootConfig = ../../provisioning/config/rpi5-prototype-eeprom/boot.conf;
  };
  eepromPlanUnsignedArtifacts = mkReleaseIntentUnsignedArtifacts {
    name = "kaiba-rpi5-eeprom-plan-unsigned-artifacts";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    expectedCustomerKeyHash = "sha256:${developmentYubiKeyCustomerKeyHash}";
    sourceRevision = canonicalSourceRevision40;
  };
  eepromReleaseIntentFixture = built.mkRpi5ReleaseIntent {
    name = "kaiba-rpi5-eeprom-release-intent-fixture";
    releaseID = "release:rpi5-eeprom-fixture:1";
    bootImage = "${eepromPlanUnsignedArtifacts}/unsigned/boot.img";
    eepromBootcodeSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-bootcode.signing-input";
    eepromBootsysSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-bootsys.signing-input";
    eepromConfigSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-config.signing-input";
    eepromRelease = built.rpi5EEPROMRelease;
    ownedRecoveryBootcodeSigningInput = "${eepromReleaseSigningInputsFixture}/owned-recovery-bootcode.signing-input";
    expectedCustomerKeyHash = "sha256:${developmentYubiKeyCustomerKeyHash}";
    publicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
    signerPolicyDigest = developmentYubiKeySignerPolicyDigest;
    sourceDateEpoch = 1786968000;
    sourceRevision = canonicalSourceRevision40;
    unsignedArtifacts = eepromPlanUnsignedArtifacts;
  };
  eepromSigningPlanFixture = built.mkRpi5EEPROMSigningPlan {
    name = "kaiba-rpi5-eeprom-signing-plan-fixture";
    planID = "plan:rpi5-eeprom-fixture:1";
    bootConfig = ../../provisioning/config/rpi5-prototype-eeprom/boot.conf;
    customerKeyHash = "sha256:${developmentYubiKeyCustomerKeyHash}";
    eepromSigningInputs = eepromReleaseSigningInputsFixture;
    publicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
    releaseIntent = eepromReleaseIntentFixture;
    reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
    signerPolicyDigest = developmentYubiKeySignerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  ownedRecoverySyntheticVerifiedFreshEEPROM =
    pkgs.runCommand "kaiba-owned-recovery-synthetic-verified-fresh-eeprom"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
        passthru.kaibaVerifiedSignedEEPROM = {
          signingPlan = eepromSigningPlanFixture;
          signedOutput = emptySignedOutputFixture;
          verificationMode = "synthetic_contract_fixture";
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        mkdir "$out"
        install -m 0444 ${eepromSigningPlanFixture}/pieeprom.original.bin \
          "$out/pieeprom.bin"
        install -m 0444 ${eepromSigningPlanFixture}/recovery.original.bin \
          "$out/bootcode5.bin"
        printf '%s\n' 'synthetic EEPROM metadata' > "$out/pieeprom.sig"

        plan_json="$(cat ${eepromSigningPlanFixture}/plan.json)"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        file_record() {
          jq \
            --null-input \
            --compact-output \
            --arg digest "sha256:$(sha256sum "$1" | cut -d ' ' -f 1)" \
            --argjson size_bytes "$(stat --format=%s "$1")" \
            '{digest: $digest, size_bytes: $size_bytes}'
        }
        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'kaiba.provisioning.rpi5-eeprom-signing-result/v1alpha1' \
          --arg plan_id "$(jq -r .plan_id ${eepromSigningPlanFixture}/plan.json)" \
          --arg plan_digest "$plan_digest" \
          --arg release_intent_digest \
            "$(jq -r .release_intent_digest ${eepromSigningPlanFixture}/plan.json)" \
          --arg eeprom_release_manifest_digest \
            "$(jq -r .eeprom_release_manifest_digest ${eepromSigningPlanFixture}/plan.json)" \
          --arg signer_policy_digest \
            "$(jq -r .signer_policy_digest ${eepromSigningPlanFixture}/plan.json)" \
          --arg public_key_fingerprint \
            "$(jq -r .public_key_fingerprint ${eepromSigningPlanFixture}/plan.json)" \
          --arg customer_key_hash \
            "$(jq -r .customer_key_hash ${eepromSigningPlanFixture}/plan.json)" \
          --argjson source_date_epoch \
            "$(jq -r .source_date_epoch ${eepromSigningPlanFixture}/plan.json)" \
          --argjson signing_inputs \
            "$(jq -c .signing_inputs ${eepromSigningPlanFixture}/plan.json)" \
          --argjson signed_eeprom "$(file_record "$out/pieeprom.bin")" \
          --argjson metadata "$(file_record "$out/pieeprom.sig")" \
          --argjson recovery "$(file_record "$out/bootcode5.bin")" \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $release_intent_digest,
            eeprom_release_manifest_digest: $eeprom_release_manifest_digest,
            signer_policy_digest: $signer_policy_digest,
            public_key_fingerprint: $public_key_fingerprint,
            customer_key_hash: $customer_key_hash,
            source_date_epoch: $source_date_epoch,
            updater_mode: "fresh-board",
            recovery_mode: "unsigned-copy",
            signatures: ($signing_inputs | map({
              role: .role,
              input_digest: .digest,
              input_size_bytes: .size_bytes,
              signature_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              signature_size_bytes: 256,
              gate_receipt_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            })),
            signed_eeprom: $signed_eeprom,
            eeprom_update_metadata: $metadata,
            fresh_recovery_bootcode: $recovery
          }' > "$out/result.json"
        chmod 0444 "$out/result.json"
      '';
  ownedRecoverySigningPlanFixture = built.mkRpi5OwnedRecoverySigningPlan {
    name = "kaiba-rpi5-owned-recovery-signing-plan-fixture";
    planID = "plan:rpi5-owned-recovery-fixture:1";
    freshSigningPlan = eepromSigningPlanFixture;
    verifiedSignedEEPROM = ownedRecoverySyntheticVerifiedFreshEEPROM;
  };
  ownedRecoverySigningPlanInputAccepted =
    overrides:
    (builtins.tryEval (
      (built.mkRpi5OwnedRecoverySigningPlan (
        {
          name = "kaiba-rpi5-owned-recovery-signing-plan-input-evaluation";
          planID = "plan:rpi5-owned-recovery-fixture:1";
          freshSigningPlan = eepromSigningPlanFixture;
          verifiedSignedEEPROM = ownedRecoverySyntheticVerifiedFreshEEPROM;
        }
        // overrides
      )).drvPath
    )).success;
  oversizedEEPROMBootConfig = pkgs.writeText "kaiba-oversized-eeprom-boot.conf" (
    builtins.concatStringsSep "" (builtins.genList (_: "X") 4077)
  );
  eepromPinnedUpdaterTestHSM = pkgs.writeShellScript "kaiba-eeprom-pinned-updater-test-hsm" ''
    set -euo pipefail
    test "$#" -eq 3
    test "$1" = '-a'
    test "$2" = 'rsa2048-sha256'
    test -f "$3"
    test -f "$KAIBA_TEST_PRIVATE_KEY"
    test -n "$KAIBA_TEST_CALLBACK_LOG"
    printf '%s\n' "sha256:$(${pkgs.coreutils}/bin/sha256sum "$3" | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)" \
      >> "$KAIBA_TEST_CALLBACK_LOG"
    ${pkgs.openssl}/bin/openssl dgst -sha256 -sign "$KAIBA_TEST_PRIVATE_KEY" "$3" \
      | ${pkgs.xxd}/bin/xxd -c 4096 -p
  '';
  eepromSigningPlanInputAccepted =
    overrides:
    (builtins.tryEval (
      (built.mkRpi5EEPROMSigningPlan (
        {
          name = "kaiba-rpi5-eeprom-signing-plan-evaluation";
          planID = "plan:rpi5-eeprom-fixture:1";
          bootConfig = ../../provisioning/config/rpi5-prototype-eeprom/boot.conf;
          customerKeyHash = "sha256:${developmentYubiKeyCustomerKeyHash}";
          eepromSigningInputs = eepromReleaseSigningInputsFixture;
          publicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
          releaseIntent = eepromReleaseIntentFixture;
          reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
          signerPolicyDigest = developmentYubiKeySignerPolicyDigest;
          sourceDateEpoch = 1786968000;
        }
        // overrides
      )).drvPath
    )).success;
  verifiedSignedEEPROMEvaluationFixture = built.mkRpi5VerifiedSignedEEPROM {
    name = "kaiba-rpi5-verified-signed-eeprom-evaluation";
    signedOutput = emptySignedOutputFixture;
    signingPlan = eepromSigningPlanFixture;
  };
  ownedRecoverySigningPlanEvaluationFixture = built.mkRpi5OwnedRecoverySigningPlan {
    name = "kaiba-rpi5-owned-recovery-signing-plan-evaluation";
    planID = "plan:rpi5-owned-recovery-fixture:1";
    freshSigningPlan = eepromSigningPlanFixture;
    verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
  };
  verifiedOwnedRecoveryEvaluationFixture = built.mkRpi5VerifiedOwnedRecovery {
    name = "kaiba-rpi5-verified-owned-recovery-evaluation";
    signedOutput = emptySignedOutputFixture;
    signingPlan = ownedRecoverySigningPlanEvaluationFixture;
  };
  emptySignedOutputFixture = pkgs.runCommand "kaiba-empty-signed-output-fixture" { } ''
    mkdir "$out"
  '';
  verifiedSignedBootEvaluationFixture = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-rpi5-verified-signed-boot-metadata-fixture";
    signingPlan = bootSigningPlanFixture;
    signedOutput = emptySignedOutputFixture;
  };
  rpibootBundleEvaluationFixture = built.mkRpi5VerifiedRPIBootBundles {
    name = "kaiba-rpi5-rpiboot-bundle-set-evaluation";
    unsignedArtifacts = secureBootFixtureA;
    verifiedOwnedRecovery = verifiedOwnedRecoveryEvaluationFixture;
    verifiedSignedBoot = verifiedSignedBootEvaluationFixture;
    verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
  };
  signedReleaseBootSigningPlanEvaluationFixture = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-signed-release-boot-plan-evaluation";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    planID = "plan:rpi5-signed-release-evaluation:1";
    publicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
    releaseIntent = eepromReleaseIntentFixture;
    reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
    signerPolicyDigest = developmentYubiKeySignerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  signedReleaseVerifiedBootEvaluationFixture = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-rpi5-signed-release-verified-boot-evaluation";
    signingPlan = signedReleaseBootSigningPlanEvaluationFixture;
    signedOutput = emptySignedOutputFixture;
  };
  signedReleaseRPIBootBundleEvaluationFixture = built.mkRpi5VerifiedRPIBootBundles {
    name = "kaiba-rpi5-signed-release-rpiboot-evaluation";
    unsignedArtifacts = secureBootFixtureA;
    verifiedOwnedRecovery = verifiedOwnedRecoveryEvaluationFixture;
    verifiedSignedBoot = signedReleaseVerifiedBootEvaluationFixture;
    verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
  };
  signedReleasePlatformAdapterEvaluationFixture = pkgs.writeText "kaiba-rpi5-platform-adapter-evaluation" "immutable adapter fixture\n";
  signedReleaseRootIntegrityEvaluationFixture = pkgs.writeText "kaiba-rpi5-root-integrity-evaluation.json" "{}\n";
  signedReleaseReceiptVerificationEvaluationFixture = built.mkRpi5VerifiedSigningReceipts {
    name = "kaiba-rpi5-signing-receipt-verification-evaluation.json";
    reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
    signingGrantRegistry = emptySigningGrantRegistryEvaluationFixture;
    signingReceiptExport = emptySigningReceiptExportEvaluationFixture;
    verifiedOwnedRecovery = verifiedOwnedRecoveryEvaluationFixture;
    verifiedSignedBoot = signedReleaseVerifiedBootEvaluationFixture;
    verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
  };
  signedReleaseEvaluationFixture = built.mkRpi5VerifiedSignedRelease {
    name = "kaiba-rpi5-verified-signed-release-evaluation";
    deviceProfile = ../../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json;
    eepromRelease = built.rpi5EEPROMRelease;
    platformAdapter = signedReleasePlatformAdapterEvaluationFixture;
    rootIntegrity = signedReleaseRootIntegrityEvaluationFixture;
    signingReceiptVerification = signedReleaseReceiptVerificationEvaluationFixture;
    unsignedArtifacts = secureBootFixtureA;
    verifiedOwnedRecovery = verifiedOwnedRecoveryEvaluationFixture;
    verifiedRPIBootBundles = signedReleaseRPIBootBundleEvaluationFixture;
    verifiedSignedBoot = signedReleaseVerifiedBootEvaluationFixture;
    verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
  };
  untypedSigningReceiptVerificationEvaluationFixture =
    pkgs.writeText "kaiba-untyped-signing-receipt-verification-evaluation.json"
      (
        builtins.toJSON {
          schema_version = "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2";
          status = "valid";
          export_digest = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "6") 64)}";
          registry_digest = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "7") 64)}";
          release_intent_digest = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "8") 64)}";
          public_key_fingerprint = developmentYubiKeyPublicKeyFingerprint;
          receipt_digests =
            map (digit: "sha256:${builtins.concatStringsSep "" (builtins.genList (_: digit) 64)}")
              [
                "1"
                "2"
                "3"
                "4"
                "5"
              ];
        }
      );
  signedReleaseReceiptVerificationInputAccepted =
    signingReceiptVerification:
    (builtins.tryEval (
      (built.mkRpi5VerifiedSignedRelease {
        name = "kaiba-rpi5-signed-release-receipt-input-evaluation";
        deviceProfile = ../../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json;
        eepromRelease = built.rpi5EEPROMRelease;
        platformAdapter = signedReleasePlatformAdapterEvaluationFixture;
        rootIntegrity = signedReleaseRootIntegrityEvaluationFixture;
        inherit signingReceiptVerification;
        unsignedArtifacts = secureBootFixtureA;
        verifiedOwnedRecovery = verifiedOwnedRecoveryEvaluationFixture;
        verifiedRPIBootBundles = signedReleaseRPIBootBundleEvaluationFixture;
        verifiedSignedBoot = signedReleaseVerifiedBootEvaluationFixture;
        verifiedSignedEEPROM = verifiedSignedEEPROMEvaluationFixture;
      }).drvPath
    )).success;
  signedBootFinalizerBootImage = pkgs.writeText "kaiba-signed-boot-finalizer-boot.img" ''
    kaiba signed-boot finalizer fixture
  '';
  signedBootFinalizerPublicKey = pkgs.writeText "kaiba-signed-boot-finalizer-public.pem" (
    builtins.readFile ./fixtures/signed-boot-finalizer-public.pem
  );
  signedBootFinalizerReleaseIntent = mkTestReleaseIntent {
    name = "kaiba-rpi5-signed-boot-finalizer-release-intent";
    bootImage = signedBootFinalizerBootImage;
    releaseID = "release:rpi5-finalizer-fixture:1";
    publicKeyFingerprint = "sha256:104dbbf42aacd5c3357ed4229237f8d8d848af868b8f680b46cba5505d8f67fc";
    signerPolicyDigest = "sha256:68498f57aa811b8a714260a4ac4390118c78efdb2af416cc64bfbd8eac4c42e3";
    sourceDateEpoch = 1786968000;
  };
  signedBootFinalizerPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-signed-boot-finalizer-plan";
    bootImage = signedBootFinalizerBootImage;
    planID = "plan:rpi5-finalizer-fixture:1";
    publicKeyFingerprint = "sha256:104dbbf42aacd5c3357ed4229237f8d8d848af868b8f680b46cba5505d8f67fc";
    releaseIntent = signedBootFinalizerReleaseIntent;
    reviewedPublicKeyPEM = signedBootFinalizerPublicKey;
    signerPolicyDigest = "sha256:68498f57aa811b8a714260a4ac4390118c78efdb2af416cc64bfbd8eac4c42e3";
    sourceDateEpoch = 1786968000;
  };
  signedBootFinalizerSignedOutput =
    pkgs.runCommand "kaiba-signed-boot-finalizer-result"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        mkdir "$out"
        install -m 0444 \
          ${./fixtures/signed-boot-finalizer/boot.sig} \
          "$out/boot.sig"
        canonical_plan="$(cat ${signedBootFinalizerPlan}/plan.json)"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-boot-signing-plan.v1alpha2'
          printf '%s' "$canonical_plan"
        } | sha256sum | cut -d ' ' -f 1)"
        boot_signature_digest="sha256:$(sha256sum "$out/boot.sig" | cut -d ' ' -f 1)"
        boot_signature_size="$(stat --format=%s "$out/boot.sig")"

        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-boot-signing-result/v1alpha2' \
          --arg plan_id "$(jq -r .plan_id ${signedBootFinalizerPlan}/plan.json)" \
          --arg plan_digest "$plan_digest" \
          --arg release_intent_digest \
            "$(jq -r .release_intent_digest ${signedBootFinalizerPlan}/plan.json)" \
          --arg boot_image_digest \
            "$(jq -r .boot_image_digest ${signedBootFinalizerPlan}/plan.json)" \
          --argjson boot_image_size_bytes \
            "$(jq -r .boot_image_size_bytes ${signedBootFinalizerPlan}/plan.json)" \
          --arg boot_signature_digest "$boot_signature_digest" \
          --argjson boot_signature_size_bytes "$boot_signature_size" \
          --arg public_key_fingerprint \
            "$(jq -r .public_key_fingerprint ${signedBootFinalizerPlan}/plan.json)" \
          --arg signer_policy_digest \
            "$(jq -r .signer_policy_digest ${signedBootFinalizerPlan}/plan.json)" \
          --arg gate_receipt_digest \
            'sha256:eced6ea3c3a42c7a0ee24e6cabf6338536e106faee65f5e2627ac55cbcd3ccb2' \
          --argjson source_date_epoch \
            "$(jq -r .source_date_epoch ${signedBootFinalizerPlan}/plan.json)" \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $release_intent_digest,
            boot_image_digest: $boot_image_digest,
            boot_image_size_bytes: $boot_image_size_bytes,
            boot_signature_digest: $boot_signature_digest,
            boot_signature_size_bytes: $boot_signature_size_bytes,
            public_key_fingerprint: $public_key_fingerprint,
            signer_policy_digest: $signer_policy_digest,
            gate_receipt_digest: $gate_receipt_digest,
            source_date_epoch: $source_date_epoch
          }' > "$out/signing-result.json"
        chmod 0444 "$out/signing-result.json"
      '';
  signedBootFinalizerHSMWrapper = pkgs.writeShellScript "kaiba-signed-boot-finalizer-hsm-wrapper" ''
    set -euo pipefail
    test "$#" -eq 3
    test "$1" = '-a'
    test "$2" = 'rsa2048-sha256'
    test -f "$3"
    sed -n 's/^rsa2048: //p' ${./fixtures/signed-boot-finalizer/boot.sig}
  '';
  verifiedSignedBootFixture = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-rpi5-verified-signed-boot-fixture";
    signingPlan = signedBootFinalizerPlan;
    signedOutput = signedBootFinalizerSignedOutput;
  };
  # Reuse the fixture-only deterministic key below so the unfused capsule's
  # signature is regenerated for the current secureBootFixtureA instead of
  # depending on a checked-in signature for an obsolete boot image.  The
  # public-key fingerprint and customer-key hash remain derived and checked
  # by productionMediaFixturePublicKey.
  unfusedCapsulePublicKey = productionMediaFixturePublicKey;
  unfusedCapsulePublicKeyFingerprint = productionMediaFixturePublicKeyFingerprint;
  unfusedCapsuleCustomerKeyHash = productionMediaFixtureCustomerKeyHash;
  unfusedCapsuleReleaseIntent = mkTestReleaseIntent {
    name = "kaiba-rpi5-unfused-capsule-release-intent";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    releaseID = "release:rpi5-unfused-capsule-fixture:1";
    publicKeyFingerprint = unfusedCapsulePublicKeyFingerprint;
    expectedCustomerKeyHash = "sha256:${unfusedCapsuleCustomerKeyHash}";
    signerPolicyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    sourceDateEpoch = 1786968000;
  };
  unfusedCapsuleSigningPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-unfused-capsule-signing-plan-fixture";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    planID = "plan:rpi5-unfused-capsule-fixture:1";
    publicKeyFingerprint = unfusedCapsulePublicKeyFingerprint;
    releaseIntent = unfusedCapsuleReleaseIntent;
    reviewedPublicKeyPEM = unfusedCapsulePublicKey;
    signerPolicyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    sourceDateEpoch = 1786968000;
  };
  unfusedCapsuleSignedOutput =
    pkgs.runCommand "kaiba-rpi5-unfused-capsule-signing-output-fixture"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        cmp "$TMPDIR/public.pem" ${unfusedCapsulePublicKey}

        mkdir "$out"
        readonly boot=${secureBootFixtureA}/unsigned/boot.img
        readonly plan=${unfusedCapsuleSigningPlan}/plan.json
        readonly image_digest="$(sha256sum "$boot" | cut -d ' ' -f 1)"
        readonly source_date_epoch="$(jq -er .source_date_epoch "$plan")"
        openssl dgst -sha256 -sign "$TMPDIR/private.pem" "$boot" \
          > "$TMPDIR/signature.bin"
        test "$(stat --format=%s "$TMPDIR/signature.bin")" -eq 256
        printf '%s\nts: %s\nrsa2048: %s\n' \
          "$image_digest" \
          "$source_date_epoch" \
          "$(xxd -p -c 4096 "$TMPDIR/signature.bin")" \
          > "$out/boot.sig"
        canonical_plan="$(cat ${unfusedCapsuleSigningPlan}/plan.json)"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-boot-signing-plan.v1alpha2'
          printf '%s' "$canonical_plan"
        } | sha256sum | cut -d ' ' -f 1)"
        boot_signature_digest="sha256:$(
          sha256sum "$out/boot.sig" | cut -d ' ' -f 1
        )"
        boot_signature_size="$(stat --format=%s "$out/boot.sig")"

        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'kaiba.provisioning.rpi5-boot-signing-result/v1alpha2' \
          --arg plan_id \
            "$(jq -r .plan_id ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg plan_digest "$plan_digest" \
          --arg release_intent_digest \
            "$(jq -r .release_intent_digest ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg boot_image_digest \
            "$(jq -r .boot_image_digest ${unfusedCapsuleSigningPlan}/plan.json)" \
          --argjson boot_image_size_bytes \
            "$(jq -r .boot_image_size_bytes ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg boot_signature_digest "$boot_signature_digest" \
          --argjson boot_signature_size_bytes "$boot_signature_size" \
          --arg public_key_fingerprint \
            "$(jq -r .public_key_fingerprint ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg signer_policy_digest \
            "$(jq -r .signer_policy_digest ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg gate_receipt_digest \
            'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
          --argjson source_date_epoch \
            "$(jq -r .source_date_epoch ${unfusedCapsuleSigningPlan}/plan.json)" \
          '{
            schema_version: $schema_version,
            plan_id: $plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $release_intent_digest,
            boot_image_digest: $boot_image_digest,
            boot_image_size_bytes: $boot_image_size_bytes,
            boot_signature_digest: $boot_signature_digest,
            boot_signature_size_bytes: $boot_signature_size_bytes,
            public_key_fingerprint: $public_key_fingerprint,
            signer_policy_digest: $signer_policy_digest,
            gate_receipt_digest: $gate_receipt_digest,
            source_date_epoch: $source_date_epoch
          }' > "$out/signing-result.json"
        chmod 0444 "$out/boot.sig" "$out/signing-result.json"
      '';
  unfusedCapsuleVerifiedSignedBoot = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-rpi5-unfused-capsule-verified-signed-boot-fixture";
    signingPlan = unfusedCapsuleSigningPlan;
    signedOutput = unfusedCapsuleSignedOutput;
  };
  verifiedUnfusedCapsuleFixture = built.mkRpi5VerifiedUnfusedCapsule {
    name = "kaiba-rpi5-verified-unfused-capsule-fixture";
    capsuleID = "capsule:rpi5-unfused-fixture:1";
    fixtureID = "fixture:rpi5-unfused-fixture:synthetic:1";
    trustedPublicKeyFingerprint = unfusedCapsulePublicKeyFingerprint;
    unsignedArtifacts = secureBootFixtureA;
    verifiedSignedBoot = unfusedCapsuleVerifiedSignedBoot;
  };
  mediaStagingFixture = built.mkRpi5MediaStagingFixture {
    name = "kaiba-rpi5-media-staging-fixture";
    verifiedCapsule = verifiedUnfusedCapsuleFixture;
  };
  productionMediaFixtureCustomerKeyHash = "75889a936354d53b58be5584e94825fde88671207d374eb6b7611861d13dc9ef";
  productionMediaFixturePublicKeyFingerprint = "sha256:649339461d2755f68c7e72104b9b9ba3d3643c2dae7d9712f2c81a6d44a5c202";
  productionMediaFixtureSignerPolicyDigest = "sha256:49ea92765d4c21f6e86c193115e32d2819ca4249465de329f56d460af20e0406";
  productionMediaFixturePublicKey =
    pkgs.runCommand "kaiba-production-media-fixture-public.pem"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -check -noout
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        test "sha256:$(openssl pkey -pubin -in "$TMPDIR/public.pem" -outform DER \
          | sha256sum | cut -d ' ' -f 1)" = \
          '${productionMediaFixturePublicKeyFingerprint}'
        openssl rsa -pubin -in "$TMPDIR/public.pem" -modulus -noout \
          | cut -d= -f2 | xxd -r -p | xxd -p -c1 | tac | xxd -r -p \
          > "$TMPDIR/customer-key.bin"
        printf '\001\000\001\000\000\000\000\000' >> "$TMPDIR/customer-key.bin"
        test "$(stat --format=%s "$TMPDIR/customer-key.bin")" -eq 264
        test "$(sha256sum "$TMPDIR/customer-key.bin" | cut -d ' ' -f 1)" = \
          '${productionMediaFixtureCustomerKeyHash}'
        install -m 0444 "$TMPDIR/public.pem" "$out"
      '';
  productionMediaFixtureFirmware = pkgs.runCommand "kaiba-production-media-fixture-firmware" { } ''
    set -euo pipefail
    mkdir -p "$out/nixos/default/overlays"
    printf '%s\n' 'boot_ramdisk=1' > "$out/config.txt"
    printf '%s\n' 'fixture production device tree' \
      > "$out/nixos/default/bcm2712-rpi-5-b.dtb"
    printf '%s\n' 'console=serial0,115200' \
      > "$out/nixos/default/cmdline.txt"
    printf '%s\n' 'fixture production initrd' > "$out/nixos/default/initrd"
    printf '%s\n' 'fixture production kernel' > "$out/nixos/default/kernel.img"
    printf '%s\n' 'fixture production overlay sentinel' \
      > "$out/nixos/default/overlays/README"
    printf '%s\n' 'fixture BCM2712 D0 correction overlay' \
      > "$out/nixos/default/overlays/bcm2712d0.dtbo"
    printf '%s\n' 'fixture firmware overlay-name map' \
      > "$out/nixos/default/overlays/overlay_map.dtb"
  '';
  productionMediaUnsignedArtifacts = secureBootArtifactBuilder {
    name = "kaiba-production-media-unsigned-artifacts-fixture";
    bootCommandLinePath = "nixos/default/cmdline.txt";
    expectedCustomerKeyHash = productionMediaFixtureCustomerKeyHash;
    firmwareAllowlist = [
      "config.txt"
      "nixos/default/bcm2712-rpi-5-b.dtb"
      "nixos/default/cmdline.txt"
      "nixos/default/initrd"
      "nixos/default/kernel.img"
      "nixos/default/overlays/README"
      "nixos/default/overlays/bcm2712d0.dtbo"
      "nixos/default/overlays/overlay_map.dtb"
    ];
    firmwareTree = productionMediaFixtureFirmware;
    rootImage = secureBootFixtureRootA;
    rootDataPartitionGUID = secureBootRootDataPartitionGUID;
    rootHashPartitionGUID = secureBootRootHashPartitionGUID;
    sourceRevision = canonicalSourceRevision40;
  };
  productionMediaReleaseIntent = built.mkRpi5ReleaseIntent {
    name = "kaiba-production-media-release-intent-fixture";
    releaseID = "release:rpi5-production-media-fixture:1";
    bootImage = "${productionMediaUnsignedArtifacts}/unsigned/boot.img";
    eepromBootcodeSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-bootcode.signing-input";
    eepromBootsysSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-bootsys.signing-input";
    eepromConfigSigningInput = "${eepromReleaseSigningInputsFixture}/eeprom-config.signing-input";
    eepromRelease = built.rpi5EEPROMRelease;
    ownedRecoveryBootcodeSigningInput = "${eepromReleaseSigningInputsFixture}/owned-recovery-bootcode.signing-input";
    expectedCustomerKeyHash = "sha256:${productionMediaFixtureCustomerKeyHash}";
    publicKeyFingerprint = productionMediaFixturePublicKeyFingerprint;
    signerPolicyDigest = productionMediaFixtureSignerPolicyDigest;
    sourceDateEpoch = 1786968000;
    sourceRevision = canonicalSourceRevision40;
    unsignedArtifacts = productionMediaUnsignedArtifacts;
  };
  productionMediaSigningReceiptEvidence =
    pkgs.runCommand "kaiba-production-media-authenticated-signing-receipts-fixture"
      {
        nativeBuildInputs = [
          pkgs.findutils
          pkgs.go
          pkgs.jq
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        export LC_ALL=C

        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        cd ${built.goSource}
        go run ./internal/provisioning/signingreceipts/testfixture \
          --release-intent ${productionMediaReleaseIntent}/release-intent.json \
          --private-key "$TMPDIR/private.pem" \
          --artifact rpi5.boot_image=${productionMediaUnsignedArtifacts}/unsigned/boot.img \
          --artifact rpi5.eeprom_bootcode=${eepromReleaseSigningInputsFixture}/eeprom-bootcode.signing-input \
          --artifact rpi5.eeprom_bootsys=${eepromReleaseSigningInputsFixture}/eeprom-bootsys.signing-input \
          --artifact rpi5.eeprom_config=${eepromReleaseSigningInputsFixture}/eeprom-config.signing-input \
          --artifact rpi5.owned_recovery_bootcode=${eepromReleaseSigningInputsFixture}/owned-recovery-bootcode.signing-input \
          --output "$out"

        test "$(find "$out" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)" = \
          $'approval.json\npublic.pem\nreceipt-digests.json\nsigning-grants.json\nsigning-receipts.json'
        cmp "$out/public.pem" ${productionMediaFixturePublicKey}
        test "$(jq -r 'length' "$out/receipt-digests.json")" -eq 5
        test "$(jq -r '[.[].receipt_digest] | unique | length' \
          "$out/receipt-digests.json")" -eq 5
      '';
  productionMediaBootSigningPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-production-media-boot-signing-plan-fixture";
    bootImage = "${productionMediaUnsignedArtifacts}/unsigned/boot.img";
    planID = "plan:rpi5-production-media-boot-fixture:1";
    publicKeyFingerprint = productionMediaFixturePublicKeyFingerprint;
    releaseIntent = productionMediaReleaseIntent;
    reviewedPublicKeyPEM = productionMediaFixturePublicKey;
    signerPolicyDigest = productionMediaFixtureSignerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  productionMediaBootSignedOutput =
    pkgs.runCommand "kaiba-production-media-boot-signed-output-fixture"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        cmp "$TMPDIR/public.pem" ${productionMediaFixturePublicKey}
        mkdir "$out"
        readonly boot=${productionMediaUnsignedArtifacts}/unsigned/boot.img
        readonly image_digest="$(sha256sum "$boot" | cut -d ' ' -f 1)"
        openssl dgst -sha256 -sign "$TMPDIR/private.pem" "$boot" \
          > "$TMPDIR/signature.bin"
        test "$(stat --format=%s "$TMPDIR/signature.bin")" -eq 256
        printf '%s\nts: 1786968000\nrsa2048: %s\n' \
          "$image_digest" "$(xxd -p -c 4096 "$TMPDIR/signature.bin")" \
          > "$out/boot.sig"
        readonly plan=${productionMediaBootSigningPlan}/plan.json
        readonly plan_json="$(cat "$plan")"
        readonly plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-boot-signing-plan.v1alpha2'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq -cn \
          --arg plan_digest "$plan_digest" \
          --argjson plan "$plan_json" \
          --arg signature_digest "sha256:$(sha256sum "$out/boot.sig" | cut -d ' ' -f 1)" \
          --argjson signature_size "$(stat --format=%s "$out/boot.sig")" \
          --arg gate_receipt_digest "$(jq -er \
            '.[] | select(.role == "rpi5.boot_image") | .receipt_digest' \
            ${productionMediaSigningReceiptEvidence}/receipt-digests.json)" \
          '{
            schema_version: "kaiba.provisioning.rpi5-boot-signing-result/v1alpha2",
            plan_id: $plan.plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $plan.release_intent_digest,
            boot_image_digest: $plan.boot_image_digest,
            boot_image_size_bytes: $plan.boot_image_size_bytes,
            boot_signature_digest: $signature_digest,
            boot_signature_size_bytes: $signature_size,
            public_key_fingerprint: $plan.public_key_fingerprint,
            signer_policy_digest: $plan.signer_policy_digest,
            gate_receipt_digest: $gate_receipt_digest,
            source_date_epoch: $plan.source_date_epoch
          }' > "$out/signing-result.json"
        chmod 0444 "$out/boot.sig" "$out/signing-result.json"
      '';
  productionMediaVerifiedSignedBoot = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-production-media-verified-signed-boot-fixture";
    signingPlan = productionMediaBootSigningPlan;
    signedOutput = productionMediaBootSignedOutput;
  };
  productionMediaEEPROMSigningPlan = built.mkRpi5EEPROMSigningPlan {
    name = "kaiba-production-media-eeprom-signing-plan-fixture";
    planID = "plan:rpi5-production-media-eeprom-fixture:1";
    bootConfig = ../../provisioning/config/rpi5-prototype-eeprom/boot.conf;
    customerKeyHash = "sha256:${productionMediaFixtureCustomerKeyHash}";
    eepromSigningInputs = eepromReleaseSigningInputsFixture;
    publicKeyFingerprint = productionMediaFixturePublicKeyFingerprint;
    releaseIntent = productionMediaReleaseIntent;
    reviewedPublicKeyPEM = productionMediaFixturePublicKey;
    signerPolicyDigest = productionMediaFixtureSignerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  productionMediaFixtureHSM = pkgs.writeShellScript "kaiba-production-media-fixture-hsm" ''
    set -euo pipefail
    test "$#" -eq 3
    test "$1" = '-a'
    test "$2" = 'rsa2048-sha256'
    test -f "$3"
    test -f "$KAIBA_TEST_PRIVATE_KEY"
    test -d "$KAIBA_TEST_SIGNATURE_DIR"
    readonly counter_file="$KAIBA_TEST_SIGNATURE_DIR/counter"
    counter=0
    if test -f "$counter_file"; then
      counter="$(cat "$counter_file")"
    fi
    printf '%s\n' "sha256:$(${pkgs.coreutils}/bin/sha256sum "$3" | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)" \
      >> "$KAIBA_TEST_SIGNATURE_DIR/callbacks"
    ${pkgs.openssl}/bin/openssl dgst -sha256 -sign "$KAIBA_TEST_PRIVATE_KEY" "$3" \
      > "$KAIBA_TEST_SIGNATURE_DIR/signature-$counter.bin"
    printf '%s\n' "$((counter + 1))" > "$counter_file"
    ${pkgs.xxd}/bin/xxd -c 4096 -p "$KAIBA_TEST_SIGNATURE_DIR/signature-$counter.bin"
  '';
  productionMediaEEPROMSignedOutput =
    pkgs.runCommand "kaiba-production-media-eeprom-signed-output-fixture"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export SOURCE_DATE_EPOCH=1786968000
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        cmp "$TMPDIR/public.pem" ${productionMediaFixturePublicKey}
        readonly plan=${productionMediaEEPROMSigningPlan}
        readonly work="$TMPDIR/updater"
        export KAIBA_TEST_PRIVATE_KEY="$TMPDIR/private.pem"
        export KAIBA_TEST_SIGNATURE_DIR="$TMPDIR/signatures"
        mkdir -m 0700 "$work" "$KAIBA_TEST_SIGNATURE_DIR"
        install -m 0600 "$plan/pieeprom.original.bin" "$work/pieeprom.original.bin"
        install -m 0600 "$plan/recovery.original.bin" "$work/recovery.original.bin"
        install -m 0600 "$plan/boot.conf" "$work/boot.conf"
        install -m 0600 "$plan/public.pem" "$work/public.pem"
        : > "$KAIBA_TEST_SIGNATURE_DIR/callbacks"
        (
          cd "$work"
          PATH=${lib.escapeShellArg built.eepromSigningTool.kaibaEEPROMSigningTool.toolPATH} \
            ${built.eepromToolRuntime}/bin/update-pieeprom.sh \
              -f -c boot.conf -i pieeprom.original.bin -o pieeprom.bin \
              -p public.pem -H ${productionMediaFixtureHSM}
        )
        jq -r '.signing_inputs[].digest' "$plan/plan.json" \
          > "$TMPDIR/expected-callbacks"
        cmp "$TMPDIR/expected-callbacks" "$KAIBA_TEST_SIGNATURE_DIR/callbacks"
        test "$(cat "$KAIBA_TEST_SIGNATURE_DIR/counter")" -eq 3
        mkdir "$out"
        install -m 0444 "$work/pieeprom.bin" "$out/pieeprom.bin"
        install -m 0444 "$work/pieeprom.sig" "$out/pieeprom.sig"
        install -m 0444 "$work/bootcode5.bin" "$out/bootcode5.bin"
        file_record() {
          jq -cjn \
            --arg digest "sha256:$(sha256sum "$1" | cut -d ' ' -f 1)" \
            --argjson size "$(stat --format=%s "$1")" \
            '{digest: $digest, size_bytes: $size}'
        }
        readonly plan_json="$(cat "$plan/plan.json")"
        readonly plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        readonly signatures="$(jq -c \
          --arg sig0 "sha256:$(sha256sum "$KAIBA_TEST_SIGNATURE_DIR/signature-0.bin" | cut -d ' ' -f 1)" \
          --arg sig1 "sha256:$(sha256sum "$KAIBA_TEST_SIGNATURE_DIR/signature-1.bin" | cut -d ' ' -f 1)" \
          --arg sig2 "sha256:$(sha256sum "$KAIBA_TEST_SIGNATURE_DIR/signature-2.bin" | cut -d ' ' -f 1)" \
          --arg receipt0 "$(jq -er \
            '.[] | select(.role == "rpi5.eeprom_bootcode") | .receipt_digest' \
            ${productionMediaSigningReceiptEvidence}/receipt-digests.json)" \
          --arg receipt1 "$(jq -er \
            '.[] | select(.role == "rpi5.eeprom_bootsys") | .receipt_digest' \
            ${productionMediaSigningReceiptEvidence}/receipt-digests.json)" \
          --arg receipt2 "$(jq -er \
            '.[] | select(.role == "rpi5.eeprom_config") | .receipt_digest' \
            ${productionMediaSigningReceiptEvidence}/receipt-digests.json)" \
          '.signing_inputs | to_entries | map({
            role: .value.role,
            input_digest: .value.digest,
            input_size_bytes: .value.size_bytes,
            signature_digest: ([$sig0, $sig1, $sig2][.key]),
            signature_size_bytes: 256,
            gate_receipt_digest: ([$receipt0, $receipt1, $receipt2][.key])
          })' "$plan/plan.json")"
        jq -cn \
          --arg plan_digest "$plan_digest" \
          --argjson plan "$plan_json" \
          --argjson signatures "$signatures" \
          --argjson signed_eeprom "$(file_record "$out/pieeprom.bin")" \
          --argjson metadata "$(file_record "$out/pieeprom.sig")" \
          --argjson recovery "$(file_record "$out/bootcode5.bin")" \
          '{
            schema_version: "kaiba.provisioning.rpi5-eeprom-signing-result/v1alpha1",
            plan_id: $plan.plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $plan.release_intent_digest,
            eeprom_release_manifest_digest: $plan.eeprom_release_manifest_digest,
            signer_policy_digest: $plan.signer_policy_digest,
            public_key_fingerprint: $plan.public_key_fingerprint,
            customer_key_hash: $plan.customer_key_hash,
            source_date_epoch: $plan.source_date_epoch,
            updater_mode: "fresh-board",
            recovery_mode: "unsigned-copy",
            signatures: $signatures,
            signed_eeprom: $signed_eeprom,
            eeprom_update_metadata: $metadata,
            fresh_recovery_bootcode: $recovery
          }' > "$out/result.json"
        chmod 0444 "$out/result.json"
      '';
  productionMediaVerifiedSignedEEPROM = built.mkRpi5VerifiedSignedEEPROM {
    name = "kaiba-production-media-verified-signed-eeprom-fixture";
    signingPlan = productionMediaEEPROMSigningPlan;
    signedOutput = productionMediaEEPROMSignedOutput;
  };
  productionMediaOwnedRecoveryPlan = built.mkRpi5OwnedRecoverySigningPlan {
    name = "kaiba-production-media-owned-recovery-plan-fixture";
    planID = "plan:rpi5-production-media-owned-recovery-fixture:1";
    freshSigningPlan = productionMediaEEPROMSigningPlan;
    verifiedSignedEEPROM = productionMediaVerifiedSignedEEPROM;
  };
  productionMediaOwnedRecoverySignedOutput =
    pkgs.runCommand "kaiba-production-media-owned-recovery-signed-output-fixture"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export SOURCE_DATE_EPOCH=1786968000
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        cmp "$TMPDIR/public.pem" ${productionMediaFixturePublicKey}
        readonly plan=${productionMediaOwnedRecoveryPlan}
        readonly work="$TMPDIR/updater"
        export KAIBA_TEST_PRIVATE_KEY="$TMPDIR/private.pem"
        export KAIBA_TEST_SIGNATURE_DIR="$TMPDIR/signatures"
        mkdir -m 0700 "$work" "$KAIBA_TEST_SIGNATURE_DIR"
        install -m 0600 "$plan/pieeprom.original.bin" "$work/pieeprom.original.bin"
        install -m 0600 "$plan/recovery.original.bin" "$work/recovery.original.bin"
        install -m 0600 "$plan/boot.conf" "$work/boot.conf"
        install -m 0600 "$plan/public.pem" "$work/public.pem"
        : > "$KAIBA_TEST_SIGNATURE_DIR/callbacks"
        (
          cd "$work"
          PATH=${lib.escapeShellArg built.eepromSigningTool.kaibaEEPROMSigningTool.toolPATH} \
            ${built.eepromToolRuntime}/bin/update-pieeprom.sh \
              -f -r -c boot.conf -i pieeprom.original.bin -o pieeprom.bin \
              -p public.pem -H ${productionMediaFixtureHSM}
        )
        {
          jq -r .owned_recovery_signing_input.digest "$plan/plan.json"
          jq -r '.fresh_eeprom_plan.signing_inputs[].digest' "$plan/plan.json"
        } > "$TMPDIR/expected-callbacks"
        cmp "$TMPDIR/expected-callbacks" "$KAIBA_TEST_SIGNATURE_DIR/callbacks"
        test "$(cat "$KAIBA_TEST_SIGNATURE_DIR/counter")" -eq 4
        mkdir "$out"
        install -m 0444 "$work/pieeprom.bin" "$out/pieeprom.bin"
        install -m 0444 "$work/pieeprom.sig" "$out/pieeprom.sig"
        install -m 0444 "$work/bootcode5.bin" "$out/bootcode5.bin"
        cmp "$out/pieeprom.bin" ${productionMediaVerifiedSignedEEPROM}/pieeprom.bin
        cmp "$out/pieeprom.sig" ${productionMediaVerifiedSignedEEPROM}/pieeprom.sig
        file_record() {
          jq -cjn \
            --arg digest "sha256:$(sha256sum "$1" | cut -d ' ' -f 1)" \
            --argjson size "$(stat --format=%s "$1")" \
            '{digest: $digest, size_bytes: $size}'
        }
        readonly plan_json="$(cat "$plan/plan.json")"
        readonly plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-owned-recovery-signing-plan.v1alpha1'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq -cn \
          --arg plan_digest "$plan_digest" \
          --argjson plan "$plan_json" \
          --arg signature_digest "sha256:$(sha256sum "$KAIBA_TEST_SIGNATURE_DIR/signature-0.bin" | cut -d ' ' -f 1)" \
          --arg gate_receipt_digest "$(jq -er \
            '.[] | select(.role == "rpi5.owned_recovery_bootcode") | .receipt_digest' \
            ${productionMediaSigningReceiptEvidence}/receipt-digests.json)" \
          --argjson recovery "$(file_record "$out/bootcode5.bin")" \
          --argjson eeprom "$(file_record "$out/pieeprom.bin")" \
          --argjson metadata "$(file_record "$out/pieeprom.sig")" \
          '{
            schema_version: "kaiba.provisioning.rpi5-owned-recovery-signing-result/v1alpha1",
            plan_id: $plan.plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $plan.fresh_eeprom_plan.release_intent_digest,
            eeprom_release_manifest_digest: $plan.fresh_eeprom_plan.eeprom_release_manifest_digest,
            signer_policy_digest: $plan.fresh_eeprom_plan.signer_policy_digest,
            public_key_fingerprint: $plan.fresh_eeprom_plan.public_key_fingerprint,
            customer_key_hash: $plan.fresh_eeprom_plan.customer_key_hash,
            source_date_epoch: $plan.fresh_eeprom_plan.source_date_epoch,
            updater_mode: "owned-recovery",
            recovery_mode: "customer-counter-signed",
            signature: {
              role: $plan.owned_recovery_signing_input.role,
              input_digest: $plan.owned_recovery_signing_input.digest,
              input_size_bytes: $plan.owned_recovery_signing_input.size_bytes,
              signature_digest: $signature_digest,
              signature_size_bytes: 256,
              gate_receipt_digest: $gate_receipt_digest
            },
            owned_recovery_bootcode: $recovery,
            replayed_signed_eeprom: $eeprom,
            replayed_eeprom_update_metadata: $metadata
          }' > "$out/result.json"
        chmod 0444 "$out/result.json"
      '';
  productionMediaVerifiedOwnedRecovery = built.mkRpi5VerifiedOwnedRecovery {
    name = "kaiba-production-media-verified-owned-recovery-fixture";
    signingPlan = productionMediaOwnedRecoveryPlan;
    signedOutput = productionMediaOwnedRecoverySignedOutput;
  };
  productionMediaRPIBootBundles = built.mkRpi5VerifiedRPIBootBundles {
    name = "kaiba-production-media-rpiboot-bundles-fixture";
    unsignedArtifacts = productionMediaUnsignedArtifacts;
    verifiedOwnedRecovery = productionMediaVerifiedOwnedRecovery;
    verifiedSignedBoot = productionMediaVerifiedSignedBoot;
    verifiedSignedEEPROM = productionMediaVerifiedSignedEEPROM;
  };
  productionMediaRootIntegrity =
    pkgs.runCommand "kaiba-production-media-root-integrity-fixture.json"
      { nativeBuildInputs = [ pkgs.mtools ]; }
      ''
        mtype -i ${productionMediaUnsignedArtifacts}/unsigned/boot.img \
          ::kaiba-root-integrity.json > "$out"
        chmod 0444 "$out"
      '';
  productionMediaPlatformAdapter = pkgs.writeText "kaiba-production-media-platform-adapter-fixture" ''
    immutable Raspberry Pi 5 production-media platform adapter fixture
  '';
  productionMediaSigningReceiptVerification = built.mkRpi5VerifiedSigningReceipts {
    name = "kaiba-production-media-signing-receipt-verification.json";
    reviewedPublicKeyPEM = productionMediaFixturePublicKey;
    signingGrantRegistry = "${productionMediaSigningReceiptEvidence}/signing-grants.json";
    signingReceiptExport = "${productionMediaSigningReceiptEvidence}/signing-receipts.json";
    verifiedOwnedRecovery = productionMediaVerifiedOwnedRecovery;
    verifiedSignedBoot = productionMediaVerifiedSignedBoot;
    verifiedSignedEEPROM = productionMediaVerifiedSignedEEPROM;
  };
  productionMediaSignedReleaseFixture = built.mkRpi5VerifiedSignedRelease {
    name = "kaiba-production-media-verified-signed-release-fixture";
    deviceProfile = ../../provisioning/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json;
    eepromRelease = built.rpi5EEPROMRelease;
    platformAdapter = productionMediaPlatformAdapter;
    rootIntegrity = productionMediaRootIntegrity;
    signingReceiptVerification = productionMediaSigningReceiptVerification;
    unsignedArtifacts = productionMediaUnsignedArtifacts;
    verifiedOwnedRecovery = productionMediaVerifiedOwnedRecovery;
    verifiedRPIBootBundles = productionMediaRPIBootBundles;
    verifiedSignedBoot = productionMediaVerifiedSignedBoot;
    verifiedSignedEEPROM = productionMediaVerifiedSignedEEPROM;
  };
  productionMediaTarget = {
    logicalSectorSizeBytes = 512;
    sizeBytes = 268435456;
  };
  productionMediaHardwareConfiguration =
    hardwareConfigurations.malakRaspberryPi5SacrificialDevelopmentUsbSd;
  productionMediaAlternateHardwareConfiguration =
    hardwareConfigurations.raspberryPi5SacrificialDevelopmentPiLocalNvme;
  productionMediaFixture = built.mkRpi5ProductionMedia {
    name = "kaiba-rpi5-production-media-fixture";
    verifiedSignedRelease = productionMediaSignedReleaseFixture;
    transactionID = "transaction:rpi5-media-fixture:1";
    target = productionMediaTarget;
    hardwareConfiguration = productionMediaHardwareConfiguration;
  };
  productionMediaAlternateHardwareFixture = built.mkRpi5ProductionMedia {
    name = "kaiba-rpi5-production-media-fixture";
    verifiedSignedRelease = productionMediaSignedReleaseFixture;
    transactionID = "transaction:rpi5-media-fixture:1";
    target = productionMediaTarget;
    hardwareConfiguration = productionMediaAlternateHardwareConfiguration;
  };
  productionMediaDeterminismFixture = built.mkRpi5ProductionMedia {
    name = "kaiba-rpi5-production-media-determinism-fixture";
    verifiedSignedRelease = productionMediaSignedReleaseFixture;
    transactionID = "transaction:rpi5-media-fixture:1";
    target = productionMediaTarget;
    hardwareConfiguration = productionMediaHardwareConfiguration;
  };
  productionMediaAlternatePlanFixture = built.mkRpi5ProductionMedia {
    name = "kaiba-rpi5-production-media-alternate-plan-fixture";
    verifiedSignedRelease = productionMediaSignedReleaseFixture;
    transactionID = "transaction:rpi5-media-alternate:1";
    target = productionMediaTarget;
    hardwareConfiguration = productionMediaHardwareConfiguration;
  };
  spoofedSignedRelease =
    pkgs.runCommand "kaiba-spoofed-signed-release"
      {
        passthru.kaibaVerifiedSignedRelease =
          productionMediaSignedReleaseFixture.kaibaVerifiedSignedRelease
          // {
            artifactRoleCount = 17;
          };
      }
      ''
        mkdir "$out"
      '';
  productionMediaInputAccepted =
    verifiedSignedRelease:
    (builtins.tryEval (
      (built.mkRpi5ProductionMedia {
        name = "kaiba-rpi5-production-media-input-evaluation";
        inherit verifiedSignedRelease;
        transactionID = "transaction:rpi5-media-fixture:1";
        target = productionMediaTarget;
        hardwareConfiguration = productionMediaHardwareConfiguration;
      }).drvPath
    )).success;
  productionMediaTargetInputAccepted =
    targetOverrides:
    (builtins.tryEval (
      (built.mkRpi5ProductionMedia {
        name = "kaiba-rpi5-production-media-target-input-evaluation";
        verifiedSignedRelease = productionMediaSignedReleaseFixture;
        transactionID = "transaction:rpi5-media-fixture:1";
        target = productionMediaTarget // targetOverrides;
        hardwareConfiguration = productionMediaHardwareConfiguration;
      }).drvPath
    )).success;
  productionMediaHardwareConfigurationInputAccepted =
    hardwareConfiguration:
    (builtins.tryEval (
      (built.mkRpi5ProductionMedia {
        name = "kaiba-rpi5-production-media-hardware-configuration-input-evaluation";
        verifiedSignedRelease = productionMediaSignedReleaseFixture;
        transactionID = "transaction:rpi5-media-fixture:1";
        target = productionMediaTarget;
        inherit hardwareConfiguration;
      }).drvPath
    )).success;
  verifiedUnfusedCapsuleInputAccepted =
    overrides:
    (builtins.tryEval (
      (built.mkRpi5VerifiedUnfusedCapsule (
        {
          name = "kaiba-rpi5-verified-unfused-capsule-evaluation";
          capsuleID = "capsule:rpi5-unfused-fixture:1";
          fixtureID = "fixture:rpi5-unfused-fixture:synthetic:1";
          trustedPublicKeyFingerprint = unfusedCapsulePublicKeyFingerprint;
          unsignedArtifacts = secureBootFixtureA;
          verifiedSignedBoot = unfusedCapsuleVerifiedSignedBoot;
        }
        // overrides
      )).drvPath
    )).success;
  verifiedSignedBootInputAccepted =
    overrides:
    (builtins.tryEval (
      (built.mkRpi5VerifiedSignedBoot (
        {
          name = "kaiba-rpi5-verified-signed-boot-evaluation";
          signingPlan = bootSigningPlanFixture;
          signedOutput = emptySignedOutputFixture;
        }
        // overrides
      )).drvPath
    )).success;
  expectedDevelopmentYubiKeyOpenSSLConfiguration = pkgs.writeText "kaiba-development-yubikey-openssl-expected.cnf" ''
    config_diagnostics = 1
    openssl_conf = kaiba_openssl_init

    [kaiba_openssl_init]
    providers = kaiba_provider_sect

    [kaiba_provider_sect]
    default = kaiba_default_sect
    pkcs11 = kaiba_pkcs11_sect

    [kaiba_default_sect]
    activate = 1

    [kaiba_pkcs11_sect]
    module = ${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so
    pkcs11-module-path = ${pkgs.yubico-piv-tool}/lib/libykcs11.so.${pkgs.yubico-piv-tool.version}
    pkcs11-module-token-pin = file:/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin
    pkcs11-module-cache-keys = false
    pkcs11-module-cache-sessions = 0
    pkcs11-module-login-behavior = always
    activate = 1
  '';

  qualificationProfileName = "raspberry-pi-5-model-b-v1alpha1.json";
  qualificationEvidenceName = "sacrificial-pi-5.json";
  developmentPostureName = "raspberry-pi-5-development-posture-v1alpha1.json";
  developmentPostureEvidencePath = "evidence/provisioning/development-posture/${developmentPostureName}";
  developmentPosturePath = built.goSource + "/policies/${developmentPostureName}";
  developmentPostureSchemaPath =
    built.goSource + "/schemas/rpi5-development-posture-v1alpha1.schema.json";
  developmentPosture = builtins.fromJSON (builtins.readFile developmentPosturePath);
  qualificationProfilePath = built.goSource + "/profiles/device-classes/${qualificationProfileName}";
  qualificationProfile = builtins.fromJSON (builtins.readFile qualificationProfilePath);
  qualificationPolicy = qualificationProfile // {
    metadata = {
      id = qualificationProfile.metadata.id;
    };
  };
  qualificationPolicyDigest = "sha256:${
    builtins.hashString "sha256" (
      "kaiba.device-profile-policy.v1\n" + builtins.toJSON qualificationPolicy
    )
  }";
  qualificationProfileReference = {
    id = qualificationProfile.metadata.id;
    status = qualificationProfile.metadata.status;
    digest = "sha256:${builtins.hashFile "sha256" qualificationProfilePath}";
    policy_digest = qualificationPolicyDigest;
  };
  qualificationAdapterReference = {
    id = qualificationProfile.spec.adapter.id;
    version = qualificationProfile.spec.adapter.version;
  };
  profileReferenceMatches =
    current: recorded:
    recorded == current
    || (
      current.status == "stable"
      && (recorded.id or null) == current.id
      && (recorded.status or null) == "experimental"
      && (recorded.policy_digest or null) == current.policy_digest
    );
  profilePromotionContract =
    let
      candidate = qualificationProfileReference // {
        status = "experimental";
        digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      };
      promoted = candidate // {
        status = "stable";
        digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      };
      changedPolicy = candidate // {
        policy_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      };
    in
    profileReferenceMatches promoted candidate && !profileReferenceMatches promoted changedPolicy;
  qualificationMetadataFields = {
    USER_SERIAL_NUM = "A7EB274C";
    MAC_ADDR = "2C:CF:67:70:76:F3";
    CUSTOMER_KEY_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    BOOT_ROM = "0000000A";
    BOARD_ATTR = "00000000";
    USER_BOARDREV = "B04170";
    JTAG_LOCKED = "0";
    MAC_WIFI_ADDR = "2C:CF:67:70:76:F4";
    MAC_BT_ADDR = "2C:CF:67:70:76:F5";
    FACTORY_UUID = "001000911006186073";
  };
  qualificationMetadata = pkgs.writeText "kaiba-rpi5-qualification-metadata.json" (
    builtins.toJSON qualificationMetadataFields
  );
  qualificationMetadataWithOptionalUpstreamFields =
    pkgs.writeText "kaiba-rpi5-qualification-metadata-with-optional-upstream-fields.json"
      (
        builtins.toJSON (
          qualificationMetadataFields
          // {
            SIGNATURE_MODE = "0";
            ADVANCED_BOOT = "00000000";
          }
        )
      );

  developmentPostureContract =
    assert lib.assertMsg (
      secureBootFixtureA.kaibaUnsignedArtifacts.bootOrderPolicy == developmentPosture.boot_order.policy
    ) "the secure-boot artifact default drifted from the approved development posture";
    pkgs.runCommand "kaiba-rpi5-development-posture-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail

        readonly posture=${developmentPosturePath}
        readonly schema=${developmentPostureSchemaPath}
        readonly boot_config=${../../provisioning/config/rpi5-prototype-eeprom/boot.conf}
        readonly unsigned_manifest=${secureBootFixtureA}/manifest.json

        check-jsonschema --check-metaschema "$schema"
        check-jsonschema --schemafile "$schema" "$posture"

        jq -r '
          [
            "[all]",
            "BOOT_UART=\(.boot_uart.value)",
            "BOOT_ORDER=\(.boot_order.value)",
            "ENABLE_SELF_UPDATE=\(.self_update.value)"
          ][]
        ' "$posture" > "$TMPDIR/expected-boot.conf"
        cmp "$TMPDIR/expected-boot.conf" "$boot_config"

        jq -e '
          .production_ready == false
          and .release_classification == "development_asset"
          and .boot_order.evaluation == "right-to-left"
          and .boot_order.sequence == ["nvme", "sd", "network-tftp", "restart"]
          and .boot_order.production_blocker == true
          and .boot_uart.review_status == "unreviewed-existing-development-setting"
          and .videocore_jtag.policy == "unlocked-development"
          and .videocore_jtag.production_blocker == true
          and .initial_eeprom_update.retry_after_uncertain_result == false
          and .initial_eeprom_update.other_updaters_permitted == false
          and .recovery.bundle_prebuilt_before_ownership == true
          and .recovery.execution_before_ownership_permitted == false
          and .recovery.owned_state_required_for_execution == true
          and .recovery.customer_key_signed == true
          and .recovery.reject_stock == true
          and .recovery.reject_unsigned == true
          and .recovery.reject_wrong_key == true
          and .recovery.reject_altered == true
          and .self_update.automatic_sd_usb_tftp_scan == false
          and .self_update.rpiboot_eeprom_write_still_possible == true
          and .root_integrity.persistent_root == "read-only-dm-verity"
          and .root_integrity.mutable_state == "tmpfs-only"
          and .rollback.policy == "unimplemented-block-enrollment-ready"
          and .rollback.older_correctly_signed_image_may_boot == true
          and .lifecycle.terminal_state == "security_applied"
          and .lifecycle.enrollment_ready == false
          and .lifecycle.authorizes_mutation == false
        ' "$posture" > /dev/null

        jq -e \
          --arg boot_order_policy '${developmentPosture.boot_order.policy}' \
          '
            .boot_order_policy == $boot_order_policy
            and .persistent_mutable_state == "tmpfs-only"
            and .rollback_policy == "unimplemented-block-enrollment-ready"
            and .debug_policy == "videocore-jtag-unlocked-development"
            and .eeprom_write_protection_policy == "unlocked-development"
          ' "$unsigned_manifest" > /dev/null

        install -D -m 0444 "$posture" \
          "$out/${developmentPostureEvidencePath}"
        touch "$out/passed"
      '';

  deviceProfileSchema =
    assert profilePromotionContract;
    pkgs.runCommand "kaiba-device-profile-schema-check"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.jq
        ];
      }
      ''
        set -eu
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/device-profile-v1alpha1.schema.json \
          ${qualificationProfilePath}
        check-jsonschema --check-metaschema \
          ${developmentPostureSchemaPath} \
          ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json
        check-jsonschema --check-metaschema \
          ${built.goSource}/schemas/rpi5-boot-signing-plan-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-boot-signing-result-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-eeprom-signing-plan-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-eeprom-signing-result-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-device-media-layout-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-binding-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-cold-power-observation-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-cold-power-observation-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-device-preflight-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-device-preflight-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-device-preflight-v1alpha3.schema.json \
          ${built.goSource}/schemas/rpi5-media-fixture-result-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-stage-receipt-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-stage-receipt-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-staging-plan-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-staging-plan-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-staging-receipt-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-staging-receipt-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-verification-receipt-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-media-verification-receipt-v1alpha2.schema.json \
          ${built.goSource}/schemas/rpi5-media-verification-report-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-platform-adapter-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-signing-approval-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-unfused-runtime-facts-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-release-intent-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-rpiboot-directory-tree-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha2.schema.json \
          ${built.goSource}/schemas/secure-boot-bundle-v1alpha1.schema.json \
          ${built.goSource}/schemas/signing-grant-registry-v1alpha2.schema.json \
          ${built.goSource}/schemas/signing-gate-receipt-export-v1alpha2.schema.json \
          ${built.goSource}/schemas/signing-gate-receipt-verification-v1alpha2.schema.json \
          ${built.goSource}/schemas/signing-request-v1alpha2.schema.json \
          ${built.goSource}/schemas/signer-independent-review-v1alpha1.schema.json \
          ${built.goSource}/schemas/unsigned-artifact-set-v1alpha1.schema.json \
          ${built.goSource}/schemas/yubikey-signing-policy-v1alpha1.schema.json

        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-platform-adapter-v1alpha1.schema.json \
          ${built.goSource}/config/rpi5-prototype-release/platform-adapter-v1alpha1.json
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/signer-independent-review-v1alpha1.schema.json \
          ${built.goSource}/signers/development-prototype/independent-review-2026-08-27.json

        readonly signing_approval_schema=${built.goSource}/schemas/rpi5-signing-approval-v1alpha1.schema.json
        readonly signing_approval_instance="$TMPDIR/rpi5-signing-approval-valid.json"
        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-signing-approval/v1alpha1",
          approval_id: ("approval:" + ("a" * 64)),
          approval_digest: ("sha256:" + ("a" * 64)),
          decision: "approved",
          reviewer_id: "reviewer:software-only-fixture",
          approved_at: "2026-08-27T12:00:00Z",
          expires_at: "2026-08-27T16:00:00Z",
          release_id: "release:rpi5-software-only-fixture:1",
          source_revision: ("b" * 40),
          release_intent_digest: ("sha256:" + ("b" * 64)),
          signing_inputs: [
            {role: "rpi5.boot_image", digest: ("sha256:" + ("1" * 64)), size_bytes: 4096},
            {role: "rpi5.eeprom_bootcode", digest: ("sha256:" + ("2" * 64)), size_bytes: 4096},
            {role: "rpi5.eeprom_bootsys", digest: ("sha256:" + ("3" * 64)), size_bytes: 4096},
            {role: "rpi5.eeprom_config", digest: ("sha256:" + ("4" * 64)), size_bytes: 4096},
            {role: "rpi5.owned_recovery_bootcode", digest: ("sha256:" + ("5" * 64)), size_bytes: 4096}
          ]
        }' > "$signing_approval_instance"
        check-jsonschema \
          --schemafile "$signing_approval_schema" \
          "$signing_approval_instance"

        readonly signing_receipt_export_schema=${built.goSource}/schemas/signing-gate-receipt-export-v1alpha2.schema.json
        readonly signing_receipt_export_instance="$TMPDIR/signing-gate-receipt-export-valid.json"
        jq -cn '{
          schema_version: "kaiba.provisioning.signing-gate-receipt-export/v1alpha2",
          registry_digest: ("sha256:" + ("6" * 64)),
          release_intent_digest: ("sha256:" + ("b" * 64)),
          public_key_fingerprint: ("sha256:" + ("7" * 64)),
          receipts: [{
            receipt_digest: ("sha256:" + ("8" * 64)),
            receipt: {
              schema_version: "kaiba.provisioning.signing-gate-receipt/v1alpha3",
              grant: {
                schema_version: "kaiba.provisioning.signing-grant/v1alpha2",
                grant_id: "grant:software-only-fixture:1",
                expires_at: "2026-08-27T16:00:00Z",
                request: {
                  schema_version: "kaiba.provisioning.signing-request/v1alpha2",
                  request_id: "request:software-only-fixture:1",
                  algorithm: "rsa2048-sha256",
                  role: "rpi5.boot_image",
                  artifact_digest: ("sha256:" + ("1" * 64)),
                  approval: {
                    approval_id: ("approval:" + ("a" * 64)),
                    approval_digest: ("sha256:" + ("a" * 64)),
                    release_intent_digest: ("sha256:" + ("b" * 64)),
                    role: "rpi5.boot_image",
                    artifact_digest: ("sha256:" + ("1" * 64))
                  }
                }
              },
              request_digest: ("sha256:" + ("9" * 64)),
              backend_id: "backend:software-only-fixture",
              signature_hex: ("ab" * 256),
              signature_digest: ("sha256:" + ("c" * 64)),
              signed_at: "2026-08-27T12:01:00Z",
              attestation_signature_hex: ("cd" * 256),
              attestation_signature_digest: ("sha256:" + ("d" * 64))
            }
          }]
        }' > "$signing_receipt_export_instance"
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile "$signing_receipt_export_schema" \
          "$signing_receipt_export_instance"
        jq 'del(.receipts[0].receipt.attestation_signature_hex)' \
          "$signing_receipt_export_instance" \
          > "$TMPDIR/signing-gate-receipt-export-missing-attestation.json"
        if check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile "$signing_receipt_export_schema" \
          "$TMPDIR/signing-gate-receipt-export-missing-attestation.json" \
          > /dev/null 2>&1
        then
          echo 'receipt export schema accepted a receipt without its attestation signature' >&2
          exit 1
        fi

        readonly media_preflight_schema=${built.goSource}/schemas/rpi5-media-device-preflight-v1alpha3.schema.json
        readonly media_preflight_valid="$TMPDIR/rpi5-media-device-preflight-valid.json"
        readonly media_preflight_invalid="$TMPDIR/rpi5-media-device-preflight-invalid.json"
        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-media-device-preflight/v1alpha3",
          status: "validated_no_write",
          evidence_mode: "device_preflight",
          plan_digest: ("sha256:" + ("a" * 64)),
          target: {
            size_bytes: 8388608,
            logical_sector_size_bytes: 512
          },
          hardware_configuration_id: "hardware-configuration:malak-rpi5-sacrificial-development-usb-sd:1",
          execution_hostname: "malak",
          requested_device_selector: "/dev/disk/by-path/platform-kaiba-fixture",
          resolved_device_path: "/dev/sda",
          attachment_boot_id: "11111111-1111-4111-8111-111111111111",
          attachment_sequence: 1,
          target_whole_device: true,
          target_geometry_verified: true,
          sources_verified: true,
          target_usage_clear: true,
          target_locked: true,
          write_performed: false
        }' > "$media_preflight_valid"
        check-jsonschema \
          --schemafile "$media_preflight_schema" \
          "$media_preflight_valid"
        for mutation in \
          '.unexpected_property = true' \
          '.hardware_configuration_id = "NOT-CANONICAL"' \
          '.execution_hostname = "Malak"' \
          '.requested_device_selector = "/dev/disk/by-id/prohibited"' \
          '.resolved_device_path = "/dev/disk/by-path/prohibited"' \
          'del(.hardware_configuration_id)' \
          '.target.device_path = "/dev/nvme0n1"' \
          '.write_performed = true' \
          '.target_whole_device = false' \
          '.target_geometry_verified = false' \
          '.plan_digest = "sha256:not-canonical"' \
          '.attachment_boot_id = "not-a-guid"'
        do
          jq "$mutation" "$media_preflight_valid" > "$media_preflight_invalid"
          if check-jsonschema \
            --schemafile "$media_preflight_schema" \
            "$media_preflight_invalid" > /dev/null 2>&1
          then
            echo "media preflight schema accepted prohibited mutation: $mutation" >&2
            exit 1
          fi
        done

        readonly media_stage_receipt_schema=${built.goSource}/schemas/rpi5-media-stage-receipt-v1alpha2.schema.json
        readonly media_verification_receipt_schema=${built.goSource}/schemas/rpi5-media-verification-receipt-v1alpha2.schema.json
        readonly media_cold_observation_schema=${built.goSource}/schemas/rpi5-media-cold-power-observation-v1alpha2.schema.json
        readonly media_final_receipt_schema=${built.goSource}/schemas/rpi5-media-staging-receipt-v1alpha2.schema.json
        readonly media_stage_receipt="$TMPDIR/rpi5-media-stage-receipt-valid.json"
        readonly media_verification_receipt="$TMPDIR/rpi5-media-verification-receipt-valid.json"
        readonly media_cold_observation="$TMPDIR/rpi5-media-cold-power-observation-valid.json"
        readonly media_final_receipt="$TMPDIR/rpi5-media-staging-receipt-valid.json"

        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-media-stage-receipt/v1alpha2",
          status: "staged_readback_required",
          transaction_id: "transaction:media-schema:1",
          plan_digest: ("sha256:" + ("a" * 64)),
          signed_release_manifest_digest: ("sha256:" + ("b" * 64)),
          layout_digest: ("sha256:" + ("c" * 64)),
          target: {size_bytes: 8388608, logical_sector_size_bytes: 512},
          attachment_boot_id: "11111111-1111-4111-8111-111111111111",
          attachment_sequence: 1,
          expected_media_digest: ("sha256:" + ("d" * 64)),
          observed_media_digest: ("sha256:" + ("d" * 64)),
          bytes_written: 9437184,
          fsync_complete: true,
          reopened_target: true,
          independent_readback_required: true,
          cold_power_cycle_observed: false,
          one_time_settings_changed: false,
          receipt_digest: ("sha256:" + ("e" * 64))
        }' > "$media_stage_receipt"
        check-jsonschema --schemafile "$media_stage_receipt_schema" "$media_stage_receipt"

        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-media-verification-receipt/v1alpha2",
          status: "full_media_verified",
          verification_mode: "independent_read_only_device",
          transaction_id: "transaction:media-schema:1",
          plan_digest: ("sha256:" + ("a" * 64)),
          stage_receipt_digest: ("sha256:" + ("e" * 64)),
          signed_release_manifest_digest: ("sha256:" + ("b" * 64)),
          layout_digest: ("sha256:" + ("c" * 64)),
          target: {size_bytes: 8388608, logical_sector_size_bytes: 512},
          attachment_boot_id: "22222222-2222-4222-8222-222222222222",
          attachment_sequence: 2,
          full_media_digest: ("sha256:" + ("d" * 64)),
          regions: [
            {role: "primary-gpt", digest: ("sha256:" + ("1" * 64)), verified: true},
            {role: "boot-filesystem", digest: ("sha256:" + ("2" * 64)), verified: true},
            {role: "root-data", digest: ("sha256:" + ("3" * 64)), verified: true},
            {role: "root-hash", digest: ("sha256:" + ("4" * 64)), verified: true},
            {role: "tail-zero", digest: ("sha256:" + ("5" * 64)), verified: true},
            {role: "backup-gpt", digest: ("sha256:" + ("6" * 64)), verified: true}
          ],
          gpt_verified: true,
          fat_verified: true,
          partition_digests_verified: true,
          dm_verity_verified: true,
          boot_signature_verified: true,
          release_lineage_verified: true,
          reopened_target: true,
          cold_power_cycle_observed: false,
          one_time_settings_changed: false,
          receipt_digest: ("sha256:" + ("f" * 64))
        }' > "$media_verification_receipt"
        check-jsonschema \
          --schemafile "$media_verification_receipt_schema" \
          "$media_verification_receipt"

        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-media-cold-power-observation/v1alpha2",
          observation_id: "observation:media-schema:1",
          observation_mode: "manual_operator_confirmation",
          transaction_id: "transaction:media-schema:1",
          plan_digest: ("sha256:" + ("a" * 64)),
          stage_receipt_digest: ("sha256:" + ("e" * 64)),
          verification_receipt_digest: ("sha256:" + ("f" * 64)),
          target: {size_bytes: 8388608, logical_sector_size_bytes: 512},
          before_attachment_boot_id: "11111111-1111-4111-8111-111111111111",
          before_attachment_sequence: 1,
          after_attachment_boot_id: "22222222-2222-4222-8222-222222222222",
          after_attachment_sequence: 2,
          complete_power_removal: true,
          collector_evidence_digest: ("sha256:" + ("7" * 64)),
          capture_authenticated: false,
          freshness_established: false,
          observation_digest: ("sha256:" + ("8" * 64))
        }' > "$media_cold_observation"
        check-jsonschema \
          --schemafile "$media_cold_observation_schema" \
          "$media_cold_observation"

        jq -cn '{
          schema_version: "kaiba.provisioning.rpi5-media-staging-receipt/v1alpha2",
          status: "media_staging_verified",
          transaction_id: "transaction:media-schema:1",
          plan_digest: ("sha256:" + ("a" * 64)),
          stage_receipt_digest: ("sha256:" + ("e" * 64)),
          verification_receipt_digest: ("sha256:" + ("f" * 64)),
          cold_power_observation_digest: ("sha256:" + ("8" * 64)),
          signed_release_manifest_digest: ("sha256:" + ("b" * 64)),
          layout_digest: ("sha256:" + ("c" * 64)),
          target: {size_bytes: 8388608, logical_sector_size_bytes: 512},
          full_media_digest: ("sha256:" + ("d" * 64)),
          cold_readback_verified: true,
          capture_authenticated: false,
          freshness_established: false,
          hardware_observed: false,
          security_enforced: false,
          mutation_eligible: false,
          one_time_settings_changed: false,
          receipt_digest: ("sha256:" + ("9" * 64))
        }' > "$media_final_receipt"
        check-jsonschema --schemafile "$media_final_receipt_schema" "$media_final_receipt"

        for receipt_schema_and_path in \
          "$media_stage_receipt_schema:$media_stage_receipt" \
          "$media_verification_receipt_schema:$media_verification_receipt" \
          "$media_cold_observation_schema:$media_cold_observation" \
          "$media_final_receipt_schema:$media_final_receipt"
        do
          receipt_schema="''${receipt_schema_and_path%%:*}"
          receipt_path="''${receipt_schema_and_path#*:}"
          jq '.target.serial = "prohibited-media-identity"' \
            "$receipt_path" > "$media_preflight_invalid"
          if check-jsonschema \
            --schemafile "$receipt_schema" \
            "$media_preflight_invalid" > /dev/null 2>&1
          then
            echo "media schema accepted a prohibited target serial: $receipt_schema" >&2
            exit 1
          fi
          jq '.target.device_path = "/dev/nvme0n1"' \
            "$receipt_path" > "$media_preflight_invalid"
          if check-jsonschema \
            --schemafile "$receipt_schema" \
            "$media_preflight_invalid" > /dev/null 2>&1
          then
            echo "media schema accepted a prohibited target selector: $receipt_schema" >&2
            exit 1
          fi
          jq '.hardware_configuration_id = "hardware-configuration:prohibited:1"' \
            "$receipt_path" > "$media_preflight_invalid"
          if check-jsonschema \
            --schemafile "$receipt_schema" \
            "$media_preflight_invalid" > /dev/null 2>&1
          then
            echo "media schema accepted a prohibited hardware-configuration identity: $receipt_schema" >&2
            exit 1
          fi
        done
        # Resolve cross-schema references from the immutable source tree.
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile ${built.goSource}/schemas/signing-grant-registry-v1alpha2.schema.json \
          ${signingGrantFixture}

        ${built.provision}/bin/kaiba-provision probe \
          --profile ${qualificationProfilePath} \
          --metadata ${qualificationMetadata} \
          > "$TMPDIR/base-probe.json"
        jq -e '
          .assessment.device_class.status == "pass"
          and .assessment.observable_baseline.status == "pass"
          and (.observation | has("eeprom_hash") | not)
          and (.observation | has("upstream_fields") | not)
        ' "$TMPDIR/base-probe.json" > /dev/null
        ${built.provision}/bin/kaiba-provision probe \
          --profile ${qualificationProfilePath} \
          --metadata ${qualificationMetadataWithOptionalUpstreamFields} \
          > "$TMPDIR/optional-base-probe.json"
        jq -e '
          .assessment.device_class.status == "pass"
          and .assessment.observable_baseline.status == "pass"
          and .observation.upstream_fields == {
            "ADVANCED_BOOT": "00000000",
            "SIGNATURE_MODE": "0"
          }
        ' "$TMPDIR/optional-base-probe.json" > /dev/null
        tool_version="$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)"
        tool_digest="$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
        bundle_digest="$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
        firmware_digest="$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)"
        config_digest="$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)"
        for sequence in 1 2; do
          observed_at="2026-08-13T12:0$((sequence - 1)):00Z"
          for fixture in base optional-base; do
            output_prefix="probe-"
            if test "$fixture" = optional-base; then
              output_prefix="optional-probe-"
            fi
            jq \
              --arg observed_at "$observed_at" \
              --arg tool_version "$tool_version" \
              --arg tool_digest "$tool_digest" \
              --arg bundle_digest "$bundle_digest" \
              --arg firmware_digest "$firmware_digest" \
              --arg config_digest "$config_digest" \
              '.observed_at = $observed_at | .source = {
                source: "live-rpiboot",
                lane_id: "lane-qualification",
                usb_path: "1-2.3",
                tool_version: $tool_version,
                tool_digest: $tool_digest,
                bundle_digest: $bundle_digest,
                firmware_digest: $firmware_digest,
                config_digest: $config_digest
              }' \
              "$TMPDIR/$fixture-probe.json" > "$TMPDIR/$output_prefix''${sequence}.json"
          done
        done
        qualify() {
          ${built.provision}/bin/kaiba-provision qualify \
            --profile ${qualificationProfilePath} \
            --first-result "$1" \
            --second-result "$2" \
            --source-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            --system-closure /nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-qualification-station-1 \
            --power-cycle-confirmation complete \
            --pre-probe-normal-boot confirmed \
            --normal-boot-confirmation "$3"
        }
        qualify "$TMPDIR/probe-1.json" "$TMPDIR/probe-2.json" unchanged > "$TMPDIR/passed.json"
        if qualify "$TMPDIR/probe-1.json" "$TMPDIR/probe-2.json" pending > "$TMPDIR/incomplete.json"; then
          echo "incomplete qualification unexpectedly exited zero" >&2
          exit 1
        else
          test "$?" -eq 7
        fi
        if qualify "$TMPDIR/probe-1.json" "$TMPDIR/probe-2.json" failed > "$TMPDIR/failed.json"; then
          echo "failed qualification unexpectedly exited zero" >&2
          exit 1
        else
          test "$?" -eq 6
        fi
        qualify \
          "$TMPDIR/optional-probe-1.json" \
          "$TMPDIR/optional-probe-2.json" \
          unchanged > "$TMPDIR/optional-present.json"
        if qualify \
          "$TMPDIR/probe-1.json" \
          "$TMPDIR/optional-probe-2.json" \
          unchanged > "$TMPDIR/optional-mixed.json"; then
          echo "mixed optional upstream observations unexpectedly passed" >&2
          exit 1
        else
          test "$?" -eq 6
        fi
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
          "$TMPDIR/passed.json" \
          "$TMPDIR/incomplete.json" \
          "$TMPDIR/failed.json" \
          "$TMPDIR/optional-present.json" \
          "$TMPDIR/optional-mixed.json"
        schema_must_reject() {
          description="$1"
          record="$2"
          if check-jsonschema \
            --schemafile ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
            "$record"; then
            echo "schema accepted $description" >&2
            exit 1
          fi
        }
        jq '
          (.comparisons[] | select(.field == "boot_rom") | .status) = "not_observed"
        ' "$TMPDIR/passed.json" > "$TMPDIR/invalid-unobserved-required-comparison.json"
        schema_must_reject \
          "not_observed for the mandatory boot_rom comparison" \
          "$TMPDIR/invalid-unobserved-required-comparison.json"
        jq '
          .findings |= map(select(. != "signature-mode-changed"))
        ' "$TMPDIR/optional-mixed.json" > "$TMPDIR/invalid-missing-signature-mode-finding.json"
        schema_must_reject \
          "a changed signature_mode comparison without its finding" \
          "$TMPDIR/invalid-missing-signature-mode-finding.json"
        jq '
          .findings |= map(select(. != "advanced-boot-changed"))
        ' "$TMPDIR/optional-mixed.json" > "$TMPDIR/invalid-missing-advanced-boot-finding.json"
        schema_must_reject \
          "a changed advanced_boot comparison without its finding" \
          "$TMPDIR/invalid-missing-advanced-boot-finding.json"
        jq '
          .findings += ["signature-mode-changed"] | .findings |= sort
        ' "$TMPDIR/failed.json" > "$TMPDIR/invalid-spurious-signature-mode-finding.json"
        schema_must_reject \
          "a signature-mode-changed finding for a not_observed comparison" \
          "$TMPDIR/invalid-spurious-signature-mode-finding.json"
        jq '
          .findings += ["advanced-boot-changed"] | .findings |= sort
        ' "$TMPDIR/failed.json" > "$TMPDIR/invalid-spurious-advanced-boot-finding.json"
        schema_must_reject \
          "an advanced-boot-changed finding for a not_observed comparison" \
          "$TMPDIR/invalid-spurious-advanced-boot-finding.json"
        test "$(jq -r .profile.digest "$TMPDIR/passed.json")" = '${qualificationProfileReference.digest}'
        test "$(jq -r .profile.policy_digest "$TMPDIR/passed.json")" = '${qualificationPolicyDigest}'
        test "$(jq -r .station_system "$TMPDIR/passed.json")" = '${pkgs.stdenv.hostPlatform.system}'
        test "$(jq -r .source.bundle_digest "$TMPDIR/passed.json")" = "$bundle_digest"
        jq -e '
          [.probes[].eeprom_hash] == [null, null]
          and ([.comparisons[] | select(.field == "eeprom_hash") | .status] == ["not_observed"])
          and ([.comparisons[] | select(.field == "signature_mode") | .status] == ["not_observed"])
          and ([.comparisons[] | select(.field == "advanced_boot") | .status] == ["not_observed"])
        ' "$TMPDIR/passed.json" > /dev/null
        jq -e '
          .status == "passed"
          and .findings == []
          and ([.comparisons[] | select(.field == "signature_mode") | .status] == ["match"])
          and ([.comparisons[] | select(.field == "advanced_boot") | .status] == ["match"])
        ' "$TMPDIR/optional-present.json" > /dev/null
        jq -e '
          .status == "failed"
          and .quarantine_required == true
          and .findings == ["advanced-boot-changed", "signature-mode-changed"]
          and ([.comparisons[] | select(.field == "signature_mode") | .status] == ["changed"])
          and ([.comparisons[] | select(.field == "advanced_boot") | .status] == ["changed"])
        ' "$TMPDIR/optional-mixed.json" > /dev/null
        ! grep -F 'nixos-system-qualification-station' "$TMPDIR/passed.json"

        mkdir -p "$out"
        touch "$out/passed"
      '';

  probeBundleIntegrity =
    pkgs.runCommand "kaiba-rpi5-probe-bundle-check" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        test "$(find ${built.rpi5ProbeBundle}/bundle -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = $'bootcode5.bin\nconfig.txt'
        test ! -L ${built.rpi5ProbeBundle}/bundle/bootcode5.bin
        test ! -L ${built.rpi5ProbeBundle}/bundle/config.txt
        cmp ${built.rpi5ProbeBundle}/bundle/bootcode5.bin \
          ${pkgs.rpiboot.src}/recovery5/bootcode5.bin
        test "$(cat ${built.rpi5ProbeBundle}/bundle/config.txt)" = 'recovery_metadata=1'
        test "$(wc -c < ${built.rpi5ProbeBundle}/bundle/config.txt)" -eq 20
        test "$(jq -r .schema ${built.rpi5ProbeBundle}/manifest.json)" = 'kaiba.rpi5-probe-bundle/v1alpha1'
        test "$(jq -c 'keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bundle_sha256","files","schema","tool_sha256","tool_version"]'
        test "$(jq -c '.files | keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bootcode5.bin","config.txt"]'
        test "$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)" = '${built.rpiboot.version}'
        tool_digest="sha256:$(sha256sum ${built.rpiboot}/bin/rpiboot | cut -d ' ' -f 1)"
        firmware_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/bootcode5.bin | cut -d ' ' -f 1)"
        config_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/config.txt | cut -d ' ' -f 1)"
        bundle_digest="sha256:$(
          printf '%s\0%s\0%s\0%s\0%s\0' \
            'kaiba.rpi5.probe-bundle.v1' \
            'bootcode5.bin' "$firmware_digest" \
            'config.txt' "$config_digest" \
            | sha256sum | cut -d ' ' -f 1
        )"
        test "$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$tool_digest"
        test "$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$firmware_digest"
        test "$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$config_digest"
        test "$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$bundle_digest"
        mkdir -p "$out"
        touch "$out/passed"
      '';

  rpibootMetadataStdoutCompatibility =
    pkgs.runCommand "kaiba-rpiboot-metadata-stdout-compatibility"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.pkg-config
          pkgs.stdenv.cc
        ];
        buildInputs = [ pkgs.libusb1 ];
      }
      ''
        set -eu
        test "$(sha256sum ${built.rpibootSource}/main.c | cut -d ' ' -f 1)" = \
          d506bbde92c66f96655d000892e13903a19c39468f87be9fdd930334d95c0e7c
        test '${built.rpiboot.version}' = \
          '${pkgs.rpiboot.version}+kaiba-stdout-metadata.1'
        ! cmp -s ${built.rpiboot}/bin/rpiboot ${pkgs.rpiboot}/bin/rpiboot

        ${built.rpiboot}/bin/rpiboot --help > "$TMPDIR/help.txt"
        grep -F \
          -- '-j [path]        : Write metadata JSON object to a file at the given path (BCM2712/2711)' \
          "$TMPDIR/help.txt"
        test "$(${built.rpiboot}/bin/rpiboot --version)" = \
          'RPIBOOT: build-date 2025/12/02 pkg-version 20250908~162618~bookworm+kaiba-stdout-metadata.1 f64fa310'

        mkdir "$TMPDIR/harness"
        cp -R ${built.rpibootSource}/. "$TMPDIR/harness/source"
        chmod -R u+w "$TMPDIR/harness/source"
        cd "$TMPDIR/harness/source"
        $CC -Wall -Wextra bin2c.c -o bin2c
        ./bin2c msd/bootcode.bin msd/bootcode.h
        ./bin2c msd/start.elf msd/start.h
        ./bin2c msd/bootcode4.bin msd/bootcode4.h
        cflags="$(pkg-config --cflags libusb-1.0)"
        libs="$(pkg-config --libs libusb-1.0)"
        $CC -Wall -Wextra $cflags \
          -Dmain=rpiboot_program_main \
          '-DGIT_VER="compatibility-test"' \
          '-DPKG_VER="compatibility-test"' \
          '-DBUILD_DATE="1970/01/01"' \
          '-DINSTALL_PREFIX="/nonexistent"' \
          -c main.c -o main.o
        $CC -Wall -Wextra $cflags \
          -c bootfiles.c -o bootfiles.o
        $CC -Wall -Wextra $cflags \
          -c decode_duid.c -o decode_duid.o
        $CC -Wall -Wextra $cflags \
          ${./rpiboot-metadata-stdout-harness.c} \
          main.o bootfiles.o decode_duid.o \
          -Wl,--wrap=libusb_control_transfer \
          $libs \
          -o rpiboot-metadata-stdout-harness

        ./rpiboot-metadata-stdout-harness > stdout.txt
        test -z "$(find . -maxdepth 1 -name '*.json' -print -quit)"
        test "$(grep -c '^{' stdout.txt)" -eq 1
        test "$(grep -c '^}$' stdout.txt)" -eq 1
        sed -n '/^{/,/^}$/p' stdout.txt > metadata.json
        jq -e '
          keys == ["EEPROM_HASH", "USER_SERIAL_NUM"]
          and .USER_SERIAL_NUM == "A7EB274C"
          and .EEPROM_HASH == "dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137"
        ' metadata.json > /dev/null
        grep -Fx 'KAIBA_RPIBOOT_STDOUT_HARNESS_DONE' stdout.txt
        ! grep -F 'Created metadata file:' stdout.txt

        mkdir -p "$out"
        touch "$out/passed"
      '';

  physicalLaneGuardFixture = built.mkRpi5PhysicalLaneGuard {
    name = "kaiba-rpi5-physical-lane-guard-module-fixture";
    verifiedSignedRelease = productionMediaSignedReleaseFixture;
  };

  moduleEval = import ./module-eval.nix {
    inherit pkgs lib kaibaModules;
    kaibaAuditPackage = built.audit;
    kaibaAuthorityBridgePackage = built.authorityBridge;
    kaibaControlPackage = built.control;
    kaibaLaneGuardPackage = physicalLaneGuardFixture;
    kaibaProvisionPackage = built.provision;
    kaibaStationDemoPackage = built.stationDemo;
  };

  checks = [
    {
      id = "device-profile-schema";
      description = "Stable Raspberry Pi 5 device-profile conformance with the strict v1alpha1 schema.";
    }
    {
      id = "rpi5-development-posture";
      description = "The approved sacrificial Pi 5 development posture is schema-valid and artifact/configuration-bound: BOOT_ORDER=0xf216 selects NVMe, SD, TFTP, then restart; BOOT_UART=1 and ENABLE_SELF_UPDATE=0 are explicit. Policy leaves VideoCore JTAG and EEPROM write protection unlocked, requires recovery to be prebuilt before customer ownership, and forbids its execution until ownership. This software-only check makes no live hardware or enforcement claim. These settings are not production-ready; production boot/debug/write-protection values remain undecided, rollback is unimplemented, and enrollment is blocked.";
      evidence = [ developmentPostureEvidencePath ];
    }
    {
      id = "development-signer-independent-review";
      description = "The checked-in independent-review record binds the non-production sacrificial-development signer to the reviewed repository revision, vendor certificate-chain evidence digests, token and slot policy, reviewed public key, customer-key hash, and signer policy. The record explicitly grants neither signing authorization nor production approval. This is a software-only validation of retained evidence; it performs no live token or hardware access and makes no production-readiness claim.";
    }
    {
      id = "go-tests";
      description = "Go package tests covering the provisioning profile, adapter, live acquisition, and CLI behavior.";
    }
    {
      id = "exact-release-signing-authorization";
      description = "Software-only tests author and validate a reviewer-attributed, time-, expiry-, and exact-release-intent-bound approval with a domain-separated digest, then deterministically derive exactly the five reviewed role-and-artifact grants without caller-selected signing inputs. Reviewer identity and handoff are procedural and not cryptographically authenticated; signing-host root remains trusted, so this is not production separation-of-duties enforcement. The tests exercise no live token, signing service, or hardware; the authorization is release-specific and does not approve production devices or production policy.";
    }
    {
      id = "authenticated-signing-receipts";
      description = "Software-only tests export the signing gate's complete durable receipt snapshot and independently verify every artifact RSA signature plus a domain-separated canonical receipt-attestation signature binding the full grant and request, request digest, backend identity, artifact signature and digest, and gate-clock signed_at value. Verification also requires the exact reviewed registry, separately captured receipt digests, reviewed public key, and grant expiry. The signed_at field is authenticated gate metadata, not an external trusted timestamp. These tests use synthetic cryptographic fixtures only, perform no live token or hardware operation, and make no production-signing or production-readiness claim.";
    }
    {
      id = "ubuntu-signing-gate-deployment";
      description = "Software-only Ubuntu 24.04 deployment tests validate the inert installer, fixed service identity and authority, restrictive systemd, polkit, tmpfiles, state, socket, registry, and root-only tmpfs PIN-source boundaries, plus fail-closed static preflight behavior. They do not install or start a live service, read a PIN, enumerate or use a token, access hardware, or sign an artifact; this deployment remains limited to the non-production sacrificial-development ceremony.";
    }
    {
      id = "development-signing-ceremony-automation";
      description = "Software-only tests cover the exact-release, public-only ceremony orchestrator, including stable direct annotated-tag checks, immutable phase evidence, fixed-output resume, terminal no-retry assembly failure, authenticated handoff snapshot binding, and exclusion of live signing, token, gate-control, sudo, and hardware authority from its closure. The helper never authors approval, installs authority, handles a PIN, starts a service, signs, transfers evidence, or mutates hardware; human role boundaries remain mandatory and this is not a production ceremony.";
    }
    {
      id = "authenticated-authority-bridge";
      description = "Independent approver mTLS identity, stable control/audit reads, typed server-time claim and approval preflights, strict Unix IPC, the v1alpha4 lane plan, and the v1alpha3 authority bridge fail closed against clock, boot-mode, or authority tampering before emitting a hardware request. After delayed physical pre-observation, the guard reacquires the exact binding and control requires operation-budget-plus-margin claim time and dispatch-margin approval time before AttemptStarted or hardware dispatch. The digest-bound policy requires normal for cold_power_cycle and rpiboot for the other six operations without exposing physical paths, an operator-selected mode, or a generic mutation primitive. The combined software contract reaches the authenticated, journal-backed physical-mode boundary, but every target interface remains simulated; this makes no live BOOTSEL, USB, UART, GPIO, mutation, or enforcement claim.";
    }
    {
      id = "authenticated-physical-mode-workflow";
      description = "Software tests cover the fixed seven-operation workflow and development terminalization; independent approver mTLS and typed approver-only preflight; server-time claim and approval checks before audited transitions and after delayed pre-observation with minimum remaining windows; approval- or reviewed-deadline-bound same-claim renewals authorized atomically without rebasing immutable proposal resource versions; exact committed approval replay after expiry while audit-only attempts fail; and selector-free terminal claim release that cannot retarget a later claim. They also cover role-separated control/audit clients and audit-before-control writes, durable trusted attempt receipts, exact existing-receipt and summary replay, publication-only retry for durable execute and non-uncertain reconciliation results, prompt-capable read-only re-observation of reconciliation AttemptUncertain with zero mutation redispatch, authenticated Unix-socket BOOTSEL acknowledgements, and the journal-backed Raspberry Pi 5 mode state machine. The native acknowledgement wrapper is tested compositionally, not as a live NixOS runtime setgid deployment. GPIO, USB, UART, power, timeout, cancellation, restart, and safe-off behavior use fakes or simulated OS interfaces; this row does not qualify live hardware or claim security enforcement.";
    }
    {
      id = "authenticated-restart-reconciliation";
      description = "The restart integration reopens durable control, audit, execute-once, and boot-transition stores, reacquires read-only reconciliation authority over mTLS and strict Unix IPC, and performs direct observation through the Raspberry Pi 5 adapter to resolve applied and not-applied outcomes without mutation redispatch. Separate command and guard tests prove exact durable terminal-receipt verification and publication replay without target I/O, plus repeated read-only observation for reconciliation AttemptUncertain. The restart integration uses deterministic simulated prompt acknowledgements rather than the Unix peer-authentication prompt server, and every target-facing OS interface is simulated; this makes no live-hardware or security-enforcement claim.";
    }
    {
      id = "media-staging-fixture";
      description = "Synthetic capsule-bound regular-file fixture validates FAT/GPT layout, staged extents, reopened readback, complete partition digests, dm-verity, and fail-closed tamper rejection without making hardware or enforcement claims.";
    }
    {
      id = "rpi5-production-media-contract";
      description = "Software-only v1alpha2 production-media contract sources the operational selector from typed hardware configuration while keeping the selector and configuration ID out of plans, receipts, and evidence; it binds the signed release, exact GPT/FAT/root/verity content, and per-run geometry without media model, serial, or WWID. The linker-fixed writer and verifier retain whole-device, clear-use, and geometry guards; this makes no hardware, cold-power, or live signed-system boot-enforcement claim.";
    }
    {
      id = "nixos-module-evaluation";
      description = "Provisioning-probe NixOS module evaluation and its narrow USB access boundary.";
    }
    {
      id = "probe-bundle-integrity";
      description = "Immutable metadata-only probe bundle and compiled digest-manifest integrity.";
    }
    {
      id = "rpiboot-metadata-stdout";
      description = "Pinned rpiboot host tool emits one bounded metadata object on stdout without creating a side file.";
    }
    {
      id = "rpi5-eeprom-release-contract";
      description = "Pinned Raspberry Pi 5 EEPROM firmware and A/B-aware signing-tool sources match exact public provenance, digest, and mandatory boot_img_sha256 capability contracts without signing or hardware authority.";
    }
    {
      id = "rpi5-eeprom-signing-contract";
      description = "Canonical release intent binds the exact boot, EEPROM, and owned-recovery signing inputs and the deterministic fresh-board EEPROM signing plan, result, and finalizer without device-mutation authority.";
    }
    {
      id = "rpi5-rpiboot-bundle-set";
      description = "Owned-recovery signing, fresh/owned RPIBOOT trees, and deterministic negative/root-integrity fixtures are canonical, digest-bound, replay-verified, and explicitly carry no hardware-observation claim.";
    }
    {
      id = "rpi5-signed-release-finalization";
      description = "Complete synthetic signed-release assembly verifies all public lineage, pinned fresh-EEPROM and owned-recovery replay, canonical RPIBOOT siblings, exact content-addressed publication, and fail-closed tamper rejection without live signing or hardware claims.";
    }
    {
      id = "signed-release-manifest-contract";
      description = "Complete signed-release manifest requires the exact 18-role set and canonical RPIBOOT directory-tree bindings while preserving partial signed-boot manifests.";
    }
    {
      id = "provision-package";
      description = "kaiba-provision package with pinned probe-tool, profile, schema, manifest, and bundle inputs.";
    }
  ];

  evidenceEntries = builtins.readDir ./evidence;
  unsupportedEvidenceEntries = lib.filter (
    name: name != "README.md" && name != qualificationEvidenceName
  ) (builtins.attrNames evidenceEntries);
  qualificationEvidence =
    if unsupportedEvidenceEntries != [ ] then
      throw "unsupported hardware qualification evidence entries: ${lib.concatStringsSep ", " unsupportedEvidenceEntries}"
    else if !builtins.hasAttr qualificationEvidenceName evidenceEntries then
      null
    else
      let
        name = qualificationEvidenceName;
        kind = evidenceEntries.${name};
        record = builtins.fromJSON (builtins.readFile (./evidence + "/${name}"));
        recordProfile = record.profile or { };
      in
      if kind != "regular" then
        throw "hardware qualification evidence must be a regular file"
      else if
        !builtins.elem (record.status or null) [
          "passed"
          "failed"
        ]
      then
        throw "published hardware qualification evidence must have passed or failed status"
      else if !profileReferenceMatches qualificationProfileReference recordProfile then
        throw "hardware qualification evidence does not match the current profile policy or allowed status-only promotion"
      else if (record.adapter or null) != qualificationAdapterReference then
        throw "hardware qualification evidence does not match the current profile adapter"
      else if
        !builtins.elem (record.station_system or null) [
          "x86_64-linux"
          "aarch64-linux"
        ]
      then
        throw "hardware qualification evidence has an unsupported station system"
      else
        {
          inherit name record;
        };

  hardwareQualification =
    if qualificationEvidence == null then
      {
        status = "pending";
        description = "The required two-probe, full-power-cycle qualification on a sacrificial fresh Raspberry Pi 5 Model B has not been completed.";
        evidence = [ ];
      }
    else
      {
        status = qualificationEvidence.record.status;
        description =
          if qualificationEvidence.record.status == "passed" then
            "A sacrificial fresh Raspberry Pi 5 Model B passed the reviewed two-probe, full-power-cycle qualification."
          else
            "The sacrificial Raspberry Pi 5 Model B qualification failed and requires quarantine review.";
        evidence = [
          "evidence/provisioning/hardware-qualification/${qualificationEvidence.name}"
        ];
      };

  platformJSON = pkgs.writeText "kaiba-provisioning-${pkgs.stdenv.hostPlatform.system}.json" (
    builtins.toJSON {
      schema_version = 1;
      suite = "kaiba-rpi5-provisioning-platform-result";
      system = pkgs.stdenv.hostPlatform.system;
      checks = map (
        check:
        check
        // {
          status = "passed";
          evidence = check.evidence or [ ];
        }
      ) checks;
    }
  );

  reportInputJSON = pkgs.writeText "kaiba-provisioning-report-input.json" (
    builtins.toJSON {
      schema_version = 1;
      suite = "kaiba-rpi5-provisioning-probe";
      automated = {
        overall = "partial";
        checks =
          lib.concatMap
            (
              system:
              map (
                check:
                check
                // {
                  inherit system;
                  status = if system == "x86_64-linux" then "passed" else "not-observed";
                  evidence = [ ];
                }
              ) checks
            )
            [
              "aarch64-linux"
              "x86_64-linux"
            ];
      };
      hardware_qualification = hardwareQualification;
      mutation_eligible = false;
    }
  );

  canonicalJSON =
    pkgs.runCommand "kaiba-provisioning-canonical-contracts" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        mkdir -p "$out"
        jq --sort-keys . ${platformJSON} > "$out/platform.json"
        jq --sort-keys . ${reportInputJSON} > "$out/report-input.json"
      '';

  eepromReleaseContract =
    assert lib.assertMsg (
      let
        contract = built.rpi5EEPROMRelease.kaibaRpi5EEPROMRelease;
      in
      contract.schemaVersion == "kaiba.provisioning.rpi5-eeprom-release/v1alpha1"
      &&
        contract.requiredBootImageSHA256DeviceTreePath
        == "/proc/device-tree/chosen/bootloader/boot_img_sha256"
      && contract.releaseManifest.required_capability.required
      && contract.releaseManifest.required_capability.fail_closed
      && contract.releaseManifest.required_capability.hardware_emission_must_be_observed
      && lib.all (value: value == false) [
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.hardwareEmissionObserved
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
        contract.signedEEPROMProduced
        contract.signingAuthorityConfigured
      ]
    ) "the pinned EEPROM release gained signing, hardware, mutation, or observation authority";
    pkgs.runCommand "kaiba-rpi5-eeprom-release-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        readonly release=${built.rpi5EEPROMRelease}
        readonly manifest="$release/release.json"
        readonly schema=${built.goSource}/schemas/rpi5-eeprom-release-v1alpha1.schema.json
        readonly source=${built.rpi5EEPROMRelease.kaibaRpi5EEPROMRelease.eepromSource}
        readonly update_script=${built.rpi5EEPROMRelease.kaibaRpi5EEPROMRelease.updatePieeprom}
        readonly verifier=${built.rpi5EEPROMReleaseVerifier}/bin/kaiba-verify-rpi5-eeprom-release

        check-jsonschema --check-metaschema "$schema"
        check-jsonschema --schemafile "$schema" "$manifest"
        jq --sort-keys --compact-output . "$manifest" > "$TMPDIR/canonical.json"
        cmp "$manifest" "$TMPDIR/canonical.json"

        jq -e '
          .schema_version == "kaiba.provisioning.rpi5-eeprom-release/v1alpha1"
          and .device_class == "raspberry-pi-5-model-b-v1alpha1"
          and .source.revision == "05d94be4554ce44a057bfce8d0dd37d951703dab"
          and .source.nix_hash == "sha256-duzftioXXrLizQVLwAS285n6ve4Y3rCt/ERjcGQG+Dc="
          and .firmware.release == "2026-05-26"
          and .firmware.build_epoch == 1779807685
          and .firmware.revision == "086b83e3"
          and .firmware.image.upstream_channel == "default"
          and .firmware.image.upstream_path == "firmware-2712/default/pieeprom-2026-05-26.bin"
          and .firmware.recovery.upstream_channel == "latest"
          and .firmware.recovery.upstream_path == "firmware-2712/latest/recovery.bin"
          and [.firmware.extracted_components[].id] == ["bootcode.bin", "bootsys"]
          and .toolchain.update_workflow == {
            "repository": "https://github.com/raspberrypi/usbboot",
            "revision": "42ca50932f67f4571951a11da3c3161561cb49c2",
            "ab_signing_revision": "08d4060ecfd85d402d2134572fe1e11d8b1b2dc8"
          }
          and .toolchain.usbboot_rpi_eeprom_submodule == {
            "repository": "https://github.com/raspberrypi/rpi-eeprom",
            "revision": "25f837ab8009a643ed85b9aad94d911baddaf0c4",
            "selected_helper_source_revision": "05d94be4554ce44a057bfce8d0dd37d951703dab",
            "selected_helpers_byte_identical": true
          }
          and [.toolchain.tools[].id] == [
            "update-pieeprom.sh",
            "rpi-eeprom-config",
            "rpi-eeprom-digest",
            "rpi-sign-bootcode",
            "rpi-bootloader-key-convert"
          ]
          and .required_capability == {
            "id": "boot_img_sha256",
            "device_tree_path": "/proc/device-tree/chosen/bootloader/boot_img_sha256",
            "enabled_when": "signed_boot",
            "introduced_release": "2025-01-22",
            "introduced_revision": "7918c84b4b9d7695c3b734e628139dd78b14a6b3",
            "introduced_build_epoch": 1737505011,
            "required": true,
            "fail_closed": true,
            "hardware_emission_must_be_observed": true
          }
          and ([.authority[]] | all(. == false))
        ' "$manifest" > /dev/null

        jq -r '
          [
            .firmware.image,
            .firmware.recovery,
            .firmware.extracted_components[],
            .provenance[],
            .toolchain.tools[]
          ][]
          | [.path, (.size_bytes | tostring), .sha256]
          | @tsv
        ' "$manifest" > "$TMPDIR/manifest-files.tsv"
        while IFS=$'\t' read -r relative expected_size expected_sha256; do
          candidate="$release/$relative"
          test -f "$candidate"
          test ! -L "$candidate"
          test "$(stat --format=%s "$candidate")" = "$expected_size"
          test "sha256:$(sha256sum "$candidate" | cut -d ' ' -f 1)" = \
            "$expected_sha256"
          test "$(stat --format=%a "$candidate")" = 444
        done < "$TMPDIR/manifest-files.tsv"
        test "$(wc -l < "$TMPDIR/manifest-files.tsv")" -eq 11
        test "$(stat --format=%a "$manifest")" = 444
        test -z "$(find "$release" -type l -print -quit)"
        test -z "$(find "$release" ! -type d ! -type f -print -quit)"
        test -z "$(find "$release" -type f -perm /111 -print -quit)"

        "$verifier" "$source" "$update_script" > "$TMPDIR/positive.stdout"
        test "$(cat "$TMPDIR/positive.stdout")" = \
          'rpi5 EEPROM release verification: pass'

        mkdir -p \
          "$TMPDIR/source/firmware-2712/default" \
          "$TMPDIR/source/firmware-2712/latest" \
          "$TMPDIR/source/tools"
        install -m 0644 \
          "$source/firmware-2712/default/pieeprom-2026-05-26.bin" \
          "$TMPDIR/source/firmware-2712/default/pieeprom-2026-05-26.bin"
        install -m 0644 \
          "$source/firmware-2712/latest/recovery.bin" \
          "$TMPDIR/source/firmware-2712/latest/recovery.bin"
        install -m 0644 \
          "$source/firmware-2712/release-notes.md" \
          "$TMPDIR/source/firmware-2712/release-notes.md"
        install -m 0644 \
          "$source/firmware-2712/versions.txt" \
          "$TMPDIR/source/firmware-2712/versions.txt"
        install -m 0644 "$source/rpi-eeprom-config" "$TMPDIR/source/rpi-eeprom-config"
        install -m 0644 "$source/rpi-eeprom-digest" "$TMPDIR/source/rpi-eeprom-digest"
        install -m 0644 "$source/tools/rpi-sign-bootcode" "$TMPDIR/source/tools/rpi-sign-bootcode"
        install -m 0644 \
          "$source/tools/rpi-bootloader-key-convert" \
          "$TMPDIR/source/tools/rpi-bootloader-key-convert"

        cp -R "$TMPDIR/source" "$TMPDIR/missing-capability-source"
        sed -i '/boot_img_sha256/d' \
          "$TMPDIR/missing-capability-source/firmware-2712/release-notes.md"
        set +e
        "$verifier" "$TMPDIR/missing-capability-source" "$update_script" \
          > "$TMPDIR/missing-capability.stdout" \
          2> "$TMPDIR/missing-capability.stderr"
        missing_capability_status="$?"
        set -e
        test "$missing_capability_status" -eq 1
        test ! -s "$TMPDIR/missing-capability.stdout"
        grep -F 'required boot_img_sha256 device-tree path is missing' \
          "$TMPDIR/missing-capability.stderr"

        cp -R "$TMPDIR/source" "$TMPDIR/old-firmware-source"
        install -m 0644 \
          "$source/firmware-2712/old/latest/pieeprom-2025-01-14.bin" \
          "$TMPDIR/old-firmware-source/firmware-2712/default/pieeprom-2026-05-26.bin"
        set +e
        "$verifier" "$TMPDIR/old-firmware-source" "$update_script" \
          > "$TMPDIR/old-firmware.stdout" \
          2> "$TMPDIR/old-firmware.stderr"
        old_firmware_status="$?"
        set -e
        test "$old_firmware_status" -eq 1
        test ! -s "$TMPDIR/old-firmware.stdout"
        grep -F 'firmware image predates the required boot_img_sha256 capability' \
          "$TMPDIR/old-firmware.stderr"

        cp "$update_script" "$TMPDIR/non-ab-update-pieeprom.sh"
        chmod u+w "$TMPDIR/non-ab-update-pieeprom.sh"
        sed -i '/sign_firmware_blob.*bootsys.*bootsys.signed/d' \
          "$TMPDIR/non-ab-update-pieeprom.sh"
        set +e
        "$verifier" "$source" "$TMPDIR/non-ab-update-pieeprom.sh" \
          > "$TMPDIR/non-ab.stdout" \
          2> "$TMPDIR/non-ab.stderr"
        non_ab_status="$?"
        set -e
        test "$non_ab_status" -eq 1
        test ! -s "$TMPDIR/non-ab.stdout"
        grep -F 'update workflow does not counter-sign bootsys' \
          "$TMPDIR/non-ab.stderr"

        cp -R "$TMPDIR/source" "$TMPDIR/tampered-source"
        printf X | dd \
          of="$TMPDIR/tampered-source/firmware-2712/default/pieeprom-2026-05-26.bin" \
          bs=1 seek=0 conv=notrunc status=none
        set +e
        "$verifier" "$TMPDIR/tampered-source" "$update_script" \
          > "$TMPDIR/tampered.stdout" \
          2> "$TMPDIR/tampered.stderr"
        tampered_status="$?"
        set -e
        test "$tampered_status" -eq 1
        test ! -s "$TMPDIR/tampered.stdout"
        grep -F 'EEPROM image digest differs from the reviewed pin' \
          "$TMPDIR/tampered.stderr"

        jq 'del(.required_capability)' "$manifest" \
          > "$TMPDIR/missing-required-capability.json"
        jq '.required_capability.fail_closed = false' "$manifest" \
          > "$TMPDIR/non-fail-closed-capability.json"
        jq '.firmware.release = "2026-05-22"' "$manifest" \
          > "$TMPDIR/different-release.json"
        jq '.firmware.recovery.upstream_channel = "default"' "$manifest" \
          > "$TMPDIR/wrong-recovery-channel.json"
        jq '.firmware.recovery.upstream_path = "firmware-2712/default/recovery.bin"' "$manifest" \
          > "$TMPDIR/wrong-recovery-path.json"
        jq '.toolchain.usbboot_rpi_eeprom_submodule.repository = "https://github.com/raspberrypi/usbboot"' \
          "$manifest" > "$TMPDIR/wrong-helper-repository.json"
        jq '.toolchain.tools |= reverse' "$manifest" \
          > "$TMPDIR/reordered-tools.json"
        jq '.unexpected = true' "$manifest" \
          > "$TMPDIR/unknown-field.json"
        for invalid_manifest in \
          "$TMPDIR/missing-required-capability.json" \
          "$TMPDIR/non-fail-closed-capability.json" \
          "$TMPDIR/different-release.json" \
          "$TMPDIR/wrong-recovery-channel.json" \
          "$TMPDIR/wrong-recovery-path.json" \
          "$TMPDIR/wrong-helper-repository.json" \
          "$TMPDIR/reordered-tools.json" \
          "$TMPDIR/unknown-field.json"
        do
          if check-jsonschema --schemafile "$schema" "$invalid_manifest"; then
            echo "EEPROM release schema accepted invalid manifest: $invalid_manifest" >&2
            exit 1
          fi
        done

        mkdir -p "$out"
        touch "$out/passed"
      '';

  eepromSigningContract =
    assert lib.assertMsg (eepromSigningPlanInputAccepted
      { }
    ) "the EEPROM signing-plan factory rejected reviewed public store inputs";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        bootConfig = "/tmp/kaiba-untrusted-eeprom-boot.conf";
      })
    ) "the EEPROM signing-plan factory accepted an untrusted boot config";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        eepromSigningInputs = "/tmp/kaiba-untrusted-eeprom-inputs";
      })
    ) "the EEPROM signing-plan factory accepted untrusted signing inputs";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        releaseIntent = "/tmp/kaiba-untrusted-release-intent";
      })
    ) "the EEPROM signing-plan factory accepted an untrusted release intent";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        reviewedPublicKeyPEM = "/tmp/kaiba-untrusted-public.pem";
      })
    ) "the EEPROM signing-plan factory accepted an untrusted public key";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        planID = "EEPROM Plan With Spaces";
      })
    ) "the EEPROM signing-plan factory accepted a non-canonical plan ID";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        sourceDateEpoch = 0;
      })
    ) "the EEPROM signing-plan factory accepted an unset source epoch";
    assert lib.assertMsg (
      !(eepromSigningPlanInputAccepted {
        customerKeyHash = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      })
    ) "the EEPROM signing-plan factory accepted a non-canonical customer-key hash";
    assert lib.assertMsg (lib.isDerivation verifiedSignedEEPROMEvaluationFixture)
      "the signed-EEPROM finalizer factory rejected public store inputs";
    assert lib.assertMsg (lib.isDerivation ownedRecoverySigningPlanEvaluationFixture)
      "the owned-recovery plan factory rejected verified fresh EEPROM inputs";
    assert lib.assertMsg (lib.isDerivation verifiedOwnedRecoveryEvaluationFixture)
      "the owned-recovery finalizer factory rejected public store inputs";
    assert lib.assertMsg (ownedRecoverySigningPlanInputAccepted
      { }
    ) "the owned-recovery plan factory rejected verified public inputs";
    assert lib.assertMsg (
      !(ownedRecoverySigningPlanInputAccepted {
        freshSigningPlan = "/tmp/untrusted-fresh-plan";
      })
    ) "the owned-recovery plan factory accepted an untrusted fresh plan";
    assert lib.assertMsg (
      !(ownedRecoverySigningPlanInputAccepted {
        verifiedSignedEEPROM = "/tmp/untrusted-verified-eeprom";
      })
    ) "the owned-recovery plan factory accepted an untrusted EEPROM result";
    assert lib.assertMsg (
      !(ownedRecoverySigningPlanInputAccepted {
        planID = "Owned Recovery With Spaces";
      })
    ) "the owned-recovery plan factory accepted a non-canonical plan ID";
    assert lib.assertMsg (
      let
        contract = ownedRecoverySigningPlanEvaluationFixture.kaibaRpi5OwnedRecoverySigningPlan;
      in
      contract.schemaVersion == "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1"
      && contract.updaterMode == "owned-recovery"
      &&
        contract.updaterFlags == [
          "-f"
          "-r"
        ]
      && contract.newSigningInputCount == 1
      && contract.reusedFreshSignatureCount == 3
      && lib.all (value: value == false) [
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
        contract.recoverySigningPerformed
        contract.signingAuthorityConfigured
      ]
    ) "the owned-recovery public plan gained signing, hardware, or mutation authority";
    assert lib.assertMsg (
      let
        contract = eepromSigningPlanFixture.kaibaRpi5EEPROMSigningPlan;
      in
      contract.schemaVersion == "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1"
      && contract.updaterMode == "fresh-board"
      && contract.updaterFlags == [ "-f" ]
      && lib.all (value: value == false) [
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
        contract.recoverySigningPerformed
        contract.signedEEPROMProduced
        contract.signingAuthorityConfigured
      ]
    ) "the public EEPROM signing plan gained signing, hardware, or mutation authority";
    assert lib.assertMsg (
      let
        contract = built.eepromSigningTool.kaibaEEPROMSigningTool;
      in
      contract.approvalGateConfigured
      && contract.updaterMode == "fresh-board"
      && contract.updaterFlags == [ "-f" ]
      && contract.recoverySigningCapable
      && contract.ownedRecoveryGateRequestCount == 1
      && contract.ownedRecoveryReusedSignatureCount == 3
      &&
        contract.ownedRecoveryUpdaterFlags == [
          "-f"
          "-r"
        ]
      && contract.signingAuthorityConfigured
      && lib.all (value: value == false) [
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
      ]
    ) "the EEPROM signing adapter gained device, private-key, or recovery-signing authority";
    pkgs.runCommand "kaiba-rpi5-eeprom-signing-contract"
      {
        nativeBuildInputs = [
          pkgs.binutils
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.go
          pkgs.gnugrep
          pkgs.jq
          pkgs.openssl
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        export LC_ALL=C

        cd ${built.goSource}
        go test \
          ./internal/provisioning/eepromsigning \
          ./cmd/kaiba-provision-sign-eeprom \
          -count=1

        readonly plan_schema=${built.goSource}/schemas/rpi5-eeprom-signing-plan-v1alpha1.schema.json
        readonly result_schema=${built.goSource}/schemas/rpi5-eeprom-signing-result-v1alpha1.schema.json
        readonly owned_plan_schema=${built.goSource}/schemas/rpi5-owned-recovery-signing-plan-v1alpha1.schema.json
        readonly owned_result_schema=${built.goSource}/schemas/rpi5-owned-recovery-signing-result-v1alpha1.schema.json
        readonly plan=${eepromSigningPlanFixture}
        readonly owned_plan=${ownedRecoverySigningPlanFixture}
        check-jsonschema --check-metaschema \
          "$plan_schema" \
          "$result_schema" \
          "$owned_plan_schema" \
          "$owned_result_schema"
        check-jsonschema --schemafile "$plan_schema" "$plan/plan.json"
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile "$owned_plan_schema" \
          "$owned_plan/plan.json"
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-release-intent-v1alpha1.schema.json \
          "$plan/release-intent.json"

        find "$owned_plan" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
          > "$TMPDIR/actual-owned-plan-files"
        printf '%s\n' \
          boot.conf \
          bootcode.original.bin \
          bootcode5.fresh.bin \
          bootsys.original \
          pieeprom.expected.bin \
          pieeprom.expected.sig \
          pieeprom.original.bin \
          plan.json \
          public.pem \
          recovery.original.bin \
          release-intent.json \
          > "$TMPDIR/expected-owned-plan-files"
        cmp "$TMPDIR/expected-owned-plan-files" "$TMPDIR/actual-owned-plan-files"
        jq -e '
          .schema_version
            == "kaiba.provisioning.rpi5-owned-recovery-signing-plan/v1alpha1"
          and .plan_id == "plan:rpi5-owned-recovery-fixture:1"
          and .updater_mode == "owned-recovery"
          and .updater_flags == ["-f", "-r"]
          and .owned_recovery_signing_input.role
            == "rpi5.owned_recovery_bootcode"
          and ((.fresh_eeprom_plan.signing_inputs | map(.role)) == [
                "rpi5.eeprom_bootcode",
                "rpi5.eeprom_bootsys",
                "rpi5.eeprom_config"
              ])
        ' "$owned_plan/plan.json" > /dev/null

        owned_plan_json="$(cat "$owned_plan/plan.json")"
        owned_plan_digest="sha256:$({
          printf '%s\0' \
            'kaiba.provisioning.rpi5-owned-recovery-signing-plan.v1alpha1'
          printf '%s' "$owned_plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq \
          --null-input \
          --compact-output \
          --arg plan_digest "$owned_plan_digest" \
          --argjson plan "$owned_plan_json" \
          '{
            schema_version: "kaiba.provisioning.rpi5-owned-recovery-signing-result/v1alpha1",
            plan_id: $plan.plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $plan.fresh_eeprom_plan.release_intent_digest,
            eeprom_release_manifest_digest: $plan.fresh_eeprom_plan.eeprom_release_manifest_digest,
            signer_policy_digest: $plan.fresh_eeprom_plan.signer_policy_digest,
            public_key_fingerprint: $plan.fresh_eeprom_plan.public_key_fingerprint,
            customer_key_hash: $plan.fresh_eeprom_plan.customer_key_hash,
            source_date_epoch: $plan.fresh_eeprom_plan.source_date_epoch,
            updater_mode: "owned-recovery",
            recovery_mode: "customer-counter-signed",
            signature: {
              role: $plan.owned_recovery_signing_input.role,
              input_digest: $plan.owned_recovery_signing_input.digest,
              input_size_bytes: $plan.owned_recovery_signing_input.size_bytes,
              signature_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              signature_size_bytes: 256,
              gate_receipt_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            owned_recovery_bootcode: {
              digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              size_bytes: ($plan.fresh_eeprom_plan.original_recovery.size_bytes + 532)
            },
            replayed_signed_eeprom: $plan.fresh_eeprom_result.signed_eeprom,
            replayed_eeprom_update_metadata: $plan.fresh_eeprom_result.eeprom_update_metadata
          }' > "$TMPDIR/owned-result.json"
        check-jsonschema \
          --schemafile "$owned_result_schema" \
          "$TMPDIR/owned-result.json"

        ${eepromSigningPlanFixture.eepromBootConfigValidator} "$plan/boot.conf"
        if ${eepromSigningPlanFixture.eepromBootConfigValidator} ${oversizedEEPROMBootConfig}; then
          echo 'EEPROM signing-plan boot config validator accepted 4077 bytes' >&2
          exit 1
        fi

        find "$plan" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' \
          boot.conf \
          bootcode.original.bin \
          bootsys.original \
          pieeprom.original.bin \
          plan.json \
          public.pem \
          recovery.original.bin \
          release-intent.json \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"

        release_intent_json="$(cat "$plan/release-intent.json")"
        release_intent_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-release-intent.v1alpha1'
          printf '%s' "$release_intent_json"
        } | sha256sum | cut -d ' ' -f 1)"
        eeprom_release_manifest_digest="sha256:$(
          sha256sum ${built.rpi5EEPROMRelease}/release.json | cut -d ' ' -f 1
        )"
        jq -e \
          --arg release_intent_digest "$release_intent_digest" \
          --arg eeprom_release_manifest_digest "$eeprom_release_manifest_digest" \
          --arg public_key_fingerprint '${developmentYubiKeyPublicKeyFingerprint}' \
          --arg signer_policy_digest '${developmentYubiKeySignerPolicyDigest}' \
          --arg customer_key_hash 'sha256:${developmentYubiKeyCustomerKeyHash}' \
          '
            .schema_version == "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1"
            and .plan_id == "plan:rpi5-eeprom-fixture:1"
            and .release_intent_digest == $release_intent_digest
            and .eeprom_release_manifest_digest == $eeprom_release_manifest_digest
            and .public_key_fingerprint == $public_key_fingerprint
            and .signer_policy_digest == $signer_policy_digest
            and .customer_key_hash == $customer_key_hash
            and .firmware_build_epoch == 1779807685
            and .source_date_epoch == 1786968000
            and .updater_mode == "fresh-board"
            and .updater_flags == ["-f"]
            and (.signing_inputs | map(.role)) == [
              "rpi5.eeprom_bootcode",
              "rpi5.eeprom_bootsys",
              "rpi5.eeprom_config"
            ]
          ' "$plan/plan.json" > /dev/null

        jq -r '
          [
            ["pieeprom.original.bin", .original_eeprom],
            ["recovery.original.bin", .original_recovery],
            ["bootcode.original.bin", .original_bootcode],
            ["bootsys.original", .original_bootsys],
            ["boot.conf", .boot_config],
            ["public.pem", .public_key_pem]
          ][]
          | [.[0], .[1].digest, (.[1].size_bytes | tostring)]
          | @tsv
        ' "$plan/plan.json" > "$TMPDIR/plan-files.tsv"
        while IFS=$'\t' read -r name expected_digest expected_size; do
          test "sha256:$(sha256sum "$plan/$name" | cut -d ' ' -f 1)" = \
            "$expected_digest"
          test "$(stat --format=%s "$plan/$name")" = "$expected_size"
        done < "$TMPDIR/plan-files.tsv"

        plan_json="$(cat "$plan/plan.json")"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-eeprom-signing-plan.v1alpha1'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-eeprom-signing-result/v1alpha1' \
          --arg plan_id "$(jq -r .plan_id "$plan/plan.json")" \
          --arg plan_digest "$plan_digest" \
          --arg release_intent_digest "$release_intent_digest" \
          --arg eeprom_release_manifest_digest "$eeprom_release_manifest_digest" \
          --arg signer_policy_digest '${developmentYubiKeySignerPolicyDigest}' \
          --arg public_key_fingerprint '${developmentYubiKeyPublicKeyFingerprint}' \
          --arg customer_key_hash 'sha256:${developmentYubiKeyCustomerKeyHash}' \
          --argjson source_date_epoch 1786968000 \
          --argjson signing_inputs "$(jq -c .signing_inputs "$plan/plan.json")" \
          --argjson original_eeprom "$(jq -c .original_eeprom "$plan/plan.json")" \
          --argjson original_recovery "$(jq -c .original_recovery "$plan/plan.json")" \
          '
            {
              schema_version: $schema_version,
              plan_id: $plan_id,
              plan_digest: $plan_digest,
              release_intent_digest: $release_intent_digest,
              eeprom_release_manifest_digest: $eeprom_release_manifest_digest,
              signer_policy_digest: $signer_policy_digest,
              public_key_fingerprint: $public_key_fingerprint,
              customer_key_hash: $customer_key_hash,
              source_date_epoch: $source_date_epoch,
              updater_mode: "fresh-board",
              recovery_mode: "unsigned-copy",
              signatures: ($signing_inputs | map({
                role: .role,
                input_digest: .digest,
                input_size_bytes: .size_bytes,
                signature_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                signature_size_bytes: 256,
                gate_receipt_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              })),
              signed_eeprom: {
                digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                size_bytes: $original_eeprom.size_bytes
              },
              eeprom_update_metadata: {
                digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                size_bytes: 80
              },
              fresh_recovery_bootcode: $original_recovery
            }
          ' > "$TMPDIR/result.json"
        check-jsonschema --schemafile "$result_schema" "$TMPDIR/result.json"

        # Exercise the exact pinned vendor updater and helpers with an
        # ephemeral test key that exists only in this build sandbox. The
        # callback log must contain precisely the three release-authorized
        # preimages in order; the output is deliberately not published.
        readonly updater_work="$TMPDIR/pinned-updater"
        mkdir "$updater_work"
        install -m 0600 "$plan/pieeprom.original.bin" \
          "$updater_work/pieeprom.original.bin"
        install -m 0600 "$plan/recovery.original.bin" \
          "$updater_work/recovery.original.bin"
        install -m 0600 "$plan/boot.conf" "$updater_work/boot.conf"
        ${pkgs.openssl}/bin/openssl genpkey \
          -algorithm RSA \
          -pkeyopt rsa_keygen_bits:2048 \
          -out "$TMPDIR/ephemeral-private.pem" \
          > /dev/null 2>&1
        ${pkgs.openssl}/bin/openssl pkey \
          -in "$TMPDIR/ephemeral-private.pem" \
          -pubout \
          -out "$updater_work/public.pem"
        export KAIBA_TEST_PRIVATE_KEY="$TMPDIR/ephemeral-private.pem"
        export KAIBA_TEST_CALLBACK_LOG="$TMPDIR/updater-callbacks"
        : > "$KAIBA_TEST_CALLBACK_LOG"
        set +e
        (
          cd "$updater_work"
          PATH=${lib.escapeShellArg built.eepromSigningTool.kaibaEEPROMSigningTool.toolPATH} \
            SOURCE_DATE_EPOCH=1786968000 \
            ${built.eepromToolRuntime}/bin/update-pieeprom.sh \
              -f \
              -c boot.conf \
              -i pieeprom.original.bin \
              -o pieeprom.bin \
              -p public.pem \
              -H ${eepromPinnedUpdaterTestHSM}
        ) > "$TMPDIR/updater.stdout" 2> "$TMPDIR/updater.stderr"
        updater_status="$?"
        set -e
        if test "$updater_status" -ne 0; then
          sed 's/^/pinned updater stdout: /' "$TMPDIR/updater.stdout" >&2
          sed 's/^/pinned updater stderr: /' "$TMPDIR/updater.stderr" >&2
          exit "$updater_status"
        fi
        jq -r '.signing_inputs[].digest' "$plan/plan.json" \
          > "$TMPDIR/expected-updater-callbacks"
        cmp "$TMPDIR/expected-updater-callbacks" "$KAIBA_TEST_CALLBACK_LOG"
        test "$(wc -l < "$KAIBA_TEST_CALLBACK_LOG")" -eq 3
        test "$(stat --format=%s "$updater_work/pieeprom.bin")" = \
          "$(stat --format=%s "$plan/pieeprom.original.bin")"
        cmp "$updater_work/bootcode5.bin" "$plan/recovery.original.bin"
        test "$(sed -n '2p' "$updater_work/pieeprom.sig")" = 'ts: 1786968000'
        test "$(sed -n '1p' "$updater_work/pieeprom.sig")" = \
          "$(sha256sum "$updater_work/pieeprom.bin" | cut -d ' ' -f 1)"
        mkdir "$TMPDIR/extracted-pinned-updater"
        (
          cd "$TMPDIR/extracted-pinned-updater"
          ${built.eepromToolRuntime}/bin/rpi-eeprom-config \
            -x "$updater_work/pieeprom.bin"
        )
        cmp "$TMPDIR/extracted-pinned-updater/bootconf.txt" "$plan/boot.conf"
        test "$(stat --format=%s "$TMPDIR/extracted-pinned-updater/pubkey.bin")" -eq 264
        test "$(stat --format=%s "$TMPDIR/extracted-pinned-updater/bootcode.bin")" -eq \
          "$(( $(stat --format=%s "$plan/bootcode.original.bin") + 532 ))"
        test "$(stat --format=%s "$TMPDIR/extracted-pinned-updater/bootsys")" -eq \
          "$(( $(stat --format=%s "$plan/bootsys.original") + 532 ))"

        test -x ${built.eepromSigningTool}/bin/kaiba-provision-sign-eeprom
        set +e
        ${built.eepromSigningTool}/bin/kaiba-provision-sign-eeprom sign \
          --plan "$TMPDIR/missing-plan" \
          --output "$TMPDIR/signed-output" \
          > "$TMPDIR/packaged-smoke.stdout" \
          2> "$TMPDIR/packaged-smoke.stderr"
        packaged_smoke_status="$?"
        set -e
        test "$packaged_smoke_status" -eq 1
        grep -F 'load EEPROM signing plan directory' "$TMPDIR/packaged-smoke.stderr"
        if grep -F 'EEPROM signing adapter configuration' "$TMPDIR/packaged-smoke.stderr"; then
          echo 'EEPROM signing adapter is missing a linker-fixed release input' >&2
          exit 1
        fi

        # The signing-plan factory uses this exact OpenSSL invariant after
        # canonicalizing the reviewed key. Exercise its rejection branch with
        # an ephemeral exponent-3 key that never leaves the build sandbox.
        ${eepromSigningPlanFixture.eepromPublicKeyValidator} "$plan/public.pem"
        openssl genpkey \
          -algorithm RSA \
          -pkeyopt rsa_keygen_bits:2048 \
          -pkeyopt rsa_keygen_pubexp:3 \
          -out "$TMPDIR/exponent-three-private.pem" \
          > /dev/null 2>&1
        openssl pkey \
          -in "$TMPDIR/exponent-three-private.pem" \
          -pubout \
          -out "$TMPDIR/exponent-three-public.pem"
        exponent="$(
          openssl pkey \
            -pubin \
            -in "$TMPDIR/exponent-three-public.pem" \
            -text \
            -noout \
            | sed -n 's/^Exponent: //p'
        )"
        test "$exponent" = '3 (0x3)'
        if ${eepromSigningPlanFixture.eepromPublicKeyValidator} \
          "$TMPDIR/exponent-three-public.pem"; then
          echo 'EEPROM signing-plan key check accepted RSA exponent 3' >&2
          exit 1
        fi
        if strings ${built.eepromSigningTool}/bin/kaiba-provision-sign-eeprom \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/bin/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'EEPROM signing adapter links a physical provisioning capability' >&2
          exit 1
        fi

        mkdir "$out"
        touch "$out/passed"
      '';

  rpibootBundleContract =
    assert lib.assertMsg (lib.isDerivation rpibootBundleEvaluationFixture)
      "the RPIBOOT bundle-set factory rejected verified public inputs";
    assert lib.assertMsg (
      let
        tool = built.rpibootBundleTool.kaibaRPIBootBundleTool;
        contract = rpibootBundleEvaluationFixture.kaibaVerifiedRPIBootBundles;
      in
      contract.schemaVersion == "kaiba.provisioning.rpi5-rpiboot-bundle-set/v1alpha1"
      && contract.verificationMode == "pure_offline_replay"
      &&
        contract.bundlePaths == {
          freshCommit = "fresh-commit";
          freshReadback = "fresh-readback";
          negativeBoot = "negative-boot";
          ownedReadback = "owned-readback";
          ownedRecovery = "owned-recovery";
          rootIntegrityTest = "root-integrity-test";
        }
      && lib.all (value: value == false) [
        tool.blockDeviceWriteCapable
        tool.directHardwareAccess
        tool.eepromProgrammingCapable
        tool.fixtureHardwareObserved
        tool.mutationCapable
        tool.oneTimeSettingCapable
        tool.otpCapable
        tool.privateKeyAccess
        tool.signingAuthorityConfigured
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.fixtureHardwareObserved
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
        contract.signingAuthorityConfigured
      ]
    ) "the RPIBOOT bundle contract gained hardware, signing, mutation, or observation authority";
    pkgs.runCommand "kaiba-rpi5-rpiboot-bundle-set-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        readonly schema=${built.goSource}/schemas/rpi5-rpiboot-bundle-set-v1alpha1.schema.json
        check-jsonschema --check-metaschema \
          "$schema" \
          ${built.goSource}/schemas/rpi5-rpiboot-directory-tree-v1alpha1.schema.json

        printf '%s\n' 'unsigned fresh recovery fixture' > "$TMPDIR/fresh-recovery.bin"
        printf '%s\n' 'customer-counter-signed owned recovery fixture' \
          > "$TMPDIR/owned-recovery.bin"
        printf '%s\n' 'signed EEPROM fixture' > "$TMPDIR/pieeprom.bin"
        {
          sha256sum "$TMPDIR/pieeprom.bin" | cut -d ' ' -f 1
          printf '%s\n' 'ts: 1786968000'
        } > "$TMPDIR/pieeprom.sig"
        readonly release_intent_digest="$(jq -r .release_intent_digest \
          ${verifiedSignedBootFixture}/signing-result.json)"

        ${built.rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles build \
          --release-intent-digest "$release_intent_digest" \
          --fresh-recovery "$TMPDIR/fresh-recovery.bin" \
          --owned-recovery "$TMPDIR/owned-recovery.bin" \
          --signed-eeprom "$TMPDIR/pieeprom.bin" \
          --eeprom-metadata "$TMPDIR/pieeprom.sig" \
          --boot-image ${verifiedSignedBootFixture}/boot.img \
          --boot-signature ${verifiedSignedBootFixture}/boot.sig \
          --boot-public-key ${verifiedSignedBootFixture}/public.pem \
          --root-data ${secureBootFixtureA}/nvme/root-data.img \
          --root-hash-tree ${secureBootFixtureA}/nvme/root-hash.img \
          --output "$TMPDIR/bundle-set" > "$TMPDIR/build-digest"
        ${built.rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles verify \
          --input "$TMPDIR/bundle-set" > "$TMPDIR/verify-digest"
        cmp "$TMPDIR/build-digest" "$TMPDIR/verify-digest"
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile "$schema" \
          "$TMPDIR/bundle-set/bundle-set.json"
        jq -e --arg lineage "$release_intent_digest" '
          .release_intent_digest == $lineage
          and ([.bundles[].role] == [
            "rpi5.fresh_commit_bundle",
            "rpi5.fresh_readback_bundle",
            "rpi5.negative_boot_bundle",
            "rpi5.owned_readback_bundle",
            "rpi5.owned_recovery_bundle",
            "rpi5.root_integrity_test_bundle"
          ])
          and ([.fixtures[].hardware_observed] | all(. == false))
          and .fixtures[0].expected_outcome == "owned_rom_rejects_second_stage"
          and .fixtures[1].expected_outcome == "verity_rejects_root_data"
        ' "$TMPDIR/bundle-set/bundle-set.json" > /dev/null
        test "$(cat "$TMPDIR/bundle-set/fresh-commit/config.txt")" = \
          $'uart_2ndstage=1\nprogram_pubkey=1\nrecovery_metadata=1'
        ! grep -F program_pubkey "$TMPDIR/bundle-set/owned-recovery/config.txt"

        cp --recursive "$TMPDIR/bundle-set" "$TMPDIR/tampered"
        chmod --recursive u+w "$TMPDIR/tampered"
        printf '%s\n' 'tampered' > "$TMPDIR/tampered/owned-readback/bootcode5.bin"
        if ${built.rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles verify \
          --input "$TMPDIR/tampered" > /dev/null 2>&1
        then
          echo 'RPIBOOT bundle verifier accepted a changed published tree' >&2
          exit 1
        fi

        mkdir "$out"
        touch "$out/passed"
      '';

  signingReceiptVerificationContract =
    assert lib.assertMsg (
      let
        contract = productionMediaSigningReceiptVerification.kaibaVerifiedSigningReceipts;
      in
      contract.exactReceiptCount == 5
      && contract.receiptAttestationRequired
      &&
        contract.receiptAttestationSchemaVersion
        == "kaiba.provisioning.signing-gate-receipt-attestation/v1alpha1"
      && contract.schemaVersion == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
      && contract.verificationMode == "authenticated_offline"
      && contract.verifiedSignedBoot == productionMediaVerifiedSignedBoot
      && contract.verifiedSignedEEPROM == productionMediaVerifiedSignedEEPROM
      && contract.verifiedOwnedRecovery == productionMediaVerifiedOwnedRecovery
      && contract.reviewedPublicKeyPEM == productionMediaFixturePublicKey
      && lib.all (value: value == false) [
        contract.privateKeyAccess
        contract.signingAuthorityConfigured
      ]
    ) "the verified signing-receipt constructor lost its exact public input lineage";
    pkgs.runCommand "kaiba-signing-receipt-verification-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 077

        readonly tool=${built.signingReceiptsTool}/bin/kaiba-provision-signing-receipts
        readonly approval_tool=${built.signingApprovalTool}/bin/kaiba-provision-signing-approval
        readonly evidence=${productionMediaSigningReceiptEvidence}
        readonly registry="$evidence/signing-grants.json"
        readonly receipt_export="$evidence/signing-receipts.json"
        readonly public_key=${productionMediaFixturePublicKey}
        readonly verification=${productionMediaSigningReceiptVerification}
        readonly release_intent=${productionMediaReleaseIntent}/release-intent.json
        readonly verification_schema=${built.signingReceiptsTool}/share/kaiba/schemas/signing-gate-receipt-verification-v1alpha2.schema.json

        receipt_digest() {
          jq -er --arg role "$1" \
            '[.[] | select(.role == $role) | .receipt_digest]
             | if length == 1 then .[0] else error("missing unique receipt role") end' \
            "$evidence/receipt-digests.json"
        }
        readonly boot_receipt="$(receipt_digest rpi5.boot_image)"
        readonly eeprom_bootcode_receipt="$(receipt_digest rpi5.eeprom_bootcode)"
        readonly eeprom_bootsys_receipt="$(receipt_digest rpi5.eeprom_bootsys)"
        readonly eeprom_config_receipt="$(receipt_digest rpi5.eeprom_config)"
        readonly owned_recovery_receipt="$(receipt_digest rpi5.owned_recovery_bootcode)"

        verify_receipts() {
          "$tool" verify \
            --export "$1" \
            --registry "$2" \
            --public-key "$3" \
            --expected-receipt-digest "$4" \
            --expected-receipt-digest "$5" \
            --expected-receipt-digest "$6" \
            --expected-receipt-digest "$7" \
            --expected-receipt-digest "$8"
        }
        expect_rejection() {
          local label="$1"
          local expected_error="$2"
          shift 2
          set +e
          verify_receipts "$@" \
            > "$TMPDIR/$label.stdout" \
            2> "$TMPDIR/$label.stderr"
          local status="$?"
          set -e
          if test "$status" -ne 3; then
            echo "$label returned $status, want verification failure 3" >&2
            cat "$TMPDIR/$label.stderr" >&2
            exit 1
          fi
          test ! -s "$TMPDIR/$label.stdout"
          grep -F "$expected_error" "$TMPDIR/$label.stderr" > /dev/null
        }
        refresh_receipt_digest() {
          local input="$1"
          local index="$2"
          local output="$3"
          local receipt_json
          local receipt_digest
          receipt_json="$(jq -c --argjson index "$index" \
            '.receipts[$index].receipt' "$input")"
          receipt_digest="sha256:$({
            printf '%s\0' 'kaiba.provisioning.signing-gate-receipt.v1alpha3'
            printf '%s' "$receipt_json"
          } | sha256sum | cut -d ' ' -f 1)"
          jq --compact-output \
            --argjson index "$index" \
            --arg receipt_digest "$receipt_digest" \
            '.receipts[$index].receipt_digest = $receipt_digest' \
            "$input" > "$output"
        }

        "$approval_tool" validate \
          --release-intent "$release_intent" \
          --approval "$evidence/approval.json" \
          --registry "$registry" \
          > "$TMPDIR/authorization-verification.json"
        jq -e '.status == "valid" and .grant_count == 5' \
          "$TMPDIR/authorization-verification.json" > /dev/null
        check-jsonschema --schemafile "$verification_schema" "$verification"
        verify_receipts \
          "$receipt_export" \
          "$registry" \
          "$public_key" \
          "$boot_receipt" \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt" \
          > "$TMPDIR/independent-verification.json"
        cmp "$TMPDIR/independent-verification.json" "$verification"

        expect_rejection \
          changed-result-digest \
          'was not independently captured from a signing result' \
          "$receipt_export" \
          "$registry" \
          "$public_key" \
          'sha256:0000000000000000000000000000000000000000000000000000000000000000' \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt"

        jq --compact-output \
          '.grants[0].expires_at = "2026-08-29T12:00:00Z"' \
          "$registry" > "$TMPDIR/changed-registry.json"
        expect_rejection \
          changed-registry \
          'receipt export registry_digest does not match the reviewed registry' \
          "$receipt_export" \
          "$TMPDIR/changed-registry.json" \
          "$public_key" \
          "$boot_receipt" \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt"

        jq --compact-output \
          '.receipts[0].receipt.signed_at = "2026-08-27T12:02:00Z"' \
          "$receipt_export" > "$TMPDIR/changed-signed-at-intermediate.json"
        refresh_receipt_digest \
          "$TMPDIR/changed-signed-at-intermediate.json" \
          0 \
          "$TMPDIR/changed-signed-at.json"
        readonly changed_signed_at_receipt="$(jq -er \
          '.receipts[0].receipt_digest' "$TMPDIR/changed-signed-at.json")"
        expect_rejection \
          changed-signed-at \
          'receipt attestation signature does not verify against the reviewed public key and canonical receipt metadata' \
          "$TMPDIR/changed-signed-at.json" \
          "$registry" \
          "$public_key" \
          "$changed_signed_at_receipt" \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt"

        jq --compact-output \
          '.receipts |= map(.receipt.backend_id = "backend:forged")' \
          "$receipt_export" > "$TMPDIR/changed-backend-0.json"
        for index in 0 1 2 3 4; do
          refresh_receipt_digest \
            "$TMPDIR/changed-backend-$index.json" \
            "$index" \
            "$TMPDIR/changed-backend-$((index + 1)).json"
        done
        mapfile -t changed_backend_receipts < <(
          jq -er '.receipts[].receipt_digest' "$TMPDIR/changed-backend-5.json"
        )
        test "''${#changed_backend_receipts[@]}" -eq 5
        expect_rejection \
          changed-backend-id \
          'receipt attestation signature does not verify against the reviewed public key and canonical receipt metadata' \
          "$TMPDIR/changed-backend-5.json" \
          "$registry" \
          "$public_key" \
          "''${changed_backend_receipts[0]}" \
          "''${changed_backend_receipts[1]}" \
          "''${changed_backend_receipts[2]}" \
          "''${changed_backend_receipts[3]}" \
          "''${changed_backend_receipts[4]}"

        jq --compact-output '
          .receipts[0].receipt.signature_hex |=
            (if startswith("0") then "1" + .[1:] else "0" + .[1:] end)
        ' "$receipt_export" > "$TMPDIR/changed-export-intermediate.json"
        changed_signature_hex="$(jq -er '.receipts[0].receipt.signature_hex' \
          "$TMPDIR/changed-export-intermediate.json")"
        changed_signature_digest="sha256:$(printf '%s' "$changed_signature_hex" \
          | xxd -r -p | sha256sum | cut -d ' ' -f 1)"
        jq --compact-output \
          --arg signature_digest "$changed_signature_digest" \
          '.receipts[0].receipt.signature_digest = $signature_digest' \
          "$TMPDIR/changed-export-intermediate.json" \
          > "$TMPDIR/changed-export-receipt.json"
        changed_receipt_json="$(jq -c '.receipts[0].receipt' \
          "$TMPDIR/changed-export-receipt.json")"
        changed_receipt_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.signing-gate-receipt.v1alpha3'
          printf '%s' "$changed_receipt_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --compact-output \
          --arg receipt_digest "$changed_receipt_digest" \
          '.receipts[0].receipt_digest = $receipt_digest' \
          "$TMPDIR/changed-export-receipt.json" \
          > "$TMPDIR/changed-export.json"
        expect_rejection \
          changed-export-signature \
          'receipt signature does not verify against the reviewed public key and artifact digest' \
          "$TMPDIR/changed-export.json" \
          "$registry" \
          "$public_key" \
          "$boot_receipt" \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt"

        openssl genpkey \
          -algorithm RSA \
          -pkeyopt rsa_keygen_bits:2048 \
          -out "$TMPDIR/other-private.pem" \
          > /dev/null 2>&1
        openssl pkey \
          -in "$TMPDIR/other-private.pem" \
          -pubout \
          -out "$TMPDIR/other-public.pem"
        chmod 0400 "$TMPDIR/other-public.pem"
        expect_rejection \
          changed-public-key \
          'receipt export public_key_fingerprint does not match the reviewed public key' \
          "$receipt_export" \
          "$registry" \
          "$TMPDIR/other-public.pem" \
          "$boot_receipt" \
          "$eeprom_bootcode_receipt" \
          "$eeprom_bootsys_receipt" \
          "$eeprom_config_receipt" \
          "$owned_recovery_receipt"

        mkdir "$out"
        touch "$out/passed"
      '';

  signedReleaseFinalizationContract =
    assert lib.assertMsg (lib.isDerivation signedReleaseEvaluationFixture)
      "the signed-release factory rejected a complete verified public input graph";
    assert lib.assertMsg (
      signedReleaseReceiptVerificationInputAccepted signedReleaseReceiptVerificationEvaluationFixture
      && !(signedReleaseReceiptVerificationInputAccepted untypedSigningReceiptVerificationEvaluationFixture)
    ) "the signed-release factory accepted an untyped signing-receipt verification assertion";
    assert lib.assertMsg
      (
        let
          tool = built.signedReleaseTool.kaibaSignedReleaseTool;
          replay = tool.eepromReplayFinalizer.kaibaEEPROMReplayFinalizer;
          contract = signedReleaseEvaluationFixture.kaibaVerifiedSignedRelease;
        in
        tool.artifactRoleCount == 18
        && tool.authenticatedSigningReceiptCount == 5
        && tool.deterministicEEPROMReplayRequired
        && tool.deterministicOwnedRecoveryReplayRequired
        && tool.publicationSchemaVersion == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
        && tool.signingReceiptVerificationRequired
        && replay.verificationMode == "pinned_offline_replay"
        && contract.artifactRoleCount == 18
        && contract.authenticatedSigningReceiptCount == 5
        && contract.contentAddressedPublication
        && contract.deterministicEEPROMReplayRequired
        && contract.deterministicOwnedRecoveryReplayRequired
        &&
          contract.publicationSchemaVersion == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
        &&
          contract.signedReleaseManifestSchemaVersion
          == "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha2"
        && contract.verificationMode == "pure_offline_replay"
        && toString contract.verifiedRPIBootBundles == toString signedReleaseRPIBootBundleEvaluationFixture
        &&
          toString contract.signingReceiptVerification
          == toString signedReleaseReceiptVerificationEvaluationFixture
        && lib.all (value: value == false) [
          replay.approvalGateConfigured
          replay.blockDeviceWriteCapable
          replay.directHardwareAccess
          replay.eepromProgrammingCapable
          replay.mutationCapable
          replay.oneTimeSettingCapable
          replay.otpCapable
          replay.privateKeyAccess
          replay.signingAuthorityConfigured
          tool.blockDeviceWriteCapable
          tool.directHardwareAccess
          tool.eepromProgrammingCapable
          tool.mutationCapable
          tool.oneTimeSettingCapable
          tool.otpCapable
          tool.privateKeyAccess
          tool.signingAuthorityConfigured
          contract.blockDeviceWriteCapable
          contract.directHardwareAccess
          contract.eepromProgrammingCapable
          contract.fixtureHardwareObserved
          contract.mutationCapable
          contract.oneTimeSettingCapable
          contract.otpCapable
          contract.privateKeyAccess
          contract.signingAuthorityConfigured
        ]
      )
      "the signed-release finalization boundary gained signing, device, media, mutation, or observation authority";
    pkgs.runCommand "kaiba-rpi5-signed-release-finalization-contract"
      {
        nativeBuildInputs = [
          pkgs.binutils
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.gnugrep
          pkgs.go
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        export LC_ALL=C

        cd ${built.goSource}
        readonly focused_test_pattern='^(TestFinalizeVerifiesCompleteCrossBundleLineage|TestResolveRejectsBootPolicyAndSignedEEPROMConfigMismatch|TestResolveRejectsHistoricalBootPolicyForNewFinalization|TestResolveRejectsTreesOutsideCanonicalRPIBootBundleSet|TestResolveRequiresOwnedRecoveryUpdaterReplay|TestRetainedPublicationParentDetectsPathReplacement|TestTreePayloadLimitAccommodatesProductionRootImages|TestVerifyPublicationRejectsTamperingAndAdditions)$'
        go test ./internal/provisioning/signedrelease \
          -list "$focused_test_pattern" > "$TMPDIR/focused-tests.txt"
        test "$(grep -Ec "$focused_test_pattern" "$TMPDIR/focused-tests.txt")" -eq 8
        KAIBA_SIGNED_RELEASE_TEST_PUBLICATION="$TMPDIR/publication.json" \
          go test ./internal/provisioning/signedrelease \
            -run "$focused_test_pattern" \
            -count=1
        go test ./cmd/kaiba-provision-finalize-release \
          -run '^(TestRunPassesTheExactFixedInputSet|TestProductionDependenciesFailClosedWithoutLinkerPath)$' \
          -count=1
        go test ./internal/provisioning/rpibootbundle \
          -run '^TestSetRejectsWritableBundleRoot$' \
          -count=1

        readonly publication_schema=${built.goSource}/schemas/rpi5-signed-release-publication-v1alpha1.schema.json
        check-jsonschema --check-metaschema "$publication_schema"
        check-jsonschema \
          --schemafile "$publication_schema" \
          "$TMPDIR/publication.json"

        test -x ${built.signedReleaseTool}/bin/kaiba-provision-finalize-release
        strings ${built.signedReleaseTool}/bin/kaiba-provision-finalize-release \
          | grep -F '${built.signedReleaseTool.kaibaSignedReleaseTool.eepromReplayFinalizer}/bin/kaiba-provision-sign-eeprom' \
          > /dev/null
        if strings ${built.signedReleaseTool}/bin/kaiba-provision-finalize-release \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'signed-release finalizer links a physical provisioning capability' >&2
          exit 1
        fi

        set +e
        ${built.signedReleaseTool}/bin/kaiba-provision-finalize-release finalize \
          --release-intent /kaiba-contract/missing-release-intent \
          --unsigned-artifacts-manifest /kaiba-contract/missing-unsigned-manifest \
          --eeprom-release-manifest /kaiba-contract/missing-eeprom-release \
          --signed-boot /kaiba-contract/missing-signed-boot \
          --signed-eeprom /kaiba-contract/missing-signed-eeprom \
          --eeprom-replay-plan /kaiba-contract/missing-eeprom-plan \
          --eeprom-replay-signed /kaiba-contract/missing-eeprom-signed \
          --owned-recovery /kaiba-contract/missing-owned-recovery \
          --owned-replay-plan /kaiba-contract/missing-owned-plan \
          --owned-replay-signed /kaiba-contract/missing-owned-signed \
          --device-profile /kaiba-contract/missing-device-profile \
          --platform-adapter /kaiba-contract/missing-platform-adapter \
          --root-integrity /kaiba-contract/missing-root-integrity \
          --fresh-commit-bundle /kaiba-contract/bundles/fresh-commit \
          --fresh-readback-bundle /kaiba-contract/bundles/fresh-readback \
          --negative-boot-bundle /kaiba-contract/bundles/negative-boot \
          --owned-readback-bundle /kaiba-contract/bundles/owned-readback \
          --owned-recovery-bundle /kaiba-contract/bundles/owned-recovery \
          --root-integrity-test-bundle /kaiba-contract/bundles/root-integrity-test \
          --root-data-image /kaiba-contract/missing-root-data \
          --root-hash-tree-image /kaiba-contract/missing-root-hash \
          --output "$TMPDIR/missing-output" \
          > "$TMPDIR/packaged.stdout" 2> "$TMPDIR/packaged.stderr"
        readonly packaged_status="$?"
        set -e
        test "$packaged_status" -eq 1
        grep -F 'release intent:' "$TMPDIR/packaged.stderr" > /dev/null
        if grep -F 'signed-release finalizer configuration:' "$TMPDIR/packaged.stderr"; then
          echo 'signed-release finalizer is missing its linker-fixed EEPROM replay executable' >&2
          exit 1
        fi

        mkdir "$out"
        touch "$out/passed"
      '';

  signedReleaseManifestContract =
    pkgs.runCommand "kaiba-rpi5-signed-release-manifest-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.go
          pkgs.gnugrep
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"

        cd ${built.goSource}
        readonly focused_test_pattern='^(Test(New)?SignedRelease|TestDirectoryTree|TestSnapshotDirectoryTree)'
        go test ./internal/provisioning/bundle \
          -list "$focused_test_pattern" > "$TMPDIR/focused-tests.txt"
        grep -Eq "$focused_test_pattern" "$TMPDIR/focused-tests.txt"
        go test ./internal/provisioning/bundle \
          -run "$focused_test_pattern" \
          -count=1
        check-jsonschema --check-metaschema \
          ${built.goSource}/schemas/rpi5-rpiboot-directory-tree-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha2.schema.json

        readonly release_schema=${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha2.schema.json
        readonly golden_manifest=${built.goSource}/internal/provisioning/bundle/testdata/rpi5-signed-release-manifest-v1alpha2.json
        readonly tree_schema=${built.goSource}/schemas/rpi5-rpiboot-directory-tree-v1alpha1.schema.json
        readonly multibyte_tree=${built.goSource}/internal/provisioning/bundle/testdata/rpiboot-directory-tree-multibyte-v1alpha1.json
        check-jsonschema \
          --schemafile "$tree_schema" \
          "$multibyte_tree"
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile "$release_schema" \
          "$golden_manifest"

        jq 'del(.artifacts[-1])' "$golden_manifest" \
          > "$TMPDIR/missing-role.json"
        jq '.artifacts += [.artifacts[-1]]' "$golden_manifest" \
          > "$TMPDIR/duplicate-extra-role.json"
        jq '
          .artifacts[0] as $first
          | .artifacts[1] as $second
          | .artifacts[0] = $second
          | .artifacts[1] = $first
        ' "$golden_manifest" > "$TMPDIR/swapped-role-order.json"
        for invalid_manifest in \
          "$TMPDIR/missing-role.json" \
          "$TMPDIR/duplicate-extra-role.json" \
          "$TMPDIR/swapped-role-order.json"
        do
          if check-jsonschema \
            --base-uri file://${built.goSource}/schemas/ \
            --schemafile "$release_schema" \
            "$invalid_manifest"
          then
            echo "signed-release schema accepted invalid manifest: $invalid_manifest" >&2
            exit 1
          fi
        done

        mkdir -p "$out"
        touch "$out/passed"
      '';

  secureBootArtifactContract =
    assert lib.assertMsg (lib.all sourceRevisionAccepted validSourceRevisions)
      "the secure-boot artifact builder rejected a canonical Git source revision";
    assert lib.assertMsg (lib.all (sourceRevision: !(sourceRevisionAccepted sourceRevision))
      invalidSourceRevisions
    ) "the secure-boot artifact builder accepted a non-canonical source revision";
    assert lib.assertMsg
      (partitionGUIDsAccepted secureBootRootDataPartitionGUID secureBootRootHashPartitionGUID)
      "the secure-boot artifact builder rejected canonical distinct GPT partition GUIDs";
    assert lib.assertMsg (lib.all (value: !value) [
      (partitionGUIDsAccepted "/dev/nvme0n1p2" secureBootRootHashPartitionGUID)
      (partitionGUIDsAccepted "BDD5BE20-F7EA-56E7-AE90-4465AE950596" secureBootRootHashPartitionGUID)
      (partitionGUIDsAccepted "00000000-0000-0000-0000-000000000000" secureBootRootHashPartitionGUID)
      (partitionGUIDsAccepted secureBootRootDataPartitionGUID secureBootRootDataPartitionGUID)
    ]) "the secure-boot artifact builder accepted an unsafe GPT partition GUID binding";
    assert lib.assertMsg (
      secureBootFixtureA.kaibaUnsignedArtifacts.schemaVersion
      == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
      && secureBootFixtureA.kaibaUnsignedArtifacts.signingStatus == "unsigned"
      && lib.all (value: value == false) [
        secureBootFixtureA.kaibaUnsignedArtifacts.blockDeviceWriteCapable
        secureBootFixtureA.kaibaUnsignedArtifacts.directHardwareAccess
        secureBootFixtureA.kaibaUnsignedArtifacts.eepromProgrammingCapable
        secureBootFixtureA.kaibaUnsignedArtifacts.mutationCapable
        secureBootFixtureA.kaibaUnsignedArtifacts.oneTimeSettingCapable
        secureBootFixtureA.kaibaUnsignedArtifacts.otpCapable
        secureBootFixtureA.kaibaUnsignedArtifacts.privateKeyAccess
        secureBootFixtureA.kaibaUnsignedArtifacts.signingAuthorityConfigured
      ]
    ) "the unsigned artifact builder gained signing, hardware, or mutation capability";
    pkgs.runCommand "kaiba-secure-boot-artifact-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.cryptsetup
          pkgs.jq
          pkgs.mtools
        ];
      }
      ''
        set -euo pipefail
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/unsigned-artifact-set-v1alpha1.schema.json \
          ${secureBootFixtureA}/manifest.json
        test "$(jq -r .signing_status ${secureBootFixtureA}/manifest.json)" = unsigned
        test "$(jq -r .rollback_policy ${secureBootFixtureA}/manifest.json)" = \
          unimplemented-block-enrollment-ready
        test "$(jq -r .persistent_mutable_state ${secureBootFixtureA}/manifest.json)" = tmpfs-only
        test "$(jq -r .expected_customer_key_hash ${secureBootFixtureA}/manifest.json)" = \
          sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        test "$(jq -r .source_revision ${secureBootFixtureA}/manifest.json)" = \
          ${canonicalSourceRevision40}
        jq -e '
          .boot_image_size_bytes == 100663296
          and .firmware_allowlist == [
            "bcm2712-rpi-5-b.dtb",
            "cmdline.txt",
            "initramfs_2712",
            "kaiba-root-integrity.json",
            "kernel_2712.img",
            "overlays/README"
          ]
          and .verity.data_device == "PARTUUID=${secureBootRootDataPartitionGUID}"
          and .verity.hash_device == "PARTUUID=${secureBootRootHashPartitionGUID}"
          and .verity.mapper == "/dev/mapper/root"
          and .verity.algorithm == "sha256"
          and .boot_command_line_path == "cmdline.txt"
        ' ${secureBootFixtureA}/manifest.json > /dev/null
        canonical_manifest="$(jq --compact-output --sort-keys \
          'del(.bundle_digest)' ${secureBootFixtureA}/manifest.json)"
        expected_bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
          printf '%s' "$canonical_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .bundle_digest ${secureBootFixtureA}/manifest.json)" = \
          "$expected_bundle_digest"

        root_hash="$(jq -r .root_integrity_digest ${secureBootFixtureA}/manifest.json | cut -d: -f2)"
        veritysetup verify \
          ${secureBootFixtureA}/nvme/root-data.img \
          ${secureBootFixtureA}/nvme/root-hash.img \
          "$root_hash"
        mtype -i ${secureBootFixtureA}/unsigned/boot.img ::cmdline.txt \
          | grep -F "root=fstab rd.systemd.verity=1 roothash=$root_hash"
        mtype -i ${secureBootFixtureA}/unsigned/boot.img ::cmdline.txt \
          > "$TMPDIR/secure-boot-cmdline.txt"
        grep -F \
          'systemd.verity_root_data=PARTUUID=${secureBootRootDataPartitionGUID}' \
          "$TMPDIR/secure-boot-cmdline.txt"
        grep -F \
          'systemd.verity_root_hash=PARTUUID=${secureBootRootHashPartitionGUID}' \
          "$TMPDIR/secure-boot-cmdline.txt"
        if grep -F '/dev/nvme' "$TMPDIR/secure-boot-cmdline.txt"; then
          echo 'secure-boot command line contains an enumeration-dependent NVMe path' >&2
          exit 1
        fi
        if grep -Eq '(^|[[:space:]])rootfstype=' "$TMPDIR/secure-boot-cmdline.txt"; then
          echo 'secure-boot command line bypasses the sealed initrd fstab filesystem type' >&2
          exit 1
        fi
        mtype -i ${secureBootFixtureA}/unsigned/boot.img ::kaiba-root-integrity.json \
          | jq -e \
            --arg root_hash "$root_hash" \
            --arg data_device 'PARTUUID=${secureBootRootDataPartitionGUID}' \
            --arg hash_device 'PARTUUID=${secureBootRootHashPartitionGUID}' \
            '.root_hash == $root_hash
              and .data_device == $data_device
              and .hash_device == $hash_device
              and .no_superblock == false' \
          > /dev/null

        cmp ${secureBootFixtureA}/unsigned/boot.img ${secureBootFixtureB}/unsigned/boot.img
        cmp ${secureBootFixtureA}/nvme/root-data.img ${secureBootFixtureB}/nvme/root-data.img
        cmp ${secureBootFixtureA}/nvme/root-hash.img ${secureBootFixtureB}/nvme/root-hash.img
        test "$(jq -r .bundle_digest ${secureBootFixtureA}/manifest.json)" = \
          "$(jq -r .bundle_digest ${secureBootFixtureB}/manifest.json)"

        mkdir -p "$out"
        touch "$out/passed"
      '';

  signedBootPlanContract =
    assert lib.assertMsg (bootSigningPlanInputAccepted
      { }
    ) "the signed-boot plan factory rejected valid public store inputs";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        bootImage = "/tmp/kaiba-untrusted-boot.img";
      })
    ) "the signed-boot plan factory accepted a boot image outside the Nix store";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        reviewedPublicKeyPEM = "/tmp/kaiba-untrusted-public.pem";
      })
    ) "the signed-boot plan factory accepted a public key outside the Nix store";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        releaseIntent = "/tmp/kaiba-untrusted-release-intent";
      })
    ) "the signed-boot plan factory accepted a release intent outside the Nix store";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        planID = "Plan With Spaces";
      })
    ) "the signed-boot plan factory accepted a non-canonical plan ID";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        publicKeyFingerprint = "sha256:21BFCA39F5DB869C81F1FDAB5F1D2569BDD5E67EF07CCFE0E3B6DDD792A6CFE1";
      })
    ) "the signed-boot plan factory accepted a non-canonical public-key fingerprint";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        sourceDateEpoch = -1;
      })
    ) "the signed-boot plan factory accepted a negative source epoch";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        sourceDateEpoch = 253402300800;
      })
    ) "the signed-boot plan factory accepted an out-of-range source epoch";
    assert lib.assertMsg (
      !(bootSigningPlanInputAccepted {
        signerPolicyDigest = "sha256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
      })
    ) "the signed-boot plan factory accepted a non-canonical signer-policy digest";
    assert lib.assertMsg (verifiedSignedBootInputAccepted
      { }
    ) "the signed-boot finalizer factory rejected public store inputs";
    assert lib.assertMsg (
      !(verifiedSignedBootInputAccepted {
        signingPlan = "/tmp/kaiba-untrusted-signing-plan";
      })
    ) "the signed-boot finalizer factory accepted a plan outside the Nix store";
    assert lib.assertMsg (
      !(verifiedSignedBootInputAccepted {
        signedOutput = "/tmp/kaiba-untrusted-signed-output";
      })
    ) "the signed-boot finalizer factory accepted signed output outside the Nix store";
    pkgs.runCommand "kaiba-signed-boot-plan-contract"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.jq
          pkgs.openssl
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail

        find ${bootSigningPlanFixture} -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' boot.img plan.json public.pem release-intent.json \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"

        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-boot-signing-plan-v1alpha2.schema.json \
          ${bootSigningPlanFixture}/plan.json
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-release-intent-v1alpha1.schema.json \
          ${bootSigningPlanFixture}/release-intent.json
        cmp \
          ${bootReleaseIntentFixture}/release-intent.json \
          ${bootSigningPlanFixture}/release-intent.json

        cmp \
          ${secureBootFixtureA}/unsigned/boot.img \
          ${bootSigningPlanFixture}/boot.img
        cmp \
          ${./fixtures/development-boot-public.pem} \
          ${bootSigningPlanFixture}/public.pem
        test "$(jq -r .schema_version ${bootSigningPlanFixture}/plan.json)" = \
          'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2'
        test "$(jq -r .plan_id ${bootSigningPlanFixture}/plan.json)" = \
          'plan:rpi5-development-fixture:1'
        test "$(jq -r .public_key_fingerprint ${bootSigningPlanFixture}/plan.json)" = \
          '${developmentYubiKeyPublicKeyFingerprint}'
        test "$(jq -r .source_date_epoch ${bootSigningPlanFixture}/plan.json)" = \
          '1786968000'
        test "$(jq -r .signer_policy_digest ${bootSigningPlanFixture}/plan.json)" = \
          '${developmentYubiKeySignerPolicyDigest}'
        test "$(jq -r .boot_image_size_bytes ${bootSigningPlanFixture}/plan.json)" = \
          "$(stat --format=%s ${bootSigningPlanFixture}/boot.img)"
        test "$(jq -r .boot_image_digest ${bootSigningPlanFixture}/plan.json)" = \
          "sha256:$(sha256sum ${bootSigningPlanFixture}/boot.img | cut -d ' ' -f 1)"
        jq -e '
          keys == [
            "boot_image_digest",
            "boot_image_size_bytes",
            "plan_id",
            "public_key_fingerprint",
            "release_intent_digest",
            "schema_version",
            "signer_policy_digest",
            "source_date_epoch"
          ]
          and (.boot_image_size_bytes | type) == "number"
          and (.source_date_epoch | type) == "number"
        ' ${bootSigningPlanFixture}/plan.json > /dev/null

        openssl pkey \
          -pubin \
          -in ${bootSigningPlanFixture}/public.pem \
          -outform DER \
          -out "$TMPDIR/boot-signing-public.der"
        test "$(
          openssl pkey \
            -pubin \
            -in ${bootSigningPlanFixture}/public.pem \
            -text \
            -noout \
            | sed -n '1p'
        )" = 'Public-Key: (2048 bit)'
        openssl pkey \
          -pubin \
          -in ${bootSigningPlanFixture}/public.pem \
          -text \
          -noout \
          | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
        test "sha256:$(sha256sum "$TMPDIR/boot-signing-public.der" | cut -d ' ' -f 1)" = \
          '${developmentYubiKeyPublicKeyFingerprint}'

        test -x ${built.signedBootTool}/bin/kaiba-provision-sign-boot
        test -x ${built.rpibootBundleTool}/bin/kaiba-provision-rpiboot-bundles
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.privateKeyAccess}' = 'false'
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.signingAuthorityConfigured}' = 'false'
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.directHardwareAccess}' = 'false'
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.mutationCapable}' = 'false'
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.oneTimeSettingCapable}' = 'false'
        test '${builtins.toJSON built.signedBootTool.kaibaSignedBootTool.otpCapable}' = 'false'
        test '${builtins.toJSON bootSigningPlanFixture.kaibaBootSigningPlan.privateKeyAccess}' = 'false'
        test '${builtins.toJSON bootSigningPlanFixture.kaibaBootSigningPlan.signingAuthorityConfigured}' = 'false'
        test '${builtins.toJSON bootSigningPlanFixture.kaibaBootSigningPlan.mutationCapable}' = 'false'
        test '${bootSigningPlanFixture.kaibaBootSigningPlan.schemaVersion}' = \
          'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2'
        test '${bootSigningPlanFixture.kaibaBootSigningPlan.signerPolicyDigest}' = \
          '${developmentYubiKeySignerPolicyDigest}'
        test '${builtins.toJSON verifiedSignedBootEvaluationFixture.kaibaVerifiedSignedBoot.privateKeyAccess}' = \
          'false'
        test '${builtins.toJSON verifiedSignedBootEvaluationFixture.kaibaVerifiedSignedBoot.mutationCapable}' = \
          'false'
        test '${builtins.toJSON verifiedSignedBootEvaluationFixture.kaibaVerifiedSignedBoot.signatureVerificationRequired}' = \
          'true'
        test '${verifiedSignedBootEvaluationFixture.kaibaVerifiedSignedBoot.verificationMode}' = \
          'pure_offline'

        find ${verifiedSignedBootFixture} -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-final-files"
        printf '%s\n' \
          boot.img \
          boot.sig \
          manifest.json \
          public.pem \
          release-intent.json \
          signing-plan.json \
          signing-result.json \
          > "$TMPDIR/expected-final-files"
        cmp "$TMPDIR/expected-final-files" "$TMPDIR/actual-final-files"
        cmp ${signedBootFinalizerBootImage} ${verifiedSignedBootFixture}/boot.img
        cmp ${./fixtures/signed-boot-finalizer/boot.sig} ${verifiedSignedBootFixture}/boot.sig
        cmp ${signedBootFinalizerPublicKey} ${verifiedSignedBootFixture}/public.pem
        cmp \
          ${signedBootFinalizerReleaseIntent}/release-intent.json \
          ${verifiedSignedBootFixture}/release-intent.json
        cmp ${signedBootFinalizerPlan}/plan.json ${verifiedSignedBootFixture}/signing-plan.json
        cmp \
          ${signedBootFinalizerSignedOutput}/signing-result.json \
          ${verifiedSignedBootFixture}/signing-result.json
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-boot-signing-result-v1alpha2.schema.json \
          ${verifiedSignedBootFixture}/signing-result.json
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/secure-boot-bundle-v1alpha1.schema.json \
          ${verifiedSignedBootFixture}/manifest.json
        jq -e '
          .schema_version == "kaiba.provisioning.secure-boot-bundle/v1alpha1"
          and .manifest_id == "plan:rpi5-finalizer-fixture:1"
          and .device_class == "raspberry-pi-5"
          and .signing_policy_digest == "sha256:68498f57aa811b8a714260a4ac4390118c78efdb2af416cc64bfbd8eac4c42e3"
          and [.artifacts[].role] == [
            "boot_public_key",
            "rpi5.boot_image",
            "rpi5.boot_signature"
          ]
        ' ${verifiedSignedBootFixture}/manifest.json > /dev/null
        ${pkgs.bash}/bin/bash ${pkgs.raspberrypi-eeprom.src}/rpi-eeprom-digest \
          -k ${verifiedSignedBootFixture}/public.pem \
          -i ${verifiedSignedBootFixture}/boot.img \
          -v ${verifiedSignedBootFixture}/boot.sig
        SOURCE_DATE_EPOCH=1786968000 \
          ${pkgs.bash}/bin/bash ${pkgs.raspberrypi-eeprom.src}/rpi-eeprom-digest \
          -H ${signedBootFinalizerHSMWrapper} \
          -i ${verifiedSignedBootFixture}/boot.img \
          -o "$TMPDIR/upstream-boot.sig"
        cmp ${verifiedSignedBootFixture}/boot.sig "$TMPDIR/upstream-boot.sig"

        set +e
        ${built.signedBootTool}/bin/kaiba-provision-sign-boot sign \
          --plan ${bootSigningPlanFixture} \
          --output "$TMPDIR/generic-sign-output" \
          > "$TMPDIR/generic-sign.stdout" \
          2> "$TMPDIR/generic-sign.stderr"
        generic_sign_status="$?"
        set -e
        test "$generic_sign_status" -eq 1
        test ! -e "$TMPDIR/generic-sign-output"
        grep -F 'linker-fixed public-key fingerprint' \
          "$TMPDIR/generic-sign.stderr"

        mkdir -p "$out"
        touch "$out/passed"
      '';

  unfusedCapsuleContract =
    assert lib.assertMsg (verifiedUnfusedCapsuleInputAccepted
      { }
    ) "the unfused capsule factory rejected valid typed store inputs";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        verifiedSignedBoot = "/tmp/kaiba-untrusted-verified-signed-boot";
      })
    ) "the unfused capsule factory accepted a signed bundle outside the Nix store";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        unsignedArtifacts = "/tmp/kaiba-untrusted-unsigned-artifacts";
      })
    ) "the unfused capsule factory accepted root images outside the Nix store";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        capsuleID = "Capsule With Spaces";
      })
    ) "the unfused capsule factory accepted a non-canonical capsule ID";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        fixtureID = "fixture:rpi5:UPPERCASE";
      })
    ) "the unfused capsule factory accepted a non-canonical fixture ID";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        trustedPublicKeyFingerprint = "sha256:941775DDAEDDDBC068EE6802FD90E2CBBC606DBADBEFE2A743375DB4F0233A81";
      })
    ) "the unfused capsule factory accepted a non-canonical signer trust anchor";
    assert lib.assertMsg (
      !(verifiedUnfusedCapsuleInputAccepted {
        trustedPublicKeyFingerprint = developmentYubiKeyPublicKeyFingerprint;
      })
    ) "the unfused capsule factory accepted a mismatched signer trust anchor";
    assert lib.assertMsg (
      let
        contract = verifiedUnfusedCapsuleFixture.kaibaVerifiedUnfusedCapsule;
      in
      contract.dmVerityVerified
      && contract.fixtureSynthetic
      && contract.signatureVerificationRequired
      && contract.signerTrustAnchored
      && contract.evidenceMode == "offline_fixture"
      && contract.verificationMode == "pure_offline_synthetic_fixture"
      && lib.all (value: value == false) [
        contract.blockDeviceWriteCapable
        contract.directHardwareAccess
        contract.eepromProgrammingCapable
        contract.hardwareObservationClaim
        contract.mutationCapable
        contract.oneTimeSettingCapable
        contract.otpCapable
        contract.privateKeyAccess
        contract.securityEnforcementClaim
        contract.signingAuthorityConfigured
      ]
    ) "the unfused capsule derivation gained hardware, mutation, signing, or enforcement authority";
    pkgs.runCommand "kaiba-rpi5-unfused-capsule-contract"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.findutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        readonly bundle=${verifiedUnfusedCapsuleFixture}
        readonly capsule="$bundle/capsule"
        readonly manifest="$bundle/capsule-manifest.json"
        readonly fixture="$bundle/unfused-fixture.json"
        readonly result="$bundle/compatibility-result.json"
        readonly public_key="$bundle/public.pem"
        readonly verifier="${verifiedUnfusedCapsuleFixture.kaibaVerifiedUnfusedCapsule.unfusedVerifier}/bin/kaiba-provision-unfused-compat"

        find "$bundle" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-output-files"
        printf '%s\n' \
          capsule \
          capsule-manifest.json \
          compatibility-result.json \
          public.pem \
          unfused-fixture.json \
          > "$TMPDIR/expected-output-files"
        cmp "$TMPDIR/expected-output-files" "$TMPDIR/actual-output-files"

        find "$capsule" -type f -printf '%P\n' | sort \
          > "$TMPDIR/actual-capsule-files"
        printf '%s\n' \
          boot.img \
          boot.sig \
          nvme/root-data.img \
          nvme/root-hash.img \
          > "$TMPDIR/expected-capsule-files"
        cmp "$TMPDIR/expected-capsule-files" "$TMPDIR/actual-capsule-files"
        test "$(find "$capsule" -mindepth 1 -type d -printf '%P\n')" = nvme
        test -z "$(find "$bundle" -type l -print -quit)"
        test -z "$(find "$bundle" ! -type d ! -type f -print -quit)"

        cmp ${unfusedCapsuleVerifiedSignedBoot}/boot.img "$capsule/boot.img"
        cmp ${unfusedCapsuleVerifiedSignedBoot}/boot.sig "$capsule/boot.sig"
        cmp ${unfusedCapsuleVerifiedSignedBoot}/public.pem "$public_key"
        cmp \
          ${secureBootFixtureA}/nvme/root-data.img \
          "$capsule/nvme/root-data.img"
        cmp \
          ${secureBootFixtureA}/nvme/root-hash.img \
          "$capsule/nvme/root-hash.img"

        root_hash="$(jq -r .root_integrity_digest \
          ${secureBootFixtureA}/manifest.json | cut -d: -f2)"
        veritysetup verify \
          "$capsule/nvme/root-data.img" \
          "$capsule/nvme/root-hash.img" \
          "$root_hash"

        jq -e '
          keys == [
            "boot_image_path",
            "boot_signature_path",
            "capsule_digest",
            "capsule_id",
            "files",
            "root_data_path",
            "root_hash_path",
            "schema_version"
          ]
          and .schema_version
            == "provisioning.kaiba.network/rpi5-unfused-capsule-manifest/v1alpha1"
          and .capsule_id == "capsule:rpi5-unfused-fixture:1"
          and .boot_image_path == "boot.img"
          and .boot_signature_path == "boot.sig"
          and .root_data_path == "nvme/root-data.img"
          and .root_hash_path == "nvme/root-hash.img"
          and [.files[].path] == [
            "boot.img",
            "boot.sig",
            "nvme/root-data.img",
            "nvme/root-hash.img"
          ]
          and ([.files[].size_bytes | type] | all(. == "number"))
          and ([.files[].sha256]
            | all(test("^sha256:[0-9a-f]{64}$")))
        ' "$manifest" > /dev/null

        while IFS= read -r relative; do
          test "$(jq -r --arg path "$relative" \
            '.files[] | select(.path == $path) | .size_bytes' "$manifest")" = \
            "$(stat --format=%s "$capsule/$relative")"
          test "$(jq -r --arg path "$relative" \
            '.files[] | select(.path == $path) | .sha256' "$manifest")" = \
            "sha256:$(sha256sum "$capsule/$relative" | cut -d ' ' -f 1)"
        done < "$TMPDIR/expected-capsule-files"

        expected_capsule_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unfused-capsule.v1'
          while IFS= read -r relative; do
            printf '%s\0%s\0sha256:%s\0' \
              "$relative" \
              "$(stat --format=%s "$capsule/$relative")" \
              "$(sha256sum "$capsule/$relative" | cut -d ' ' -f 1)"
          done < "$TMPDIR/expected-capsule-files"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .capsule_digest "$manifest")" = \
          "$expected_capsule_digest"

        jq -e --slurpfile manifest "$manifest" '
          keys == [
            "boot_image_digest",
            "boot_mode",
            "boot_signature_digest",
            "capsule_digest",
            "capsule_id",
            "compatibility_marker_observed",
            "firmware_loaded",
            "fixture_id",
            "initramfs_started",
            "kernel_started",
            "root_data_digest",
            "root_hash_digest",
            "schema_version"
          ]
          and .schema_version
            == "provisioning.kaiba.network/rpi5-unfused-compatibility-fixture/v1alpha1"
          and .fixture_id == "fixture:rpi5-unfused-fixture:synthetic:1"
          and .capsule_id == $manifest[0].capsule_id
          and .capsule_digest == $manifest[0].capsule_digest
          and .boot_image_digest == $manifest[0].files[0].sha256
          and .boot_signature_digest == $manifest[0].files[1].sha256
          and .root_data_digest == $manifest[0].files[2].sha256
          and .root_hash_digest == $manifest[0].files[3].sha256
          and .boot_mode == "boot_ramdisk"
          and .firmware_loaded == true
          and .kernel_started == true
          and .initramfs_started == true
          and .compatibility_marker_observed == true
        ' "$fixture" > /dev/null

        jq -e --slurpfile manifest "$manifest" --slurpfile fixture "$fixture" '
          keys == [
            "boot_image_digest",
            "boot_public_key_fingerprint",
            "boot_signature_digest",
            "capsule_digest",
            "capsule_id",
            "evidence_mode",
            "files_verified",
            "fixture_digest",
            "fixture_id",
            "hardware_observed",
            "manifest_digest",
            "mutation_eligible",
            "root_data_digest",
            "root_hash_digest",
            "schema_version",
            "security_enforced",
            "signature_verification_receipt",
            "signature_verified",
            "signer_trust_anchored",
            "signer_trust_policy_digest",
            "status"
          ]
          and .schema_version
            == "provisioning.kaiba.network/rpi5-unfused-compatibility-result/v1alpha2"
          and .status == "compatibility_passed"
          and .evidence_mode == "offline_fixture"
          and .fixture_id == $fixture[0].fixture_id
          and .capsule_id == $manifest[0].capsule_id
          and .capsule_digest == $manifest[0].capsule_digest
          and .boot_image_digest == $manifest[0].files[0].sha256
          and .boot_signature_digest == $manifest[0].files[1].sha256
          and .root_data_digest == $manifest[0].files[2].sha256
          and .root_hash_digest == $manifest[0].files[3].sha256
          and .boot_public_key_fingerprint
            == "${unfusedCapsulePublicKeyFingerprint}"
          and (.manifest_digest | test("^sha256:[0-9a-f]{64}$"))
          and (.fixture_digest | test("^sha256:[0-9a-f]{64}$"))
          and (.signature_verification_receipt | test("^sha256:[0-9a-f]{64}$"))
          and (.signer_trust_policy_digest | test("^sha256:[0-9a-f]{64}$"))
          and .files_verified == 4
          and .signature_verified == true
          and .signer_trust_anchored == true
          and .hardware_observed == false
          and .security_enforced == false
          and .mutation_eligible == false
        ' "$result" > /dev/null

        cp -R --no-preserve=ownership "$capsule" "$TMPDIR/tampered-capsule"
        chmod u+w "$TMPDIR/tampered-capsule/nvme/root-hash.img"
        printf 'X' | dd \
          of="$TMPDIR/tampered-capsule/nvme/root-hash.img" \
          bs=1 \
          seek=0 \
          conv=notrunc \
          status=none
        set +e
        "$verifier" verify-signed-offline-fixture \
          --manifest "$manifest" \
          --capsule-root "$TMPDIR/tampered-capsule" \
          --fixture "$fixture" \
          --public-key "$public_key" \
          > "$TMPDIR/tampered.stdout" \
          2> "$TMPDIR/tampered.stderr"
        tampered_status="$?"
        set -e
        test "$tampered_status" -eq 3
        test ! -s "$TMPDIR/tampered.stdout"
        grep -F 'digest does not match the capsule manifest' \
          "$TMPDIR/tampered.stderr"

        mkdir -p "$out"
        touch "$out/passed"
      '';

  mediaStagingFixtureContract =
    assert lib.assertMsg
      (
        let
          contract = mediaStagingFixture.kaibaMediaStagingFixture;
        in
        contract.verifiedCapsule == verifiedUnfusedCapsuleFixture
        && contract.mediaStager == built.mediaStager
        && contract.bootFilesystemSizeMiB == 128
        && contract.alignmentBytes == 1048576
        && contract.sectorSizeBytes == 512
        && contract.fixtureFileWriteCapable
        && contract.snapshotExclusiveLockRequired
        && contract.snapshotPinnedRegularFile
        && contract.fixtureSnapshot.kaibaFixtureSnapshot.regularFileOnly
        && contract.fixtureSnapshot.kaibaFixtureSnapshot.destinationFileWriteCapable
        && lib.all (value: value == false) [
          contract.fixtureSnapshot.kaibaFixtureSnapshot.blockDeviceAccess
          contract.fixtureSnapshot.kaibaFixtureSnapshot.directHardwareAccess
          contract.fixtureSnapshot.kaibaFixtureSnapshot.mutationCapable
          contract.fixtureSnapshot.kaibaFixtureSnapshot.sourceWriteCapable
        ]
        && lib.all (value: value == false) [
          contract.blockDeviceAccess
          contract.blockDeviceWriteCapable
          contract.coldPowerCycleClaim
          contract.gptBoundByStagerReceipt
          contract.hardwareObservationClaim
          contract.mutationCapable
          contract.oneTimeSettingCapable
          contract.otpCapable
          contract.securityEnforcementClaim
        ]
      )
      "the media-staging fixture gained block-device, hardware, enforcement, or one-time-setting authority";
    pkgs.runCommand "kaiba-rpi5-media-staging-fixture-contract"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.diffutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.gptfdisk
          pkgs.jq
          pkgs.mtools
          pkgs.util-linux
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        readonly fixture=${mediaStagingFixture}
        readonly fixture_tool="$fixture/bin/kaiba-provision-media-fixture"
        readonly media_stager=${built.mediaStager}/bin/kaiba-provision-media-stager
        readonly boot_filesystem="$fixture/boot-filesystem.img"
        readonly gpt_template="$fixture/gpt-template.img"
        readonly layout="$fixture/layout.json"
        readonly gpt_template_source="$(jq -r .gpt.template_path "$layout")"
        readonly boot_source="$(jq -r \
          '.images[] | select(.role == "boot-filesystem") | .source_path' \
          "$layout")"
        readonly capsule=${verifiedUnfusedCapsuleFixture}/capsule
        readonly capsule_manifest=${verifiedUnfusedCapsuleFixture}/capsule-manifest.json
        readonly workspace="$TMPDIR/media-fixture-workspace"

        test -x "$fixture_tool"
        test -x "$media_stager"
        test -f "$boot_filesystem"
        test -s "$boot_filesystem"
        test -f "$gpt_template"
        test -s "$gpt_template"
        test -f "$gpt_template_source"
        test ! -L "$gpt_template_source"
        test "$(readlink -f "$gpt_template")" = "$gpt_template_source"
        test -f "$layout"
        test -s "$layout"
        test -f "$boot_source"
        test ! -L "$boot_source"
        cmp "$boot_source" "$boot_filesystem"

        find "$fixture" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-fixture-entries"
        printf '%s\n' \
          bin \
          boot-filesystem.img \
          gpt-template.img \
          layout.json \
          > "$TMPDIR/expected-fixture-entries"
        cmp "$TMPDIR/expected-fixture-entries" "$TMPDIR/actual-fixture-entries"
        test "$(find "$fixture/bin" -mindepth 1 -maxdepth 1 -printf '%f\n')" = \
          kaiba-provision-media-fixture

        mdir -b -i "$boot_filesystem" :: \
          | sed 's#^::/##' \
          | sort > "$TMPDIR/actual-boot-files"
        printf '%s\n' boot.img boot.sig config.txt \
          > "$TMPDIR/expected-boot-files"
        cmp "$TMPDIR/expected-boot-files" "$TMPDIR/actual-boot-files"
        test "$(mtype -i "$boot_filesystem" ::config.txt | tr -d '\r')" = \
          'boot_ramdisk=1'
        mcopy -n -i "$boot_filesystem" ::boot.img "$TMPDIR/outer-boot.img"
        mcopy -n -i "$boot_filesystem" ::boot.sig "$TMPDIR/outer-boot.sig"
        cmp "$capsule/boot.img" "$TMPDIR/outer-boot.img"
        cmp "$capsule/boot.sig" "$TMPDIR/outer-boot.sig"

        ${pkgs.coreutils}/bin/env -i \
          LC_ALL=C \
          PATH="$TMPDIR/empty-path" \
          TMPDIR="$TMPDIR" \
          "$fixture_tool" init --workspace "$workspace" \
          > "$TMPDIR/init.json"
        jq -e \
          --arg workspace "$workspace" \
          --arg layout_digest "$(jq -r .layout_digest "$layout")" \
          '
            keys == [
              "block_device_access",
              "evidence_mode",
              "layout_digest",
              "one_time_settings_changed",
              "plan",
              "status",
              "target",
              "workspace"
            ]
            and .status == "fixture_initialized"
            and .evidence_mode == "regular_file_fixture"
            and .workspace == $workspace
            and .target == ($workspace + "/target.img")
            and .plan == ($workspace + "/fixture-plan.json")
            and .layout_digest == $layout_digest
            and .block_device_access == false
            and .one_time_settings_changed == false
          ' "$TMPDIR/init.json" > /dev/null
        test -d "$workspace"
        test ! -L "$workspace"
        find "$workspace" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-workspace-files"
        printf '%s\n' fixture-plan.json target.img \
          > "$TMPDIR/expected-workspace-files"
        cmp "$TMPDIR/expected-workspace-files" "$TMPDIR/actual-workspace-files"

        readonly plan="$workspace/fixture-plan.json"
        readonly target="$workspace/target.img"
        cmp "$gpt_template" "$target"
        test "$(stat --format=%a "$plan")" = 600
        test -f "$plan"
        test ! -L "$plan"
        test -s "$plan"
        test -f "$target"
        test ! -L "$target"

        jq -e \
          --arg target "$target" \
          --arg boot_filesystem "$boot_source" \
          --arg root_data "$capsule/nvme/root-data.img" \
          --arg root_hash "$capsule/nvme/root-hash.img" \
          '
            keys == ["images", "schema_version", "target"]
            and .schema_version
              == "provisioning.kaiba.network/media-staging-plan/v1alpha1"
            and (.target | keys)
              == ["expected_identity", "expected_size_bytes", "path"]
            and .target.path == $target
            and .target.expected_identity == "target.img"
            and .target.expected_size_bytes > 0
            and [.images[].role]
              == ["boot-filesystem", "root-data", "root-hash"]
            and [.images[].path]
              == [$boot_filesystem, $root_data, $root_hash]
            and ([.images[] | keys]
              | all(. == ["digest", "offset_bytes", "path", "role", "size_bytes"]))
            and ([.images[].digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and ([.images[].size_bytes] | all(. > 0))
            and ([.images[].offset_bytes] | all(. >= 1048576 and . % 4096 == 0))
            and .images[0].offset_bytes + .images[0].size_bytes
              <= .images[1].offset_bytes
            and .images[1].offset_bytes + .images[1].size_bytes
              <= .images[2].offset_bytes
            and .images[2].offset_bytes + .images[2].size_bytes
              <= .target.expected_size_bytes
          ' "$plan" > /dev/null
        test "$(stat --format=%s "$target")" = \
          "$(jq -r .target.expected_size_bytes "$plan")"

        for index in 0 1 2; do
          source="$(jq -r ".images[$index].path" "$plan")"
          test -f "$source"
          test ! -L "$source"
          test "$(stat --format=%s "$source")" = \
            "$(jq -r ".images[$index].size_bytes" "$plan")"
          test "sha256:$(sha256sum "$source" | cut -d ' ' -f 1)" = \
            "$(jq -r ".images[$index].digest" "$plan")"
        done

        jq -e \
          --arg gpt_template "$gpt_template_source" \
          --slurpfile plan "$plan" \
          --slurpfile capsule_manifest "$capsule_manifest" \
          '
            keys == [
              "alignment_bytes",
              "boot_filesystem",
              "capsule",
              "evidence_mode",
              "fixture_id",
              "gpt",
              "images",
              "layout_digest",
              "safety",
              "schema_version",
              "sector_size_bytes",
              "target_size_bytes",
              "verity"
            ]
            and .schema_version
              == "provisioning.kaiba.network/rpi5-media-staging-fixture/v1alpha1"
            and .fixture_id
              == ($capsule_manifest[0].capsule_id + ":media-staging-fixture")
            and .evidence_mode == "regular_file_fixture"
            and .capsule.capsule_id == $capsule_manifest[0].capsule_id
            and .capsule.capsule_digest == $capsule_manifest[0].capsule_digest
            and (.capsule.manifest_file_digest
              | test("^sha256:[0-9a-f]{64}$"))
            and (.layout_digest | test("^sha256:[0-9a-f]{64}$"))
            and .sector_size_bytes == 512
            and .alignment_bytes == 1048576
            and .target_size_bytes == $plan[0].target.expected_size_bytes
            and (.gpt.disk_guid
              | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$"))
            and .gpt.template_path == $gpt_template
            and (.gpt.template_digest | test("^sha256:[0-9a-f]{64}$"))
            and .gpt.backup_reserved_bytes == 1048576
            and .gpt.first_usable_lba == 34
            and .gpt.last_usable_lba
              == (.target_size_bytes / .sector_size_bytes - 34)
            and [.gpt.metadata_regions[].role] == ["primary", "backup"]
            and [.gpt.metadata_regions[].offset_bytes]
              == [0, (.target_size_bytes - .alignment_bytes)]
            and [.gpt.metadata_regions[].size_bytes]
              == [.alignment_bytes, .alignment_bytes]
            and ([.gpt.metadata_regions[].digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and .gpt.partitions[0].offset_bytes == .alignment_bytes
            and .gpt.partitions[1].offset_bytes
              == (.gpt.partitions[0].offset_bytes
                + .gpt.partitions[0].partition_size_bytes)
            and .gpt.partitions[2].offset_bytes
              == (.gpt.partitions[1].offset_bytes
                + .gpt.partitions[1].partition_size_bytes)
            and .gpt.metadata_regions[1].offset_bytes
              == (.gpt.partitions[2].offset_bytes
                + .gpt.partitions[2].partition_size_bytes)
            and (.gpt.metadata_regions[1].offset_bytes
              + .gpt.metadata_regions[1].size_bytes) == .target_size_bytes
            and [.gpt.partitions[].number] == [1, 2, 3]
            and [.gpt.partitions[].attributes] == [null, null, null]
            and ([.gpt.partitions[].content_digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and [.gpt.partitions[].name]
              == ["kaiba-boot", "kaiba-root", "kaiba-root-verity"]
            and [.gpt.partitions[].role]
              == ["boot-filesystem", "root-data", "root-hash"]
            and [.gpt.partitions[].type_code] == ["ef00", "8305", "830e"]
            and [.gpt.partitions[].offset_bytes]
              == [$plan[0].images[].offset_bytes]
            and ([.gpt.partitions[].partition_size_bytes] | all(. > 0))
            and ([.gpt.partitions[].unique_guid]
              | all(test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$")))
            and .boot_filesystem.filesystem == "fat32"
            and .boot_filesystem.label == "KAIBA_BOOT"
            and .boot_filesystem.volume_id == "4b414942"
            and [.boot_filesystem.allowlist[].path]
              == ["boot.img", "boot.sig", "config.txt"]
            and ([.boot_filesystem.allowlist[].digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and [.images[].role]
              == ["boot-filesystem", "root-data", "root-hash"]
            and [.images[].source_path] == [$plan[0].images[].path]
            and [.images[].digest] == [$plan[0].images[].digest]
            and [.images[].size_bytes] == [$plan[0].images[].size_bytes]
            and [.images[].offset_bytes] == [$plan[0].images[].offset_bytes]
            and .verity.algorithm == "sha256"
            and (.verity.root_hash | test("^sha256:[0-9a-f]{64}$"))
            and .verity.data_block_size == 4096
            and .verity.hash_block_size == 4096
            and .safety == {
              synthetic: true,
              block_device_access: false,
              hardware_observed: false,
              security_enforced: false,
              mutation_eligible: false,
              one_time_settings_changed: false,
              gpt_bound_by_stager_receipt: false,
              cold_power_cycle_observed: false
            }
          ' "$layout" > /dev/null
        jq --compact-output --sort-keys 'del(.layout_digest)' "$layout" \
          > "$TMPDIR/canonical-layout"
        expected_layout_digest="sha256:$({
          printf '%s\0' \
            'kaiba.provisioning.rpi5-media-staging-fixture.v1alpha1'
          cat "$TMPDIR/canonical-layout"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .layout_digest "$layout")" = "$expected_layout_digest"
        test "sha256:$(sha256sum "$gpt_template" | cut -d ' ' -f 1)" = \
          "$(jq -r .gpt.template_digest "$layout")"

        sgdisk --verify "$target" > "$TMPDIR/gpt-before.txt"
        dd if="$target" of="$TMPDIR/primary-gpt.before" \
          bs=1M count=1 status=none
        target_size="$(stat --format=%s "$target")"
        dd if="$target" of="$TMPDIR/backup-gpt.before" \
          bs=1M skip="$((target_size - 1048576))" count=1 \
          iflag=skip_bytes status=none
        test "sha256:$(sha256sum "$TMPDIR/primary-gpt.before" | cut -d ' ' -f 1)" = \
          "$(jq -r '.gpt.metadata_regions[] | select(.role == "primary") | .digest' "$layout")"
        test "sha256:$(sha256sum "$TMPDIR/backup-gpt.before" | cut -d ' ' -f 1)" = \
          "$(jq -r '.gpt.metadata_regions[] | select(.role == "backup") | .digest' "$layout")"

        "$media_stager" fixture-dry-run --plan "$plan" \
          > "$TMPDIR/dry-run.json"
        "$media_stager" fixture-stage --plan "$plan" \
          > "$TMPDIR/stage.json"
        "$media_stager" fixture-readback --plan "$plan" \
          > "$TMPDIR/readback.json"

        dd if="$target" of="$TMPDIR/primary-gpt.after" \
          bs=1M count=1 status=none
        dd if="$target" of="$TMPDIR/backup-gpt.after" \
          bs=1M skip="$((target_size - 1048576))" count=1 \
          iflag=skip_bytes status=none
        cmp "$TMPDIR/primary-gpt.before" "$TMPDIR/primary-gpt.after"
        cmp "$TMPDIR/backup-gpt.before" "$TMPDIR/backup-gpt.after"
        sgdisk --verify "$target" > "$TMPDIR/gpt-after.txt"

        jq -e -s \
          --slurpfile plan "$plan" \
          '
            length == 3
            and ([.[].schema_version]
              | all(. == "provisioning.kaiba.network/media-staging-result/v1alpha1"))
          ' \
          "$TMPDIR/dry-run.json" \
          "$TMPDIR/stage.json" \
          "$TMPDIR/readback.json" > /dev/null
        jq -e -s \
          --slurpfile plan "$plan" \
          '
            [.[].action] == ["dry_run", "stage", "readback"]
            and [.[].status] == [
              "validated_no_write",
              "fsync_complete_readback_required",
              "reopened_readback_verified"
            ]
            and ([.[].plan_digest] | unique | length) == 1
            and ([.[].plan_digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and ([.[].receipt_digest] | unique | length) == 3
            and ([.[].receipt_digest]
              | all(test("^sha256:[0-9a-f]{64}$")))
            and ([.[].target_path]
              | all(. == $plan[0].target.path))
          ' \
          "$TMPDIR/dry-run.json" \
          "$TMPDIR/stage.json" \
          "$TMPDIR/readback.json" > /dev/null
        jq -e -s \
          --slurpfile plan "$plan" \
          '
            ([.[].target_identity]
              | all(. == $plan[0].target.expected_identity))
            and ([.[].target_size_bytes]
              | all(. == $plan[0].target.expected_size_bytes))
            and ([.[].images]
              | all(. == ($plan[0].images | map(del(.path)))))
            and [.[].reopened_target] == [false, false, true]
            and ([.[].cold_power_cycle_observed] | all(. == false))
            and ([.[].one_time_settings_changed] | all(. == false))
          ' \
          "$TMPDIR/dry-run.json" \
          "$TMPDIR/stage.json" \
          "$TMPDIR/readback.json" > /dev/null

        for index in 0 1 2; do
          source="$(jq -r ".images[$index].path" "$plan")"
          offset="$(jq -r ".images[$index].offset_bytes" "$plan")"
          size="$(jq -r ".images[$index].size_bytes" "$plan")"
          dd if="$target" of="$TMPDIR/staged-$index.img" \
            bs=1M skip="$offset" count="$size" \
            iflag=skip_bytes,count_bytes status=none
          cmp "$source" "$TMPDIR/staged-$index.img"
        done

        mdir -b -i "$TMPDIR/staged-0.img" :: \
          | sed 's#^::/##' \
          | sort > "$TMPDIR/actual-staged-boot-files"
        cmp "$TMPDIR/expected-boot-files" "$TMPDIR/actual-staged-boot-files"
        test "$(mtype -i "$TMPDIR/staged-0.img" ::config.txt | tr -d '\r')" = \
          'boot_ramdisk=1'
        root_hash="$(jq -r .verity.root_hash "$layout")"
        test "$root_hash" = "$(jq -r .root_integrity_digest \
          ${secureBootFixtureA}/manifest.json)"
        veritysetup verify \
          --data-block-size="$(jq -r .verity.data_block_size "$layout")" \
          --hash-block-size="$(jq -r .verity.hash_block_size "$layout")" \
          "$TMPDIR/staged-1.img" \
          "$TMPDIR/staged-2.img" \
          "''${root_hash#sha256:}"

        cp "$plan" "$TMPDIR/original-fixture-plan.json"
        sed 's/schema_version/schema_versioN/' "$plan" \
          > "$TMPDIR/unexpected-fixture-plan.json"
        install -m 0400 "$TMPDIR/unexpected-fixture-plan.json" "$plan"
        if ${pkgs.coreutils}/bin/env -i \
          LC_ALL=C \
          PATH="$TMPDIR/empty-path" \
          TMPDIR="$TMPDIR" \
          "$fixture_tool" verify --workspace "$workspace" \
          > "$TMPDIR/unexpected-plan.json" \
          2> "$TMPDIR/unexpected-plan.stderr"
        then
          echo 'fixture verifier accepted a plan with an unknown field' >&2
          exit 1
        fi
        grep -Fqx \
          'kaiba-provision-media-fixture: fixture plan differs from the immutable layout' \
          "$TMPDIR/unexpected-plan.stderr"
        install -m 0400 "$TMPDIR/original-fixture-plan.json" "$plan"

        exec {fixture_lock_fd}<>"$target"
        flock --exclusive --nonblock "$fixture_lock_fd"
        if ${pkgs.coreutils}/bin/env -i \
          LC_ALL=C \
          PATH="$TMPDIR/empty-path" \
          TMPDIR="$TMPDIR" \
          "$fixture_tool" verify --workspace "$workspace" \
          > "$TMPDIR/locked-target.json" \
          2> "$TMPDIR/locked-target.stderr"
        then
          echo 'fixture verifier accepted an exclusively locked target' >&2
          exit 1
        fi
        grep -Fq 'source fixture is busy' "$TMPDIR/locked-target.stderr"
        flock --unlock "$fixture_lock_fd"
        exec {fixture_lock_fd}>&-

        ${pkgs.coreutils}/bin/env -i \
          LC_ALL=C \
          PATH="$TMPDIR/empty-path" \
          TMPDIR="$TMPDIR" \
          "$fixture_tool" verify --workspace "$workspace" \
          > "$TMPDIR/verification.json"
        jq -e \
          --slurpfile layout "$layout" \
          '
            keys == [
              "cold_power_cycle_observed",
              "dm_verity_verified",
              "evidence_mode",
              "extent_digests_verified",
              "fat_allowlist_verified",
              "gpt_verified",
              "hardware_observed",
              "layout_digest",
              "mutation_eligible",
              "one_time_settings_changed",
              "partition_contents_verified",
              "pinned_regular_file_snapshot_verified",
              "security_enforced",
              "status"
            ]
            and .status == "fixture_layout_verified"
            and .evidence_mode == "regular_file_fixture"
            and .layout_digest == $layout[0].layout_digest
            and .gpt_verified == true
            and .fat_allowlist_verified == true
            and .extent_digests_verified == true
            and .dm_verity_verified == true
            and .partition_contents_verified == true
            and .pinned_regular_file_snapshot_verified == true
            and .hardware_observed == false
            and .security_enforced == false
            and .mutation_eligible == false
            and .cold_power_cycle_observed == false
            and .one_time_settings_changed == false
          ' "$TMPDIR/verification.json" > /dev/null

        root_hash_padding_offset=$((
          $(jq -r '.images[] | select(.role == "root-hash") | .offset_bytes' "$layout")
          + $(jq -r '.images[] | select(.role == "root-hash") | .size_bytes' "$layout")
        ))
        root_hash_partition_end=$((
          $(jq -r '.gpt.partitions[] | select(.role == "root-hash") | .offset_bytes' "$layout")
          + $(jq -r '.gpt.partitions[] | select(.role == "root-hash") | .partition_size_bytes' "$layout")
        ))
        readonly root_hash_padding_offset root_hash_partition_end
        test "$root_hash_padding_offset" -lt "$root_hash_partition_end"
        printf '\377' | dd of="$target" bs=1 \
          seek="$root_hash_padding_offset" count=1 conv=notrunc status=none
        if ${pkgs.coreutils}/bin/env -i \
          LC_ALL=C \
          PATH="$TMPDIR/empty-path" \
          TMPDIR="$TMPDIR" \
          "$fixture_tool" verify --workspace "$workspace" \
          > "$TMPDIR/nonzero-padding.json" \
          2> "$TMPDIR/nonzero-padding.stderr"
        then
          echo 'fixture verifier accepted nonzero root-hash partition padding' >&2
          exit 1
        fi
        grep -Fqx \
          'kaiba-provision-media-fixture: root-hash partition content differs from the immutable layout' \
          "$TMPDIR/nonzero-padding.stderr"
        printf '\000' | dd of="$target" bs=1 \
          seek="$root_hash_padding_offset" count=1 conv=notrunc status=none

        expect_gpt_rejection() {
          local label="$1"
          local region="$2"
          if ${pkgs.coreutils}/bin/env -i \
            LC_ALL=C \
            PATH="$TMPDIR/empty-path" \
            TMPDIR="$TMPDIR" \
            "$fixture_tool" verify --workspace "$workspace" \
            > "$TMPDIR/$label.json" \
            2> "$TMPDIR/$label.stderr"
          then
            echo "fixture verifier accepted invalid GPT: $label" >&2
            exit 1
          fi
          grep -Fqx \
            "kaiba-provision-media-fixture: $region GPT metadata differs from the immutable layout" \
            "$TMPDIR/$label.stderr"
        }

        dd if=/dev/zero of="$target" bs=1 seek=512 count=8 \
          conv=notrunc status=none
        expect_gpt_rejection corrupt-primary-gpt primary
        dd if="$TMPDIR/primary-gpt.after" of="$target" bs=1M count=1 \
          conv=notrunc status=none
        sgdisk --verify "$target" > /dev/null

        dd if=/dev/zero of="$target" bs=1 \
          seek="$((target_size - 512))" count=8 conv=notrunc status=none
        expect_gpt_rejection corrupt-backup-gpt backup
        dd if="$TMPDIR/backup-gpt.after" of="$target" bs=1M \
          seek="$((target_size - 1048576))" count=1 \
          oflag=seek_bytes conv=notrunc status=none
        sgdisk --verify "$target" > /dev/null

        sgdisk --attributes=2:set:63 "$target" > /dev/null
        sgdisk --verify "$target" > /dev/null
        expect_gpt_rejection unexpected-partition-attribute primary
        sgdisk --attributes=2:clear:63 "$target" > /dev/null
        sgdisk --verify "$target" > /dev/null

        sector_size="$(jq -r .sector_size_bytes "$layout")"
        root_hash_start=$(( $(jq -r '.gpt.partitions[] | select(.number == 3) | .offset_bytes' "$layout") / sector_size ))
        root_hash_size=$(( $(jq -r '.gpt.partitions[] | select(.number == 3) | .partition_size_bytes' "$layout") / sector_size ))
        root_hash_end=$((root_hash_start + root_hash_size - 1))
        readonly sector_size root_hash_start root_hash_size root_hash_end
        sgdisk \
          --delete=3 \
          --new=4:"$root_hash_start":"$root_hash_end" \
          --typecode=4:"$(jq -r '.gpt.partitions[] | select(.number == 3) | .type_code' "$layout")" \
          --change-name=4:"$(jq -r '.gpt.partitions[] | select(.number == 3) | .name' "$layout")" \
          --partition-guid=4:"$(jq -r '.gpt.partitions[] | select(.number == 3) | .unique_guid' "$layout")" \
          "$target" > /dev/null
        sgdisk --verify "$target" > /dev/null
        expect_gpt_rejection wrong-partition-number primary

        mkdir -p "$out"
        touch "$out/passed"
      '';

  productionMediaStagingContract =
    assert lib.assertMsg
      (
        let
          contract = productionMediaFixture.kaibaRpi5ProductionMedia;
          alternateHardwareContract = productionMediaAlternateHardwareFixture.kaibaRpi5ProductionMedia;
          assetsContract = contract.assets.kaibaRpi5ProductionMediaAssets;
          stager = contract.deviceStager.kaibaMediaDeviceStager;
          verifier = contract.deviceVerifier.kaibaMediaDeviceVerifier;
          fixtureStager = contract.fixtureStager.kaibaMediaFixtureStager;
          fixtureVerifier = contract.regularVerifier.kaibaMediaRegularVerifier;
          hardwareWithDevicePath =
            devicePath:
            productionMediaHardwareConfiguration
            // {
              targetMedia = productionMediaHardwareConfiguration.targetMedia // {
                inherit devicePath;
              };
            };
        in
        productionMediaInputAccepted productionMediaSignedReleaseFixture
        && !(productionMediaInputAccepted spoofedSignedRelease)
        &&
          builtins.attrNames hardwareConfigurations == [
            "malakRaspberryPi5SacrificialDevelopmentUsbSd"
            "raspberryPi5SacrificialDevelopmentPiLocalNvme"
          ]
        &&
          builtins.attrNames productionMediaHardwareConfiguration == [
            "configurationID"
            "executionHost"
            "schemaVersion"
            "targetMedia"
          ]
        && builtins.attrNames productionMediaHardwareConfiguration.executionHost == [ "hostname" ]
        &&
          builtins.attrNames productionMediaHardwareConfiguration.targetMedia == [
            "devicePath"
            "protectedDevicePaths"
          ]
        &&
          productionMediaHardwareConfiguration.schemaVersion
          == "kaiba.provisioning.hardware-configuration/v1alpha2"
        &&
          productionMediaHardwareConfiguration.configurationID
          == "hardware-configuration:malak-rpi5-sacrificial-development-usb-sd:1"
        && productionMediaHardwareConfiguration.executionHost.hostname == "malak"
        &&
          productionMediaHardwareConfiguration.targetMedia.devicePath
          == "/dev/disk/by-path/pci-0000:0e:00.3-usb-0:4:1.0-scsi-0:0:0:0"
        && productionMediaHardwareConfiguration.targetMedia.protectedDevicePaths == [ "/dev/nvme0n1" ]
        &&
          productionMediaAlternateHardwareConfiguration.configurationID
          == "hardware-configuration:rpi5-sacrificial-development-pi-local-nvme:1"
        && productionMediaAlternateHardwareConfiguration.executionHost.hostname == "kaiba-rpi5-provisioner"
        && productionMediaAlternateHardwareConfiguration.targetMedia.devicePath == "/dev/nvme0n1"
        && productionMediaAlternateHardwareConfiguration.targetMedia.protectedDevicePaths == [ ]
        && productionMediaTargetInputAccepted { }
        && !(productionMediaTargetInputAccepted { model = "must-not-bind-media-model"; })
        && !(productionMediaTargetInputAccepted { devicePath = "/dev/nvme0n1"; })
        && !(productionMediaTargetInputAccepted { logicalSectorSizeBytes = 4096; })
        && !(productionMediaTargetInputAccepted { sizeBytes = 8388096; })
        && !(productionMediaTargetInputAccepted { sizeBytes = 9223372036854775807; })
        && productionMediaHardwareConfigurationInputAccepted productionMediaHardwareConfiguration
        && productionMediaHardwareConfigurationInputAccepted productionMediaAlternateHardwareConfiguration
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration // { schemaVersion = "unsupported"; }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration // { configurationID = "NOT-CANONICAL"; }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration // { model = "must-not-bind-media-model"; }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration // { executionHost.hostname = "Malak"; }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration
          // {
            targetMedia = productionMediaHardwareConfiguration.targetMedia // {
              serial = "must-not-bind-media-serial";
            };
          }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          hardwareWithDevicePath "/dev/disk/by-id/nvme-forbidden"
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          hardwareWithDevicePath "/dev/disk/by-path/platform-kaiba-fixture-part1"
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          hardwareWithDevicePath "/dev/mapper/forbidden"
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (hardwareWithDevicePath "nvme0n1"))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaHardwareConfiguration
          // {
            targetMedia.protectedDevicePaths = [ ];
          }
        ))
        && !(productionMediaHardwareConfigurationInputAccepted (
          productionMediaAlternateHardwareConfiguration
          // {
            targetMedia.protectedDevicePaths = [ "/dev/nvme0n1" ];
          }
        ))
        && !(builtins.functionArgs built.mkRpi5ProductionMedia ? targetDevicePath)
        && contract.verifiedSignedRelease == productionMediaSignedReleaseFixture
        && contract.targetGeometry == productionMediaTarget
        && !(contract ? target)
        && !(contract ? targetDevicePath)
        && !(contract ? hardwareConfiguration)
        && assetsContract.targetGeometry == productionMediaTarget
        && !(assetsContract ? target)
        && !(assetsContract ? targetDevicePath)
        && !(assetsContract ? hardwareConfiguration)
        && !(assetsContract ? hardwareConfigurationID)
        && contract.hardwareConfigurationID == productionMediaHardwareConfiguration.configurationID
        && contract.transactionID == "transaction:rpi5-media-fixture:1"
        && contract.schemaVersion == "kaiba.provisioning.rpi5-media-staging-plan/v1alpha2"
        && contract.contentAddressedReleaseRequired
        && contract.verificationMode == "pure_offline_plan_derivation"
        && stager.blockDeviceWriteCapable
        && stager.configuredSelectorMode == "operational_path_not_media_identity"
        && stager.executionHostBound
        && stager.fixtureModeAvailable == false
        && stager.hardwareConfigurationID == productionMediaHardwareConfiguration.configurationID
        && !(stager ? targetDevicePath)
        && !(stager ? hardwareConfiguration)
        && stager.mutationScope == "one_linker_fixed_operational_device_path"
        && stager.protectedDeviceCount == 1
        && verifier.blockDeviceReadCapable
        && verifier.blockDeviceWriteCapable == false
        && verifier.configuredSelectorMode == "operational_path_not_media_identity"
        && verifier.executionHostBound
        && verifier.hardwareConfigurationID == productionMediaHardwareConfiguration.configurationID
        && !(verifier ? targetDevicePath)
        && !(verifier ? hardwareConfiguration)
        && verifier.independentAttachmentRequired
        && verifier.releaseLineageVerifier == productionMediaSignedReleaseFixture
        && contract.assets.drvPath == alternateHardwareContract.assets.drvPath
        && contract.plan == alternateHardwareContract.plan
        && contract.deviceStager.drvPath != alternateHardwareContract.deviceStager.drvPath
        && contract.deviceVerifier.drvPath != alternateHardwareContract.deviceVerifier.drvPath
        &&
          alternateHardwareContract.hardwareConfigurationID
          == productionMediaAlternateHardwareConfiguration.configurationID
        && fixtureStager.blockDeviceAccess == false
        && fixtureStager.evidenceMode == "regular_file_fixture"
        && fixtureStager.mutationEligible == false
        && fixtureVerifier.blockDeviceAccess == false
        && fixtureVerifier.evidenceMode == "regular_file_fixture"
        && lib.all (value: value == false) [
          contract.blockDeviceWriteCapable
          contract.directHardwareAccess
          contract.fixtureHardwareObserved
          contract.mutationCapable
          contract.oneTimeSettingCapable
          contract.otpCapable
          contract.signingAuthorityConfigured
          stager.eepromProgrammingCapable
          stager.oneTimeSettingCapable
          stager.otpCapable
          verifier.eepromProgrammingCapable
          verifier.mutationCapable
          verifier.oneTimeSettingCapable
          verifier.otpCapable
          fixtureVerifier.mutationCapable
        ]
      )
      "the production-media factory accepted spoofed lineage or gained signing, fixture/device crossover, hardware, EEPROM, OTP, or undeclared mutation authority";
    pkgs.runCommand "kaiba-rpi5-production-media-staging-contract"
      {
        nativeBuildInputs = [
          built.mediaContractTool
          built.unfusedRuntimeRecordTool
          pkgs.coreutils
          pkgs.go
          pkgs.gnugrep
          pkgs.jq
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        export LC_ALL=C
        export PYTHONPYCACHEPREFIX="$TMPDIR/pycache"

        cd ${built.goSource}
        go test \
          ./internal/provisioning/evidencefile \
          ./internal/provisioning/mediacontract \
          ./internal/provisioning/mediadevice \
          ./internal/provisioning/mediainventory \
          ./internal/provisioning/mediarelease \
          ./internal/provisioning/mediaverity \
          ./internal/provisioning/mediawriter \
          ./internal/provisioning/planapproval \
          ./cmd/kaiba-provision-media-contract \
          ./cmd/kaiba-provision-media-device-stager \
          ./cmd/kaiba-provision-media-device-verifier \
          ./cmd/kaiba-provision-media-fixture-stager \
          ./cmd/kaiba-provision-media-verifier \
          ./cmd/kaiba-provision-unfused-runtime-record

        # The evidence publisher uses Linux descriptor-relative APIs. Compile
        # its tests for arm64 in the x86 fast-check job so architecture-specific
        # portability regressions fail before native ARM image construction
        # fans out.
        GOOS=linux GOARCH=arm64 go test -c \
          -o "$TMPDIR/evidencefile-linux-arm64.test" \
          ./internal/provisioning/evidencefile
        test -s "$TMPDIR/evidencefile-linux-arm64.test"

        go list -deps ./cmd/kaiba-provision-media-device-verifier \
          > "$TMPDIR/device-verifier-deps"
        if grep -E '/internal/provisioning/(mediawriter|mediastager)$' \
          "$TMPDIR/device-verifier-deps"
        then
          echo 'production device verifier imports a staging writer or legacy mixed stager' >&2
          exit 1
        fi
        go list -deps ./cmd/kaiba-provision-media-device-stager \
          | grep -F '/internal/provisioning/mediawriter' > /dev/null
        python3 -m py_compile ${../../nix/provisioning/build-canonical-fat.py}
        python3 -m py_compile ${./deterministic-rsa-fixture.py}

        readonly production_assets=${productionMediaFixture.kaibaRpi5ProductionMedia.assets}
        readonly deterministic_assets=${productionMediaDeterminismFixture.kaibaRpi5ProductionMedia.assets}
        readonly alternate_assets=${productionMediaAlternatePlanFixture.kaibaRpi5ProductionMedia.assets}
        readonly production_check=${productionMediaFixture.kaibaRpi5ProductionMedia.softwareCheck}
        test -f "$production_check"
        for artifact in \
          primary-gpt.img \
          backup-gpt.img \
          boot-filesystem.img \
          media-binding.json \
          layout.json \
          plan.json \
          plan-digest \
          expected-media-digest
        do
          cmp "$production_assets/$artifact" "$deterministic_assets/$artifact"
        done
        test -f ${productionMediaFixture}/plan.json
        test ! -L ${productionMediaFixture}/plan.json
        jq -e '
          .schema_version == "kaiba.provisioning.rpi5-media-staging-plan/v1alpha2"
          and .target == {
            size_bytes: ${toString productionMediaTarget.sizeBytes},
            logical_sector_size_bytes: 512
          }
          and (has("initial_media_digest") | not)
        ' "$production_assets/plan.json" > /dev/null
        if grep -E \
          '"(by_id_path|device_path|model|serial|wwid|physical_sector_size_bytes|initial_media_digest)"' \
          "$production_assets/plan.json"
        then
          echo 'canonical media plan retained an operational selector, hardware identity, or prestate field' >&2
          exit 1
        fi
        if grep -F ${lib.escapeShellArg productionMediaHardwareConfiguration.targetMedia.devicePath} \
          "$production_assets/plan.json"
        then
          echo 'linker-fixed operational selector leaked into the canonical media plan' >&2
          exit 1
        fi
        if grep -F ${lib.escapeShellArg productionMediaHardwareConfiguration.configurationID} \
          "$production_assets/plan.json"
        then
          echo 'hardware-configuration identity leaked into the canonical media plan' >&2
          exit 1
        fi
        test -x ${productionMediaFixture.kaibaRpi5ProductionMedia.deviceStager}/bin/kaiba-provision-media-device-stager
        test -x ${productionMediaFixture.kaibaRpi5ProductionMedia.deviceVerifier}/bin/kaiba-provision-media-device-verifier
        test -x ${productionMediaFixture.kaibaRpi5ProductionMedia.fixtureStager}/bin/kaiba-provision-media-fixture-stager
        test -x ${productionMediaFixture.kaibaRpi5ProductionMedia.regularVerifier}/bin/kaiba-provision-media-verifier
        for station_binary in \
          ${productionMediaFixture.kaibaRpi5ProductionMedia.deviceStager}/bin/kaiba-provision-media-device-stager \
          ${productionMediaFixture.kaibaRpi5ProductionMedia.deviceVerifier}/bin/kaiba-provision-media-device-verifier
        do
          grep -aF ${lib.escapeShellArg productionMediaHardwareConfiguration.configurationID} \
            "$station_binary" > /dev/null
          grep -aF ${lib.escapeShellArg productionMediaHardwareConfiguration.executionHost.hostname} \
            "$station_binary" > /dev/null
          grep -aF ${lib.escapeShellArg productionMediaHardwareConfiguration.targetMedia.devicePath} \
            "$station_binary" > /dev/null
          grep -aF /dev/nvme0n1 "$station_binary" > /dev/null
        done

        # This alternate plan is canonical and self-consistent, but the
        # primary fixture binaries are linker-authorized for exactly the
        # primary plan. Reject it before staging can mutate even one byte.
        truncate --size=${toString productionMediaTarget.sizeBytes} \
          "$TMPDIR/alternate-plan-target.img"
        cp --reflink=auto --sparse=always \
          "$TMPDIR/alternate-plan-target.img" \
          "$TMPDIR/alternate-plan-target.before"
        if ${productionMediaFixture.kaibaRpi5ProductionMedia.fixtureStager}/bin/kaiba-provision-media-fixture-stager stage \
          --plan "$alternate_assets/plan.json" \
          --target "$TMPDIR/alternate-plan-target.img" \
          --result "$TMPDIR/alternate-plan-result.json" \
          > "$TMPDIR/alternate-plan-stager.stdout" \
          2> "$TMPDIR/alternate-plan-stager.stderr"
        then
          echo 'fixture stager accepted a different canonical linker-fixed plan' >&2
          exit 1
        fi
        grep -F \
          'approve plan: caller media plan differs from the linker-fixed approved plan' \
          "$TMPDIR/alternate-plan-stager.stderr" > /dev/null
        cmp \
          "$TMPDIR/alternate-plan-target.before" \
          "$TMPDIR/alternate-plan-target.img"

        if ${productionMediaFixture.kaibaRpi5ProductionMedia.regularVerifier}/bin/kaiba-provision-media-verifier verify-regular-file \
          --plan "$alternate_assets/plan.json" \
          --target "$TMPDIR/alternate-plan-target.img" \
          > "$TMPDIR/alternate-plan-verifier.stdout" \
          2> "$TMPDIR/alternate-plan-verifier.stderr"
        then
          echo 'regular verifier accepted a different canonical linker-fixed plan' >&2
          exit 1
        fi
        grep -F \
          'approve plan: caller media plan differs from the linker-fixed approved plan' \
          "$TMPDIR/alternate-plan-verifier.stderr" > /dev/null
        cmp \
          "$TMPDIR/alternate-plan-target.before" \
          "$TMPDIR/alternate-plan-target.img"

        test -x ${built.mediaContractTool}/bin/kaiba-provision-media-contract
        test -x ${built.unfusedRuntimeRecordTool}/bin/kaiba-provision-unfused-runtime-record
        test '${built.unfusedRuntimeRecordTool.kaibaUnfusedRuntimeRecordTool.authority}' = \
          serialization_fixture_only
        test '${builtins.toJSON built.unfusedRuntimeRecordTool.kaibaUnfusedRuntimeRecordTool.hardwareObservationClaim}' = false
        test '${builtins.toJSON built.mediaContractTool.kaibaMediaContractTool.blockDeviceAccess}' = false
        test '${builtins.toJSON built.mediaContractTool.kaibaMediaContractTool.mutationCapable}' = false

        mkdir "$out"
        touch "$out/passed"
      '';

  developmentYubiKeySigningContract =
    pkgs.runCommand "kaiba-development-yubikey-signing-contract"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.jq
          pkgs.openssl
        ];
      }
      ''
        set -euo pipefail

        expected_binaries="$(${pkgs.coreutils}/bin/printf '%s\n' \
          kaiba-provision-sign-boot \
          kaiba-provision-sign-eeprom \
          kaiba-provision-signer \
          kaiba-provision-signing-client \
          kaiba-provision-signing-gate \
          kaiba-provision-signing-receipts \
          kaiba-provision-yubikey-wrapper)"
        actual_binaries="$(
          find -L ${developmentYubiKeySigning}/bin \
            -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
            | sort
        )"
        test "$actual_binaries" = "$expected_binaries"
        for binary in $expected_binaries; do
          test -x ${developmentYubiKeySigning}/bin/"$binary"
        done

        test '${developmentYubiKeySigning.kaibaSigning.signerID}' = \
          'signer:development-fixture'
        test '${developmentYubiKeySigning.kaibaSigning.cohortID}' = \
          'cohort:development-fixture'
        test '${developmentYubiKeySigning.kaibaSigning.grantRegistryPath}' = \
          '/etc/kaiba-provisioning/signing-grants.json'
        test '${developmentYubiKeySigning.kaibaSigning.pkcs11URI}' = \
          'pkcs11:serial=12345678;id=%02;type=private'
        test '${developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint}' = \
          '${developmentYubiKeyPublicKeyFingerprint}'
        test '${developmentYubiKeySigning.kaibaSigning.expectedCustomerKeyHash}' = \
          '${developmentYubiKeyCustomerKeyHash}'
        test '${developmentYubiKeySigning.kaibaSigning.signerPolicyDigest}' = \
          '${developmentYubiKeySignerPolicyDigest}'
        test '${toString developmentYubiKeySigning.kaibaSigning.minimumArtifactSignatureOperationsPerCompletedGrant}' = '1'
        test '${toString developmentYubiKeySigning.kaibaSigning.minimumReceiptAttestationOperationsPerCompletedGrant}' = '1'
        test '${toString developmentYubiKeySigning.kaibaSigning.minimumPrivateKeyOperationsPerCompletedGrant}' = '2'
        test '${developmentYubiKeySigning.kaibaSigning.operationCountSemantics}' = \
          'minimum_successful_path'
        test '${developmentYubiKeySigning.kaibaSigning.incompleteGrantRetryPolicy}' = \
          'deny_same_grant_require_new_approval'
        test '${builtins.toJSON developmentYubiKeySigning.kaibaSigning.privateKeyOperationUpperBoundDeclared}' = \
          'false'
        test -x \
          ${developmentYubiKeySigning.kaibaSigning.signedBoot}/bin/kaiba-provision-sign-boot
        test -x \
          ${developmentYubiKeySigning.kaibaSigning.eepromSigningTool}/bin/kaiba-provision-sign-eeprom
        test -x \
          ${developmentYubiKeySigning.kaibaSigning.signingReceiptsTool}/bin/kaiba-provision-signing-receipts
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.gateSocketPath}' = \
          '/run/kaiba-provision-signing/signing.sock'
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.signerID}' = \
          'signer:development-fixture'
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.cohortID}' = \
          'cohort:development-fixture'
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.pkcs11URI}' = \
          'pkcs11:serial=12345678;id=%02;type=private'
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.publicKeyFingerprint}' = \
          '${developmentYubiKeyPublicKeyFingerprint}'
        test '${developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.expectedPublicKeyPath}' = \
          '${developmentYubiKeyPublicKeyPEM}'
        test '${builtins.toJSON developmentYubiKeySigning.kaibaSigning.signedBootConfiguration.runtimeAuthoritySelectors}' = \
          'false'
        test "$(cat ${developmentYubiKeySigning.kaibaSigning.customerKeyHashFile})" = \
          '${developmentYubiKeyCustomerKeyHash}'
        test "$(stat --format=%s \
          ${developmentYubiKeySigning.kaibaSigning.customerPublicKeyBinary})" -eq 264
        test "$(sha256sum \
          ${developmentYubiKeySigning.kaibaSigning.customerPublicKeyBinary} \
          | cut -d ' ' -f 1)" = '${developmentYubiKeyCustomerKeyHash}'
        test "$(cat ${developmentYubiKeySigning.kaibaSigning.signerPolicyDigestFile})" = \
          '${developmentYubiKeySignerPolicyDigest}'
        jq -e '
          .schema_version == "kaiba.provisioning.yubikey-signing-policy/v1alpha1"
          and .signer_id == "signer:development-fixture"
          and .cohort_id == "cohort:development-fixture"
          and .provider == "yubikey-piv"
          and .piv_slot == "9c"
          and .pkcs11_uri == "pkcs11:serial=12345678;id=%02;type=private"
          and .public_key_fingerprint == "${developmentYubiKeyPublicKeyFingerprint}"
          and .key_algorithm == "rsa-2048"
          and .pin_required == true
          and .touch_required == true
          and .private_key_exportable == false
        ' ${developmentYubiKeySigning.kaibaSigning.signerPolicyJSON} > /dev/null
        test '${developmentYubiKeySigning.kaibaSigning.pinCredentialPath}' = \
          '/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin'
        test '${developmentYubiKeySigning.kaibaSigning.socketPath}' = \
          '/run/kaiba-provision-signing/signing.sock'
        test '${developmentYubiKeySigning.kaibaSigning.stateDirectoryPath}' = \
          '/var/lib/kaiba-provision-signing'
        test '${developmentYubiKeySigning.kaibaSigning.pkcs11ProviderModule}' = \
          '${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so'
        test '${developmentYubiKeySigning.kaibaSigning.ykcs11Module}' = \
          '${pkgs.yubico-piv-tool}/lib/libykcs11.so.${pkgs.yubico-piv-tool.version}'
        cmp \
          ${developmentYubiKeySigning.kaibaSigning.opensslConfiguration} \
          ${expectedDevelopmentYubiKeyOpenSSLConfiguration}

        openssl pkey \
          -pubin \
          -in ${developmentYubiKeyPublicKeyPEM} \
          -outform DER \
          -out "$TMPDIR/development-boot-public.der"
        test "sha256:$(sha256sum "$TMPDIR/development-boot-public.der" | cut -d ' ' -f 1)" = \
          '${developmentYubiKeyPublicKeyFingerprint}'

        # Argument validation must happen without a token or credential. The
        # configured binary still validates all immutable public dependencies.
        test ! -e '${developmentYubiKeySigning.kaibaSigning.pinCredentialPath}'
        set +e
        ${developmentYubiKeySigning}/bin/kaiba-provision-yubikey-wrapper \
          > "$TMPDIR/wrapper.stdout" \
          2> "$TMPDIR/wrapper.stderr"
        wrapper_status="$?"
        set -e
        test "$wrapper_status" -eq 2
        test ! -s "$TMPDIR/wrapper.stdout"
        grep -Fx \
          'usage: kaiba-provision-yubikey-wrapper -a rsa2048-sha256 INPUT_FILE' \
          "$TMPDIR/wrapper.stderr"
        test "$(wc -l < "$TMPDIR/wrapper.stderr")" -eq 1

        # The configured adapter fixes every authority value at link time and
        # rejects attempts to replace any of them on the command line.
        set +e
        ${developmentYubiKeySigning}/bin/kaiba-provision-sign-boot \
          sign \
          --plan /tmp/kaiba-plan \
          --output /tmp/kaiba-signed \
          --socket /tmp/attacker.sock \
          > "$TMPDIR/sign-boot.stdout" \
          2> "$TMPDIR/sign-boot.stderr"
        sign_boot_status="$?"
        set -e
        test "$sign_boot_status" -eq 2
        test ! -s "$TMPDIR/sign-boot.stdout"
        grep -Fx \
          'usage: kaiba-provision-sign-boot sign --plan ABSOLUTE_PLAN_DIR --output ABSOLUTE_OUTPUT_DIR' \
          "$TMPDIR/sign-boot.stderr"
        grep -Fx \
          '       kaiba-provision-sign-boot finalize --plan ABSOLUTE_PLAN_DIR --signed ABSOLUTE_SIGNED_DIR --output ABSOLUTE_OUTPUT_DIR' \
          "$TMPDIR/sign-boot.stderr"

        mkdir -p "$out"
        touch "$out/passed"
      '';

  provisioningTestResult =
    pkgs.runCommand "kaiba-provisioning-test-result-${pkgs.stdenv.hostPlatform.system}"
      {
        nativeBuildInputs = [
          pkgs.binutils
          pkgs.check-jsonschema
          pkgs.go
          pkgs.gnugrep
          pkgs.jq
        ];
      }
      ''
        ${lib.optionalString (pkgs.stdenv.hostPlatform.system == "x86_64-linux") ''
          test -f ${signingCeremonyAutomationCheck}/passed
        ''}
        test -x ${built.suite}/bin/kaiba-provision
        test -x ${built.serviceSuite}/bin/kaiba-provision-audit
        test -x ${built.serviceSuite}/bin/kaiba-provision-authority-bridge
        test -x ${built.serviceSuite}/bin/kaiba-provision-control
        test -x ${built.serviceSuite}/bin/kaiba-provision-lane-guard
        test ! -e ${built.serviceSuite}/bin/kaiba-provision-lane-workflow
        test -x ${built.serviceSuite}/bin/kaiba-provision-signer
        test -x ${built.serviceSuite}/bin/kaiba-provision-signing-client
        test -x ${built.serviceSuite}/bin/kaiba-provision-signing-gate
        test -x ${built.serviceSuite}/bin/kaiba-provision-station
        test -x ${built.serviceSuite}/bin/kaiba-provision-yubikey-wrapper
        test -x ${built.signedBootTool}/bin/kaiba-provision-sign-boot
        test -x ${built.laneOperator}/bin/kaiba-provision-lane-operator
        test -x ${built.laneWorkflow}/bin/kaiba-provision-lane-workflow
        test '${built.laneOperator.kaibaLaneOperator.authority}' = 'acknowledgement_only'
        test '${builtins.toJSON built.laneOperator.kaibaLaneOperator.directHardwareAccess}' = 'false'
        test '${builtins.toJSON built.laneOperator.kaibaLaneOperator.mutationCapable}' = 'false'
        test '${builtins.toJSON built.laneOperator.kaibaLaneOperator.operationSelectionCapable}' = 'false'
        test '${builtins.toJSON built.laneOperator.kaibaLaneOperator.physicalPathSelectionCapable}' = 'false'
        test '${built.laneWorkflow.kaibaLaneWorkflow.authority}' = 'fixed_authenticated_lane_workflow'
        test '${builtins.toJSON built.laneWorkflow.kaibaLaneWorkflow.directHardwareAccess}' = 'false'
        test '${builtins.toJSON built.laneWorkflow.kaibaLaneWorkflow.mutationCapable}' = 'false'
        test '${builtins.toJSON built.laneWorkflow.kaibaLaneWorkflow.operationSelectionCapable}' = 'false'
        test '${builtins.toJSON built.laneWorkflow.kaibaLaneWorkflow.physicalPathSelectionCapable}' = 'false'

        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        (
          cd ${built.goSource}
          go list -deps ./cmd/kaiba-provision-lane-operator \
            > "$TMPDIR/lane-operator-deps"
          go list -deps ./cmd/kaiba-provision-lane-workflow \
            > "$TMPDIR/lane-workflow-deps"
        )
        while IFS= read -r package; do
          case "$package" in
            github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle|\
            github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign|\
            github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard|\
            github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt|\
            github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding|\
            github.com/ams-tech/nixos-kaiba-network/provisioning/cmd/kaiba-provision-lane-operator)
              ;;
            github.com/ams-tech/nixos-kaiba-network/provisioning/*)
              echo "lane operator imports an unapproved repository package: $package" >&2
              exit 1
              ;;
          esac
        done < "$TMPDIR/lane-operator-deps"
        grep -Fx \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt \
          "$TMPDIR/lane-operator-deps"
        for package in \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5 \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5 \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediawriter \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediastager
        do
          if grep -Fx "$package" "$TMPDIR/lane-operator-deps"; then
            echo "lane operator imports forbidden package: $package" >&2
            exit 1
          fi
        done
        for package in \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5 \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5 \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediawriter \
          github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediastager
        do
          if grep -Fx "$package" "$TMPDIR/lane-workflow-deps"; then
            echo "lane authority workflow imports forbidden package: $package" >&2
            exit 1
          fi
        done
        if strings ${built.laneOperator}/bin/kaiba-provision-lane-operator \
          | grep -E 'internal/provisioning/physicalrpi5([./]|$)|/bin/rpiboot|/bin/gpioset'; then
          echo 'lane operator links a physical mutation capability' >&2
          exit 1
        fi
        if strings ${built.laneWorkflow}/bin/kaiba-provision-lane-workflow \
          | grep -E 'internal/provisioning/physicalrpi5([./]|$)|/bin/rpiboot|/bin/gpioset'; then
          echo 'lane authority workflow links a physical mutation capability' >&2
          exit 1
        fi
        test -x ${built.provision}/bin/kaiba-provision
        test -x ${built.rehearsal}/bin/kaiba-provision-rehearsal
        test '${built.rehearsal.kaibaRehearsal.authority}' = \
          'rehearsal_only_non_authoritative'
        test '${builtins.toJSON built.rehearsal.kaibaRehearsal.hardwareAccess}' = 'false'
        test '${builtins.toJSON built.rehearsal.kaibaRehearsal.mutationCapable}' = 'false'
        test '${builtins.toJSON built.rehearsal.kaibaRehearsal.otpCapable}' = 'false'
        ${built.rehearsal}/bin/kaiba-provision-rehearsal \
          --rehearsal-id nix-contract > "$TMPDIR/rehearsal.json"
        jq -e '
          .authority == "rehearsal_only_non_authoritative"
          and .safety_mode == "software_only_no_otp"
          and .outcome == "rehearsal_passed"
          and .state.physical_mutation_performed == false
          and .state.otp_write_count == 0
          and (.evidence | length) == 7
          and ([.evidence[].physical_action_attempted] | all(. == false))
          and ([.evidence[].otp_write_attempted] | all(. == false))
        ' "$TMPDIR/rehearsal.json" > /dev/null
        if strings ${built.rehearsal}/bin/kaiba-provision-rehearsal \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)'; then
          echo 'software rehearsal binary links a physical provisioning package' >&2
          exit 1
        fi
        test -x ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal
        test '${built.integratedRehearsal.kaibaIntegratedRehearsal.authority}' = 'non_authoritative'
        test '${built.integratedRehearsal.kaibaIntegratedRehearsal.executionMode}' = 'software_only'
        test '${builtins.toJSON built.integratedRehearsal.kaibaIntegratedRehearsal.directHardwareAccess}' = 'false'
        test '${builtins.toJSON built.integratedRehearsal.kaibaIntegratedRehearsal.mutationCapable}' = 'false'
        test '${builtins.toJSON built.integratedRehearsal.kaibaIntegratedRehearsal.oneTimeSettingCapable}' = 'false'
        test '${builtins.toJSON built.integratedRehearsal.kaibaIntegratedRehearsal.otpCapable}' = 'false'
        ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal \
          --state-dir "$TMPDIR/integrated-rehearsal-state" \
          --rehearsal-id nix-integrated > "$TMPDIR/integrated-rehearsal.json"
        jq -e '
          .execution_mode == "software_only"
          and .authority_class == "non_authoritative"
          and .control_audit_exercised == true
          and .persistence_revalidated == true
          and .hardware_observed == false
          and .security_enforced == false
          and .mutation_eligible == false
          and .authority.plan_operation_count == 7
          and .authority.validated_intent_count == 1
          and .authority.executable_request_count == 0
          and .authority.pending_sequence == 1
          and .simulation.outcome == "rehearsal_passed"
        ' "$TMPDIR/integrated-rehearsal.json" > /dev/null
        # Match linked implementation packages and concrete executable/device
        # paths, not closed contract vocabulary such as the "rpiboot" boot
        # mode. Go may coalesce adjacent string data into text like
        # "http://rpiboot", so a bare /rpiboot pattern is not a path test.
        if strings ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal \
          | grep -E 'internal/provisioning/(physicalrpi5|rpi5)([./]|$)|/bin/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'integrated rehearsal links a live physical provisioning capability' >&2
          exit 1
        fi
        if strings ${built.serviceSuite}/bin/kaiba-provision-authority-bridge \
          | grep -E 'internal/provisioning/physicalrpi5([./]|$)|/bin/rpiboot|/gpioset'; then
          echo 'authority bridge links a live physical provisioning capability' >&2
          exit 1
        fi
        test -x ${built.unfusedCompat}/bin/kaiba-provision-unfused-compat
        test '${built.unfusedCompat.kaibaUnfusedCompatibility.evidenceMode}' = \
          'offline_fixture'
        test '${builtins.toJSON built.unfusedCompat.kaibaUnfusedCompatibility.hardwareAccess}' = 'false'
        test '${builtins.toJSON built.unfusedCompat.kaibaUnfusedCompatibility.mutationCapable}' = 'false'
        test '${builtins.toJSON built.unfusedCompat.kaibaUnfusedCompatibility.otpCapable}' = 'false'
        test '${builtins.toJSON built.unfusedCompat.kaibaUnfusedCompatibility.securityEnforcementClaim}' = 'false'
        test '${builtins.toJSON built.unfusedCompat.kaibaUnfusedCompatibility.signerTrustAnchored}' = 'false'
        if strings ${built.unfusedCompat}/bin/kaiba-provision-unfused-compat \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/bin/rpiboot|/gpioset'; then
          echo 'unfused compatibility verifier links a physical provisioning capability' >&2
          exit 1
        fi
        test -x ${built.unfusedEvidence}/bin/kaiba-provision-unfused-evidence
        test '${built.unfusedEvidence.kaibaUnfusedEvidence.evidenceMode}' = \
          'offline_operator_correlation'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.captureAuthenticated}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.directHardwareAccess}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.hardwareObservationClaim}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.mutationCapable}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.oneTimeSettingCapable}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.otpCapable}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.securityEnforcementClaim}' = 'false'
        test '${builtins.toJSON built.unfusedEvidence.kaibaUnfusedEvidence.signerTrustAnchored}' = 'false'
        if strings ${built.unfusedEvidence}/bin/kaiba-provision-unfused-evidence \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/bin/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'unfused evidence verifier links a live physical provisioning capability' >&2
          exit 1
        fi
        test -x ${unfusedVerifierFixture}/bin/kaiba-provision-unfused-compat
        test -x ${unfusedVerifierFixture}/bin/kaiba-provision-unfused-evidence
        test '${builtins.toJSON unfusedVerifierFixture.kaibaUnfusedVerifier.signerTrustAnchored}' = 'true'
        test '${unfusedVerifierFixture.kaibaUnfusedVerifier.trustedPublicKeyFingerprint}' = \
          '${developmentYubiKeyPublicKeyFingerprint}'
        test '${unfusedVerifierFixture.kaibaUnfusedVerifier.evidenceMode}' = \
          'offline_operator_correlation'
        test '${builtins.toJSON unfusedVerifierFixture.kaibaUnfusedVerifier.captureAuthenticated}' = 'false'
        test '${builtins.toJSON unfusedVerifierFixture.kaibaUnfusedVerifier.hardwareObservationClaim}' = 'false'
        test '${builtins.toJSON unfusedVerifierFixture.kaibaUnfusedVerifier.oneTimeSettingCapable}' = 'false'
        test '${builtins.toJSON unfusedVerifierFixture.kaibaUnfusedVerifier.securityEnforcementClaim}' = 'false'
        test -x ${built.mediaStager}/bin/kaiba-provision-media-stager
        test '${builtins.toJSON built.mediaStager.kaibaMediaStager.blockDeviceWriteCapable}' = 'true'
        test '${builtins.toJSON built.mediaStager.kaibaMediaStager.oneTimeSettingCapable}' = 'false'
        test '${builtins.toJSON built.mediaStager.kaibaMediaStager.otpCapable}' = 'false'
        test '${builtins.toJSON built.mediaStager.kaibaMediaStager.eepromProgrammingCapable}' = 'false'
        test '${builtins.toJSON built.mediaStager.kaibaMediaStager.fixtureModeAvailable}' = 'true'
        if strings ${built.mediaStager}/bin/kaiba-provision-media-stager \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/bin/rpiboot|/gpioset'; then
          echo 'media stager links a Pi ownership or lane-control capability' >&2
          exit 1
        fi
        test -x ${physicalLaneGuardFixture}/bin/kaiba-provision-lane-guard
        ${physicalLaneGuardFixture}/bin/kaiba-provision-lane-guard \
          --print-release-binding > "$TMPDIR/physical-lane-release-binding.json"
        release_publication=${productionMediaSignedReleaseFixture}/publication.json
        release_manifest=${productionMediaSignedReleaseFixture}/$(jq -er .manifest_path "$release_publication")
        jq -e --slurpfile publication "$release_publication" --slurpfile manifest "$release_manifest" '
          def role_digest($role):
            [$manifest[0].artifacts[] | select(.role == $role)]
            | if length == 1 then .[0].digest else null end;
          .signed_release_manifest_digest == $publication[0].signed_release_manifest_digest
          and .expected_customer_key_hash == $manifest[0].expected_customer_key_hash
          and .expected_eeprom_digest == role_digest("rpi5.signed_eeprom_image")
          and .expected_boot_image_digest == role_digest("rpi5.boot_image")
          and (.lane_guard_package_digest | test("^sha256:[0-9a-f]{64}$"))
          and (.compiled_artifact_set_digest | test("^sha256:[0-9a-f]{64}$"))
        ' "$TMPDIR/physical-lane-release-binding.json"
        ${physicalLaneGuardFixture}/bin/kaiba-provision-lane-guard \
          --print-release-binding-material > "$TMPDIR/physical-lane-release-material.json"
        jq -e --slurpfile binding "$TMPDIR/physical-lane-release-binding.json" '
          .schema_version == "kaiba.provisioning.rpi5-lane-release-material/v1alpha1"
          and .binding == $binding[0]
          and (.compiled_artifact_set.artifacts | length) == 8
          and [.compiled_artifact_set.artifacts[].role] == [
            "rpi5.patched_rpiboot_binary",
            "rpi5.gpio_set_binary",
            "rpi5.fresh_commit_bundle",
            "rpi5.fresh_readback_bundle",
            "rpi5.negative_boot_bundle",
            "rpi5.owned_readback_bundle",
            "rpi5.owned_recovery_bundle",
            "rpi5.root_integrity_test_bundle"
          ]
          and .lane_guard_package.executable.role == "rpi5.lane_guard_executable"
          and .lane_guard_package.compiled_artifact_set_digest
            == .binding.compiled_artifact_set_digest
        ' "$TMPDIR/physical-lane-release-material.json"
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.verifiedSignedRelease}' = \
          '${productionMediaSignedReleaseFixture}'
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.releaseLineageIdentity}' = \
          'single-verified-signed-release-v1alpha2'
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.releaseBindingIdentity}' = \
          'runtime-verified-content-derived-v1alpha1'
        test -r ${built.provision}/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json
        test -r ${built.provision}/share/kaiba/schemas/rpi5-hardware-qualification-v1alpha1.schema.json
        test -f ${deviceProfileSchema}/passed
        test -f ${developmentPostureContract}/passed
        test -f ${probeBundleIntegrity}/passed
        test -f ${rpibootMetadataStdoutCompatibility}/passed
        test -f ${eepromReleaseContract}/passed
        test -f ${eepromSigningContract}/passed
        test -f ${rpibootBundleContract}/passed
        test -f ${signedReleaseFinalizationContract}/passed
        test -f ${signedReleaseManifestContract}/passed
        test -f ${secureBootArtifactContract}/passed
        test -f ${signedBootPlanContract}/passed
        test -f ${unfusedCapsuleContract}/passed
        test -f ${mediaStagingFixtureContract}/passed
        test -f ${productionMediaStagingContract}/passed
        test -f ${developmentYubiKeySigningContract}/passed
        test -f ${moduleEval}/results.txt

        jq -e \
          '[.checks[] | select(.id == "rpi5-development-posture") | [.status, .evidence]]
            == [["passed", ["${developmentPostureEvidencePath}"]]]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-development-posture")
            | [.system, .status, .evidence]
          ] == [
            ["aarch64-linux", "not-observed", []],
            ["x86_64-linux", "passed", []]
          ]
        ' ${canonicalJSON}/report-input.json > /dev/null

        for software_only_check in \
          development-signer-independent-review \
          exact-release-signing-authorization \
          authenticated-signing-receipts \
          ubuntu-signing-gate-deployment
        do
          jq -e \
            --arg check_id "$software_only_check" \
            '[.checks[] | select(.id == $check_id) | .status] == ["passed"]' \
            ${canonicalJSON}/platform.json > /dev/null
          jq -e \
            --arg check_id "$software_only_check" \
            '[.automated.checks[]
              | select(.id == $check_id)
              | [.system, .status]
            ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]' \
            ${canonicalJSON}/report-input.json > /dev/null
        done

        jq -e \
          '[.checks[] | select(.id == "authenticated-authority-bridge") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "authenticated-authority-bridge")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null

        jq -e \
          '[.checks[] | select(.id == "authenticated-physical-mode-workflow") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "authenticated-physical-mode-workflow")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null

        jq -e \
          '[.checks[] | select(.id == "authenticated-restart-reconciliation") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "authenticated-restart-reconciliation")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null

        jq -e '[.checks[] | select(.id == "media-staging-fixture") | .status] == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "media-staging-fixture")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "rpi5-production-media-contract") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-production-media-contract")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "rpi5-eeprom-release-contract") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-eeprom-release-contract")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "rpi5-eeprom-signing-contract") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-eeprom-signing-contract")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "rpi5-rpiboot-bundle-set") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-rpiboot-bundle-set")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "rpi5-signed-release-finalization") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "rpi5-signed-release-finalization")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null
        jq -e \
          '[.checks[] | select(.id == "signed-release-manifest-contract") | .status]
            == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "signed-release-manifest-contract")
            | [.system, .status]
          ] == [["aarch64-linux", "not-observed"], ["x86_64-linux", "passed"]]
        ' ${canonicalJSON}/report-input.json > /dev/null

        mkdir -p \
          "$out/evidence/provisioning/development-posture" \
          "$out/evidence/provisioning/hardware-qualification"
        install -m 0444 \
          ${developmentPostureContract}/${developmentPostureEvidencePath} \
          "$out/${developmentPostureEvidencePath}"
        ${lib.optionalString (qualificationEvidence != null) ''
          entry=${./evidence + "/${qualificationEvidenceName}"}
          test -f "$entry"
          test ! -L "$entry"
          check-jsonschema \
            --schemafile ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
            "$entry"
          test "$(jq -r .source.tool_version "$entry")" = \
            "$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)"
          ${lib.optionalString
            (qualificationEvidence.record.station_system == pkgs.stdenv.hostPlatform.system)
            ''
              test "$(jq -r .source.tool_digest "$entry")" = \
                "$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
            ''
          }
          test "$(jq -r .source.bundle_digest "$entry")" = \
            "$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
          test "$(jq -r .source.firmware_digest "$entry")" = \
            "$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)"
          test "$(jq -r .source.config_digest "$entry")" = \
            "$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)"
          install -m 0444 "$entry" \
            "$out/evidence/provisioning/hardware-qualification/${qualificationEvidenceName}"
        ''}
        install -m 0444 ${canonicalJSON}/platform.json "$out/platform.json"
        ${lib.optionalString (pkgs.stdenv.hostPlatform.system == "x86_64-linux") ''
          test "$(jq --sort-keys --compact-output . ${./report-input.json})" = \
            "$(jq --sort-keys --compact-output . ${canonicalJSON}/report-input.json)"
          install -m 0444 ${canonicalJSON}/report-input.json "$out/report-input.json"
        ''}
      '';
in
{
  inherit
    developmentPostureContract
    developmentYubiKeySigningContract
    deviceProfileSchema
    eepromReleaseContract
    eepromSigningContract
    mediaStagingFixtureContract
    physicalLaneGuardFixture
    productionMediaStagingContract
    moduleEval
    probeBundleIntegrity
    provisioningTestResult
    rpibootBundleContract
    rpibootMetadataStdoutCompatibility
    secureBootArtifactContract
    signingReceiptVerificationContract
    signedReleaseFinalizationContract
    signedReleaseManifestContract
    signedBootPlanContract
    unfusedCapsuleContract
    ;
}
