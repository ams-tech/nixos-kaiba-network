{
  pkgs,
  lib,
  built,
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
  signingGrantFixture = pkgs.writeText "kaiba-signing-grant-registry-fixture.json" (
    builtins.toJSON {
      schema_version = "kaiba.provisioning.signing-grant-registry/v1alpha1";
      grants = [
        {
          schema_version = "kaiba.provisioning.signing-grant/v1alpha1";
          grant_id = "grant:boot-image:1";
          expires_at = "2099-01-01T00:00:00Z";
          request = {
            schema_version = "kaiba.provisioning.signing-request/v1alpha1";
            request_id = "request:boot-image:1";
            algorithm = "rsa2048-sha256";
            role = "rpi5.boot_image";
            artifact_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            approval = {
              approval_id = "approval:development:1";
              approval_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
              transaction_id = "transaction:development:1";
              transaction_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
              manifest_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
              plan_digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
              target_fingerprint = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
              fence_epoch = 1;
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
  bootSigningPlanFixture = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-boot-signing-plan-fixture";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    planID = "plan:rpi5-development-fixture:1";
    publicKeyFingerprint = developmentYubiKeySigning.kaibaSigning.publicKeyFingerprint;
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
          reviewedPublicKeyPEM = developmentYubiKeyPublicKeyPEM;
          signerPolicyDigest = developmentYubiKeySigning.kaibaSigning.signerPolicyDigest;
          sourceDateEpoch = 1786968000;
        }
        // overrides
      )).drvPath
    )).success;
  emptySignedOutputFixture = pkgs.runCommand "kaiba-empty-signed-output-fixture" { } ''
    mkdir "$out"
  '';
  verifiedSignedBootEvaluationFixture = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-rpi5-verified-signed-boot-metadata-fixture";
    signingPlan = bootSigningPlanFixture;
    signedOutput = emptySignedOutputFixture;
  };
  signedBootFinalizerBootImage = pkgs.writeText "kaiba-signed-boot-finalizer-boot.img" ''
    kaiba signed-boot finalizer fixture
  '';
  signedBootFinalizerPublicKey = pkgs.writeText "kaiba-signed-boot-finalizer-public.pem" (
    builtins.readFile ./fixtures/signed-boot-finalizer-public.pem
  );
  signedBootFinalizerPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-signed-boot-finalizer-plan";
    bootImage = signedBootFinalizerBootImage;
    planID = "plan:rpi5-finalizer-fixture:1";
    publicKeyFingerprint = "sha256:104dbbf42aacd5c3357ed4229237f8d8d848af868b8f680b46cba5505d8f67fc";
    reviewedPublicKeyPEM = signedBootFinalizerPublicKey;
    signerPolicyDigest = "sha256:68498f57aa811b8a714260a4ac4390118c78efdb2af416cc64bfbd8eac4c42e3";
    sourceDateEpoch = 1786968000;
  };
  signedBootFinalizerSignedOutput = pkgs.runCommand "kaiba-signed-boot-finalizer-result" { } ''
    mkdir "$out"
    install -m 0444 \
      ${./fixtures/signed-boot-finalizer/boot.sig} \
      "$out/boot.sig"
    install -m 0444 \
      ${./fixtures/signed-boot-finalizer/signing-result.json} \
      "$out/signing-result.json"
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
  unfusedCapsulePublicKey = pkgs.writeText "kaiba-unfused-capsule-public.pem" (
    builtins.readFile ./fixtures/unfused-capsule/public.pem
  );
  unfusedCapsulePublicKeyFingerprint = "sha256:82c052b2366dee3e8831baf823dc192aa4ac344373d694e980cbc27d663e3c1d";
  unfusedCapsuleSigningPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-rpi5-unfused-capsule-signing-plan-fixture";
    bootImage = "${secureBootFixtureA}/unsigned/boot.img";
    planID = "plan:rpi5-unfused-capsule-fixture:1";
    publicKeyFingerprint = unfusedCapsulePublicKeyFingerprint;
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
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        mkdir "$out"
        install -m 0444 \
          ${./fixtures/unfused-capsule/boot.sig} \
          "$out/boot.sig"
        canonical_plan="$(cat ${unfusedCapsuleSigningPlan}/plan.json)"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-boot-signing-plan.v1alpha1'
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
            'kaiba.provisioning.rpi5-boot-signing-result/v1alpha1' \
          --arg plan_id \
            "$(jq -r .plan_id ${unfusedCapsuleSigningPlan}/plan.json)" \
          --arg plan_digest "$plan_digest" \
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
          ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json
        check-jsonschema --check-metaschema \
          ${built.goSource}/schemas/rpi5-boot-signing-plan-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-boot-signing-result-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-rpiboot-directory-tree-v1alpha1.schema.json \
          ${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha1.schema.json \
          ${built.goSource}/schemas/secure-boot-bundle-v1alpha1.schema.json \
          ${built.goSource}/schemas/signing-grant-registry-v1alpha1.schema.json \
          ${built.goSource}/schemas/signing-request-v1alpha1.schema.json \
          ${built.goSource}/schemas/unsigned-artifact-set-v1alpha1.schema.json \
          ${built.goSource}/schemas/yubikey-signing-policy-v1alpha1.schema.json
        # Resolve cross-schema references from the immutable source tree.
        check-jsonschema \
          --base-uri file://${built.goSource}/schemas/ \
          --schemafile ${built.goSource}/schemas/signing-grant-registry-v1alpha1.schema.json \
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
    compiledArtifactSetDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    expectedBootImageDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    expectedEEPROMHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    freshCommitBundle = "${built.rpi5ProbeBundle}/bundle";
    freshReadbackBundle = "${built.rpi5ProbeBundle}/bundle";
    negativeBootBundle = "${built.rpi5ProbeBundle}/bundle";
    ownedReadbackBundle = "${built.rpi5ProbeBundle}/bundle";
    ownedRecoveryBundle = "${built.rpi5ProbeBundle}/bundle";
    rootIntegrityBundle = "${built.rpi5ProbeBundle}/bundle";
    laneGuardPackageDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    signedReleaseManifestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  };

  moduleEval = import ./module-eval.nix {
    inherit pkgs lib kaibaModules;
    kaibaAuditPackage = built.audit;
    kaibaControlPackage = built.control;
    kaibaLaneGuardPackage = physicalLaneGuardFixture;
    kaibaProvisionPackage = built.provision;
    kaibaStationDemoPackage = built.stationDemo;
  };

  checks = [
    {
      id = "device-profile-schema";
      description = "Experimental Raspberry Pi 5 device-profile conformance with the strict v1alpha1 schema.";
    }
    {
      id = "go-tests";
      description = "Go package tests covering the provisioning profile, adapter, live acquisition, and CLI behavior.";
    }
    {
      id = "media-staging-fixture";
      description = "Synthetic capsule-bound regular-file fixture validates FAT/GPT layout, staged extents, reopened readback, complete partition digests, dm-verity, and fail-closed tamper rejection without making hardware or enforcement claims.";
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
          evidence = [ ];
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
          ${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha1.schema.json

        readonly release_schema=${built.goSource}/schemas/rpi5-signed-release-manifest-v1alpha1.schema.json
        readonly golden_manifest=${built.goSource}/internal/provisioning/bundle/testdata/rpi5-signed-release-manifest-v1alpha1.json
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
          and .verity.data_device == "/dev/nvme0n1p2"
          and .verity.hash_device == "/dev/nvme0n1p3"
          and .verity.mapper == "/dev/mapper/root"
          and .verity.algorithm == "sha256"
          and .boot_command_line_path == "cmdline.txt"
        ' ${secureBootFixtureA}/manifest.json > /dev/null
        jq --compact-output --sort-keys 'del(.bundle_digest)' \
          ${secureBootFixtureA}/manifest.json > "$TMPDIR/canonical-manifest"
        expected_bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
          cat "$TMPDIR/canonical-manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .bundle_digest ${secureBootFixtureA}/manifest.json)" = \
          "$expected_bundle_digest"

        root_hash="$(jq -r .root_integrity_digest ${secureBootFixtureA}/manifest.json | cut -d: -f2)"
        veritysetup verify \
          ${secureBootFixtureA}/nvme/root-data.img \
          ${secureBootFixtureA}/nvme/root-hash.img \
          "$root_hash"
        mtype -i ${secureBootFixtureA}/unsigned/boot.img ::cmdline.txt \
          | grep -F "root=/dev/mapper/root rootfstype=ext4 rd.systemd.verity=1 roothash=$root_hash"
        mtype -i ${secureBootFixtureA}/unsigned/boot.img ::kaiba-root-integrity.json \
          | jq -e --arg root_hash "$root_hash" \
            '.root_hash == $root_hash and .no_superblock == false' \
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
        printf '%s\n' boot.img plan.json public.pem \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"

        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-boot-signing-plan-v1alpha1.schema.json \
          ${bootSigningPlanFixture}/plan.json

        cmp \
          ${secureBootFixtureA}/unsigned/boot.img \
          ${bootSigningPlanFixture}/boot.img
        cmp \
          ${./fixtures/development-boot-public.pem} \
          ${bootSigningPlanFixture}/public.pem
        test "$(jq -r .schema_version ${bootSigningPlanFixture}/plan.json)" = \
          'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1'
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
          'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1'
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
          signing-plan.json \
          signing-result.json \
          > "$TMPDIR/expected-final-files"
        cmp "$TMPDIR/expected-final-files" "$TMPDIR/actual-final-files"
        cmp ${signedBootFinalizerBootImage} ${verifiedSignedBootFixture}/boot.img
        cmp ${./fixtures/signed-boot-finalizer/boot.sig} ${verifiedSignedBootFixture}/boot.sig
        cmp ${signedBootFinalizerPublicKey} ${verifiedSignedBootFixture}/public.pem
        cmp ${signedBootFinalizerPlan}/plan.json ${verifiedSignedBootFixture}/signing-plan.json
        cmp \
          ${./fixtures/signed-boot-finalizer/signing-result.json} \
          ${verifiedSignedBootFixture}/signing-result.json
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-boot-signing-result-v1alpha1.schema.json \
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
          kaiba-provision-signer \
          kaiba-provision-signing-client \
          kaiba-provision-signing-gate \
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
        test -x \
          ${developmentYubiKeySigning.kaibaSigning.signedBoot}/bin/kaiba-provision-sign-boot
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
          pkgs.jq
        ];
      }
      ''
        test -x ${built.suite}/bin/kaiba-provision
        test -x ${built.serviceSuite}/bin/kaiba-provision-audit
        test -x ${built.serviceSuite}/bin/kaiba-provision-control
        test -x ${built.serviceSuite}/bin/kaiba-provision-lane-guard
        test -x ${built.serviceSuite}/bin/kaiba-provision-signer
        test -x ${built.serviceSuite}/bin/kaiba-provision-signing-client
        test -x ${built.serviceSuite}/bin/kaiba-provision-signing-gate
        test -x ${built.serviceSuite}/bin/kaiba-provision-station
        test -x ${built.serviceSuite}/bin/kaiba-provision-yubikey-wrapper
        test -x ${built.signedBootTool}/bin/kaiba-provision-sign-boot
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
        if strings ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal \
          | grep -E 'internal/provisioning/(physicalrpi5|rpi5)([./]|$)|/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'integrated rehearsal links a live physical provisioning capability' >&2
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
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/rpiboot|/gpioset'; then
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
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
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
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)([./]|$)|/rpiboot|/gpioset'; then
          echo 'media stager links a Pi ownership or lane-control capability' >&2
          exit 1
        fi
        test -x ${physicalLaneGuardFixture}/bin/kaiba-provision-lane-guard
        ${physicalLaneGuardFixture}/bin/kaiba-provision-lane-guard \
          --print-release-binding > "$TMPDIR/physical-lane-release-binding.json"
        jq -e '
          . == {
            "signed_release_manifest_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "lane_guard_package_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "compiled_artifact_set_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "expected_customer_key_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_eeprom_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "expected_boot_image_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          }
        ' "$TMPDIR/physical-lane-release-binding.json"
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.signedReleaseManifestDigest}' = \
          'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.laneGuardPackageDigest}' = \
          'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
        test '${physicalLaneGuardFixture.kaibaPhysicalLaneGuard.compiledArtifactSetDigest}' = \
          'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
        test -r ${built.provision}/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json
        test -r ${built.provision}/share/kaiba/schemas/rpi5-hardware-qualification-v1alpha1.schema.json
        test -f ${deviceProfileSchema}/passed
        test -f ${probeBundleIntegrity}/passed
        test -f ${rpibootMetadataStdoutCompatibility}/passed
        test -f ${signedReleaseManifestContract}/passed
        test -f ${secureBootArtifactContract}/passed
        test -f ${signedBootPlanContract}/passed
        test -f ${unfusedCapsuleContract}/passed
        test -f ${mediaStagingFixtureContract}/passed
        test -f ${developmentYubiKeySigningContract}/passed
        test -f ${moduleEval}/results.txt

        jq -e '[.checks[] | select(.id == "media-staging-fixture") | .status] == ["passed"]' \
          ${canonicalJSON}/platform.json > /dev/null
        jq -e '
          [.automated.checks[]
            | select(.id == "media-staging-fixture")
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

        mkdir -p "$out/evidence/provisioning/hardware-qualification"
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
    developmentYubiKeySigningContract
    deviceProfileSchema
    mediaStagingFixtureContract
    moduleEval
    probeBundleIntegrity
    provisioningTestResult
    rpibootMetadataStdoutCompatibility
    secureBootArtifactContract
    signedReleaseManifestContract
    signedBootPlanContract
    unfusedCapsuleContract
    ;
}
