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
  secureBootFixtureRoot =
    pkgs.runCommand "kaiba-secure-boot-fixture-root.img" { nativeBuildInputs = [ pkgs.e2fsprogs ]; }
      ''
        mkdir root
        printf '%s\n' 'kaiba dm-verity fixture' > root/README
        truncate --size=16M "$out"
        mkfs.ext4 \
          -F \
          -L KAIBA_ROOT \
          -U 4b414942-4152-4f4f-9400-000000000001 \
          -d root \
          "$out" \
          > /dev/null
      '';
  canonicalSourceRevision40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  canonicalSourceRevision64 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  mkSecureBootFixture =
    {
      name,
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
      rootImage = secureBootFixtureRoot;
      inherit sourceRevision;
    };
  secureBootFixtureA = mkSecureBootFixture { name = "kaiba-secure-boot-artifacts-fixture-a"; };
  secureBootFixtureB = mkSecureBootFixture { name = "kaiba-secure-boot-artifacts-fixture-b"; };
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
    expectedCustomerKeyHash = developmentYubiKeyCustomerKeyHash;
    grantRegistryPath = "/etc/kaiba-provisioning/signing-grants.json";
  };
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

  secureBootArtifactContract =
    assert lib.assertMsg (lib.all sourceRevisionAccepted validSourceRevisions)
      "the secure-boot artifact builder rejected a canonical Git source revision";
    assert lib.assertMsg (lib.all (sourceRevision: !(sourceRevisionAccepted sourceRevision))
      invalidSourceRevisions
    ) "the secure-boot artifact builder accepted a non-canonical source revision";
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

  developmentYubiKeySigningContract =
    pkgs.runCommand "kaiba-development-yubikey-signing-contract"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.openssl
        ];
      }
      ''
        set -euo pipefail

        expected_binaries="$(${pkgs.coreutils}/bin/printf '%s\n' \
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
        test "$(cat ${developmentYubiKeySigning.kaibaSigning.customerKeyHashFile})" = \
          '${developmentYubiKeyCustomerKeyHash}'
        test "$(stat --format=%s \
          ${developmentYubiKeySigning.kaibaSigning.customerPublicKeyBinary})" -eq 264
        test "$(sha256sum \
          ${developmentYubiKeySigning.kaibaSigning.customerPublicKeyBinary} \
          | cut -d ' ' -f 1)" = '${developmentYubiKeyCustomerKeyHash}'
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
        test -x ${built.provision}/bin/kaiba-provision
        test -x ${built.rehearsal}/bin/kaiba-provision-rehearsal
        test '${built.rehearsal.kaibaRehearsal.authority}' = \
          'rehearsal_only_non_authoritative'
        test '${toString built.rehearsal.kaibaRehearsal.hardwareAccess}' = 'false'
        test '${toString built.rehearsal.kaibaRehearsal.mutationCapable}' = 'false'
        test '${toString built.rehearsal.kaibaRehearsal.otpCapable}' = 'false'
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
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)'; then
          echo 'software rehearsal binary links a physical provisioning package' >&2
          exit 1
        fi
        test -x ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal
        test '${built.integratedRehearsal.kaibaIntegratedRehearsal.authority}' = 'non_authoritative'
        test '${built.integratedRehearsal.kaibaIntegratedRehearsal.executionMode}' = 'software_only'
        test '${toString built.integratedRehearsal.kaibaIntegratedRehearsal.directHardwareAccess}' = 'false'
        test '${toString built.integratedRehearsal.kaibaIntegratedRehearsal.mutationCapable}' = 'false'
        test '${toString built.integratedRehearsal.kaibaIntegratedRehearsal.oneTimeSettingCapable}' = 'false'
        test '${toString built.integratedRehearsal.kaibaIntegratedRehearsal.otpCapable}' = 'false'
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
          and .authority.execute_request_count == 7
          and .simulation.outcome == "rehearsal_passed"
        ' "$TMPDIR/integrated-rehearsal.json" > /dev/null
        if strings ${built.integratedRehearsal}/bin/kaiba-provision-integrated-rehearsal \
          | grep -E 'internal/provisioning/(physicalrpi5|rpi5)|/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'integrated rehearsal links a live physical provisioning capability' >&2
          exit 1
        fi
        test -x ${built.unfusedCompat}/bin/kaiba-provision-unfused-compat
        test '${built.unfusedCompat.kaibaUnfusedCompatibility.evidenceMode}' = \
          'offline_fixture'
        test '${toString built.unfusedCompat.kaibaUnfusedCompatibility.hardwareAccess}' = 'false'
        test '${toString built.unfusedCompat.kaibaUnfusedCompatibility.mutationCapable}' = 'false'
        test '${toString built.unfusedCompat.kaibaUnfusedCompatibility.otpCapable}' = 'false'
        test '${toString built.unfusedCompat.kaibaUnfusedCompatibility.securityEnforcementClaim}' = 'false'
        if strings ${built.unfusedCompat}/bin/kaiba-provision-unfused-compat \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)|/rpiboot|/gpioset'; then
          echo 'unfused compatibility verifier links a physical provisioning capability' >&2
          exit 1
        fi
        test -x ${built.unfusedEvidence}/bin/kaiba-provision-unfused-evidence
        test '${built.unfusedEvidence.kaibaUnfusedEvidence.evidenceMode}' = \
          'operator_hardware_observation'
        test '${toString built.unfusedEvidence.kaibaUnfusedEvidence.directHardwareAccess}' = 'false'
        test '${toString built.unfusedEvidence.kaibaUnfusedEvidence.mutationCapable}' = 'false'
        test '${toString built.unfusedEvidence.kaibaUnfusedEvidence.oneTimeSettingCapable}' = 'false'
        test '${toString built.unfusedEvidence.kaibaUnfusedEvidence.otpCapable}' = 'false'
        test '${toString built.unfusedEvidence.kaibaUnfusedEvidence.securityEnforcementClaim}' = 'false'
        if strings ${built.unfusedEvidence}/bin/kaiba-provision-unfused-evidence \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)|/rpiboot|/gpioset|/dev/serial|/dev/gpio'; then
          echo 'unfused evidence verifier links a live physical provisioning capability' >&2
          exit 1
        fi
        test -x ${built.mediaStager}/bin/kaiba-provision-media-stager
        test '${toString built.mediaStager.kaibaMediaStager.blockDeviceWriteCapable}' = 'true'
        test '${toString built.mediaStager.kaibaMediaStager.oneTimeSettingCapable}' = 'false'
        test '${toString built.mediaStager.kaibaMediaStager.otpCapable}' = 'false'
        test '${toString built.mediaStager.kaibaMediaStager.eepromProgrammingCapable}' = 'false'
        test '${toString built.mediaStager.kaibaMediaStager.fixtureModeAvailable}' = 'true'
        if strings ${built.mediaStager}/bin/kaiba-provision-media-stager \
          | grep -E 'internal/provisioning/(physicalrpi5|laneguard|rpi5)|/rpiboot|/gpioset'; then
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
        test -f ${secureBootArtifactContract}/passed
        test -f ${developmentYubiKeySigningContract}/passed
        test -f ${moduleEval}/results.txt

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
    moduleEval
    probeBundleIntegrity
    provisioningTestResult
    rpibootMetadataStdoutCompatibility
    secureBootArtifactContract
    ;
}
