{
  pkgs,
  lib,
  moduleRoot ? ../../provisioning,
}:

let
  version = "0.1.0";
  # Flake Git sources are already clean. Filtering this store-backed subpath a
  # second time can leave an unmaterialized source path under lazy-tree Nix.
  goSource = moduleRoot;

  # Keep the audited recovery firmware on the frozen Nixpkgs source while
  # backporting only the two upstream host-tool commits that make metadata
  # arrive on stdout without -j. The post-patch digest is the exact main.c
  # blob produced by upstream commit f64fa310afd45eb7c5b46ec4f9319e5404a48e6a.
  rpibootBase = pkgs.rpiboot;
  rpibootSource = pkgs.applyPatches {
    name = "rpiboot-${rpibootBase.version}-kaiba-source";
    src = rpibootBase.src;
    patches = [ ./patches/rpiboot-metadata-stdout.patch ];
    postPatch = ''
      test "$(sha256sum main.c | cut -d ' ' -f 1)" = \
        d506bbde92c66f96655d000892e13903a19c39468f87be9fdd930334d95c0e7c
    '';
  };
  rpiboot = rpibootBase.overrideAttrs (previous: {
    version = "${previous.version}+kaiba-stdout-metadata.1";
    src = rpibootSource;
    patches = [ ];
    makeFlags = (previous.makeFlags or [ ]) ++ [
      "BUILD_DATE=2025/12/02"
      "GIT_VER=f64fa310"
      "PKG_VER=20250908~162618~bookworm+kaiba-stdout-metadata.1"
    ];
    passthru = (previous.passthru or { }) // {
      kaibaMetadataStdoutBackport = {
        baseVersion = rpibootBase.version;
        mainSHA256 = "d506bbde92c66f96655d000892e13903a19c39468f87be9fdd930334d95c0e7c";
        upstreamCommits = [
          "163cc6e5e69c92f39666ad40c496bcd917c1a0d8"
          "f64fa310afd45eb7c5b46ec4f9319e5404a48e6a"
        ];
      };
    };
  });

  rpi5ProbeBundle =
    pkgs.runCommand "kaiba-rpi5-probe-bundle"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
        passthru = {
          inherit rpiboot;
        };
      }
      ''
        mkdir -p "$out/bundle"
        install -m 0444 ${rpibootBase.src}/recovery5/bootcode5.bin "$out/bundle/bootcode5.bin"
        printf '%s\n' 'recovery_metadata=1' > "$out/bundle/config.txt"
        chmod 0444 "$out/bundle/config.txt"

        rpiboot_sha256="sha256:$(sha256sum ${rpiboot}/bin/rpiboot | cut -d ' ' -f 1)"
        bootcode_sha256="sha256:$(sha256sum "$out/bundle/bootcode5.bin" | cut -d ' ' -f 1)"
        config_sha256="sha256:$(sha256sum "$out/bundle/config.txt" | cut -d ' ' -f 1)"
        bundle_sha256="$(
          printf '%s\0%s\0%s\0%s\0%s\0' \
            'kaiba.rpi5.probe-bundle.v1' \
            'bootcode5.bin' "$bootcode_sha256" \
            'config.txt' "$config_sha256" \
            | sha256sum | cut -d ' ' -f 1
        )"
        bundle_sha256="sha256:$bundle_sha256"

        jq --null-input \
          --arg schema 'kaiba.rpi5-probe-bundle/v1alpha1' \
          --arg tool_version '${rpiboot.version}' \
          --arg rpiboot_sha256 "$rpiboot_sha256" \
          --arg bootcode_sha256 "$bootcode_sha256" \
          --arg config_sha256 "$config_sha256" \
          --arg bundle_sha256 "$bundle_sha256" \
          '{
            schema: $schema,
            tool_version: $tool_version,
            tool_sha256: $rpiboot_sha256,
            bundle_sha256: $bundle_sha256,
            files: {
              "bootcode5.bin": $bootcode_sha256,
              "config.txt": $config_sha256
            }
          }' > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  suite = pkgs.buildGoModule {
    pname = "kaiba-provisioning";
    inherit version;
    src = goSource;

    subPackages = [
      "cmd/kaiba-provision"
      "cmd/kaiba-provision-station-demo"
    ];

    ldflags = [
      "-X=main.rpibootPath=${rpiboot}/bin/rpiboot"
      "-X=main.probeBundlePath=${rpi5ProbeBundle}/bundle"
      "-X=main.probeManifestPath=${rpi5ProbeBundle}/manifest.json"
      "-X=main.buildSystem=${pkgs.stdenv.hostPlatform.system}"
    ];

    vendorHash = null;

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      go test ./...
      runHook postCheck
    '';
  };

  serviceSuite = pkgs.buildGoModule {
    pname = "kaiba-provisioning-services";
    inherit version;
    src = goSource;

    subPackages = [
      "cmd/kaiba-provision-audit"
      "cmd/kaiba-provision-control"
      "cmd/kaiba-provision-lane-guard"
      "cmd/kaiba-provision-signer"
      "cmd/kaiba-provision-signing-client"
      "cmd/kaiba-provision-signing-gate"
      "cmd/kaiba-provision-station"
      "cmd/kaiba-provision-yubikey-wrapper"
    ];

    vendorHash = null;

    # The primary suite already runs every package test.  Keeping the service
    # link step separate prevents probe-only build-time paths from becoming
    # ambient configuration for the control and station processes.
    doCheck = false;
  };

  # Keep the software-only rehearsal in its own derivation.  In particular,
  # do not symlink it from serviceSuite: that output also contains the lane
  # guard and would make the closure boundary impossible to audit.
  rehearsal = pkgs.buildGoModule {
    pname = "kaiba-provision-rehearsal";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-rehearsal" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaRehearsal = {
      authority = "rehearsal_only_non_authoritative";
      hardwareAccess = false;
      mutationCapable = false;
      otpCapable = false;
    };
    meta = {
      mainProgram = "kaiba-provision-rehearsal";
      description = "Software-only Kaiba secure-boot campaign rehearsal";
      platforms = lib.platforms.linux;
    };
  };

  # This closure exercises the real durable control/audit/plan-binding code,
  # but its only executor is the software rehearsal simulator. Keep it apart
  # from serviceSuite so the lane guard and physical adapter are not available
  # as sibling binaries at runtime.
  integratedRehearsal = pkgs.buildGoModule {
    pname = "kaiba-provision-integrated-rehearsal";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-integrated-rehearsal" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaIntegratedRehearsal = {
      authority = "non_authoritative";
      executionMode = "software_only";
      directHardwareAccess = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
    };
    meta = {
      mainProgram = "kaiba-provision-integrated-rehearsal";
      description = "Durable control/audit secure-boot rehearsal with a software-only executor";
      platforms = lib.platforms.linux;
    };
  };

  # Offline verification of an unfused compatibility capsule is also kept in
  # a dedicated closure.  It deliberately has no device runner or subprocess
  # boundary; later media and lane tools consume only its verified receipts.
  unfusedCompat = pkgs.buildGoModule {
    pname = "kaiba-provision-unfused-compat";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-unfused-compat" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaUnfusedCompatibility = {
      evidenceMode = "offline_fixture";
      hardwareAccess = false;
      mutationCapable = false;
      otpCapable = false;
      securityEnforcementClaim = false;
      signerTrustAnchored = false;
    };
    meta = {
      mainProgram = "kaiba-provision-unfused-compat";
      description = "Offline verifier for unfused Raspberry Pi 5 compatibility capsules";
      platforms = lib.platforms.linux;
    };
  };

  # The media stager is intentionally not part of serviceSuite or any station
  # image.  It can overwrite an explicitly approved block device, so operators
  # must opt into this dedicated closure and its narrow CLI.  It carries no Pi
  # OTP, EEPROM, RPIBOOT, GPIO, or lane-guard implementation.
  mediaStager = pkgs.buildGoModule {
    pname = "kaiba-provision-media-stager";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-media-stager" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaMediaStager = {
      blockDeviceWriteCapable = true;
      oneTimeSettingCapable = false;
      otpCapable = false;
      eepromProgrammingCapable = false;
      fixtureModeAvailable = true;
    };
    meta = {
      mainProgram = "kaiba-provision-media-stager";
      description = "Fail-closed target-media writer with reopened digest readback";
      platforms = lib.platforms.linux;
    };
  };

  # This verifier re-verifies raw signed capsule inputs and correlates them with
  # already captured operator and UART records. It has no live serial, USB,
  # GPIO, block-device, or subprocess boundary and emits no hardware claim.
  unfusedEvidence = pkgs.buildGoModule {
    pname = "kaiba-provision-unfused-evidence";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-unfused-evidence" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaUnfusedEvidence = {
      evidenceMode = "offline_operator_correlation";
      captureAuthenticated = false;
      directHardwareAccess = false;
      hardwareObservationClaim = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      securityEnforcementClaim = false;
      signerTrustAnchored = false;
    };
    meta = {
      mainProgram = "kaiba-provision-unfused-evidence";
      description = "Offline correlator for operator-recorded unfused Pi 5 boot records";
      platforms = lib.platforms.linux;
    };
  };

  # Build both passive unfused verifiers with one immutable signer anchor. The
  # public key remains an explicit runtime input for offline inspection, but a
  # caller-selected key cannot become trusted unless its canonical SPKI digest
  # matches this linker-fixed fingerprint.
  mkRpi5UnfusedVerifier =
    {
      trustedPublicKeyFingerprint,
      name ? "kaiba-rpi5-unfused-verifier",
    }:
    assert lib.assertMsg (canonicalDigest trustedPublicKeyFingerprint)
      "trustedPublicKeyFingerprint must use canonical sha256:<64 lowercase hex> form";
    let
      buildVerifier =
        {
          pname,
          subPackage,
        }:
        pkgs.buildGoModule {
          inherit pname version;
          src = goSource;
          subPackages = [ subPackage ];
          vendorHash = null;
          doCheck = false;
          ldflags = [ "-X=main.trustedSignerFingerprint=${trustedPublicKeyFingerprint}" ];
        };
      compatibilityVerifier = buildVerifier {
        pname = "${name}-compatibility";
        subPackage = "cmd/kaiba-provision-unfused-compat";
      };
      evidenceVerifier = buildVerifier {
        pname = "${name}-evidence";
        subPackage = "cmd/kaiba-provision-unfused-evidence";
      };
    in
    pkgs.symlinkJoin {
      inherit name;
      paths = [
        compatibilityVerifier
        evidenceVerifier
      ];
      passthru.kaibaUnfusedVerifier = {
        inherit compatibilityVerifier evidenceVerifier trustedPublicKeyFingerprint;
        captureAuthenticated = false;
        directHardwareAccess = false;
        evidenceMode = "offline_operator_correlation";
        hardwareObservationClaim = false;
        mutationCapable = false;
        oneTimeSettingCapable = false;
        otpCapable = false;
        securityEnforcementClaim = false;
        signerTrustAnchored = true;
      };
      meta = {
        description = "Signer-anchored offline Raspberry Pi 5 unfused compatibility and evidence verifiers";
        platforms = lib.platforms.linux;
      };
    };

  servicePackage =
    {
      binary,
      description,
      name ? binary,
    }:
    pkgs.runCommand name
      {
        meta = {
          mainProgram = binary;
          inherit description;
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p "$out/bin"
        ln -s ${serviceSuite}/bin/${binary} "$out/bin/${binary}"
      '';

  audit = servicePackage {
    binary = "kaiba-provision-audit";
    description = "Kaiba append-only provisioning audit reference service";
  };

  control = servicePackage {
    binary = "kaiba-provision-control";
    description = "Kaiba provisioning transaction and inventory reference service";
  };

  laneGuard = servicePackage {
    binary = "kaiba-provision-lane-guard";
    description = "Kaiba one-lane privileged Raspberry Pi 5 provisioning guard";
  };

  liveStation = servicePackage {
    binary = "kaiba-provision-station";
    description = "Kaiba live secure-boot provisioning station interface";
  };

  signerFoundation = servicePackage {
    binary = "kaiba-provision-signer";
    description = "Fail-closed Kaiba Raspberry Pi signing-wrapper foundation";
  };

  signingClientFoundation = servicePackage {
    binary = "kaiba-provision-signing-client";
    description = "Fail-closed Kaiba approval-gate signing client foundation";
  };

  signingGateFoundation = servicePackage {
    binary = "kaiba-provision-signing-gate";
    description = "Fail-closed Kaiba approval-gated signing service foundation";
  };

  yubiKeyWrapperFoundation = servicePackage {
    binary = "kaiba-provision-yubikey-wrapper";
    description = "Fail-closed Kaiba YubiKey PKCS#11 wrapper foundation";
  };

  canonicalDigest = value: builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalRawDigest = value: builtins.match "[0-9a-f]{64}" value != null;
  canonicalIdentifier = value: builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
  cleanAbsolute =
    value: builtins.isString value && lib.hasPrefix "/" value && !(lib.hasInfix "/../" value);
  storeBacked =
    value: cleanAbsolute (toString value) && lib.hasPrefix "${builtins.storeDir}/" (toString value);

  # Produces the only lane-guard build that can cross the mutation boundary.
  # Every executable, payload, and expected digest is fixed into the binary;
  # runtime JSON can select only a typed operation already present in its
  # approved plan.
  mkRpi5PhysicalLaneGuard =
    {
      compiledArtifactSetDigest,
      expectedBootImageDigest,
      expectedCustomerKeyHash,
      expectedEEPROMHash,
      freshCommitBundle,
      freshReadbackBundle,
      negativeBootBundle,
      ownedReadbackBundle,
      ownedRecoveryBundle,
      rootIntegrityBundle,
      signedReleaseManifestDigest,
      laneGuardPackageDigest,
      name ? "kaiba-rpi5-physical-lane-guard",
    }:
    assert lib.assertMsg (canonicalDigest signedReleaseManifestDigest)
      "signedReleaseManifestDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest laneGuardPackageDigest)
      "laneGuardPackageDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest compiledArtifactSetDigest)
      "compiledArtifactSetDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest expectedBootImageDigest)
      "expectedBootImageDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalRawDigest expectedCustomerKeyHash)
      "expectedCustomerKeyHash must contain 64 lowercase hexadecimal characters";
    assert lib.assertMsg (canonicalRawDigest expectedEEPROMHash)
      "expectedEEPROMHash must contain 64 lowercase hexadecimal characters";
    assert lib.assertMsg (lib.all storeBacked [
      freshCommitBundle
      freshReadbackBundle
      negativeBootBundle
      ownedReadbackBundle
      ownedRecoveryBundle
      rootIntegrityBundle
    ]) "every physical lane bundle must be a fixed Nix-store path";
    pkgs.buildGoModule {
      pname = name;
      inherit version;
      src = goSource;
      subPackages = [ "cmd/kaiba-provision-lane-guard" ];
      vendorHash = null;
      doCheck = false;
      ldflags = [
        "-X=main.rpibootBinary=${rpiboot}/bin/rpiboot"
        "-X=main.gpioSetBinary=${pkgs.libgpiod}/bin/gpioset"
        "-X=main.freshReadbackBundle=${toString freshReadbackBundle}"
        "-X=main.freshCommitBundle=${toString freshCommitBundle}"
        "-X=main.ownedReadbackBundle=${toString ownedReadbackBundle}"
        "-X=main.ownedRecoveryBundle=${toString ownedRecoveryBundle}"
        "-X=main.negativeBootBundle=${toString negativeBootBundle}"
        "-X=main.rootIntegrityBundle=${toString rootIntegrityBundle}"
        "-X=main.signedReleaseManifestDigest=${signedReleaseManifestDigest}"
        "-X=main.laneGuardPackageDigest=${laneGuardPackageDigest}"
        "-X=main.compiledArtifactSetDigest=${compiledArtifactSetDigest}"
        "-X=main.expectedCustomerKeyHash=${expectedCustomerKeyHash}"
        "-X=main.expectedEEPROMHash=${expectedEEPROMHash}"
        "-X=main.expectedBootImageDigest=${expectedBootImageDigest}"
      ];
      passthru.kaibaPhysicalLaneGuard = {
        inherit
          compiledArtifactSetDigest
          expectedBootImageDigest
          expectedCustomerKeyHash
          expectedEEPROMHash
          laneGuardPackageDigest
          signedReleaseManifestDigest
          ;
        gpioSet = pkgs.libgpiod;
        inherit rpiboot;
      };
      meta = {
        mainProgram = "kaiba-provision-lane-guard";
        description = "Immutable one-lane Raspberry Pi 5 secure-boot mutation guard";
        platforms = lib.platforms.linux;
      };
    };

  # Builds the complete external-wrapper -> approval gate -> immutable
  # OpenSSL-provider -> YKCS11 chain.  Only public metadata enters the Nix
  # store; the PIN is read at runtime from the fixed systemd credential path.
  mkDevelopmentYubiKeySigning =
    {
      cohortID,
      expectedCustomerKeyHash,
      grantRegistryPath ? "/etc/kaiba-provisioning/signing-grants.json",
      publicKeyFingerprint,
      publicKeyPEM,
      signerID,
      tokenSerial,
      name ? "kaiba-development-yubikey-signing",
    }:
    assert lib.assertMsg (canonicalIdentifier cohortID) "cohortID must be a canonical identifier";
    assert lib.assertMsg (canonicalIdentifier signerID) "signerID must be a canonical identifier";
    assert lib.assertMsg (
      builtins.match "[0-9]{1,16}" tokenSerial != null
    ) "tokenSerial must contain 1 to 16 decimal digits";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalRawDigest expectedCustomerKeyHash)
      "expectedCustomerKeyHash must contain 64 lowercase hexadecimal characters";
    assert lib.assertMsg (storeBacked publicKeyPEM) "publicKeyPEM must be a fixed Nix-store path";
    assert lib.assertMsg (
      cleanAbsolute grantRegistryPath && !lib.hasPrefix "${builtins.storeDir}/" grantRegistryPath
    ) "grantRegistryPath must be an absolute mutable root-managed path outside the Nix store";
    let
      socketPath = "/run/kaiba-provision-signing/signing.sock";
      stateDirectoryPath = "/var/lib/kaiba-provision-signing";
      pinCredentialPath = "/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin";
      pkcs11URI = "pkcs11:serial=${tokenSerial};id=%02;type=private";
      ykcs11Module = "${pkgs.yubico-piv-tool}/lib/libykcs11.so.${pkgs.yubico-piv-tool.version}";
      pkcs11ProviderModule = "${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so";
      customerKeyPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.pycryptodomex ]);
      customerKeyContract =
        pkgs.runCommand "${name}-customer-key-contract"
          {
            nativeBuildInputs = [
              customerKeyPython
              pkgs.coreutils
            ];
          }
          ''
            set -euo pipefail

            ${customerKeyPython}/bin/python3 \
              ${pkgs.raspberrypi-eeprom.src}/tools/rpi-bootloader-key-convert \
              ${publicKeyPEM} \
              --output "$TMPDIR/customer-public-key.bin"
            test "$(stat --format=%s "$TMPDIR/customer-public-key.bin")" -eq 264

            actual_customer_key_hash="$(
              sha256sum "$TMPDIR/customer-public-key.bin" | cut -d ' ' -f 1
            )"
            if test "$actual_customer_key_hash" != '${expectedCustomerKeyHash}'; then
              echo "configured Raspberry Pi customer-key hash does not match publicKeyPEM" >&2
              exit 1
            fi

            mkdir -p "$out/share/kaiba"
            install -m 0444 \
              "$TMPDIR/customer-public-key.bin" \
              "$out/share/kaiba/customer-public-key.bin"
            printf '%s\n' "$actual_customer_key_hash" \
              > "$out/share/kaiba/customer-key-hash"
          '';
      opensslConfiguration = pkgs.writeText "kaiba-yubikey-openssl.cnf" ''
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
        module = ${pkcs11ProviderModule}
        pkcs11-module-path = ${ykcs11Module}
        pkcs11-module-token-pin = file:${pinCredentialPath}
        pkcs11-module-cache-keys = false
        pkcs11-module-cache-sessions = 0
        pkcs11-module-login-behavior = always
        activate = 1
      '';
      buildCommand =
        {
          pname,
          subPackage,
          ldflags,
        }:
        pkgs.buildGoModule {
          inherit pname version ldflags;
          src = goSource;
          subPackages = [ subPackage ];
          vendorHash = null;
          doCheck = false;
        };
      yubiKeyWrapper = buildCommand {
        pname = "${name}-yubikey-wrapper";
        subPackage = "cmd/kaiba-provision-yubikey-wrapper";
        ldflags = [
          "-X=main.opensslExecutablePath=${pkgs.openssl}/bin/openssl"
          "-X=main.opensslConfigurationPath=${opensslConfiguration}"
          "-X=main.pkcs11ProviderModulePath=${pkcs11ProviderModule}"
          "-X=main.ykcs11ModulePath=${ykcs11Module}"
          "-X=main.yubiKeyPKCS11URI=${pkcs11URI}"
          "-X=main.yubiKeyPINCredentialPath=${pinCredentialPath}"
          "-X=main.yubiKeyPublicKeyPEMPath=${toString publicKeyPEM}"
          "-X=main.yubiKeyExpectedPublicKeyFingerprint=${publicKeyFingerprint}"
        ];
      };
      signingGate = buildCommand {
        pname = "${name}-gate";
        subPackage = "cmd/kaiba-provision-signing-gate";
        ldflags = [
          "-X=main.signingGateSocketPath=${socketPath}"
          "-X=main.signingGrantRegistryPath=${grantRegistryPath}"
          "-X=main.signingStateDirectoryPath=${stateDirectoryPath}"
          "-X=main.signingBackendID=backend:${signerID}"
          "-X=main.signingBackendExecutablePath=${yubiKeyWrapper}/bin/kaiba-provision-yubikey-wrapper"
          "-X=main.signingBackendArgumentsJSON=[]"
        ];
      };
      signingClient = buildCommand {
        pname = "${name}-client";
        subPackage = "cmd/kaiba-provision-signing-client";
        ldflags = [ "-X=main.signingGateSocketPath=${socketPath}" ];
      };
      signer = buildCommand {
        pname = "${name}-rpi-wrapper";
        subPackage = "cmd/kaiba-provision-signer";
        ldflags = [
          "-X=main.approvalGatedSignerPath=${signingClient}/bin/kaiba-provision-signing-client"
          "-X=main.approvalGatedSignerArgumentsJSON=[]"
          "-X=main.developmentSignerID=${signerID}"
          "-X=main.developmentCohortID=${cohortID}"
          "-X=main.developmentPKCS11URI=${pkcs11URI}"
          "-X=main.developmentPublicKeyFingerprint=${publicKeyFingerprint}"
        ];
      };
    in
    pkgs.symlinkJoin {
      inherit name;
      paths = [
        customerKeyContract
        signer
        signingClient
        signingGate
        yubiKeyWrapper
      ];
      passthru.kaibaSigning = {
        inherit
          cohortID
          customerKeyContract
          expectedCustomerKeyHash
          grantRegistryPath
          opensslConfiguration
          pkcs11ProviderModule
          pinCredentialPath
          pkcs11URI
          publicKeyFingerprint
          signerID
          signingClient
          signingGate
          socketPath
          stateDirectoryPath
          ykcs11Module
          yubiKeyWrapper
          ;
        customerKeyHashFile = "${customerKeyContract}/share/kaiba/customer-key-hash";
        customerPublicKeyBinary = "${customerKeyContract}/share/kaiba/customer-public-key.bin";
      };
      meta = {
        mainProgram = "kaiba-provision-signer";
        description = "Approval-gated development YubiKey Raspberry Pi signing chain";
        platforms = lib.platforms.linux;
      };
    };

  stationGraphGenerator = pkgs.buildGoModule {
    pname = "kaiba-provision-station-graph";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-station-graph" ];
    vendorHash = null;
    doCheck = false;
  };

  stationPages =
    pkgs.runCommand "kaiba-provision-station-pages"
      {
        meta = {
          description = "Static browser simulation of the Kaiba provisioning-station workflow";
          platforms = lib.platforms.all;
        };
      }
      ''
        set -eu
        mkdir -p "$out"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/index.html "$out/index.html"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/styles.css "$out/styles.css"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/transport.js "$out/transport.js"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/app.js "$out/app.js"
        printf '%s\n' \
          '{"schema_version":"provisioning.kaiba.network/station-demo-runtime/v1alpha1","mode":"transition-graph","graph_url":"./workflow-graph.json"}' \
          > "$out/runtime-config.json"
        ${stationGraphGenerator}/bin/kaiba-provision-station-graph > "$out/workflow-graph.json"
        chmod 0444 "$out/runtime-config.json" "$out/workflow-graph.json"
      '';

  provision =
    pkgs.runCommand "kaiba-provision"
      {
        meta = {
          mainProgram = "kaiba-provision";
          description = "Kaiba non-persistent device provisioning preflight utility";
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p \
          "$out/bin" \
          "$out/libexec/kaiba" \
          "$out/share/kaiba/device-profiles" \
          "$out/share/kaiba/schemas"
        ln -s ${suite}/bin/kaiba-provision "$out/bin/kaiba-provision"
        ln -s ${rpiboot}/bin/rpiboot "$out/libexec/kaiba/rpiboot"
        ln -s ${goSource}/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json \
          "$out/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json"
        ln -s ${goSource}/schemas/device-profile-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/device-profile-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-hardware-qualification-v1alpha1.schema.json"
        ln -s ${rpi5ProbeBundle}/bundle "$out/share/kaiba/rpi5-probe-bundle"
        ln -s ${rpi5ProbeBundle}/manifest.json "$out/share/kaiba/rpi5-probe-bundle-manifest.json"
      '';

  stationDemo =
    pkgs.runCommand "kaiba-provision-station-demo"
      {
        meta = {
          mainProgram = "kaiba-provision-station-demo";
          description = "Kaiba provisioning station interface demo binary";
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p "$out/bin"
        ln -s ${suite}/bin/kaiba-provision-station-demo "$out/bin/kaiba-provision-station-demo"
      '';

in
{
  inherit
    audit
    control
    goSource
    integratedRehearsal
    laneGuard
    liveStation
    mediaStager
    mkDevelopmentYubiKeySigning
    mkRpi5PhysicalLaneGuard
    mkRpi5UnfusedVerifier
    provision
    rehearsal
    rpiboot
    rpibootSource
    rpi5ProbeBundle
    stationDemo
    stationGraphGenerator
    stationPages
    unfusedCompat
    unfusedEvidence
    serviceSuite
    signerFoundation
    signingClientFoundation
    signingGateFoundation
    suite
    yubiKeyWrapperFoundation
    ;
}
