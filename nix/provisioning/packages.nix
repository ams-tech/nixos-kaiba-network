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

  # This generic command can finalize public signed-boot records, but it is
  # deliberately built without a signing backend or private-key locator. A
  # separately configured runtime package may submit a prepared request to an
  # approval-gated signer; Nix derivations only consume the resulting public
  # record.
  signedBootTool = pkgs.buildGoModule {
    pname = "kaiba-provision-sign-boot";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-sign-boot" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaSignedBootTool = {
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
    };
    meta = {
      mainProgram = "kaiba-provision-sign-boot";
      description = "Public signing-plan and signed-boot bundle verifier";
      platforms = lib.platforms.linux;
    };
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

  # Secret-free serializers and validators remain generic. Production writers
  # and verifiers are emitted only by mkRpi5ProductionMedia, which linker-pins
  # one immutable plan, source set, signed release, and verifier toolchain.
  mediaContractTool = pkgs.buildGoModule {
    pname = "kaiba-provision-media-contract";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-media-contract" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaMediaContractTool = {
      blockDeviceAccess = false;
      mutationCapable = false;
      signingAuthorityConfigured = false;
    };
    meta = {
      mainProgram = "kaiba-provision-media-contract";
      description = "Canonical Raspberry Pi 5 media-plan and receipt validator";
      platforms = lib.platforms.linux;
    };
  };

  unfusedRuntimeRecordTool = pkgs.buildGoModule {
    pname = "kaiba-provision-unfused-runtime-record";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-unfused-runtime-record" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaUnfusedRuntimeRecordTool = {
      authority = "serialization_fixture_only";
      blockDeviceAccess = false;
      hardwareObservationClaim = false;
      mutationCapable = false;
      signingAuthorityConfigured = false;
    };
    meta = {
      mainProgram = "kaiba-provision-unfused-runtime-record";
      description = "Plan-correlated serializer for unfused runtime UART records";
      platforms = lib.platforms.linux;
    };
  };

  # Legacy mixed fixture/device prototype retained only for the old synthetic
  # fixture contract. It is deliberately not exported by the provisioning
  # flake; production callers must use mkRpi5ProductionMedia's device-only,
  # plan-specialized stager.
  mediaStager = pkgs.buildGoModule {
    pname = "kaiba-provision-media-stager";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-media-stager" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaMediaStager = {
      authority = "legacy_fixture_prototype";
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

  # Snapshot only a no-follow, exclusively locked regular-file fixture. Keep
  # this helper separate from the block-device-capable media stager so the
  # synthetic verifier does not acquire device-write capability in its closure.
  fixtureSnapshot = pkgs.buildGoModule {
    pname = "kaiba-provision-fixture-snapshot";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-fixture-snapshot" ];
    vendorHash = null;
    doCheck = true;
    checkPhase = ''
      runHook preCheck
      go test ./internal/provisioning/fixturesnapshot ./cmd/kaiba-provision-fixture-snapshot
      runHook postCheck
    '';
    passthru.kaibaFixtureSnapshot = {
      blockDeviceAccess = false;
      directHardwareAccess = false;
      destinationFileWriteCapable = true;
      mutationCapable = false;
      regularFileOnly = true;
      sourceWriteCapable = false;
    };
    meta = {
      mainProgram = "kaiba-provision-fixture-snapshot";
      description = "No-follow, locked snapshot helper for regular-file media fixtures";
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

  eepromReleaseFactories = import ./eeprom-release.nix {
    inherit lib pkgs;
    eepromPackageVersion = pkgs.raspberrypi-eeprom.version;
    eepromSource = pkgs.raspberrypi-eeprom.src;
    eepromSourceHash = pkgs.raspberrypi-eeprom.src.outputHash;
    eepromSourceRevision = pkgs.raspberrypi-eeprom.src.rev;
  };
  inherit (eepromReleaseFactories) mkRpi5EEPROMRelease;
  rpi5EEPROMRelease = mkRpi5EEPROMRelease { };
  rpi5EEPROMReleaseVerifier = eepromReleaseFactories.verifier;

  eepromPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.pycryptodomex ]);
  eepromToolRuntime =
    pkgs.runCommand "kaiba-rpi5-eeprom-signing-toolchain"
      {
        nativeBuildInputs = [ pkgs.makeWrapper ];
      }
      ''
        mkdir -p "$out/bin"
        makeWrapper ${eepromPython}/bin/python3 "$out/bin/rpi-eeprom-config" \
          --add-flags ${lib.escapeShellArg "${rpi5EEPROMRelease}/toolchain/rpi-eeprom-config"}
        makeWrapper ${eepromPython}/bin/python3 "$out/bin/rpi-sign-bootcode" \
          --add-flags ${lib.escapeShellArg "${rpi5EEPROMRelease}/toolchain/rpi-sign-bootcode"}
        makeWrapper ${eepromPython}/bin/python3 "$out/bin/rpi-bootloader-key-convert" \
          --add-flags ${lib.escapeShellArg "${rpi5EEPROMRelease}/toolchain/rpi-bootloader-key-convert"}
        ${pkgs.gnused}/bin/sed \
          '1c #!${pkgs.dash}/bin/dash' \
          ${rpi5EEPROMRelease}/toolchain/rpi-eeprom-digest \
          > "$out/bin/rpi-eeprom-digest"
        ${pkgs.gnused}/bin/sed \
          '1c #!${pkgs.dash}/bin/dash' \
          ${rpi5EEPROMRelease}/toolchain/update-pieeprom.sh \
          > "$out/bin/update-pieeprom.sh"
        chmod 0555 "$out/bin/rpi-eeprom-digest" "$out/bin/update-pieeprom.sh"
      '';
  eepromToolPATH = lib.makeBinPath [
    eepromToolRuntime
    pkgs.binutils
    pkgs.coreutils
    pkgs.findutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
    pkgs.openssl
    pkgs.xxd
  ];
  mkEEPROMSigningToolLDFlags = signingGateSocketPath: [
    "-X=main.signingGateSocketPath=${signingGateSocketPath}"
    "-X=main.pinnedUpdatePieepromExecutablePath=${eepromToolRuntime}/bin/update-pieeprom.sh"
    "-X=main.pinnedRpiEEPROMConfigExecutablePath=${eepromToolRuntime}/bin/rpi-eeprom-config"
    "-X=main.pinnedToolRuntimePath=${eepromToolPATH}"
    "-X=main.expectedEEPROMReleaseManifestDigest=${rpi5EEPROMRelease.kaibaRpi5EEPROMRelease.releaseManifestDigest}"
    "-X=main.expectedOriginalEEPROMDigest=${eepromReleaseFactories.policy.firmware.image.sha256}"
    "-X=main.expectedOriginalRecoveryDigest=${eepromReleaseFactories.policy.firmware.recovery.sha256}"
    "-X=main.expectedOriginalBootcodeDigest=${eepromReleaseFactories.policy.firmware.bootcode.sha256}"
    "-X=main.expectedOriginalBootsysDigest=${eepromReleaseFactories.policy.firmware.bootsys.sha256}"
    "-X=main.expectedEEPROMFirmwareBuildEpoch=${toString eepromReleaseFactories.policy.firmware.buildEpoch}"
  ];
  eepromSigningTool = pkgs.buildGoModule {
    pname = "kaiba-provision-sign-eeprom";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-sign-eeprom" ];
    vendorHash = null;
    doCheck = false;
    ldflags = mkEEPROMSigningToolLDFlags "/run/kaiba-provision-signing/signing.sock";
    passthru.kaibaEEPROMSigningTool = {
      inherit eepromToolRuntime;
      approvalGateConfigured = true;
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      recoverySigningCapable = true;
      ownedRecoveryGateRequestCount = 1;
      ownedRecoveryReusedSignatureCount = 3;
      ownedRecoveryUpdaterFlags = [
        "-f"
        "-r"
      ];
      signingAuthorityConfigured = true;
      toolPATH = eepromToolPATH;
      updaterFlags = [ "-f" ];
      updaterMode = "fresh-board";
    };
    meta = {
      mainProgram = "kaiba-provision-sign-eeprom";
      description = "Approval-gated Raspberry Pi 5 EEPROM and one-input owned-recovery signing adapter";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  };

  # The complete-release finalizer must replay the pinned EEPROM updater and
  # extractor, but it must not inherit the live approval-gate endpoint. This
  # private closure deliberately fixes the unusable character device as its
  # gate path; only the public `finalize` operation is consumed below.
  eepromReplayFinalizer = pkgs.buildGoModule {
    pname = "kaiba-provision-eeprom-replay-finalizer";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-sign-eeprom" ];
    vendorHash = null;
    doCheck = false;
    ldflags = mkEEPROMSigningToolLDFlags "/dev/null";
    passthru.kaibaEEPROMReplayFinalizer = {
      inherit eepromToolRuntime;
      approvalGateConfigured = false;
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
      toolPATH = eepromToolPATH;
      verificationMode = "pinned_offline_replay";
    };
    meta = {
      mainProgram = "kaiba-provision-sign-eeprom";
      description = "No-authority EEPROM finalizer used for deterministic signed-release replay";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  };

  signedReleaseTool = pkgs.buildGoModule {
    pname = "kaiba-provision-finalize-release";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-finalize-release" ];
    vendorHash = null;
    doCheck = true;
    checkPhase = ''
      runHook preCheck
      go test ./internal/provisioning/signedrelease \
        ./cmd/kaiba-provision-finalize-release
      runHook postCheck
    '';
    ldflags = [
      "-X=main.eepromFinalizerExecutablePath=${eepromReplayFinalizer}/bin/kaiba-provision-sign-eeprom"
    ];
    passthru.kaibaSignedReleaseTool = {
      inherit eepromReplayFinalizer;
      artifactRoleCount = 18;
      blockDeviceWriteCapable = false;
      deterministicEEPROMReplayRequired = true;
      deterministicOwnedRecoveryReplayRequired = true;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      publicationSchemaVersion = "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1";
      signingAuthorityConfigured = false;
    };
    meta = {
      mainProgram = "kaiba-provision-finalize-release";
      description = "Offline verifier and content-addressed publisher for complete Raspberry Pi 5 signed releases";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  };

  # Pure public bundle construction is isolated from the physical lane guard:
  # this closure can only copy, mutate the two deterministic negative-test
  # fixtures, snapshot directory trees, and verify public signatures/digests.
  rpibootBundleTool = pkgs.buildGoModule {
    pname = "kaiba-provision-rpiboot-bundles";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-rpiboot-bundles" ];
    vendorHash = null;
    doCheck = false;
    passthru.kaibaRPIBootBundleTool = {
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      fixtureHardwareObserved = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      signingAuthorityConfigured = false;
    };
    meta = {
      mainProgram = "kaiba-provision-rpiboot-bundles";
      description = "Offline constructor and verifier for immutable Raspberry Pi 5 RPIBOOT bundle sets";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  };

  releaseIntentFactories = import ./release-intent.nix {
    inherit lib pkgs;
  };
  inherit (releaseIntentFactories) mkRpi5EEPROMReleaseSigningInputs mkRpi5ReleaseIntent;

  eepromSigningFactories = import ./eeprom-signing.nix {
    eepromRelease = rpi5EEPROMRelease;
    inherit
      eepromSigningTool
      eepromToolRuntime
      lib
      pkgs
      ;
  };
  inherit (eepromSigningFactories) mkRpi5EEPROMSigningPlan mkRpi5VerifiedSignedEEPROM;

  ownedRecoverySigningFactories = import ./owned-recovery-signing.nix {
    inherit eepromSigningTool lib pkgs;
  };
  inherit (ownedRecoverySigningFactories)
    mkRpi5OwnedRecoverySigningPlan
    mkRpi5VerifiedOwnedRecovery
    ;

  rpibootBundleFactories = import ./rpiboot-bundles.nix {
    inherit
      eepromSigningTool
      lib
      pkgs
      rpibootBundleTool
      signedBootTool
      ;
  };
  inherit (rpibootBundleFactories) mkRpi5VerifiedRPIBootBundles;

  signedReleaseFactories = import ./signed-release.nix {
    inherit lib pkgs signedReleaseTool;
  };
  inherit (signedReleaseFactories) mkRpi5VerifiedSignedRelease;

  productionMediaFactories = import ./media-staging.nix {
    inherit
      lib
      mediaContractTool
      moduleRoot
      pkgs
      version
      ;
  };
  inherit (productionMediaFactories) mkRpi5ProductionMedia;

  signedBootFactories = import ./signed-boot.nix {
    inherit lib pkgs signedBootTool;
  };
  inherit (signedBootFactories) mkRpi5BootSigningPlan mkRpi5VerifiedSignedBoot;

  unfusedCapsuleFactories = import ./unfused-capsule.nix {
    inherit lib pkgs mkRpi5UnfusedVerifier;
    unsignedArtifactSchema = goSource + "/schemas/unsigned-artifact-set-v1alpha1.schema.json";
  };
  inherit (unfusedCapsuleFactories) mkRpi5VerifiedUnfusedCapsule;

  mediaStagingFixtureFactories = import ./media-staging-fixture.nix {
    inherit
      fixtureSnapshot
      lib
      mediaStager
      pkgs
      ;
  };
  inherit (mediaStagingFixtureFactories) mkRpi5MediaStagingFixture;

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
      signerPolicyDigest,
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
    assert lib.assertMsg (canonicalDigest signerPolicyDigest)
      "signerPolicyDigest must use canonical sha256:<64 lowercase hex> form";
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
              pkgs.jq
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

            signer_policy_json="$(
              jq \
                --null-input \
                --compact-output \
                --arg schema_version 'kaiba.provisioning.yubikey-signing-policy/v1alpha1' \
                --arg signer_id '${signerID}' \
                --arg cohort_id '${cohortID}' \
                --arg provider 'yubikey-piv' \
                --arg piv_slot '9c' \
                --arg pkcs11_uri '${pkcs11URI}' \
                --arg public_key_fingerprint '${publicKeyFingerprint}' \
                --arg key_algorithm 'rsa-2048' \
                '{
                  schema_version: $schema_version,
                  signer_id: $signer_id,
                  cohort_id: $cohort_id,
                  provider: $provider,
                  piv_slot: $piv_slot,
                  pkcs11_uri: $pkcs11_uri,
                  public_key_fingerprint: $public_key_fingerprint,
                  key_algorithm: $key_algorithm,
                  pin_required: true,
                  touch_required: true,
                  private_key_exportable: false
                }'
            )"
            actual_signer_policy_digest="sha256:$({
              printf '%s\0' 'kaiba.provisioning.yubikey-signing-policy.v1alpha1'
              printf '%s' "$signer_policy_json"
            } | sha256sum | cut -d ' ' -f 1)"
            if test "$actual_signer_policy_digest" != '${signerPolicyDigest}'; then
              echo "configured signerPolicyDigest does not match the canonical YubiKey policy" >&2
              exit 1
            fi

            mkdir -p "$out/share/kaiba"
            install -m 0444 \
              "$TMPDIR/customer-public-key.bin" \
              "$out/share/kaiba/customer-public-key.bin"
            printf '%s\n' "$actual_customer_key_hash" \
              > "$out/share/kaiba/customer-key-hash"
            printf '%s\n' "$signer_policy_json" \
              > "$out/share/kaiba/signer-policy.json"
            printf '%s\n' "$actual_signer_policy_digest" \
              > "$out/share/kaiba/signer-policy-digest"
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
      signedBoot = buildCommand {
        pname = "${name}-sign-boot";
        subPackage = "cmd/kaiba-provision-sign-boot";
        ldflags = [
          "-X=main.signingGateSocketPath=${socketPath}"
          "-X=main.signerID=${signerID}"
          "-X=main.cohortID=${cohortID}"
          "-X=main.signingPKCS11URI=${pkcs11URI}"
          "-X=main.expectedPublicKeyPath=${toString publicKeyPEM}"
          "-X=main.expectedPublicKeyFingerprint=${publicKeyFingerprint}"
        ];
      };
    in
    pkgs.symlinkJoin {
      inherit name;
      paths = [
        customerKeyContract
        signedBoot
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
          signedBoot
          signerID
          signerPolicyDigest
          signingClient
          signingGate
          socketPath
          stateDirectoryPath
          ykcs11Module
          yubiKeyWrapper
          ;
        signedBootConfiguration = {
          gateSocketPath = socketPath;
          inherit
            cohortID
            pkcs11URI
            publicKeyFingerprint
            signerID
            ;
          expectedPublicKeyPath = toString publicKeyPEM;
          runtimeAuthoritySelectors = false;
        };
        customerKeyHashFile = "${customerKeyContract}/share/kaiba/customer-key-hash";
        customerPublicKeyBinary = "${customerKeyContract}/share/kaiba/customer-public-key.bin";
        signerPolicyDigestFile = "${customerKeyContract}/share/kaiba/signer-policy-digest";
        signerPolicyJSON = "${customerKeyContract}/share/kaiba/signer-policy.json";
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
        ln -s ${goSource}/schemas/rpi5-device-media-layout-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-device-media-layout-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-binding-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-binding-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-cold-power-observation-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-cold-power-observation-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-device-preflight-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-device-preflight-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-fixture-result-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-fixture-result-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-stage-receipt-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-stage-receipt-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-staging-plan-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-staging-plan-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-staging-receipt-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-staging-receipt-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-verification-receipt-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-verification-receipt-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-media-verification-report-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-media-verification-report-v1alpha1.schema.json"
        ln -s ${goSource}/schemas/rpi5-unfused-runtime-facts-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/rpi5-unfused-runtime-facts-v1alpha1.schema.json"
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
    mediaContractTool
    mediaStager
    eepromSigningTool
    eepromToolRuntime
    mkDevelopmentYubiKeySigning
    mkRpi5BootSigningPlan
    mkRpi5EEPROMRelease
    mkRpi5EEPROMReleaseSigningInputs
    mkRpi5EEPROMSigningPlan
    mkRpi5PhysicalLaneGuard
    mkRpi5ProductionMedia
    mkRpi5MediaStagingFixture
    mkRpi5OwnedRecoverySigningPlan
    mkRpi5VerifiedRPIBootBundles
    mkRpi5VerifiedSignedRelease
    mkRpi5ReleaseIntent
    mkRpi5UnfusedVerifier
    mkRpi5VerifiedSignedBoot
    mkRpi5VerifiedSignedEEPROM
    mkRpi5VerifiedOwnedRecovery
    mkRpi5VerifiedUnfusedCapsule
    provision
    rehearsal
    rpiboot
    rpibootBundleTool
    rpibootSource
    rpi5EEPROMRelease
    rpi5EEPROMReleaseVerifier
    rpi5ProbeBundle
    stationDemo
    stationGraphGenerator
    stationPages
    unfusedCompat
    unfusedEvidence
    unfusedRuntimeRecordTool
    serviceSuite
    signerFoundation
    signingClientFoundation
    signingGateFoundation
    signedBootTool
    signedReleaseTool
    suite
    yubiKeyWrapperFoundation
    ;
}
