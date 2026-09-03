{
  description = "Kaiba secure-device dynamic DNS pilot";

  nixConfig = {
    extra-substituters = [
      "https://nixos-raspberrypi.cachix.org"
    ];
    extra-trusted-public-keys = [
      "nixos-raspberrypi.cachix.org-1:4iMO9LXa8BqhU+Rpg6LQKiGa2lsNh/j2oiYLNOQ5sPI="
    ];
    connect-timeout = 5;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";
    nixos-raspberrypi.url = "github:ams-tech/nixos-raspberrypi/24b786fc4750abcce26eb8fc5e9e58632e358ad2";
    provisioning = {
      url = "path:./nix/provisioning";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    dns = {
      url = "path:./nix/dns";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.provisioning.follows = "provisioning";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-raspberrypi,
      provisioning,
      dns,
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      rpi5DevelopmentPosture = builtins.fromJSON (
        builtins.readFile ./provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
      );

      sourceRevision =
        if self ? rev then
          self.rev
        else if self ? dirtyRev then
          self.dirtyRev
        else
          "uncommitted";

      developmentCeremonySourceRevision =
        if self ? rev then
          self.rev
        else
          let
            dirtyMatch = builtins.match "([0-9a-f]{40}|[0-9a-f]{64})-dirty" sourceRevision;
          in
          if dirtyMatch != null then
            builtins.head dirtyMatch
          else
            throw "development signing ceremony package requires a Git revision";
      developmentCeremonySourceTreeClean = self ? rev;

      defaultTargetSourceRevision =
        if
          builtins.isString sourceRevision
          && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null
        then
          sourceRevision
        else
          throw "mkRpi5SecureBootTarget requires a clean Git source or an explicit canonical sourceRevision";

      # Keep this list deliberately small and literal.  The target module
      # filters the kernel DTBs to the single supported Pi 5 Model B base file.
      # The three kernel-matched overlay-directory files let current Pi 5
      # firmware apply the BCM2712 D0 correction. README is the documented
      # os_prefix viability sentinel, bcm2712d0.dtbo carries the correction,
      # and overlay_map.dtb is the matching firmware overlay-name map. The
      # target module disables inherited optional overlay requests. The
      # firmware-tree derivation fails if the pinned upstream population
      # command or this explicit revision-file copy ever adds, removes, or
      # renames a file.
      rpi5SecureBootFirmwareAllowlist = [
        "config.txt"
        "nixos/default/bcm2712-rpi-5-b.dtb"
        "nixos/default/cmdline.txt"
        "nixos/default/initrd"
        "nixos/default/kernel.img"
        "nixos/default/overlays/README"
        "nixos/default/overlays/bcm2712d0.dtbo"
        "nixos/default/overlays/overlay_map.dtb"
      ];

      rpi5ProvisioningSystem = nixos-raspberrypi.lib.nixosSystem {
        trustCaches = false;
        modules = [
          nixos-raspberrypi.nixosModules.sd-image
          nixos-raspberrypi.nixosModules.raspberry-pi-5.base
          nixos-raspberrypi.nixosModules.raspberry-pi-5.page-size-16k
          provisioning.nixosModules.provisioning-probe
          (import ./nix/images/rpi5-provisioning-station.nix {
            kaibaProvisionPackage = provisioning.packages.aarch64-linux.kaiba-provision;
            inherit sourceRevision;
          })
        ];
      };

      mkRpi5SecureBootTarget =
        {
          expectedCustomerKeyHash,
          bootImageSizeMiB ? 96,
          bootOrderPolicy ? rpi5DevelopmentPosture.boot_order.policy,
          rootDataPartitionGUID ? "bdd5be20-f7ea-56e7-ae90-4465ae950596",
          rootHashPartitionGUID ? "62616022-71fb-5036-8cc4-b7949cc6e52c",
          sourceRevision ? defaultTargetSourceRevision,
        }:
        let
          nixosSystem = nixos-raspberrypi.lib.nixosSystem {
            trustCaches = false;
            modules = [
              nixos-raspberrypi.nixosModules.sd-image
              nixos-raspberrypi.nixosModules.raspberry-pi-5.base
              nixos-raspberrypi.nixosModules.raspberry-pi-5.page-size-16k
              provisioning.nixosModules.secure-boot-target
              (import ./nix/images/rpi5-secure-boot-target.nix {
                inherit expectedCustomerKeyHash sourceRevision;
              })
            ];
          };
          targetConfig = nixosSystem.config;
          targetPkgs = nixosSystem.pkgs;
          bootCommandLinePath = "nixos/default/cmdline.txt";
          firmwareAllowlist = rpi5SecureBootFirmwareAllowlist;
          firmwareTree =
            targetPkgs.runCommand "kaiba-rpi5-secure-boot-firmware-tree"
              {
                nativeBuildInputs = with targetPkgs.buildPackages; [
                  coreutils
                  diffutils
                  findutils
                ];
                preferLocalBuild = true;
              }
              ''
                set -euo pipefail
                export LC_ALL=C
                export TZ=UTC

                mkdir -p firmware
                ${targetConfig.sdImage.populateFirmwareCommands}

                # nixos-raspberrypi's shared firmware builder emits legacy
                # Pi 1-4 files and generation metadata. Pi 5 loads firmware
                # from EEPROM and consumes none of these from boot.img.
                rm -f -- \
                  firmware/bootcode.bin \
                  firmware/fixup.dat \
                  firmware/fixup4.dat \
                  firmware/fixup4cd.dat \
                  firmware/fixup4db.dat \
                  firmware/fixup4x.dat \
                  firmware/fixup_cd.dat \
                  firmware/fixup_db.dat \
                  firmware/fixup_x.dat \
                  firmware/start.elf \
                  firmware/start4.elf \
                  firmware/start4cd.elf \
                  firmware/start4db.elf \
                  firmware/start4x.elf \
                  firmware/start_cd.elf \
                  firmware/start_db.elf \
                  firmware/start_x.elf \
                  firmware/nixos/default/kernel-link \
                  firmware/nixos/default/system-link

                # Pi 5 firmware selects this overlay automatically on D0
                # silicon.  hardware.deviceTree.filter intentionally keeps the
                # generated base-DTB set narrow, so copy only the required
                # overlay-directory files from the exact kernel that supplied
                # the base DTB. They remain inside os_prefix and therefore
                # inside the signed boot image.
                mkdir -p firmware/nixos/default/overlays
                for revision_file in README bcm2712d0.dtbo overlay_map.dtb; do
                  source_file=${targetConfig.hardware.deviceTree.dtbSource}/overlays/"$revision_file"
                  if ! test -f "$source_file"; then
                    echo "Raspberry Pi kernel DTBs are missing $revision_file" >&2
                    exit 1
                  fi
                  cp --no-preserve=mode,ownership -- \
                    "$source_file" \
                    firmware/nixos/default/overlays/"$revision_file"
                done

                if test -n "$(find firmware -type l -print -quit)"; then
                  echo "Raspberry Pi firmware population produced a symbolic link" >&2
                  exit 1
                fi
                if test -n "$(find firmware ! -type d ! -type f -print -quit)"; then
                  echo "Raspberry Pi firmware population produced an unsupported filesystem object" >&2
                  exit 1
                fi

                find firmware -type f -printf '%P\n' | sort > actual-files
                {
                  ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") (
                    lib.sort builtins.lessThan firmwareAllowlist
                  )}
                } > expected-files
                if ! cmp expected-files actual-files; then
                  echo "Raspberry Pi firmware population differs from the explicit allowlist" >&2
                  exit 1
                fi

                find firmware -exec touch --date=@315532800 '{}' +
                find firmware -type d -exec chmod 0555 '{}' +
                find firmware -type f -exec chmod 0444 '{}' +
                mkdir -p "$out"
                cp -R --no-preserve=ownership firmware/. "$out/"
              '';
          rootImage = targetConfig.sdImage.rootFilesystemImage;
          unsignedArtifacts = provisioning.lib.mkRpi5SecureBootArtifacts {
            system = "aarch64-linux";
            inherit
              bootCommandLinePath
              bootImageSizeMiB
              bootOrderPolicy
              expectedCustomerKeyHash
              firmwareAllowlist
              firmwareTree
              rootImage
              rootDataPartitionGUID
              rootHashPartitionGUID
              sourceRevision
              ;
          };
        in
        {
          inherit
            bootCommandLinePath
            firmwareAllowlist
            firmwareTree
            nixosSystem
            rootImage
            rootDataPartitionGUID
            rootHashPartitionGUID
            unsignedArtifacts
            ;
          system = targetConfig.system.build.toplevel;
        };

      compatibilitySuiteFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.symlinkJoin {
          name = "kaiba-dns-pilot-0.1.0";
          paths = [
            dns.packages.${system}.dns-suite
            provisioning.packages.${system}.provisioning-suite
          ];
        };

      developmentSigningFor =
        system:
        import ./nix/development-signing.nix {
          inherit provisioning system;
        };

      ubuntuSigningGateDeploymentFor =
        system:
        import ./nix/ubuntu-signing-gate-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
        };

      ubuntuProvisioningAuthorityDeploymentFor =
        system:
        import ./nix/ubuntu-provisioning-authority-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
          auditPackage = provisioning.packages.${system}.kaiba-provision-audit;
          controlPackage = provisioning.packages.${system}.kaiba-provision-control;
        };

      ubuntuProvisioningAuthorityLoopbackTestDeploymentFor =
        system:
        import ./nix/ubuntu-provisioning-authority-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
          auditPackage = provisioning.packages.${system}.kaiba-provision-audit;
          controlPackage = provisioning.packages.${system}.kaiba-provision-control;
          listenAddress = "127.0.0.1";
          controlPort = 38091;
          auditPort = 38092;
        };

      developmentSigningCeremonyFor =
        system:
        import ./nix/development-signing-ceremony.nix {
          pkgs = import nixpkgs { inherit system; };
          sourceRevision = developmentCeremonySourceRevision;
          sourceTreeClean = developmentCeremonySourceTreeClean;
        };

      rpi5PrototypeRelease =
        let
          system = "x86_64-linux";
          pkgs = import nixpkgs { inherit system; };
        in
        import ./nix/rpi5-prototype-release.nix {
          developmentSigning = developmentSigningFor system;
          inherit
            lib
            mkRpi5SecureBootTarget
            pkgs
            provisioning
            system
            ;
          sourceDateEpoch = self.lastModified;
          sourceRevision = defaultTargetSourceRevision;
        };

      mkRpi5PrototypeVerifiedUnfusedCapsule =
        {
          signedOutput,
          capsuleID ? "capsule:rpi5-prototype:${builtins.substring 0 12 defaultTargetSourceRevision}",
          fixtureID ? "${capsuleID}:synthetic",
          name ? "kaiba-rpi5-prototype-verified-unfused-capsule",
        }:
        let
          system = "x86_64-linux";
          developmentSigning = developmentSigningFor system;
          verifiedSignedBoot = provisioning.lib.mkRpi5VerifiedSignedBoot {
            inherit system signedOutput;
            name = "${name}-signed-boot";
            signingPlan = rpi5PrototypeRelease.signingPlan;
          };
        in
        provisioning.lib.mkRpi5VerifiedUnfusedCapsule {
          inherit
            capsuleID
            fixtureID
            name
            system
            verifiedSignedBoot
            ;
          trustedPublicKeyFingerprint = developmentSigning.metadata.publicKeyFingerprint;
          unsignedArtifacts = rpi5PrototypeRelease.unsignedArtifacts;
        };

      mkRpi5PrototypeSignedRelease =
        let
          system = "x86_64-linux";
        in
        import ./nix/rpi5-prototype-signed-release.nix {
          inherit lib provisioning;
          pkgs = import nixpkgs { inherit system; };
          prototype = rpi5PrototypeRelease;
          signingProfile = developmentSigningFor system;
        };

      # Recover a payload whose signatures and authenticated receipts passed
      # independent verification but whose original offline finalizer had a
      # software-only defect. The payload factory remains pinned to its own
      # source revision; only the no-authority final publication step comes
      # from this flake. This does not create or repeat a signing request.
      mkRpi5PrototypeSignedReleaseRecovery =
        {
          payload,
          payloadSourceRevision,
          bootSignedOutput,
          eepromSignedOutput,
          ownedRecoverySignedOutput,
          signingGrantRegistry,
          signingReceiptExport,
          name ? "kaiba-rpi5-${builtins.substring 0 12 payloadSourceRevision}-recovery-signed-release",
        }:
        let
          system = "x86_64-linux";
          payloadGraph = payload.lib.mkRpi5PrototypeSignedRelease {
            inherit
              bootSignedOutput
              eepromSignedOutput
              ownedRecoverySignedOutput
              signingGrantRegistry
              signingReceiptExport
              ;
          };
          payloadInputs = payloadGraph.release.kaibaVerifiedSignedRelease;
          recovered = provisioning.lib.mkRpi5VerifiedSignedRelease {
            inherit name system;
            inherit (payloadInputs)
              deviceProfile
              eepromRelease
              platformAdapter
              rootIntegrity
              signingReceiptVerification
              unsignedArtifacts
              verifiedOwnedRecovery
              verifiedRPIBootBundles
              verifiedSignedBoot
              verifiedSignedEEPROM
              ;
          };
        in
        assert lib.assertMsg (
          builtins.isString payloadSourceRevision
          && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" payloadSourceRevision != null
          && payloadGraph.metadata.sourceRevision == payloadSourceRevision
        ) "the recovery payload factory is not bound to the expected source revision";
        recovered
        // {
          kaibaPrototypeSignedReleaseRecovery = {
            inherit payloadSourceRevision;
            recoveryToolSourceRevision = defaultTargetSourceRevision;
            hardwareAccess = false;
            mutationCapable = false;
            privateKeyAccess = false;
            signingAuthorityConfigured = false;
          };
        };

      mkRpi5PrototypeOwnedRecoveryPlan =
        let
          system = "x86_64-linux";
        in
        import ./nix/rpi5-prototype-owned-recovery-plan.nix {
          inherit lib provisioning;
          prototype = rpi5PrototypeRelease;
          signingProfile = developmentSigningFor system;
        };

      rpi5DevelopmentMutationLaneGuardName =
        manualLaneQualificationDigest:
        let
          digestMatch = builtins.match "sha256:([0-9a-f]{64})" manualLaneQualificationDigest;
        in
        if digestMatch == null then
          throw "manualLaneQualificationDigest must use canonical sha256:<64 lowercase hex> form"
        else
          "kaiba-rpi5-v016-development-physical-lane-guard-${builtins.head digestMatch}";

      mkRpi5DevelopmentMutationStation =
        {
          acceptedTargetFingerprint,
          verifiedSignedRelease,
          auditAddress,
          auditPort ? 8092,
          controlAddress,
          controlPort ? 8091,
          hardwareQualificationDigest,
          laneID,
          manualLaneQualificationDigest,
          manualLaneQualificationSourceRevision,
          operatorName ? "provisioner",
          payloadSourceRevision,
          rpibootSysfsPath,
          sourceRevision ? defaultTargetSourceRevision,
          stationID,
          uartPath,
          unfusedCompatibilityUARTDigest,
        }:
        let
          physicalLaneGuard = provisioning.lib.mkRpi5PhysicalLaneGuard {
            system = "aarch64-linux";
            inherit verifiedSignedRelease;
            name = rpi5DevelopmentMutationLaneGuardName manualLaneQualificationDigest;
          };
        in
        import ./nix/rpi5-development-mutation-station.nix {
          inherit
            auditAddress
            auditPort
            acceptedTargetFingerprint
            controlAddress
            controlPort
            hardwareQualificationDigest
            laneID
            lib
            manualLaneQualificationDigest
            manualLaneQualificationSourceRevision
            nixos-raspberrypi
            operatorName
            payloadSourceRevision
            physicalLaneGuard
            provisioning
            rpibootSysfsPath
            sourceRevision
            stationID
            uartPath
            unfusedCompatibilityUARTDigest
            verifiedSignedRelease
            ;
        };
    in
    {
      nixosModules = {
        default = {
          imports = [
            dns.nixosModules.default
            provisioning.nixosModules.default
          ];
        };
        inherit (dns.nixosModules)
          device-agent
          hidden-primary
          hidden-standby
          public-secondary
          update-controller
          update-services
          ;
        inherit (provisioning.nixosModules)
          provisioning-audit
          provisioning-authority-bridge
          provisioning-control
          provisioning-lane-guard
          provisioning-probe
          provisioning-signing-gate
          provisioning-station-demo
          secure-boot-target
          ;
      };

      lib = provisioning.lib // {
        inherit
          mkRpi5DevelopmentMutationStation
          mkRpi5PrototypeVerifiedUnfusedCapsule
          mkRpi5PrototypeOwnedRecoveryPlan
          mkRpi5PrototypeSignedRelease
          mkRpi5PrototypeSignedReleaseRecovery
          mkRpi5SecureBootTarget
          rpi5SecureBootFirmwareAllowlist
          ;
      };

      packages = forAllSystems (
        system:
        let
          developmentSigning = developmentSigningFor system;
        in
        {
          default = compatibilitySuiteFor system;
          rpi5-unfused-verifier = developmentSigning.unfusedVerifier;
          ubuntu-provisioning-authority-deployment = ubuntuProvisioningAuthorityDeploymentFor system;
          ubuntu-signing-gate-deployment = ubuntuSigningGateDeploymentFor system;
          inherit (dns.packages.${system})
            kaiba-agent
            kaiba-controller
            kaiba-publisher
            ;
          inherit (provisioning.packages.${system})
            kaiba-provision-audit
            kaiba-provision-authority-bridge
            kaiba-provision-control
            kaiba-provision-integrated-rehearsal
            kaiba-provision-lane-guard
            kaiba-provision-lane-operator
            kaiba-provision-lane-workflow
            kaiba-provision-media-contract
            kaiba-provision
            kaiba-provision-rehearsal
            kaiba-provision-signer-foundation
            kaiba-provision-signing-client-foundation
            kaiba-provision-signing-approval
            kaiba-provision-signing-receipts
            kaiba-provision-signing-gate-foundation
            kaiba-provision-finalize-release
            kaiba-provision-sign-boot
            kaiba-provision-sign-eeprom
            kaiba-provision-station
            kaiba-provision-station-demo
            kaiba-provision-station-pages
            kaiba-provision-unfused-compat
            kaiba-provision-unfused-evidence
            kaiba-provision-unfused-runtime-record
            provisioning-test-result
            kaiba-provision-yubikey-wrapper-foundation
            ;
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          development-signing = developmentSigning.signing;
          kaiba-provision-signing-ceremony = developmentSigningCeremonyFor system;
          rpi5-prototype-eeprom-signing-inputs = rpi5PrototypeRelease.eepromSigningInputs;
          rpi5-prototype-eeprom-signing-plan = rpi5PrototypeRelease.eepromSigningPlan;
          rpi5-prototype-release-intent = rpi5PrototypeRelease.releaseIntent;
          rpi5-prototype-release-review = rpi5PrototypeRelease.review;
          rpi5-prototype-signing-plan = rpi5PrototypeRelease.signingPlan;
          inherit (dns.packages.${system})
            dns-schema-gate
            dns-security-gate
            dns-test-driver
            dns-test-gate
            dns-test-raw
            dns-test-report
            report-unit
            ;
        }
        // lib.optionalAttrs (system == "aarch64-linux") {
          rpi5-provisioning-sd-image = rpi5ProvisioningSystem.config.system.build.sdImage;
          rpi5-prototype-unsigned-artifacts = rpi5PrototypeRelease.unsignedArtifacts;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          developmentSigning = developmentSigningFor system;
          laneGuardFixture = provisioning.packages.${system}.rpi5-physical-lane-guard-fixture;
          moduleEval = import ./tests/module-eval.nix {
            inherit pkgs lib;
            kaibaPackage = dns.packages.${system}.dns-suite;
            kaibaAuditPackage = provisioning.packages.${system}.kaiba-provision-audit;
            kaibaAuthorityBridgePackage = provisioning.packages.${system}.kaiba-provision-authority-bridge;
            kaibaControlPackage = provisioning.packages.${system}.kaiba-provision-control;
            kaibaLaneGuardPackage = laneGuardFixture;
            kaibaProvisionPackage = provisioning.packages.${system}.kaiba-provision;
            kaibaStationDemoPackage = provisioning.packages.${system}.kaiba-provision-station-demo;
            kaibaModules = self.nixosModules;
          };
        in
        {
          unit = self.packages.${system}.default;
          development-yubikey-signing = provisioning.checks.${system}.development-yubikey-signing;
          device-profile-schema = provisioning.checks.${system}.device-profile-schema;
          rpi5-development-posture = provisioning.checks.${system}.rpi5-development-posture;
          rpi5-probe-bundle = provisioning.checks.${system}.rpi5-probe-bundle;
          module-eval = moduleEval;
          provisioning-test-result = provisioning.checks.${system}.provisioning-test-result;
          station-ui = provisioning.checks.${system}.station-ui;
          rpiboot-metadata-stdout = provisioning.checks.${system}.rpiboot-metadata-stdout;
          rpi5-unfused-capsule = provisioning.checks.${system}.unfused-capsule;
          rpi5-media-staging-fixture = provisioning.checks.${system}.media-staging-fixture;
          rpi5-production-media-staging = provisioning.checks.${system}.production-media-staging;
          rpi5-unfused-verifier = developmentSigning.unfusedVerifier;
          secure-boot-artifacts = provisioning.checks.${system}.secure-boot-artifacts;
          rpi5-signed-release-manifest = provisioning.checks.${system}.signed-release-manifest;
          rpi5-signed-release = provisioning.checks.${system}.rpi5-signed-release;
          signed-boot-plan = provisioning.checks.${system}.signed-boot-plan;
          signing-approval = provisioning.checks.${system}.signing-approval;
          signing-receipts = provisioning.checks.${system}.signing-receipts;
          signing-receipts-integration = provisioning.checks.${system}.signing-receipts-integration;
          ubuntu-provisioning-authority-deployment = import ./tests/ubuntu-provisioning-authority.nix {
            deployment = ubuntuProvisioningAuthorityDeploymentFor system;
            runtimeDeployment = ubuntuProvisioningAuthorityLoopbackTestDeploymentFor system;
            inherit pkgs;
          };
          ubuntu-signing-gate-deployment = ubuntuSigningGateDeploymentFor system;
          ci-workflow =
            pkgs.runCommand "kaiba-ci-workflow-check"
              {
                nativeBuildInputs = [
                  pkgs.actionlint
                  pkgs.gitMinimal
                  pkgs.python3
                  pkgs.shellcheck
                ];
              }
              ''
                actionlint \
                  ${./.github/workflows/ci.yml} \
                  ${./.github/workflows/release.yml}
                python3 ${./tests/ci/workflow_cache_policy.py} \
                  ${./.github/workflows/ci.yml} \
                  ${./.github/workflows/release.yml}
                python3 ${./tests/ci/release_workflow_policy.py} \
                  ${./.github/workflows/release.yml} \
                  ${./scripts/ci/verify_remote_release_tag.sh}
                shellcheck \
                  ${./scripts/ci/verify_remote_release_tag.sh} \
                  ${./scripts/ci/verify_release_tag.sh} \
                  ${./tests/ci/verify_remote_release_tag_test.sh} \
                  ${./tests/ci/verify_release_tag_test.sh}
                bash ${./tests/ci/verify_release_tag_test.sh} \
                  ${./scripts/ci/verify_release_tag.sh}
                bash ${./tests/ci/verify_remote_release_tag_test.sh} \
                  ${./scripts/ci/verify_remote_release_tag.sh}
                mkdir -p "$out"
                touch "$out/passed"
              '';
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          development-signing = developmentSigning.signing;
          signing-ceremony = import ./tests/signing-ceremony.nix {
            ceremony = developmentSigningCeremonyFor system;
            inherit pkgs;
          };
          report-unit = dns.checks.${system}.report-unit;
          dns-schema = dns.checks.${system}.dns-schema;
          dns-topology = dns.checks.${system}.dns-topology;
          dns-security = dns.checks.${system}.dns-security;
          rpi5-provisioning-image-eval = import ./tests/rpi5-provisioning-image-eval.nix {
            inherit
              lib
              pkgs
              sourceRevision
              ;
            imageConfig = rpi5ProvisioningSystem.config;
            kaibaProvisionPackage = provisioning.packages.aarch64-linux.kaiba-provision;
          };
          rpi5-development-mutation-station-eval =
            let
              fixtureSourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
              fixturePayloadSourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              fixtureBaseRelease =
                provisioning.packages.aarch64-linux.rpi5-physical-lane-guard-fixture.kaibaPhysicalLaneGuard.verifiedSignedRelease;
              fixtureRecoveredRelease = fixtureBaseRelease.overrideAttrs (old: {
                passthru = (old.passthru or { }) // {
                  kaibaPrototypeSignedReleaseRecovery = {
                    payloadSourceRevision = fixturePayloadSourceRevision;
                    recoveryToolSourceRevision = fixtureSourceRevision;
                    privateKeyAccess = false;
                    signingAuthorityConfigured = false;
                    hardwareAccess = false;
                    mutationCapable = false;
                  };
                };
              });
              fixtureReleaseContract = fixtureRecoveredRelease.kaibaVerifiedSignedRelease;
              fixtureReleaseIntentWithMismatchedSource =
                fixtureReleaseContract.releaseIntent.overrideAttrs
                  (old: {
                    passthru = (old.passthru or { }) // {
                      kaibaRpi5ReleaseIntent = old.passthru.kaibaRpi5ReleaseIntent // {
                        sourceRevision = fixtureSourceRevision;
                      };
                    };
                  });
              fixtureUnsignedArtifactsWithMismatchedSource =
                fixtureReleaseContract.unsignedArtifacts.overrideAttrs
                  (old: {
                    passthru = (old.passthru or { }) // {
                      kaibaUnsignedArtifacts = old.passthru.kaibaUnsignedArtifacts // {
                        sourceRevision = fixtureSourceRevision;
                      };
                    };
                  });
              mkRecoveredReleaseWithContract =
                contractOverrides:
                fixtureRecoveredRelease.overrideAttrs (old: {
                  passthru = (old.passthru or { }) // {
                    kaibaVerifiedSignedRelease = old.passthru.kaibaVerifiedSignedRelease // contractOverrides;
                  };
                });
              fixtureReleaseIntentMismatch = mkRecoveredReleaseWithContract {
                releaseIntent = fixtureReleaseIntentWithMismatchedSource;
              };
              fixtureUnsignedArtifactsMismatch = mkRecoveredReleaseWithContract {
                unsignedArtifacts = fixtureUnsignedArtifactsWithMismatchedSource;
              };
              mkFixtureMutationStation =
                overrides:
                mkRpi5DevelopmentMutationStation (
                  {
                    acceptedTargetFingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
                    auditAddress = "192.168.8.249";
                    controlAddress = "192.168.8.249";
                    hardwareQualificationDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
                    laneID = "lane-1";
                    manualLaneQualificationDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
                    manualLaneQualificationSourceRevision = fixturePayloadSourceRevision;
                    operatorName = "provisioner";
                    payloadSourceRevision = fixturePayloadSourceRevision;
                    rpibootSysfsPath = "/sys/bus/usb/devices/3-1";
                    sourceRevision = fixtureSourceRevision;
                    stationID = "kaiba-rpi5-provisioner";
                    uartPath = "/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E663B035973F3F26-if01";
                    unfusedCompatibilityUARTDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                    verifiedSignedRelease = fixtureRecoveredRelease;
                  }
                  // overrides
                );
              mutationStation = mkFixtureMutationStation { };
              mutationStationInputRejected =
                overrides:
                !(builtins.tryEval ((mkFixtureMutationStation overrides).metadata.payloadSourceRevision)).success;
              noncanonicalPayloadSourceRevisionRejected = mutationStationInputRejected {
                payloadSourceRevision = "not-a-canonical-revision";
              };
              mismatchedReleaseIntentSourceRevisionRejected = mutationStationInputRejected {
                verifiedSignedRelease = fixtureReleaseIntentMismatch;
              };
              mismatchedUnsignedArtifactSourceRevisionRejected = mutationStationInputRejected {
                verifiedSignedRelease = fixtureUnsignedArtifactsMismatch;
              };
              bindingFixtureRelease =
                provisioning.packages.x86_64-linux.rpi5-physical-lane-guard-fixture.kaibaPhysicalLaneGuard.verifiedSignedRelease;
              bindingGuardA = provisioning.lib.mkRpi5PhysicalLaneGuard {
                system = "x86_64-linux";
                verifiedSignedRelease = bindingFixtureRelease;
                name = rpi5DevelopmentMutationLaneGuardName "sha256:1111111111111111111111111111111111111111111111111111111111111111";
              };
              bindingGuardB = provisioning.lib.mkRpi5PhysicalLaneGuard {
                system = "x86_64-linux";
                verifiedSignedRelease = bindingFixtureRelease;
                name = rpi5DevelopmentMutationLaneGuardName "sha256:2222222222222222222222222222222222222222222222222222222222222222";
              };
            in
            import ./tests/rpi5-development-mutation-station-eval.nix {
              inherit
                bindingGuardA
                bindingGuardB
                lib
                mismatchedReleaseIntentSourceRevisionRejected
                mismatchedUnsignedArtifactSourceRevisionRejected
                mutationStation
                noncanonicalPayloadSourceRevisionRejected
                pkgs
                ;
              sourceRevision = fixtureSourceRevision;
            };
          rpi5-qualification-ceremony = import ./tests/rpi5-qualification-ceremony.nix {
            inherit lib pkgs;
          };
          rpi5-prototype-release-eval = import ./tests/rpi5-prototype-release-eval.nix {
            inherit lib pkgs;
            prototype = rpi5PrototypeRelease;
            signingProfile = developmentSigning;
          };
          rpi5-root-integrity-record = import ./tests/rpi5-root-integrity-record.nix {
            inherit lib pkgs;
          };
          rpi5-prototype-signed-release-eval = import ./tests/rpi5-prototype-signed-release-eval.nix {
            inherit
              lib
              mkRpi5PrototypeOwnedRecoveryPlan
              mkRpi5PrototypeSignedRelease
              mkRpi5PrototypeSignedReleaseRecovery
              pkgs
              ;
            prototype = rpi5PrototypeRelease;
          };
        }
        // lib.optionalAttrs (system == "aarch64-linux") {
          rpi5-secure-boot-target-eval = import ./tests/rpi5-secure-boot-target-eval.nix {
            inherit lib pkgs;
            target = mkRpi5SecureBootTarget {
              # Evaluation fixture only.  Deployments must supply the reviewed
              # customer-key hash produced by the pinned Raspberry Pi tooling.
              expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              sourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            };
          };
        }
      );

      nixosConfigurations.rpi5-provisioning-station = rpi5ProvisioningSystem;

      apps.x86_64-linux.dns-test-driver = dns.apps.x86_64-linux.dns-test-driver;

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          reportPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.jsonschema ]);
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              gotools
              sqlite
              knot-dns
              unbound
              bind.dnsutils
              jq
              reportPython
              openssl
              nixfmt-tree
              actionlint
              shellcheck
            ];
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.nixfmt-tree
      );
    };
}
