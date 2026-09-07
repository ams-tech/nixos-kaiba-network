{
  description = "Kaiba device provisioning";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      repositoryRoot = self.sourceInfo.outPath;
      moduleRoot = ./.;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      hardwareConfigurations = import ./config/hardware;

      packagesFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./nix/packages.nix {
          inherit pkgs lib moduleRoot;
        };

      modules = {
        default = import ./nix/modules;
        provisioning-audit = import ./nix/modules/provisioning-audit.nix;
        provisioning-authority-bridge = import ./nix/modules/provisioning-authority-bridge.nix;
        provisioning-control = import ./nix/modules/provisioning-control.nix;
        provisioning-lane-guard = import ./nix/modules/provisioning-lane-guard.nix;
        provisioning-probe = import ./nix/modules/provisioning-probe.nix;
        provisioning-signing-gate = import ./nix/modules/provisioning-signing-gate.nix;
        provisioning-station-demo = import ./nix/modules/provisioning-station-demo.nix;
        secure-boot-target = import ./nix/modules/secure-boot-target.nix;
      };

      provisioningFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./tests/packages.nix {
          inherit hardwareConfigurations pkgs lib;
          built = packagesFor system;
          kaibaModules = modules;
        };

      mkDevelopmentSigningCeremony =
        {
          system,
          sourceRevision,
          sourceTreeClean,
        }:
        import ./nix/development-signing-ceremony.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit sourceRevision sourceTreeClean;
        };

      mkUbuntuProvisioningAuthorityDeployment =
        {
          system,
          auditPackage ? (packagesFor system).audit,
          auditPort ? 8092,
          controlPackage ? (packagesFor system).control,
          controlPort ? 8091,
          listenAddress ? "192.168.8.249",
        }:
        import ./nix/ubuntu-provisioning-authority-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit
            auditPackage
            auditPort
            controlPackage
            controlPort
            listenAddress
            ;
        };

      mkUbuntuSigningGateDeployment =
        { system }:
        import ./nix/ubuntu-signing-gate-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
        };
    in
    {
      nixosModules = modules;

      lib = {
        inherit
          hardwareConfigurations
          mkDevelopmentSigningCeremony
          mkUbuntuProvisioningAuthorityDeployment
          mkUbuntuSigningGateDeployment
          ;

        mkRpi5SecureBootArtifacts =
          { system, ... }@args:
          let
            pkgs = import nixpkgs { inherit system; };
            builder = import ./nix/secure-boot-artifacts.nix { inherit pkgs lib; };
          in
          builder (builtins.removeAttrs args [ "system" ]);

        mkRpi5PhysicalLaneGuard =
          { system, ... }@args:
          (packagesFor system).mkRpi5PhysicalLaneGuard (builtins.removeAttrs args [ "system" ]);

        mkRpi5DevelopmentSecureBootRunner =
          { system, ... }@args:
          (packagesFor system).mkRpi5DevelopmentSecureBootRunner (builtins.removeAttrs args [ "system" ]);

        mkRpi5DevelopmentSecureBootOperationalPayload =
          { system, ... }@args:
          (packagesFor system).mkRpi5DevelopmentSecureBootOperationalPayload (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5BootSigningPlan =
          { system, ... }@args:
          (packagesFor system).mkRpi5BootSigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5EEPROMRelease =
          { system, ... }@args:
          (packagesFor system).mkRpi5EEPROMRelease (builtins.removeAttrs args [ "system" ]);

        mkRpi5EEPROMReleaseSigningInputs =
          { system, ... }@args:
          (packagesFor system).mkRpi5EEPROMReleaseSigningInputs (builtins.removeAttrs args [ "system" ]);

        mkRpi5EEPROMSigningPlan =
          { system, ... }@args:
          (packagesFor system).mkRpi5EEPROMSigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5OwnedRecoverySigningPlan =
          { system, ... }@args:
          (packagesFor system).mkRpi5OwnedRecoverySigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedRPIBootBundles =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedRPIBootBundles (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSigningReceipts =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedSigningReceipts (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSignedRelease =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedSignedRelease (builtins.removeAttrs args [ "system" ]);

        mkRpi5ReleaseIntent =
          { system, ... }@args:
          (packagesFor system).mkRpi5ReleaseIntent (builtins.removeAttrs args [ "system" ]);

        mkDevelopmentYubiKeySigning =
          { system, ... }@args:
          (packagesFor system).mkDevelopmentYubiKeySigning (builtins.removeAttrs args [ "system" ]);

        mkRpi5UnfusedVerifier =
          { system, ... }@args:
          (packagesFor system).mkRpi5UnfusedVerifier (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSignedBoot =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedSignedBoot (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSignedEEPROM =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedSignedEEPROM (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedOwnedRecovery =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedOwnedRecovery (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedUnfusedCapsule =
          { system, ... }@args:
          (packagesFor system).mkRpi5VerifiedUnfusedCapsule (builtins.removeAttrs args [ "system" ]);

        mkRpi5MediaStagingFixture =
          { system, ... }@args:
          (packagesFor system).mkRpi5MediaStagingFixture (builtins.removeAttrs args [ "system" ]);

        mkRpi5ProductionMedia =
          { system, ... }@args:
          (packagesFor system).mkRpi5ProductionMedia (builtins.removeAttrs args [ "system" ]);
      };

      packages = forAllSystems (
        system:
        let
          built = packagesFor system;
          provisioning = provisioningFor system;
        in
        {
          default = built.provision;
          kaiba-provision-audit = built.audit;
          kaiba-provision-authority-bridge = built.authorityBridge;
          kaiba-provision-control = built.control;
          kaiba-provision-integrated-rehearsal = built.integratedRehearsal;
          kaiba-provision-lane-guard = built.laneGuard;
          kaiba-provision-lane-operator = built.laneOperator;
          kaiba-provision-lane-workflow = built.laneWorkflow;
          kaiba-provision-media-contract = built.mediaContractTool;
          kaiba-provision = built.provision;
          kaiba-provision-rehearsal = built.rehearsal;
          kaiba-provision-signer-foundation = built.signerFoundation;
          kaiba-provision-signing-client-foundation = built.signingClientFoundation;
          kaiba-provision-signing-gate-foundation = built.signingGateFoundation;
          kaiba-provision-signing-approval = built.signingApprovalTool;
          kaiba-provision-signing-receipts = built.signingReceiptsTool;
          kaiba-provision-sign-boot = built.signedBootTool;
          kaiba-provision-sign-eeprom = built.eepromSigningTool;
          kaiba-provision-rpiboot-bundles = built.rpibootBundleTool;
          kaiba-provision-finalize-release = built.signedReleaseTool;
          kaiba-provision-station = built.liveStation;
          kaiba-provision-station-demo = built.stationDemo;
          kaiba-provision-station-pages = built.stationPages;
          kaiba-provision-unfused-compat = built.unfusedCompat;
          kaiba-provision-unfused-evidence = built.unfusedEvidence;
          kaiba-provision-unfused-runtime-record = built.unfusedRuntimeRecordTool;
          provisioning-suite = built.suite;
          provisioning-services = built.serviceSuite;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-physical-lane-guard-fixture = provisioning.physicalLaneGuardFixture;
          rpi5-probe-bundle = built.rpi5ProbeBundle;
          rpi5-eeprom-release = built.rpi5EEPROMRelease;
          kaiba-provision-yubikey-wrapper-foundation = built.yubiKeyWrapperFoundation;
          ubuntu-provisioning-authority-deployment = mkUbuntuProvisioningAuthorityDeployment {
            inherit system;
          };
          ubuntu-signing-gate-deployment = mkUbuntuSigningGateDeployment { inherit system; };
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          kaiba-provision-signing-ceremony = mkDevelopmentSigningCeremony {
            inherit system;
            sourceRevision = "0000000000000000000000000000000000000000";
            sourceTreeClean = false;
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
          provisioning = provisioningFor system;
        in
        {
          unit = built.suite;
          development-yubikey-signing = provisioning.developmentYubiKeySigningContract;
          device-profile-schema = provisioning.deviceProfileSchema;
          rpi5-development-posture = provisioning.developmentPostureContract;
          module-eval = provisioning.moduleEval;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = provisioning.probeBundleIntegrity;
          rpi5-eeprom-release = provisioning.eepromReleaseContract;
          rpi5-eeprom-signing = provisioning.eepromSigningContract;
          rpi5-rpiboot-bundles = provisioning.rpibootBundleContract;
          rpi5-signed-release = provisioning.signedReleaseFinalizationContract;
          rpiboot-metadata-stdout = provisioning.rpibootMetadataStdoutCompatibility;
          secure-boot-artifacts = provisioning.secureBootArtifactContract;
          media-staging-fixture = provisioning.mediaStagingFixtureContract;
          production-media-staging = provisioning.productionMediaStagingContract;
          signed-release-manifest = provisioning.signedReleaseManifestContract;
          signed-boot-plan = provisioning.signedBootPlanContract;
          signing-approval = built.signingApprovalTool;
          signing-receipts = built.signingReceiptsTool;
          signing-receipts-integration = provisioning.signingReceiptVerificationContract;
          unfused-capsule = provisioning.unfusedCapsuleContract;
          ubuntu-provisioning-authority-deployment = import ./tests/ubuntu-provisioning-authority.nix {
            deployment = mkUbuntuProvisioningAuthorityDeployment { inherit system; };
            runtimeDeployment = mkUbuntuProvisioningAuthorityDeployment {
              inherit system;
              listenAddress = "127.0.0.1";
              controlPort = 38091;
              auditPort = 38092;
            };
            inherit pkgs;
          };
          ubuntu-signing-gate-deployment = mkUbuntuSigningGateDeployment { inherit system; };
          station-ui =
            pkgs.runCommand "kaiba-provisioning-station-ui-check"
              {
                nativeBuildInputs = [
                  pkgs.nodejs
                  pkgs.python3
                ];
              }
              ''
                set -eu
                export PYTHONDONTWRITEBYTECODE=1
                cd ${repositoryRoot}
                node --check internal/provisioning/stationui/web/app.js
                node --check internal/provisioning/stationui/web/transport.js
                node --check internal/provisioning/livestation/web/app.js
                node internal/provisioning/livestation/web/app.test.cjs
                export KAIBA_STATION_PAGES=${built.stationPages}
                node --test tests/station-ui/transport.test.mjs
                python3 -m unittest discover -s tests/station-ui -p 'test_*.py' -v
                for asset in index.html styles.css transport.js app.js; do
                  cmp "internal/provisioning/stationui/web/$asset" "${built.stationPages}/$asset"
                done
                test "$(find ${built.stationPages} -maxdepth 1 -type f | wc -l)" -eq 6
                mkdir -p "$out"
                printf '%s\n' 'provisioning station UI: pass' > "$out/results.txt"
              '';
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          signing-ceremony = import ./tests/signing-ceremony.nix {
            ceremony = mkDevelopmentSigningCeremony {
              inherit system;
              sourceRevision = "0000000000000000000000000000000000000000";
              sourceTreeClean = false;
            };
            inherit pkgs;
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          reportPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.jsonschema ]);
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              check-jsonschema
              go
              gopls
              gotools
              jq
              nodejs
              reportPython
              nixfmt-tree
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
