{
  description = "Kaiba device provisioning";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      repositoryRoot = self.sourceInfo.outPath;
      moduleRoot = ../../provisioning;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;

      packagesFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./packages.nix {
          inherit pkgs lib moduleRoot;
        };

      modules = {
        default = import ./modules;
        provisioning-audit = import ./modules/provisioning-audit.nix;
        provisioning-control = import ./modules/provisioning-control.nix;
        provisioning-lane-guard = import ./modules/provisioning-lane-guard.nix;
        provisioning-probe = import ./modules/provisioning-probe.nix;
        provisioning-signing-gate = import ./modules/provisioning-signing-gate.nix;
        provisioning-station-demo = import ./modules/provisioning-station-demo.nix;
        secure-boot-target = import ./modules/secure-boot-target.nix;
      };

      provisioningFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ../../tests/provisioning/packages.nix {
          inherit pkgs lib;
          built = packagesFor system;
          kaibaModules = modules;
        };
    in
    {
      nixosModules = modules;

      lib = {
        mkRpi5SecureBootArtifacts =
          { system, ... }@args:
          let
            pkgs = import nixpkgs { inherit system; };
            builder = import ./secure-boot-artifacts.nix { inherit pkgs lib; };
          in
          builder (builtins.removeAttrs args [ "system" ]);

        mkRpi5PhysicalLaneGuard =
          { system, ... }@args:
          (packagesFor system).mkRpi5PhysicalLaneGuard (builtins.removeAttrs args [ "system" ]);

        mkDevelopmentYubiKeySigning =
          { system, ... }@args:
          (packagesFor system).mkDevelopmentYubiKeySigning (builtins.removeAttrs args [ "system" ]);

        mkRpi5UnfusedVerifier =
          { system, ... }@args:
          (packagesFor system).mkRpi5UnfusedVerifier (builtins.removeAttrs args [ "system" ]);
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
          kaiba-provision-control = built.control;
          kaiba-provision-integrated-rehearsal = built.integratedRehearsal;
          kaiba-provision-lane-guard = built.laneGuard;
          kaiba-provision-media-stager = built.mediaStager;
          kaiba-provision = built.provision;
          kaiba-provision-rehearsal = built.rehearsal;
          kaiba-provision-signer-foundation = built.signerFoundation;
          kaiba-provision-signing-client-foundation = built.signingClientFoundation;
          kaiba-provision-signing-gate-foundation = built.signingGateFoundation;
          kaiba-provision-station = built.liveStation;
          kaiba-provision-station-demo = built.stationDemo;
          kaiba-provision-station-pages = built.stationPages;
          kaiba-provision-unfused-compat = built.unfusedCompat;
          kaiba-provision-unfused-evidence = built.unfusedEvidence;
          provisioning-suite = built.suite;
          provisioning-services = built.serviceSuite;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = built.rpi5ProbeBundle;
          kaiba-provision-yubikey-wrapper-foundation = built.yubiKeyWrapperFoundation;
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
          module-eval = provisioning.moduleEval;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = provisioning.probeBundleIntegrity;
          rpiboot-metadata-stdout = provisioning.rpibootMetadataStdoutCompatibility;
          secure-boot-artifacts = provisioning.secureBootArtifactContract;
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
                node --check provisioning/internal/provisioning/stationui/web/app.js
                node --check provisioning/internal/provisioning/stationui/web/transport.js
                node --check provisioning/internal/provisioning/livestation/web/app.js
                node provisioning/internal/provisioning/livestation/web/app.test.cjs
                export KAIBA_STATION_PAGES=${built.stationPages}
                node --test tests/station-ui/transport.test.mjs
                python3 -m unittest discover -s tests/station-ui -p 'test_*.py' -v
                for asset in index.html styles.css transport.js app.js; do
                  cmp "provisioning/internal/provisioning/stationui/web/$asset" "${built.stationPages}/$asset"
                done
                test "$(find ${built.stationPages} -maxdepth 1 -type f | wc -l)" -eq 6
                mkdir -p "$out"
                printf '%s\n' 'provisioning station UI: pass' > "$out/results.txt"
              '';
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
