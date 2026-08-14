{
  description = "Kaiba device provisioning";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      repositoryRoot = self.sourceInfo.outPath;
      moduleRoot = "${repositoryRoot}/provisioning";
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
        provisioning-probe = import ./modules/provisioning-probe.nix;
        provisioning-station-demo = import ./modules/provisioning-station-demo.nix;
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

      packages = forAllSystems (
        system:
        let
          built = packagesFor system;
          provisioning = provisioningFor system;
        in
        {
          default = built.provision;
          kaiba-provision = built.provision;
          kaiba-provision-station-demo = built.stationDemo;
          kaiba-provision-station-pages = built.stationPages;
          provisioning-suite = built.suite;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = built.rpi5ProbeBundle;
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
          device-profile-schema = provisioning.deviceProfileSchema;
          module-eval = provisioning.moduleEval;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = provisioning.probeBundleIntegrity;
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
