{
  description = "Kaiba secure-device dynamic DNS pilot";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
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
        import ./nix/packages.nix { inherit pkgs lib; };
      provisioningFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./tests/provisioning/packages.nix {
          inherit pkgs lib;
          built = packagesFor system;
          kaibaModules = self.nixosModules;
        };
    in
    {
      nixosModules = {
        default = import ./nix/modules;
        device-agent = import ./nix/modules/device-agent.nix;
        update-services = import ./nix/modules/update-services.nix;
        hidden-primary = import ./nix/modules/hidden-primary.nix;
        hidden-standby = import ./nix/modules/hidden-standby.nix;
        public-secondary = import ./nix/modules/public-secondary.nix;
        provisioning-probe = import ./nix/modules/provisioning-probe.nix;
        provisioning-station-demo = import ./nix/modules/provisioning-station-demo.nix;
      };

      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
          provisioning = provisioningFor system;
          integration = lib.optionalAttrs (system == "x86_64-linux") (
            import ./tests/integration/packages.nix {
              inherit pkgs lib;
              kaibaPackage = built.suite;
              kaibaModules = self.nixosModules;
              provisioningTestResult = provisioning.provisioningTestResult;
              stationPages = built.stationPages;
            }
          );
        in
        {
          default = built.suite;
          kaiba-agent = built.agent;
          kaiba-controller = built.controller;
          kaiba-provision = built.provision;
          kaiba-provision-station-demo = built.stationDemo;
          kaiba-provision-station-pages = built.stationPages;
          kaiba-publisher = built.publisher;
          provisioning-test-result = provisioning.provisioningTestResult;
        }
        // integration
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
          rpi5-probe-bundle = provisioning.probeBundleIntegrity;
          module-eval = provisioning.moduleEval;
          provisioning-test-result = provisioning.provisioningTestResult;
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
                cd ${./.}
                node --check internal/provisioning/stationui/web/app.js
                node --check internal/provisioning/stationui/web/transport.js
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
          ci-workflow =
            pkgs.runCommand "kaiba-ci-workflow-check"
              {
                nativeBuildInputs = [
                  pkgs.actionlint
                  pkgs.shellcheck
                ];
              }
              ''
                actionlint ${./.github/workflows/ci.yml}
                mkdir -p "$out"
                touch "$out/passed"
              '';
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          report-unit = self.packages.${system}.report-unit;
          dns-schema = self.packages.${system}.dns-schema-gate;
          dns-topology = self.packages.${system}.dns-test-gate;
          dns-security = self.packages.${system}.dns-security-gate;
        }
      );

      apps.x86_64-linux = {
        dns-test-driver = {
          type = "app";
          program = "${self.packages.x86_64-linux.dns-test-driver}/bin/nixos-test-driver";
        };
      };

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
