{
  description = "Kaiba secure-device dynamic DNS pilot";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";
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
          provisioning-probe
          provisioning-station-demo
          ;
      };

      packages = forAllSystems (
        system:
        {
          default = compatibilitySuiteFor system;
          inherit (dns.packages.${system})
            kaiba-agent
            kaiba-controller
            kaiba-publisher
            ;
          inherit (provisioning.packages.${system})
            kaiba-provision
            kaiba-provision-station-demo
            kaiba-provision-station-pages
            provisioning-test-result
            ;
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
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
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          moduleEval = import ./tests/module-eval.nix {
            inherit pkgs lib;
            kaibaPackage = dns.packages.${system}.dns-suite;
            kaibaProvisionPackage = provisioning.packages.${system}.kaiba-provision;
            kaibaStationDemoPackage = provisioning.packages.${system}.kaiba-provision-station-demo;
            kaibaModules = self.nixosModules;
          };
        in
        {
          unit = self.packages.${system}.default;
          device-profile-schema = provisioning.checks.${system}.device-profile-schema;
          rpi5-probe-bundle = provisioning.checks.${system}.rpi5-probe-bundle;
          module-eval = moduleEval;
          provisioning-test-result = provisioning.checks.${system}.provisioning-test-result;
          station-ui = provisioning.checks.${system}.station-ui;
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
          report-unit = dns.checks.${system}.report-unit;
          dns-schema = dns.checks.${system}.dns-schema;
          dns-topology = dns.checks.${system}.dns-topology;
          dns-security = dns.checks.${system}.dns-security;
        }
      );

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
