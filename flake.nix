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

      sourceRevision =
        if self ? rev then
          self.rev
        else if self ? dirtyRev then
          self.dirtyRev
        else
          "uncommitted";

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
        // lib.optionalAttrs (system == "aarch64-linux") {
          rpi5-provisioning-sd-image = rpi5ProvisioningSystem.config.system.build.sdImage;
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
          rpiboot-metadata-stdout = provisioning.checks.${system}.rpiboot-metadata-stdout;
          ci-workflow =
            pkgs.runCommand "kaiba-ci-workflow-check"
              {
                nativeBuildInputs = [
                  pkgs.actionlint
                  pkgs.shellcheck
                ];
              }
              ''
                actionlint \
                  ${./.github/workflows/ci.yml} \
                  ${./.github/workflows/release.yml}
                mkdir -p "$out"
                touch "$out/passed"
              '';
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
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
