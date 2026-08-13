{
  description = "Kaiba secure dynamic DNS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";
    provisioning = {
      url = "path:../provisioning";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      provisioning,
    }:
    let
      lib = nixpkgs.lib;
      sourceRoot = self.sourceInfo.outPath;
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
          inherit pkgs lib sourceRoot;
        };

      modules = {
        default = import ./modules;
        device-agent = import ../modules/device-agent.nix;
        update-controller = import ../modules/update-controller.nix;
        update-services = import ../modules/update-services.nix;
        hidden-primary = import ../modules/hidden-primary.nix;
        hidden-standby = import ../modules/hidden-standby.nix;
        public-secondary = import ../modules/public-secondary.nix;
      };

      moduleEvalFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
        in
        import ../../tests/integration/module-eval.nix {
          inherit pkgs lib;
          kaibaPackage = built.suite;
          kaibaModules = modules;
        };

      integrationFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
          provisioningPackages = provisioning.packages.${system};
        in
        import ../../tests/integration/packages.nix {
          inherit pkgs lib;
          kaibaPackage = built.suite;
          kaibaModules = modules;
          provisioningTestResult = provisioningPackages.provisioning-test-result;
          stationPages = provisioningPackages.kaiba-provision-station-pages;
        };
    in
    {
      nixosModules = modules;

      packages = forAllSystems (
        system:
        let
          built = packagesFor system;
          integration = lib.optionalAttrs (system == "x86_64-linux") (integrationFor system);
        in
        {
          default = built.suite;
          dns-suite = built.suite;
          kaiba-agent = built.agent;
          kaiba-controller = built.controller;
          kaiba-publisher = built.publisher;
        }
        // integration
      );

      checks = forAllSystems (
        system:
        let
          built = packagesFor system;
        in
        {
          unit = built.suite;
          module-eval = moduleEvalFor system;
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          report-unit = self.packages.${system}.report-unit;
          dns-schema = self.packages.${system}.dns-schema-gate;
          dns-topology = self.packages.${system}.dns-test-gate;
          dns-security = self.packages.${system}.dns-security-gate;
        }
      );

      apps.x86_64-linux.dns-test-driver = {
        type = "app";
        program = "${self.packages.x86_64-linux.dns-test-driver}/bin/nixos-test-driver";
        meta.description = "Run the interactive Kaiba DNS integration topology";
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
