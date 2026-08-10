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
    in
    {
      nixosModules = {
        default = import ./nix/modules;
        device-agent = import ./nix/modules/device-agent.nix;
        update-services = import ./nix/modules/update-services.nix;
        hidden-primary = import ./nix/modules/hidden-primary.nix;
        hidden-standby = import ./nix/modules/hidden-standby.nix;
        public-secondary = import ./nix/modules/public-secondary.nix;
      };

      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
          integration = lib.optionalAttrs (system == "x86_64-linux") (
            import ./tests/integration/packages.nix {
              inherit pkgs lib;
              kaibaPackage = built.suite;
              kaibaModules = self.nixosModules;
            }
          );
        in
        {
          default = built.suite;
          kaiba-agent = built.agent;
          kaiba-controller = built.controller;
          kaiba-publisher = built.publisher;
        }
        // integration
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesFor system;
        in
        {
          unit = built.suite;
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
          module-eval = import ./tests/module-eval.nix {
            inherit pkgs lib;
            kaibaPackage = built.suite;
            kaibaModules = self.nixosModules;
          };
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
              python3
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
