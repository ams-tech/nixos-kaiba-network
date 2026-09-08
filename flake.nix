{
  description = "Kaiba secure-device dynamic DNS pilot";

  nixConfig = {
    extra-substituters = [
      "https://nixos-kaiba-network.cachix.org"
    ];
    extra-trusted-public-keys = [
      "nixos-kaiba-network.cachix.org-1:BCAt/P9Fo2JFexLB4T7eB3o0csSQI/Dy+hx+3RwzA8U="
    ];
    connect-timeout = 5;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";
    dns = {
      url = "path:./nix/dns";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      dns,
      ...
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
    in
    {
      nixosModules = dns.nixosModules;
      packages = dns.packages;
      apps = dns.apps;
      formatter = dns.formatter;

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        dns.checks.${system}
        // {
          ci-workflow =
            pkgs.runCommand "kaiba-ci-workflow-check"
              {
                nativeBuildInputs = [ pkgs.actionlint ];
              }
              ''
                actionlint ${./.github/workflows/ci.yml}
                mkdir -p "$out"
                touch "$out/passed"
              '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = dns.devShells.${system}.default.overrideAttrs (old: {
            nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.actionlint ];
          });
        }
      );
    };
}
