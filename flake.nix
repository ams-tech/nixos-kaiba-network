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
        provisioning-probe = import ./nix/modules/provisioning-probe.nix;
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
          kaiba-provision = built.provision;
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
          device-profile-schema =
            pkgs.runCommand "kaiba-device-profile-schema-check"
              { nativeBuildInputs = [ pkgs.check-jsonschema ]; }
              ''
                check-jsonschema \
                  --schemafile ${./schemas/device-profile-v1alpha1.schema.json} \
                  ${./profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json}
                mkdir -p "$out"
                touch "$out/passed"
              '';
          rpi5-probe-bundle =
            pkgs.runCommand "kaiba-rpi5-probe-bundle-check" { nativeBuildInputs = [ pkgs.jq ]; }
              ''
                test "$(find ${built.rpi5ProbeBundle}/bundle -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = $'bootcode5.bin\nconfig.txt'
                test ! -L ${built.rpi5ProbeBundle}/bundle/bootcode5.bin
                test ! -L ${built.rpi5ProbeBundle}/bundle/config.txt
                test "$(cat ${built.rpi5ProbeBundle}/bundle/config.txt)" = 'recovery_metadata=1'
                test "$(wc -c < ${built.rpi5ProbeBundle}/bundle/config.txt)" -eq 20
                test "$(jq -r .schema ${built.rpi5ProbeBundle}/manifest.json)" = 'kaiba.rpi5-probe-bundle/v1alpha1'
                test "$(jq -c 'keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bundle_sha256","files","schema","tool_sha256","tool_version"]'
                test "$(jq -c '.files | keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bootcode5.bin","config.txt"]'
                test "$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)" = '${pkgs.rpiboot.version}'
                tool_digest="sha256:$(sha256sum ${pkgs.rpiboot}/bin/rpiboot | cut -d ' ' -f 1)"
                firmware_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/bootcode5.bin | cut -d ' ' -f 1)"
                config_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/config.txt | cut -d ' ' -f 1)"
                bundle_digest="sha256:$(
                  printf '%s\0%s\0%s\0%s\0%s\0' \
                    'kaiba.rpi5.probe-bundle.v1' \
                    'bootcode5.bin' "$firmware_digest" \
                    'config.txt' "$config_digest" \
                    | sha256sum | cut -d ' ' -f 1
                )"
                test "$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$tool_digest"
                test "$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$firmware_digest"
                test "$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$config_digest"
                test "$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$bundle_digest"
                mkdir -p "$out"
                touch "$out/passed"
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
          module-eval = import ./tests/module-eval.nix {
            inherit pkgs lib;
            kaibaPackage = built.suite;
            kaibaProvisionPackage = built.provision;
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
