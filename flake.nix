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

      defaultTargetSourceRevision =
        if
          builtins.isString sourceRevision
          && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null
        then
          sourceRevision
        else
          throw "mkRpi5SecureBootTarget requires a clean Git source or an explicit canonical sourceRevision";

      # Keep this list deliberately small and literal.  The target module
      # filters the kernel DTBs to the single supported Pi 5 Model B file, and
      # the firmware-tree derivation fails if the pinned upstream population
      # command ever adds, removes, or renames a file.
      rpi5SecureBootFirmwareAllowlist = [
        "config.txt"
        "nixos/default/bcm2712-rpi-5-b.dtb"
        "nixos/default/cmdline.txt"
        "nixos/default/initrd"
        "nixos/default/kernel.img"
      ];

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

      mkRpi5SecureBootTarget =
        {
          expectedCustomerKeyHash,
          bootImageSizeMiB ? 96,
          bootOrderPolicy ? "nvme-only",
          dataDevice ? "/dev/nvme0n1p2",
          hashDevice ? "/dev/nvme0n1p3",
          sourceRevision ? defaultTargetSourceRevision,
        }:
        let
          nixosSystem = nixos-raspberrypi.lib.nixosSystem {
            trustCaches = false;
            modules = [
              nixos-raspberrypi.nixosModules.sd-image
              nixos-raspberrypi.nixosModules.raspberry-pi-5.base
              nixos-raspberrypi.nixosModules.raspberry-pi-5.page-size-16k
              provisioning.nixosModules.secure-boot-target
              (import ./nix/images/rpi5-secure-boot-target.nix {
                inherit expectedCustomerKeyHash sourceRevision;
              })
            ];
          };
          targetConfig = nixosSystem.config;
          targetPkgs = nixosSystem.pkgs;
          bootCommandLinePath = "nixos/default/cmdline.txt";
          firmwareAllowlist = rpi5SecureBootFirmwareAllowlist;
          firmwareTree =
            targetPkgs.runCommand "kaiba-rpi5-secure-boot-firmware-tree"
              {
                nativeBuildInputs = with targetPkgs.buildPackages; [
                  coreutils
                  diffutils
                  findutils
                ];
                preferLocalBuild = true;
              }
              ''
                set -euo pipefail
                export LC_ALL=C
                export TZ=UTC

                mkdir -p firmware
                ${targetConfig.sdImage.populateFirmwareCommands}

                # nixos-raspberrypi's shared firmware builder emits legacy
                # Pi 1-4 files and generation metadata. Pi 5 loads firmware
                # from EEPROM and consumes none of these from boot.img.
                rm -f -- \
                  firmware/bootcode.bin \
                  firmware/fixup.dat \
                  firmware/fixup4.dat \
                  firmware/fixup4cd.dat \
                  firmware/fixup4db.dat \
                  firmware/fixup4x.dat \
                  firmware/fixup_cd.dat \
                  firmware/fixup_db.dat \
                  firmware/fixup_x.dat \
                  firmware/start.elf \
                  firmware/start4.elf \
                  firmware/start4cd.elf \
                  firmware/start4db.elf \
                  firmware/start4x.elf \
                  firmware/start_cd.elf \
                  firmware/start_db.elf \
                  firmware/start_x.elf \
                  firmware/nixos/default/kernel-link \
                  firmware/nixos/default/system-link

                if test -n "$(find firmware -type l -print -quit)"; then
                  echo "Raspberry Pi firmware population produced a symbolic link" >&2
                  exit 1
                fi
                if test -n "$(find firmware ! -type d ! -type f -print -quit)"; then
                  echo "Raspberry Pi firmware population produced an unsupported filesystem object" >&2
                  exit 1
                fi

                find firmware -type f -printf '%P\n' | sort > actual-files
                {
                  ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") (
                    lib.sort builtins.lessThan firmwareAllowlist
                  )}
                } > expected-files
                if ! cmp expected-files actual-files; then
                  echo "Raspberry Pi firmware population differs from the explicit allowlist" >&2
                  exit 1
                fi

                find firmware -exec touch --date=@315532800 '{}' +
                find firmware -type d -exec chmod 0555 '{}' +
                find firmware -type f -exec chmod 0444 '{}' +
                mkdir -p "$out"
                cp -R --no-preserve=ownership firmware/. "$out/"
              '';
          rootImage = targetConfig.sdImage.rootFilesystemImage;
          unsignedArtifacts = provisioning.lib.mkRpi5SecureBootArtifacts {
            system = "aarch64-linux";
            inherit
              bootCommandLinePath
              bootImageSizeMiB
              bootOrderPolicy
              dataDevice
              expectedCustomerKeyHash
              firmwareAllowlist
              firmwareTree
              hashDevice
              rootImage
              sourceRevision
              ;
          };
        in
        {
          inherit
            bootCommandLinePath
            firmwareAllowlist
            firmwareTree
            nixosSystem
            rootImage
            unsignedArtifacts
            ;
          system = targetConfig.system.build.toplevel;
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
          provisioning-audit
          provisioning-control
          provisioning-lane-guard
          provisioning-probe
          provisioning-signing-gate
          provisioning-station-demo
          secure-boot-target
          ;
      };

      lib = provisioning.lib // {
        inherit mkRpi5SecureBootTarget rpi5SecureBootFirmwareAllowlist;
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
            kaiba-provision-audit
            kaiba-provision-control
            kaiba-provision-integrated-rehearsal
            kaiba-provision-lane-guard
            kaiba-provision-media-stager
            kaiba-provision
            kaiba-provision-rehearsal
            kaiba-provision-signer-foundation
            kaiba-provision-signing-client-foundation
            kaiba-provision-signing-gate-foundation
            kaiba-provision-station
            kaiba-provision-station-demo
            kaiba-provision-station-pages
            kaiba-provision-unfused-compat
            kaiba-provision-unfused-evidence
            provisioning-test-result
            kaiba-provision-yubikey-wrapper-foundation
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
          laneGuardFixtureBundle = "${provisioning.packages.${system}.rpi5-probe-bundle}/bundle";
          laneGuardFixture = provisioning.lib.mkRpi5PhysicalLaneGuard {
            inherit system;
            name = "kaiba-rpi5-physical-lane-guard-module-fixture";
            compiledArtifactSetDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
            expectedBootImageDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            expectedEEPROMHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
            freshCommitBundle = laneGuardFixtureBundle;
            freshReadbackBundle = laneGuardFixtureBundle;
            negativeBootBundle = laneGuardFixtureBundle;
            ownedReadbackBundle = laneGuardFixtureBundle;
            ownedRecoveryBundle = laneGuardFixtureBundle;
            rootIntegrityBundle = laneGuardFixtureBundle;
            laneGuardPackageDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
            signedReleaseManifestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
          };
          moduleEval = import ./tests/module-eval.nix {
            inherit pkgs lib;
            kaibaPackage = dns.packages.${system}.dns-suite;
            kaibaAuditPackage = provisioning.packages.${system}.kaiba-provision-audit;
            kaibaControlPackage = provisioning.packages.${system}.kaiba-provision-control;
            kaibaLaneGuardPackage = laneGuardFixture;
            kaibaProvisionPackage = provisioning.packages.${system}.kaiba-provision;
            kaibaStationDemoPackage = provisioning.packages.${system}.kaiba-provision-station-demo;
            kaibaModules = self.nixosModules;
          };
        in
        {
          unit = self.packages.${system}.default;
          development-yubikey-signing = provisioning.checks.${system}.development-yubikey-signing;
          device-profile-schema = provisioning.checks.${system}.device-profile-schema;
          rpi5-probe-bundle = provisioning.checks.${system}.rpi5-probe-bundle;
          module-eval = moduleEval;
          provisioning-test-result = provisioning.checks.${system}.provisioning-test-result;
          station-ui = provisioning.checks.${system}.station-ui;
          rpiboot-metadata-stdout = provisioning.checks.${system}.rpiboot-metadata-stdout;
          secure-boot-artifacts = provisioning.checks.${system}.secure-boot-artifacts;
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
          rpi5-qualification-ceremony = import ./tests/rpi5-qualification-ceremony.nix {
            inherit lib pkgs;
          };
          rpi5-secure-boot-target-eval = import ./tests/rpi5-secure-boot-target-eval.nix {
            inherit lib pkgs;
            target = mkRpi5SecureBootTarget {
              # Evaluation fixture only.  Deployments must supply the reviewed
              # customer-key hash produced by the pinned Raspberry Pi tooling.
              expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              sourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            };
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
