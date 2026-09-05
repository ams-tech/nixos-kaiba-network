{
  acceptedTargetFingerprint,
  hardwareQualificationDigest,
  laneID,
  manualLaneQualificationDigest,
  manualLaneQualificationSourceRevision,
  operatorName,
  payloadSourceRevision,
  rpibootSysfsPath,
  secureBootRunner,
  sourceRevision,
  stationID,
  uartPath,
  unfusedCompatibilityUARTDigest,
}:

{
  config,
  lib,
  modulesPath,
  pkgs,
  ...
}:

let
  runner = "${secureBootRunner}/bin/kaiba-rpi5-development-secure-boot";
  operatorCommandText = ''
    exec ${config.security.wrapperDir}/sudo -- ${runner} "$@"
  '';
  operatorCommand =
    (pkgs.writeShellApplication {
      name = "kaiba-secure-boot";
      text = operatorCommandText;
    }).overrideAttrs
      (old: {
        passthru = (old.passthru or { }) // {
          kaibaSecureBootOperatorCommand = {
            privilegeWrapper = "${config.security.wrapperDir}/sudo";
            script = operatorCommandText;
          };
        };
      });
  inventoryCommand = pkgs.writeShellApplication {
    name = "kaiba-secure-boot-inventory";
    text = ''
      exec ${runner} inventory
    '';
  };
in
{
  disabledModules = [
    (modulesPath + "/profiles/base.nix")
    (modulesPath + "/profiles/all-hardware.nix")
  ];

  assertions = [
    {
      assertion = secureBootRunner.system == pkgs.stdenv.hostPlatform.system;
      message = "the direct mutation station requires its native secure-boot runner";
    }
    {
      assertion = secureBootRunner ? kaibaDevelopmentSecureBoot;
      message = "the direct mutation station requires a factory-produced secure-boot runner";
    }
    {
      assertion = !secureBootRunner.kaibaDevelopmentSecureBoot.remoteAuthorityRequired;
      message = "the direct mutation station runner unexpectedly requires remote authority";
    }
    {
      assertion = !secureBootRunner.kaibaDevelopmentSecureBoot.signingCapable;
      message = "the direct mutation station must not contain signing capability";
    }
  ];

  networking = {
    hostName = "kaiba-rpi5-secure-boot-station";
    firewall.enable = true;
    useDHCP = false;
    useNetworkd = true;
  };

  i18n.defaultLocale = "C.UTF-8";

  hardware = {
    enableAllHardware = lib.mkForce false;
    raspberry-pi.config.all.base-dt-params.strict_gpiod.enable = true;
  };

  boot = {
    loader.raspberry-pi.bootloader = "kernel";
    tmp = {
      cleanOnBoot = true;
      useTmpfs = true;
    };
    zfs.forceImportRoot = false;
  };

  image.baseName = lib.mkForce "kaiba-rpi5-development-secure-boot-station";
  sdImage = {
    compressImage = true;
    expandOnBoot = true;
    preBuildCommands = ''
      ${pkgs.coreutils}/bin/chmod u+w "$root_fs"
      ${pkgs.coreutils}/bin/truncate --size=+512M "$root_fs"
      ${pkgs.e2fsprogs}/bin/resize2fs "$root_fs"
      ${pkgs.e2fsprogs}/bin/tune2fs -m 0 "$root_fs"
    '';
  };

  swapDevices = lib.mkForce [ ];
  zramSwap.enable = false;

  users = {
    allowNoPasswordLogin = true;
    mutableUsers = false;
    groups.${operatorName}.gid = 1000;
    users = {
      root.hashedPassword = "!";
      ${operatorName} = {
        isNormalUser = true;
        uid = 1000;
        group = operatorName;
        hashedPassword = "!";
        homeMode = "0700";
      };
    };
  };

  services = {
    getty = {
      autologinOnce = false;
      autologinUser = operatorName;
    };
    openssh = {
      authorizedKeysInHomedir = true;
      enable = true;
      openFirewall = true;
      settings = {
        AllowUsers = [ operatorName ];
        AuthenticationMethods = "publickey";
        KbdInteractiveAuthentication = false;
        PasswordAuthentication = false;
        PermitRootLogin = "no";
      };
    };
    journald.extraConfig = ''
      Storage=persistent
      Compress=yes
      Seal=yes
    '';
  };

  systemd = {
    coredump.enable = false;
    network = {
      enable = true;
      networks."10-wired" = {
        matchConfig.Name = "e*";
        networkConfig.DHCP = "yes";
        linkConfig.RequiredForOnline = "no";
      };
      wait-online.enable = false;
    };
    tmpfiles.rules = [
      "d /var/lib/kaiba-development-secure-boot 0700 root root - -"
    ];
    services.register-nix-paths.enable = false;
  };

  environment = {
    defaultPackages = [ ];
    systemPackages = lib.mkForce (
      config.environment.corePackages
      ++ (with pkgs; [
        inventoryCommand
        iproute2
        iputils
        jq
        less
        openssh
        operatorCommand
        usbutils
      ])
    );
    interactiveShellInit = ''
      if [ "$(id -un)" = ${lib.escapeShellArg operatorName} ]; then
        umask 077
      fi
    '';
    etc = {
      "NIXOS".text = "";
      "issue".text = ''
        Kaiba Raspberry Pi 5 development secure-boot station
        No signing or remote authority is present on this image.
        Keep the target disconnected, then run: kaiba-secure-boot provision
        The foreground command prints each physical action and detects USB transitions automatically.
        Resume/status after interruption: kaiba-secure-boot status

      '';
      "kaiba-provisioning/source-revision".text = "${sourceRevision}\n";
      "kaiba-provisioning/payload-source-revision".text = "${payloadSourceRevision}\n";
      "kaiba-provisioning/manual-lane-qualification-source-revision".text =
        "${manualLaneQualificationSourceRevision}\n";
      "kaiba-provisioning/manual-lane-qualification-digest".text = "${manualLaneQualificationDigest}\n";
      "kaiba-provisioning/hardware-qualification-digest".text = "${hardwareQualificationDigest}\n";
      "kaiba-provisioning/accepted-target-fingerprint".text = "${acceptedTargetFingerprint}\n";
      "kaiba-provisioning/unfused-compatibility-uart-digest".text = "${unfusedCompatibilityUARTDigest}\n";
      "kaiba-provisioning/rpiboot-sysfs-path".text = "${rpibootSysfsPath}\n";
      "kaiba-provisioning/uart-path".text = "${uartPath}\n";
      "kaiba-provisioning/station-id".text = "${stationID}\n";
      "kaiba-provisioning/lane-id".text = "${laneID}\n";
    };
  };

  security = {
    sudo = {
      enable = true;
      wheelNeedsPassword = true;
      extraRules = [
        {
          users = [ operatorName ];
          commands = [
            {
              command = runner;
              options = [ "NOPASSWD" ];
            }
          ];
        }
      ];
    };
    pam = {
      enableUMask = true;
      services.login.rules.session.umask.settings.umask = "0077";
      services.sshd.rules.session.umask.settings.umask = "0077";
    };
  };

  nix.enable = false;
  system = {
    configurationRevision = sourceRevision;
    disableInstallerTools = true;
    stateVersion = "26.05";
    switch.enable = false;
  };
}
