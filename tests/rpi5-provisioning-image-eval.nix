{
  imageConfig,
  kaibaProvisionPackage,
  lib,
  pkgs,
  sourceRevision,
}:

let
  privateDirectory = "/var/lib/kaiba-hardware-qual/private";
  systemPackageNames = map lib.getName imageConfig.environment.systemPackages;
  forbiddenMutationPackages = [
    "cryptsetup"
    "ddrescue"
    "gptfdisk"
    "hdparm"
    "ms-sys"
    "nvme-cli"
    "parted"
    "raspberrypi-eeprom"
    "raspberrypi-utils"
    "rpi-otp-derived-key-provision"
    "rpi-otp-private-key"
    "testdisk"
  ];
  sourceRevisionIsCanonical = builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;

  hardwareContract =
    imageConfig.nixpkgs.hostPlatform.system == "aarch64-linux"
    && imageConfig.boot.loader.raspberry-pi.variant == "5"
    && imageConfig.boot.loader.raspberry-pi.bootloader == "kernel"
    && lib.isDerivation imageConfig.system.build.sdImage
    && imageConfig.image.baseName == "kaiba-rpi5-provisioning"
    && imageConfig.sdImage.compressImage
    && !imageConfig.sdImage.expandOnBoot
    && lib.hasInfix "chmod u+w" imageConfig.sdImage.preBuildCommands
    && lib.hasInfix "truncate --size=+256M" imageConfig.sdImage.preBuildCommands
    && lib.hasInfix "resize2fs" imageConfig.sdImage.preBuildCommands
    && lib.hasInfix "tune2fs -m 0" imageConfig.sdImage.preBuildCommands
    && lib.hasInfix "less than 240 MiB of root headroom" imageConfig.sdImage.preBuildCommands
    && !imageConfig.hardware.enableAllHardware;

  probeBoundary =
    imageConfig.services.kaiba-provisioning-probe.enable
    && imageConfig.services.kaiba-provisioning-probe.package == kaibaProvisionPackage
    && imageConfig.services.kaiba-provisioning-probe.operators == [ "provisioner" ]
    && builtins.elem kaibaProvisionPackage imageConfig.environment.systemPackages
    && builtins.elem "kaiba-provision" imageConfig.users.users.provisioner.extraGroups
    && lib.hasInfix ''SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", GROUP="kaiba-provision"'' imageConfig.services.udev.extraRules
    && !(lib.hasInfix ''ATTR{idVendor}=="0a5c", MODE="0660"'' imageConfig.services.udev.extraRules);

  accessContract =
    imageConfig.users.allowNoPasswordLogin
    && !imageConfig.users.mutableUsers
    && imageConfig.users.users.root.hashedPassword == "!"
    && imageConfig.users.users.provisioner.hashedPassword == "!"
    && imageConfig.users.users.provisioner.homeMode == "0700"
    && imageConfig.services.getty.autologinUser == "provisioner"
    && !imageConfig.services.getty.autologinOnce
    && imageConfig.services.openssh.enable
    && imageConfig.services.openssh.authorizedKeysInHomedir
    && imageConfig.services.openssh.openFirewall
    && imageConfig.services.openssh.settings.AllowUsers == [ "provisioner" ]
    && imageConfig.services.openssh.settings.AuthenticationMethods == "publickey"
    && !imageConfig.services.openssh.settings.KbdInteractiveAuthentication
    && !imageConfig.services.openssh.settings.PasswordAuthentication
    && imageConfig.services.openssh.settings.PermitRootLogin == "no"
    && imageConfig.services.openssh.settings.UsePAM
    && imageConfig.users.users.root.openssh.authorizedKeys.keys == [ ]
    && imageConfig.users.users.root.openssh.authorizedKeys.keyFiles == [ ]
    && imageConfig.users.users.provisioner.openssh.authorizedKeys.keys == [ ]
    && imageConfig.users.users.provisioner.openssh.authorizedKeys.keyFiles == [ ]
    && !imageConfig.security.sudo.enable
    && imageConfig.security.pam.enableUMask
    && imageConfig.security.pam.services.login.rules.session.umask.settings.umask == "0077"
    && imageConfig.security.pam.services.sshd.rules.session.umask.settings.umask == "0077";

  networkContract =
    imageConfig.networking.useNetworkd
    && !imageConfig.networking.networkmanager.enable
    && imageConfig.systemd.network.enable
    && !imageConfig.systemd.network.wait-online.enable
    && imageConfig.systemd.network.networks."10-wired".matchConfig.Name == "e*"
    && imageConfig.systemd.network.networks."10-wired".networkConfig.DHCP == "yes";

  privateEvidenceContract =
    imageConfig.fileSystems.${privateDirectory}.device == "tmpfs"
    && imageConfig.fileSystems.${privateDirectory}.fsType == "tmpfs"
    && builtins.all (option: builtins.elem option imageConfig.fileSystems.${privateDirectory}.options) [
      "nosuid"
      "nodev"
      "noexec"
      "mode=0700"
      "uid=1000"
      "gid=1000"
    ]
    && imageConfig.swapDevices == [ ]
    && !imageConfig.zramSwap.enable
    && !imageConfig.systemd.coredump.enable
    && lib.hasInfix "Storage=volatile" imageConfig.services.journald.extraConfig
    && builtins.elem "d ${privateDirectory} 0700 provisioner provisioner - -" imageConfig.systemd.tmpfiles.rules;

  provenanceContract =
    imageConfig.environment.etc."NIXOS".text == ""
    && imageConfig.environment.etc."kaiba-provisioning/source-revision".text == "${sourceRevision}\n"
    && imageConfig.environment.sessionVariables.SOURCE_REVISION == sourceRevision
    && imageConfig.environment.sessionVariables.PRIVATE == privateDirectory
    && lib.hasInfix "readlink -f /run/current-system" imageConfig.environment.interactiveShellInit
    && lib.hasInfix ''READY_ENV="$(kaiba-qualification-ready)" && eval "$READY_ENV"'' imageConfig.environment.etc.issue.text
    && builtins.elem "kaiba-qualification-ready" systemPackageNames
    && (
      if sourceRevisionIsCanonical then
        imageConfig.system.configurationRevision == sourceRevision
      else
        imageConfig.system.configurationRevision == null
    );

  guidedCeremonyContract =
    builtins.elem "kaiba-qualification-ceremony" systemPackageNames
    && lib.hasInfix "Run: kaiba-qualification-ceremony --lane-id lane-1" imageConfig.environment.etc.issue.text;

  applianceContract =
    !imageConfig.nix.enable
    && imageConfig.system.disableInstallerTools
    && !imageConfig.system.switch.enable
    && !imageConfig.systemd.services.register-nix-paths.enable
    && !(builtins.any (name: builtins.elem name forbiddenMutationPackages) systemPackageNames);
in
assert lib.assertMsg hardwareContract
  "the RPi 5 provisioning image hardware or SD-image contract changed";
assert lib.assertMsg probeBoundary "the RPi 5 provisioning image USB probe boundary changed";
assert lib.assertMsg accessContract
  "the RPi 5 provisioning image local or remote access contract changed";
assert lib.assertMsg networkContract "the RPi 5 provisioning image wired-network contract changed";
assert lib.assertMsg privateEvidenceContract
  "the RPi 5 provisioning image private-evidence boundary changed";
assert lib.assertMsg provenanceContract
  "the RPi 5 provisioning image source-provenance contract changed";
assert lib.assertMsg guidedCeremonyContract
  "the RPi 5 provisioning image guided-ceremony contract changed";
assert lib.assertMsg applianceContract
  "the RPi 5 provisioning image appliance or no-mutation-tools contract changed";
pkgs.runCommand "kaiba-rpi5-provisioning-image-evaluation" { } ''
  readiness_failure() {
    return 23
  }
  if READY_ENV="$(readiness_failure)" && eval "$READY_ENV" && unset READY_ENV; then
    echo "failed readiness command was accidentally accepted" >&2
    exit 1
  fi
  test -z "''${SOURCE_REVISION:-}"

  readiness_success() {
    printf '%s\n' 'export SOURCE_REVISION=0123456789012345678901234567890123456789'
  }
  READY_ENV="$(readiness_success)" && eval "$READY_ENV" && unset READY_ENV
  test "$SOURCE_REVISION" = 0123456789012345678901234567890123456789

  mkdir -p "$out"
  printf '%s\n' \
    'rpi5-hardware-and-sd-image: pass' \
    'probe-usb-boundary: pass' \
    'console-and-key-only-ssh: pass' \
    'wired-networkd-dhcp: pass' \
    'volatile-private-evidence: pass' \
    'clean-source-readiness: pass' \
    'guided-qualification-ceremony: pass' \
    'fail-closed-readiness-evaluation: pass' \
    'no-installer-mutation-tools: pass' \
    > "$out/results.txt"
''
