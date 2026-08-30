{
  kaibaProvisionPackage,
  sourceRevision,
}:

{
  config,
  lib,
  modulesPath,
  pkgs,
  ...
}:

let
  operatorName = "provisioner";
  privateDirectory = "/var/lib/kaiba-hardware-qual/private";
  relayGPIOGroup = "kaiba-relay-gpio";
  relayGPIOPath = "/dev/gpiochip-kaiba-rp1";
  # Custom share trees are not guaranteed to appear in the NixOS system path.
  # Keep qualification inputs bound to the same immutable package as the tool.
  profilePath = "${kaibaProvisionPackage}/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json";
  qualificationSchemaPath = "${kaibaProvisionPackage}/share/kaiba/schemas/rpi5-hardware-qualification-v1alpha1.schema.json";
  sourceRevisionIsCanonical = builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;

  qualificationReady = pkgs.writeShellApplication {
    name = "kaiba-qualification-ready";
    runtimeInputs = with pkgs; [
      coreutils
      gnugrep
      util-linux
    ];
    text = ''
      fail() {
        printf 'kaiba qualification station is not ready: %s\n' "$1" >&2
        exit 1
      }

      readonly source_revision_file=/etc/kaiba-provisioning/source-revision
      readonly private_directory=${lib.escapeShellArg privateDirectory}
      readonly profile=${lib.escapeShellArg profilePath}
      readonly qualification_schema=${lib.escapeShellArg qualificationSchemaPath}
      readonly provision=/run/current-system/sw/bin/kaiba-provision
      readonly relay_gpio_inventory=/run/current-system/sw/bin/kaiba-relay-gpio-inventory

      [[ -f "$source_revision_file" ]] || fail "source revision record is absent"
      source_revision="$(tr -d '\n' < "$source_revision_file")"
      [[ "$source_revision" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || \
        fail "image was not built from one clean 40- or 64-hex Git revision"

      [[ -e /run/current-system ]] || fail "/run/current-system is absent"
      [[ -e /etc/NIXOS ]] || fail "/etc/NIXOS marker is absent"
      system_closure="$(readlink -f /run/current-system)"
      [[ "$system_closure" =~ ^/nix/store/[0-9a-df-np-sv-z]{32}-[^/]+$ ]] || \
        fail "/run/current-system did not resolve to one canonical Nix store path"

      [[ "$(uname -m)" == aarch64 ]] || fail "machine architecture is not aarch64"
      [[ -x "$provision" ]] || fail "kaiba-provision is absent from the system closure"
      [[ -x "$relay_gpio_inventory" ]] || fail "relay GPIO inventory command is absent"
      for tool in gpiodetect gpioinfo gpioset; do
        [[ -x "/run/current-system/sw/bin/$tool" ]] || \
          fail "$tool is absent from the system closure"
      done
      [[ -r "$profile" ]] || fail "Raspberry Pi 5 device profile is absent"
      [[ -r "$qualification_schema" ]] || fail "qualification schema is absent"
      [[ -d "$private_directory" ]] || fail "private evidence directory is absent"
      [[ "$(stat -c %U "$private_directory")" == ${lib.escapeShellArg operatorName} ]] || \
        fail "private evidence directory has the wrong owner"
      [[ "$(stat -c %a "$private_directory")" == 700 ]] || \
        fail "private evidence directory mode is not 0700"
      [[ "$(findmnt --noheadings --raw --output FSTYPE --target "$private_directory" | head -n 1)" == tmpfs ]] || \
        fail "private evidence directory is not backed by volatile tmpfs"
      [[ -z "$(swapon --noheadings --show=NAME)" ]] || \
        fail "swap is active and could persist private evidence"
      id -nG | tr ' ' '\n' | grep -qx kaiba-provision || \
        fail "current operator is not in the kaiba-provision group"
      id -nG | tr ' ' '\n' | grep -qx ${lib.escapeShellArg relayGPIOGroup} || \
        fail "current operator is not in the relay GPIO group"

      printf 'Kaiba Pi 5 qualification station ready at revision %s.\n' \
        "$source_revision" >&2
      printf '%s\n' 'umask 077'
      printf 'export SOURCE_REVISION=%q\n' "$source_revision"
      printf 'export SYSTEM_CLOSURE=%q\n' "$system_closure"
      printf 'export KAIBA_PROVISION=%q\n' "$provision"
      printf 'export PROFILE=%q\n' "$profile"
      printf 'export QUALIFICATION_SCHEMA=%q\n' "$qualification_schema"
      printf 'export PRIVATE=%q\n' "$private_directory"
    '';
  };
  listRPIBootPaths = pkgs.writeShellApplication {
    name = "kaiba-list-rpiboot-paths";
    text = ''
      shopt -s nullglob
      for device in /sys/bus/usb/devices/*; do
        [[ -f "$device/idVendor" && -f "$device/idProduct" ]] || continue
        if ! IFS= read -r vendor < "$device/idVendor"; then
          [[ -e "$device/idVendor" ]] || continue
          exit 1
        fi
        if ! IFS= read -r product < "$device/idProduct"; then
          [[ -e "$device/idProduct" ]] || continue
          exit 1
        fi
        [[ "''${vendor,,}" == 0a5c && "''${product,,}" == 2712 ]] || continue
        usb_path="''${device##*/}"
        [[ "$usb_path" =~ ^[0-9]+-[0-9]+(\.[0-9]+)*$ ]] || exit 1
        printf '%s\n' "$usb_path"
      done
    '';
  };
  relayGPIOInventory = pkgs.writeShellApplication {
    name = "kaiba-relay-gpio-inventory";
    runtimeInputs = with pkgs; [
      coreutils
      libgpiod
    ];
    text = ''
      fail() {
        printf 'relay-gpio-inventory: %s\n' "$1" >&2
        exit 1
      }

      readonly gpio_link=${lib.escapeShellArg relayGPIOPath}
      [[ -L "$gpio_link" ]] || fail "$gpio_link is absent"

      gpio_chip="$(readlink -f -- "$gpio_link")"
      [[ "$gpio_chip" =~ ^/dev/gpiochip[0-9]+$ ]] || \
        fail "$gpio_link did not resolve to one canonical gpiochip device"
      [[ -c "$gpio_chip" ]] || fail "$gpio_chip is not a character device"

      gpio_chip_name="''${gpio_chip##*/}"
      gpio_chip_id="''${gpio_chip_name#gpiochip}"
      [[ "$gpio_chip_id" =~ ^[0-9]+$ ]] || \
        fail "$gpio_chip has an invalid character-device ID"
      # gpiochip<N> in the legacy sysfs namespace uses the deprecated global
      # GPIO base and does not identify /dev/gpiochip<N>. The chip<N>
      # extended-sysfs namespace uses the character-device ID.
      sysfs_chip="/sys/class/gpio/chip$gpio_chip_id"
      [[ -r "$sysfs_chip/label" ]] || fail "GPIO controller label is unreadable"
      IFS= read -r gpio_label < "$sysfs_chip/label"
      [[ "$gpio_label" == pinctrl-rp1 ]] || \
        fail "GPIO controller label is not pinctrl-rp1"
      [[ -r "$gpio_chip" && -w "$gpio_chip" ]] || \
        fail "$gpio_chip is not accessible to the current operator"

      printf 'KAIBA_RP1_GPIO_CHIP=%s\n' "$gpio_chip"
      gpiodetect "$gpio_link"
      gpioinfo --chip "$gpio_link" 4 6 22 26
    '';
  };
  qualificationCeremony = import ./rpi5-qualification-ceremony.nix {
    inherit
      kaibaProvisionPackage
      lib
      pkgs
      ;
    listRPIBootPathsCommand = "${listRPIBootPaths}/bin/kaiba-list-rpiboot-paths";
    qualificationReadyPackage = qualificationReady;
  };
in
{
  # The generic SD-image module imports the broad recovery-oriented base and
  # all-hardware profiles. This appliance supplies an explicit operator PATH
  # and the Pi module supplies its actual hardware support.
  disabledModules = [
    (modulesPath + "/profiles/base.nix")
    (modulesPath + "/profiles/all-hardware.nix")
  ];

  assertions = [
    {
      assertion = kaibaProvisionPackage.system == pkgs.stdenv.hostPlatform.system;
      message = "the Pi 5 image requires a native aarch64-linux kaiba-provision package";
    }
    {
      assertion = builtins.isString sourceRevision && sourceRevision != "";
      message = "the Pi 5 image requires a non-empty source revision marker";
    }
  ];

  networking = {
    hostName = "kaiba-rpi5-provisioner";
    firewall.enable = true;
    useDHCP = false;
    useNetworkd = true;
  };

  hardware.enableAllHardware = lib.mkForce false;

  boot = {
    loader.raspberry-pi.bootloader = "kernel";
    tmp = {
      cleanOnBoot = true;
      useTmpfs = true;
    };
    zfs.forceImportRoot = false;
  };

  image.baseName = lib.mkForce "kaiba-rpi5-provisioning";
  sdImage = {
    compressImage = true;
    expandOnBoot = false;
    preBuildCommands = ''
      ${pkgs.coreutils}/bin/chmod u+w "$root_fs"
      ${pkgs.coreutils}/bin/truncate --size=+256M "$root_fs"
      ${pkgs.e2fsprogs}/bin/resize2fs "$root_fs"
      ${pkgs.e2fsprogs}/bin/tune2fs -m 0 "$root_fs"

      free_blocks="$(${pkgs.e2fsprogs}/bin/dumpe2fs -h "$root_fs" 2>/dev/null \
        | ${pkgs.gawk}/bin/awk -F: '/^Free blocks:/ { gsub(/[[:space:]]/, "", $2); print $2 }')"
      block_size="$(${pkgs.e2fsprogs}/bin/dumpe2fs -h "$root_fs" 2>/dev/null \
        | ${pkgs.gawk}/bin/awk -F: '/^Block size:/ { gsub(/[[:space:]]/, "", $2); print $2 }')"
      if (( free_blocks * block_size < 240 * 1024 * 1024 )); then
        echo "RPi 5 provisioning image has less than 240 MiB of root headroom" >&2
        exit 1
      fi
    '';
  };

  swapDevices = lib.mkForce [ ];
  zramSwap.enable = false;

  fileSystems.${privateDirectory} = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [
      "rw"
      "nosuid"
      "nodev"
      "noexec"
      "mode=0700"
      "uid=1000"
      "gid=1000"
      "size=256M"
    ];
  };

  users = {
    # This is a deliberately non-admin appliance: physical console autologin
    # replaces a baked password, and no user receives wheel membership.
    allowNoPasswordLogin = true;
    mutableUsers = false;
    groups = {
      ${operatorName}.gid = 1000;
      ${relayGPIOGroup} = { };
    };
    users = {
      root.hashedPassword = "!";
      ${operatorName} = {
        isNormalUser = true;
        uid = 1000;
        group = operatorName;
        extraGroups = [ relayGPIOGroup ];
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

    kaiba-provisioning-probe = {
      enable = true;
      package = kaibaProvisionPackage;
      operators = [ operatorName ];
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
      Storage=volatile
    '';

    udev.extraRules = ''
      # Development bench access to the Pi 5 RP1 header controller only. The
      # standard Raspberry Pi rules grant every gpiochip to group gpio; keep
      # provisioner out of that group and replace the matching RP1 device's
      # group with this narrower role. Match the already-bound parent driver:
      # gpiolib emits the gpiochip add event before it creates the label sysfs
      # attribute, so ATTR{label} cannot reliably match that event. The
      # inventory helper independently verifies the label after enumeration.
      # GPIO character-device access includes line-control authority even when
      # the immediate task is inspection.
      ACTION!="remove", SUBSYSTEM=="gpio", KERNEL=="gpiochip[0-9]*", DRIVERS=="pinctrl-rp1", OWNER:="root", GROUP:="${relayGPIOGroup}", MODE:="0660", SYMLINK+="gpiochip-kaiba-rp1"
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
      "d /var/lib/kaiba-hardware-qual 0711 root root - -"
      "d ${privateDirectory} 0700 ${operatorName} ${operatorName} - -"
    ];
    # The SD module's registration unit exists for later nixos-rebuild use.
    # This fixed appliance has neither a Nix daemon nor switching authority.
    services.register-nix-paths.enable = false;
  };

  environment = {
    defaultPackages = [ ];
    systemPackages = lib.mkForce (
      config.environment.corePackages
      ++ (with pkgs; [
        iproute2
        iputils
        jq
        kaibaProvisionPackage
        less
        libgpiod
        openssh
        qualificationCeremony
        qualificationReady
        relayGPIOInventory
        usbutils
      ])
    );
    sessionVariables = {
      KAIBA_PROVISION = "/run/current-system/sw/bin/kaiba-provision";
      PRIVATE = privateDirectory;
      PROFILE = profilePath;
      QUALIFICATION_SCHEMA = qualificationSchemaPath;
      SOURCE_REVISION = sourceRevision;
    };
    interactiveShellInit = ''
      if [ "$(id -un)" = ${lib.escapeShellArg operatorName} ]; then
        export SYSTEM_CLOSURE="$(readlink -f /run/current-system)"
        umask 077
      fi
    '';
    etc = {
      "NIXOS".text = "";
      "issue".text = ''
        Kaiba Raspberry Pi 5 hardware-qualification station
        Run: kaiba-qualification-ceremony --lane-id lane-1
        Diagnostic readiness: READY_ENV="$(kaiba-qualification-ready)" && eval "$READY_ENV" && unset READY_ENV
        Relay GPIO inventory: kaiba-relay-gpio-inventory
        Runbook: /etc/kaiba-provisioning/operator-runbook.md

      '';
      "kaiba-provisioning/source-revision".text = "${sourceRevision}\n";
      "kaiba-provisioning/operator-runbook.md".source = ../../docs/raspberry-pi-5-provisioning-probe.md;
    };
  };

  security = {
    sudo.enable = false;
    pam = {
      enableUMask = true;
      services.login.rules.session.umask.settings.umask = "0077";
      services.sshd.rules.session.umask.settings.umask = "0077";
    };
  };
  nix.enable = false;
  system = {
    configurationRevision = lib.mkIf sourceRevisionIsCanonical sourceRevision;
    disableInstallerTools = true;
    stateVersion = "26.05";
    switch.enable = false;
  };
}
