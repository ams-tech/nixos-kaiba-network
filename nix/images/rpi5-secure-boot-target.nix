{
  expectedCustomerKeyHash,
  sourceRevision,
}:

{
  config,
  lib,
  modulesPath,
  pkgs,
  ...
}:

{
  # The generic SD-image module is used only as a deterministic root-image and
  # firmware-population interface.  This target does not need its broad rescue
  # profile or automatic hardware discovery.
  disabledModules = [
    (modulesPath + "/profiles/base.nix")
    (modulesPath + "/profiles/all-hardware.nix")
  ];

  assertions = [
    {
      assertion = config.sdImage.compressImage == false;
      message = "the secure-boot target root filesystem image must remain an uncompressed ext4 image";
    }
    {
      assertion = config.hardware.deviceTree.filter == "bcm2712-rpi-5-b.dtb";
      message = "the secure-boot target base-DTB set must contain only the Raspberry Pi 5 Model B DTB";
    }
    {
      assertion =
        !config.hardware.raspberry-pi.config.all.options.camera_auto_detect.enable
        && !config.hardware.raspberry-pi.config.all.options.display_auto_detect.enable
        && !config.hardware.raspberry-pi.config.all.options.max_framebuffers.enable
        && !config.hardware.raspberry-pi.config.all.base-dt-params.audio.enable
        && !config.hardware.raspberry-pi.config.all.dt-overlays.vc4-kms-v3d.enable;
      message = "the headless secure-boot target must not request firmware overlays outside its sealed allowlist";
    }
  ];

  kaiba.secureBootTarget = {
    enable = true;
    inherit expectedCustomerKeyHash sourceRevision;
  };

  documentation.enable = false;
  # systemd can bind-mount its transient per-boot identity only over an empty
  # regular file.  The normal /etc symlink mode is intentionally unsuitable.
  environment.etc."machine-id" = {
    mode = "0444";
    text = "";
  };
  networking = {
    hostName = "kaiba-rpi5-secure-target";
    # This sealed target has no configured network interfaces.  resolvconf's
    # activation unit tries to replace and chmod /etc/resolv.conf, which is
    # incompatible with the immutable /etc metadata mount.
    resolvconf.enable = false;
  };
  # dbus-broker repeatedly exits during stage 2 on the immutable Raspberry Pi
  # root, while the reference daemon supports the same generated policy and
  # socket interface without depending on the broker-specific launch path.
  # Keep the system bus enabled, but select the reference implementation.
  services.dbus.implementation = "dbus";
  nix = {
    enable = false;
    # The generic SD-image builder still invokes nix-store and nix-env to
    # initialize the filesystem database. The modular CLI output supplies
    # those commands without pulling the manual and full Nix test aggregate
    # into this native AArch64 image-construction dependency.
    package = pkgs.nix.nix-cli;
  };

  boot.loader.raspberry-pi = {
    bootloader = "kernel";
    configurationLimit = 0;
    useGenerationDeviceTree = true;
  };

  hardware = {
    enableAllHardware = lib.mkForce false;
    deviceTree.filter = "bcm2712-rpi-5-b.dtb";
    raspberry-pi.config.all = {
      # The sealed appliance is headless. These defaults request optional
      # overlays that are deliberately absent from the minimal signed boot
      # image and can vary with attached display or camera hardware.
      options = {
        camera_auto_detect.enable = lib.mkForce false;
        display_auto_detect.enable = lib.mkForce false;
        max_framebuffers.enable = lib.mkForce false;
      };
      base-dt-params.audio.enable = lib.mkForce false;
      dt-overlays.vc4-kms-v3d.enable = lib.mkForce false;
    };
  };

  # The SD-image module otherwise points / at its removable-media label.  The
  # signed boot command line supplies the fixed dm-verity data/hash devices and
  # the initrd creates this mapper before mounting the immutable filesystem.
  fileSystems."/" = {
    device = lib.mkForce "/dev/mapper/root";
    fsType = lib.mkForce "ext4";
  };

  image.baseName = lib.mkForce "kaiba-rpi5-secure-boot-target";
  sdImage = {
    compressImage = false;
    expandOnBoot = false;
    # nixos-raspberrypi's SD-image profile fixes this at 1024 MiB. This target
    # uses the SD-image module only to obtain its root image and firmware tree;
    # the separately assembled boot.img must stay within the Pi 5
    # boot_ramdisk ceiling.
    firmwareSize = lib.mkForce 96;
    populateRootCommands = lib.mkAfter ''
      # systemd must be able to transfer these API filesystem mounts into the
      # real root during switch-root.  It cannot create missing mountpoints
      # after dm-verity has made the root filesystem read-only.
      mkdir -p \
        ./files/dev \
        ./files/etc \
        ./files/proc \
        ./files/root \
        ./files/run \
        ./files/sys \
        ./files/tmp \
        ./files/var
      chmod 0555 \
        ./files/dev \
        ./files/etc \
        ./files/proc \
        ./files/root \
        ./files/sys
      chmod 0755 ./files/run ./files/tmp ./files/var
    '';
    rootPartitionUUID = "4b414942-4152-4f4f-9488-888888888888";
    rootVolumeLabel = "KAIBA_ROOT";
  };

  system = {
    # Build /etc as a read-only initrd-mounted metadata layer.  Classic NixOS
    # activation writes symlinks into /etc and therefore cannot boot from the
    # dm-verity filesystem without this immutable overlay interface.
    etc.overlay = {
      enable = true;
      mutable = false;
    };
    disableInstallerTools = true;
    stateVersion = "26.05";
    switch.enable = false;
  };

  systemd = {
    sysusers.enable = true;
    services = {
      # The generic SD-image profile installs these mutation-oriented units.
      # This appliance has neither a Nix daemon nor a writable /etc or /nix.
      register-nix-paths.enable = false;
      systemd-update-done.enable = false;
    };
  };
}
