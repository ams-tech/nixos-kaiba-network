{
  expectedCustomerKeyHash,
  sourceRevision,
}:

{
  config,
  lib,
  modulesPath,
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
      message = "the secure-boot target firmware tree must contain only the Raspberry Pi 5 Model B DTB";
    }
  ];

  kaiba.secureBootTarget = {
    enable = true;
    inherit expectedCustomerKeyHash sourceRevision;
  };

  networking.hostName = "kaiba-rpi5-secure-target";

  boot.loader.raspberry-pi = {
    bootloader = "kernel";
    configurationLimit = 0;
    useGenerationDeviceTree = true;
  };

  hardware = {
    enableAllHardware = lib.mkForce false;
    deviceTree.filter = "bcm2712-rpi-5-b.dtb";
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
      mkdir -p ./files/etc ./files/root ./files/run ./files/tmp ./files/var
      chmod 0555 ./files/etc ./files/root
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
    stateVersion = "26.05";
    switch.enable = false;
  };

  systemd.sysusers.enable = true;
}
