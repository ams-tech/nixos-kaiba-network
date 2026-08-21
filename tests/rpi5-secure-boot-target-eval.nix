{
  lib,
  pkgs,
  target,
}:

let
  cfg = target.nixosSystem.config;
  targetPolicy = builtins.fromJSON cfg.environment.etc."kaiba-provisioning/target-policy.json".text;
  allAssertionsPass = builtins.all (entry: entry.assertion) cfg.assertions;
in
assert lib.assertMsg allAssertionsPass
  "the Raspberry Pi 5 secure-boot target has a failing NixOS assertion";
assert lib.assertMsg (
  cfg.nixpkgs.hostPlatform.system == "aarch64-linux"
) "the Raspberry Pi 5 secure-boot target is not aarch64-linux";
assert lib.assertMsg (
  cfg.boot.loader.raspberry-pi.variant == "5"
) "the secure-boot target is not using the Raspberry Pi 5 loader";
assert lib.assertMsg (
  cfg.boot.loader.raspberry-pi.bootloader == "kernel"
) "the secure-boot target is not using the generational direct-kernel loader";
assert lib.assertMsg (
  cfg.boot.loader.raspberry-pi.configurationLimit == 0
) "the secure-boot firmware tree may include mutable host generations";
assert lib.assertMsg (
  cfg.hardware.deviceTree.filter == "bcm2712-rpi-5-b.dtb"
) "the secure-boot target DTB set is not restricted to Pi 5 Model B";
assert lib.assertMsg (
  !cfg.sdImage.compressImage
) "the secure-boot root image is compressed instead of raw ext4";
assert lib.assertMsg (
  cfg.sdImage.firmwareSize == 96
) "the secure-boot firmware image exceeds the Raspberry Pi 5 boot_ramdisk ceiling";
assert lib.assertMsg (
  !cfg.sdImage.expandOnBoot
) "the immutable secure-boot root image is configured to expand on boot";
assert lib.assertMsg (
  target.rootImage == cfg.sdImage.rootFilesystemImage
) "the artifact helper does not reuse sdImage.rootFilesystemImage";
assert lib.assertMsg (
  cfg.fileSystems."/".device == "/dev/mapper/root"
) "the target root is not the dm-verity mapper";
assert lib.assertMsg (
  cfg.boot.initrd.systemd.enable && cfg.boot.initrd.systemd.dmVerity.enable
) "the target initrd does not include systemd's dm-verity generator and setup binary";
assert lib.assertMsg (
  cfg.system.etc.overlay.enable && !cfg.system.etc.overlay.mutable
) "the read-only target root does not provide an immutable /etc layer";
assert lib.assertMsg (
  cfg.systemd.sysusers.enable && !cfg.system.switch.enable
) "the immutable target still depends on classic mutable activation or switching";
assert lib.assertMsg (
  !cfg.nix.enable && cfg.system.disableInstallerTools && !cfg.documentation.enable
) "the immutable target still contains Nix, installer tooling, or generated documentation";
assert lib.assertMsg (
  cfg.nix.package == target.nixosSystem.pkgs.nix.nix-cli
) "the image builder is using the full Nix manual and test aggregate instead of the modular CLI";
assert lib.assertMsg (
  cfg.systemd.services.kaiba-secure-boot-evidence.serviceConfig.StandardOutput == "journal+console"
  && cfg.systemd.services.kaiba-secure-boot-evidence.serviceConfig.StandardError == "journal+console"
) "secure-boot evidence is not routed to the UART-backed kernel console";
assert lib.assertMsg (
  lib.hasInfix "./files/etc" cfg.sdImage.populateRootCommands
  && lib.hasInfix "./files/var" cfg.sdImage.populateRootCommands
) "the raw root image is missing immutable-root mountpoints";
assert lib.assertMsg (lib.isDerivation target.system)
  "the target system closure is not exposed as a derivation";
assert lib.assertMsg (lib.isDerivation target.rootImage)
  "the target root filesystem image is not exposed as a derivation";
assert lib.assertMsg (lib.isDerivation target.firmwareTree)
  "the target firmware tree is not exposed as a derivation";
assert lib.assertMsg (lib.isDerivation target.unsignedArtifacts)
  "the unsigned secure-boot artifact set is not exposed as a derivation";
assert lib.assertMsg (
  builtins.length target.firmwareAllowlist == 5
  && builtins.length target.firmwareAllowlist == builtins.length (lib.unique target.firmwareAllowlist)
) "the target firmware allowlist is incomplete or contains duplicates";
assert lib.assertMsg (
  target.bootCommandLinePath == "nixos/default/cmdline.txt"
  && lib.elem target.bootCommandLinePath target.firmwareAllowlist
) "the artifact builder is not rewriting the command line selected by the Pi os_prefix";
assert lib.assertMsg (
  cfg.sdImage.populateFirmwareCommands != ""
  && lib.hasInfix " -c " cfg.sdImage.populateFirmwareCommands
  && lib.hasInfix " -f ./firmware" cfg.sdImage.populateFirmwareCommands
) "the firmware tree is not populated by the evaluated nixos-raspberrypi command";
assert lib.assertMsg (
  !(targetPolicy ? boot_image_digest)
) "the target policy embeds the final boot-image digest and creates a self-hash cycle";
pkgs.runCommand "kaiba-rpi5-secure-boot-target-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'rpi5-secure-boot-target-system: pass' \
    'rpi5-secure-boot-root-image: pass' \
    'rpi5-secure-boot-immutable-etc: pass' \
    'rpi5-secure-boot-firmware-allowlist: pass' \
    'rpi5-secure-boot-no-self-hash-cycle: pass' \
    > "$out/results.txt"
''
