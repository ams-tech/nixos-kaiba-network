{
  lib,
  pkgs,
  target,
}:

let
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  cfg = target.nixosSystem.config;
  targetPolicy = builtins.fromJSON cfg.environment.etc."kaiba-provisioning/target-policy.json".text;
  developmentAccessKey = lib.removeSuffix "\n" (
    builtins.readFile ../provisioning/keys/codex-rpi5-development-2026-09-05.pub
  );
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
  !cfg.hardware.raspberry-pi.config.all.options.camera_auto_detect.enable
  && !cfg.hardware.raspberry-pi.config.all.options.display_auto_detect.enable
  && !cfg.hardware.raspberry-pi.config.all.options.max_framebuffers.enable
  && !cfg.hardware.raspberry-pi.config.all.base-dt-params.audio.enable
  && !cfg.hardware.raspberry-pi.config.all.dt-overlays.vc4-kms-v3d.enable
) "the headless secure-boot target still requests an optional firmware overlay";
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
  cfg.environment.etc."machine-id".text == "" && cfg.environment.etc."machine-id".mode == "0444"
) "the immutable /etc layer does not seed an empty transient machine-id file";
assert lib.assertMsg (
  !cfg.networking.resolvconf.enable
  && !cfg.systemd.services.register-nix-paths.enable
  && !cfg.systemd.services.systemd-update-done.enable
) "the immutable target still enables a service that mutates sealed state";
assert lib.assertMsg (
  cfg.hardware.raspberry-pi.usb-gadget-ethernet.enable
  && cfg.hardware.raspberry-pi.config.all.dt-overlays.dwc2.enable
  && cfg.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.enable
  && cfg.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.value == "peripheral"
  && builtins.elem "dwc2" cfg.boot.kernelModules
  && builtins.elem "g_ether" cfg.boot.kernelModules
  && lib.hasInfix "dev_addr=02:4b:41:49:42:41" cfg.boot.extraModprobeConfig
  && lib.hasInfix "host_addr=02:4b:41:49:42:42" cfg.boot.extraModprobeConfig
) "the target USB-C port is not fixed as the development Ethernet gadget";
assert lib.assertMsg (
  cfg.networking.useNetworkd
  && !cfg.networking.useDHCP
  &&
    cfg.networking.interfaces.usb0.ipv4.addresses == [
      {
        address = "10.0.0.2";
        prefixLength = 24;
      }
    ]
  && cfg.networking.firewall.interfaces.usb0.allowedTCPPorts == [ 22 ]
) "the development USB network is not restricted to its fixed address and SSH port";
assert lib.assertMsg (
  cfg.kaiba.secureBootTarget.developmentAccess.enable
  && cfg.kaiba.secureBootTarget.developmentAccess.authorizedKey == developmentAccessKey
  && cfg.services.openssh.enable
  && !cfg.services.openssh.authorizedKeysInHomedir
  && !cfg.services.openssh.openFirewall
  &&
    cfg.services.openssh.listenAddresses == [
      {
        addr = "10.0.0.2";
        port = 22;
      }
    ]
  && cfg.services.openssh.settings.AllowUsers == [ "codex" ]
  && cfg.services.openssh.settings.AuthenticationMethods == "publickey"
  && !cfg.services.openssh.settings.KbdInteractiveAuthentication
  && !cfg.services.openssh.settings.PasswordAuthentication
  && !cfg.services.openssh.settings.PermitEmptyPasswords
  && cfg.services.openssh.settings.PermitRootLogin == "no"
  && cfg.users.users.root.openssh.authorizedKeys.keys == [ ]
  && cfg.users.users.codex.openssh.authorizedKeys.keys == [ developmentAccessKey ]
  && cfg.security.sudo.enable
) "the development SSH user is not confined to the fixed public-key-only contract";
assert lib.assertMsg (
  cfg.services.openssh.hostKeys == [
    {
      path = "/run/kaiba-development-ssh/ssh_host_ed25519_key";
      type = "ed25519";
    }
  ]
  &&
    cfg.systemd.services.kaiba-development-ssh-evidence.serviceConfig.StandardOutput
    == "journal+console"
  &&
    cfg.systemd.services.kaiba-development-ssh-evidence.serviceConfig.StandardError == "journal+console"
) "the ephemeral SSH host identity is not reported on the trusted UART";
assert lib.assertMsg (
  targetPolicy.development_access == {
    enabled = true;
    transport = "usb-gadget-ethernet";
    address = "10.0.0.2";
    user = "codex";
    root_via_passwordless_sudo = true;
    ephemeral_host_key = true;
  }
) "the immutable target policy does not disclose its development access boundary";
assert lib.assertMsg (
  cfg.services.dbus.enable && cfg.services.dbus.implementation == "dbus"
) "the immutable target does not use the compatible reference D-Bus daemon";
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
  lib.hasInfix "./files/dev" cfg.sdImage.populateRootCommands
  && lib.hasInfix "./files/etc" cfg.sdImage.populateRootCommands
  && lib.hasInfix "./files/proc" cfg.sdImage.populateRootCommands
  && lib.hasInfix "./files/run" cfg.sdImage.populateRootCommands
  && lib.hasInfix "./files/sys" cfg.sdImage.populateRootCommands
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
  target.firmwareAllowlist == [
    "config.txt"
    "nixos/default/bcm2712-rpi-5-b.dtb"
    "nixos/default/cmdline.txt"
    "nixos/default/initrd"
    "nixos/default/kernel.img"
    "nixos/default/overlays/README"
    "nixos/default/overlays/bcm2712d0.dtbo"
    "nixos/default/overlays/dwc2.dtbo"
    "nixos/default/overlays/overlay_map.dtb"
  ]
) "the target firmware allowlist does not contain the exact Pi 5 base and D0 revision files";
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
assert lib.assertMsg (
  targetPolicy.development_posture_id == developmentPosture.posture_id
  && targetPolicy.videocore_jtag == developmentPosture.videocore_jtag.policy
  && targetPolicy.eeprom_write_protection == developmentPosture.eeprom_write_protection.policy
) "the target runtime policy is not bound to the canonical development posture";
pkgs.runCommand "kaiba-rpi5-secure-boot-target-evaluation"
  {
    nativeBuildInputs = [
      pkgs.diffutils
      pkgs.dtc
      pkgs.e2fsprogs
      pkgs.erofs-utils
      pkgs.go
      pkgs.gnugrep
    ];
  }
  ''
    export CGO_ENABLED=0
    export GOCACHE="$TMPDIR/go-cache"
    export GOPATH="$TMPDIR/go-path"

    readonly firmware=${target.firmwareTree}
    readonly kernel_dtbs=${cfg.hardware.deviceTree.dtbSource}
    readonly root_image=${target.rootImage}
    readonly dbus_unit="$(readlink -f ${target.system}/etc/systemd/system/dbus.service)"

    (
      cd ${../provisioning}
      KAIBA_SIGNED_RELEASE_TEST_UNSIGNED_ARTIFACT_SET=${target.unsignedArtifacts}/manifest.json \
        go test ./internal/provisioning/signedrelease \
          -run '^TestReviewedUnsignedArtifactSetMatchesFinalizerContract$' \
          -count=1
    )

    grep -F '${cfg.services.dbus.dbusPackage}/bin/dbus-daemon' "$dbus_unit" > /dev/null
    if grep -F 'dbus-broker-launch' "$dbus_unit" > /dev/null; then
      echo "stage 2 still resolves dbus.service to dbus-broker" >&2
      exit 1
    fi

    fsck.erofs --extract="$TMPDIR/etc" ${cfg.system.build.etcMetadataImage}
    test -f "$TMPDIR/etc/machine-id"
    test ! -L "$TMPDIR/etc/machine-id"
    test ! -s "$TMPDIR/etc/machine-id"
    test "$(stat --format=%a "$TMPDIR/etc/machine-id")" = 444
    grep -Fx ${lib.escapeShellArg developmentAccessKey} \
      "$TMPDIR/etc/ssh/authorized_keys.d/codex" > /dev/null

    for stage1_mountpoint in dev proc run sys; do
      debugfs -R "stat /$stage1_mountpoint" "$root_image" 2>&1 \
        | grep -F 'Type: directory' > /dev/null
    done

    grep -Fx 'os_prefix=nixos/default/' "$firmware/config.txt" > /dev/null
    grep -Fx 'dtoverlay=dwc2' "$firmware/config.txt" > /dev/null
    grep -Fx 'dtparam=dr_mode=peripheral' "$firmware/config.txt" > /dev/null
    if grep -Eq \
      '^(camera_auto_detect|display_auto_detect|dtparam=audio=|dtoverlay=vc4-kms-v3d)' \
      "$firmware/config.txt"; then
      echo "headless firmware config requests an optional overlay" >&2
      exit 1
    fi

    for revision_file in README bcm2712d0.dtbo dwc2.dtbo overlay_map.dtb; do
      cmp \
        "$kernel_dtbs/overlays/$revision_file" \
        "$firmware/nixos/default/overlays/$revision_file"
    done

    fdtoverlay \
      -i "$firmware/nixos/default/bcm2712-rpi-5-b.dtb" \
      -o "$TMPDIR/bcm2712d0-rpi-5-b.dtb" \
      "$firmware/nixos/default/overlays/bcm2712d0.dtbo"
    dtc \
      -I dtb \
      -O dts \
      -o "$TMPDIR/bcm2712d0-rpi-5-b.dts" \
      "$TMPDIR/bcm2712d0-rpi-5-b.dtb"
    grep -F 'compatible = "brcm,bcm2712d0-pinctrl";' \
      "$TMPDIR/bcm2712d0-rpi-5-b.dts" > /dev/null
    grep -F 'reg = <0x7d504100 0x20>;' \
      "$TMPDIR/bcm2712d0-rpi-5-b.dts" > /dev/null
    grep -F 'compatible = "brcm,bcm2712d0-aon-pinctrl";' \
      "$TMPDIR/bcm2712d0-rpi-5-b.dts" > /dev/null
    grep -F 'reg = <0x7d510700 0x1c>;' \
      "$TMPDIR/bcm2712d0-rpi-5-b.dts" > /dev/null

    mkdir -p "$out"
    printf '%s\n' \
      'rpi5-secure-boot-target-system: pass' \
      'rpi5-secure-boot-root-image: pass' \
      'rpi5-secure-boot-immutable-etc: pass' \
      'rpi5-secure-boot-firmware-allowlist: pass' \
      'rpi5-secure-boot-no-self-hash-cycle: pass' \
      'rpi5-secure-boot-development-posture-binding: pass' \
      'rpi5-secure-boot-development-usb-ssh: pass' \
      > "$out/results.txt"
  ''
