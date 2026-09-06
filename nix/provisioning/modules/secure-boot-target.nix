{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.kaiba.secureBootTarget;
  access = cfg.developmentAccess;
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../../../provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  evidenceDirectory = "/run/kaiba-secure-boot";
  sshRuntimeDirectory = "/run/kaiba-development-ssh";
  sshHostKey = "${sshRuntimeDirectory}/ssh_host_ed25519_key";
  expectedHashPattern = "[0-9a-f]{64}";
  bootEvidence = pkgs.writeShellApplication {
    name = "kaiba-boot-evidence";
    runtimeInputs = with pkgs; [
      coreutils
      util-linux
    ];
    text = ''
      set -euo pipefail

      readonly chosen=/proc/device-tree/chosen/bootloader
      readonly output=${evidenceDirectory}/evidence.env
      fail() {
        printf 'KAIBA_SECURE_BOOT_EVIDENCE=fail reason=%s\n' "$1" >&2
        exit 1
      }

      test -d "$chosen" || fail missing-bootloader-device-tree
      test -r "$chosen/signed" || fail missing-signed-property
      test "$(stat --format=%s "$chosen/signed")" -eq 4 || fail malformed-signed-property
      signed_hex="$(od -An -tx1 -v "$chosen/signed" | tr -d ' \n')"
      test "''${#signed_hex}" -eq 8 || fail malformed-signed-property
      signed_value=$((16#$signed_hex))
      (( (signed_value & 8) == 8 )) || fail customer-key-otp-bit-not-set

      root_source="$(findmnt --noheadings --raw --output SOURCE / | head -n 1)"
      test "$root_source" = /dev/mapper/root || fail root-is-not-verity
      root_options="$(findmnt --noheadings --raw --output OPTIONS / | head -n 1)"
      case ",$root_options," in
        (*,ro,*) ;;
        (*) fail root-is-not-read-only ;;
      esac

      test -r "$chosen/boot_img_sha256" || fail missing-boot-image-hash
      image_hash_size="$(stat --format=%s "$chosen/boot_img_sha256")"
      case "$image_hash_size" in
        32)
          image_hash="$(od -An -tx1 -v "$chosen/boot_img_sha256" | tr -d ' \n')"
          ;;
        64|65)
          image_hash="$(tr -d '\000' < "$chosen/boot_img_sha256")"
          ;;
        *)
          fail malformed-boot-image-hash
          ;;
      esac
      test "''${#image_hash}" -eq 64 || fail malformed-boot-image-hash
      case "$image_hash" in
        (*[!0-9a-f]*) fail malformed-boot-image-hash ;;
      esac

      # The expected whole-image digest cannot be embedded in boot.img without
      # creating a self-reference.  Emit the bootloader observation here; the
      # lane guard compares it with the immutable signed-bundle manifest.

      install -d -m 0700 ${evidenceDirectory}
      umask 077
      {
        printf 'schema=%s\n' 'provisioning.kaiba.network/target-boot-evidence/v1alpha1'
        printf 'signed_bits_hex=%s\n' "$signed_hex"
        printf 'customer_key_otp=true\n'
        printf 'boot_image_sha256=sha256:%s\n' "$image_hash"
        printf 'root_source=%s\n' "$root_source"
        printf 'root_read_only=true\n'
        printf 'rollback_gate=unimplemented\n'
        printf 'enrollment_ready=false\n'
      } > "$output"
      chmod 0400 "$output"
      printf 'KAIBA_SECURE_BOOT_EVIDENCE=pass signed=%s boot_img_sha256=sha256:%s root=%s rollback=unimplemented enrollment_ready=false\n' \
        "$signed_hex" "$image_hash" "$root_source"
    '';
  };
  enterRPIBoot = pkgs.writeShellApplication {
    name = "kaiba-enter-rpiboot";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.libraspberrypi
    ];
    text = ''
      set -euo pipefail

      if [ "$(id -u)" -ne 0 ]; then
        printf 'kaiba-enter-rpiboot must be run through sudo\n' >&2
        exit 1
      fi

      vcmailbox 0x0003808b 4 4 0x3
      sync
      exec ${config.systemd.package}/bin/systemctl reboot
    '';
  };
  sshAccessEvidence = pkgs.writeShellApplication {
    name = "kaiba-development-ssh-evidence";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.openssh
    ];
    text = ''
      set -euo pipefail

      readonly public_host_key=${sshHostKey}.pub
      test -s "$public_host_key"
      host_fingerprint="$(ssh-keygen -E sha256 -lf "$public_host_key" | cut -d ' ' -f 2)"
      case "$host_fingerprint" in
        SHA256:*) ;;
        (*)
          printf 'KAIBA_DEVELOPMENT_SSH=fail reason=malformed-host-key-fingerprint\n' >&2
          exit 1
          ;;
      esac
      printf 'KAIBA_DEVELOPMENT_SSH=ready user=codex address=10.0.0.2 host_key=%s\n' \
        "$host_fingerprint"
    '';
  };
in
{
  options.kaiba.secureBootTarget = {
    enable = lib.mkEnableOption "the development Pi 5 verified-root target profile";

    expectedCustomerKeyHash = lib.mkOption {
      type = lib.types.str;
      description = ''
        Lowercase SHA-256 digest of the development-cohort boot public key.
        The private key is never part of this configuration or its closure.
      '';
    };

    sourceRevision = lib.mkOption {
      type = lib.types.str;
      description = "Source revision from which the target image was built.";
    };

    developmentAccess = {
      enable = lib.mkEnableOption "the fixed development-only USB SSH management lane";

      authorizedKey = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          One public Ed25519 key admitted as the codex development user. The
          corresponding private key must remain outside Git, Nix and the image.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          developmentPosture.approval_status == "approved-development-only"
          && developmentPosture.production_ready == false
          && developmentPosture.videocore_jtag.production_blocker
          && developmentPosture.eeprom_write_protection.production_blocker;
        message = "the canonical Raspberry Pi 5 posture must remain development-only";
      }
      {
        assertion = builtins.match expectedHashPattern cfg.expectedCustomerKeyHash != null;
        message = "kaiba.secureBootTarget.expectedCustomerKeyHash must be one lowercase SHA-256 digest";
      }
      {
        assertion = cfg.sourceRevision != "";
        message = "kaiba.secureBootTarget.sourceRevision must be non-empty";
      }
      {
        assertion =
          !access.enable
          ||
            builtins.match "ssh-ed25519 [A-Za-z0-9+/]+={0,3} codex-rpi5-development-[0-9-]+" access.authorizedKey
            != null;
        message = "development access requires the fixed public Ed25519 session-key form";
      }
      {
        assertion = config.fileSystems."/".device == "/dev/mapper/root";
        message = "the secure-boot target root must be systemd's /dev/mapper/root verity mapping";
      }
    ];

    boot = {
      extraModprobeConfig = lib.optionalString access.enable ''
        options g_ether dev_addr=02:4b:41:49:42:41 host_addr=02:4b:41:49:42:42
      '';
      initrd = {
        systemd = {
          enable = true;
          dmVerity.enable = true;
        };
        availableKernelModules = [
          "dm_mod"
          "dm_verity"
          "nvme"
        ];
        kernelModules = [ "dm_verity" ];
      };
      kernelModules = lib.optionals access.enable [
        "dwc2"
        "g_ether"
      ];
      kernelParams = [
        "ro"
        "systemd.gpt_auto=no"
        "console=serial0,115200"
      ];
      tmp = {
        cleanOnBoot = true;
        useTmpfs = true;
      };
    };

    fileSystems = {
      "/" = {
        device = "/dev/mapper/root";
        fsType = "ext4";
        options = [
          "ro"
          "noatime"
          "nodev"
        ];
      };
      "/var" = {
        device = "tmpfs";
        fsType = "tmpfs";
        options = [
          "mode=0755"
          "nodev"
          "nosuid"
          "size=256M"
        ];
      };
    };

    networking = {
      firewall.enable = true;
      firewall.interfaces.usb0.allowedTCPPorts = lib.optionals access.enable [ 22 ];
      interfaces.usb0.ipv4.addresses = lib.mkIf access.enable (
        lib.mkForce [
          {
            address = "10.0.0.2";
            prefixLength = 24;
          }
        ]
      );
      useDHCP = false;
      useNetworkd = access.enable;
    };
    swapDevices = lib.mkForce [ ];
    zramSwap.enable = false;

    users = {
      # NixOS's evaluation-time lockout check requires this because every
      # password remains locked. Development access is public-key-only.
      allowNoPasswordLogin = true;
      mutableUsers = false;
      groups = lib.mkIf access.enable {
        codex.gid = 991;
      };
      users = {
        root = {
          # Immutable /etc uses systemd-sysusers, which consumes only the
          # initial password fields. Keep the account locked without requiring
          # classic activation to rewrite the immutable metadata layer.
          hashedPassword = lib.mkForce null;
          initialHashedPassword = lib.mkForce "!";
        };
        codex = lib.mkIf access.enable {
          isSystemUser = true;
          uid = 991;
          group = "codex";
          home = "/var/lib/kaiba-codex";
          createHome = false;
          shell = pkgs.bashInteractive;
          hashedPassword = lib.mkForce null;
          initialHashedPassword = lib.mkForce "!";
          openssh.authorizedKeys.keys = [ access.authorizedKey ];
        };
      };
    };

    services = {
      getty.autologinUser = lib.mkForce null;
      journald.extraConfig = "Storage=volatile";
      openssh = {
        authorizedKeysInHomedir = false;
        enable = access.enable;
        hostKeys = lib.optionals access.enable [
          {
            path = sshHostKey;
            type = "ed25519";
          }
        ];
        listenAddresses = lib.optionals access.enable [
          {
            addr = "10.0.0.2";
            port = 22;
          }
        ];
        openFirewall = false;
        settings = lib.mkIf access.enable {
          AllowUsers = [ "codex" ];
          AuthenticationMethods = "publickey";
          KbdInteractiveAuthentication = false;
          PasswordAuthentication = false;
          PermitEmptyPasswords = false;
          PermitRootLogin = "no";
          UsePAM = true;
        };
      };
    };

    systemd = {
      coredump.enable = false;
      network.wait-online.enable = false;
      services.kaiba-secure-boot-evidence = {
        description = "Verify and report the Kaiba Pi 5 signed-boot runtime";
        wantedBy = [ "multi-user.target" ];
        before = [ "multi-user.target" ];
        after = [ "local-fs.target" ];
        requires = [ "local-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = lib.getExe bootEvidence;
          # The physical lane consumes this record from the target UART.  The
          # serial kernel console alone does not forward service stdout, so
          # explicitly mirror the journal record to /dev/console.
          StandardOutput = "journal+console";
          StandardError = "journal+console";
          RemainAfterExit = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ evidenceDirectory ];
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          SystemCallArchitectures = "native";
        };
      };
      services.kaiba-development-ssh-evidence = lib.mkIf access.enable {
        description = "Report the ephemeral development SSH host key on the trusted UART";
        wantedBy = [ "multi-user.target" ];
        after = [ "sshd.service" ];
        requires = [ "sshd.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = lib.getExe sshAccessEvidence;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          CapabilityBoundingSet = "";
          LockPersonality = true;
          RestrictNamespaces = true;
          SystemCallArchitectures = "native";
        };
      };
      tmpfiles.rules = [
        "d ${evidenceDirectory} 0700 root root - -"
      ]
      ++ lib.optionals access.enable [
        "d ${sshRuntimeDirectory} 0700 root root - -"
        "d /var/lib/kaiba-codex 0700 codex codex - -"
      ];
    };

    environment = {
      systemPackages = [
        bootEvidence
      ]
      ++ lib.optionals access.enable [
        enterRPIBoot
        pkgs.iproute2
        pkgs.openssh
      ];
      etc."kaiba-provisioning/target-policy.json".text = builtins.toJSON {
        schema = "provisioning.kaiba.network/target-policy/v1alpha1";
        development_posture_id = developmentPosture.posture_id;
        source_revision = cfg.sourceRevision;
        expected_customer_key_hash = "sha256:${cfg.expectedCustomerKeyHash}";
        persistent_root = "dm-verity";
        mutable_state = "tmpfs-only";
        rollback_gate = "unimplemented";
        enrollment_ready = false;
        videocore_jtag = developmentPosture.videocore_jtag.policy;
        eeprom_write_protection = developmentPosture.eeprom_write_protection.policy;
        development_access =
          if access.enable then
            {
              enabled = true;
              transport = "usb-gadget-ethernet";
              address = "10.0.0.2";
              user = "codex";
              root_via_passwordless_sudo = true;
              ephemeral_host_key = true;
            }
          else
            {
              enabled = false;
            };
      };
    };

    security.sudo = {
      enable = access.enable;
      extraRules = lib.optionals access.enable [
        {
          users = [ "codex" ];
          commands = [
            {
              command = "ALL";
              options = [ "NOPASSWD" ];
            }
          ];
        }
      ];
    };
  };
}
