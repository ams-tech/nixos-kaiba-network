{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.kaiba.secureBootTarget;
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../../../provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  evidenceDirectory = "/run/kaiba-secure-boot";
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
        assertion = config.fileSystems."/".device == "/dev/mapper/root";
        message = "the secure-boot target root must be systemd's /dev/mapper/root verity mapping";
      }
    ];

    boot = {
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
      useDHCP = false;
    };
    swapDevices = lib.mkForce [ ];
    zramSwap.enable = false;

    users = {
      # NixOS's evaluation-time lockout check requires this for an appliance
      # with no usable account.  The root hash is locked, getty autologin is
      # disabled, SSH is absent, and the target has no network configuration.
      allowNoPasswordLogin = true;
      mutableUsers = false;
      users.root = {
        # Immutable /etc uses systemd-sysusers, which consumes only the
        # initial password fields.  Keep the account locked without requiring
        # classic activation to rewrite /etc/shadow on the verified root.
        hashedPassword = lib.mkForce null;
        initialHashedPassword = lib.mkForce "!";
      };
    };

    services = {
      getty.autologinUser = lib.mkForce null;
      journald.extraConfig = "Storage=volatile";
      openssh.enable = false;
    };

    systemd = {
      coredump.enable = false;
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
      tmpfiles.rules = [ "d ${evidenceDirectory} 0700 root root - -" ];
    };

    environment = {
      systemPackages = [ bootEvidence ];
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
      };
    };

    security.sudo.enable = false;
  };
}
