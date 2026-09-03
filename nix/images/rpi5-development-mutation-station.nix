{
  acceptedTargetFingerprint,
  auditAddress,
  auditPort,
  authorityBridgePackage,
  controlAddress,
  controlPort,
  hardwareQualificationDigest,
  laneID,
  laneOperatorPackage,
  laneWorkflowPackage,
  manualLaneQualificationDigest,
  manualLaneQualificationSourceRevision,
  operatorName,
  payloadSourceRevision,
  physicalLaneGuard,
  rpibootSysfsPath,
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
  credentialRoot = "/var/lib/kaiba-provisioning-credentials";
  bridgeCredentialRoot = "${credentialRoot}/bridge";
  operatorCredentialRoot = "/home/${operatorName}/.config/kaiba-provisioning/lane-workflow";
  evidenceRoot = "/var/lib/kaiba-provisioning-evidence";
  manualLaneQualificationPath = "${evidenceRoot}/manual-lane-qualification.json";
  sourceRevisionIsCanonical = builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;
  manualLaneQualificationDigestIsCanonical =
    builtins.match "sha256:[0-9a-f]{64}" manualLaneQualificationDigest != null;
  acceptedTargetFingerprintIsCanonical =
    builtins.match "sha256:[0-9a-f]{64}" acceptedTargetFingerprint != null;
  hardwareQualificationDigestIsCanonical =
    builtins.match "sha256:[0-9a-f]{64}" hardwareQualificationDigest != null;
  unfusedCompatibilityUARTDigestIsCanonical =
    builtins.match "sha256:[0-9a-f]{64}" unfusedCompatibilityUARTDigest != null;
  credentialPacketValidator = pkgs.writeShellApplication {
    name = "kaiba-validate-mutation-credential-packet";
    runtimeInputs = with pkgs; [
      coreutils
      diffutils
    ];
    text = ''
      case "''${1:-}" in
        validate-manifest)
          test "$#" -eq 2
          credential_root=$2
          manifest="$credential_root/SHA256SUMS"

          mapfile -t manifest_lines < "$manifest"
          test "''${#manifest_lines[@]}" -eq 4

          manifest_files=()
          for manifest_line in "''${manifest_lines[@]}"; do
            digest="''${manifest_line%% *}"
            test "''${#digest}" -eq 64
            test -z "''${digest//[0-9a-f]/}"

            separator_and_file="''${manifest_line#"$digest"}"
            test "''${separator_and_file:0:2}" = "  "
            manifest_file="''${separator_and_file:2}"
            case "$manifest_file" in
              audit-server-ca.crt|control-server-ca.crt|station-client.crt|station-client.key)
                ;;
              *)
                exit 1
                ;;
            esac
            manifest_files+=("$manifest_file")
          done

          expected_manifest_files="$(printf '%s\n' \
            audit-server-ca.crt \
            control-server-ca.crt \
            station-client.crt \
            station-client.key | sort)"
          observed_manifest_files="$(printf '%s\n' "''${manifest_files[@]}" | sort)"
          test "$observed_manifest_files" = "$expected_manifest_files"

          (
            cd "$credential_root"
            sha256sum --check --strict SHA256SUMS >/dev/null
          )
          ;;
        require-distinct-cas)
          test "$#" -eq 3
          comparison_status=0
          cmp --silent -- "$2" "$3" || comparison_status=$?
          test "$comparison_status" -eq 1
          ;;
        *)
          exit 2
          ;;
      esac
    '';
  };
  manualLaneAdmission = pkgs.writeShellApplication {
    name = "kaiba-mutation-manual-lane-admission";
    runtimeInputs = with pkgs; [
      check-jsonschema
      coreutils
      jq
    ];
    text = ''
      record=${lib.escapeShellArg manualLaneQualificationPath}
      expected=${lib.escapeShellArg manualLaneQualificationDigest}

      test -f "$record"
      test ! -L "$record"
      test "$(stat -c '%u:%g:%a' "$record")" = 0:0:400

      check-jsonschema \
        --schemafile ${../../provisioning/schemas/rpi5-manual-lane-qualification-v1alpha1.schema.json} \
        "$record"

      observed="sha256:$(sha256sum "$record" | cut -d ' ' -f 1)"
      test "$observed" = "$expected"

      jq -e \
        --arg station_id ${lib.escapeShellArg stationID} \
        --arg lane_id ${lib.escapeShellArg laneID} \
        --arg rpiboot_sysfs_path ${lib.escapeShellArg rpibootSysfsPath} \
        --arg uart_path ${lib.escapeShellArg uartPath} \
        --arg target_fingerprint ${lib.escapeShellArg acceptedTargetFingerprint} \
        --arg hardware_qualification_digest ${lib.escapeShellArg hardwareQualificationDigest} \
        --arg qualification_source_revision ${lib.escapeShellArg manualLaneQualificationSourceRevision} \
        --arg unfused_uart_digest ${lib.escapeShellArg unfusedCompatibilityUARTDigest} \
        '
          .schema_version == "kaiba.provisioning.rpi5-manual-lane-qualification/v1alpha1"
          and .status == "accepted_development_rehearsal"
          and .evidence_basis == "operator_attestation_and_software_observation"
          and .automated_failoff == false
          and .electrical_measurement_performed == false
          and .production_qualified == false
          and .station_id == $station_id
          and .lane_id == $lane_id
          and .rpiboot_sysfs_path == $rpiboot_sysfs_path
          and .uart_path == $uart_path
          and .target_fingerprint == $target_fingerprint
          and .hardware_qualification_digest == $hardware_qualification_digest
          and .qualification_source_revision == $qualification_source_revision
          and .power_control_mode == "manual"
          and .no_mutation_performed == true
          and (.qualified_at | type == "string" and length > 0)
          and (.operator_id | type == "string" and length > 0)
          and (.usb_power_path.source_id | type == "string" and length > 0)
          and (.usb_power_path.cable_id | type == "string" and length > 0)
          and .usb_power_path.cable_type == "intact_power_and_data"
          and .usb_power_path.sole_target_power_source == true
          and .usb_power_path.normal_target_psu_absent == true
          and (.usb_power_path.source_rated_current_milliamps >= 900)
          and (.usb_power_path.source_rating_basis == "manufacturer_label"
            or .usb_power_path.source_rating_basis == "manufacturer_datasheet"
            or .usb_power_path.source_rating_basis == "host_port_specification"
            or .usb_power_path.source_rating_basis == "powered_hub_specification")
          and (.usb_power_path.source_rating_reference | type == "string" and length > 0)
          and .usb_power_path.load_test_completed == true
          and .usb_power_path.load_test_reviewed == true
          and .usb_power_path.rpiboot_enumeration_observed == true
          and .usb_power_path.undervoltage_observed == false
          and .usb_power_path.usb_reset_observed == false
          and .usb_power_path.unexpected_target_disappearance_observed == false
          and .normal_boot_path.provisioning_usb_absent == true
          and .normal_boot_path.normal_psu_sole_power_source == true
          and .normal_boot_path.bootsel_not_asserted == true
          and .normal_boot_path.uart_observed == true
          and .normal_boot_path.uart_capture_digest == $unfused_uart_digest
          and .uart.receive_only == true
          and .uart.common_ground == true
          and .uart.adapter_vcc_disconnected == true
          and .uart.adapter_tx_disconnected == true
          and .uart.target_tx_observed == true
        ' "$record" >/dev/null

      printf 'manual-lane admission: OK: %s\n' "$observed"
    '';
  };
  authorityCredentialAdmission = pkgs.writeShellApplication {
    name = "kaiba-mutation-authority-credential-admission";
    runtimeInputs = with pkgs; [
      coreutils
      diffutils
      findutils
      gnused
      openssl
    ];
    text = ''
      credential_root=${lib.escapeShellArg bridgeCredentialRoot}
      test -d "$credential_root"
      test ! -L "$credential_root"
      test "$(stat -c '%u:%g:%a' "$credential_root")" = 0:0:700

      expected_files="$(printf '%s\n' \
        SHA256SUMS \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt \
        station-client.key | sort)"
      observed_files="$(
        find "$credential_root" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' |
          sort
      )"
      test "$observed_files" = "$expected_files"
      test -z "$(find "$credential_root" -mindepth 1 -maxdepth 1 ! -type f -print -quit)"

      for public_file in \
        SHA256SUMS audit-server-ca.crt control-server-ca.crt station-client.crt; do
        path="$credential_root/$public_file"
        test -f "$path"
        test ! -L "$path"
        test "$(stat -c '%u:%g:%a:%h' "$path")" = 0:0:444:1
      done
      private_key="$credential_root/station-client.key"
      test -f "$private_key"
      test ! -L "$private_key"
      test "$(stat -c '%u:%g:%a:%h' "$private_key")" = 0:0:400:1

      ${credentialPacketValidator}/bin/kaiba-validate-mutation-credential-packet \
        validate-manifest "$credential_root"
      for certificate in \
        audit-server-ca.crt control-server-ca.crt station-client.crt; do
        openssl x509 -in "$credential_root/$certificate" -outform PEM |
          cmp --silent - "$credential_root/$certificate"
      done
      ${credentialPacketValidator}/bin/kaiba-validate-mutation-credential-packet \
        require-distinct-cas \
        "$credential_root/control-server-ca.crt" \
        "$credential_root/audit-server-ca.crt"

      station_san="$(
        openssl x509 -in "$credential_root/station-client.crt" \
          -noout -ext subjectAltName |
          sed '1d' | tr -d '[:space:]'
      )"
      test "$station_san" = \
        ${lib.escapeShellArg "URI:spiffe://kaiba.network/station/${stationID}/lane/${laneID}"}
      certificate_key="$(
        openssl x509 -in "$credential_root/station-client.crt" -pubkey -noout |
          openssl pkey -pubin -outform DER 2>/dev/null |
          sha256sum | cut -d ' ' -f 1
      )"
      private_key_digest="$(
        openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null |
          sha256sum | cut -d ' ' -f 1
      )"
      test "$certificate_key" = "$private_key_digest"

      printf 'authority-credential admission: OK: bridge packet is exact and checksum-consistent\n'
    '';
  };
  releaseBinding = pkgs.writeShellApplication {
    name = "kaiba-mutation-release-binding";
    text = ''
      exec ${physicalLaneGuard}/bin/kaiba-provision-lane-guard \
        --print-release-binding-material
    '';
  };
  stationInventory = pkgs.writeShellApplication {
    name = "kaiba-mutation-station-inventory";
    runtimeInputs = with pkgs; [
      coreutils
      systemd
    ];
    text = ''
      printf '%s\n' \
        'STATION_SOURCE_REVISION=${sourceRevision}' \
        'PAYLOAD_SOURCE_REVISION=${payloadSourceRevision}' \
        'RECOVERY_TOOL_SOURCE_REVISION=${sourceRevision}' \
        'STATION_ID=${stationID}' \
        'LANE_ID=${laneID}' \
        'POWER_CONTROL=manual' \
        'RPIBOOT_SYSFS_PATH=${rpibootSysfsPath}' \
        'UART_PATH=${uartPath}' \
        'TARGET_FINGERPRINT=${acceptedTargetFingerprint}' \
        'HARDWARE_QUALIFICATION=${hardwareQualificationDigest}' \
        'UNFUSED_COMPATIBILITY_UART=${unfusedCompatibilityUARTDigest}' \
        'MANUAL_LANE_QUALIFICATION=${manualLaneQualificationDigest}' \
        'QUALIFICATION_SOURCE_REVISION=${manualLaneQualificationSourceRevision}' \
        'CONTROL_ENDPOINT=https://${controlAddress}:${toString controlPort}' \
        'AUDIT_ENDPOINT=https://${auditAddress}:${toString auditPort}'

      systemctl show kaiba-provisioning-lane-guard.service \
        --property=ActiveState \
        --property=SubState \
        --property=UnitFileState \
        --property=ExecStart \
        --no-pager
    '';
  };
  stationLaneWorkflow = pkgs.writeShellApplication {
    name = "kaiba-provision-lane-workflow";
    passthru.kaibaCredentialPacketValidator = credentialPacketValidator;
    runtimeInputs = with pkgs; [
      coreutils
      findutils
      gnused
      openssl
    ];
    text = ''
      if (( $# == 0 )); then
        exec ${laneWorkflowPackage}/bin/kaiba-provision-lane-workflow
      fi

      subcommand=$1
      shift
      case "$subcommand" in
        install-draft)
          exec ${laneWorkflowPackage}/bin/kaiba-provision-lane-workflow \
            "$subcommand" "$@"
          ;;
        apply-approval)
          printf '%s\n' \
            'kaiba-provision-lane-workflow: apply-approval requires the separate approver host and credential' >&2
          exit 2
          ;;
        prepare-draft|propose-approval|propose-next-intent|renew-pending-intent|propose-evidence|renew-ready-campaign|propose-security-applied|prepare-reconciliation|propose-reconciliation|release-terminal-claim|apply-intent|apply-evidence|apply-security-applied|apply-reconciliation)
          ;;
        *)
          exec ${laneWorkflowPackage}/bin/kaiba-provision-lane-workflow \
            "$subcommand" "$@"
          ;;
      esac

      credential_root=${lib.escapeShellArg operatorCredentialRoot}
      test -d "$credential_root"
      test ! -L "$credential_root"
      test "$(stat -c '%u:%g:%a' "$credential_root")" = 1000:1000:700
      credential_files=(
        "$credential_root/SHA256SUMS"
        "$credential_root/station-client.crt"
        "$credential_root/station-client.key"
        "$credential_root/control-server-ca.crt"
        "$credential_root/audit-server-ca.crt"
      )
      for credential_file in "''${credential_files[@]}"; do
        test -f "$credential_file"
        test ! -L "$credential_file"
        test "$(stat -c '%u:%g:%a:%h' "$credential_file")" = 1000:1000:400:1
      done
      expected_files="$(printf '%s\n' \
        SHA256SUMS \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt \
        station-client.key | sort)"
      observed_files="$(
        find "$credential_root" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' |
          sort
      )"
      test "$observed_files" = "$expected_files"
      test -z "$(find "$credential_root" -mindepth 1 -maxdepth 1 ! -type f -print -quit)"
      ${credentialPacketValidator}/bin/kaiba-validate-mutation-credential-packet \
        validate-manifest "$credential_root"
      station_san="$(
        openssl x509 -in "$credential_root/station-client.crt" \
          -noout -ext subjectAltName |
          sed '1d' | tr -d '[:space:]'
      )"
      test "$station_san" = \
        ${lib.escapeShellArg "URI:spiffe://kaiba.network/station/${stationID}/lane/${laneID}"}
      certificate_key="$(
        openssl x509 -in "$credential_root/station-client.crt" -pubkey -noout |
          openssl pkey -pubin -outform DER 2>/dev/null |
          sha256sum | cut -d ' ' -f 1
      )"
      private_key_digest="$(
        openssl pkey -in "$credential_root/station-client.key" \
          -pubout -outform DER 2>/dev/null |
          sha256sum | cut -d ' ' -f 1
      )"
      test "$certificate_key" = "$private_key_digest"

      station_control=(
        --control-url ${lib.escapeShellArg "https://${controlAddress}:${toString controlPort}"}
        --tls-cert "$credential_root/station-client.crt"
        --tls-key "$credential_root/station-client.key"
        --control-server-ca "$credential_root/control-server-ca.crt"
      )
      station_authorities=(
        "''${station_control[@]}"
        --audit-url ${lib.escapeShellArg "https://${auditAddress}:${toString auditPort}"}
        --audit-server-ca "$credential_root/audit-server-ca.crt"
      )

      case "$subcommand" in
        apply-intent|apply-evidence|apply-security-applied|apply-reconciliation)
          exec ${laneWorkflowPackage}/bin/kaiba-provision-lane-workflow \
            "$subcommand" "$@" "''${station_authorities[@]}"
          ;;
        *)
          exec ${laneWorkflowPackage}/bin/kaiba-provision-lane-workflow \
            "$subcommand" "$@" "''${station_control[@]}"
          ;;
      esac
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
      assertion = physicalLaneGuard.system == pkgs.stdenv.hostPlatform.system;
      message = "the mutation station requires a native physical lane-guard package";
    }
    {
      assertion = physicalLaneGuard ? kaibaPhysicalLaneGuard;
      message = "the mutation station requires a factory-produced physical lane guard";
    }
    {
      assertion = sourceRevisionIsCanonical;
      message = "the mutation station requires a canonical 40- or 64-hex source revision";
    }
    {
      assertion = manualLaneQualificationDigestIsCanonical;
      message = "the mutation station requires a canonical reviewed manual-lane qualification digest";
    }
    {
      assertion = acceptedTargetFingerprintIsCanonical;
      message = "the mutation station requires a canonical accepted target fingerprint";
    }
    {
      assertion = hardwareQualificationDigestIsCanonical;
      message = "the mutation station requires a canonical accepted hardware-qualification digest";
    }
    {
      assertion =
        builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" manualLaneQualificationSourceRevision != null;
      message = "the mutation station requires the canonical source revision used for manual-lane qualification";
    }
    {
      assertion = unfusedCompatibilityUARTDigestIsCanonical;
      message = "the mutation station requires the canonical accepted unfused compatibility UART digest";
    }
  ];

  networking = {
    hostName = "kaiba-rpi5-mutation-station";
    firewall.enable = true;
    useDHCP = false;
    useNetworkd = true;
  };

  hardware = {
    enableAllHardware = lib.mkForce false;
    # Manual power mode must not acquire a GPIO line or retain the qualification
    # image's relay-facing udev rule.
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

  image.baseName = lib.mkForce "kaiba-rpi5-development-mutation-station";
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
        extraGroups = [ "wheel" ];
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

    kaiba-provisioning-authority-bridge = {
      enable = true;
      package = authorityBridgePackage;
      inherit
        auditAddress
        auditPort
        controlAddress
        controlPort
        ;
      tlsCertificateFile = "${bridgeCredentialRoot}/station-client.crt";
      tlsPrivateKeyFile = "${bridgeCredentialRoot}/station-client.key";
      controlServerCAFile = "${bridgeCredentialRoot}/control-server-ca.crt";
      auditServerCAFile = "${bridgeCredentialRoot}/audit-server-ca.crt";
    };

    kaiba-provisioning-lane-guard = {
      enable = true;
      package = physicalLaneGuard;
      operatorPackage = laneOperatorPackage;
      operators = [ operatorName ];
      inherit
        laneID
        rpibootSysfsPath
        stationID
        uartPath
        ;
      powerControl = "manual";
      enableMutations = true;
      mode = "execute";
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
      "d ${credentialRoot} 0700 root root - -"
      "d ${bridgeCredentialRoot} 0700 root root - -"
      "d /home/${operatorName}/.config 0700 ${operatorName} ${operatorName} - -"
      "d /home/${operatorName}/.config/kaiba-provisioning 0700 ${operatorName} ${operatorName} - -"
      "d ${operatorCredentialRoot} 0700 ${operatorName} ${operatorName} - -"
      "d ${evidenceRoot} 0700 root root - -"
    ];

    # Credentials are provisioned after first boot and are intentionally not
    # copied into the image or Nix store. Starting the lane guard explicitly
    # pulls in this bridge after those credentials have been installed.
    services.kaiba-provisioning-authority-bridge.wantedBy = lib.mkForce [ ];
    services.kaiba-provisioning-authority-credential-admission = {
      description = "Admit the authenticated development authority bridge credential packet";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe authorityCredentialAdmission;
        UMask = "0077";
        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
      };
    };
    services.kaiba-provisioning-authority-bridge = {
      after = [ "kaiba-provisioning-authority-credential-admission.service" ];
      requires = [ "kaiba-provisioning-authority-credential-admission.service" ];
    };
    services.kaiba-provisioning-manual-lane-admission = {
      description = "Admit the reviewed development-only manual power lane";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe manualLaneAdmission;
        UMask = "0077";
        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
      };
    };
    services.kaiba-provisioning-lane-guard = {
      after = [ "kaiba-provisioning-manual-lane-admission.service" ];
      requires = [ "kaiba-provisioning-manual-lane-admission.service" ];
    };
    # The SD module's registration unit exists for later nixos-rebuild use.
    # This fixed mutation appliance has neither a Nix daemon nor switching.
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
        stationLaneWorkflow
        less
        openssh
        releaseBinding
        stationInventory
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
        Kaiba Raspberry Pi 5 development mutation station
        Target mutation is inactive until an approved draft is installed and
        kaiba-provisioning-lane-guard.service is explicitly started.
        Inventory: kaiba-mutation-station-inventory
        Release binding: kaiba-mutation-release-binding

      '';
      "kaiba-provisioning/source-revision".text = "${sourceRevision}\n";
      "kaiba-provisioning/payload-source-revision".text = "${payloadSourceRevision}\n";
      "kaiba-provisioning/recovery-tool-source-revision".text = "${sourceRevision}\n";
      "kaiba-provisioning/manual-lane-qualification-digest".text = "${manualLaneQualificationDigest}\n";
      "kaiba-provisioning/manual-lane-qualification-source-revision".text =
        "${manualLaneQualificationSourceRevision}\n";
      "kaiba-provisioning/hardware-qualification-digest".text = "${hardwareQualificationDigest}\n";
      "kaiba-provisioning/accepted-target-fingerprint".text = "${acceptedTargetFingerprint}\n";
      "kaiba-provisioning/unfused-compatibility-uart-digest".text = "${unfusedCompatibilityUARTDigest}\n";
    };
  };

  security = {
    sudo = {
      enable = true;
      wheelNeedsPassword = false;
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
