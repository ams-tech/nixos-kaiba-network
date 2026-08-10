{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  inherit (lib)
    concatMap
    getExe'
    hasPrefix
    mkEnableOption
    mkIf
    mkOption
    optionals
    types
    unique
    ;

  cfg = config.kaiba.deviceAgent;
  executable =
    if cfg.package == null then "${pkgs.coreutils}/bin/false" else getExe' cfg.package "kaiba-agent";

  args = [
    executable
    "--endpoint"
    cfg.endpoint
    "--client-cert"
    (toString cfg.credentials.clientCertificate)
    "--client-key"
    (toString cfg.credentials.clientKey)
    "--ca"
    (toString cfg.credentials.serverCA)
    "--idempotency-state"
    cfg.idempotencyStateFile
    "--renew-interval"
    cfg.renewInterval
    "--request-timeout"
    cfg.requestTimeout
  ]
  ++ concatMap (address: [
    "--address"
    address
  ]) cfg.addresses
  ++ concatMap (interface: [
    "--interface"
    interface
  ]) cfg.interfaces
  ++ optionals cfg.once [ "--once" ]
  ++ cfg.extraArgs;

  absoluteOrNull = value: value == null || hasPrefix "/" (toString value);
in
{
  options.kaiba.deviceAgent = {
    enable = mkEnableOption "the Kaiba device endpoint-registration agent";

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      example = lib.literalExpression "pkgs.kaiba-agent";
      description = "Package containing bin/kaiba-agent. Required when enabled.";
    };

    endpoint = mkOption {
      type = types.str;
      default = "";
      example = "https://updates.kaiba.network:8443";
      description = "HTTPS URL of the update controller; devices do not receive DNS-origin details.";
    };

    addresses = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "203.0.113.42"
        "2001:db8::42"
      ];
      description = "Static addresses submitted as the complete A/AAAA set.";
    };

    interfaces = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "eth0" ];
      description = "Interfaces from which the agent discovers submit-worthy addresses.";
    };

    credentials = {
      clientCertificate = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-agent/client.crt";
        description = "Absolute runtime path to the device mTLS certificate.";
      };
      clientKey = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-agent/client.key";
        description = "Absolute runtime path to the device mTLS private key.";
      };
      serverCA = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-agent/controller-ca.crt";
        description = "Absolute runtime path to the CA used to verify the update controller.";
      };
      provisioningUnits = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Units which must provision the runtime credentials before the agent starts.";
      };
    };

    stateDirectory = mkOption {
      type = types.strMatching "[a-zA-Z0-9][a-zA-Z0-9_.-]*";
      default = "kaiba-agent";
      description = "systemd StateDirectory used for durable idempotency state.";
    };

    idempotencyStateFile = mkOption {
      type = types.str;
      default = "/var/lib/${cfg.stateDirectory}/idempotency.json";
      defaultText = lib.literalExpression ''"/var/lib/''${config.kaiba.deviceAgent.stateDirectory}/idempotency.json"'';
      description = "Durable state file used to avoid replaying requests under new keys.";
    };

    renewInterval = mkOption {
      type = types.str;
      default = "6h";
      description = "Base interval between lease renewals; the agent applies jitter.";
    };

    requestTimeout = mkOption {
      type = types.str;
      default = "15s";
      description = "Timeout for a registration request.";
    };

    once = mkOption {
      type = types.bool;
      default = false;
      description = "Submit one update and exit, primarily for deterministic tests.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Additional kaiba-agent arguments for forward-compatible experimentation.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "kaiba.deviceAgent.package is required when the agent is enabled.";
      }
      {
        assertion = hasPrefix "https://" cfg.endpoint;
        message = "kaiba.deviceAgent.endpoint must be a non-empty HTTPS URL.";
      }
      {
        assertion = cfg.addresses != [ ] || cfg.interfaces != [ ];
        message = "The device agent requires at least one static address or discovery interface.";
      }
      {
        assertion =
          cfg.credentials.clientCertificate != null
          && cfg.credentials.clientKey != null
          && cfg.credentials.serverCA != null;
        message = "The device agent requires clientCertificate, clientKey, and serverCA runtime paths.";
      }
      {
        assertion =
          absoluteOrNull cfg.credentials.clientCertificate
          && absoluteOrNull cfg.credentials.clientKey
          && absoluteOrNull cfg.credentials.serverCA;
        message = "Device-agent credential paths must be absolute.";
      }
      {
        assertion =
          builtins.length (unique [
            cfg.credentials.clientCertificate
            cfg.credentials.clientKey
            cfg.credentials.serverCA
          ]) == 3;
        message = "Device certificate, private key, and server CA files must be distinct.";
      }
      {
        assertion = hasPrefix "/var/lib/${cfg.stateDirectory}/" cfg.idempotencyStateFile;
        message = "idempotencyStateFile must remain inside the configured StateDirectory.";
      }
    ];

    users.groups.kaiba-agent = { };
    users.users.kaiba-agent = {
      isSystemUser = true;
      group = "kaiba-agent";
      description = "Kaiba device registration agent";
    };

    systemd.services.kaiba-agent = {
      description = "Kaiba endpoint registration agent";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ] ++ cfg.credentials.provisioningUnits;
      after = [ "network-online.target" ] ++ cfg.credentials.provisioningUnits;
      requires = cfg.credentials.provisioningUnits;
      serviceConfig = {
        Type = if cfg.once then "oneshot" else "simple";
        ExecStart = utils.escapeSystemdExecArgs args;
        User = "kaiba-agent";
        Group = "kaiba-agent";
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        Restart = if cfg.once then "no" else "on-failure";
        RestartSec = "5s";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        # Go's interface discovery uses routing netlink on Linux.
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
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
  };
}
