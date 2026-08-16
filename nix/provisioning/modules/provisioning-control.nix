{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  inherit (lib)
    getExe'
    mkEnableOption
    mkIf
    mkOption
    optionalAttrs
    optionalString
    optionals
    types
    ;

  cfg = config.services.kaiba-provisioning-control;
  defaultPackage = (import ../packages.nix { inherit pkgs lib; }).control;
  loopbackAddresses = [
    "127.0.0.1"
    "::1"
  ];
  ipv4Octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  looksLikeConcreteIP =
    (
      builtins.match "${ipv4Octet}(\\.${ipv4Octet}){3}" cfg.listenAddress != null
      || builtins.match "[0-9A-Fa-f]*:[0-9A-Fa-f:]+" cfg.listenAddress != null
    )
    && !builtins.elem cfg.listenAddress [
      "0.0.0.0"
      "::"
    ];
  tlsCredentials = [
    cfg.tlsCertificateFile
    cfg.tlsPrivateKeyFile
    cfg.clientCAFile
  ];
  tlsCredentialsConfigured = builtins.all (path: path != null) tlsCredentials;
  tlsCredentialsAbsent = builtins.all (path: path == null) tlsCredentials;
  tlsCredentialPathsSafe = builtins.all (
    path: path != null && lib.hasPrefix "/" path && !lib.hasPrefix "${builtins.storeDir}/" path
  ) tlsCredentials;
  listenEndpoint =
    if cfg.listenAddress == "::1" then
      "[::1]:${toString cfg.port}"
    else
      "${cfg.listenAddress}:${toString cfg.port}";
  statePath = "/var/lib/${cfg.stateDirectory}/${cfg.stateFile}";
  args = [
    (getExe' cfg.package "kaiba-provision-control")
    "--listen"
    listenEndpoint
    "--state"
    statePath
  ];
  tlsArgs = optionalString cfg.enableTLS ''"--tls-cert" "%d/server-cert" "--tls-key" "%d/server-key" "--client-ca" "%d/client-ca"'';
in
{
  options.services.kaiba-provisioning-control = {
    enable = mkEnableOption "the local Kaiba provisioning coordinator reference service";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "the kaiba-provision-control package from the provisioning source tree";
      example = lib.literalExpression "inputs.kaiba-provisioning.packages.\${pkgs.system}.kaiba-provision-control";
      description = "Package containing bin/kaiba-provision-control.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      example = "::1";
      description = ''
        Concrete IP address on which the reference coordinator listens. The
        default plaintext mode requires loopback; non-loopback use requires
        mutual TLS.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 8091;
      description = "TCP port for the provisioning coordinator.";
    };

    enableTLS = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable TLS 1.3 mutual authentication. Plain HTTP remains available
        only on an explicit loopback address.
      '';
    };

    tlsCertificateFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-control-server.crt";
      description = ''
        Absolute runtime path to the server certificate PEM. systemd reads it
        with LoadCredential; the file is not imported into the Nix store.
      '';
    };

    tlsPrivateKeyFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-control-server.key";
      description = ''
        Absolute runtime path to the server private-key PEM, supplied only
        through systemd LoadCredential.
      '';
    };

    clientCAFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-station-client-ca.crt";
      description = ''
        Absolute runtime path to the exclusive client CA PEM, supplied only
        through systemd LoadCredential.
      '';
    };

    stateDirectory = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]{0,63}";
      default = "kaiba-provision-control";
      description = ''
        Name of the private systemd StateDirectory below /var/lib. systemd
        creates it with mode 0700 and preserves it across service restarts.
      '';
    };

    stateFile = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]{0,127}";
      default = "control.json";
      description = "Coordinator snapshot filename within stateDirectory.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion =
          if cfg.enableTLS then looksLikeConcreteIP else builtins.elem cfg.listenAddress loopbackAddresses;
        message = ''
          services.kaiba-provisioning-control.listenAddress must be an IPv4 or
          IPv6 loopback address for plaintext, or a concrete non-wildcard IP
          literal when mutual TLS is enabled. Hostnames and wildcard listeners
          are rejected.
        '';
      }
      {
        assertion =
          if cfg.enableTLS then tlsCredentialsConfigured && tlsCredentialPathsSafe else tlsCredentialsAbsent;
        message = ''
          services.kaiba-provisioning-control TLS requires absolute, non-store
          tlsCertificateFile, tlsPrivateKeyFile, and clientCAFile paths; set
          all three with enableTLS or leave all three unset for loopback HTTP.
        '';
      }
    ];

    environment.systemPackages = [ cfg.package ];

    systemd.services.kaiba-provisioning-control = {
      description = "Kaiba provisioning coordinator reference service";
      wantedBy = [ "multi-user.target" ];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = (utils.escapeSystemdExecArgs args) + tlsArgs;
        DynamicUser = true;
        LoadCredential = optionals cfg.enableTLS [
          "server-cert:${cfg.tlsCertificateFile}"
          "server-key:${cfg.tlsPrivateKeyFile}"
          "client-ca:${cfg.clientCAFile}"
        ];
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";

        AmbientCapabilities = "";
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
        RemoveIPC = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
      }
      // optionalAttrs (!cfg.enableTLS) {
        IPAddressAllow = "localhost";
        IPAddressDeny = "any";
      };
    };
  };
}
