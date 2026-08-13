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
    hasInfix
    hasPrefix
    mkEnableOption
    mkIf
    mkOption
    optionals
    types
    unique
    ;

  cfg = config.kaiba.updateController;
  statePath = "/var/lib/${cfg.stateDirectory}";
  databaseDirectory = builtins.dirOf cfg.databasePath;
  tmpfilesUnit = "systemd-tmpfiles-setup.service";
  controllerCredentialPaths = map toString (
    builtins.filter (path: path != null) [
      cfg.credentials.serverCertificate
      cfg.credentials.serverKey
      cfg.credentials.clientCA
    ]
  );
  publisherCredentialPaths = map toString (
    builtins.filter (path: path != null) [ cfg.credentials.publisherTSIGSecret ]
  );
  controllerExecutable =
    if cfg.controller.package == null then
      "${pkgs.coreutils}/bin/false"
    else
      getExe' cfg.controller.package "kaiba-controller";
  publisherExecutable =
    if cfg.publisher.package == null then
      "${pkgs.coreutils}/bin/false"
    else
      getExe' cfg.publisher.package "kaiba-publisher";

  listenEndpoint =
    if hasInfix ":" cfg.controller.listenAddress then
      "[${cfg.controller.listenAddress}]:${toString cfg.controller.port}"
    else
      "${cfg.controller.listenAddress}:${toString cfg.controller.port}";

  controllerArgs = [
    controllerExecutable
    "--listen"
    listenEndpoint
    "--db"
    cfg.databasePath
    "--tls-cert"
    (toString cfg.credentials.serverCertificate)
    "--tls-key"
    (toString cfg.credentials.serverKey)
    "--client-ca"
    (toString cfg.credentials.clientCA)
    "--zone"
    cfg.zone
    "--lease-duration"
    cfg.leaseDuration
    "--renew-after"
    cfg.renewAfter
  ]
  ++ optionals cfg.controller.allowNonGlobalAddresses [ "--allow-non-global-addresses" ]
  ++ cfg.controller.extraArgs;

  publisherArgs = [
    publisherExecutable
    "--db"
    cfg.databasePath
    "--dns-server"
    cfg.publisher.dnsServer
    "--zone"
    cfg.zone
    "--tsig-name"
    cfg.publisher.tsigName
    "--tsig-algorithm"
    cfg.publisher.tsigAlgorithm
    "--tsig-secret-file"
    (toString cfg.credentials.publisherTSIGSecret)
    "--ttl"
    (toString cfg.publisher.ttl)
    "--poll-interval"
    cfg.publisher.pollInterval
  ]
  ++ concatMap (server: [
    "--observe-server"
    server
  ]) cfg.publisher.observeServers
  ++ optionals cfg.publisher.once [ "--once" ]
  ++ cfg.publisher.extraArgs;

  absoluteOrNull = value: value == null || hasPrefix "/" (toString value);

  sandbox = {
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
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
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
in
{
  options.kaiba.updateController = {
    enable = mkEnableOption "the Kaiba mTLS update controller and single DNS publisher";

    zone = mkOption {
      type = types.str;
      default = "kaiba.network.";
      description = "Server-controlled zone used to derive device FQDNs.";
    };

    databasePath = mkOption {
      type = types.str;
      default = "/var/lib/${cfg.stateDirectory}/desired-state.db";
      defaultText = lib.literalExpression ''"/var/lib/''${config.kaiba.updateController.stateDirectory}/desired-state.db"'';
      description = "SQLite desired-state database, including publication status.";
    };

    stateDirectory = mkOption {
      type = types.strMatching "[a-zA-Z0-9][a-zA-Z0-9_.-]*";
      default = "kaiba-controller";
      description = ''
        Shared persistent directory for SQLite desired state. The module
        creates it with a setgid state-sharing group so the database, WAL, and
        SHM files remain accessible to both otherwise-separated services.
      '';
    };

    leaseDuration = mkOption {
      type = types.str;
      default = "24h";
      description = "Lifetime of a device endpoint lease.";
    };

    renewAfter = mkOption {
      type = types.str;
      default = "6h";
      description = "Renewal guidance returned to devices.";
    };

    credentials = {
      serverCertificate = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-controller/server.crt";
        description = "Absolute runtime path to the controller TLS certificate.";
      };
      serverKey = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-controller/server.key";
        description = "Absolute runtime path to the controller TLS private key.";
      };
      clientCA = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-controller/device-ca.crt";
        description = "Absolute runtime path to the CA used for device authentication.";
      };
      publisherTSIGSecret = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/kaiba-publisher/update.secret";
        description = ''
          Absolute runtime path to the raw base64 TSIG secret used by the
          publisher. This is distinct from Knot's runtime-format key include.
        '';
      };
      provisioningUnits = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Units which provision runtime credentials before either service
          starts. Controller TLS material should be readable only by the
          kaiba-controller identity and the TSIG secret only by
          kaiba-publisher; credentials must never be owned by kaiba-state.
        '';
      };
    };

    controller = {
      package = mkOption {
        type = types.nullOr types.package;
        default = null;
        example = lib.literalExpression "pkgs.kaiba-controller";
        description = "Package containing bin/kaiba-controller. Required when enabled.";
      };
      listenAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "IPv4 or IPv6 address on which the mTLS API listens.";
      };
      port = mkOption {
        type = types.port;
        default = 8443;
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Whether to open the controller TCP port in the host firewall.";
      };
      allowNonGlobalAddresses = mkOption {
        type = types.bool;
        default = false;
        description = "Allow documentation/private addresses; intended for isolated VM tests only.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
    };

    publisher = {
      package = mkOption {
        type = types.nullOr types.package;
        default = null;
        example = lib.literalExpression "pkgs.kaiba-publisher";
        description = "Package containing bin/kaiba-publisher. Required when enabled.";
      };
      dnsServer = mkOption {
        type = types.str;
        default = "";
        example = "192.0.2.53:53";
        description = "P0 update endpoint. This value is never exposed to a device.";
      };
      tsigName = mkOption {
        type = types.str;
        default = "kaiba-publisher";
      };
      tsigAlgorithm = mkOption {
        type = types.enum [
          "hmac-sha256"
          "hmac-sha384"
          "hmac-sha512"
        ];
        default = "hmac-sha256";
      };
      ttl = mkOption {
        type = types.ints.positive;
        default = 300;
        description = "Server-controlled TTL for device A and AAAA records.";
      };
      pollInterval = mkOption {
        type = types.str;
        default = "2s";
      };
      observeServers = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "198.51.100.53:53"
          "198.51.100.54:53"
        ];
        description = "Public-authority endpoints polled to establish publicly-observed status.";
      };
      once = mkOption {
        type = types.bool;
        default = false;
        description = "Run one reconciliation pass and exit, primarily for tests.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.controller.package != null && cfg.publisher.package != null;
        message = "Both controller.package and publisher.package are required when enabled.";
      }
      {
        assertion = cfg.publisher.dnsServer != "";
        message = "kaiba.updateController.publisher.dnsServer must identify P0.";
      }
      {
        assertion =
          builtins.length cfg.publisher.observeServers >= 2
          && builtins.all (server: server != "") cfg.publisher.observeServers
          &&
            builtins.length cfg.publisher.observeServers
            == builtins.length (unique cfg.publisher.observeServers);
        message = ''
          kaiba.updateController.publisher.observeServers must contain at least
          two distinct public-authority endpoints. A generation is only
          publicly-observed after every configured endpoint agrees.
        '';
      }
      {
        assertion = cfg.zone != "";
        message = "kaiba.updateController.zone must not be empty.";
      }
      {
        assertion =
          cfg.credentials.serverCertificate != null
          && cfg.credentials.serverKey != null
          && cfg.credentials.clientCA != null
          && cfg.credentials.publisherTSIGSecret != null;
        message = "Controller mTLS credentials and publisherTSIGSecret runtime paths are required.";
      }
      {
        assertion =
          absoluteOrNull cfg.credentials.serverCertificate
          && absoluteOrNull cfg.credentials.serverKey
          && absoluteOrNull cfg.credentials.clientCA
          && absoluteOrNull cfg.credentials.publisherTSIGSecret;
        message = "Controller and publisher credential paths must be absolute.";
      }
      {
        assertion =
          builtins.length (unique [
            cfg.credentials.serverCertificate
            cfg.credentials.serverKey
            cfg.credentials.clientCA
            cfg.credentials.publisherTSIGSecret
          ]) == 4;
        message = "TLS certificate, TLS key, client CA, and publisher TSIG files must be distinct.";
      }
      {
        assertion = hasPrefix "/var/lib/${cfg.stateDirectory}/" cfg.databasePath;
        message = "databasePath must remain inside the configured StateDirectory.";
      }
    ];

    # The controller owns the Internet-facing mTLS socket while the publisher
    # owns the DNS mutation credential. They deliberately use different UIDs
    # and primary groups. Only the setgid desired-state directory is writable
    # by their shared supplementary group.
    users.groups = {
      kaiba-controller = { };
      kaiba-publisher = { };
      kaiba-state = { };
    };
    users.users.kaiba-controller = {
      isSystemUser = true;
      group = "kaiba-controller";
      description = "Kaiba desired-state controller";
    };
    users.users.kaiba-publisher = {
      isSystemUser = true;
      group = "kaiba-publisher";
      description = "Kaiba DNS publisher";
    };

    # SQLite creates a new main database with mode 0644 before applying the
    # process umask. An umask can remove permissions but cannot add group
    # write, so merely using a setgid directory would leave the publisher with
    # a read-only database. Pre-creating (and repairing) the main file as 0660
    # also makes SQLite derive 0660 for new WAL and SHM sidecars. The z rules
    # repair sidecars left by an older configuration without creating them.
    systemd.tmpfiles.rules = [
      "d ${statePath} 2770 kaiba-controller kaiba-state - -"
    ]
    ++ optionals (databaseDirectory != statePath) [
      "d ${databaseDirectory} 2770 kaiba-controller kaiba-state - -"
    ]
    ++ [
      "f ${cfg.databasePath} 0660 kaiba-controller kaiba-state - -"
      "z ${cfg.databasePath}-wal 0660 kaiba-controller kaiba-state - -"
      "z ${cfg.databasePath}-shm 0660 kaiba-controller kaiba-state - -"
    ];

    networking.firewall.allowedTCPPorts = optionals cfg.controller.openFirewall [ cfg.controller.port ];

    systemd.services = {
      kaiba-controller = {
        description = "Kaiba mTLS endpoint update controller";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ] ++ cfg.credentials.provisioningUnits;
        after = [
          tmpfilesUnit
          "network-online.target"
        ]
        ++ cfg.credentials.provisioningUnits;
        requires = [ tmpfilesUnit ] ++ cfg.credentials.provisioningUnits;
        serviceConfig = sandbox // {
          Type = "simple";
          ExecStart = utils.escapeSystemdExecArgs controllerArgs;
          User = "kaiba-controller";
          Group = "kaiba-controller";
          SupplementaryGroups = [ "kaiba-state" ];
          ReadWritePaths = [ statePath ];
          InaccessiblePaths = publisherCredentialPaths;
          UMask = "0007";
          Restart = "on-failure";
          RestartSec = "3s";
        };
      };

      kaiba-publisher = {
        description = "Kaiba single-writer DNS reconciler";
        wantedBy = [ "multi-user.target" ];
        wants = [
          "network-online.target"
          "kaiba-controller.service"
        ]
        ++ cfg.credentials.provisioningUnits;
        after = [
          tmpfilesUnit
          "network-online.target"
          "kaiba-controller.service"
        ]
        ++ cfg.credentials.provisioningUnits;
        requires = [ tmpfilesUnit ] ++ cfg.credentials.provisioningUnits;
        serviceConfig = sandbox // {
          Type = if cfg.publisher.once then "oneshot" else "simple";
          ExecStart = utils.escapeSystemdExecArgs publisherArgs;
          User = "kaiba-publisher";
          Group = "kaiba-publisher";
          SupplementaryGroups = [ "kaiba-state" ];
          ReadWritePaths = [ statePath ];
          InaccessiblePaths = controllerCredentialPaths;
          UMask = "0007";
          Restart = if cfg.publisher.once then "no" else "on-failure";
          RestartSec = "3s";
        };
      };
    };
  };
}
