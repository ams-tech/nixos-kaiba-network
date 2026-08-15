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
    types
    ;

  cfg = config.services.kaiba-provisioning-station-demo;
  defaultPackage = (import ../packages.nix { inherit pkgs lib; }).stationDemo;
  loopbackAddresses = [
    "127.0.0.1"
    "::1"
  ];
  listenEndpoint =
    if cfg.listenAddress == "::1" then
      "[::1]:${toString cfg.port}"
    else
      "${cfg.listenAddress}:${toString cfg.port}";
  args = [
    (getExe' cfg.package "kaiba-provision-station-demo")
    "--listen"
    listenEndpoint
    "--scenario"
    cfg.scenario
  ];
in
{
  options.services.kaiba-provisioning-station-demo = {
    enable = mkEnableOption "the local Kaiba provisioning-station interface demo";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "the kaiba-provision-station-demo package from the provisioning source tree";
      example = lib.literalExpression "inputs.kaiba-provisioning.packages.\${pkgs.system}.kaiba-provision-station-demo";
      description = "Package containing bin/kaiba-provision-station-demo.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      example = "::1";
      description = ''
        Loopback address on which the demo HTTP server listens. Non-loopback
        listeners are rejected because the demo has no authentication layer.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "Loopback TCP port on which the demo HTTP server listens.";
    };

    scenario = mkOption {
      type = types.enum [
        "happy-path"
        "class-mismatch"
        "baseline-failure"
        "multiple-targets"
        "acquisition-error"
        "target-replaced"
        "mutation-safety-violation"
        "boot-failure"
        "preparation-failure"
        "approval-failure"
        "trust-failure"
        "commit-uncertain"
        "commit-readback-mismatch"
        "signed-boot-failure"
        "owned-readback-mismatch"
        "recovery-failure"
        "negative-boot-failure"
        "root-integrity-failure"
        "rollback-failure"
        "finalization-failure"
        "final-retest-failure"
        "audit-failure"
        "deferred-baseline-failure"
        "precommit-target-replaced"
        "post-recovery-readback-mismatch"
      ];
      default = "happy-path";
      example = "commit-readback-mismatch";
      description = ''
        Named deterministic secure-boot ceremony scenario rendered by the
        simulation interface. Scenarios have no hardware or mutation authority.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.elem cfg.listenAddress loopbackAddresses;
        message = ''
          services.kaiba-provisioning-station-demo.listenAddress must be the
          IPv4 or IPv6 loopback address; this unauthenticated demo must not be
          exposed to a network.
        '';
      }
    ];

    environment.systemPackages = [ cfg.package ];

    systemd.services.kaiba-provisioning-station-demo = {
      description = "Kaiba local provisioning-station interface demo";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = utils.escapeSystemdExecArgs args;
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";

        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        IPAddressAllow = "localhost";
        IPAddressDeny = "any";
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
      };
    };
  };
}
