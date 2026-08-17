{
  config,
  lib,
  utils,
  ...
}:

let
  inherit (lib)
    getExe'
    hasPrefix
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    optional
    types
    ;

  cfg = config.services.kaiba-provisioning-lane-guard;
  stateDirectory = "kaiba-provision-lane-guard";
  stateRoot = "/var/lib/${stateDirectory}";
  mutablePaths = [
    cfg.journalPath
    cfg.planPath
    cfg.requestPath
  ];

  isCleanStatePath =
    path:
    let
      components = lib.drop 1 (lib.splitString "/" path);
    in
    builtins.match "${stateRoot}/[A-Za-z0-9][A-Za-z0-9._/-]*" path != null
    && builtins.all (component: component != "" && component != "." && component != "..") components
    && !hasPrefix "${builtins.storeDir}/" path;

  args =
    if cfg.package == null then
      [ ]
    else
      [
        (getExe' cfg.package "kaiba-provision-lane-guard")
        "--station-id"
        cfg.stationID
        "--lane-id"
        cfg.laneID
        "--rpiboot-sysfs"
        cfg.rpibootSysfsPath
        "--uart"
        cfg.uartPath
        "--gpio-chip"
        cfg.gpioChip
        "--gpio-offset"
        (toString cfg.gpioOffset)
        "--journal"
        cfg.journalPath
        "--plan"
        cfg.planPath
        "--request"
        cfg.requestPath
        "--mode"
        cfg.mode
      ]
      ++ optional cfg.gpioActiveLow "--gpio-active-low"
      ++ optional cfg.enableMutations "--enable-mutations";
in
{
  options.services.kaiba-provisioning-lane-guard = {
    enable = mkEnableOption "the one-shot physical Kaiba Raspberry Pi 5 lane guard";

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      example = lib.literalExpression ''
        inputs.kaiba-provisioning.lib.mkRpi5PhysicalLaneGuard {
          system = pkgs.system;
          # Supply the six immutable RPIBOOT bundles, release/build bindings,
          # and three expected target digests.
        }
      '';
      description = ''
        Explicit immutable package containing bin/kaiba-provision-lane-guard.
        Its linker-fixed rpiboot, gpioset, bundle, signed-release, build, and
        expected-target digest inputs must describe this station. There is
        deliberately no inferred or source-tree default.
      '';
    };

    enableMutations = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Explicitly pass --enable-mutations to the guard. The safe default only
        validates the fixed lane configuration and cannot touch hardware.
      '';
    };

    stationID = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}";
      default = "development-station";
      description = "Fixed station identity compiled into this unit invocation.";
    };

    laneID = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}";
      default = "lane-1";
      description = "Fixed physical lane identity compiled into this unit invocation.";
    };

    rpibootSysfsPath = mkOption {
      type = types.strMatching "/sys/bus/usb/devices/[A-Za-z0-9][A-Za-z0-9._:-]*";
      default = "/sys/bus/usb/devices/1-1";
      description = "Exact sysfs child for the lane's sole BCM2712 RPIBOOT target.";
    };

    uartPath = mkOption {
      type = types.strMatching "/dev/serial/by-id/[A-Za-z0-9][A-Za-z0-9._:+-]*";
      default = "/dev/serial/by-id/kaiba-target-uart";
      description = "Exact persistent by-id symlink for the lane's target UART.";
    };

    gpioChip = mkOption {
      type = types.strMatching "/dev/gpiochip[0-9]+";
      default = "/dev/gpiochip0";
      description = "Exact GPIO character device controlling the qualified normally-off relay.";
    };

    gpioOffset = mkOption {
      type = types.ints.u32;
      default = 0;
      description = "Fixed GPIO line offset controlling lane power.";
    };

    gpioActiveLow = mkOption {
      type = types.bool;
      default = false;
      description = "Interpret the fixed GPIO relay line as active-low.";
    };

    journalPath = mkOption {
      type = types.str;
      default = "${stateRoot}/journal.json";
      description = ''
        Durable execute-once journal. It must be a clean non-store path below
        ${stateRoot}; systemd creates that root-owned boundary with mode 0700.
      '';
    };

    planPath = mkOption {
      type = types.str;
      default = "${stateRoot}/plan.json";
      description = ''
        Root-installed approved-plan JSON. It must be a clean, regular,
        non-symlink, non-store path below ${stateRoot}.
      '';
    };

    requestPath = mkOption {
      type = types.str;
      default = "${stateRoot}/request.json";
      description = ''
        Root-installed one-shot request JSON. It must be a clean, regular,
        non-symlink, non-store path below ${stateRoot}.
      '';
    };

    mode = mkOption {
      type = types.enum [
        "execute"
        "reconcile"
      ];
      default = "execute";
      description = "Fixed one-shot guard mode.";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      assertions = [
        {
          assertion = cfg.package != null;
          message = ''
            services.kaiba-provisioning-lane-guard.package must be explicitly
            configured with the immutable physical lane-guard package.
          '';
        }
        {
          assertion = cfg.package == null || hasPrefix "${builtins.storeDir}/" (toString cfg.package);
          message = "services.kaiba-provisioning-lane-guard.package must resolve to an immutable Nix store path";
        }
        {
          assertion = cfg.package == null || cfg.package ? kaibaPhysicalLaneGuard;
          message = ''
            services.kaiba-provisioning-lane-guard.package must be produced by
            lib.mkRpi5PhysicalLaneGuard; the generic unlinked lane-guard binary
            has no immutable rpiboot, gpioset, bundle, or digest configuration.
          '';
        }
        {
          assertion = builtins.all isCleanStatePath mutablePaths;
          message = ''
            services.kaiba-provisioning-lane-guard journalPath, planPath, and
            requestPath must be clean absolute non-store paths strictly below
            ${stateRoot} with no empty, dot, or parent components.
          '';
        }
        {
          assertion = builtins.length (lib.unique mutablePaths) == builtins.length mutablePaths;
          message = "lane-guard journal, plan, and request paths must be distinct";
        }
      ];
    }

    (mkIf (cfg.package != null) {
      systemd.services.kaiba-provisioning-lane-guard = {
        description = "One-shot Kaiba physical Raspberry Pi 5 provisioning lane guard";
        serviceConfig = {
          Type = "oneshot";
          User = "root";
          Group = "root";
          ExecStart = utils.escapeSystemdExecArgs args;
          StateDirectory = stateDirectory;
          StateDirectoryMode = "0700";
          WorkingDirectory = stateRoot;
          UMask = "0077";
          TimeoutStartSec = "10min";
          TimeoutStopSec = "5s";
          KillMode = "control-group";

          # GPIO and UART are exact device nodes. USB bus numbers and device
          # numbers are dynamic, so the USB character-device class is the
          # narrowest cgroup rule with which libusb/rpiboot can operate.
          DevicePolicy = "closed";
          DeviceAllow = [
            "${cfg.gpioChip} rw"
            "${cfg.uartPath} r"
            "char-usb_device rw"
          ];
          PrivateDevices = false;

          ReadOnlyPaths = [
            cfg.planPath
            cfg.requestPath
          ];
          ReadWritePaths = [ stateRoot ];

          AmbientCapabilities = "";
          CapabilityBoundingSet = "";
          KeyringMode = "private";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
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
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StandardInput = "null";
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
          ];
        };
      };
    })
  ]);
}
