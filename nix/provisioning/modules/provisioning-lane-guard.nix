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
    hasPrefix
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    optional
    types
    unique
    ;

  cfg = config.services.kaiba-provisioning-lane-guard;
  bridgeCfg = config.services.kaiba-provisioning-authority-bridge;
  bridgeClientGroup = "kaiba-provision-bridge";
  bridgeRuntimeDirectory = "kaiba-provision-authority-bridge";
  bridgeSocketPath = "/run/${bridgeRuntimeDirectory}/${bridgeCfg.socketName}";
  operatorGroup = "kaiba-provision-operator";
  operatorRuntimeDirectory = "kaiba-provision-lane-guard";
  operatorSocketPath = "/run/${operatorRuntimeDirectory}/operator.sock";
  stateDirectory = "kaiba-provision-lane-guard";
  stateRoot = "/var/lib/${stateDirectory}";
  attemptDirectory = "${stateRoot}/attempts";
  gpioPersistenceParameter = "/sys/module/pinctrl_rp1/parameters/persist_gpio_outputs";
  relayPowerControl = cfg.powerControl == "relay";
  defaultOperatorPackage = (import ../packages.nix { inherit pkgs lib; }).laneOperator;
  # This source must be a native executable: shells intentionally drop an
  # inherited setgid identity unless privileged mode is requested. The NixOS
  # security wrapper enters operatorGroup, then this fixed-argv launcher keeps
  # that identity while exposing no caller-controlled selector.
  operatorWrapper =
    (pkgs.writeCBin "kaiba-provision-lane-acknowledge" ''
      #include <errno.h>
      #include <stdio.h>
      #include <string.h>
      #include <unistd.h>

      int main(int argc, char **argv) {
        (void)argv;
        if (argc != 1) {
          fputs("usage: kaiba-provision-lane-acknowledge\n", stderr);
          return 2;
        }
        execl(
          "${getExe' cfg.operatorPackage "kaiba-provision-lane-operator"}",
          "kaiba-provision-lane-operator",
          "--socket",
          "${operatorSocketPath}",
          (char *)0
        );
        fprintf(stderr, "kaiba-provision-lane-acknowledge: %s\n", strerror(errno));
        return 1;
      }
    '').overrideAttrs
      (old: {
        passthru = (old.passthru or { }) // {
          kaibaLaneOperatorWrapper = {
            group = operatorGroup;
            socketPath = operatorSocketPath;
            acceptsArguments = false;
            mutationCapable = false;
            operationSelectionCapable = false;
            physicalPathSelectionCapable = false;
          };
        };
      });
  statePaths = [
    cfg.journalPath
    cfg.draftPath
  ];

  gpioSetPackage =
    if cfg.package == null then null else cfg.package.kaibaPhysicalLaneGuard.gpioSet or null;
  gpioReleasePolicyCheckArgs = [
    (getExe' pkgs.gnugrep "grep")
    "--fixed-strings"
    "--line-regexp"
    "N"
    gpioPersistenceParameter
  ];
  gpioInactiveArgs =
    if gpioSetPackage == null || !relayPowerControl then
      [ ]
    else
      [
        "${gpioSetPackage}/bin/gpioset"
        "--chip"
        cfg.gpioChip
        "--consumer"
        "kaiba-provision-lane-guard-inactive"
      ]
      ++ optional cfg.gpioActiveLow "--active-low"
      ++ [
        "--hold-period"
        "100ms"
        "--toggle"
        "0"
        "${toString cfg.gpioOffset}=0"
      ];

  isCleanStatePath =
    path:
    let
      components = lib.drop 1 (lib.splitString "/" path);
    in
    builtins.match "${stateRoot}/[A-Za-z0-9][A-Za-z0-9._/-]*" path != null
    && builtins.all (component: component != "" && component != "." && component != "..") components
    && !hasPrefix "${builtins.storeDir}/" path;

  isCleanRuntimeSocket =
    path:
    let
      components = lib.drop 1 (lib.splitString "/" path);
    in
    builtins.match "/run/[A-Za-z0-9][A-Za-z0-9._/-]*\.sock" path != null
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
        "--power-control"
        cfg.powerControl
        "--lease-safety-margin"
        "${toString bridgeCfg.leaseSafetyMarginSeconds}s"
        "--journal"
        cfg.journalPath
        "--draft"
        cfg.draftPath
        "--bridge-socket"
        bridgeSocketPath
        "--operator-socket"
        operatorSocketPath
        "--operator-group"
        operatorGroup
        "--attempt-directory"
        attemptDirectory
        "--mode"
        cfg.mode
      ]
      ++ lib.optionals relayPowerControl [
        "--gpio-chip"
        cfg.gpioChip
        "--gpio-offset"
        (toString cfg.gpioOffset)
      ]
      ++ optional (relayPowerControl && cfg.gpioActiveLow) "--gpio-active-low"
      ++ optional cfg.enableMutations "--enable-mutations";
in
{
  imports = [ ./provisioning-authority-bridge.nix ];

  options.services.kaiba-provisioning-lane-guard = {
    enable = mkEnableOption "the one-shot physical Kaiba Raspberry Pi 5 lane guard";

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      example = lib.literalExpression ''
        inputs.kaiba-provisioning.lib.mkRpi5PhysicalLaneGuard {
          system = pkgs.system;
          verifiedSignedRelease = inputs.release.packages.''${pkgs.system}.verified;
        }
      '';
      description = ''
        Explicit immutable package containing bin/kaiba-provision-lane-guard.
        Its single typed verified signed-release input supplies the six
        content-addressed bundles and every expected release digest. The
        executable and compiled-artifact identities are derived by reopening
        those immutable store paths; there is deliberately no independently
        caller-declared bundle or digest input.
      '';
    };

    operatorPackage = mkOption {
      type = types.package;
      default = defaultOperatorPackage;
      defaultText = lib.literalExpression "the acknowledgement-only kaiba-provision-lane-operator package from the provisioning source tree";
      description = ''
        Unprivileged client containing bin/kaiba-provision-lane-operator. The
        package can only display and acknowledge the exact active prompt chosen
        by the privileged lane service; it cannot select an operation, target,
        boot mode, physical path, or mutation.
      '';
    };

    operators = mkOption {
      type = types.listOf (types.strMatching "[a-z_][a-z0-9_-]{0,30}");
      default = [ ];
      example = [ "provisioner" ];
      description = ''
        Existing local users allowed to acknowledge the lane service's active
        physical prompt. The server authenticates the connecting process's
        primary group. The module installs the native, fixed, no-argument
        kaiba-provision-lane-acknowledge setgid security wrapper for these
        users; invoke that wrapper directly for each prompt. Supplementary
        membership alone does not authorize an acknowledgement.
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

    powerControl = mkOption {
      type = types.enum [
        "relay"
        "manual"
      ];
      default = "relay";
      description = ''
        Fixed target-power mechanism for this lane. The default relay mode
        requires the qualified GPIO-controlled normally-off relay and retains
        every GPIO release-policy, pre-start, post-stop, and device-access
        boundary. Manual mode delegates only the physical connect/disconnect
        actions to authenticated operator prompts and grants the service no
        GPIO device access. It is a development-only deviation with no
        automated electrical fail-off: after abrupt process or station loss,
        the operator must remove target power before reconciliation can
        establish a terminal state.
      '';
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
        Durable execute-once journal. It must be a clean non-store direct child
        of ${stateRoot}; systemd creates that root-owned boundary with mode
        0700.
      '';
    };

    draftPath = mkOption {
      type = types.str;
      default = "${stateRoot}/draft.json";
      description = ''
        Root-installed authority-free plan draft reviewed before approval. It
        must be a clean, regular, non-symlink, non-store direct child of
        ${stateRoot}. It cannot authorize execution: the bridge independently
        binds its digest to current control and audit authority.
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
          assertion =
            hasPrefix "${builtins.storeDir}/" (toString cfg.operatorPackage)
            && cfg.operatorPackage ? kaibaLaneOperator
            && (cfg.operatorPackage.kaibaLaneOperator.authority or "") == "acknowledgement_only"
            && !(cfg.operatorPackage.kaibaLaneOperator.directHardwareAccess or true)
            && !(cfg.operatorPackage.kaibaLaneOperator.mutationCapable or true)
            && !(cfg.operatorPackage.kaibaLaneOperator.operationSelectionCapable or true)
            && !(cfg.operatorPackage.kaibaLaneOperator.physicalPathSelectionCapable or true);
          message = ''
            services.kaiba-provisioning-lane-guard.operatorPackage must be the
            immutable acknowledgement-only lane operator package and must not
            expose hardware, mutation, operation-selection, or path-selection
            authority.
          '';
        }
        {
          assertion = builtins.length cfg.operators == builtins.length (unique cfg.operators);
          message = "services.kaiba-provisioning-lane-guard.operators must not contain duplicates";
        }
        {
          assertion = cfg.package == null || cfg.package ? kaibaPhysicalLaneGuard;
          message = ''
            services.kaiba-provisioning-lane-guard.package must be produced by
            lib.mkRpi5PhysicalLaneGuard; the generic unlinked lane-guard binary
            has no immutable rpiboot, gpioset, or verified-release lineage.
          '';
        }
        {
          assertion =
            cfg.package == null
            || (
              gpioSetPackage != null
              && lib.isDerivation gpioSetPackage
              && hasPrefix "${builtins.storeDir}/" (toString gpioSetPackage)
            );
          message = ''
            services.kaiba-provisioning-lane-guard.package must bind the exact
            immutable libgpiod package used for active and inactive relay
            control.
          '';
        }
        {
          assertion =
            cfg.package == null
            || (
              let
                contract = cfg.package.kaibaPhysicalLaneGuard or { };
                release = contract.verifiedSignedRelease or null;
              in
              (contract.releaseBindingIdentity or "") == "runtime-verified-content-derived-v1alpha1"
              && (contract.releaseLineageIdentity or "") == "single-verified-signed-release-v1alpha2"
              && release != null
              && builtins.isAttrs release
              && hasPrefix "${builtins.storeDir}/" (toString release)
              && release ? kaibaVerifiedSignedRelease
            );
          message = ''
            services.kaiba-provisioning-lane-guard.package must expose the
            content-derived binding and single verified-signed-release lineage
            contract produced by the current mkRpi5PhysicalLaneGuard factory.
          '';
        }
        {
          assertion = builtins.all isCleanStatePath statePaths;
          message = ''
            services.kaiba-provisioning-lane-guard journalPath and draftPath
            must be clean absolute non-store paths strictly below ${stateRoot}
            with no empty, dot, or parent components.
          '';
        }
        {
          assertion = builtins.all (path: builtins.dirOf path == stateRoot) statePaths;
          message = ''
            services.kaiba-provisioning-lane-guard journalPath and draftPath
            must be direct children of ${stateRoot} so the pre-start trusted
            state boundary has no implicitly created parent directories.
          '';
        }
        {
          assertion = builtins.length (lib.unique statePaths) == builtins.length statePaths;
          message = "lane-guard journal and draft paths must be distinct";
        }
        {
          assertion = builtins.all (
            path: path != attemptDirectory && !hasPrefix "${attemptDirectory}/" path
          ) statePaths;
          message = "lane-guard journal and draft paths must remain outside the immutable attempt-receipt directory";
        }
        {
          assertion = isCleanRuntimeSocket bridgeSocketPath;
          message = "the module-derived authority-bridge socket must be a clean absolute non-store .sock path below /run";
        }
        {
          assertion = isCleanRuntimeSocket operatorSocketPath;
          message = "the module-derived operator socket must be a clean absolute non-store .sock path below /run";
        }
        {
          assertion = !cfg.enableMutations || config.services.kaiba-provisioning-authority-bridge.enable;
          message = ''
            mutation-enabled lane guard requires
            services.kaiba-provisioning-authority-bridge.enable so executable
            authority cannot fall back to root-installed JSON.
          '';
        }
        {
          assertion = cfg.mode != "reconcile" || cfg.enableMutations;
          message = ''
            services.kaiba-provisioning-lane-guard.mode = "reconcile" requires
            enableMutations so the one-shot is allowed to open the durable
            journal and observe the fixed lane. Reconciliation remains
            observation-only and cannot dispatch a hardware mutation.
          '';
        }
      ];
    }

    (mkIf (cfg.package != null) {
      # Only the fixed NixOS security wrapper enters PATH. The compiled wrapper
      # changes the client's effective primary group to the peer-authenticated
      # operator group before executing this argument-free source wrapper. The
      # source supplies the module-owned socket and accepts no operation, mode,
      # target, or physical selector.
      security.wrappers.kaiba-provision-lane-acknowledge = {
        source = getExe' operatorWrapper "kaiba-provision-lane-acknowledge";
        owner = "root";
        group = operatorGroup;
        setuid = false;
        setgid = true;
        permissions = "u+rx,g+rx,o-rwx";
      };
      users.groups.${operatorGroup} = { };
      users.users = builtins.listToAttrs (
        map (name: {
          inherit name;
          value.extraGroups = [ operatorGroup ];
        }) cfg.operators
      );

      # The reviewed draft must be installed before the first one-shot starts,
      # so StateDirectory= alone is too late to bootstrap this trusted parent.
      # tmpfiles and systemd agree on the same root-owned, non-writable mode.
      systemd.tmpfiles.rules = [
        "d ${stateRoot} 0700 root ${operatorGroup} -"
        "d ${attemptDirectory} 0700 root ${operatorGroup} -"
      ];

      systemd.services.kaiba-provisioning-lane-guard = {
        description = "One-shot Kaiba physical Raspberry Pi 5 provisioning lane guard";
        after = optional cfg.enableMutations "kaiba-provisioning-authority-bridge.service";
        requires = optional cfg.enableMutations "kaiba-provisioning-authority-bridge.service";
        serviceConfig = {
          Type = "oneshot";
          User = "root";
          Group = operatorGroup;
          SupplementaryGroups = optional cfg.enableMutations bridgeClientGroup;
          # Relay mode refuses kernels that retain an output after its
          # character-device owner exits and establishes logical inactive
          # before startup and after every main-process exit. Manual mode has
          # no GPIO command or device permission; its disconnect evidence is
          # collected through the authenticated operator-prompt path during a
          # live service. A hard process or station failure cannot actuate
          # manual power and leaves restart reconciliation to the operator.
          ExecStartPre = lib.optionals relayPowerControl [
            (utils.escapeSystemdExecArgs gpioReleasePolicyCheckArgs)
            (utils.escapeSystemdExecArgs gpioInactiveArgs)
          ];
          ExecStart = utils.escapeSystemdExecArgs args;
          ExecStopPost = if relayPowerControl then utils.escapeSystemdExecArgs gpioInactiveArgs else [ ];
          StateDirectory = [
            stateDirectory
            "${stateDirectory}/attempts"
          ];
          StateDirectoryMode = "0700";
          RuntimeDirectory = operatorRuntimeDirectory;
          RuntimeDirectoryMode = "0750";
          WorkingDirectory = stateRoot;
          UMask = "0077";
          # Reviewed operation budgets are at most 50 minutes. The guard
          # enforces that budget; this outer bound leaves time for authority
          # setup and cancellation-independent safe relay release plus
          # terminal journal persistence.
          TimeoutStartSec = "65min";
          # During graceful cancellation the adapter gets a cancellation-
          # independent safe-off window: 30 seconds for relay release, or the
          # full advertised two-minute manual disconnect prompt plus bounded
          # USB disappearance. Give systemd enough margin to persist the
          # terminal transition. SIGKILL and station power loss cannot perform
          # a manual action.
          TimeoutStopSec = if relayPowerControl then "45s" else "3min";
          KillMode = "control-group";

          # Relay GPIO and UART are exact device nodes. Manual mode omits GPIO
          # entirely. USB bus and device numbers are dynamic, so the USB
          # character-device class is the narrowest cgroup rule with which
          # libusb/rpiboot can operate.
          DevicePolicy = "closed";
          DeviceAllow =
            lib.optionals relayPowerControl [
              "${cfg.gpioChip} rw"
            ]
            ++ [
              "${cfg.uartPath} r"
              "char-usb_device rw"
            ];
          PrivateDevices = false;

          ReadOnlyPaths = [ cfg.draftPath ];
          ReadWritePaths = [
            stateRoot
            "/run/${operatorRuntimeDirectory}"
          ];

          AmbientCapabilities = "";
          CapabilityBoundingSet = "";
          KeyringMode = "private";
          IPAddressDeny = "any";
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
