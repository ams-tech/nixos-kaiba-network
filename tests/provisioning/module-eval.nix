{
  pkgs,
  lib,
  kaibaProvisionPackage,
  kaibaStationDemoPackage,
  kaibaModules,
}:

let
  baseModule = {
    boot.loader.grub.devices = [ "nodev" ];
    fileSystems."/" = {
      device = "none";
      fsType = "tmpfs";
    };
    system.stateVersion = "26.05";
  };

  evaluateModules =
    modules:
    (lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [ baseModule ] ++ modules;
    }).config;

  evaluateConfig =
    module:
    evaluateModules [
      kaibaModules.default
      module
    ];

  evaluate = module: (evaluateConfig module).assertions;

  assertionsPass = module: builtins.all (assertion: assertion.assertion) (evaluate module);
  failedMessages =
    module:
    map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) (evaluate module)
    );

  provisioningProbe = {
    users.users.provisioner.isNormalUser = true;
    services.kaiba-provisioning-probe = {
      enable = true;
      package = kaibaProvisionPackage;
      operators = [ "provisioner" ];
    };
  };

  provisioningProbeDefaultPackage = {
    services.kaiba-provisioning-probe.enable = true;
  };

  duplicateProbeOperators = lib.recursiveUpdate provisioningProbe {
    services.kaiba-provisioning-probe.operators = [
      "provisioner"
      "provisioner"
    ];
  };

  provisioningStationDemo = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      package = kaibaStationDemoPackage;
    };
  };

  provisioningStationDemoDefaultPackage = {
    services.kaiba-provisioning-station-demo.enable = true;
  };

  provisioningStationDemoIPv6 = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      package = kaibaStationDemoPackage;
      listenAddress = "::1";
      port = 8081;
      scenario = "target-replaced";
    };
  };

  provisioningStationDemoNonLoopback = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      package = kaibaStationDemoPackage;
      listenAddress = "192.0.2.10";
    };
  };

  probeConfig = evaluateConfig provisioningProbe;
  defaultProbeConfig = evaluateConfig provisioningProbeDefaultPackage;
  disabledProbeConfig = evaluateConfig { };
  stationDemoConfig = evaluateConfig provisioningStationDemo;
  defaultStationDemoConfig = evaluateConfig provisioningStationDemoDefaultPackage;
  stationDemoIPv6Config = evaluateConfig provisioningStationDemoIPv6;
  stationDemoService =
    stationDemoConfig.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  stationDemoIPv6Service =
    stationDemoIPv6Config.systemd.services.kaiba-provisioning-station-demo.serviceConfig;

  probeBoundary =
    probeConfig.users.groups ? kaiba-provision
    && builtins.elem "kaiba-provision" probeConfig.users.users.provisioner.extraGroups
    && builtins.elem kaibaProvisionPackage probeConfig.environment.systemPackages
    && defaultProbeConfig.services.kaiba-provisioning-probe.package == kaibaProvisionPackage
    && builtins.elem kaibaProvisionPackage defaultProbeConfig.environment.systemPackages
    && !disabledProbeConfig.services.kaiba-provisioning-probe.enable
    && !(disabledProbeConfig.users.groups ? kaiba-provision)
    && lib.hasInfix ''SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", GROUP="kaiba-provision"'' probeConfig.services.udev.extraRules
    && !(lib.hasInfix ''ATTR{idVendor}=="0a5c", MODE="0660"'' probeConfig.services.udev.extraRules);

  stationDemoBoundary =
    stationDemoConfig.services.kaiba-provisioning-station-demo.listenAddress == "127.0.0.1"
    &&
      defaultStationDemoConfig.services.kaiba-provisioning-station-demo.package == kaibaStationDemoPackage
    && builtins.elem kaibaStationDemoPackage defaultStationDemoConfig.environment.systemPackages
    && stationDemoConfig.services.kaiba-provisioning-station-demo.port == 8080
    && stationDemoConfig.services.kaiba-provisioning-station-demo.scenario == "happy-path"
    && builtins.elem stationDemoConfig.services.kaiba-provisioning-station-demo.package stationDemoConfig.environment.systemPackages
    && lib.hasInfix ''"--listen" "127.0.0.1:8080" "--scenario" "happy-path"'' stationDemoService.ExecStart
    && lib.hasInfix ''"--listen" "[::1]:8081" "--scenario" "target-replaced"'' stationDemoIPv6Service.ExecStart
    && stationDemoService.DynamicUser
    && stationDemoService.AmbientCapabilities == ""
    && stationDemoService.CapabilityBoundingSet == ""
    && stationDemoService.DevicePolicy == "closed"
    && stationDemoService.IPAddressAllow == "localhost"
    && stationDemoService.IPAddressDeny == "any"
    && stationDemoService.NoNewPrivileges
    && stationDemoService.PrivateDevices
    && stationDemoService.PrivateTmp
    && stationDemoService.ProtectHome
    && stationDemoService.ProtectSystem == "strict"
    &&
      stationDemoService.RestrictAddressFamilies == [
        "AF_UNIX"
        "AF_INET"
        "AF_INET6"
      ]
    && stationDemoService.RestrictNamespaces
    && stationDemoService.SystemCallArchitectures == "native"
    && !(stationDemoService ? DeviceAllow)
    && !(stationDemoService ? SupplementaryGroups)
    && !(stationDemoConfig.users.groups ? kaiba-provision)
    && stationDemoConfig.services.udev.extraRules == disabledProbeConfig.services.udev.extraRules
    &&
      stationDemoConfig.networking.firewall.allowedTCPPorts
      == disabledProbeConfig.networking.firewall.allowedTCPPorts
    && !disabledProbeConfig.services.kaiba-provisioning-station-demo.enable
    && !(disabledProbeConfig.systemd.services ? kaiba-provisioning-station-demo);

in
assert lib.assertMsg (assertionsPass provisioningProbe) (
  builtins.toJSON (failedMessages provisioningProbe)
);
assert lib.assertMsg (assertionsPass provisioningProbeDefaultPackage) (
  builtins.toJSON (failedMessages provisioningProbeDefaultPackage)
);
assert lib.assertMsg (assertionsPass provisioningStationDemo) (
  builtins.toJSON (failedMessages provisioningStationDemo)
);
assert lib.assertMsg (assertionsPass provisioningStationDemoDefaultPackage) (
  builtins.toJSON (failedMessages provisioningStationDemoDefaultPackage)
);
assert lib.assertMsg (assertionsPass provisioningStationDemoIPv6) (
  builtins.toJSON (failedMessages provisioningStationDemoIPv6)
);
assert lib.assertMsg (
  !assertionsPass provisioningStationDemoNonLoopback
) "a non-loopback provisioning-station demo listener was accepted";
assert lib.assertMsg (
  !assertionsPass duplicateProbeOperators
) "duplicate probe operators were accepted";
assert lib.assertMsg probeBoundary
  "provisioning probe package, group, or narrow udev boundary is not enforced";
assert lib.assertMsg stationDemoBoundary
  "provisioning-station demo loopback, sandbox, or no-USB boundary is not enforced";
pkgs.runCommand "kaiba-provisioning-module-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'provisioning-probe-module: pass' \
    'provisioning-probe-usb-boundary: pass' \
    'provisioning-station-demo-module: pass' \
    'provisioning-station-demo-loopback-only: pass' \
    'provisioning-station-demo-sandbox-and-no-usb: pass' \
    > "$out/results.txt"
''
