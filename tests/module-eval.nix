{
  pkgs,
  lib,
  kaibaPackage,
  kaibaProvisionPackage,
  kaibaModules,
}:

let
  fixtures = import ./integration/fixtures.nix { inherit pkgs; };

  evaluateConfig =
    module:
    (lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        kaibaModules.default
        {
          boot.loader.grub.devices = [ "nodev" ];
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "26.05";
        }
        module
      ];
    }).config;

  evaluate = module: (evaluateConfig module).assertions;

  assertionsPass = module: builtins.all (assertion: assertion.assertion) (evaluate module);
  failedMessages =
    module:
    map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) (evaluate module)
    );

  primary = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.1" ];
      hiddenPrimary = {
        enable = true;
        initialZoneFile = fixtures.kaibaZone;
        publisherUpdate.keyFile = "/run/credentials/update.conf";
        standby = {
          address = "192.0.2.2";
          keyFile = "/run/credentials/standby.conf";
        };
        publicTransfer = {
          keyFile = "/run/credentials/public.conf";
          secondaries = [
            {
              id = "public-a";
              address = "192.0.2.3";
            }
          ];
        };
      };
    };
  };

  standby = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.2" ];
      hiddenStandby = {
        enable = true;
        primary = {
          address = "192.0.2.1";
          keyFile = "/run/credentials/standby.conf";
        };
        publicTransfer = {
          keyFile = "/run/credentials/public.conf";
          secondaries = [
            {
              id = "public-a";
              address = "192.0.2.3";
            }
          ];
        };
      };
    };
  };

  publicSecondary = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.3" ];
      publicSecondary = {
        enable = true;
        keyFiles = [ "/run/credentials/public.conf" ];
        masters = [
          {
            id = "p0";
            address = "192.0.2.1";
          }
          {
            id = "p1";
            address = "192.0.2.2";
          }
        ];
      };
    };
  };

  applicationServices = {
    kaiba.deviceAgent = {
      enable = true;
      package = kaibaPackage;
      endpoint = "https://updates.kaiba.network";
      addresses = [ "203.0.113.10" ];
      credentials = {
        clientCertificate = "/run/credentials/device.pem";
        clientKey = "/run/credentials/device-key.pem";
        serverCA = "/run/credentials/ca.pem";
      };
    };
    kaiba.updateController = {
      enable = true;
      credentials = {
        serverCertificate = "/run/credentials/controller.pem";
        serverKey = "/run/credentials/controller-key.pem";
        clientCA = "/run/credentials/ca.pem";
        publisherTSIGSecret = "/run/credentials/update.secret";
      };
      controller.package = kaibaPackage;
      publisher = {
        package = kaibaPackage;
        dnsServer = "192.0.2.1:53";
        observeServers = [
          "192.0.2.3:53"
          "192.0.2.4:53"
        ];
      };
    };
  };

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
    services.kaiba-provisioning-station-demo.enable = true;
  };

  provisioningStationDemoIPv6 = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      listenAddress = "::1";
      port = 8081;
      scenario = "target-replaced";
    };
  };

  provisioningStationDemoNonLoopback = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      listenAddress = "192.0.2.10";
    };
  };

  recursionViolation = lib.recursiveUpdate primary {
    kaiba.dns.recursion = true;
  };

  singleObserver = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [ "192.0.2.3:53" ];
  };

  duplicateObservers = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [
      "192.0.2.3:53"
      "192.0.2.3:53"
    ];
  };

  emptyObserver = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [
      "192.0.2.3:53"
      ""
    ];
  };

  applicationConfig = evaluateConfig applicationServices;
  probeConfig = evaluateConfig provisioningProbe;
  defaultProbeConfig = evaluateConfig provisioningProbeDefaultPackage;
  disabledProbeConfig = evaluateConfig { };
  stationDemoConfig = evaluateConfig provisioningStationDemo;
  stationDemoIPv6Config = evaluateConfig provisioningStationDemoIPv6;
  stationDemoService =
    stationDemoConfig.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  stationDemoIPv6Service =
    stationDemoIPv6Config.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  controllerService = applicationConfig.systemd.services.kaiba-controller.serviceConfig;
  publisherService = applicationConfig.systemd.services.kaiba-publisher.serviceConfig;
  controllerUnit = applicationConfig.systemd.services.kaiba-controller;
  publisherUnit = applicationConfig.systemd.services.kaiba-publisher;
  serviceBoundary =
    applicationConfig.users.users.kaiba-controller.group == "kaiba-controller"
    && applicationConfig.users.users.kaiba-controller.extraGroups == [ ]
    && applicationConfig.users.users.kaiba-publisher.group == "kaiba-publisher"
    && applicationConfig.users.users.kaiba-publisher.extraGroups == [ ]
    && controllerService.User == "kaiba-controller"
    && controllerService.Group == "kaiba-controller"
    && controllerService.SupplementaryGroups == [ "kaiba-state" ]
    && controllerService.ReadWritePaths == [ "/var/lib/kaiba-controller" ]
    && controllerService.InaccessiblePaths == [ "/run/credentials/update.secret" ]
    && publisherService.User == "kaiba-publisher"
    && publisherService.Group == "kaiba-publisher"
    && publisherService.SupplementaryGroups == [ "kaiba-state" ]
    && publisherService.ReadWritePaths == [ "/var/lib/kaiba-controller" ]
    &&
      publisherService.InaccessiblePaths == [
        "/run/credentials/controller.pem"
        "/run/credentials/controller-key.pem"
        "/run/credentials/ca.pem"
      ]
    && builtins.elem "systemd-tmpfiles-setup.service" controllerUnit.requires
    && builtins.elem "systemd-tmpfiles-setup.service" controllerUnit.after
    && builtins.elem "systemd-tmpfiles-setup.service" publisherUnit.requires
    && builtins.elem "systemd-tmpfiles-setup.service" publisherUnit.after
    && builtins.elem "d /var/lib/kaiba-controller 2770 kaiba-controller kaiba-state - -" applicationConfig.systemd.tmpfiles.rules;

  sqlitePermissionPreparation =
    builtins.all (rule: builtins.elem rule applicationConfig.systemd.tmpfiles.rules)
      [
        "f /var/lib/kaiba-controller/desired-state.db 0660 kaiba-controller kaiba-state - -"
        "z /var/lib/kaiba-controller/desired-state.db-wal 0660 kaiba-controller kaiba-state - -"
        "z /var/lib/kaiba-controller/desired-state.db-shm 0660 kaiba-controller kaiba-state - -"
      ];

  probeBoundary =
    probeConfig.users.groups ? kaiba-provision
    && builtins.elem "kaiba-provision" probeConfig.users.users.provisioner.extraGroups
    && builtins.elem kaibaProvisionPackage probeConfig.environment.systemPackages
    && builtins.elem kaibaProvisionPackage defaultProbeConfig.environment.systemPackages
    && !disabledProbeConfig.services.kaiba-provisioning-probe.enable
    && !(disabledProbeConfig.users.groups ? kaiba-provision)
    && lib.hasInfix ''SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", GROUP="kaiba-provision"'' probeConfig.services.udev.extraRules
    && !(lib.hasInfix ''ATTR{idVendor}=="0a5c", MODE="0660"'' probeConfig.services.udev.extraRules);

  stationDemoBoundary =
    stationDemoConfig.services.kaiba-provisioning-station-demo.listenAddress == "127.0.0.1"
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

  invalidRejected = !assertionsPass recursionViolation;
in
assert lib.assertMsg (assertionsPass primary) (builtins.toJSON (failedMessages primary));
assert lib.assertMsg (assertionsPass standby) (builtins.toJSON (failedMessages standby));
assert lib.assertMsg (assertionsPass publicSecondary) (
  builtins.toJSON (failedMessages publicSecondary)
);
assert lib.assertMsg (assertionsPass applicationServices) (
  builtins.toJSON (failedMessages applicationServices)
);
assert lib.assertMsg (assertionsPass provisioningProbe) (
  builtins.toJSON (failedMessages provisioningProbe)
);
assert lib.assertMsg (assertionsPass provisioningStationDemo) (
  builtins.toJSON (failedMessages provisioningStationDemo)
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
assert invalidRejected;
assert lib.assertMsg (!assertionsPass singleObserver) "one observation endpoint was accepted";
assert lib.assertMsg (
  !assertionsPass duplicateObservers
) "duplicate observation endpoints were accepted";
assert lib.assertMsg (!assertionsPass emptyObserver) "an empty observation endpoint was accepted";
assert lib.assertMsg serviceBoundary "controller/publisher service boundary is not enforced";
assert lib.assertMsg sqlitePermissionPreparation "SQLite shared-file modes are not prepared";
assert lib.assertMsg probeBoundary
  "provisioning probe package, group, or narrow udev boundary is not enforced";
assert lib.assertMsg stationDemoBoundary
  "provisioning-station demo loopback, sandbox, or no-USB boundary is not enforced";
pkgs.runCommand "kaiba-module-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'primary: pass' \
    'standby: pass' \
    'public-secondary: pass' \
    'application-services: pass' \
    'provisioning-probe-module: pass' \
    'provisioning-probe-usb-boundary: pass' \
    'provisioning-station-demo-module: pass' \
    'provisioning-station-demo-loopback-only: pass' \
    'provisioning-station-demo-sandbox-and-no-usb: pass' \
    'controller-publisher-uid-and-state-boundary: pass' \
    'sqlite-main-wal-shm-permissions-prepared: pass' \
    'two-distinct-nonempty-observers-required: pass' \
    'authoritative-recursion-rejected: pass' \
    > "$out/results.txt"
''
