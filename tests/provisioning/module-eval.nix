{
  pkgs,
  lib,
  kaibaAuditPackage,
  kaibaControlPackage,
  kaibaLaneGuardPackage,
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

  provisioningControl = {
    services.kaiba-provisioning-control = {
      enable = true;
      package = kaibaControlPackage;
    };
  };

  provisioningControlNonLoopback = {
    services.kaiba-provisioning-control = {
      enable = true;
      package = kaibaControlPackage;
      listenAddress = "192.0.2.10";
    };
  };

  provisioningControlTLS = {
    services.kaiba-provisioning-control = {
      enable = true;
      package = kaibaControlPackage;
      listenAddress = "192.0.2.10";
      enableTLS = true;
      tlsCertificateFile = "/run/keys/kaiba-control-server.crt";
      tlsPrivateKeyFile = "/run/keys/kaiba-control-server.key";
      clientCAFile = "/run/keys/kaiba-station-client-ca.crt";
    };
  };

  provisioningControlTLSIncomplete = lib.recursiveUpdate provisioningControlTLS {
    services.kaiba-provisioning-control.clientCAFile = null;
  };

  provisioningControlTLSWildcard = lib.recursiveUpdate provisioningControlTLS {
    services.kaiba-provisioning-control.listenAddress = "0.0.0.0";
  };

  provisioningControlTLSStoreCredential = lib.recursiveUpdate provisioningControlTLS {
    services.kaiba-provisioning-control.tlsPrivateKeyFile = "${kaibaControlPackage}/server.key";
  };

  provisioningAudit = {
    services.kaiba-provisioning-audit = {
      enable = true;
      package = kaibaAuditPackage;
    };
  };

  provisioningAuditNonLoopback = {
    services.kaiba-provisioning-audit = {
      enable = true;
      package = kaibaAuditPackage;
      listenAddress = "192.0.2.11";
    };
  };

  provisioningAuditTLS = {
    services.kaiba-provisioning-audit = {
      enable = true;
      package = kaibaAuditPackage;
      listenAddress = "192.0.2.11";
      enableTLS = true;
      tlsCertificateFile = "/run/keys/kaiba-audit-server.crt";
      tlsPrivateKeyFile = "/run/keys/kaiba-audit-server.key";
      clientCAFile = "/run/keys/kaiba-station-client-ca.crt";
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
      scenario = "post-recovery-readback-mismatch";
    };
  };

  provisioningStationDemoNonLoopback = {
    services.kaiba-provisioning-station-demo = {
      enable = true;
      package = kaibaStationDemoPackage;
      listenAddress = "192.0.2.10";
    };
  };

  secureBootTarget = {
    fileSystems."/" = {
      device = lib.mkForce "/dev/mapper/root";
      fsType = lib.mkForce "ext4";
    };
    kaiba.secureBootTarget = {
      enable = true;
      expectedCustomerKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      sourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    };
  };

  secureBootTargetInvalidHash = lib.recursiveUpdate secureBootTarget {
    kaiba.secureBootTarget.expectedCustomerKeyHash = "not-a-digest";
  };

  signingTestPackage =
    pkgs.runCommand "kaiba-signing-module-fixture"
      {
        passthru.kaibaSigning = {
          pinCredentialPath = "/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin";
          socketPath = "/run/kaiba-provision-signing/signing.sock";
          stateDirectoryPath = "/var/lib/kaiba-provision-signing";
        };
        meta.mainProgram = "kaiba-provision-signer";
      }
      ''
        mkdir -p "$out/bin"
        touch "$out/bin/kaiba-provision-signing-gate"
        chmod 0555 "$out/bin/kaiba-provision-signing-gate"
      '';

  provisioningLaneGuard = {
    services.kaiba-provisioning-lane-guard = {
      enable = true;
      package = kaibaLaneGuardPackage;
    };
  };

  unlinkedLaneGuardPackage = pkgs.runCommand "kaiba-unlinked-lane-guard-fixture" { } ''
    mkdir -p "$out/bin"
    touch "$out/bin/kaiba-provision-lane-guard"
    chmod 0555 "$out/bin/kaiba-provision-lane-guard"
  '';

  provisioningLaneGuardUnlinked = {
    services.kaiba-provisioning-lane-guard = {
      enable = true;
      package = unlinkedLaneGuardPackage;
    };
  };

  provisioningLaneGuardMutating = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.enableMutations = true;
  };

  provisioningLaneGuardStoreJournal = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.journalPath = "${kaibaLaneGuardPackage}/journal.json";
  };

  provisioningSigningGate = {
    services.kaiba-provisioning-signing-gate = {
      enable = true;
      package = signingTestPackage;
      pinFile = "/run/keys/kaiba-development-yubikey-pin";
    };
  };

  provisioningSigningGateStorePIN = lib.recursiveUpdate provisioningSigningGate {
    services.kaiba-provisioning-signing-gate.pinFile = "${signingTestPackage}/pin";
  };

  probeConfig = evaluateConfig provisioningProbe;
  controlConfig = evaluateConfig provisioningControl;
  controlTLSConfig = evaluateConfig provisioningControlTLS;
  auditConfig = evaluateConfig provisioningAudit;
  auditTLSConfig = evaluateConfig provisioningAuditTLS;
  defaultProbeConfig = evaluateConfig provisioningProbeDefaultPackage;
  disabledProbeConfig = evaluateConfig { };
  stationDemoConfig = evaluateConfig provisioningStationDemo;
  defaultStationDemoConfig = evaluateConfig provisioningStationDemoDefaultPackage;
  stationDemoIPv6Config = evaluateConfig provisioningStationDemoIPv6;
  secureBootTargetConfig = evaluateConfig secureBootTarget;
  laneGuardConfig = evaluateConfig provisioningLaneGuard;
  laneGuardMutatingConfig = evaluateConfig provisioningLaneGuardMutating;
  signingGateConfig = evaluateConfig provisioningSigningGate;
  stationDemoService =
    stationDemoConfig.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  stationDemoIPv6Service =
    stationDemoIPv6Config.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  controlService = controlConfig.systemd.services.kaiba-provisioning-control.serviceConfig;
  controlTLSService = controlTLSConfig.systemd.services.kaiba-provisioning-control.serviceConfig;
  auditService = auditConfig.systemd.services.kaiba-provisioning-audit.serviceConfig;
  auditTLSService = auditTLSConfig.systemd.services.kaiba-provisioning-audit.serviceConfig;
  laneGuardService = laneGuardConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardMutatingService =
    laneGuardMutatingConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  signingGateService = signingGateConfig.systemd.services.kaiba-provision-signing-gate.serviceConfig;

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

  referenceServiceBoundary =
    controlConfig.services.kaiba-provisioning-control.package == kaibaControlPackage
    && auditConfig.services.kaiba-provisioning-audit.package == kaibaAuditPackage
    && builtins.elem kaibaControlPackage controlConfig.environment.systemPackages
    && builtins.elem kaibaAuditPackage auditConfig.environment.systemPackages
    && lib.hasInfix ''"--listen" "127.0.0.1:8091" "--state" "/var/lib/kaiba-provision-control/control.json"'' controlService.ExecStart
    && lib.hasInfix ''"--listen" "127.0.0.1:8092" "--state" "/var/lib/kaiba-provision-audit/audit.json"'' auditService.ExecStart
    && controlService.DynamicUser
    && auditService.DynamicUser
    && controlService.StateDirectoryMode == "0700"
    && auditService.StateDirectoryMode == "0700"
    && controlService.IPAddressAllow == "localhost"
    && auditService.IPAddressAllow == "localhost"
    && controlService.IPAddressDeny == "any"
    && auditService.IPAddressDeny == "any"
    && controlService.DevicePolicy == "closed"
    && auditService.DevicePolicy == "closed"
    && controlService.NoNewPrivileges
    && auditService.NoNewPrivileges
    && controlService.ProtectSystem == "strict"
    && auditService.ProtectSystem == "strict";

  referenceServiceTLSBoundary =
    controlTLSConfig.services.kaiba-provisioning-control.enableTLS
    && auditTLSConfig.services.kaiba-provisioning-audit.enableTLS
    && lib.hasInfix ''"--listen" "192.0.2.10:8091"'' controlTLSService.ExecStart
    && lib.hasInfix ''"--listen" "192.0.2.11:8092"'' auditTLSService.ExecStart
    && lib.hasInfix ''--tls-cert" "%d/server-cert"'' controlTLSService.ExecStart
    && lib.hasInfix ''--tls-key" "%d/server-key"'' controlTLSService.ExecStart
    && lib.hasInfix ''--client-ca" "%d/client-ca"'' controlTLSService.ExecStart
    && builtins.elem "server-cert:/run/keys/kaiba-control-server.crt" controlTLSService.LoadCredential
    && builtins.elem "server-key:/run/keys/kaiba-control-server.key" controlTLSService.LoadCredential
    && builtins.elem "client-ca:/run/keys/kaiba-station-client-ca.crt" controlTLSService.LoadCredential
    && builtins.elem "server-cert:/run/keys/kaiba-audit-server.crt" auditTLSService.LoadCredential
    && builtins.elem "server-key:/run/keys/kaiba-audit-server.key" auditTLSService.LoadCredential
    && builtins.elem "client-ca:/run/keys/kaiba-station-client-ca.crt" auditTLSService.LoadCredential
    && !(controlTLSService ? IPAddressAllow)
    && !(controlTLSService ? IPAddressDeny)
    && !(auditTLSService ? IPAddressAllow)
    && !(auditTLSService ? IPAddressDeny);

  stationDemoBoundary =
    stationDemoConfig.services.kaiba-provisioning-station-demo.listenAddress == "127.0.0.1"
    &&
      defaultStationDemoConfig.services.kaiba-provisioning-station-demo.package == kaibaStationDemoPackage
    && builtins.elem kaibaStationDemoPackage defaultStationDemoConfig.environment.systemPackages
    && stationDemoConfig.services.kaiba-provisioning-station-demo.port == 8080
    && stationDemoConfig.services.kaiba-provisioning-station-demo.scenario == "happy-path"
    && builtins.elem stationDemoConfig.services.kaiba-provisioning-station-demo.package stationDemoConfig.environment.systemPackages
    && lib.hasInfix ''"--listen" "127.0.0.1:8080" "--scenario" "happy-path"'' stationDemoService.ExecStart
    && lib.hasInfix ''"--listen" "[::1]:8081" "--scenario" "post-recovery-readback-mismatch"'' stationDemoIPv6Service.ExecStart
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

  secureBootTargetBoundary =
    secureBootTargetConfig.fileSystems."/".device == "/dev/mapper/root"
    && builtins.all (option: builtins.elem option secureBootTargetConfig.fileSystems."/".options) [
      "x-initrd.mount"
      "ro"
      "noatime"
      "nodev"
    ]
    && !(builtins.elem "rw" secureBootTargetConfig.fileSystems."/".options)
    && secureBootTargetConfig.fileSystems."/var".fsType == "tmpfs"
    && builtins.elem "dm_verity" secureBootTargetConfig.boot.initrd.availableKernelModules
    && builtins.elem "nvme" secureBootTargetConfig.boot.initrd.availableKernelModules
    && secureBootTargetConfig.boot.initrd.systemd.enable
    && secureBootTargetConfig.boot.initrd.systemd.dmVerity.enable
    && secureBootTargetConfig.swapDevices == [ ]
    && !secureBootTargetConfig.zramSwap.enable
    && !secureBootTargetConfig.services.openssh.enable
    && !secureBootTargetConfig.security.sudo.enable
    &&
      lib.hasInfix ''"rollback_gate":"unimplemented"''
        secureBootTargetConfig.environment.etc."kaiba-provisioning/target-policy.json".text
    &&
      lib.hasInfix ''"enrollment_ready":false''
        secureBootTargetConfig.environment.etc."kaiba-provisioning/target-policy.json".text
    && secureBootTargetConfig.systemd.services.kaiba-secure-boot-evidence.serviceConfig.NoNewPrivileges
    &&
      secureBootTargetConfig.systemd.services.kaiba-secure-boot-evidence.serviceConfig.StandardOutput
      == "journal+console"
    &&
      secureBootTargetConfig.systemd.services.kaiba-secure-boot-evidence.serviceConfig.ProtectSystem
      == "strict";

  physicalServiceBoundary =
    lib.hasInfix ''"--rpiboot-sysfs" "/sys/bus/usb/devices/1-1"'' laneGuardService.ExecStart
    && !(lib.hasInfix "--enable-mutations" laneGuardService.ExecStart)
    && lib.hasInfix "--enable-mutations" laneGuardMutatingService.ExecStart
    && laneGuardService.User == "root"
    && laneGuardService.StateDirectory == "kaiba-provision-lane-guard"
    && laneGuardService.StateDirectoryMode == "0700"
    && laneGuardService.DevicePolicy == "closed"
    && builtins.elem "/dev/gpiochip0 rw" laneGuardService.DeviceAllow
    && builtins.elem "/dev/serial/by-id/kaiba-target-uart r" laneGuardService.DeviceAllow
    && builtins.elem "char-usb_device rw" laneGuardService.DeviceAllow
    && laneGuardService.ProtectSystem == "strict"
    && laneGuardConfig.systemd.services.kaiba-provisioning-lane-guard.wantedBy == [ ];

  signingServiceBoundary =
    signingGateConfig.services.pcscd.enable
    && signingGateConfig.users.users.kaiba-signing.isSystemUser
    && signingGateService.User == "kaiba-signing"
    && signingGateService.Group == "kaiba-signing"
    &&
      signingGateService.LoadCredential == [
        "yubikey-pin:/run/keys/kaiba-development-yubikey-pin"
      ]
    && signingGateService.StateDirectory == "kaiba-provision-signing"
    && signingGateService.RuntimeDirectory == "kaiba-provision-signing"
    && signingGateService.DevicePolicy == "closed"
    && signingGateService.IPAddressDeny == "any"
    && signingGateService.ProtectSystem == "strict";

in
assert lib.assertMsg (assertionsPass provisioningProbe) (
  builtins.toJSON (failedMessages provisioningProbe)
);
assert lib.assertMsg (assertionsPass provisioningProbeDefaultPackage) (
  builtins.toJSON (failedMessages provisioningProbeDefaultPackage)
);
assert lib.assertMsg (assertionsPass provisioningControl) (
  builtins.toJSON (failedMessages provisioningControl)
);
assert lib.assertMsg (assertionsPass provisioningAudit) (
  builtins.toJSON (failedMessages provisioningAudit)
);
assert lib.assertMsg (assertionsPass provisioningControlTLS) (
  builtins.toJSON (failedMessages provisioningControlTLS)
);
assert lib.assertMsg (assertionsPass provisioningAuditTLS) (
  builtins.toJSON (failedMessages provisioningAuditTLS)
);
assert lib.assertMsg (
  !assertionsPass provisioningControlNonLoopback
) "a non-loopback provisioning control listener was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuditNonLoopback
) "a non-loopback provisioning audit listener was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningControlTLSIncomplete
) "an incomplete provisioning control TLS configuration was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningControlTLSWildcard
) "a wildcard provisioning control TLS listener was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningControlTLSStoreCredential
) "a Nix-store provisioning control private key was accepted";
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
assert lib.assertMsg (assertionsPass secureBootTarget) (
  builtins.toJSON (failedMessages secureBootTarget)
);
assert lib.assertMsg (
  !assertionsPass secureBootTargetInvalidHash
) "an invalid secure-boot target customer-key hash was accepted";
assert lib.assertMsg (assertionsPass provisioningLaneGuard) (
  builtins.toJSON (failedMessages provisioningLaneGuard)
);
assert lib.assertMsg (assertionsPass provisioningLaneGuardMutating) (
  builtins.toJSON (failedMessages provisioningLaneGuardMutating)
);
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardUnlinked
) "a generic lane-guard package without immutable physical configuration was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardStoreJournal
) "a Nix-store lane-guard journal was accepted";
assert lib.assertMsg (assertionsPass provisioningSigningGate) (
  builtins.toJSON (failedMessages provisioningSigningGate)
);
assert lib.assertMsg (
  !assertionsPass provisioningSigningGateStorePIN
) "a Nix-store YubiKey PIN was accepted";
assert lib.assertMsg (
  !assertionsPass duplicateProbeOperators
) "duplicate probe operators were accepted";
assert lib.assertMsg probeBoundary
  "provisioning probe package, group, or narrow udev boundary is not enforced";
assert lib.assertMsg referenceServiceBoundary
  "provisioning control or audit persistence, loopback, or sandbox boundary is not enforced";
assert lib.assertMsg referenceServiceTLSBoundary
  "provisioning control or audit mutual-TLS credential boundary is not enforced";
assert lib.assertMsg stationDemoBoundary
  "provisioning-station demo loopback, sandbox, or no-USB boundary is not enforced";
assert lib.assertMsg secureBootTargetBoundary
  "secure-boot target dm-verity, no-enrollment, or runtime evidence boundary is not enforced";
assert lib.assertMsg physicalServiceBoundary
  "physical lane-guard mutation opt-in, device, or root service boundary is not enforced";
assert lib.assertMsg signingServiceBoundary
  "YubiKey signer credential, PC/SC, user, or sandbox boundary is not enforced";
pkgs.runCommand "kaiba-provisioning-module-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'provisioning-probe-module: pass' \
    'provisioning-probe-usb-boundary: pass' \
    'provisioning-control-loopback-persistence: pass' \
    'provisioning-audit-loopback-persistence: pass' \
    'provisioning-control-audit-mutual-tls: pass' \
    'provisioning-station-demo-module: pass' \
    'provisioning-station-demo-loopback-only: pass' \
    'provisioning-station-demo-sandbox-and-no-usb: pass' \
    'secure-boot-target-dm-verity-boundary: pass' \
    'secure-boot-target-enrollment-blocked: pass' \
    'physical-lane-guard-explicit-mutation-boundary: pass' \
    'yubikey-signing-gate-credential-boundary: pass' \
    > "$out/results.txt"
''
