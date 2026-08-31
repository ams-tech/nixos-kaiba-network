{
  pkgs,
  lib,
  kaibaAuditPackage,
  kaibaAuthorityBridgePackage,
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

  provisioningAuthorityBridge = {
    services.kaiba-provisioning-authority-bridge = {
      enable = true;
      package = kaibaAuthorityBridgePackage;
      controlAddress = "192.0.2.10";
      auditAddress = "192.0.2.11";
      tlsCertificateFile = "/run/keys/kaiba-lane-station.crt";
      tlsPrivateKeyFile = "/run/keys/kaiba-lane-station.key";
      controlServerCAFile = "/run/keys/kaiba-control-server-ca.crt";
      auditServerCAFile = "/run/keys/kaiba-audit-server-ca.crt";
    };
  };

  provisioningAuthorityBridgeHostname = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.controlAddress = "control.example.test";
  };

  provisioningAuthorityBridgeIncomplete = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.auditServerCAFile = null;
  };

  provisioningAuthorityBridgeStoreKey = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.tlsPrivateKeyFile = "${kaibaAuthorityBridgePackage}/client.key";
  };

  provisioningAuthorityBridgeUncleanCredential = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.tlsPrivateKeyFile = "/run/../nix/store/attacker/client.key";
  };

  provisioningAuthorityBridgeSharedCA = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.auditServerCAFile =
      provisioningAuthorityBridge.services.kaiba-provisioning-authority-bridge.controlServerCAFile;
  };

  provisioningAuthorityBridgeIPv6 = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.controlAddress = "2001:db8::10";
  };

  provisioningAuthorityBridgeInvalidAddresses =
    map
      (
        address:
        lib.recursiveUpdate provisioningAuthorityBridge {
          services.kaiba-provisioning-authority-bridge.controlAddress = address;
        }
      )
      [
        "dead:beef"
        "1:::2"
        "::::"
        "abc:def:"
        "::"
        "0:0:0:0:0:0:0:0"
        "::ffff:c000:201"
        "2001:db8::10/64"
      ];

  provisioningAuthorityBridgeLongSocket = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.socketName = "${
      builtins.concatStringsSep "" (builtins.genList (_: "a") 64)
    }.sock";
  };

  provisioningAuthorityBridgeZeroPort = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge.controlPort = 0;
  };

  provisioningAuthorityBridgeInvalidLeaseMargins =
    map
      (
        leaseSafetyMarginSeconds:
        lib.recursiveUpdate provisioningAuthorityBridge {
          services.kaiba-provisioning-authority-bridge = { inherit leaseSafetyMarginSeconds; };
        }
      )
      [
        0
        301
      ];

  provisioningAuthorityBridgeEquivalentOrigins = lib.recursiveUpdate provisioningAuthorityBridge {
    services.kaiba-provisioning-authority-bridge = {
      controlAddress = "::1";
      auditAddress = "0:0:0:0:0:0:0:1";
      auditPort = 8091;
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
    users.users.provisioner.isNormalUser = true;
    services.kaiba-provisioning-lane-guard = {
      enable = true;
      package = kaibaLaneGuardPackage;
      operators = [ "provisioner" ];
    };
  };

  provisioningLaneGuardActiveLow = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard = {
      gpioActiveLow = true;
      gpioOffset = 22;
    };
  };

  provisioningLaneGuardManual = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.powerControl = "manual";
  };

  duplicateLaneGuardOperators = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.operators = [
      "provisioner"
      "provisioner"
    ];
  };

  unsafeLaneOperatorPackage =
    pkgs.runCommand "kaiba-unsafe-lane-operator-fixture"
      {
        passthru.kaibaLaneOperator = {
          authority = "acknowledgement_only";
          directHardwareAccess = true;
          mutationCapable = false;
          operationSelectionCapable = false;
          physicalPathSelectionCapable = false;
        };
      }
      ''
        mkdir -p "$out/bin"
        touch "$out/bin/kaiba-provision-lane-operator"
        chmod 0555 "$out/bin/kaiba-provision-lane-operator"
      '';

  provisioningLaneGuardUnsafeOperator = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.operatorPackage = unsafeLaneOperatorPackage;
  };

  unlinkedLaneGuardPackage = pkgs.runCommand "kaiba-unlinked-lane-guard-fixture" { } ''
    mkdir -p "$out/bin"
    touch "$out/bin/kaiba-provision-lane-guard"
    chmod 0555 "$out/bin/kaiba-provision-lane-guard"
  '';

  staleLineageLaneGuardPackage =
    pkgs.runCommand "kaiba-stale-lineage-lane-guard-fixture"
      {
        passthru.kaibaPhysicalLaneGuard = {
          verifiedSignedRelease = kaibaLaneGuardPackage.kaibaPhysicalLaneGuard.verifiedSignedRelease;
          releaseBindingIdentity = "runtime-verified-content-derived-v1alpha1";
          releaseLineageIdentity = "independently-selected-artifacts-v1alpha1";
        };
        meta.mainProgram = "kaiba-provision-lane-guard";
      }
      ''
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

  provisioningLaneGuardStaleLineage = {
    services.kaiba-provisioning-lane-guard = {
      enable = true;
      package = staleLineageLaneGuardPackage;
    };
  };

  provisioningLaneGuardMutationWithoutBridge = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.enableMutations = true;
  };

  provisioningLaneGuardMutating = lib.recursiveUpdate (lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.enableMutations = true;
  }) provisioningAuthorityBridge;

  provisioningLaneGuardMutatingCustomSocket = lib.recursiveUpdate provisioningLaneGuardMutating {
    services.kaiba-provisioning-authority-bridge = {
      socketName = "lane-authority.sock";
      leaseSafetyMarginSeconds = 47;
    };
  };

  provisioningLaneGuardReconcile = lib.recursiveUpdate provisioningLaneGuardMutating {
    services.kaiba-provisioning-lane-guard.mode = "reconcile";
  };

  provisioningLaneGuardReconcileDisabled = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.mode = "reconcile";
  };

  provisioningLaneGuardStoreJournal = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.journalPath = "${kaibaLaneGuardPackage}/journal.json";
  };

  provisioningLaneGuardNestedDraft = lib.recursiveUpdate provisioningLaneGuard {
    services.kaiba-provisioning-lane-guard.draftPath = "/var/lib/kaiba-provision-lane-guard/reviewed/draft.json";
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

  provisioningSigningGateWithoutPolkit = lib.recursiveUpdate provisioningSigningGate {
    security.polkit.enable = lib.mkForce false;
  };

  provisioningSigningGateWithoutProtectedPcscd = lib.recursiveUpdate provisioningSigningGate {
    services.pcscd.package = lib.mkForce pkgs.pcsclite;
  };

  provisioningSigningGateWithPcscdArgs = lib.recursiveUpdate provisioningSigningGate {
    services.pcscd.extraArgs = [ "--disable-polkit" ];
  };

  probeConfig = evaluateConfig provisioningProbe;
  controlConfig = evaluateConfig provisioningControl;
  controlTLSConfig = evaluateConfig provisioningControlTLS;
  auditConfig = evaluateConfig provisioningAudit;
  auditTLSConfig = evaluateConfig provisioningAuditTLS;
  authorityBridgeConfig = evaluateConfig provisioningAuthorityBridge;
  defaultProbeConfig = evaluateConfig provisioningProbeDefaultPackage;
  disabledProbeConfig = evaluateConfig { };
  stationDemoConfig = evaluateConfig provisioningStationDemo;
  defaultStationDemoConfig = evaluateConfig provisioningStationDemoDefaultPackage;
  stationDemoIPv6Config = evaluateConfig provisioningStationDemoIPv6;
  secureBootTargetConfig = evaluateConfig secureBootTarget;
  laneGuardConfig = evaluateConfig provisioningLaneGuard;
  laneGuardActiveLowConfig = evaluateConfig provisioningLaneGuardActiveLow;
  laneGuardManualConfig = evaluateConfig provisioningLaneGuardManual;
  laneGuardMutatingConfig = evaluateConfig provisioningLaneGuardMutating;
  laneGuardMutatingCustomSocketConfig = evaluateConfig provisioningLaneGuardMutatingCustomSocket;
  laneGuardReconcileConfig = evaluateConfig provisioningLaneGuardReconcile;
  laneGuardNamedModuleConfig = evaluateModules [
    kaibaModules."provisioning-lane-guard"
    provisioningLaneGuardMutating
  ];
  signingGateConfig = evaluateConfig provisioningSigningGate;
  stationDemoService =
    stationDemoConfig.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  stationDemoIPv6Service =
    stationDemoIPv6Config.systemd.services.kaiba-provisioning-station-demo.serviceConfig;
  controlService = controlConfig.systemd.services.kaiba-provisioning-control.serviceConfig;
  controlTLSService = controlTLSConfig.systemd.services.kaiba-provisioning-control.serviceConfig;
  auditService = auditConfig.systemd.services.kaiba-provisioning-audit.serviceConfig;
  auditTLSService = auditTLSConfig.systemd.services.kaiba-provisioning-audit.serviceConfig;
  authorityBridgeService =
    authorityBridgeConfig.systemd.services.kaiba-provisioning-authority-bridge.serviceConfig;
  laneGuardService = laneGuardConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardActiveLowService =
    laneGuardActiveLowConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardManualService =
    laneGuardManualConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardMutatingService =
    laneGuardMutatingConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardMutatingCustomSocketService =
    laneGuardMutatingCustomSocketConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardReconcileService =
    laneGuardReconcileConfig.systemd.services.kaiba-provisioning-lane-guard.serviceConfig;
  laneGuardOperatorSecurityWrapper =
    laneGuardConfig.security.wrappers.kaiba-provision-lane-acknowledge;
  authorityBridgeCustomSocketService =
    laneGuardMutatingCustomSocketConfig.systemd.services.kaiba-provisioning-authority-bridge.serviceConfig;
  signingGateService = signingGateConfig.systemd.services.kaiba-provision-signing-gate.serviceConfig;
  signingGatePolkit = signingGateConfig.security.polkit.extraConfig;

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

  authorityBridgeBoundary =
    authorityBridgeConfig.services.kaiba-provisioning-authority-bridge.package
    == kaibaAuthorityBridgePackage
    && builtins.elem kaibaAuthorityBridgePackage authorityBridgeConfig.environment.systemPackages
    && lib.hasInfix ''"--socket" "/run/kaiba-provision-authority-bridge/bridge.sock"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--control-url" "https://192.0.2.10:8091"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--audit-url" "https://192.0.2.11:8092"'' authorityBridgeService.ExecStart
    && authorityBridgeConfig.services.kaiba-provisioning-authority-bridge.leaseSafetyMarginSeconds == 30
    && lib.hasInfix ''"--lease-safety-margin" "30s"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--tls-cert" "%d/client-cert"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--tls-key" "%d/client-key"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--control-server-ca" "%d/control-server-ca"'' authorityBridgeService.ExecStart
    && lib.hasInfix ''"--audit-server-ca" "%d/audit-server-ca"'' authorityBridgeService.ExecStart
    && authorityBridgeService.DynamicUser
    && authorityBridgeService.Group == "kaiba-provision-bridge"
    && authorityBridgeService.RuntimeDirectory == "kaiba-provision-authority-bridge"
    && authorityBridgeService.RuntimeDirectoryMode == "0750"
    && authorityBridgeService ? ExecStartPost
    && lib.hasInfix "kaiba-provision-authority-bridge-ready" (
      toString authorityBridgeService.ExecStartPost
    )
    && authorityBridgeConfig.users.groups ? kaiba-provision-bridge
    && builtins.elem "client-cert:/run/keys/kaiba-lane-station.crt" authorityBridgeService.LoadCredential
    && builtins.elem "client-key:/run/keys/kaiba-lane-station.key" authorityBridgeService.LoadCredential
    && builtins.elem "control-server-ca:/run/keys/kaiba-control-server-ca.crt" authorityBridgeService.LoadCredential
    && builtins.elem "audit-server-ca:/run/keys/kaiba-audit-server-ca.crt" authorityBridgeService.LoadCredential
    && authorityBridgeService.DevicePolicy == "closed"
    &&
      authorityBridgeService.IPAddressAllow == [
        "192.0.2.10"
        "192.0.2.11"
      ]
    && authorityBridgeService.IPAddressDeny == "any"
    && authorityBridgeService.NoNewPrivileges
    && authorityBridgeService.PrivateDevices
    && authorityBridgeService.ProtectSystem == "strict";

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
    && lib.hasInfix ''"--power-control" "relay"'' laneGuardService.ExecStart
    && lib.hasInfix ''"--power-control" "manual"'' laneGuardManualService.ExecStart
    && !(lib.hasInfix ''"--gpio-chip"'' laneGuardManualService.ExecStart)
    && !(lib.hasInfix ''"--gpio-offset"'' laneGuardManualService.ExecStart)
    && !(lib.hasInfix ''"--gpio-active-low"'' laneGuardManualService.ExecStart)
    && lib.hasInfix ''"--draft" "/var/lib/kaiba-provision-lane-guard/draft.json"'' laneGuardService.ExecStart
    && lib.hasInfix ''"--bridge-socket" "/run/kaiba-provision-authority-bridge/bridge.sock"'' laneGuardService.ExecStart
    && lib.hasInfix ''"--operator-socket" "/run/kaiba-provision-lane-guard/operator.sock"'' laneGuardService.ExecStart
    && lib.hasInfix ''"--operator-group" "kaiba-provision-operator"'' laneGuardService.ExecStart
    && lib.hasInfix ''"--attempt-directory" "/var/lib/kaiba-provision-lane-guard/attempts"'' laneGuardService.ExecStart
    && !(lib.hasInfix ''"--plan"'' laneGuardService.ExecStart)
    && !(lib.hasInfix ''"--request"'' laneGuardService.ExecStart)
    && !(lib.hasInfix "--enable-mutations" laneGuardService.ExecStart)
    && laneGuardService.SupplementaryGroups == [ ]
    && lib.hasInfix "--enable-mutations" laneGuardMutatingService.ExecStart
    && laneGuardMutatingService.SupplementaryGroups == [ "kaiba-provision-bridge" ]
    && lib.hasInfix ''"--socket" "/run/kaiba-provision-authority-bridge/lane-authority.sock"'' authorityBridgeCustomSocketService.ExecStart
    && lib.hasInfix ''"--bridge-socket" "/run/kaiba-provision-authority-bridge/lane-authority.sock"'' laneGuardMutatingCustomSocketService.ExecStart
    && lib.hasInfix ''"--lease-safety-margin" "47s"'' authorityBridgeCustomSocketService.ExecStart
    && lib.hasInfix ''"--lease-safety-margin" "47s"'' laneGuardMutatingCustomSocketService.ExecStart
    && lib.hasInfix ''"--mode" "reconcile"'' laneGuardReconcileService.ExecStart
    && lib.hasInfix "--enable-mutations" laneGuardReconcileService.ExecStart
    &&
      laneGuardMutatingConfig.systemd.services.kaiba-provisioning-lane-guard.requires
      == [ "kaiba-provisioning-authority-bridge.service" ]
    && laneGuardService.User == "root"
    && laneGuardService.Group == "kaiba-provision-operator"
    &&
      laneGuardService.StateDirectory == [
        "kaiba-provision-lane-guard"
        "kaiba-provision-lane-guard/attempts"
      ]
    && laneGuardService.StateDirectoryMode == "0700"
    && laneGuardService.RuntimeDirectory == "kaiba-provision-lane-guard"
    && laneGuardService.RuntimeDirectoryMode == "0750"
    && laneGuardConfig.users.groups ? kaiba-provision-operator
    && builtins.elem "kaiba-provision-operator" laneGuardConfig.users.users.provisioner.extraGroups
    && laneGuardOperatorSecurityWrapper.owner == "root"
    && laneGuardOperatorSecurityWrapper.group == "kaiba-provision-operator"
    && laneGuardOperatorSecurityWrapper.setuid == false
    && laneGuardOperatorSecurityWrapper.setgid == true
    && laneGuardOperatorSecurityWrapper.permissions == "u+rx,g+rx,o-rwx"
    && laneGuardOperatorSecurityWrapper.capabilities == ""
    && builtins.elem "d /var/lib/kaiba-provision-lane-guard 0700 root kaiba-provision-operator -" laneGuardConfig.systemd.tmpfiles.rules
    && builtins.elem "d /var/lib/kaiba-provision-lane-guard/attempts 0700 root kaiba-provision-operator -" laneGuardConfig.systemd.tmpfiles.rules
    && laneGuardService.TimeoutStartSec == "65min"
    && laneGuardService.TimeoutStopSec == "45s"
    && laneGuardManualService.TimeoutStopSec == "3min"
    && builtins.length laneGuardService.ExecStartPre == 2
    && lib.hasInfix "/sys/module/pinctrl_rp1/parameters/persist_gpio_outputs" (
      builtins.elemAt laneGuardService.ExecStartPre 0
    )
    && lib.hasInfix ''"--fixed-strings" "--line-regexp" "N"'' (
      builtins.elemAt laneGuardService.ExecStartPre 0
    )
    && lib.hasInfix ''"--chip" "/dev/gpiochip0"'' (builtins.elemAt laneGuardService.ExecStartPre 1)
    && lib.hasInfix ''"--consumer" "kaiba-provision-lane-guard-inactive"'' (
      builtins.elemAt laneGuardService.ExecStartPre 1
    )
    && lib.hasInfix ''"--hold-period" "100ms" "--toggle" "0" "0=0"'' (
      builtins.elemAt laneGuardService.ExecStartPre 1
    )
    && laneGuardService.ExecStopPost == builtins.elemAt laneGuardService.ExecStartPre 1
    && lib.hasInfix ''"--active-low" "--hold-period" "100ms" "--toggle" "0" "22=0"'' laneGuardActiveLowService.ExecStopPost
    && laneGuardManualService.ExecStartPre == [ ]
    && laneGuardManualService.ExecStopPost == [ ]
    && laneGuardService.DevicePolicy == "closed"
    && builtins.elem "/dev/gpiochip0 rw" laneGuardService.DeviceAllow
    && !(builtins.elem "/dev/gpiochip0 rw" laneGuardManualService.DeviceAllow)
    && builtins.elem "/dev/serial/by-id/kaiba-target-uart r" laneGuardManualService.DeviceAllow
    && builtins.elem "char-usb_device rw" laneGuardManualService.DeviceAllow
    && builtins.elem "/dev/serial/by-id/kaiba-target-uart r" laneGuardService.DeviceAllow
    && builtins.elem "char-usb_device rw" laneGuardService.DeviceAllow
    && laneGuardService.IPAddressDeny == "any"
    && laneGuardService.ProtectSystem == "strict"
    && laneGuardConfig.systemd.services.kaiba-provisioning-lane-guard.wantedBy == [ ];

  signingServiceBoundary =
    signingGateConfig.services.pcscd.enable
    && signingGateConfig.security.polkit.enable
    && signingGateConfig.services.pcscd.package == pkgs.pcscliteWithPolkit
    && signingGateConfig.services.pcscd.extraArgs == [ ]
    && lib.hasInfix ''subject.user == "kaiba-signing"'' signingGatePolkit
    && lib.hasInfix ''action.id == "org.debian.pcsc-lite.access_pcsc"'' signingGatePolkit
    && lib.hasInfix ''action.id == "org.debian.pcsc-lite.access_card"'' signingGatePolkit
    && !(lib.hasInfix "subject.isInGroup" signingGatePolkit)
    && !disabledProbeConfig.security.polkit.enable
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
assert lib.assertMsg (assertionsPass provisioningAuthorityBridge) (
  builtins.toJSON (failedMessages provisioningAuthorityBridge)
);
assert lib.assertMsg (assertionsPass provisioningAuthorityBridgeIPv6) (
  builtins.toJSON (failedMessages provisioningAuthorityBridgeIPv6)
);
assert lib.assertMsg (builtins.all (module: !assertionsPass module)
  provisioningAuthorityBridgeInvalidAddresses
) "an invalid or wildcard authority-bridge IP literal was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeLongSocket
) "an authority-bridge Unix socket path exceeding the Go limit was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeZeroPort
) "an authority-bridge endpoint using TCP port zero was accepted";
assert lib.assertMsg (builtins.all
  (
    module:
    !(builtins.tryEval (
      (evaluateConfig module).services.kaiba-provisioning-authority-bridge.leaseSafetyMarginSeconds
    )).success
  )
  provisioningAuthorityBridgeInvalidLeaseMargins
) "an authority-bridge lease safety margin outside 1 through 300 seconds was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeEquivalentOrigins
) "equivalent IPv6 spellings of one authority origin were accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeHostname
) "an authority bridge with an ambient-DNS endpoint was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeIncomplete
) "an authority bridge with incomplete TLS authority was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeStoreKey
) "an authority bridge with a Nix-store client key was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeUncleanCredential
) "an authority bridge with an unclean credential path was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningAuthorityBridgeSharedCA
) "an authority bridge with one shared control/audit CA path was accepted";
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
assert lib.assertMsg (assertionsPass provisioningLaneGuardMutatingCustomSocket) (
  builtins.toJSON (failedMessages provisioningLaneGuardMutatingCustomSocket)
);
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardMutationWithoutBridge
) "a mutation-enabled lane guard without the authenticated bridge was accepted";
assert lib.assertMsg (assertionsPass provisioningLaneGuardReconcile) (
  builtins.toJSON (failedMessages provisioningLaneGuardReconcile)
);
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardReconcileDisabled
) "a reconciliation-mode lane guard with physical operation disabled was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardUnlinked
) "a generic lane-guard package without immutable physical configuration was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardStaleLineage
) "a stale marker-bearing lane-guard package without single-release lineage was accepted";
assert lib.assertMsg (builtins.all (assertion: assertion.assertion)
  laneGuardNamedModuleConfig.assertions
) "the named lane-guard module did not import and couple its authority-bridge dependency";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardStoreJournal
) "a Nix-store lane-guard journal was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardNestedDraft
) "a lane-guard draft with an unbootstrapped nested parent was accepted";
assert lib.assertMsg (assertionsPass provisioningSigningGate) (
  builtins.toJSON (failedMessages provisioningSigningGate)
);
assert lib.assertMsg (
  !assertionsPass provisioningSigningGateStorePIN
) "a Nix-store YubiKey PIN was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningSigningGateWithoutPolkit
) "a YubiKey signing gate without polkit was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningSigningGateWithoutProtectedPcscd
) "a YubiKey signing gate with a non-polkit PC/SC daemon was accepted";
assert lib.assertMsg (
  !assertionsPass provisioningSigningGateWithPcscdArgs
) "a YubiKey signing gate with unsafe pcscd arguments was accepted";
assert lib.assertMsg (
  !assertionsPass duplicateProbeOperators
) "duplicate probe operators were accepted";
assert lib.assertMsg (
  !assertionsPass duplicateLaneGuardOperators
) "duplicate lane-guard operators were accepted";
assert lib.assertMsg (
  !assertionsPass provisioningLaneGuardUnsafeOperator
) "a lane operator package with direct hardware access was accepted";
assert lib.assertMsg probeBoundary
  "provisioning probe package, group, or narrow udev boundary is not enforced";
assert lib.assertMsg referenceServiceBoundary
  "provisioning control or audit persistence, loopback, or sandbox boundary is not enforced";
assert lib.assertMsg referenceServiceTLSBoundary
  "provisioning control or audit mutual-TLS credential boundary is not enforced";
assert lib.assertMsg authorityBridgeBoundary
  "authenticated authority-bridge network, credential, socket, or sandbox boundary is not enforced";
assert lib.assertMsg stationDemoBoundary
  "provisioning-station demo loopback, sandbox, or no-USB boundary is not enforced";
assert lib.assertMsg secureBootTargetBoundary
  "secure-boot target dm-verity, no-enrollment, or runtime evidence boundary is not enforced";
assert lib.assertMsg physicalServiceBoundary
  "physical lane-guard mutation opt-in, device, or root service boundary is not enforced";
assert lib.assertMsg signingServiceBoundary
  "YubiKey signer credential, PC/SC, user, or sandbox boundary is not enforced";
pkgs.runCommand "kaiba-provisioning-module-evaluation" { } ''
  operator_wrapper_source=${laneGuardOperatorSecurityWrapper.source}
  test -x "$operator_wrapper_source"
  ${pkgs.file}/bin/file -b "$operator_wrapper_source" | grep -E '^ELF ' > /dev/null
  grep -F -- 'kaiba-provision-lane-operator' "$operator_wrapper_source" > /dev/null
  grep -F -- '--socket' "$operator_wrapper_source" > /dev/null
  grep -F -- '/run/kaiba-provision-lane-guard/operator.sock' "$operator_wrapper_source" > /dev/null
  ! grep -F -- '/bin/sg' "$operator_wrapper_source"
  set +e
  "$operator_wrapper_source" unexpected > wrapper.stdout 2> wrapper.stderr
  wrapper_status="$?"
  set -e
  test "$wrapper_status" -eq 2
  test ! -s wrapper.stdout
  grep -Fx 'usage: kaiba-provision-lane-acknowledge' wrapper.stderr > /dev/null

  mkdir -p "$out"
  printf '%s\n' \
    'provisioning-probe-module: pass' \
    'provisioning-probe-usb-boundary: pass' \
    'provisioning-control-loopback-persistence: pass' \
    'provisioning-audit-loopback-persistence: pass' \
    'provisioning-control-audit-mutual-tls: pass' \
    'provisioning-authority-bridge-authenticated-ipc: pass' \
    'provisioning-station-demo-module: pass' \
    'provisioning-station-demo-loopback-only: pass' \
    'provisioning-station-demo-sandbox-and-no-usb: pass' \
    'secure-boot-target-dm-verity-boundary: pass' \
    'secure-boot-target-enrollment-blocked: pass' \
    'physical-lane-guard-explicit-mutation-boundary: pass' \
    'yubikey-signing-gate-credential-boundary: pass' \
    'yubikey-signing-gate-pcsc-authorization: pass' \
    > "$out/results.txt"
''
