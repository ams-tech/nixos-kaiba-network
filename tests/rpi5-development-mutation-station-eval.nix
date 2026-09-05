{
  bindingGuardA,
  bindingGuardB,
  directMutationStation,
  lib,
  mismatchedReleaseIntentSourceRevisionRejected,
  mismatchedUnsignedArtifactSourceRevisionRejected,
  mutationStation,
  nativeCredentialPacketValidator,
  noncanonicalPayloadSourceRevisionRejected,
  pkgs,
  sourceRevision,
}:

let
  imageConfig = mutationStation.nixosSystem.config;
  lane = imageConfig.services.kaiba-provisioning-lane-guard;
  bridge = imageConfig.services.kaiba-provisioning-authority-bridge;
  laneUnit = imageConfig.systemd.services.kaiba-provisioning-lane-guard;
  bridgeUnit = imageConfig.systemd.services.kaiba-provisioning-authority-bridge;
  credentialAdmissionUnit =
    imageConfig.systemd.services.kaiba-provisioning-authority-credential-admission;
  admissionUnit = imageConfig.systemd.services.kaiba-provisioning-manual-lane-admission;
  systemPackageNames = map lib.getName imageConfig.environment.systemPackages;
  stationLaneWorkflow = lib.findFirst (
    package: lib.getName package == "kaiba-provision-lane-workflow"
  ) null imageConfig.environment.systemPackages;
  stationCredentialPacketValidator = stationLaneWorkflow.kaibaCredentialPacketValidator;

  hardwareContract =
    imageConfig.nixpkgs.hostPlatform.system == "aarch64-linux"
    && imageConfig.boot.loader.raspberry-pi.variant == "5"
    && imageConfig.boot.loader.raspberry-pi.bootloader == "kernel"
    && lib.isDerivation mutationStation.sdImage
    && imageConfig.image.baseName == "kaiba-rpi5-development-mutation-station"
    && imageConfig.sdImage.compressImage
    && imageConfig.sdImage.expandOnBoot
    && !imageConfig.hardware.enableAllHardware;

  fixedLaneContract =
    lane.enable
    && lane.package == mutationStation.physicalLaneGuard
    && lane.package ? kaibaPhysicalLaneGuard
    && lane.operators == [ "provisioner" ]
    && lane.stationID == "kaiba-rpi5-provisioner"
    && lane.laneID == "lane-1"
    && lane.rpibootSysfsPath == "/sys/bus/usb/devices/3-1"
    &&
      lane.uartPath == "/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E663B035973F3F26-if01"
    && lane.powerControl == "manual"
    && lane.enableMutations
    && lane.mode == "execute"
    && lib.hasInfix ''"--power-control" "manual"'' laneUnit.serviceConfig.ExecStart
    && lib.hasInfix ''"--enable-mutations"'' laneUnit.serviceConfig.ExecStart
    && !(lib.hasInfix "--gpio-" laneUnit.serviceConfig.ExecStart)
    && laneUnit.wantedBy == [ ]
    && laneUnit.serviceConfig.ExecStartPre == [ ]
    && laneUnit.serviceConfig.ExecStopPost == [ ]
    && !(builtins.any (rule: lib.hasInfix "gpiochip" rule) laneUnit.serviceConfig.DeviceAllow);

  manualAdmissionContract =
    mutationStation.metadata.manualLaneQualificationDigest
    == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    && builtins.elem "kaiba-provisioning-manual-lane-admission.service" laneUnit.requires
    && builtins.elem "kaiba-provisioning-manual-lane-admission.service" laneUnit.after
    && admissionUnit.wantedBy == [ ]
    && lib.hasInfix "kaiba-mutation-manual-lane-admission" admissionUnit.serviceConfig.ExecStart
    && builtins.elem "d /var/lib/kaiba-provisioning-evidence 0700 root root - -" imageConfig.systemd.tmpfiles.rules
    &&
      imageConfig.environment.etc."kaiba-provisioning/manual-lane-qualification-digest".text
      == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    &&
      imageConfig.environment.etc."kaiba-provisioning/manual-lane-qualification-source-revision".text
      == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    &&
      mutationStation.metadata.acceptedTargetFingerprint
      == "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    &&
      mutationStation.metadata.hardwareQualificationDigest
      == "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    &&
      imageConfig.environment.etc."kaiba-provisioning/accepted-target-fingerprint".text
      == "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
    &&
      imageConfig.environment.etc."kaiba-provisioning/hardware-qualification-digest".text
      == "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n"
    &&
      mutationStation.metadata.unfusedCompatibilityUARTDigest
      == "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    &&
      imageConfig.environment.etc."kaiba-provisioning/unfused-compatibility-uart-digest".text
      == "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n";

  authorityContract =
    bridge.enable
    && bridge.controlAddress == "192.168.8.249"
    && bridge.controlPort == 8091
    && bridge.auditAddress == "192.168.8.249"
    && bridge.auditPort == 8092
    &&
      bridge.controlServerCAFile == "/var/lib/kaiba-provisioning-credentials/bridge/control-server-ca.crt"
    && bridge.auditServerCAFile == "/var/lib/kaiba-provisioning-credentials/bridge/audit-server-ca.crt"
    && bridge.tlsCertificateFile == "/var/lib/kaiba-provisioning-credentials/bridge/station-client.crt"
    && bridge.tlsPrivateKeyFile == "/var/lib/kaiba-provisioning-credentials/bridge/station-client.key"
    && bridgeUnit.wantedBy == [ ]
    && credentialAdmissionUnit.wantedBy == [ ]
    && builtins.elem "kaiba-provisioning-authority-credential-admission.service" bridgeUnit.requires
    && builtins.elem "kaiba-provisioning-authority-credential-admission.service" bridgeUnit.after
    && lib.hasInfix "kaiba-mutation-authority-credential-admission" credentialAdmissionUnit.serviceConfig.ExecStart
    && builtins.elem "kaiba-provisioning-authority-bridge.service" laneUnit.requires
    && builtins.elem "kaiba-provisioning-authority-bridge.service" laneUnit.after
    && lib.isDerivation stationCredentialPacketValidator
    && stationCredentialPacketValidator.system == imageConfig.nixpkgs.hostPlatform.system
    && lib.isDerivation nativeCredentialPacketValidator
    && nativeCredentialPacketValidator.system == pkgs.stdenv.hostPlatform.system;

  manualBoundary =
    !(builtins.hasAttr "kaiba-relay-gpio" imageConfig.users.groups)
    && !(builtins.elem "gpio" imageConfig.users.users.provisioner.extraGroups)
    && !(builtins.elem "libgpiod" systemPackageNames)
    && !(builtins.any (rule: lib.hasInfix "gpiochip" rule) imageConfig.systemd.tmpfiles.rules)
    && !(lib.hasInfix "gpiochip-kaiba-rp1" imageConfig.services.udev.extraRules);

  operatorContract =
    imageConfig.users.allowNoPasswordLogin
    && !imageConfig.users.mutableUsers
    && imageConfig.users.users.root.hashedPassword == "!"
    && imageConfig.users.users.provisioner.hashedPassword == "!"
    && builtins.elem "wheel" imageConfig.users.users.provisioner.extraGroups
    && imageConfig.security.sudo.enable
    && !imageConfig.security.sudo.wheelNeedsPassword
    && imageConfig.services.getty.autologinUser == "provisioner"
    && imageConfig.services.openssh.enable
    && imageConfig.services.openssh.settings.AuthenticationMethods == "publickey"
    && !imageConfig.services.openssh.settings.PasswordAuthentication
    && imageConfig.services.openssh.settings.PermitRootLogin == "no";

  persistenceContract =
    imageConfig.swapDevices == [ ]
    && !imageConfig.zramSwap.enable
    && !imageConfig.systemd.coredump.enable
    && lib.hasInfix "Storage=persistent" imageConfig.services.journald.extraConfig
    && builtins.elem "d /var/lib/kaiba-provisioning-credentials 0700 root root - -" imageConfig.systemd.tmpfiles.rules
    && builtins.elem "d /var/lib/kaiba-provisioning-credentials/bridge 0700 root root - -" imageConfig.systemd.tmpfiles.rules
    && builtins.elem "d /home/provisioner/.config/kaiba-provisioning/lane-workflow 0700 provisioner provisioner - -" imageConfig.systemd.tmpfiles.rules
    && !imageConfig.nix.enable
    && imageConfig.system.disableInstallerTools
    && !imageConfig.system.switch.enable
    && !imageConfig.systemd.services.register-nix-paths.enable
    && !(builtins.elem "nix" systemPackageNames)
    && !(builtins.elem "nixos-rebuild" systemPackageNames);

  provenanceContract =
    imageConfig.environment.etc."NIXOS".text == ""
    && imageConfig.environment.etc."kaiba-provisioning/source-revision".text == "${sourceRevision}\n"
    &&
      imageConfig.environment.etc."kaiba-provisioning/payload-source-revision".text
      == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    &&
      imageConfig.environment.etc."kaiba-provisioning/recovery-tool-source-revision".text
      == "${sourceRevision}\n"
    && imageConfig.system.configurationRevision == sourceRevision
    && builtins.elem "kaiba-mutation-release-binding" systemPackageNames
    && builtins.elem "kaiba-mutation-station-inventory" systemPackageNames
    && builtins.elem "kaiba-provision-lane-workflow" systemPackageNames;
  recoveredLineageContract =
    mutationStation.metadata.payloadSourceRevision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    &&
      mutationStation.physicalLaneGuard.kaibaPhysicalLaneGuard.verifiedSignedRelease
      == mutationStation.nixosSystem.config.services.kaiba-provisioning-lane-guard.package.kaibaPhysicalLaneGuard.verifiedSignedRelease;
  rejectedLineageInputsContract =
    noncanonicalPayloadSourceRevisionRejected
    && mismatchedReleaseIntentSourceRevisionRejected
    && mismatchedUnsignedArtifactSourceRevisionRejected;
  qualificationBindingContract = toString bindingGuardA != toString bindingGuardB;
  directConfig = directMutationStation.nixosSystem.config;
  directSystemPackageNames = map lib.getName directConfig.environment.systemPackages;
  directOperatorCommand = lib.findFirst (
    package: lib.getName package == "kaiba-secure-boot"
  ) null directConfig.environment.systemPackages;
  directOperatorSudoCommands = builtins.concatMap (
    rule:
    if builtins.elem directMutationStation.metadata.operatorName (rule.users or [ ]) then
      rule.commands
    else
      [ ]
  ) directConfig.security.sudo.extraRules;
  directStationContract =
    directConfig.nixpkgs.hostPlatform.system == "aarch64-linux"
    && directConfig.networking.hostName == "kaiba-rpi5-secure-boot-station"
    && directConfig.image.baseName == "kaiba-rpi5-development-secure-boot-station"
    && lib.isDerivation directMutationStation.sdImage
    && directMutationStation.secureBootRunner ? kaibaDevelopmentSecureBoot
    && directMutationStation.operationalPayload ? kaibaDevelopmentSecureBootOperationalPayload
    &&
      directMutationStation.secureBootRunner.kaibaDevelopmentSecureBoot.operationalPayload
      == directMutationStation.operationalPayload
    && !directMutationStation.operationalPayload.kaibaDevelopmentSecureBootOperationalPayload.privateKeyAccess
    && !directMutationStation.operationalPayload.kaibaDevelopmentSecureBootOperationalPayload.signingCapable
    && !directMutationStation.secureBootRunner.kaibaDevelopmentSecureBoot.remoteAuthorityRequired
    && !directMutationStation.secureBootRunner.kaibaDevelopmentSecureBoot.signingCapable
    && directMutationStation.metadata.command == "kaiba-secure-boot provision"
    && !directMutationStation.metadata.automaticAtBoot
    && directMutationStation.metadata.execution == "operator_foreground"
    && !directMutationStation.metadata.remoteAuthorityRequired
    && !directMutationStation.metadata.signingCapable
    && builtins.elem "kaiba-secure-boot" directSystemPackageNames
    && builtins.elem "kaiba-secure-boot-inventory" directSystemPackageNames
    && lib.isDerivation directOperatorCommand
    && directConfig.security.wrapperDir == "/run/wrappers/bin"
    && directOperatorCommand.kaibaSecureBootOperatorCommand.privilegeWrapper == "/run/wrappers/bin/sudo"
    && lib.hasPrefix "exec /run/wrappers/bin/sudo -- " directOperatorCommand.kaibaSecureBootOperatorCommand.script
    && !(lib.hasInfix "-sudo-" directOperatorCommand.kaibaSecureBootOperatorCommand.script)
    && !(builtins.elem "kaiba-provision-lane-workflow" directSystemPackageNames)
    && !(builtins.elem "kaiba-mutation-release-binding" directSystemPackageNames)
    && builtins.length directOperatorSudoCommands == 1
    && lib.hasInfix "kaiba-rpi5-development-secure-boot" (builtins.head directOperatorSudoCommands)
    .command
    && builtins.elem "NOPASSWD" (builtins.head directOperatorSudoCommands).options
    && !(builtins.hasAttr "kaiba-development-secure-boot" directConfig.systemd.services)
    && lib.hasInfix "run: kaiba-secure-boot provision" directConfig.environment.etc.issue.text
    && directConfig.i18n.defaultLocale == "C.UTF-8"
    && builtins.elem "d /var/lib/kaiba-development-secure-boot 0700 root root - -" directConfig.systemd.tmpfiles.rules
    && directConfig.swapDevices == [ ]
    && !directConfig.zramSwap.enable
    && !directConfig.nix.enable
    && directConfig.system.disableInstallerTools
    && !directConfig.system.switch.enable;
in
assert lib.assertMsg hardwareContract
  "the development mutation station hardware or image contract changed";
assert lib.assertMsg fixedLaneContract
  "the development mutation station fixed manual lane contract changed";
assert lib.assertMsg authorityContract
  "the development mutation station authority bridge contract changed";
assert lib.assertMsg manualAdmissionContract
  "the development mutation station manual-lane admission contract changed";
assert lib.assertMsg manualBoundary
  "the development mutation station unexpectedly exposes relay or GPIO authority";
assert lib.assertMsg operatorContract
  "the development mutation station operator access contract changed";
assert lib.assertMsg persistenceContract
  "the development mutation station persistent evidence contract changed";
assert lib.assertMsg provenanceContract
  "the development mutation station provenance or workflow contract changed";
assert lib.assertMsg recoveredLineageContract
  "the development mutation station recovered payload lineage changed";
assert lib.assertMsg rejectedLineageInputsContract
  "the development mutation station accepted an invalid payload lineage";
assert lib.assertMsg qualificationBindingContract
  "the manual-lane qualification digest did not change the physical guard package identity";
assert lib.assertMsg directStationContract
  "the direct development secure-boot station contract changed";
pkgs.runCommand "kaiba-rpi5-development-mutation-station-evaluation"
  {
    nativeBuildInputs = [
      pkgs.check-jsonschema
      pkgs.coreutils
      pkgs.jq
    ];
  }
  ''
    schema=${../provisioning/schemas/rpi5-manual-lane-qualification-v1alpha1.schema.json}
    fixture=${./fixtures/rpi5-manual-lane-qualification.json}

    check-jsonschema --check-metaschema "$schema"
    check-jsonschema --schemafile "$schema" "$fixture"

    fixture_digest="$(sha256sum "$fixture" | cut -d ' ' -f 1)"
    jq '.production_qualified = true' "$fixture" > unsafe.json
    unsafe_digest="$(sha256sum unsafe.json | cut -d ' ' -f 1)"
    test "$fixture_digest" != "$unsafe_digest"
    if check-jsonschema --schemafile "$schema" unsafe.json; then
      echo "manual-lane schema accepted a production qualification claim" >&2
      exit 1
    fi

    jq '.rpiboot_sysfs_path = "/sys/bus/usb/devices/9-9"' "$fixture" > changed-path.json
    test "$fixture_digest" != "$(sha256sum changed-path.json | cut -d ' ' -f 1)"

    binding_a="$(${bindingGuardA}/bin/kaiba-provision-lane-guard \
      --print-release-binding | jq -er .lane_guard_package_digest)"
    binding_b="$(${bindingGuardB}/bin/kaiba-provision-lane-guard \
      --print-release-binding | jq -er .lane_guard_package_digest)"
    test "$binding_a" != "$binding_b"

    credential_validator=${nativeCredentialPacketValidator}/bin/kaiba-validate-mutation-credential-packet
    mkdir credential-packet
    for credential in \
      audit-server-ca.crt \
      control-server-ca.crt \
      station-client.crt \
      station-client.key; do
      printf '%s\n' "$credential" > "credential-packet/$credential"
    done
    (
      cd credential-packet
      sha256sum \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt \
        station-client.key > SHA256SUMS
    )
    "$credential_validator" validate-manifest credential-packet

    cp -R credential-packet omitted-entry
    (
      cd omitted-entry
      sha256sum \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt > SHA256SUMS
    )
    if "$credential_validator" validate-manifest omitted-entry; then
      echo "credential manifest validator accepted an omitted entry" >&2
      exit 1
    fi

    cp -R credential-packet duplicate-entry
    (
      cd duplicate-entry
      sha256sum \
        audit-server-ca.crt \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt > SHA256SUMS
    )
    if "$credential_validator" validate-manifest duplicate-entry; then
      echo "credential manifest validator accepted a duplicate entry" >&2
      exit 1
    fi

    printf '%s\n' outside-packet > outside-packet.key
    cp -R credential-packet parent-path-entry
    (
      cd parent-path-entry
      sha256sum \
        audit-server-ca.crt \
        control-server-ca.crt \
        station-client.crt \
        ../outside-packet.key > SHA256SUMS
    )
    if "$credential_validator" validate-manifest parent-path-entry; then
      echo "credential manifest validator accepted a parent-relative entry" >&2
      exit 1
    fi

    printf '%s\n' control-ca > control-ca.crt
    printf '%s\n' audit-ca > audit-ca.crt
    "$credential_validator" require-distinct-cas control-ca.crt audit-ca.crt
    if "$credential_validator" require-distinct-cas control-ca.crt control-ca.crt; then
      echo "credential CA validator accepted identical inputs" >&2
      exit 1
    fi
    if "$credential_validator" require-distinct-cas control-ca.crt missing-ca.crt; then
      echo "credential CA validator accepted a comparison error" >&2
      exit 1
    fi

    mkdir -p "$out"
    printf '%s\n' \
      'rpi5-mutation-image: pass' \
      'fixed-manual-lane: pass' \
      'authenticated-authority-bridge: pass' \
      'reviewed-manual-lane-admission: pass' \
      'no-relay-gpio-service-authority: pass' \
      'development-operator-boundary: pass' \
      'persistent-attempt-evidence: pass' \
      'release-and-source-provenance: pass' \
      'recovered-payload-lineage: pass' \
      'invalid-payload-lineage-rejection: pass' \
      'manual-lane-digest-plan-binding: pass' \
      'credential-packet-admission: pass' \
      > "$out/results.txt"
  ''
