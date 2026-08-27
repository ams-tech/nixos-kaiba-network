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
    mkOption
    types
    ;

  cfg = config.services.kaiba-provisioning-authority-bridge;
  defaultPackage = (import ../packages.nix { inherit pkgs lib; }).authorityBridge;
  bridgeClientGroup = "kaiba-provision-bridge";
  runtimeDirectory = "kaiba-provision-authority-bridge";
  socketPath = "/run/${runtimeDirectory}/${cfg.socketName}";
  ipv4Octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  unspecifiedIPv6 = "0:0:0:0:0:0:0:0";
  isIPv4Address = address: builtins.match "${ipv4Octet}(\\.${ipv4Octet}){3}" address != null;
  parsedIPv6Address = address: builtins.tryEval ((lib.network.ipv6.fromString address).address);
  canonicalAddress =
    address:
    let
      parsedIPv6 = parsedIPv6Address address;
    in
    if isIPv4Address address then
      address
    else if !lib.hasInfix "/" address && parsedIPv6.success then
      parsedIPv6.value
    else
      address;
  looksLikeConcreteIP =
    address:
    let
      parsedIPv6 = parsedIPv6Address address;
    in
    (
      isIPv4Address address
      || (
        !lib.hasInfix "/" address
        && parsedIPv6.success
        && parsedIPv6.value != unspecifiedIPv6
        && !lib.hasPrefix "0:0:0:0:0:ffff:" parsedIPv6.value
      )
    )
    && address != "0.0.0.0";
  endpoint =
    address: port:
    let
      canonical = canonicalAddress address;
    in
    if lib.hasInfix ":" canonical then
      "https://[${canonical}]:${toString port}"
    else
      "https://${canonical}:${toString port}";
  credentialFiles = [
    cfg.tlsCertificateFile
    cfg.tlsPrivateKeyFile
    cfg.controlServerCAFile
    cfg.auditServerCAFile
  ];
  credentialsConfigured = builtins.all (path: path != null) credentialFiles;
  isCleanCredentialPath =
    path:
    let
      components = lib.drop 1 (lib.splitString "/" path);
    in
    path != null
    && hasPrefix "/" path
    && builtins.all (component: component != "" && component != "." && component != "..") components
    && path != builtins.storeDir
    && !hasPrefix "${builtins.storeDir}/" path;
  credentialsSafe = builtins.all isCleanCredentialPath credentialFiles;
  args = [
    (getExe' cfg.package "kaiba-provision-authority-bridge")
    "--socket"
    socketPath
    "--control-url"
    (endpoint cfg.controlAddress cfg.controlPort)
    "--audit-url"
    (endpoint cfg.auditAddress cfg.auditPort)
    "--lease-safety-margin"
    "${toString cfg.leaseSafetyMarginSeconds}s"
  ];
  credentialArgs = ''"--tls-cert" "%d/client-cert" "--tls-key" "%d/client-key" "--control-server-ca" "%d/control-server-ca" "--audit-server-ca" "%d/audit-server-ca"'';
  readinessCheck = pkgs.writeShellScript "kaiba-provision-authority-bridge-ready" ''
    set -eu

    attempt=0
    while [ "$attempt" -lt 150 ]; do
      if [ -S ${lib.escapeShellArg socketPath} ]; then
        exit 0
      fi
      attempt=$((attempt + 1))
      ${pkgs.coreutils}/bin/sleep 0.1
    done

    echo "authority bridge did not create ${socketPath}" >&2
    exit 1
  '';
in
{
  options.services.kaiba-provisioning-authority-bridge = {
    enable = mkEnableOption "the authenticated control/audit to physical-lane authority bridge";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "the kaiba-provision-authority-bridge package from the provisioning source tree";
      example = lib.literalExpression "inputs.kaiba-provisioning.packages.\${pkgs.system}.kaiba-provision-authority-bridge";
      description = "Package containing bin/kaiba-provision-authority-bridge.";
    };

    controlAddress = mkOption {
      type = types.str;
      example = "192.0.2.10";
      description = "Concrete control-service IP address authenticated by its server certificate.";
    };

    controlPort = mkOption {
      type = types.port;
      default = 8091;
      description = "Mutual-TLS control-service port.";
    };

    auditAddress = mkOption {
      type = types.str;
      example = "192.0.2.11";
      description = "Concrete audit-service IP address authenticated by its server certificate.";
    };

    auditPort = mkOption {
      type = types.port;
      default = 8092;
      description = "Mutual-TLS audit-service port.";
    };

    tlsCertificateFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-lane-station.crt";
      description = ''
        Runtime PEM certificate containing the fixed station/lane URI SAN.
        systemd supplies it with LoadCredential; it is never imported into the
        Nix store.
      '';
    };

    tlsPrivateKeyFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-lane-station.key";
      description = "Runtime private key for the station/lane client certificate.";
    };

    controlServerCAFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-control-server-ca.crt";
      description = "Exclusive runtime trust root for the control service.";
    };

    auditServerCAFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-audit-server-ca.crt";
      description = "Exclusive runtime trust root for the independent audit service.";
    };

    socketName = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\.sock";
      default = "bridge.sock";
      description = "Socket filename in the bridge's private systemd RuntimeDirectory.";
    };

    leaseSafetyMarginSeconds = mkOption {
      type = types.ints.between 1 300;
      default = 30;
      description = "Lease lifetime, from 1 through 300 seconds, reserved beyond the current operation's maximum duration.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = looksLikeConcreteIP cfg.controlAddress && looksLikeConcreteIP cfg.auditAddress;
        message = ''
          authority-bridge controlAddress and auditAddress must be concrete,
          non-wildcard IP literals; DNS, redirects, and ambient proxy routing
          are outside this fixed authority boundary.
        '';
      }
      {
        assertion = endpoint cfg.controlAddress cfg.controlPort != endpoint cfg.auditAddress cfg.auditPort;
        message = "authority-bridge control and audit endpoints must be distinct";
      }
      {
        assertion = cfg.controlPort > 0 && cfg.auditPort > 0;
        message = "authority-bridge control and audit ports must be from 1 through 65535";
      }
      {
        assertion = credentialsConfigured && credentialsSafe;
        message = ''
          authority-bridge TLS requires absolute non-store client certificate,
          private-key, control-server-CA, and audit-server-CA paths.
        '';
      }
      {
        assertion = cfg.controlServerCAFile != cfg.auditServerCAFile;
        message = "authority-bridge control and audit server CA paths must be distinct";
      }
      {
        assertion = builtins.stringLength socketPath <= 100;
        message = "authority-bridge socketName makes the full Unix socket path exceed 100 bytes";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    users.groups.${bridgeClientGroup} = { };

    systemd.services.kaiba-provisioning-authority-bridge = {
      description = "Authenticated Kaiba physical-lane authority bridge";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        # Keep systemd's %d credential-directory specifier intact. The generic
        # argument escaper deliberately turns it into %%d, so append only these
        # fixed, module-owned arguments after escaping every configurable one.
        ExecStart = (utils.escapeSystemdExecArgs args) + " ${credentialArgs}";
        ExecStartPost = readinessCheck;
        DynamicUser = true;
        Group = bridgeClientGroup;
        LoadCredential = [
          "client-cert:${cfg.tlsCertificateFile}"
          "client-key:${cfg.tlsPrivateKeyFile}"
          "control-server-ca:${cfg.controlServerCAFile}"
          "audit-server-ca:${cfg.auditServerCAFile}"
        ];
        RuntimeDirectory = runtimeDirectory;
        RuntimeDirectoryMode = "0750";
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";

        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        IPAddressAllow = lib.unique [
          cfg.controlAddress
          cfg.auditAddress
        ];
        IPAddressDeny = "any";
        KeyringMode = "private";
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
        StandardInput = "null";
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
      };
    };
  };
}
