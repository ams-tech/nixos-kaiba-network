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
    mkOption
    optional
    types
    ;

  cfg = config.services.kaiba-provisioning-signing-gate;
  serviceName = "kaiba-provision-signing-gate";
  signingConfig =
    if cfg.package != null && cfg.package ? kaibaSigning then cfg.package.kaibaSigning else null;
  pinCredentialPath = "/run/credentials/${serviceName}.service/yubikey-pin";
  executable =
    if cfg.package == null then
      "/invalid/kaiba-provision-signing-gate"
    else
      getExe' cfg.package "kaiba-provision-signing-gate";
  pinSource = if cfg.pinFile == null then "/invalid/yubikey-pin" else cfg.pinFile;
in
{
  options.services.kaiba-provisioning-signing-gate = {
    enable = mkEnableOption "the approval-gated development YubiKey signing service";

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      example = lib.literalExpression ''
        inputs.kaiba-provisioning.lib.mkDevelopmentYubiKeySigning {
          system = pkgs.system;
          signerID = "signer:development-01";
          cohortID = "cohort:development-01";
          tokenSerial = "12345678";
          publicKeyPEM = ./development-boot-public.pem;
          publicKeyFingerprint = "sha256:...";
          expectedCustomerKeyHash = "...";
        }
      '';
      description = ''
        Explicit package returned by mkDevelopmentYubiKeySigning. The module
        intentionally has no generic signer default because the token serial,
        public key, approval registry, provider, and socket are immutable
        package inputs.
      '';
    };

    pinFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/keys/kaiba-development-yubikey-pin";
      description = ''
        Absolute runtime path to a root-managed PIV PIN file. systemd imports
        it as a service credential; the value must never enter the Nix store,
        command line, environment, service configuration, or logs.
      '';
    };

  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null && signingConfig != null;
        message = ''
          services.kaiba-provisioning-signing-gate.package must be an explicit
          mkDevelopmentYubiKeySigning result with kaibaSigning metadata.
        '';
      }
      {
        assertion = cfg.pinFile != null && hasPrefix "/" cfg.pinFile;
        message = "services.kaiba-provisioning-signing-gate.pinFile must be an absolute runtime path";
      }
      {
        assertion = cfg.pinFile == null || !hasPrefix "${builtins.storeDir}/" cfg.pinFile;
        message = "the YubiKey PIN file must not be stored in the Nix store";
      }
      {
        assertion = signingConfig == null || signingConfig.pinCredentialPath == pinCredentialPath;
        message = ''
          the signing package PIN credential path does not match the fixed
          kaiba-provision-signing-gate.service systemd credential path.
        '';
      }
      {
        assertion =
          signingConfig == null
          ||
            signingConfig.socketPath == "/run/kaiba-provision-signing/signing.sock"
            && signingConfig.stateDirectoryPath == "/var/lib/kaiba-provision-signing";
        message = "the signing package socket or state path does not match the service boundary";
      }
    ];

    users.groups.kaiba-signing = { };
    users.users.kaiba-signing = {
      isSystemUser = true;
      group = "kaiba-signing";
      extraGroups = [ ];
    };

    services.pcscd.enable = true;
    environment.systemPackages = optional (cfg.package != null) cfg.package;

    systemd.services.${serviceName} = {
      description = "Kaiba approval-gated development YubiKey signer";
      wantedBy = [ "multi-user.target" ];
      wants = [ "pcscd.service" ];
      after = [ "pcscd.service" ];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 3;
      };
      serviceConfig = {
        Type = "simple";
        User = "kaiba-signing";
        Group = "kaiba-signing";
        ExecStart = utils.escapeSystemdExecArgs [
          executable
        ];
        LoadCredential = [ "yubikey-pin:${pinSource}" ];
        StateDirectory = "kaiba-provision-signing";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "kaiba-provision-signing";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStopSec = "10s";

        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
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
        RestrictAddressFamilies = [ "AF_UNIX" ];
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
