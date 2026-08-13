{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    count
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.kaiba.dns;
  enabledRoles = [
    cfg.hiddenPrimary.enable
    cfg.hiddenStandby.enable
    cfg.publicSecondary.enable
  ];
  authoritativeEnabled = count (enabled: enabled) enabledRoles > 0;
in
{
  options.kaiba.dns = {
    package = mkOption {
      type = types.package;
      default = pkgs.knot-dns;
      defaultText = lib.literalExpression "pkgs.knot-dns";
      description = "Knot DNS package used by all Kaiba authoritative roles.";
    };

    listenAddresses = mkOption {
      type = types.nonEmptyListOf types.str;
      default = [
        "127.0.0.1"
        "::1"
      ];
      example = [
        "192.0.2.53"
        "2001:db8::53"
      ];
      description = ''
        Addresses on which the authoritative server accepts DNS queries and
        transfer traffic. External addresses must be selected deliberately.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 53;
      description = "UDP and TCP port used by the authoritative server.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to open the configured DNS port for both UDP and TCP. Network
        policy should normally narrow access to transfer endpoints separately.
      '';
    };

    recursion = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Reserved policy switch. Kaiba authoritative roles must leave this
        disabled; recursive resolution belongs on a separate node.
      '';
    };

    credentialUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "sops-nix.service" ];
      description = ''
        Units which provision runtime TSIG include files. Knot is ordered after
        and requires these units. Secrets themselves must not enter the Nix store.
      '';
    };

    hiddenPrimary.enable = mkEnableOption "the Kaiba writable hidden-primary DNS role";
    hiddenStandby.enable = mkEnableOption "the Kaiba read-only hidden-standby DNS role";
    publicSecondary.enable = mkEnableOption "the Kaiba public-secondary DNS role";
  };

  config = mkIf authoritativeEnabled {
    assertions = [
      {
        assertion = count (enabled: enabled) enabledRoles == 1;
        message = ''
          Exactly one of kaiba.dns.hiddenPrimary, kaiba.dns.hiddenStandby, and
          kaiba.dns.publicSecondary may be enabled on a node.
        '';
      }
      {
        assertion = !cfg.recursion;
        message = ''
          Kaiba authoritative DNS roles never provide recursion. Use a separate
          recursive resolver such as Unbound.
        '';
      }
    ];

    services.knot = {
      enable = true;
      package = cfg.package;
      settings = {
        server = {
          listen = map (address: "${address}@${toString cfg.port}") cfg.listenAddresses;
          automatic-acl = true;
        };
        log.syslog.any = "info";
      };
    };

    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts = [ cfg.port ];
      allowedUDPPorts = [ cfg.port ];
    };

    systemd.services.knot = {
      after = cfg.credentialUnits;
      requires = cfg.credentialUnits;
      serviceConfig = {
        Restart = lib.mkForce "on-failure";
        RestartSec = "2s";
        # The upstream NixOS Knot module already applies a strict sandbox and
        # owns this state directory. Repeating it here makes the persistence
        # contract explicit for consumers of the Kaiba modules.
        StateDirectory = "knot";
        StateDirectoryMode = "0700";
      };
    };
  };
}
