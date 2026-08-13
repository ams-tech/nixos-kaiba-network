{ config, lib, ... }:

let
  inherit (lib)
    any
    attrValues
    elem
    hasPrefix
    length
    listToAttrs
    mkIf
    mkOption
    nameValuePair
    types
    unique
    ;

  cfg = config.kaiba.dns.publicSecondary;

  masterType = types.submodule (
    { ... }: {
      options = {
        id = mkOption {
          type = types.strMatching "[a-zA-Z0-9_-]+";
          description = "Stable Knot remote identifier, such as p0 or p1.";
        };
        address = mkOption {
          type = types.str;
          description = "IPv4 or IPv6 address of the hidden origin.";
        };
        port = mkOption {
          type = types.port;
          default = 53;
        };
        keyName = mkOption {
          type = types.str;
          default = "kaiba-public-transfer";
          description = "TSIG key identifier used for authenticated zone transfer.";
        };
      };
    }
  );

  actionContains =
    wanted: acl:
    let
      action = acl.action or [ ];
    in
    if builtins.isList action then elem wanted action else action == wanted;
  finalAcls = config.services.knot.settings.acl or { };
in
{
  imports = [ ./authoritative-common.nix ];

  options.kaiba.dns.publicSecondary = {
    zone = mkOption {
      type = types.str;
      default = "kaiba.network.";
      description = "Publicly served Kaiba zone.";
    };

    masters = mkOption {
      type = types.listOf masterType;
      default = [ ];
      example = [
        {
          id = "p0";
          address = "192.0.2.53";
        }
        {
          id = "p1";
          address = "192.0.2.54";
        }
      ];
      description = ''
        Ordered hidden transfer sources. Configure P0 followed by P1 so a new
        public secondary can bootstrap while the writable origin is unavailable.
      '';
    };

    keyFiles = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "/run/credentials/knot/public-transfer.conf" ];
      description = ''
        Absolute runtime paths to Knot-format TSIG includes referenced by the
        configured masters. These files must not be copied into the Nix store.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = length cfg.masters >= 2;
        message = "A public secondary requires both P0 and P1 transfer sources.";
      }
      {
        assertion =
          length (map (master: master.id) cfg.masters)
          == length (unique (map (master: master.id) cfg.masters));
        message = "Public-secondary master identifiers must be unique.";
      }
      {
        assertion = length cfg.keyFiles > 0;
        message = "A public secondary requires at least one runtime TSIG keyFile.";
      }
      {
        assertion = builtins.all (path: hasPrefix "/" path) cfg.keyFiles;
        message = "Public-secondary TSIG keyFiles must be absolute runtime paths.";
      }
      {
        assertion = !any (actionContains "update") (attrValues finalAcls);
        message = "Public secondaries are read-only and may not have an update ACL.";
      }
      {
        assertion = !any (actionContains "transfer") (attrValues finalAcls);
        message = "Public secondaries must not serve outbound zone transfers.";
      }
    ];

    services.knot = {
      checkConfig = false;
      keyFiles = cfg.keyFiles;
      settings = {
        remote = listToAttrs (
          map (
            master:
            nameValuePair master.id {
              address = "${master.address}@${toString master.port}";
              key = master.keyName;
            }
          ) cfg.masters
        );

        template.default = {
          storage = "/var/lib/knot";
          journal-content = "all";
          zonefile-load = "none";
          zonefile-sync = -1;
          semantic-checks = true;
        };

        zone.${cfg.zone} = {
          master = map (master: master.id) cfg.masters;
        };
      };
    };
  };
}
