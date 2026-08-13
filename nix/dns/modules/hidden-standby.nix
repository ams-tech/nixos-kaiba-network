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
    optional
    types
    unique
    ;

  cfg = config.kaiba.dns.hiddenStandby;

  targetType = types.submodule (
    { ... }: {
      options = {
        id = mkOption {
          type = types.strMatching "[a-zA-Z0-9_-]+";
          description = "Stable Knot remote identifier.";
        };
        address = mkOption {
          type = types.str;
          description = "IPv4 or IPv6 address of the public secondary.";
        };
        port = mkOption {
          type = types.port;
          default = 53;
        };
      };
    }
  );

  publicRemoteName = target: "public-${target.id}";
  endpoint = target: "${target.address}@${toString target.port}";
  absoluteOrNull = value: value == null || hasPrefix "/" value;
  actionAllowsUpdate =
    acl:
    let
      action = acl.action or [ ];
    in
    if builtins.isList action then elem "update" action else action == "update";
  finalAcls = config.services.knot.settings.acl or { };
in
{
  imports = [ ./authoritative-common.nix ];

  options.kaiba.dns.hiddenStandby = {
    zone = mkOption {
      type = types.str;
      default = "kaiba.network.";
      description = "Zone transferred from the writable hidden primary.";
    };

    primary = {
      address = mkOption {
        type = types.str;
        default = "";
        example = "192.0.2.53";
        description = "Address of P0, the sole writable origin.";
      };
      port = mkOption {
        type = types.port;
        default = 53;
      };
      keyName = mkOption {
        type = types.str;
        default = "kaiba-p0-p1";
        description = "TSIG key identifier used only for P0-to-P1 transfer.";
      };
      keyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/knot/p0-p1-transfer.conf";
        description = "Absolute runtime path to the P0-to-P1 Knot TSIG include.";
      };
    };

    publicTransfer = {
      keyName = mkOption {
        type = types.str;
        default = "kaiba-public-transfer";
        description = "TSIG key identifier for downstream public transfers.";
      };
      keyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/knot/public-transfer.conf";
        description = "Absolute runtime path to the public-secondary Knot TSIG include.";
      };
      secondaries = mkOption {
        type = types.listOf targetType;
        default = [ ];
        description = ''
          Public secondaries allowed to bootstrap from P1 and notified after P1
          receives a change from P0.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.primary.address != "";
        message = "kaiba.dns.hiddenStandby.primary.address is required.";
      }
      {
        assertion = cfg.primary.keyFile != null;
        message = "A runtime P0-to-P1 transfer TSIG keyFile is required on P1.";
      }
      {
        assertion = cfg.publicTransfer.keyFile != null;
        message = "A runtime public-secondary transfer TSIG keyFile is required on P1.";
      }
      {
        assertion = length cfg.publicTransfer.secondaries > 0;
        message = "P1 requires at least one downstream public secondary.";
      }
      {
        assertion =
          length (map (target: target.id) cfg.publicTransfer.secondaries)
          == length (unique (map (target: target.id) cfg.publicTransfer.secondaries));
        message = "P1 public secondary identifiers must be unique.";
      }
      {
        assertion = cfg.primary.keyName != cfg.publicTransfer.keyName;
        message = "P0-to-P1 and public-transfer TSIG key names must be distinct.";
      }
      {
        assertion = cfg.primary.keyFile != cfg.publicTransfer.keyFile;
        message = "P0-to-P1 and public-transfer TSIG key files must be distinct.";
      }
      {
        assertion = absoluteOrNull cfg.primary.keyFile && absoluteOrNull cfg.publicTransfer.keyFile;
        message = "Knot TSIG keyFile values must be absolute runtime paths.";
      }
      {
        assertion = !any actionAllowsUpdate (attrValues finalAcls);
        message = "The hidden standby is read-only and may not have an update ACL.";
      }
    ];

    services.knot = {
      checkConfig = false;
      keyFiles =
        optional (cfg.primary.keyFile != null) cfg.primary.keyFile
        ++ optional (cfg.publicTransfer.keyFile != null) cfg.publicTransfer.keyFile;

      settings = {
        remote = {
          primary = {
            address = "${cfg.primary.address}@${toString cfg.primary.port}";
            key = cfg.primary.keyName;
          };
        }
        // listToAttrs (
          map (
            target:
            nameValuePair (publicRemoteName target) {
              address = endpoint target;
              key = cfg.publicTransfer.keyName;
            }
          ) cfg.publicTransfer.secondaries
        );

        acl.public-transfer = {
          address = map (target: target.address) cfg.publicTransfer.secondaries;
          key = cfg.publicTransfer.keyName;
          action = "transfer";
        };

        template.default = {
          storage = "/var/lib/knot";
          journal-content = "all";
          zonefile-load = "none";
          zonefile-sync = -1;
          semantic-checks = true;
        };

        zone.${cfg.zone} = {
          master = "primary";
          notify = map publicRemoteName cfg.publicTransfer.secondaries;
          acl = [ "public-transfer" ];
        };
      };
    };
  };
}
