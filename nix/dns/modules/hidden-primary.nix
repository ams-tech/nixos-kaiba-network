{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    attrNames
    elem
    filterAttrs
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

  cfg = config.kaiba.dns.hiddenPrimary;

  targetType = types.submodule (
    { ... }: {
      options = {
        id = mkOption {
          type = types.strMatching "[a-zA-Z0-9_-]+";
          description = "Stable Knot remote identifier.";
        };
        address = mkOption {
          type = types.str;
          description = "IPv4 or IPv6 address of the secondary.";
        };
        port = mkOption {
          type = types.port;
          default = 53;
          description = "Authoritative DNS port on the secondary.";
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
  updateAclNames = attrNames (
    filterAttrs (_: acl: actionAllowsUpdate acl) (config.services.knot.settings.acl or { })
  );
  initialZoneFile =
    if cfg.initialZoneFile == null then
      pkgs.writeText "kaiba-missing-primary-zone" "; initialZoneFile is required\n"
    else
      cfg.initialZoneFile;
in
{
  imports = [ ./authoritative-common.nix ];

  options.kaiba.dns.hiddenPrimary = {
    zone = mkOption {
      type = types.str;
      default = "kaiba.network.";
      description = "Zone for which this node is the sole writable origin.";
    };

    initialZoneFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = lib.literalExpression "./kaiba.network.zone";
      description = ''
        Non-secret bootstrap zone file. Dynamic changes are persisted in the
        Knot journal under /var/lib/knot; this file may safely live in the store.
      '';
    };

    publisherUpdate = {
      keyName = mkOption {
        type = types.str;
        default = "kaiba-publisher";
        description = "TSIG key identifier authorized for RFC 2136 updates.";
      };
      keyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/credentials/knot/publisher-update.conf";
        description = ''
          Absolute runtime path to a Knot-format include defining keyName.
          The include must be provisioned outside the Nix store.
        '';
      };
      sourceAddresses = mkOption {
        type = types.nonEmptyListOf types.str;
        default = [ "127.0.0.1" ];
        description = "Addresses from which the publisher may send updates.";
      };
    };

    standby = {
      address = mkOption {
        type = types.str;
        default = "";
        example = "192.0.2.54";
        description = "Address of the single read-only hidden standby.";
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
        description = "TSIG key identifier shared with the managed-secondary boundary.";
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
        example = [
          {
            id = "public-a";
            address = "198.51.100.53";
          }
          {
            id = "public-b";
            address = "198.51.100.54";
          }
        ];
        description = "Public secondaries notified by P0 and allowed to transfer the zone.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.initialZoneFile != null;
        message = "kaiba.dns.hiddenPrimary.initialZoneFile is required.";
      }
      {
        assertion = cfg.standby.address != "";
        message = "kaiba.dns.hiddenPrimary.standby.address is required.";
      }
      {
        assertion = cfg.publisherUpdate.keyFile != null;
        message = "A runtime publisher-update TSIG keyFile is required on P0.";
      }
      {
        assertion = cfg.standby.keyFile != null;
        message = "A runtime P0-to-P1 transfer TSIG keyFile is required on P0.";
      }
      {
        assertion = cfg.publicTransfer.keyFile != null;
        message = "A runtime public-secondary transfer TSIG keyFile is required on P0.";
      }
      {
        assertion = length cfg.publicTransfer.secondaries > 0;
        message = "P0 requires at least one public secondary transfer target.";
      }
      {
        assertion =
          length (map (target: target.id) cfg.publicTransfer.secondaries)
          == length (unique (map (target: target.id) cfg.publicTransfer.secondaries));
        message = "P0 public secondary identifiers must be unique.";
      }
      {
        assertion =
          cfg.publisherUpdate.keyName != cfg.standby.keyName
          && cfg.publisherUpdate.keyName != cfg.publicTransfer.keyName
          && cfg.standby.keyName != cfg.publicTransfer.keyName;
        message = "Publisher, P0-to-P1, and public-transfer TSIG key names must be distinct.";
      }
      {
        assertion =
          length (unique [
            cfg.publisherUpdate.keyFile
            cfg.standby.keyFile
            cfg.publicTransfer.keyFile
          ]) == 3;
        message = "Publisher, P0-to-P1, and public-transfer TSIG key files must be distinct.";
      }
      {
        assertion = updateAclNames == [ "publisher-update" ];
        message = "P0 must expose exactly one update ACL, bound to the Kaiba publisher.";
      }
      {
        assertion =
          absoluteOrNull cfg.publisherUpdate.keyFile
          && absoluteOrNull cfg.standby.keyFile
          && absoluteOrNull cfg.publicTransfer.keyFile;
        message = "Knot TSIG keyFile values must be absolute runtime paths.";
      }
    ];

    services.knot = {
      checkConfig = false;
      keyFiles =
        optional (cfg.publisherUpdate.keyFile != null) cfg.publisherUpdate.keyFile
        ++ optional (cfg.standby.keyFile != null) cfg.standby.keyFile
        ++ optional (cfg.publicTransfer.keyFile != null) cfg.publicTransfer.keyFile;

      settings = {
        remote = {
          standby = {
            address = "${cfg.standby.address}@${toString cfg.standby.port}";
            key = cfg.standby.keyName;
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

        acl = {
          publisher-update = {
            address = cfg.publisherUpdate.sourceAddresses;
            key = cfg.publisherUpdate.keyName;
            action = "update";
          };
          standby-transfer = {
            address = cfg.standby.address;
            key = cfg.standby.keyName;
            action = "transfer";
          };
          public-transfer = {
            address = map (target: target.address) cfg.publicTransfer.secondaries;
            key = cfg.publicTransfer.keyName;
            action = "transfer";
          };
        };

        template.default = {
          storage = "/var/lib/knot";
          journal-content = "all";
          zonefile-load = "difference";
          zonefile-sync = -1;
          semantic-checks = true;
        };

        zone.${cfg.zone} = {
          file = initialZoneFile;
          notify = [ "standby" ] ++ map publicRemoteName cfg.publicTransfer.secondaries;
          acl = [
            "publisher-update"
            "standby-transfer"
            "public-transfer"
          ];
        };
      };
    };
  };
}
