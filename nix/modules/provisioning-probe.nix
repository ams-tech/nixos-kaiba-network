{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    unique
    ;

  cfg = config.services.kaiba-provisioning-probe;
  defaultPackage = (import ../packages.nix { inherit pkgs lib; }).provision;
in
{
  options.services.kaiba-provisioning-probe = {
    enable = mkEnableOption "the controlled Kaiba Raspberry Pi 5 provisioning probe";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "the kaiba-provision package from this source tree";
      example = lib.literalExpression "inputs.kaiba.packages.${pkgs.system}.kaiba-provision";
      description = "Package containing bin/kaiba-provision.";
    };

    operators = mkOption {
      type = types.listOf (types.strMatching "[a-z_][a-z0-9_-]{0,30}");
      default = [ ];
      example = [ "provisioner" ];
      description = ''
        Existing local users granted raw access to attached BCM2712 RPIBOOT
        targets. Membership in this group is a privileged provisioning-station
        role, not ordinary permission to execute the command.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.length cfg.operators == builtins.length (unique cfg.operators);
        message = "services.kaiba-provisioning-probe.operators must not contain duplicates.";
      }
    ];

    environment.systemPackages = [ cfg.package ];
    users.groups.kaiba-provision = { };
    users.users = builtins.listToAttrs (
      map (name: {
        inherit name;
        value.extraGroups = [ "kaiba-provision" ];
      }) cfg.operators
    );

    services.udev.extraRules = ''
      # BCM2712 RPIBOOT only. Group membership grants raw target access.
      SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", GROUP="kaiba-provision"
    '';
  };
}
