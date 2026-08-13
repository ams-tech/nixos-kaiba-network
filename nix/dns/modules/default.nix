{ ... }:

{
  imports = [
    ../../modules/device-agent.nix
    ../../modules/update-controller.nix
    ../../modules/hidden-primary.nix
    ../../modules/hidden-standby.nix
    ../../modules/public-secondary.nix
  ];
}
