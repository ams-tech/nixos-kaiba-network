{ ... }:

{
  imports = [
    ./device-agent.nix
    ./update-controller.nix
    ./hidden-primary.nix
    ./hidden-standby.nix
    ./public-secondary.nix
  ];
}
