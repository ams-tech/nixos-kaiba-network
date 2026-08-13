{ lib, pkgs, ... }:

let
  built = import ../provisioning/packages.nix { inherit pkgs lib; };
in
{
  imports = [
    ../dns/modules
    ../provisioning/modules
  ];

  services.kaiba-provisioning-probe.package = lib.mkDefault built.provision;
  services.kaiba-provisioning-station-demo.package = lib.mkDefault built.stationDemo;
}
