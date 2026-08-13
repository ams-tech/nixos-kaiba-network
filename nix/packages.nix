{ pkgs, lib }:

let
  sourceRoot = ../.;
  dns = import ./dns/packages.nix {
    inherit pkgs lib sourceRoot;
  };
  provisioning = import ./provisioning/packages.nix {
    inherit pkgs lib sourceRoot;
  };

  # Preserve the original all-binary default package while the two leaf flakes
  # expose domain-specific suites. Building this compatibility output builds
  # and checks both domain suites before joining their binaries.
  suite = pkgs.symlinkJoin {
    name = "kaiba-dns-pilot-0.1.0";
    paths = [
      dns.suite
      provisioning.suite
    ];
  };
in
{
  inherit suite;
  inherit (dns) agent controller publisher;
  inherit (provisioning)
    provision
    rpi5ProbeBundle
    stationDemo
    stationPages
    ;
}
