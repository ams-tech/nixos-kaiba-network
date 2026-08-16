{ ... }:

{
  imports = [
    ./provisioning-audit.nix
    ./provisioning-control.nix
    ./provisioning-lane-guard.nix
    ./provisioning-probe.nix
    ./provisioning-signing-gate.nix
    ./provisioning-station-demo.nix
    ./secure-boot-target.nix
  ];
}
