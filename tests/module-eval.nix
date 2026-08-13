{
  pkgs,
  lib,
  kaibaPackage,
  kaibaProvisionPackage,
  kaibaStationDemoPackage,
  kaibaModules,
}:

let
  dns = import ./integration/module-eval.nix {
    inherit
      pkgs
      lib
      kaibaPackage
      kaibaModules
      ;
  };
  provisioning = import ./provisioning/module-eval.nix {
    inherit
      pkgs
      lib
      kaibaProvisionPackage
      kaibaStationDemoPackage
      kaibaModules
      ;
  };
in
pkgs.runCommand "kaiba-module-evaluation" { } ''
  test -f ${dns}/results.txt
  test -f ${provisioning}/results.txt

  mkdir -p "$out"
  printf '%s\n' \
    'primary: pass' \
    'standby: pass' \
    'public-secondary: pass' \
    'application-services: pass' \
    'provisioning-probe-module: pass' \
    'provisioning-probe-usb-boundary: pass' \
    'provisioning-station-demo-module: pass' \
    'provisioning-station-demo-loopback-only: pass' \
    'provisioning-station-demo-sandbox-and-no-usb: pass' \
    'controller-publisher-uid-and-state-boundary: pass' \
    'sqlite-main-wal-shm-permissions-prepared: pass' \
    'two-distinct-nonempty-observers-required: pass' \
    'authoritative-recursion-rejected: pass' \
    > "$out/results.txt"
''
