{
  pkgs,
  lib,
  moduleRoot ? ../../dns,
}:

let
  version = "0.1.0";
  goSource = lib.cleanSource moduleRoot;

  suite = pkgs.buildGoModule {
    pname = "kaiba-dns-pilot";
    inherit version;

    # The physical Go module boundary keeps provisioning code and repository
    # integration fixtures out of the DNS source closure.
    src = goSource;

    subPackages = [
      "cmd/kaiba-agent"
      "cmd/kaiba-controller"
      "cmd/kaiba-publisher"
    ];

    vendorHash = "sha256-L0bg2g9ZX+lvggWbSRwAcJRq1m84Hyp03+LNA8zQ1ME=";

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      go test ./...
      runHook postCheck
    '';
  };

  singleBinary =
    name:
    pkgs.runCommand name
      {
        meta = {
          mainProgram = name;
          description = "Kaiba DNS pilot ${name} binary";
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p "$out/bin"
        ln -s ${suite}/bin/${name} "$out/bin/${name}"
      '';
in
{
  inherit goSource suite;
  agent = singleBinary "kaiba-agent";
  controller = singleBinary "kaiba-controller";
  publisher = singleBinary "kaiba-publisher";
}
