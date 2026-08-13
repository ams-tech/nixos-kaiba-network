{
  pkgs,
  lib,
  sourceRoot ? ../..,
}:

let
  version = "0.1.0";
  root = toString sourceRoot;

  includedDirectories = [
    "cmd/kaiba-agent"
    "cmd/kaiba-controller"
    "cmd/kaiba-publisher"
    "internal/address"
    "internal/agent"
    "internal/api"
    "internal/cliutil"
    "internal/clock"
    "internal/controller"
    "internal/dnswriter"
    "internal/identity"
    "internal/model"
    "internal/publisher"
    "internal/store"
  ];

  goSource = lib.cleanSourceWith {
    src = sourceRoot;
    filter =
      path: _type:
      let
        absolute = toString path;
        relative = lib.removePrefix "${root}/" absolute;
        includedDirectory = builtins.any (
          directory: relative == directory || lib.hasPrefix "${directory}/" relative
        ) includedDirectories;
      in
      absolute == root
      || relative == "go.mod"
      || relative == "go.sum"
      || relative == "cmd"
      || relative == "internal"
      || includedDirectory;
  };

  suite = pkgs.buildGoModule {
    pname = "kaiba-dns-pilot";
    inherit version;

    # Keep provisioning code, integration fixtures, and reports out of the DNS
    # source so changes in those domains do not rebuild the DNS applications.
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
