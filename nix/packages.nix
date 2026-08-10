{ pkgs, lib }:

let
  version = "0.1.0";

  suite = pkgs.buildGoModule {
    pname = "kaiba-dns-pilot";
    inherit version;

    # Keep integration fixtures and reports out of the Go source derivation so
    # iterating on the VM scenario does not rebuild every application package.
    src =
      let
        root = toString ../.;
      in
      lib.cleanSourceWith {
        src = ../.;
        filter =
          path: _type:
          let
            absolute = toString path;
            relative = lib.removePrefix "${root}/" absolute;
          in
          absolute == root
          || relative == "go.mod"
          || relative == "go.sum"
          || relative == "cmd"
          || lib.hasPrefix "cmd/" relative
          || relative == "internal"
          || lib.hasPrefix "internal/" relative;
      };

    subPackages = [
      "cmd/kaiba-agent"
      "cmd/kaiba-controller"
      "cmd/kaiba-publisher"
    ];

    vendorHash = "sha256-L0bg2g9ZX+lvggWbSRwAcJRq1m84Hyp03+LNA8zQ1ME=";

    doCheck = true;
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
        mkdir -p $out/bin
        ln -s ${suite}/bin/${name} $out/bin/${name}
      '';
in
{
  inherit suite;
  agent = singleBinary "kaiba-agent";
  controller = singleBinary "kaiba-controller";
  publisher = singleBinary "kaiba-publisher";
}
