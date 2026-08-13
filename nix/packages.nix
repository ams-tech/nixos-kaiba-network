{ pkgs, lib }:

let
  version = "0.1.0";

  goSource =
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
        || lib.hasPrefix "internal/" relative
        || relative == "profiles"
        || lib.hasPrefix "profiles/" relative
        || relative == "schemas"
        || lib.hasPrefix "schemas/" relative;
    };

  rpi5ProbeBundle =
    pkgs.runCommand "kaiba-rpi5-probe-bundle"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
        passthru = {
          inherit (pkgs) rpiboot;
        };
      }
      ''
        mkdir -p "$out/bundle"
        install -m 0444 ${pkgs.rpiboot.src}/recovery5/bootcode5.bin "$out/bundle/bootcode5.bin"
        printf '%s\n' 'recovery_metadata=1' > "$out/bundle/config.txt"
        chmod 0444 "$out/bundle/config.txt"

        rpiboot_sha256="sha256:$(sha256sum ${pkgs.rpiboot}/bin/rpiboot | cut -d ' ' -f 1)"
        bootcode_sha256="sha256:$(sha256sum "$out/bundle/bootcode5.bin" | cut -d ' ' -f 1)"
        config_sha256="sha256:$(sha256sum "$out/bundle/config.txt" | cut -d ' ' -f 1)"
        bundle_sha256="$(
          printf '%s\0%s\0%s\0%s\0%s\0' \
            'kaiba.rpi5.probe-bundle.v1' \
            'bootcode5.bin' "$bootcode_sha256" \
            'config.txt' "$config_sha256" \
            | sha256sum | cut -d ' ' -f 1
        )"
        bundle_sha256="sha256:$bundle_sha256"

        jq --null-input \
          --arg schema 'kaiba.rpi5-probe-bundle/v1alpha1' \
          --arg tool_version '${pkgs.rpiboot.version}' \
          --arg rpiboot_sha256 "$rpiboot_sha256" \
          --arg bootcode_sha256 "$bootcode_sha256" \
          --arg config_sha256 "$config_sha256" \
          --arg bundle_sha256 "$bundle_sha256" \
          '{
            schema: $schema,
            tool_version: $tool_version,
            tool_sha256: $rpiboot_sha256,
            bundle_sha256: $bundle_sha256,
            files: {
              "bootcode5.bin": $bootcode_sha256,
              "config.txt": $config_sha256
            }
          }' > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  suite = pkgs.buildGoModule {
    pname = "kaiba-dns-pilot";
    inherit version;

    # Keep integration fixtures and reports out of the Go source derivation so
    # iterating on the VM scenario does not rebuild every application package.
    src = goSource;

    subPackages = [
      "cmd/kaiba-agent"
      "cmd/kaiba-controller"
      "cmd/kaiba-provision"
      "cmd/kaiba-provision-station-demo"
      "cmd/kaiba-publisher"
    ];

    ldflags = [
      "-X=main.rpibootPath=${pkgs.rpiboot}/bin/rpiboot"
      "-X=main.probeBundlePath=${rpi5ProbeBundle}/bundle"
      "-X=main.probeManifestPath=${rpi5ProbeBundle}/manifest.json"
    ];

    vendorHash = "sha256-L0bg2g9ZX+lvggWbSRwAcJRq1m84Hyp03+LNA8zQ1ME=";

    doCheck = true;
  };

  stationGraphGenerator = pkgs.buildGoModule {
    pname = "kaiba-provision-station-graph";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-station-graph" ];
    vendorHash = "sha256-L0bg2g9ZX+lvggWbSRwAcJRq1m84Hyp03+LNA8zQ1ME=";
    doCheck = false;
  };

  stationPages =
    pkgs.runCommand "kaiba-provision-station-pages"
      {
        meta = {
          description = "Static browser simulation of the Kaiba provisioning-station workflow";
          platforms = lib.platforms.all;
        };
      }
      ''
        set -eu
        mkdir -p "$out"
        install -m 0444 ${../internal/provisioning/stationui/web/index.html} "$out/index.html"
        install -m 0444 ${../internal/provisioning/stationui/web/styles.css} "$out/styles.css"
        install -m 0444 ${../internal/provisioning/stationui/web/transport.js} "$out/transport.js"
        install -m 0444 ${../internal/provisioning/stationui/web/app.js} "$out/app.js"
        printf '%s\n' \
          '{"schema_version":"provisioning.kaiba.network/station-demo-runtime/v1alpha1","mode":"transition-graph","graph_url":"./workflow-graph.json"}' \
          > "$out/runtime-config.json"
        ${stationGraphGenerator}/bin/kaiba-provision-station-graph > "$out/workflow-graph.json"
        chmod 0444 "$out/runtime-config.json" "$out/workflow-graph.json"
      '';

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

  provision =
    pkgs.runCommand "kaiba-provision"
      {
        meta = {
          mainProgram = "kaiba-provision";
          description = "Kaiba non-persistent device provisioning preflight utility";
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p \
          "$out/bin" \
          "$out/libexec/kaiba" \
          "$out/share/kaiba/device-profiles" \
          "$out/share/kaiba/schemas"
        ln -s ${suite}/bin/kaiba-provision "$out/bin/kaiba-provision"
        ln -s ${pkgs.rpiboot}/bin/rpiboot "$out/libexec/kaiba/rpiboot"
        ln -s ${../profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json} \
          "$out/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json"
        ln -s ${../schemas/device-profile-v1alpha1.schema.json} \
          "$out/share/kaiba/schemas/device-profile-v1alpha1.schema.json"
        ln -s ${rpi5ProbeBundle}/bundle "$out/share/kaiba/rpi5-probe-bundle"
        ln -s ${rpi5ProbeBundle}/manifest.json "$out/share/kaiba/rpi5-probe-bundle-manifest.json"
      '';
in
{
  inherit suite rpi5ProbeBundle stationPages;
  agent = singleBinary "kaiba-agent";
  controller = singleBinary "kaiba-controller";
  inherit provision;
  stationDemo = singleBinary "kaiba-provision-station-demo";
  publisher = singleBinary "kaiba-publisher";
}
