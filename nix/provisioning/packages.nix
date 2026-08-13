{
  pkgs,
  lib,
  moduleRoot ? ../../provisioning,
}:

let
  version = "0.1.0";
  goSource = lib.cleanSource moduleRoot;

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
    pname = "kaiba-provisioning";
    inherit version;
    src = goSource;

    subPackages = [
      "cmd/kaiba-provision"
      "cmd/kaiba-provision-station-demo"
    ];

    ldflags = [
      "-X=main.rpibootPath=${pkgs.rpiboot}/bin/rpiboot"
      "-X=main.probeBundlePath=${rpi5ProbeBundle}/bundle"
      "-X=main.probeManifestPath=${rpi5ProbeBundle}/manifest.json"
    ];

    vendorHash = null;

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      go test ./...
      runHook postCheck
    '';
  };

  stationGraphGenerator = pkgs.buildGoModule {
    pname = "kaiba-provision-station-graph";
    inherit version;
    src = goSource;
    subPackages = [ "cmd/kaiba-provision-station-graph" ];
    vendorHash = null;
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
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/index.html "$out/index.html"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/styles.css "$out/styles.css"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/transport.js "$out/transport.js"
        install -m 0444 ${goSource}/internal/provisioning/stationui/web/app.js "$out/app.js"
        printf '%s\n' \
          '{"schema_version":"provisioning.kaiba.network/station-demo-runtime/v1alpha1","mode":"transition-graph","graph_url":"./workflow-graph.json"}' \
          > "$out/runtime-config.json"
        ${stationGraphGenerator}/bin/kaiba-provision-station-graph > "$out/workflow-graph.json"
        chmod 0444 "$out/runtime-config.json" "$out/workflow-graph.json"
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
        ln -s ${goSource}/profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json \
          "$out/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json"
        ln -s ${goSource}/schemas/device-profile-v1alpha1.schema.json \
          "$out/share/kaiba/schemas/device-profile-v1alpha1.schema.json"
        ln -s ${rpi5ProbeBundle}/bundle "$out/share/kaiba/rpi5-probe-bundle"
        ln -s ${rpi5ProbeBundle}/manifest.json "$out/share/kaiba/rpi5-probe-bundle-manifest.json"
      '';

  stationDemo =
    pkgs.runCommand "kaiba-provision-station-demo"
      {
        meta = {
          mainProgram = "kaiba-provision-station-demo";
          description = "Kaiba provisioning station interface demo binary";
          platforms = lib.platforms.linux;
        };
      }
      ''
        mkdir -p "$out/bin"
        ln -s ${suite}/bin/kaiba-provision-station-demo "$out/bin/kaiba-provision-station-demo"
      '';

in
{
  inherit
    goSource
    provision
    rpi5ProbeBundle
    stationDemo
    stationGraphGenerator
    stationPages
    suite
    ;
}
