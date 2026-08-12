{
  pkgs,
  lib,
  built,
  kaibaModules,
}:

let
  deviceProfileSchema =
    pkgs.runCommand "kaiba-device-profile-schema-check"
      { nativeBuildInputs = [ pkgs.check-jsonschema ]; }
      ''
        check-jsonschema \
          --schemafile ${../../schemas/device-profile-v1alpha1.schema.json} \
          ${../../profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json}
        mkdir -p "$out"
        touch "$out/passed"
      '';

  probeBundleIntegrity =
    pkgs.runCommand "kaiba-rpi5-probe-bundle-check" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        test "$(find ${built.rpi5ProbeBundle}/bundle -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = $'bootcode5.bin\nconfig.txt'
        test ! -L ${built.rpi5ProbeBundle}/bundle/bootcode5.bin
        test ! -L ${built.rpi5ProbeBundle}/bundle/config.txt
        test "$(cat ${built.rpi5ProbeBundle}/bundle/config.txt)" = 'recovery_metadata=1'
        test "$(wc -c < ${built.rpi5ProbeBundle}/bundle/config.txt)" -eq 20
        test "$(jq -r .schema ${built.rpi5ProbeBundle}/manifest.json)" = 'kaiba.rpi5-probe-bundle/v1alpha1'
        test "$(jq -c 'keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bundle_sha256","files","schema","tool_sha256","tool_version"]'
        test "$(jq -c '.files | keys | sort' ${built.rpi5ProbeBundle}/manifest.json)" = '["bootcode5.bin","config.txt"]'
        test "$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)" = '${pkgs.rpiboot.version}'
        tool_digest="sha256:$(sha256sum ${pkgs.rpiboot}/bin/rpiboot | cut -d ' ' -f 1)"
        firmware_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/bootcode5.bin | cut -d ' ' -f 1)"
        config_digest="sha256:$(sha256sum ${built.rpi5ProbeBundle}/bundle/config.txt | cut -d ' ' -f 1)"
        bundle_digest="sha256:$(
          printf '%s\0%s\0%s\0%s\0%s\0' \
            'kaiba.rpi5.probe-bundle.v1' \
            'bootcode5.bin' "$firmware_digest" \
            'config.txt' "$config_digest" \
            | sha256sum | cut -d ' ' -f 1
        )"
        test "$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$tool_digest"
        test "$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$firmware_digest"
        test "$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)" = "$config_digest"
        test "$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)" = "$bundle_digest"
        mkdir -p "$out"
        touch "$out/passed"
      '';

  moduleEval = import ../module-eval.nix {
    inherit pkgs lib kaibaModules;
    kaibaPackage = built.suite;
    kaibaProvisionPackage = built.provision;
  };

  checks = [
    {
      id = "device-profile-schema";
      description = "Experimental Raspberry Pi 5 device-profile conformance with the strict v1alpha1 schema.";
    }
    {
      id = "go-tests";
      description = "Go package tests covering the provisioning profile, adapter, live acquisition, and CLI behavior.";
    }
    {
      id = "nixos-module-evaluation";
      description = "Provisioning-probe NixOS module evaluation and its narrow USB access boundary.";
    }
    {
      id = "probe-bundle-integrity";
      description = "Immutable metadata-only probe bundle and compiled digest-manifest integrity.";
    }
    {
      id = "provision-package";
      description = "kaiba-provision package with pinned probe-tool, profile, schema, manifest, and bundle inputs.";
    }
  ];

  platformJSON = pkgs.writeText "kaiba-provisioning-${pkgs.stdenv.hostPlatform.system}.json" (
    builtins.toJSON {
      schema_version = 1;
      suite = "kaiba-rpi5-provisioning-platform-result";
      system = pkgs.stdenv.hostPlatform.system;
      checks = map (
        check:
        check
        // {
          status = "passed";
          evidence = [ ];
        }
      ) checks;
    }
  );

  reportInputJSON = pkgs.writeText "kaiba-provisioning-report-input.json" (
    builtins.toJSON {
      schema_version = 1;
      suite = "kaiba-rpi5-provisioning-probe";
      automated = {
        overall = "partial";
        checks =
          lib.concatMap
            (
              system:
              map (
                check:
                check
                // {
                  inherit system;
                  status = if system == "x86_64-linux" then "passed" else "not-observed";
                  evidence = [ ];
                }
              ) checks
            )
            [
              "aarch64-linux"
              "x86_64-linux"
            ];
      };
      hardware_qualification = {
        status = "pending";
        description = "The required two-probe, full-power-cycle qualification on a sacrificial fresh Raspberry Pi 5 Model B has not been completed.";
        evidence = [ ];
      };
      mutation_eligible = false;
    }
  );

  canonicalJSON =
    pkgs.runCommand "kaiba-provisioning-canonical-contracts" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        mkdir -p "$out"
        jq --sort-keys . ${platformJSON} > "$out/platform.json"
        jq --sort-keys . ${reportInputJSON} > "$out/report-input.json"
      '';

  provisioningTestResult =
    pkgs.runCommand "kaiba-provisioning-test-result-${pkgs.stdenv.hostPlatform.system}"
      { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        test -x ${built.suite}/bin/kaiba-provision
        test -x ${built.provision}/bin/kaiba-provision
        test -f ${deviceProfileSchema}/passed
        test -f ${probeBundleIntegrity}/passed
        test -f ${moduleEval}/results.txt

        mkdir -p "$out"
        install -m 0444 ${canonicalJSON}/platform.json "$out/platform.json"
        ${lib.optionalString (pkgs.stdenv.hostPlatform.system == "x86_64-linux") ''
          test "$(jq --sort-keys --compact-output . ${./report-input.json})" = \
            "$(jq --sort-keys --compact-output . ${canonicalJSON}/report-input.json)"
          install -m 0444 ${canonicalJSON}/report-input.json "$out/report-input.json"
        ''}
      '';
in
{
  inherit
    deviceProfileSchema
    moduleEval
    probeBundleIntegrity
    provisioningTestResult
    ;
}
