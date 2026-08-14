{
  pkgs,
  lib,
  built,
  kaibaModules,
}:

let
  qualificationProfileName = "raspberry-pi-5-model-b-v1alpha1.json";
  qualificationEvidenceName = "sacrificial-pi-5.json";
  qualificationProfilePath = built.goSource + "/profiles/device-classes/${qualificationProfileName}";
  qualificationProfile = builtins.fromJSON (builtins.readFile qualificationProfilePath);
  qualificationPolicy = qualificationProfile // {
    metadata = {
      id = qualificationProfile.metadata.id;
    };
  };
  qualificationPolicyDigest = "sha256:${
    builtins.hashString "sha256" (
      "kaiba.device-profile-policy.v1\n" + builtins.toJSON qualificationPolicy
    )
  }";
  qualificationProfileReference = {
    id = qualificationProfile.metadata.id;
    status = qualificationProfile.metadata.status;
    digest = "sha256:${builtins.hashFile "sha256" qualificationProfilePath}";
    policy_digest = qualificationPolicyDigest;
  };
  qualificationAdapterReference = {
    id = qualificationProfile.spec.adapter.id;
    version = qualificationProfile.spec.adapter.version;
  };
  profileReferenceMatches =
    current: recorded:
    recorded == current
    || (
      current.status == "stable"
      && (recorded.id or null) == current.id
      && (recorded.status or null) == "experimental"
      && (recorded.policy_digest or null) == current.policy_digest
    );
  profilePromotionContract =
    let
      candidate = qualificationProfileReference // {
        status = "experimental";
        digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      };
      promoted = candidate // {
        status = "stable";
        digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      };
      changedPolicy = candidate // {
        policy_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      };
    in
    profileReferenceMatches promoted candidate && !profileReferenceMatches promoted changedPolicy;
  qualificationMetadata = pkgs.writeText "kaiba-rpi5-qualification-metadata.json" (
    builtins.toJSON {
      USER_SERIAL_NUM = "A7EB274C";
      MAC_ADDR = "2C:CF:67:70:76:F3";
      EEPROM_HASH = "dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137";
      CUSTOMER_KEY_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
      BOOT_ROM = "0000000A";
      BOARD_ATTR = "00000000";
      USER_BOARDREV = "B04170";
      JTAG_LOCKED = "0";
      MAC_WIFI_ADDR = "2C:CF:67:70:76:F4";
      MAC_BT_ADDR = "2C:CF:67:70:76:F5";
      FACTORY_UUID = "001000911006186073";
      SIGNATURE_MODE = "0";
      ADVANCED_BOOT = "00000000";
    }
  );

  deviceProfileSchema =
    assert profilePromotionContract;
    pkgs.runCommand "kaiba-device-profile-schema-check"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.jq
        ];
      }
      ''
        set -eu
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/device-profile-v1alpha1.schema.json \
          ${qualificationProfilePath}
        check-jsonschema --check-metaschema \
          ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json

        ${built.provision}/bin/kaiba-provision probe \
          --profile ${qualificationProfilePath} \
          --metadata ${qualificationMetadata} \
          > "$TMPDIR/base-probe.json"
        tool_version="$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)"
        tool_digest="$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
        bundle_digest="$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
        firmware_digest="$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)"
        config_digest="$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)"
        for sequence in 1 2; do
          observed_at="2026-08-13T12:0$((sequence - 1)):00Z"
          jq \
            --arg observed_at "$observed_at" \
            --arg tool_version "$tool_version" \
            --arg tool_digest "$tool_digest" \
            --arg bundle_digest "$bundle_digest" \
            --arg firmware_digest "$firmware_digest" \
            --arg config_digest "$config_digest" \
            '.observed_at = $observed_at | .source = {
              source: "live-rpiboot",
              lane_id: "lane-qualification",
              usb_path: "1-2.3",
              tool_version: $tool_version,
              tool_digest: $tool_digest,
              bundle_digest: $bundle_digest,
              firmware_digest: $firmware_digest,
              config_digest: $config_digest
            }' \
            "$TMPDIR/base-probe.json" > "$TMPDIR/probe-$sequence.json"
        done
        qualify() {
          ${built.provision}/bin/kaiba-provision qualify \
            --profile ${qualificationProfilePath} \
            --first-result "$TMPDIR/probe-1.json" \
            --second-result "$TMPDIR/probe-2.json" \
            --source-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            --system-closure /nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-qualification-station-1 \
            --power-cycle-confirmation complete \
            --pre-probe-normal-boot confirmed \
            --normal-boot-confirmation "$1"
        }
        qualify unchanged > "$TMPDIR/passed.json"
        if qualify pending > "$TMPDIR/incomplete.json"; then
          echo "incomplete qualification unexpectedly exited zero" >&2
          exit 1
        else
          test "$?" -eq 7
        fi
        if qualify failed > "$TMPDIR/failed.json"; then
          echo "failed qualification unexpectedly exited zero" >&2
          exit 1
        else
          test "$?" -eq 6
        fi
        check-jsonschema \
          --schemafile ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
          "$TMPDIR/passed.json" "$TMPDIR/incomplete.json" "$TMPDIR/failed.json"
        test "$(jq -r .profile.digest "$TMPDIR/passed.json")" = '${qualificationProfileReference.digest}'
        test "$(jq -r .profile.policy_digest "$TMPDIR/passed.json")" = '${qualificationPolicyDigest}'
        test "$(jq -r .station_system "$TMPDIR/passed.json")" = '${pkgs.stdenv.hostPlatform.system}'
        test "$(jq -r .source.bundle_digest "$TMPDIR/passed.json")" = "$bundle_digest"
        ! grep -F 'nixos-system-qualification-station' "$TMPDIR/passed.json"

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

  moduleEval = import ./module-eval.nix {
    inherit pkgs lib kaibaModules;
    kaibaProvisionPackage = built.provision;
    kaibaStationDemoPackage = built.stationDemo;
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

  evidenceEntries = builtins.readDir ./evidence;
  unsupportedEvidenceEntries = lib.filter (
    name: name != "README.md" && name != qualificationEvidenceName
  ) (builtins.attrNames evidenceEntries);
  qualificationEvidence =
    if unsupportedEvidenceEntries != [ ] then
      throw "unsupported hardware qualification evidence entries: ${lib.concatStringsSep ", " unsupportedEvidenceEntries}"
    else if !builtins.hasAttr qualificationEvidenceName evidenceEntries then
      null
    else
      let
        name = qualificationEvidenceName;
        kind = evidenceEntries.${name};
        record = builtins.fromJSON (builtins.readFile (./evidence + "/${name}"));
        recordProfile = record.profile or { };
      in
      if kind != "regular" then
        throw "hardware qualification evidence must be a regular file"
      else if
        !builtins.elem (record.status or null) [
          "passed"
          "failed"
        ]
      then
        throw "published hardware qualification evidence must have passed or failed status"
      else if !profileReferenceMatches qualificationProfileReference recordProfile then
        throw "hardware qualification evidence does not match the current profile policy or allowed status-only promotion"
      else if (record.adapter or null) != qualificationAdapterReference then
        throw "hardware qualification evidence does not match the current profile adapter"
      else if
        !builtins.elem (record.station_system or null) [
          "x86_64-linux"
          "aarch64-linux"
        ]
      then
        throw "hardware qualification evidence has an unsupported station system"
      else
        {
          inherit name record;
        };

  hardwareQualification =
    if qualificationEvidence == null then
      {
        status = "pending";
        description = "The required two-probe, full-power-cycle qualification on a sacrificial fresh Raspberry Pi 5 Model B has not been completed.";
        evidence = [ ];
      }
    else
      {
        status = qualificationEvidence.record.status;
        description =
          if qualificationEvidence.record.status == "passed" then
            "A sacrificial fresh Raspberry Pi 5 Model B passed the reviewed two-probe, full-power-cycle qualification."
          else
            "The sacrificial Raspberry Pi 5 Model B qualification failed and requires quarantine review.";
        evidence = [
          "evidence/provisioning/hardware-qualification/${qualificationEvidence.name}"
        ];
      };

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
      hardware_qualification = hardwareQualification;
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
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.jq
        ];
      }
      ''
        test -x ${built.suite}/bin/kaiba-provision
        test -x ${built.provision}/bin/kaiba-provision
        test -f ${deviceProfileSchema}/passed
        test -f ${probeBundleIntegrity}/passed
        test -f ${moduleEval}/results.txt

        mkdir -p "$out/evidence/provisioning/hardware-qualification"
        ${lib.optionalString (qualificationEvidence != null) ''
          entry=${./evidence + "/${qualificationEvidenceName}"}
          test -f "$entry"
          test ! -L "$entry"
          check-jsonschema \
            --schemafile ${built.goSource}/schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
            "$entry"
          test "$(jq -r .source.tool_version "$entry")" = \
            "$(jq -r .tool_version ${built.rpi5ProbeBundle}/manifest.json)"
          ${lib.optionalString
            (qualificationEvidence.record.station_system == pkgs.stdenv.hostPlatform.system)
            ''
              test "$(jq -r .source.tool_digest "$entry")" = \
                "$(jq -r .tool_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
            ''
          }
          test "$(jq -r .source.bundle_digest "$entry")" = \
            "$(jq -r .bundle_sha256 ${built.rpi5ProbeBundle}/manifest.json)"
          test "$(jq -r .source.firmware_digest "$entry")" = \
            "$(jq -r '.files["bootcode5.bin"]' ${built.rpi5ProbeBundle}/manifest.json)"
          test "$(jq -r .source.config_digest "$entry")" = \
            "$(jq -r '.files["config.txt"]' ${built.rpi5ProbeBundle}/manifest.json)"
          install -m 0444 "$entry" \
            "$out/evidence/provisioning/hardware-qualification/${qualificationEvidenceName}"
        ''}
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
