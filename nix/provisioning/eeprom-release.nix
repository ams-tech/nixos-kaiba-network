{
  pkgs,
  lib,
  eepromPackageVersion,
  eepromSource,
  eepromSourceHash,
  eepromSourceRevision,
}:

assert lib.assertMsg (
  eepromPackageVersion == "2026.05.17-2711-0138c0"
) "the Raspberry Pi EEPROM package version differs from the reviewed release source";
assert lib.assertMsg (
  eepromSourceRevision == "refs/tags/v2026.05.17-2711-0138c0"
) "the Raspberry Pi EEPROM source revision differs from the reviewed tag";
assert lib.assertMsg (
  toString eepromSourceHash == "sha256-duzftioXXrLizQVLwAS285n6ve4Y3rCt/ERjcGQG+Dc="
) "the Raspberry Pi EEPROM source hash differs from the reviewed tag";
assert lib.assertMsg (lib.hasPrefix "${builtins.storeDir}/" (
  toString eepromSource
)) "the Raspberry Pi EEPROM source must be a fixed Nix-store path";

let
  policy = rec {
    schemaVersion = "kaiba.provisioning.rpi5-eeprom-release/v1alpha1";
    deviceClass = "raspberry-pi-5-model-b-v1alpha1";

    source = {
      repository = "https://github.com/raspberrypi/rpi-eeprom";
      tag = "v2026.05.17-2711-0138c0";
      revision = "05d94be4554ce44a057bfce8d0dd37d951703dab";
      nixHash = "sha256-duzftioXXrLizQVLwAS285n6ve4Y3rCt/ERjcGQG+Dc=";
      packageVersion = "2026.05.17-2711-0138c0";
    };

    firmware = {
      release = "2026-05-26";
      buildEpoch = 1779807685;
      revision = "086b83e3";
      manufacturingVersion = 1;
      image = {
        path = "firmware/pieeprom.original.bin";
        upstreamChannel = "default";
        upstreamPath = "firmware-2712/default/pieeprom-2026-05-26.bin";
        sizeBytes = 2097152;
        sha256 = "sha256:fee8bee6a738a1a61004f0770f15534de7a48a2a199dc4c7af7ed73ab04f18dd";
      };
      recovery = {
        path = "firmware/recovery.original.bin";
        upstreamChannel = "latest";
        upstreamPath = "firmware-2712/latest/recovery.bin";
        sizeBytes = 105396;
        sha256 = "sha256:73dab9a01c139b7d995ac9a4055ee0d15551d7f8dbf1c2605bae584ef7126e0c";
      };
      bootcode = {
        path = "firmware/components/bootcode.bin";
        sizeBytes = 25984;
        sha256 = "sha256:78c1035aae86a25f4e92ed43e4b82bab01ecfa9e4e9a9b81d59b99a62ba9b26e";
      };
      bootsys = {
        path = "firmware/components/bootsys";
        sizeBytes = 78332;
        sha256 = "sha256:cb72681190fb140eaddc3f42327217121eeff088626a5e7026d49f804420ed72";
      };
    };

    capability = {
      id = "boot_img_sha256";
      deviceTreePath = "/proc/device-tree/chosen/bootloader/boot_img_sha256";
      enabledWhen = "signed_boot";
      introducedRelease = "2025-01-22";
      introducedRevision = "7918c84b4b9d7695c3b734e628139dd78b14a6b3";
      introducedBuildEpoch = 1737505011;
    };

    updateWorkflow = {
      repository = "https://github.com/raspberrypi/usbboot";
      revision = "42ca50932f67f4571951a11da3c3161561cb49c2";
      abSigningRevision = "08d4060ecfd85d402d2134572fe1e11d8b1b2dc8";
      eepromSubmoduleRevision = "25f837ab8009a643ed85b9aad94d911baddaf0c4";
      sha256 = "sha256:1b23da89519d73b07decf26e8fb8f7978800d407d2beb21f66c1ceef901e4da5";
      sizeBytes = 8971;
    };

    tools = {
      rpiEEPROMConfig = {
        id = "rpi-eeprom-config";
        path = "toolchain/rpi-eeprom-config";
        sizeBytes = 26205;
        sha256 = "sha256:39895792eb724afe5a4ed39e5798db844292efcca4317228aa790c580ddbb70f";
      };
      rpiEEPROMDigest = {
        id = "rpi-eeprom-digest";
        path = "toolchain/rpi-eeprom-digest";
        sizeBytes = 5245;
        sha256 = "sha256:ec84c22d54793bc68b273d1f26380280fe0453995d85660fdb5e041f4a756bbb";
      };
      rpiSignBootcode = {
        id = "rpi-sign-bootcode";
        path = "toolchain/rpi-sign-bootcode";
        sizeBytes = 11118;
        sha256 = "sha256:a1995a12340dd3a76b9f085726509eee7ebc0407bd0c71c60473bf443c9549f6";
      };
      rpiBootloaderKeyConvert = {
        id = "rpi-bootloader-key-convert";
        path = "toolchain/rpi-bootloader-key-convert";
        sizeBytes = 1398;
        sha256 = "sha256:26502957010893e74c0036c7b86b1db209ddbed716d8f52751fb0f0ee39bf16d";
      };
    };

    provenance = {
      releaseNotes = {
        id = "firmware-2712-release-notes";
        path = "provenance/firmware-2712-release-notes.md";
        sizeBytes = 48758;
        sha256 = "sha256:5c4edbadca75281a9fddca478c4fd69373e89fe232f46ab3e1578b1242559fdd";
      };
      versions = {
        id = "firmware-2712-versions";
        path = "provenance/firmware-2712-versions.txt";
        sizeBytes = 4400;
        sha256 = "sha256:dc14d345eb16bf21f88236dfd490a62949fd28edef0d15598b8ab0b1cb3cf3cd";
      };
    };
  };

  updatePieeprom = pkgs.fetchurl {
    name = "update-pieeprom-42ca50932f67f4571951a11da3c3161561cb49c2.sh";
    url = "https://raw.githubusercontent.com/raspberrypi/usbboot/${policy.updateWorkflow.revision}/tools/update-pieeprom.sh";
    hash = "sha256-GyPaiVGdc7B97PJuj7j3l4gA1AfSvrIfZsHO75AeTaU=";
  };

  verifier = pkgs.writeShellApplication {
    name = "kaiba-verify-rpi5-eeprom-release";
    runtimeInputs = with pkgs; [
      binutils
      coreutils
      gawk
      gnugrep
      gnused
      python3
    ];
    text = ''
      set -euo pipefail

      fail() {
        printf 'rpi5 EEPROM release verification failed: %s\n' "$1" >&2
        exit 1
      }

      if (( $# != 2 )); then
        printf 'usage: kaiba-verify-rpi5-eeprom-release EEPROM_SOURCE UPDATE_PIEEPROM\n' >&2
        exit 2
      fi

      readonly source_root="$1"
      readonly update_script="$2"
      readonly image="$source_root/${policy.firmware.image.upstreamPath}"
      # The coherent secure-boot-recovery5 workflow selects the latest
      # recovery payload independently from the default EEPROM release lane.
      readonly recovery="$source_root/${policy.firmware.recovery.upstreamPath}"
      readonly release_notes="$source_root/firmware-2712/release-notes.md"
      readonly versions="$source_root/firmware-2712/versions.txt"
      readonly eeprom_config="$source_root/rpi-eeprom-config"
      readonly eeprom_digest="$source_root/rpi-eeprom-digest"
      readonly sign_bootcode="$source_root/tools/rpi-sign-bootcode"
      readonly key_convert="$source_root/tools/rpi-bootloader-key-convert"

      require_regular() {
        local path="$1"
        local label="$2"
        if [[ -L "$path" || ! -f "$path" ]]; then
          fail "$label is not one regular, non-symbolic-link file"
        fi
      }

      require_size() {
        local path="$1"
        local expected="$2"
        local label="$3"
        if [[ "$(stat --format=%s "$path")" != "$expected" ]]; then
          fail "$label size differs from the reviewed pin"
        fi
      }

      require_sha256() {
        local path="$1"
        local expected="$2"
        local label="$3"
        if [[ "$(sha256sum "$path" | cut -d ' ' -f 1)" != "$expected" ]]; then
          fail "$label digest differs from the reviewed pin"
        fi
      }

      require_marker() {
        local path="$1"
        local marker="$2"
        local message="$3"
        grep -Fqx -- "$marker" "$path" || fail "$message"
      }

      for entry in \
        "$image" \
        "$recovery" \
        "$release_notes" \
        "$versions" \
        "$eeprom_config" \
        "$eeprom_digest" \
        "$sign_bootcode" \
        "$key_convert" \
        "$update_script"
      do
        require_regular "$entry" "$entry"
      done

      # The official release note is the public capability declaration. The
      # running target must still supply the property; this check makes only a
      # release-provenance claim and deliberately cannot substitute for a cold
      # boot observation.
      require_marker "$release_notes" \
        '## 2025-01-22: Add DT /chosen property signed-boot boot.img hash (latest)' \
        'required boot_img_sha256 capability declaration is missing'
      grep -Fq \
        '/proc/device-tree/chosen/bootloader/boot_img_sha256 if' \
        "$release_notes" \
        || fail 'required boot_img_sha256 device-tree path is missing'
      require_marker "$release_notes" \
        '  signed boot is enabled.' \
        'required boot_img_sha256 signed-boot condition is missing'

      actual_build_epoch="$(strings "$image" | sed -n 's/^BUILD_TIMESTAMP=//p')"
      if [[ ! "$actual_build_epoch" =~ ^[0-9]+$ ]]; then
        fail 'firmware image does not contain one canonical build timestamp'
      fi
      if (( actual_build_epoch < ${toString policy.capability.introducedBuildEpoch} )); then
        fail 'firmware image predates the required boot_img_sha256 capability'
      fi
      if [[ "$actual_build_epoch" != "${toString policy.firmware.buildEpoch}" ]]; then
        fail 'firmware build timestamp differs from the reviewed pin'
      fi
      if [[ "$(strings "$image" | grep -Fxc 'VERSION:${policy.firmware.revision}' || true)" != 1 ]]; then
        fail 'firmware revision differs from the reviewed pin'
      fi
      if [[ "$(strings "$image" | grep -Fxc 'DATE: 2026/05/26' || true)" != 1 ]]; then
        fail 'firmware date differs from the reviewed pin'
      fi
      if [[ "$(strings "$image" | grep -Fxc 'MFG_VER: ${toString policy.firmware.manufacturingVersion}' || true)" != 1 ]]; then
        fail 'firmware manufacturing version differs from the reviewed pin'
      fi
      awk '
        $1 == "${policy.firmware.release}" &&
        $2 == "${toString policy.firmware.buildEpoch}" &&
        $3 == "${policy.firmware.revision}" &&
        $4 == "${policy.firmware.image.upstreamChannel}" &&
        $5 == "${toString policy.firmware.manufacturingVersion}" { matches++ }
        END { exit matches == 1 ? 0 : 1 }
      ' "$versions" || fail 'firmware versions index differs from the reviewed pin'

      layout_marker="$(
        dd if="$image" bs=1 skip=$((0x10008)) count=8 status=none | strings
      )"
      if [[ "$layout_marker" != bootsys ]]; then
        fail 'firmware image does not use the reviewed Pi 5 A/B bootsys layout'
      fi

      # The selected workflow is the first coherent upstream integration of
      # A/B signing support plus a compatible rpi-eeprom-config. Reject the old
      # single-component updater even if every other public input is present.
      grep -Fq 'isABCapableImage()' "$update_script" \
        || fail 'update workflow lacks Pi 5 A/B layout detection'
      # The literal upstream shell variable is part of the reviewed source.
      # shellcheck disable=SC2016
      grep -Fq 'sign_firmware_blob "''${TMP_DIR}/bootsys" "''${TMP_DIR}/bootsys.signed"' \
        "$update_script" \
        || fail 'update workflow does not counter-sign bootsys'
      # shellcheck disable=SC2016
      grep -Fq -- '--bootsys "''${TMP_DIR}/bootsys.signed"' "$update_script" \
        || fail 'update workflow does not re-embed signed bootsys'
      grep -Fq "'--bootsys'" "$eeprom_config" \
        || fail 'rpi-eeprom-config does not support the A/B bootsys input'

      require_size "$image" ${toString policy.firmware.image.sizeBytes} 'EEPROM image'
      require_sha256 "$image" ${lib.removePrefix "sha256:" policy.firmware.image.sha256} 'EEPROM image'
      require_size "$recovery" ${toString policy.firmware.recovery.sizeBytes} 'recovery image'
      require_sha256 "$recovery" ${lib.removePrefix "sha256:" policy.firmware.recovery.sha256} 'recovery image'
      require_size "$release_notes" ${toString policy.provenance.releaseNotes.sizeBytes} 'release notes'
      require_sha256 "$release_notes" ${lib.removePrefix "sha256:" policy.provenance.releaseNotes.sha256} 'release notes'
      require_size "$versions" ${toString policy.provenance.versions.sizeBytes} 'versions index'
      require_sha256 "$versions" ${lib.removePrefix "sha256:" policy.provenance.versions.sha256} 'versions index'
      require_size "$update_script" ${toString policy.updateWorkflow.sizeBytes} 'update workflow'
      require_sha256 "$update_script" ${lib.removePrefix "sha256:" policy.updateWorkflow.sha256} 'update workflow'
      require_size "$eeprom_config" ${toString policy.tools.rpiEEPROMConfig.sizeBytes} 'rpi-eeprom-config'
      require_sha256 "$eeprom_config" ${lib.removePrefix "sha256:" policy.tools.rpiEEPROMConfig.sha256} 'rpi-eeprom-config'
      require_size "$eeprom_digest" ${toString policy.tools.rpiEEPROMDigest.sizeBytes} 'rpi-eeprom-digest'
      require_sha256 "$eeprom_digest" ${lib.removePrefix "sha256:" policy.tools.rpiEEPROMDigest.sha256} 'rpi-eeprom-digest'
      require_size "$sign_bootcode" ${toString policy.tools.rpiSignBootcode.sizeBytes} 'rpi-sign-bootcode'
      require_sha256 "$sign_bootcode" ${lib.removePrefix "sha256:" policy.tools.rpiSignBootcode.sha256} 'rpi-sign-bootcode'
      require_size "$key_convert" ${toString policy.tools.rpiBootloaderKeyConvert.sizeBytes} 'rpi-bootloader-key-convert'
      require_sha256 "$key_convert" ${lib.removePrefix "sha256:" policy.tools.rpiBootloaderKeyConvert.sha256} 'rpi-bootloader-key-convert'

      extract_dir="$(mktemp -d)"
      trap 'rm -rf -- "$extract_dir"' EXIT
      (
        cd "$extract_dir"
        python3 "$eeprom_config" -x "$image"
      )
      require_regular "$extract_dir/bootcode.bin" 'extracted bootcode'
      require_regular "$extract_dir/bootsys" 'extracted bootsys'
      require_size "$extract_dir/bootcode.bin" ${toString policy.firmware.bootcode.sizeBytes} 'extracted bootcode'
      require_sha256 "$extract_dir/bootcode.bin" ${lib.removePrefix "sha256:" policy.firmware.bootcode.sha256} 'extracted bootcode'
      require_size "$extract_dir/bootsys" ${toString policy.firmware.bootsys.sizeBytes} 'extracted bootsys'
      require_sha256 "$extract_dir/bootsys" ${lib.removePrefix "sha256:" policy.firmware.bootsys.sha256} 'extracted bootsys'

      printf 'rpi5 EEPROM release verification: pass\n'
    '';
  };

  fileRecord = value: {
    inherit (value) path;
    size_bytes = value.sizeBytes;
    inherit (value) sha256;
  };

  upstreamFileRecord =
    value:
    fileRecord value
    // {
      upstream_channel = value.upstreamChannel;
      upstream_path = value.upstreamPath;
    };

  releaseManifest = {
    schema_version = policy.schemaVersion;
    device_class = policy.deviceClass;
    source = {
      inherit (policy.source)
        repository
        tag
        revision
        ;
      package_version = policy.source.packageVersion;
      nix_hash = policy.source.nixHash;
    };
    firmware = {
      inherit (policy.firmware)
        release
        revision
        ;
      build_epoch = policy.firmware.buildEpoch;
      manufacturing_version = policy.firmware.manufacturingVersion;
      image = upstreamFileRecord policy.firmware.image;
      recovery = upstreamFileRecord policy.firmware.recovery;
      extracted_components = [
        ({ id = "bootcode.bin"; } // fileRecord policy.firmware.bootcode)
        ({ id = "bootsys"; } // fileRecord policy.firmware.bootsys)
      ];
    };
    provenance = [
      ({ inherit (policy.provenance.releaseNotes) id; } // fileRecord policy.provenance.releaseNotes)
      ({ inherit (policy.provenance.versions) id; } // fileRecord policy.provenance.versions)
    ];
    toolchain = {
      update_workflow = {
        repository = policy.updateWorkflow.repository;
        revision = policy.updateWorkflow.revision;
        ab_signing_revision = policy.updateWorkflow.abSigningRevision;
      };
      usbboot_rpi_eeprom_submodule = {
        repository = policy.source.repository;
        revision = policy.updateWorkflow.eepromSubmoduleRevision;
        selected_helper_source_revision = policy.source.revision;
        selected_helpers_byte_identical = true;
      };
      tools = [
        (
          {
            id = "update-pieeprom.sh";
            path = "toolchain/update-pieeprom.sh";
          }
          // {
            size_bytes = policy.updateWorkflow.sizeBytes;
            sha256 = policy.updateWorkflow.sha256;
          }
        )
        ({ inherit (policy.tools.rpiEEPROMConfig) id; } // fileRecord policy.tools.rpiEEPROMConfig)
        ({ inherit (policy.tools.rpiEEPROMDigest) id; } // fileRecord policy.tools.rpiEEPROMDigest)
        ({ inherit (policy.tools.rpiSignBootcode) id; } // fileRecord policy.tools.rpiSignBootcode)
        (
          {
            inherit (policy.tools.rpiBootloaderKeyConvert) id;
          }
          // fileRecord policy.tools.rpiBootloaderKeyConvert
        )
      ];
    };
    required_capability = {
      inherit (policy.capability) id;
      device_tree_path = policy.capability.deviceTreePath;
      enabled_when = policy.capability.enabledWhen;
      introduced_release = policy.capability.introducedRelease;
      introduced_revision = policy.capability.introducedRevision;
      introduced_build_epoch = policy.capability.introducedBuildEpoch;
      required = true;
      fail_closed = true;
      hardware_emission_must_be_observed = true;
    };
    authority = {
      block_device_write_capable = false;
      direct_hardware_access = false;
      eeprom_programming_capable = false;
      mutation_capable = false;
      one_time_setting_capable = false;
      otp_capable = false;
      private_key_access = false;
      signed_eeprom_produced = false;
      signing_authority_configured = false;
    };
  };

  releaseManifestJSON = builtins.toJSON releaseManifest;
  releaseManifestDigest = "sha256:${builtins.hashString "sha256" "${releaseManifestJSON}\n"}";

  mkRpi5EEPROMRelease =
    {
      name ? "kaiba-rpi5-eeprom-release",
    }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          pkgs.python3
        ];
        passthru.kaibaRpi5EEPROMRelease = {
          inherit
            eepromSource
            releaseManifest
            releaseManifestDigest
            updatePieeprom
            verifier
            ;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          hardwareEmissionObserved = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          requiredBootImageSHA256DeviceTreePath = policy.capability.deviceTreePath;
          schemaVersion = policy.schemaVersion;
          signedEEPROMProduced = false;
          signingAuthorityConfigured = false;
        };
        meta = {
          description = "Pinned public Raspberry Pi 5 EEPROM release and A/B-aware signing-tool sources";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        ${verifier}/bin/kaiba-verify-rpi5-eeprom-release \
          ${lib.escapeShellArg (toString eepromSource)} \
          ${lib.escapeShellArg (toString updatePieeprom)}

        mkdir -p \
          "$out/firmware/components" \
          "$out/provenance" \
          "$out/toolchain" \
          "$TMPDIR/extracted"
        install -m 0444 \
          ${eepromSource}/${policy.firmware.image.upstreamPath} \
          "$out/${policy.firmware.image.path}"
        install -m 0444 \
          ${eepromSource}/${policy.firmware.recovery.upstreamPath} \
          "$out/${policy.firmware.recovery.path}"
        install -m 0444 \
          ${eepromSource}/firmware-2712/release-notes.md \
          "$out/${policy.provenance.releaseNotes.path}"
        install -m 0444 \
          ${eepromSource}/firmware-2712/versions.txt \
          "$out/${policy.provenance.versions.path}"
        install -m 0444 ${updatePieeprom} "$out/toolchain/update-pieeprom.sh"
        install -m 0444 ${eepromSource}/rpi-eeprom-config "$out/${policy.tools.rpiEEPROMConfig.path}"
        install -m 0444 ${eepromSource}/rpi-eeprom-digest "$out/${policy.tools.rpiEEPROMDigest.path}"
        install -m 0444 ${eepromSource}/tools/rpi-sign-bootcode "$out/${policy.tools.rpiSignBootcode.path}"
        install -m 0444 \
          ${eepromSource}/tools/rpi-bootloader-key-convert \
          "$out/${policy.tools.rpiBootloaderKeyConvert.path}"

        (
          cd "$TMPDIR/extracted"
          python3 \
            "$out/${policy.tools.rpiEEPROMConfig.path}" \
            -x "$out/${policy.firmware.image.path}"
        )
        install -m 0444 \
          "$TMPDIR/extracted/bootcode.bin" \
          "$out/${policy.firmware.bootcode.path}"
        install -m 0444 \
          "$TMPDIR/extracted/bootsys" \
          "$out/${policy.firmware.bootsys.path}"

        printf '%s\n' ${lib.escapeShellArg releaseManifestJSON} \
          | jq --sort-keys --compact-output . > "$out/release.json"
        test "sha256:$(sha256sum "$out/release.json" | cut -d ' ' -f 1)" = \
          '${releaseManifestDigest}'
        chmod 0444 "$out/release.json"

        jq -r '
          [
            .firmware.image,
            .firmware.recovery,
            .firmware.extracted_components[],
            .provenance[],
            .toolchain.tools[]
          ][]
          | [.path, (.size_bytes | tostring), .sha256]
          | @tsv
        ' "$out/release.json" > "$TMPDIR/manifest-files.tsv"
        while IFS=$'\t' read -r relative expected_size expected_sha256; do
          candidate="$out/$relative"
          test -f "$candidate"
          test ! -L "$candidate"
          test "$(stat --format=%s "$candidate")" = "$expected_size"
          test "sha256:$(sha256sum "$candidate" | cut -d ' ' -f 1)" = \
            "$expected_sha256"
        done < "$TMPDIR/manifest-files.tsv"
        test "$(wc -l < "$TMPDIR/manifest-files.tsv")" -eq 11

        find "$out" -type f -printf '%P\n' | sort > "$TMPDIR/actual-files"
        printf '%s\n' \
          firmware/components/bootcode.bin \
          firmware/components/bootsys \
          firmware/pieeprom.original.bin \
          firmware/recovery.original.bin \
          provenance/firmware-2712-release-notes.md \
          provenance/firmware-2712-versions.txt \
          release.json \
          toolchain/rpi-bootloader-key-convert \
          toolchain/rpi-eeprom-config \
          toolchain/rpi-eeprom-digest \
          toolchain/rpi-sign-bootcode \
          toolchain/update-pieeprom.sh \
          | sort > "$TMPDIR/expected-files"
        cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
        test -z "$(find "$out" -type l -print -quit)"
        test -z "$(find "$out" ! -type d ! -type f -print -quit)"
        test -z "$(find "$out" -type f -perm /111 -print -quit)"
        chmod -R a-w "$out"
      '';
in
{
  inherit
    mkRpi5EEPROMRelease
    policy
    releaseManifest
    releaseManifestDigest
    updatePieeprom
    verifier
    ;
}
