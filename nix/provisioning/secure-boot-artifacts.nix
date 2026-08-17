{
  lib,
  pkgs,
}:

{
  bootCommandLinePath ? "cmdline.txt",
  bootImageSizeMiB ? 96,
  bootOrderPolicy ? "nvme-only",
  dataDevice ? "/dev/nvme0n1p2",
  expectedCustomerKeyHash,
  firmwareAllowlist,
  firmwareTree,
  hashDevice ? "/dev/nvme0n1p3",
  name ? "kaiba-rpi5-secure-boot-unsigned-artifacts",
  rootImage,
  sourceRevision,
}:

assert lib.assertMsg (
  bootImageSizeMiB >= 32 && bootImageSizeMiB <= 96
) "secure boot bootImageSizeMiB must be between 32 and the Raspberry Pi boot_ramdisk limit of 96";
assert lib.assertMsg (
  builtins.match "[0-9a-f]{64}" expectedCustomerKeyHash != null
) "expectedCustomerKeyHash must be one lowercase SHA-256 digest without a prefix";
assert lib.assertMsg (
  builtins.match "/dev/nvme[0-9]+n[0-9]+p[0-9]+" dataDevice != null
) "dataDevice must identify one fixed NVMe partition";
assert lib.assertMsg (
  builtins.match "/dev/nvme[0-9]+n[0-9]+p[0-9]+" hashDevice != null
) "hashDevice must identify one fixed NVMe partition";
assert lib.assertMsg (
  dataDevice != hashDevice
) "dataDevice and hashDevice must be distinct partitions";
assert lib.assertMsg (
  builtins.isList firmwareAllowlist
  && firmwareAllowlist != [ ]
  && lib.all (
    path:
    builtins.isString path
    && builtins.match "[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}" path != null
    && !(lib.hasPrefix "/" path)
    && !(lib.hasPrefix "." path)
    && !(lib.hasInfix "/." path)
    && !(lib.hasInfix ".." path)
    && !(lib.hasInfix "//" path)
  ) firmwareAllowlist
  && builtins.length firmwareAllowlist == builtins.length (lib.unique firmwareAllowlist)
) "firmwareAllowlist must be a non-empty unique list of canonical relative file paths";
assert lib.assertMsg (
  builtins.isString bootCommandLinePath
  && builtins.match "[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}" bootCommandLinePath != null
  && !(lib.hasPrefix "/" bootCommandLinePath)
  && !(lib.hasPrefix "." bootCommandLinePath)
  && !(lib.hasInfix "/." bootCommandLinePath)
  && !(lib.hasInfix ".." bootCommandLinePath)
  && !(lib.hasInfix "//" bootCommandLinePath)
  && lib.elem bootCommandLinePath firmwareAllowlist
) "bootCommandLinePath must name one canonical regular file in firmwareAllowlist";
assert lib.assertMsg (
  builtins.match "[a-z][a-z0-9-]{0,63}" bootOrderPolicy != null
) "bootOrderPolicy must be a lowercase policy identifier";
assert lib.assertMsg (
  builtins.isString sourceRevision
  && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null
) "sourceRevision must be one canonical lowercase 40- or 64-hex Git revision";

let
  generatedBootFiles = [ "kaiba-root-integrity.json" ];
  finalBootAllowlist = lib.sort builtins.lessThan (
    lib.unique (firmwareAllowlist ++ generatedBootFiles)
  );
in
pkgs.runCommand name
  {
    nativeBuildInputs = with pkgs; [
      coreutils
      cryptsetup
      dosfstools
      findutils
      jq
      mtools
    ];
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export TZ=UTC
    export LC_ALL=C

    readonly stage="$TMPDIR/boot-tree"
    readonly active_cmdline="$stage/${bootCommandLinePath}"
    mkdir -p "$stage" "$out/unsigned" "$out/nvme"

    # The caller supplies only public boot inputs.  Private signing material is
    # deliberately absent from this derivation and therefore from the Nix
    # store and build logs.
    cp -R --no-preserve=ownership ${firmwareTree}/. "$stage/"
    if test -n "$(find "$stage" -type l -print -quit)"; then
      echo "firmware tree contains a symbolic link" >&2
      exit 1
    fi
    if test -n "$(find "$stage" ! -type d ! -type f -print -quit)"; then
      echo "firmware tree contains an unsupported filesystem object" >&2
      exit 1
    fi
    find "$stage" -type f -printf '%P\n' | LC_ALL=C sort > "$TMPDIR/actual-firmware-files"
    {
      ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") (
        lib.sort builtins.lessThan firmwareAllowlist
      )}
    } > "$TMPDIR/expected-firmware-files"
    if ! cmp "$TMPDIR/expected-firmware-files" "$TMPDIR/actual-firmware-files"; then
      echo "firmware tree differs from firmwareAllowlist" >&2
      exit 1
    fi
    if test -e "$stage/kaiba-root-integrity.json"; then
      echo "firmware tree must not supply generated kaiba-root-integrity.json" >&2
      exit 1
    fi
    # FAT cannot encode pre-1980 timestamps.  Pin every entry to its first
    # representable UTC day so directory construction is reproducible.
    find "$stage" -exec touch --date=@315532800 '{}' +

    cp --reflink=auto ${rootImage} "$out/nvme/root-data.img"
    chmod 0444 "$out/nvme/root-data.img"
    root_image_digest="$(sha256sum "$out/nvme/root-data.img" | cut -d ' ' -f 1)"
    verity_uuid="''${root_image_digest:0:8}-''${root_image_digest:8:4}-''${root_image_digest:12:4}-''${root_image_digest:16:4}-''${root_image_digest:20:12}"

    # A digest-derived salt makes the unsigned artifact reproducible.  The
    # root hash is placed in the selected command line inside boot.img, so
    # it is covered by the Raspberry Pi signature rather than read from
    # mutable NVMe metadata.
    : > "$out/nvme/root-hash.img"
    veritysetup format \
      --salt="$root_image_digest" \
      --uuid="$verity_uuid" \
      --root-hash-file="$TMPDIR/root-hash" \
      "$out/nvme/root-data.img" \
      "$out/nvme/root-hash.img" \
      > "$TMPDIR/verity-format.txt"
    root_hash="$(tr -d '\n' < "$TMPDIR/root-hash")"
    if test "''${#root_hash}" -ne 64; then
      echo "veritysetup returned a root hash with the wrong length" >&2
      exit 1
    fi
    case "$root_hash" in
      (*[!0-9a-f]*)
        echo "veritysetup returned an invalid root hash" >&2
        exit 1
        ;;
    esac
    chmod 0444 "$out/nvme/root-hash.img"

    test -f "$active_cmdline" || {
      echo "bootCommandLinePath is not a regular file in the staged firmware" >&2
      exit 1
    }
    base_cmdline="$(tr '\n' ' ' < "$active_cmdline")"
    : > "$TMPDIR/sanitized-cmdline"
    # The upstream NixOS generation contributes console, init, and other
    # target parameters.  Remove every root/verity selector before adding the
    # signed, builder-owned values so kernel argument ordering cannot select a
    # different root or disable verification.
    for parameter in $base_cmdline; do
      case "$parameter" in
        ro|rw|root=*|rootfstype=*|roothash=*|systemd.verity=*|rd.systemd.verity=*|systemd.verity_root_*=*|rd.systemd.verity_root_*=*)
          ;;
        *)
          printf '%s\n' "$parameter" >> "$TMPDIR/sanitized-cmdline"
          ;;
      esac
    done
    sanitized_cmdline="$(paste -sd ' ' "$TMPDIR/sanitized-cmdline")"
    chmod u+w "$active_cmdline"
    printf '%s %s\n' "$sanitized_cmdline" \
      "ro root=/dev/mapper/root rootfstype=ext4 rd.systemd.verity=1 roothash=$root_hash systemd.verity_root_data=${dataDevice} systemd.verity_root_hash=${hashDevice}" \
      > "$active_cmdline"
    chmod 0444 "$active_cmdline"

    jq --null-input \
      --arg schema 'provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1' \
      --arg root_hash "$root_hash" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      '{
        schema: $schema,
        algorithm: "sha256",
        data_block_size: 4096,
        hash_block_size: 4096,
        no_superblock: false,
        root_hash: $root_hash,
        data_device: $data_device,
        hash_device: $hash_device
      }' > "$stage/kaiba-root-integrity.json"
    chmod 0444 "$stage/kaiba-root-integrity.json"
    touch --date=@315532800 "$active_cmdline" "$stage/kaiba-root-integrity.json"

    # Normalize permissions only after every builder-owned file and command
    # line has been generated.  Earlier normalization would make the staged
    # tree immutable before kaiba-root-integrity.json can be created.
    find "$stage" -type d -exec chmod 0555 '{}' +
    find "$stage" -type f -exec chmod 0444 '{}' +

    find "$stage" -type f -printf '%P\n' | LC_ALL=C sort > "$TMPDIR/actual-boot-files"
    {
      ${lib.concatMapStringsSep "\n" (
        path: "printf '%s\\n' ${lib.escapeShellArg path}"
      ) finalBootAllowlist}
    } > "$TMPDIR/expected-boot-files"
    if ! cmp "$TMPDIR/expected-boot-files" "$TMPDIR/actual-boot-files"; then
      echo "generated boot tree differs from the final boot allowlist" >&2
      exit 1
    fi

    truncate --size=${toString bootImageSizeMiB}M "$out/unsigned/boot.img"
    mkfs.vfat \
      --invariant \
      -F 32 \
      -i 4b414942 \
      -n KAIBA_BOOT \
      "$out/unsigned/boot.img" \
      > "$TMPDIR/mkfs.txt"
    mcopy -s -p -m -i "$out/unsigned/boot.img" "$stage"/* ::/
    chmod 0444 "$out/unsigned/boot.img"

    boot_digest="$(sha256sum "$out/unsigned/boot.img" | cut -d ' ' -f 1)"
    hash_image_digest="$(sha256sum "$out/nvme/root-hash.img" | cut -d ' ' -f 1)"
    boot_size="$(stat --format=%s "$out/unsigned/boot.img")"

    jq --null-input \
      --arg schema 'provisioning.kaiba.network/unsigned-artifact-set/v1alpha1' \
      --arg source_revision ${lib.escapeShellArg sourceRevision} \
      --arg expected_customer_key_hash 'sha256:${expectedCustomerKeyHash}' \
      --arg boot_order_policy ${lib.escapeShellArg bootOrderPolicy} \
      --arg boot_command_line_path ${lib.escapeShellArg bootCommandLinePath} \
      --argjson firmware_allowlist ${lib.escapeShellArg (builtins.toJSON finalBootAllowlist)} \
      --argjson boot_size "$boot_size" \
      --arg boot_digest "sha256:$boot_digest" \
      --arg root_image_digest "sha256:$root_image_digest" \
      --arg hash_image_digest "sha256:$hash_image_digest" \
      --arg root_hash "sha256:$root_hash" \
      --arg verity_uuid "$verity_uuid" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg cryptsetup_version '${lib.getVersion pkgs.cryptsetup}' \
      --arg dosfstools_version '${lib.getVersion pkgs.dosfstools}' \
      --arg mtools_version '${lib.getVersion pkgs.mtools}' \
      '{
        schema: $schema,
        source_revision: $source_revision,
        expected_customer_key_hash: $expected_customer_key_hash,
        boot_order_policy: $boot_order_policy,
        boot_command_line_path: $boot_command_line_path,
        firmware_allowlist: $firmware_allowlist,
        boot_image_size_bytes: $boot_size,
        persistent_mutable_state: "tmpfs-only",
        rollback_policy: "unimplemented-block-enrollment-ready",
        debug_policy: "videocore-jtag-unlocked-development",
        eeprom_write_protection_policy: "unlocked-development",
        toolchain: {
          cryptsetup: $cryptsetup_version,
          dosfstools: $dosfstools_version,
          mtools: $mtools_version
        },
        artifacts: {
          boot_image: { path: "unsigned/boot.img", digest: $boot_digest },
          root_data: { path: "nvme/root-data.img", digest: $root_image_digest },
          root_hash_tree: { path: "nvme/root-hash.img", digest: $hash_image_digest }
        },
        verity: {
          algorithm: "sha256",
          data_block_size: 4096,
          hash_block_size: 4096,
          uuid: $verity_uuid,
          data_device: $data_device,
          hash_device: $hash_device,
          mapper: "/dev/mapper/root"
        },
        root_integrity_digest: $root_hash,
        signing_status: "unsigned"
      }' > "$TMPDIR/manifest-without-bundle-digest.json"
    jq --compact-output --sort-keys . \
      "$TMPDIR/manifest-without-bundle-digest.json" > "$TMPDIR/canonical-manifest"
    bundle_digest="$({
      printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
      cat "$TMPDIR/canonical-manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    jq --arg bundle_digest "sha256:$bundle_digest" \
      '. + {bundle_digest: $bundle_digest}' \
      "$TMPDIR/manifest-without-bundle-digest.json" > "$out/manifest.json"
    chmod 0444 "$out/manifest.json"
  ''
