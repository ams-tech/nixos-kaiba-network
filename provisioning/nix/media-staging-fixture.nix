{
  fixtureSnapshot,
  lib,
  mediaStager,
  pkgs,
}:

let
  cleanAbsolute =
    value:
    builtins.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !(lib.hasInfix "//" value)
    && !(lib.hasInfix "/./" value)
    && !(lib.hasInfix "/../" value)
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value);
  storeBacked =
    value: cleanAbsolute (toString value) && lib.hasPrefix "${builtins.storeDir}/" (toString value);

  mkRpi5MediaStagingFixture =
    {
      verifiedCapsule,
      bootFilesystemSizeMiB ? 128,
      name ? "kaiba-rpi5-media-staging-fixture",
    }:
    let
      capsuleContract =
        if builtins.isAttrs verifiedCapsule && verifiedCapsule ? kaibaVerifiedUnfusedCapsule then
          verifiedCapsule.kaibaVerifiedUnfusedCapsule
        else
          null;
      unsignedArtifacts =
        if capsuleContract != null && capsuleContract ? unsignedArtifacts then
          capsuleContract.unsignedArtifacts
        else
          null;

      assets =
        pkgs.runCommand "${name}-assets"
          {
            verifiedCapsuleInput = verifiedCapsule;
            unsignedArtifactsInput = unsignedArtifacts;
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.diffutils
              pkgs.dosfstools
              pkgs.findutils
              pkgs.gptfdisk
              pkgs.jq
              pkgs.mtools
            ];
            preferLocalBuild = true;
          }
          ''
                set -euo pipefail
                export LC_ALL=C
                export TZ=UTC
                umask 022

                readonly capsule="$verifiedCapsuleInput/capsule"
                readonly capsule_manifest="$verifiedCapsuleInput/capsule-manifest.json"
                readonly compatibility_result="$verifiedCapsuleInput/compatibility-result.json"
                readonly unsigned_manifest="$unsignedArtifactsInput/manifest.json"
                readonly alignment_bytes=1048576
                readonly sector_size_bytes=512
                readonly boot_filesystem_size_bytes=$((${toString bootFilesystemSizeMiB} * 1024 * 1024))

                for input in \
                  "$capsule/boot.img" \
                  "$capsule/boot.sig" \
                  "$capsule/nvme/root-data.img" \
                  "$capsule/nvme/root-hash.img" \
                  "$capsule_manifest" \
                  "$compatibility_result" \
                  "$unsigned_manifest"
                do
                  test -f "$input"
                  test ! -L "$input"
                  test -s "$input"
                done

                jq -e '
                  .status == "compatibility_passed"
                  and .evidence_mode == "offline_fixture"
                  and .signature_verified == true
                  and .signer_trust_anchored == true
                  and .hardware_observed == false
                  and .security_enforced == false
                  and .mutation_eligible == false
                ' "$compatibility_result" > /dev/null

              digest_file() {
                local digest
                digest="$(sha256sum "$1" | cut -d ' ' -f 1)"
                printf 'sha256:%s' "$digest"
              }
              digest_extent() {
                local source="$1"
                local offset="$2"
                local size="$3"
                local digest
                digest="$(
                  dd if="$source" iflag=skip_bytes,count_bytes \
                    skip="$offset" count="$size" status=none \
                    | sha256sum \
                    | cut -d ' ' -f 1
                )"
                printf 'sha256:%s' "$digest"
              }
              digest_padded_file() {
                local source="$1"
                local padded_size="$2"
                local source_size
                local digest
                source_size="$(stat --format=%s "$source")"
                test "$source_size" -le "$padded_size"
                digest="$({
                  cat "$source"
                  head --bytes=$((padded_size - source_size)) /dev/zero
                } | sha256sum | cut -d ' ' -f 1)"
                printf 'sha256:%s' "$digest"
              }
                align_up() {
                  local value="$1"
                  printf '%d' $(( (value + alignment_bytes - 1) / alignment_bytes * alignment_bytes ))
                }
                derive_uuid() {
                  local domain="$1"
                  local hex
                  hex="$({
                    printf '%s\0' "$domain"
                    printf '%s\0%s' "$capsule_digest" "$boot_filesystem_size_bytes"
                  } | sha256sum | cut -d ' ' -f 1)"
                  printf '%s-%s-4%s-8%s-%s' \
                    "''${hex:0:8}" \
                    "''${hex:8:4}" \
                    "''${hex:13:3}" \
                    "''${hex:17:3}" \
                    "''${hex:20:12}"
                }

                capsule_id="$(jq -er .capsule_id "$capsule_manifest")"
                readonly capsule_id
                capsule_digest="$(jq -er .capsule_digest "$capsule_manifest")"
                readonly capsule_digest
                capsule_manifest_file_digest="$(digest_file "$capsule_manifest")"
                readonly capsule_manifest_file_digest
                boot_image_digest="$(jq -er '.files[] | select(.path == "boot.img") | .sha256' "$capsule_manifest")"
                readonly boot_image_digest
                boot_signature_digest="$(jq -er '.files[] | select(.path == "boot.sig") | .sha256' "$capsule_manifest")"
                readonly boot_signature_digest
                root_data_digest="$(jq -er '.files[] | select(.path == "nvme/root-data.img") | .sha256' "$capsule_manifest")"
                readonly root_data_digest
                root_hash_digest="$(jq -er '.files[] | select(.path == "nvme/root-hash.img") | .sha256' "$capsule_manifest")"
                readonly root_hash_digest
                root_data_size_bytes="$(stat --format=%s "$capsule/nvme/root-data.img")"
                readonly root_data_size_bytes
                root_hash_size_bytes="$(stat --format=%s "$capsule/nvme/root-hash.img")"
                readonly root_hash_size_bytes
                root_integrity_digest="$(jq -er .root_integrity_digest "$unsigned_manifest")"
                readonly root_integrity_digest

                test "$(digest_file "$capsule/boot.img")" = "$boot_image_digest"
                test "$(digest_file "$capsule/boot.sig")" = "$boot_signature_digest"
                test "$(digest_file "$capsule/nvme/root-data.img")" = "$root_data_digest"
                test "$(digest_file "$capsule/nvme/root-hash.img")" = "$root_hash_digest"

                readonly stage="$TMPDIR/outer-fat"
                mkdir -p "$stage" "$out"
                install -m 0444 "$capsule/boot.img" "$stage/boot.img"
                install -m 0444 "$capsule/boot.sig" "$stage/boot.sig"
                printf '%s\n' 'boot_ramdisk=1' > "$stage/config.txt"
                chmod 0444 "$stage/config.txt"
                touch --date=@315532800 "$stage"/*

                truncate --size="$boot_filesystem_size_bytes" "$out/boot-filesystem.img"
                mkfs.vfat \
                  --invariant \
                  -F 32 \
                  -i 4b414942 \
                  -n KAIBA_BOOT \
                  "$out/boot-filesystem.img" \
                  > "$TMPDIR/mkfs-vfat.txt"
                mcopy -p -m -i "$out/boot-filesystem.img" \
                  "$stage/config.txt" \
                  "$stage/boot.img" \
                  "$stage/boot.sig" \
                  ::/

                readonly fat_readback="$TMPDIR/fat-readback"
                mkdir -p "$fat_readback"
                mcopy -s -i "$out/boot-filesystem.img" '::*' "$fat_readback/"
                find "$fat_readback" -type f -printf '%P\n' | sort > "$TMPDIR/actual-fat-files"
                printf '%s\n' boot.img boot.sig config.txt > "$TMPDIR/expected-fat-files"
                cmp "$TMPDIR/expected-fat-files" "$TMPDIR/actual-fat-files"
                test -z "$(find "$fat_readback" -type l -print -quit)"
                test -z "$(find "$fat_readback" ! -type d ! -type f -print -quit)"
                cmp "$capsule/boot.img" "$fat_readback/boot.img"
                cmp "$capsule/boot.sig" "$fat_readback/boot.sig"
                printf '%s\n' 'boot_ramdisk=1' > "$TMPDIR/expected-config.txt"
                cmp "$TMPDIR/expected-config.txt" "$fat_readback/config.txt"

                boot_filesystem_digest="$(digest_file "$out/boot-filesystem.img")"
                readonly boot_filesystem_digest
                config_digest="$(digest_file "$stage/config.txt")"
                readonly config_digest
                readonly boot_offset_bytes="$alignment_bytes"
                readonly boot_partition_size_bytes="$boot_filesystem_size_bytes"
                readonly root_data_offset_bytes=$((boot_offset_bytes + boot_partition_size_bytes))
                root_data_partition_size_bytes="$(align_up "$root_data_size_bytes")"
                readonly root_data_partition_size_bytes
                readonly root_hash_offset_bytes=$((root_data_offset_bytes + root_data_partition_size_bytes))
                root_hash_partition_size_bytes="$(align_up "$root_hash_size_bytes")"
                readonly root_hash_partition_size_bytes
                readonly target_size_bytes=$((root_hash_offset_bytes + root_hash_partition_size_bytes + alignment_bytes))
                readonly first_usable_lba=34
                readonly last_usable_lba=$((target_size_bytes / sector_size_bytes - 34))

                disk_guid="$(derive_uuid kaiba.provisioning.media-fixture.disk.v1)"
                readonly disk_guid
                boot_guid="$(derive_uuid kaiba.provisioning.media-fixture.partition.boot.v1)"
                readonly boot_guid
                root_data_guid="$(derive_uuid kaiba.provisioning.media-fixture.partition.root-data.v1)"
                readonly root_data_guid
              root_hash_guid="$(derive_uuid kaiba.provisioning.media-fixture.partition.root-hash.v1)"
              readonly root_hash_guid

            readonly gpt_template="$out/gpt-template.img"
              truncate --size="$target_size_bytes" "$gpt_template"
              readonly boot_start=$((boot_offset_bytes / sector_size_bytes))
              readonly boot_end=$((boot_start + boot_partition_size_bytes / sector_size_bytes - 1))
              readonly root_start=$((root_data_offset_bytes / sector_size_bytes))
              readonly root_end=$((root_start + root_data_partition_size_bytes / sector_size_bytes - 1))
              readonly hash_start=$((root_hash_offset_bytes / sector_size_bytes))
              readonly hash_end=$((hash_start + root_hash_partition_size_bytes / sector_size_bytes - 1))
              sgdisk \
                --clear \
                --set-alignment=$((alignment_bytes / sector_size_bytes)) \
                --disk-guid="$disk_guid" \
                --new=1:"$boot_start":"$boot_end" \
                --typecode=1:ef00 \
                --change-name=1:kaiba-boot \
                --partition-guid=1:"$boot_guid" \
                --new=2:"$root_start":"$root_end" \
                --typecode=2:8305 \
                --change-name=2:kaiba-root \
                --partition-guid=2:"$root_data_guid" \
                --new=3:"$hash_start":"$hash_end" \
                --typecode=3:830e \
                --change-name=3:kaiba-root-verity \
                --partition-guid=3:"$root_hash_guid" \
                "$gpt_template" > /dev/null
              sgdisk --verify "$gpt_template" > /dev/null
              readonly primary_gpt_offset_bytes=0
              readonly primary_gpt_size_bytes="$alignment_bytes"
              readonly backup_gpt_offset_bytes=$((target_size_bytes - alignment_bytes))
              readonly backup_gpt_size_bytes="$alignment_bytes"
              primary_gpt_digest="$(digest_extent \
                "$gpt_template" "$primary_gpt_offset_bytes" "$primary_gpt_size_bytes")"
              readonly primary_gpt_digest
            backup_gpt_digest="$(digest_extent \
              "$gpt_template" "$backup_gpt_offset_bytes" "$backup_gpt_size_bytes")"
            readonly backup_gpt_digest
            gpt_template_digest="$(digest_file "$gpt_template")"
            readonly gpt_template_digest
              boot_partition_digest="$(digest_padded_file \
                "$out/boot-filesystem.img" "$boot_partition_size_bytes")"
              readonly boot_partition_digest
              root_data_partition_digest="$(digest_padded_file \
                "$capsule/nvme/root-data.img" "$root_data_partition_size_bytes")"
              readonly root_data_partition_digest
              root_hash_partition_digest="$(digest_padded_file \
                "$capsule/nvme/root-hash.img" "$root_hash_partition_size_bytes")"
              readonly root_hash_partition_digest

                jq --null-input --sort-keys \
                  --arg schema_version 'provisioning.kaiba.network/rpi5-media-staging-fixture/v1alpha1' \
                  --arg fixture_id "$capsule_id:media-staging-fixture" \
                  --arg capsule_id "$capsule_id" \
                  --arg capsule_digest "$capsule_digest" \
                  --arg capsule_manifest_file_digest "$capsule_manifest_file_digest" \
                  --arg disk_guid "$disk_guid" \
                  --arg boot_guid "$boot_guid" \
                  --arg root_data_guid "$root_data_guid" \
                  --arg root_hash_guid "$root_hash_guid" \
                  --arg boot_filesystem_path "$out/boot-filesystem.img" \
                  --arg boot_filesystem_digest "$boot_filesystem_digest" \
                  --arg boot_image_digest "$boot_image_digest" \
                  --arg boot_signature_digest "$boot_signature_digest" \
                  --arg config_digest "$config_digest" \
                  --arg root_data_path "$capsule/nvme/root-data.img" \
                  --arg root_data_digest "$root_data_digest" \
                  --arg root_hash_path "$capsule/nvme/root-hash.img" \
                  --arg root_hash_digest "$root_hash_digest" \
                --arg root_integrity_digest "$root_integrity_digest" \
                --arg primary_gpt_digest "$primary_gpt_digest" \
              --arg backup_gpt_digest "$backup_gpt_digest" \
              --arg gpt_template_path "$gpt_template" \
              --arg gpt_template_digest "$gpt_template_digest" \
                --arg boot_partition_digest "$boot_partition_digest" \
                --arg root_data_partition_digest "$root_data_partition_digest" \
                --arg root_hash_partition_digest "$root_hash_partition_digest" \
                  --argjson sector_size_bytes "$sector_size_bytes" \
                  --argjson alignment_bytes "$alignment_bytes" \
                  --argjson target_size_bytes "$target_size_bytes" \
                  --argjson first_usable_lba "$first_usable_lba" \
                --argjson last_usable_lba "$last_usable_lba" \
                --argjson primary_gpt_offset_bytes "$primary_gpt_offset_bytes" \
                --argjson primary_gpt_size_bytes "$primary_gpt_size_bytes" \
                --argjson backup_gpt_offset_bytes "$backup_gpt_offset_bytes" \
                --argjson backup_gpt_size_bytes "$backup_gpt_size_bytes" \
                  --argjson boot_offset_bytes "$boot_offset_bytes" \
                  --argjson boot_size_bytes "$boot_filesystem_size_bytes" \
                  --argjson boot_partition_size_bytes "$boot_partition_size_bytes" \
                  --argjson root_data_offset_bytes "$root_data_offset_bytes" \
                  --argjson root_data_size_bytes "$root_data_size_bytes" \
                  --argjson root_data_partition_size_bytes "$root_data_partition_size_bytes" \
                  --argjson root_hash_offset_bytes "$root_hash_offset_bytes" \
                  --argjson root_hash_size_bytes "$root_hash_size_bytes" \
                  --argjson root_hash_partition_size_bytes "$root_hash_partition_size_bytes" \
                  '{
                    schema_version: $schema_version,
                    fixture_id: $fixture_id,
                    evidence_mode: "regular_file_fixture",
                    capsule: {
                      capsule_id: $capsule_id,
                      capsule_digest: $capsule_digest,
                      manifest_file_digest: $capsule_manifest_file_digest
                    },
                    sector_size_bytes: $sector_size_bytes,
                    alignment_bytes: $alignment_bytes,
                    target_size_bytes: $target_size_bytes,
                    gpt: {
                    disk_guid: $disk_guid,
                    template_path: $gpt_template_path,
                    template_digest: $gpt_template_digest,
                      backup_reserved_bytes: $alignment_bytes,
                      first_usable_lba: $first_usable_lba,
                      last_usable_lba: $last_usable_lba,
                      metadata_regions: [
                        {
                          role: "primary",
                          offset_bytes: $primary_gpt_offset_bytes,
                          size_bytes: $primary_gpt_size_bytes,
                          digest: $primary_gpt_digest
                        },
                        {
                          role: "backup",
                          offset_bytes: $backup_gpt_offset_bytes,
                          size_bytes: $backup_gpt_size_bytes,
                          digest: $backup_gpt_digest
                        }
                      ],
                      partitions: [
                        {
                          number: 1,
                          name: "kaiba-boot",
                          role: "boot-filesystem",
                          type_code: "ef00",
                          type_guid: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                          unique_guid: $boot_guid,
                          attributes: null,
                          content_digest: $boot_partition_digest,
                          offset_bytes: $boot_offset_bytes,
                          partition_size_bytes: $boot_partition_size_bytes
                        },
                        {
                          number: 2,
                          name: "kaiba-root",
                          role: "root-data",
                          type_code: "8305",
                          type_guid: "b921b045-1df0-41c3-af44-4c6f280d3fae",
                          unique_guid: $root_data_guid,
                          attributes: null,
                          content_digest: $root_data_partition_digest,
                          offset_bytes: $root_data_offset_bytes,
                          partition_size_bytes: $root_data_partition_size_bytes
                        },
                        {
                          number: 3,
                          name: "kaiba-root-verity",
                          role: "root-hash",
                          type_code: "830e",
                          type_guid: "df3300ce-d69f-4c92-978c-9bfb0f38d820",
                          unique_guid: $root_hash_guid,
                          attributes: null,
                          content_digest: $root_hash_partition_digest,
                          offset_bytes: $root_hash_offset_bytes,
                          partition_size_bytes: $root_hash_partition_size_bytes
                        }
                      ]
                    },
                    boot_filesystem: {
                      filesystem: "fat32",
                      label: "KAIBA_BOOT",
                      volume_id: "4b414942",
                      allowlist: [
                        { path: "boot.img", digest: $boot_image_digest },
                        { path: "boot.sig", digest: $boot_signature_digest },
                        { path: "config.txt", digest: $config_digest }
                      ]
                    },
                    images: [
                      {
                        role: "boot-filesystem",
                        source_path: $boot_filesystem_path,
                        digest: $boot_filesystem_digest,
                        size_bytes: $boot_size_bytes,
                        offset_bytes: $boot_offset_bytes
                      },
                      {
                        role: "root-data",
                        source_path: $root_data_path,
                        digest: $root_data_digest,
                        size_bytes: $root_data_size_bytes,
                        offset_bytes: $root_data_offset_bytes
                      },
                      {
                        role: "root-hash",
                        source_path: $root_hash_path,
                        digest: $root_hash_digest,
                        size_bytes: $root_hash_size_bytes,
                        offset_bytes: $root_hash_offset_bytes
                      }
                    ],
                    verity: {
                      algorithm: "sha256",
                      root_hash: $root_integrity_digest,
                      data_block_size: 4096,
                      hash_block_size: 4096
                    },
                    safety: {
                      synthetic: true,
                      block_device_access: false,
                      hardware_observed: false,
                      security_enforced: false,
                      mutation_eligible: false,
                      one_time_settings_changed: false,
                      gpt_bound_by_stager_receipt: false,
                      cold_power_cycle_observed: false
                    }
                  }' > "$TMPDIR/layout-without-digest.json"

                jq --compact-output --sort-keys . "$TMPDIR/layout-without-digest.json" \
                  > "$TMPDIR/canonical-layout.json"
                layout_digest="sha256:$({
                  printf '%s\0' 'kaiba.provisioning.rpi5-media-staging-fixture.v1alpha1'
                  cat "$TMPDIR/canonical-layout.json"
                } | sha256sum | cut -d ' ' -f 1)"
                jq --arg layout_digest "$layout_digest" \
                  '. + {layout_digest: $layout_digest}' \
                  "$TMPDIR/layout-without-digest.json" > "$out/layout.json"

            chmod 0444 \
              "$out/boot-filesystem.img" \
              "$out/gpt-template.img" \
              "$out/layout.json"
          '';

      fixtureTool = pkgs.writeShellApplication {
        name = "kaiba-provision-media-fixture";
        runtimeInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.diffutils
          pkgs.findutils
          fixtureSnapshot
          pkgs.gptfdisk
          pkgs.gnused
          pkgs.jq
          pkgs.mtools
          pkgs.util-linux
        ];
        text = ''
          readonly assets=${lib.escapeShellArg (toString assets)}
          readonly layout="$assets/layout.json"

          usage() {
            echo 'usage: kaiba-provision-media-fixture {init|verify} --workspace /absolute/path' >&2
            exit 2
          }
          fail() {
            echo "kaiba-provision-media-fixture: $*" >&2
            exit 1
          }
          require_clean_absolute_workspace() {
            local requested="$1"
            case "$requested" in
              (/*) ;;
              (*) fail 'workspace must be an absolute path' ;;
            esac
            test "$(realpath -m -- "$requested")" = "$requested" \
              || fail 'workspace path must be clean and canonical'
            case "$requested" in
              (/|/dev|/dev/*|/nix|/nix/store|/nix/store/*)
                fail 'workspace must be outside /dev and the Nix store'
                ;;
            esac
          }
          layout_value() {
            jq -er "$1" "$layout"
          }
          partition_value() {
            local number="$1"
            local field="$2"
            jq -er --argjson number "$number" \
              ".gpt.partitions[] | select(.number == \$number) | .$field" \
              "$layout"
          }
          digest_extent() {
            local extent_target="$1"
            local offset="$2"
            local size="$3"
            dd if="$extent_target" iflag=skip_bytes,count_bytes skip="$offset" count="$size" status=none \
              | sha256sum \
              | sed 's/^/sha256:/' \
              | cut -d ' ' -f 1
          }
          write_fixture_plan() {
            local destination="$1"
            (
              set -o noclobber
              jq --null-input \
                --arg target "$target" \
                --arg identity "$(basename -- "$target")" \
                --argjson target_size "$(layout_value .target_size_bytes)" \
                --slurpfile layout "$layout" \
                '{
                  schema_version: "provisioning.kaiba.network/media-staging-plan/v1alpha1",
                  target: {
                    path: $target,
                    expected_identity: $identity,
                    expected_size_bytes: $target_size
                  },
                  images: ($layout[0].images | map({
                    role: .role,
                    path: .source_path,
                    digest: .digest,
                    size_bytes: .size_bytes,
                    offset_bytes: .offset_bytes
                  }))
                }' > "$destination"
            )
          }
          verify_gpt_metadata() {
            local metadata_target="$1"
            while IFS=$'\t' read -r role offset size expected; do
              actual="$(digest_extent "$metadata_target" "$offset" "$size")"
              test "$actual" = "$expected" \
                || fail "$role GPT metadata differs from the immutable layout"
            done < <(jq -r \
              '.gpt.metadata_regions[] | [.role, .offset_bytes, .size_bytes, .digest] | @tsv' \
              "$layout")
          }
          verify_partition_contents() {
            local partition_target="$1"
            while IFS=$'\t' read -r role offset size expected; do
              actual="$(digest_extent "$partition_target" "$offset" "$size")"
              test "$actual" = "$expected" \
                || fail "$role partition content differs from the immutable layout"
            done < <(jq -r \
              '.gpt.partitions[] | [.role, .offset_bytes, .partition_size_bytes, .content_digest] | @tsv' \
              "$layout")
          }

          test "$#" -eq 3 || usage
          readonly action="$1"
          test "$2" = '--workspace' || usage
          readonly workspace="$3"
          require_clean_absolute_workspace "$workspace"
          readonly target="$workspace/target.img"
          readonly plan="$workspace/fixture-plan.json"

          case "$action" in
            (init)
              test ! -e "$workspace" && test ! -L "$workspace" \
                || fail 'init requires a new workspace path'
              parent="$(dirname -- "$workspace")"
              readonly parent
              test -d "$parent" && test ! -L "$parent" \
                || fail 'workspace parent must be an existing non-symlink directory'
              umask 077
              mkdir --mode=0700 -- "$workspace"
              target_size="$(layout_value .target_size_bytes)"
              readonly target_size
              gpt_template="$(layout_value .gpt.template_path)"
              readonly gpt_template
              kaiba-provision-fixture-snapshot \
                --source "$gpt_template" \
                --destination "$target" \
                --expected-size "$target_size" \
                || fail 'could not install the canonical regular-file GPT template'

              init_dir="$(mktemp -d)"
              readonly init_dir
              cleanup_init() {
                rm -rf -- "$init_dir"
              }
              trap cleanup_init EXIT
              readonly plan_source="$init_dir/fixture-plan.json"
              write_fixture_plan "$plan_source"
              plan_size="$(stat --format=%s "$plan_source")"
              readonly plan_size
              kaiba-provision-fixture-snapshot \
                --source "$plan_source" \
                --destination "$plan" \
                --expected-size "$plan_size" \
                || fail 'could not install the exact regular-file fixture plan'
              test -d "$workspace" && test ! -L "$workspace" \
                && test -f "$target" && test ! -L "$target" \
                && test -f "$plan" && test ! -L "$plan" \
                || fail 'fixture workspace identity changed during initialization'
              jq --null-input \
                --arg workspace "$workspace" \
                --arg target "$target" \
                --arg plan "$plan" \
                --arg layout_digest "$(layout_value .layout_digest)" \
                '{
                  status: "fixture_initialized",
                  evidence_mode: "regular_file_fixture",
                  workspace: $workspace,
                  target: $target,
                  plan: $plan,
                  layout_digest: $layout_digest,
                  block_device_access: false,
                  one_time_settings_changed: false
                }'
              ;;
            (verify)
              test -d "$workspace" && test ! -L "$workspace" \
                || fail 'verify requires an existing non-symlink workspace'
              for input in "$target" "$plan"; do
                test -f "$input" && test ! -L "$input" \
                  || fail "missing non-symlink regular file: $input"
              done
              verify_dir="$(mktemp -d)"
              readonly verify_dir
              cleanup() {
                rm -rf -- "$verify_dir"
              }
              trap cleanup EXIT

              readonly expected_plan="$verify_dir/expected-fixture-plan.json"
              write_fixture_plan "$expected_plan"
              plan_size="$(stat --format=%s "$expected_plan")"
              readonly plan_size
              readonly verify_plan="$verify_dir/fixture-plan-snapshot.json"
              kaiba-provision-fixture-snapshot \
                --source "$plan" \
                --destination "$verify_plan" \
                --expected-size "$plan_size" \
                || fail 'could not take a locked regular-file plan snapshot'
              cmp "$expected_plan" "$verify_plan" \
                || fail 'fixture plan differs from the immutable layout'

              readonly verify_target="$verify_dir/target-snapshot.img"
              kaiba-provision-fixture-snapshot \
                --source "$target" \
                --destination "$verify_target" \
                --expected-size "$(layout_value .target_size_bytes)" \
                || fail 'could not take a locked regular-file target snapshot'
              test "$(stat --format=%s "$verify_target")" = "$(layout_value .target_size_bytes)" \
                || fail 'target snapshot size differs from the immutable layout'

              verify_gpt_metadata "$verify_target"
              sgdisk --verify "$verify_target" > /dev/null
              readonly gpt_json="$verify_dir/gpt-readback.json"
              sfdisk --json "$verify_target" > "$gpt_json"
              jq -e --arg target "$verify_target" --slurpfile layout "$layout" '
                .partitiontable.label == "gpt"
                and .partitiontable.device == $target
                and .partitiontable.unit == "sectors"
                and .partitiontable.sectorsize == $layout[0].sector_size_bytes
                and .partitiontable.firstlba == $layout[0].gpt.first_usable_lba
                and .partitiontable.lastlba == $layout[0].gpt.last_usable_lba
                and (.partitiontable.id | ascii_downcase) == $layout[0].gpt.disk_guid
                and ([.partitiontable.partitions[] | {
                  node: .node,
                  attributes: (.attrs // null),
                  name: .name,
                  start: .start,
                  size: .size,
                  type_guid: (.type | ascii_downcase),
                  unique_guid: (.uuid | ascii_downcase)
                }] == [$layout[0].gpt.partitions[] | {
                  node: ($target + (.number | tostring)),
                  attributes: .attributes,
                  name: .name,
                  start: (.offset_bytes / $layout[0].sector_size_bytes),
                  size: (.partition_size_bytes / $layout[0].sector_size_bytes),
                  type_guid: .type_guid,
                  unique_guid: .unique_guid
                }])
              ' "$gpt_json" > /dev/null \
                || fail 'GPT readback differs from the immutable layout'

              verify_partition_contents "$verify_target"

              while IFS=$'\t' read -r role offset size expected; do
                actual="$(digest_extent "$verify_target" "$offset" "$size")"
                test "$actual" = "$expected" \
                  || fail "$role extent digest differs from the immutable layout"
              done < <(jq -r '.images[] | [.role, .offset_bytes, .size_bytes, .digest] | @tsv' "$layout")

              dd if="$verify_target" of="$verify_dir/boot-filesystem.img" \
                iflag=skip_bytes,count_bytes \
                skip="$(partition_value 1 offset_bytes)" \
                count="$(layout_value '.images[] | select(.role == "boot-filesystem") | .size_bytes')" \
                status=none
              mkdir "$verify_dir/fat"
              mcopy -s -i "$verify_dir/boot-filesystem.img" '::*' "$verify_dir/fat/"
              find "$verify_dir/fat" -type f -printf '%P\n' | sort > "$verify_dir/actual-fat-files"
              printf '%s\n' boot.img boot.sig config.txt > "$verify_dir/expected-fat-files"
              cmp "$verify_dir/expected-fat-files" "$verify_dir/actual-fat-files" \
                || fail 'outer FAT allowlist differs from the immutable layout'
              test -z "$(find "$verify_dir/fat" -type l -print -quit)" \
                || fail 'outer FAT contains a symbolic link'
              cmp ${lib.escapeShellArg (toString verifiedCapsule)}/capsule/boot.img "$verify_dir/fat/boot.img"
              cmp ${lib.escapeShellArg (toString verifiedCapsule)}/capsule/boot.sig "$verify_dir/fat/boot.sig"
              printf '%s\n' 'boot_ramdisk=1' > "$verify_dir/expected-config.txt"
              cmp "$verify_dir/expected-config.txt" "$verify_dir/fat/config.txt"

              dd if="$verify_target" of="$verify_dir/root-data.img" \
                iflag=skip_bytes,count_bytes conv=sparse \
                skip="$(partition_value 2 offset_bytes)" \
                count="$(layout_value '.images[] | select(.role == "root-data") | .size_bytes')" \
                status=none
              dd if="$verify_target" of="$verify_dir/root-hash.img" \
                iflag=skip_bytes,count_bytes conv=sparse \
                skip="$(partition_value 3 offset_bytes)" \
                count="$(layout_value '.images[] | select(.role == "root-hash") | .size_bytes')" \
                status=none
              root_hash="$(layout_value .verity.root_hash)"
              readonly root_hash
              veritysetup verify \
                --data-block-size="$(layout_value .verity.data_block_size)" \
                --hash-block-size="$(layout_value .verity.hash_block_size)" \
                "$verify_dir/root-data.img" \
                "$verify_dir/root-hash.img" \
                "''${root_hash#sha256:}"

              jq --null-input \
                --arg layout_digest "$(layout_value .layout_digest)" \
                '{
                  status: "fixture_layout_verified",
                  evidence_mode: "regular_file_fixture",
                  layout_digest: $layout_digest,
                  gpt_verified: true,
                  fat_allowlist_verified: true,
                  extent_digests_verified: true,
                  partition_contents_verified: true,
                  dm_verity_verified: true,
                  pinned_regular_file_snapshot_verified: true,
                  hardware_observed: false,
                  security_enforced: false,
                  mutation_eligible: false,
                  cold_power_cycle_observed: false,
                  one_time_settings_changed: false
                }'
              ;;
            (*) usage ;;
          esac
        '';
      };
    in
    assert lib.assertMsg (storeBacked verifiedCapsule) "verifiedCapsule must be a fixed Nix-store path";
    assert lib.assertMsg (
      capsuleContract != null
      && (capsuleContract.signatureVerificationRequired or false)
      && (capsuleContract.signerTrustAnchored or false)
      && (capsuleContract.dmVerityVerified or false)
      && (capsuleContract.fixtureSynthetic or false)
      && (capsuleContract.verificationMode or null) == "pure_offline_synthetic_fixture"
      && lib.all (value: value == false) [
        (capsuleContract.blockDeviceWriteCapable or true)
        (capsuleContract.directHardwareAccess or true)
        (capsuleContract.eepromProgrammingCapable or true)
        (capsuleContract.mutationCapable or true)
        (capsuleContract.oneTimeSettingCapable or true)
        (capsuleContract.otpCapable or true)
        (capsuleContract.privateKeyAccess or true)
        (capsuleContract.securityEnforcementClaim or true)
        (capsuleContract.signingAuthorityConfigured or true)
      ]
    ) "verifiedCapsule must be a signer-anchored, synthetic, non-mutating unfused capsule";
    assert lib.assertMsg (storeBacked unsignedArtifacts)
      "verifiedCapsule must retain its fixed unsigned-artifact input";
    assert lib.assertMsg (
      builtins.isInt bootFilesystemSizeMiB && bootFilesystemSizeMiB >= 128 && bootFilesystemSizeMiB <= 512
    ) "bootFilesystemSizeMiB must be between 128 and 512";
    pkgs.symlinkJoin {
      inherit name;
      paths = [
        assets
        fixtureTool
      ];
      passthru.kaibaMediaStagingFixture = {
        inherit
          assets
          bootFilesystemSizeMiB
          fixtureSnapshot
          mediaStager
          verifiedCapsule
          ;
        alignmentBytes = 1048576;
        blockDeviceAccess = false;
        blockDeviceWriteCapable = false;
        coldPowerCycleClaim = false;
        fixtureFileWriteCapable = true;
        gptBoundByStagerReceipt = false;
        hardwareObservationClaim = false;
        mutationCapable = false;
        oneTimeSettingCapable = false;
        otpCapable = false;
        sectorSizeBytes = 512;
        securityEnforcementClaim = false;
        snapshotExclusiveLockRequired = true;
        snapshotPinnedRegularFile = true;
      };
      meta = {
        description = "Deterministic GPT/FAT regular-file staging fixture for a verified Pi 5 capsule";
        platforms = lib.platforms.linux;
      };
    };
in
{
  inherit mkRpi5MediaStagingFixture;
}
