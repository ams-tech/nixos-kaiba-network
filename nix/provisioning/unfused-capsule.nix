{
  pkgs,
  lib,
  mkRpi5UnfusedVerifier,
  unsignedArtifactSchema,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalIdentifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
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

  mkRpi5VerifiedUnfusedCapsule =
    {
      capsuleID,
      trustedPublicKeyFingerprint,
      unsignedArtifacts,
      verifiedSignedBoot,
      fixtureID ? "${capsuleID}:synthetic",
      name ? "kaiba-rpi5-verified-unfused-capsule",
    }:
    let
      verifiedContract =
        if builtins.isAttrs verifiedSignedBoot && verifiedSignedBoot ? kaibaVerifiedSignedBoot then
          verifiedSignedBoot.kaibaVerifiedSignedBoot
        else
          null;
      unsignedContract =
        if builtins.isAttrs unsignedArtifacts && unsignedArtifacts ? kaibaUnsignedArtifacts then
          unsignedArtifacts.kaibaUnsignedArtifacts
        else
          null;
      signingPlan =
        if verifiedContract != null && verifiedContract ? signingPlan then
          verifiedContract.signingPlan
        else
          null;
      signingPlanContract =
        if builtins.isAttrs signingPlan && signingPlan ? kaibaBootSigningPlan then
          signingPlan.kaibaBootSigningPlan
        else
          null;
      signedBootFingerprint =
        if signingPlanContract != null && signingPlanContract ? publicKeyFingerprint then
          signingPlanContract.publicKeyFingerprint
        else
          null;
      unfusedVerifier = mkRpi5UnfusedVerifier {
        name = "${name}-signer-pinned-verifier";
        inherit trustedPublicKeyFingerprint;
      };
    in
    assert lib.assertMsg (storeBacked verifiedSignedBoot)
      "verifiedSignedBoot must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked unsignedArtifacts)
      "unsignedArtifacts must be a fixed Nix-store path";
    assert lib.assertMsg (storeBacked unsignedArtifactSchema)
      "unsignedArtifactSchema must be a fixed Nix-store path";
    assert lib.assertMsg (canonicalIdentifier capsuleID)
      "capsuleID must be a canonical lowercase identifier";
    assert lib.assertMsg (canonicalIdentifier fixtureID)
      "fixtureID must be a canonical lowercase identifier";
    assert lib.assertMsg (
      verifiedContract != null
      && (verifiedContract.signatureVerificationRequired or false)
      && (verifiedContract.verificationMode or null) == "pure_offline"
      && lib.all (value: value == false) [
        (verifiedContract.blockDeviceWriteCapable or true)
        (verifiedContract.directHardwareAccess or true)
        (verifiedContract.eepromProgrammingCapable or true)
        (verifiedContract.mutationCapable or true)
        (verifiedContract.oneTimeSettingCapable or true)
        (verifiedContract.otpCapable or true)
        (verifiedContract.privateKeyAccess or true)
        (verifiedContract.signingAuthorityConfigured or true)
      ]
    ) "verifiedSignedBoot must be produced by the pure public signed-boot finalizer";
    assert lib.assertMsg (
      unsignedContract != null
      &&
        (unsignedContract.schemaVersion or null)
        == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
      && (unsignedContract.signingStatus or null) == "unsigned"
      && lib.all (value: value == false) [
        (unsignedContract.blockDeviceWriteCapable or true)
        (unsignedContract.directHardwareAccess or true)
        (unsignedContract.eepromProgrammingCapable or true)
        (unsignedContract.mutationCapable or true)
        (unsignedContract.oneTimeSettingCapable or true)
        (unsignedContract.otpCapable or true)
        (unsignedContract.privateKeyAccess or true)
        (unsignedContract.signingAuthorityConfigured or true)
      ]
    ) "unsignedArtifacts must be a public, non-mutating unsigned artifact set";
    assert lib.assertMsg (canonicalDigest signedBootFingerprint)
      "verifiedSignedBoot must retain its canonical signing-plan public-key fingerprint";
    assert lib.assertMsg (canonicalDigest trustedPublicKeyFingerprint)
      "trustedPublicKeyFingerprint must be an independently reviewed canonical digest";
    assert lib.assertMsg (
      signedBootFingerprint == trustedPublicKeyFingerprint
    ) "independent signer trust anchor must match the verified signed-boot signing plan";
    pkgs.runCommand name
      {
        verifiedSignedBootInput = verifiedSignedBoot;
        unsignedArtifactsInput = unsignedArtifacts;
        unfusedVerifierInput = unfusedVerifier;
        unsignedArtifactSchemaInput = unsignedArtifactSchema;
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.findutils
          pkgs.gawk
          pkgs.jq
          pkgs.mtools
          pkgs.python3
        ];
        passthru.kaibaVerifiedUnfusedCapsule = {
          inherit
            capsuleID
            fixtureID
            unfusedVerifier
            unsignedArtifacts
            verifiedSignedBoot
            ;
          blockDeviceWriteCapable = false;
          capsuleSchemaVersion = "provisioning.kaiba.network/rpi5-unfused-capsule-manifest/v1alpha1";
          directHardwareAccess = false;
          dmVerityVerified = true;
          eepromProgrammingCapable = false;
          evidenceMode = "offline_fixture";
          fixtureSchemaVersion = "provisioning.kaiba.network/rpi5-unfused-compatibility-fixture/v1alpha1";
          fixtureSynthetic = true;
          hardwareObservationClaim = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          securityEnforcementClaim = false;
          signatureVerificationRequired = true;
          signerTrustAnchored = true;
          signingAuthorityConfigured = false;
          inherit trustedPublicKeyFingerprint;
          verificationMode = "pure_offline_synthetic_fixture";
        };
        preferLocalBuild = true;
        meta = {
          description = "Signer-verified four-role Raspberry Pi 5 unfused compatibility capsule";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        readonly signed="$verifiedSignedBootInput"
        readonly unsigned="$unsignedArtifactsInput"
        readonly verifier="$unfusedVerifierInput/bin/kaiba-provision-unfused-compat"
        readonly unsigned_manifest="$unsigned/manifest.json"
        readonly capsule="$out/capsule"
        readonly capsule_id=${lib.escapeShellArg capsuleID}
        readonly fixture_id=${lib.escapeShellArg fixtureID}

        test -d "$signed"
        test ! -L "$signed"
        test -d "$unsigned"
        test ! -L "$unsigned"
        test -d "$unfusedVerifierInput"
        test ! -L "$unfusedVerifierInput"
        test -x "$verifier"

        for input in \
          "$signed/boot.img" \
          "$signed/boot.sig" \
          "$signed/public.pem" \
          "$unsigned/unsigned/boot.img" \
          "$unsigned/nvme/root-data.img" \
          "$unsigned/nvme/root-hash.img" \
          "$unsigned_manifest"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done
        test -f "$unsignedArtifactSchemaInput"
        test ! -L "$unsignedArtifactSchemaInput"
        test -s "$unsignedArtifactSchemaInput"

        digest_file() {
          printf 'sha256:%s' "$(sha256sum "$1" | cut -d ' ' -f 1)"
        }

        python3 - "$unsigned_manifest" <<'PY'
        import json
        import pathlib
        import sys

        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError(f"non-finite JSON number: {value}")

        encoded = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        decoder = json.JSONDecoder(
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
        _, end = decoder.raw_decode(encoded)
        if encoded[end:].strip():
            raise ValueError("trailing JSON value")
        PY

        check-jsonschema \
          --schemafile "$unsignedArtifactSchemaInput" \
          "$unsigned_manifest"

        jq -e '
          .schema == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
          and .signing_status == "unsigned"
          and .artifacts.boot_image.path == "unsigned/boot.img"
          and .artifacts.root_data.path == "nvme/root-data.img"
          and .artifacts.root_hash_tree.path == "nvme/root-hash.img"
          and .verity.algorithm == "sha256"
          and .verity.data_block_size == 4096
          and .verity.hash_block_size == 4096
          and .verity.mapper == "/dev/mapper/root"
          and (.firmware_allowlist | index("kaiba-root-integrity.json") != null)
          and (.root_integrity_digest | test("^sha256:[0-9a-f]{64}$"))
          and (.bundle_digest | test("^sha256:[0-9a-f]{64}$"))
        ' "$unsigned_manifest" > /dev/null

        canonical_unsigned_manifest="$(jq --compact-output --sort-keys \
          'del(.bundle_digest)' "$unsigned_manifest")"
        expected_unsigned_bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unsigned-artifacts.v1'
          printf '%s' "$canonical_unsigned_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .bundle_digest "$unsigned_manifest")" = \
          "$expected_unsigned_bundle_digest"

        test "$(digest_file "$unsigned/unsigned/boot.img")" = \
          "$(jq -r .artifacts.boot_image.digest "$unsigned_manifest")"
        test "$(stat --format=%s "$unsigned/unsigned/boot.img")" = \
          "$(jq -r .boot_image_size_bytes "$unsigned_manifest")"
        test "$(digest_file "$unsigned/nvme/root-data.img")" = \
          "$(jq -r .artifacts.root_data.digest "$unsigned_manifest")"
        test "$(digest_file "$unsigned/nvme/root-hash.img")" = \
          "$(jq -r .artifacts.root_hash_tree.digest "$unsigned_manifest")"
        cmp "$signed/boot.img" "$unsigned/unsigned/boot.img"

        root_integrity_digest="$(jq -r .root_integrity_digest "$unsigned_manifest")"
        root_hash="''${root_integrity_digest#sha256:}"
        data_device="$(jq -r .verity.data_device "$unsigned_manifest")"
        hash_device="$(jq -r .verity.hash_device "$unsigned_manifest")"
        boot_command_line_path="$(jq -r .boot_command_line_path "$unsigned_manifest")"

        mtype \
          -i "$unsigned/unsigned/boot.img" \
          ::kaiba-root-integrity.json \
          > "$TMPDIR/kaiba-root-integrity.json"
        jq -e \
          --arg root_hash "$root_hash" \
          --arg data_device "$data_device" \
          --arg hash_device "$hash_device" \
          '
            keys == [
              "algorithm",
              "data_block_size",
              "data_device",
              "hash_block_size",
              "hash_device",
              "no_superblock",
              "root_hash",
              "schema"
            ]
            and .schema == "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1"
            and .algorithm == "sha256"
            and .data_block_size == 4096
            and .hash_block_size == 4096
            and .no_superblock == false
            and .root_hash == $root_hash
            and .data_device == $data_device
            and .hash_device == $hash_device
          ' "$TMPDIR/kaiba-root-integrity.json" > /dev/null

        mtype \
          -i "$unsigned/unsigned/boot.img" \
          "::$boot_command_line_path" \
          | tr '\r\n\t' '   ' \
          > "$TMPDIR/boot-command-line"

        require_exact_parameter() {
          awk -v expected="$1" '
            {
              for (field_index = 1; field_index <= NF; field_index++) {
                if ($field_index == expected) {
                  count++
                }
              }
            }
            END { exit count == 1 ? 0 : 1 }
          ' "$TMPDIR/boot-command-line"
        }
        require_unique_prefix() {
          awk -v prefix="$1" '
            {
              for (field_index = 1; field_index <= NF; field_index++) {
                if (substr($field_index, 1, length(prefix)) == prefix) {
                  count++
                }
              }
            }
            END { exit count == 1 ? 0 : 1 }
          ' "$TMPDIR/boot-command-line"
        }
        require_absent_prefix() {
          awk -v prefix="$1" '
            {
              for (field_index = 1; field_index <= NF; field_index++) {
                if (substr($field_index, 1, length(prefix)) == prefix) {
                  exit 1
                }
              }
            }
          ' "$TMPDIR/boot-command-line"
        }
        require_absent_parameter() {
          awk -v forbidden="$1" '
            {
              for (field_index = 1; field_index <= NF; field_index++) {
                if ($field_index == forbidden) {
                  exit 1
                }
              }
            }
          ' "$TMPDIR/boot-command-line"
        }

        require_exact_parameter ro
        require_exact_parameter 'root=/dev/mapper/root'
        require_exact_parameter 'rootfstype=ext4'
        require_exact_parameter 'rd.systemd.verity=1'
        require_exact_parameter "roothash=$root_hash"
        require_exact_parameter "systemd.verity_root_data=$data_device"
        require_exact_parameter "systemd.verity_root_hash=$hash_device"
        require_unique_prefix 'root='
        require_unique_prefix 'rootfstype='
        require_unique_prefix 'rd.systemd.verity='
        require_unique_prefix 'roothash='
        require_unique_prefix 'systemd.verity_root_data='
        require_unique_prefix 'systemd.verity_root_hash='
        require_absent_parameter rw
        require_absent_prefix 'systemd.verity='
        require_absent_prefix 'systemd.verity_root_options='
        require_absent_prefix 'rd.systemd.verity_root_data='
        require_absent_prefix 'rd.systemd.verity_root_hash='
        require_absent_prefix 'rd.systemd.verity_root_options='

        mkdir -p "$capsule/nvme"
        cp --reflink=auto --sparse=always \
          "$signed/boot.img" "$capsule/boot.img"
        cp --reflink=auto --sparse=always \
          "$signed/boot.sig" "$capsule/boot.sig"
        cp --reflink=auto --sparse=always \
          "$unsigned/nvme/root-data.img" "$capsule/nvme/root-data.img"
        cp --reflink=auto --sparse=always \
          "$unsigned/nvme/root-hash.img" "$capsule/nvme/root-hash.img"
        install -m 0444 "$signed/public.pem" "$out/public.pem"
        chmod 0444 \
          "$capsule/boot.img" \
          "$capsule/boot.sig" \
          "$capsule/nvme/root-data.img" \
          "$capsule/nvme/root-hash.img"

        readonly boot_image_size="$(stat --format=%s "$capsule/boot.img")"
        readonly boot_signature_size="$(stat --format=%s "$capsule/boot.sig")"
        readonly root_data_size="$(stat --format=%s "$capsule/nvme/root-data.img")"
        readonly root_hash_size="$(stat --format=%s "$capsule/nvme/root-hash.img")"
        readonly boot_image_digest="$(digest_file "$capsule/boot.img")"
        readonly boot_signature_digest="$(digest_file "$capsule/boot.sig")"
        readonly root_data_digest="$(digest_file "$capsule/nvme/root-data.img")"
        readonly root_hash_digest="$(digest_file "$capsule/nvme/root-hash.img")"

        test "$boot_image_digest" = \
          "$(jq -r .artifacts.boot_image.digest "$unsigned_manifest")"
        test "$root_data_digest" = \
          "$(jq -r .artifacts.root_data.digest "$unsigned_manifest")"
        test "$root_hash_digest" = \
          "$(jq -r .artifacts.root_hash_tree.digest "$unsigned_manifest")"
        veritysetup verify \
          "$capsule/nvme/root-data.img" \
          "$capsule/nvme/root-hash.img" \
          "$root_hash"

        readonly capsule_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.unfused-capsule.v1'
          printf '%s\0%s\0%s\0' 'boot.img' \
            "$boot_image_size" "$boot_image_digest"
          printf '%s\0%s\0%s\0' 'boot.sig' \
            "$boot_signature_size" "$boot_signature_digest"
          printf '%s\0%s\0%s\0' 'nvme/root-data.img' \
            "$root_data_size" "$root_data_digest"
          printf '%s\0%s\0%s\0' 'nvme/root-hash.img' \
            "$root_hash_size" "$root_hash_digest"
        } | sha256sum | cut -d ' ' -f 1)"

        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'provisioning.kaiba.network/rpi5-unfused-capsule-manifest/v1alpha1' \
          --arg capsule_id "$capsule_id" \
          --arg capsule_digest "$capsule_digest" \
          --arg boot_image_digest "$boot_image_digest" \
          --arg boot_signature_digest "$boot_signature_digest" \
          --arg root_data_digest "$root_data_digest" \
          --arg root_hash_digest "$root_hash_digest" \
          --argjson boot_image_size "$boot_image_size" \
          --argjson boot_signature_size "$boot_signature_size" \
          --argjson root_data_size "$root_data_size" \
          --argjson root_hash_size "$root_hash_size" \
          '{
            schema_version: $schema_version,
            capsule_id: $capsule_id,
            capsule_digest: $capsule_digest,
            boot_image_path: "boot.img",
            boot_signature_path: "boot.sig",
            root_data_path: "nvme/root-data.img",
            root_hash_path: "nvme/root-hash.img",
            files: [
              {
                path: "boot.img",
                size_bytes: $boot_image_size,
                sha256: $boot_image_digest
              },
              {
                path: "boot.sig",
                size_bytes: $boot_signature_size,
                sha256: $boot_signature_digest
              },
              {
                path: "nvme/root-data.img",
                size_bytes: $root_data_size,
                sha256: $root_data_digest
              },
              {
                path: "nvme/root-hash.img",
                size_bytes: $root_hash_size,
                sha256: $root_hash_digest
              }
            ]
          }' > "$out/capsule-manifest.json"

        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'provisioning.kaiba.network/rpi5-unfused-compatibility-fixture/v1alpha1' \
          --arg fixture_id "$fixture_id" \
          --arg capsule_id "$capsule_id" \
          --arg capsule_digest "$capsule_digest" \
          --arg boot_image_digest "$boot_image_digest" \
          --arg boot_signature_digest "$boot_signature_digest" \
          --arg root_data_digest "$root_data_digest" \
          --arg root_hash_digest "$root_hash_digest" \
          '{
            schema_version: $schema_version,
            fixture_id: $fixture_id,
            capsule_id: $capsule_id,
            capsule_digest: $capsule_digest,
            boot_image_digest: $boot_image_digest,
            boot_signature_digest: $boot_signature_digest,
            root_data_digest: $root_data_digest,
            root_hash_digest: $root_hash_digest,
            boot_mode: "boot_ramdisk",
            firmware_loaded: true,
            kernel_started: true,
            initramfs_started: true,
            compatibility_marker_observed: true
          }' > "$out/unfused-fixture.json"

        "$verifier" verify-signed-offline-fixture \
          --manifest "$out/capsule-manifest.json" \
          --capsule-root "$capsule" \
          --fixture "$out/unfused-fixture.json" \
          --public-key "$out/public.pem" \
          > "$out/compatibility-result.json"

        jq -e \
          --arg capsule_id "$capsule_id" \
          --arg fixture_id "$fixture_id" \
          --arg capsule_digest "$capsule_digest" \
          --arg boot_image_digest "$boot_image_digest" \
          --arg boot_signature_digest "$boot_signature_digest" \
          --arg root_data_digest "$root_data_digest" \
          --arg root_hash_digest "$root_hash_digest" \
          --arg public_key_fingerprint '${trustedPublicKeyFingerprint}' \
          '
            .schema_version
              == "provisioning.kaiba.network/rpi5-unfused-compatibility-result/v1alpha2"
            and .status == "compatibility_passed"
            and .evidence_mode == "offline_fixture"
            and .fixture_id == $fixture_id
            and .capsule_id == $capsule_id
            and .capsule_digest == $capsule_digest
            and .boot_image_digest == $boot_image_digest
            and .boot_signature_digest == $boot_signature_digest
            and .root_data_digest == $root_data_digest
            and .root_hash_digest == $root_hash_digest
            and .boot_public_key_fingerprint == $public_key_fingerprint
            and (.manifest_digest | test("^sha256:[0-9a-f]{64}$"))
            and (.fixture_digest | test("^sha256:[0-9a-f]{64}$"))
            and (.signature_verification_receipt | test("^sha256:[0-9a-f]{64}$"))
            and (.signer_trust_policy_digest | test("^sha256:[0-9a-f]{64}$"))
            and .files_verified == 4
            and .signature_verified == true
            and .signer_trust_anchored == true
            and .hardware_observed == false
            and .security_enforced == false
            and .mutation_eligible == false
          ' "$out/compatibility-result.json" > /dev/null

        find "$capsule" -type f -printf '%P\n' | sort \
          > "$TMPDIR/actual-capsule-files"
        printf '%s\n' \
          boot.img \
          boot.sig \
          nvme/root-data.img \
          nvme/root-hash.img \
          > "$TMPDIR/expected-capsule-files"
        cmp "$TMPDIR/expected-capsule-files" "$TMPDIR/actual-capsule-files"
        test -z "$(find "$out" -type l -print -quit)"
        test -z "$(find "$out" ! -type d ! -type f -print -quit)"

        chmod 0444 \
          "$out/capsule-manifest.json" \
          "$out/compatibility-result.json" \
          "$out/unfused-fixture.json"
        chmod 0555 "$capsule/nvme" "$capsule"
      '';
in
{
  inherit mkRpi5VerifiedUnfusedCapsule;
}
