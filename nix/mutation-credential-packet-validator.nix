{ pkgs }:

pkgs.writeShellApplication {
  name = "kaiba-validate-mutation-credential-packet";
  runtimeInputs = with pkgs; [
    coreutils
    diffutils
  ];
  text = ''
    case "''${1:-}" in
      validate-manifest)
        test "$#" -eq 2
        credential_root=$2
        manifest="$credential_root/SHA256SUMS"

        mapfile -t manifest_lines < "$manifest"
        test "''${#manifest_lines[@]}" -eq 4

        manifest_files=()
        for manifest_line in "''${manifest_lines[@]}"; do
          digest="''${manifest_line%% *}"
          test "''${#digest}" -eq 64
          test -z "''${digest//[0-9a-f]/}"

          separator_and_file="''${manifest_line#"$digest"}"
          test "''${separator_and_file:0:2}" = "  "
          manifest_file="''${separator_and_file:2}"
          case "$manifest_file" in
            audit-server-ca.crt|control-server-ca.crt|station-client.crt|station-client.key)
              ;;
            *)
              exit 1
              ;;
          esac
          manifest_files+=("$manifest_file")
        done

        expected_manifest_files="$(printf '%s\n' \
          audit-server-ca.crt \
          control-server-ca.crt \
          station-client.crt \
          station-client.key | sort)"
        observed_manifest_files="$(printf '%s\n' "''${manifest_files[@]}" | sort)"
        test "$observed_manifest_files" = "$expected_manifest_files"

        (
          cd "$credential_root"
          sha256sum --check --strict SHA256SUMS >/dev/null
        )
        ;;
      require-distinct-cas)
        test "$#" -eq 3
        comparison_status=0
        cmp --silent -- "$2" "$3" || comparison_status=$?
        test "$comparison_status" -eq 1
        ;;
      *)
        exit 2
        ;;
    esac
  '';
}
