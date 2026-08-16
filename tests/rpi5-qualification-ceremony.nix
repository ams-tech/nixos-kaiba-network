{ lib, pkgs }:

let
  fakeProvision = pkgs.writeShellApplication {
    name = "kaiba-provision";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.jq
    ];
    text = ''
      : "''${KAIBA_CEREMONY_TEST_ROOT:?}"
      scenario="''${KAIBA_CEREMONY_SCENARIO:-success}"
      invocation_log="$KAIBA_CEREMONY_TEST_ROOT/invocations"

      {
        printf '%s' "$1"
        shift
        printf '\t%s' "$@"
        printf '\n'
      } >> "$invocation_log"

      emit_record() {
        local status="$1"
        local normal_boot="$2"
        local finding="''${3:-}"
        local changed_field="''${4:-}"
        local digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        jq -n \
          --arg status "$status" \
          --arg normal_boot "$normal_boot" \
          --arg finding "$finding" \
          --arg changed_field "$changed_field" \
          --arg digest "$digest" \
          '
            def comparison($field): {
              field: $field,
              status: (
                if $field == $changed_field then "changed"
                elif $field == "eeprom_hash"
                  or $field == "signature_mode"
                  or $field == "advanced_boot"
                then "not_observed"
                else "match"
                end
              )
            };
            def probe($sequence): {
              sequence: $sequence,
              evidence_digest: $digest,
              target_fingerprint: $digest,
              board_revision: {
                raw: "c04170",
                new_style: true,
                memory_code: 4,
                manufacturer_code: 0,
                processor_code: 4,
                model_code: 23,
                pcb_revision: 0
              },
              board_attributes: "00000000",
              boot_rom: "00000001",
              eeprom_hash: null,
              customer_key_hash: "0000000000000000000000000000000000000000000000000000000000000000",
              customer_key_state: "unset",
              videocore_jtag_locked: false,
              assessment: {
                device_class_status: "pass",
                observable_baseline_status: "pass",
                eligible_for_reversible_qualification: true,
                mutation_eligible: false,
                full_unprovisioned_state: "not_established"
              },
              mutation_audit: {success_reported: false}
            };
            {
              schema_version: "provisioning.kaiba.network/rpi5-hardware-qualification/v1alpha1",
              source_revision: "0123456789012345678901234567890123456789",
              station_system: "x86_64-linux",
              nix_system_closure_digest: $digest,
              profile: {
                id: "raspberry-pi-5-model-b-v1alpha1",
                status: "experimental",
                digest: $digest,
                policy_digest: $digest
              },
              adapter: {
                id: "raspberrypi.rpi5.otp-metadata",
                version: "v1alpha1"
              },
              source: {
                kind: "live-rpiboot",
                tool_version: "test",
                tool_digest: $digest,
                bundle_digest: $digest,
                firmware_digest: $digest,
                config_digest: $digest,
                lane_continuity: "match",
                usb_path_continuity: "match"
              },
              probes: [probe(1), probe(2)],
              comparisons: ([
                "target_fingerprint",
                "user_serial",
                "factory_uuid",
                "board_revision",
                "board_attributes",
                "ethernet_mac",
                "wifi_mac",
                "bluetooth_mac",
                "boot_rom",
                "eeprom_hash",
                "customer_key_hash",
                "customer_key_state",
                "videocore_jtag_locked",
                "signature_mode",
                "advanced_boot"
              ] | map(comparison(.))),
              power_cycle_confirmation: "operator_confirmed_complete",
              pre_probe_normal_boot_confirmation: "operator_confirmed_normal",
              normal_boot_confirmation: $normal_boot,
              status: $status,
              quarantine_required: ($status == "failed"),
              findings: (if $finding == "" then [] else [$finding] end),
              mutation_eligible: false,
              full_unprovisioned_state: "not_established",
              disclaimer: "This observation is correlation and partial preflight evidence; it is not device authentication or attestation and does not authorize irreversible provisioning."
            }
          '
      }

      case " $* " in
        *' --normal-boot-confirmation pending '*)
          if [[ "$scenario" == invalid-preflight ]]; then
            printf '%s\n' \
              '{"status":"incomplete","quarantine_required":false,"findings":[],"comparisons":[]}'
            exit 7
          fi
          emit_record incomplete not_yet_observed
          if [[ "$scenario" == preflight-zero ]]; then
            exit 0
          fi
          exit 7
          ;;
        *' --normal-boot-confirmation unchanged '*)
          if [[ "$scenario" == final-six \
            || "$scenario" == final-six-publish-fail ]]
          then
            if [[ "$scenario" == final-six-publish-fail ]]; then
              chmod 0500 "$KAIBA_CEREMONY_TEST_ROOT/private"
            fi
            emit_record failed operator_confirmed_unchanged \
              target-fingerprint-changed target_fingerprint
            exit 6
          fi
          emit_record passed operator_confirmed_unchanged
          exit 0
          ;;
        *' --normal-boot-confirmation failed '*)
          emit_record failed operator_confirmed_failed normal-boot-failed
          exit 6
          ;;
      esac

      if [[ "$scenario" == probe-fail \
        || "$scenario" == mutation-fail \
        || "$scenario" == baseline-fail ]]
      then
        probe_count_file="$KAIBA_CEREMONY_TEST_ROOT/probe-count"
        probe_count=0
        if [[ -f "$probe_count_file" ]]; then
          IFS= read -r probe_count < "$probe_count_file"
        fi
        probe_count=$((probe_count + 1))
        printf '%s\n' "$probe_count" > "$probe_count_file"
        if (( probe_count == 1 )); then
          case "$scenario" in
            mutation-fail)
              printf '%s\n' \
                'probe safety violation: mutation success reported by synthetic test' >&2
              exit 3
              ;;
            baseline-fail)
              printf '%s\n' 'synthetic baseline rejection' >&2
              exit 5
              ;;
            *)
              printf '%s\n' 'synthetic acquisition failure' >&2
              exit 3
              ;;
          esac
        fi
      fi
      printf '%s\n' '{"synthetic_private_probe":true}'
    '';
  };

  fakeReadiness = pkgs.writeShellApplication {
    name = "kaiba-qualification-ready";
    text = ''
      : "''${KAIBA_CEREMONY_TEST_ROOT:?}"
      if [[ "''${KAIBA_CEREMONY_SCENARIO:-success}" == readiness-fail ]]; then
        printf '%s\n' 'synthetic readiness failure' >&2
        exit 23
      fi
      printf '%s\n' 'umask 077'
      printf 'export SOURCE_REVISION=%q\n' \
        0123456789012345678901234567890123456789
      printf 'export SYSTEM_CLOSURE=%q\n' \
        "$KAIBA_CEREMONY_TEST_ROOT/system-closure"
      printf 'export KAIBA_PROVISION=%q\n' \
        '${fakeProvision}/bin/kaiba-provision'
      printf 'export PROFILE=%q\n' \
        "$KAIBA_CEREMONY_TEST_ROOT/profile.json"
      printf 'export QUALIFICATION_SCHEMA=%q\n' \
        '${../provisioning/schemas/rpi5-hardware-qualification-v1alpha1.schema.json}'
      printf 'export PRIVATE=%q\n' \
        "$KAIBA_CEREMONY_TEST_ROOT/private"
    '';
  };

  fakeObserver = pkgs.writeShellApplication {
    name = "kaiba-list-rpiboot-paths";
    text = ''
      : "''${KAIBA_CEREMONY_TEST_ROOT:?}"
      scenario="''${KAIBA_CEREMONY_SCENARIO:-success}"
      count_file="$KAIBA_CEREMONY_TEST_ROOT/observer-count"
      count=0
      if [[ -f "$count_file" ]]; then
        IFS= read -r count < "$count_file"
      fi
      count=$((count + 1))
      printf '%s\n' "$count" > "$count_file"

      if [[ "$scenario" == preexisting ]]; then
        case "$count" in
          1 | 4 | 6)
            printf '%s\n' 1-2.3
            ;;
          2 | 3 | 5 | 7)
            ;;
          *)
            exit 1
            ;;
        esac
        exit 0
      fi
      if [[ "$scenario" == ambiguous && "$count" -eq 3 ]]; then
        printf '%s\n' 1-2.3 1-2.4
        exit 0
      fi
      case "$count" in
        1 | 2 | 4 | 6)
          ;;
        3)
          printf '%s\n' 1-2.3
          ;;
        5)
          if [[ "$scenario" == wrong-reconnect ]]; then
            printf '%s\n' 1-2.4
          else
            printf '%s\n' 1-2.3
          fi
          ;;
        *)
          printf '%s\n' 'unexpected observer invocation' >&2
          exit 1
          ;;
      esac
    '';
  };

  ceremony = import ../nix/images/rpi5-qualification-ceremony.nix {
    inherit
      lib
      pkgs
      ;
    kaibaProvisionPackage = fakeProvision;
    listRPIBootPathsCommand = "${fakeObserver}/bin/kaiba-list-rpiboot-paths";
    qualificationReadyPackage = fakeReadiness;
  };
in
pkgs.runCommand "kaiba-rpi5-qualification-ceremony-contract"
  {
    nativeBuildInputs = [
      ceremony
      pkgs.check-jsonschema
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.util-linux
    ];
  }
  ''
    set -euo pipefail

    prepare_case() {
      local case_name="$1"
      case_root="$TMPDIR/$case_name"
      mkdir -p "$case_root/private" "$case_root/system-closure"
      chmod 0700 "$case_root/private"
      printf '%s\n' '{}' > "$case_root/profile.json"
      export KAIBA_CEREMONY_TEST_ROOT="$case_root"
    }

    run_ceremony() {
      local expected_input="$1"
      printf '%s' "$expected_input" > "$case_root/operator-input"
      set +e
      SHELL=${pkgs.bash}/bin/bash timeout --kill-after=5s 20s script \
        --quiet \
        --return \
        --command '${ceremony}/bin/kaiba-qualification-ceremony --lane-id lane-1' \
        "$case_root/terminal-transcript" \
        < "$case_root/operator-input" \
        > "$case_root/script.stdout" \
        2> "$case_root/script.stderr"
      ceremony_status="$?"
      set -e
    }

    success_input=$'STATION-QUALIFIED\n\nQUAL-MEDIA-1\nBASELINE-OK\n\nBIND lane-1 1-2.3\n\n\n\nUNCHANGED\n'
    failed_input=$'STATION-QUALIFIED\n\nQUAL-MEDIA-1\nBASELINE-OK\n\nBIND lane-1 1-2.3\n\n\n\nFAILED\n'
    wrong_bind_input=$'STATION-QUALIFIED\n\nQUAL-MEDIA-1\nBASELINE-OK\n\nBIND lane-1 1-9.9\n'

    prepare_case success
    export KAIBA_CEREMONY_SCENARIO=success
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 0
    success_session_count="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' | wc -l
    )"
    test "$success_session_count" -eq 1
    success_session="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' -print -quit
    )"
    test "$(cat "$success_session/state")" = PASSED
    test "$(stat --format=%a "$success_session")" = 700
    for private_file in \
      probe-1.json probe-2.json comparison-preflight.json \
      hardware-qualification.json operator-context.json state
    do
      test "$(stat --format=%a "$success_session/$private_file")" = 600
    done
    while IFS= read -r private_file; do
      test "$(stat --format=%a "$private_file")" = 600
    done < <(find "$success_session" -type f)
    test "$(stat --format=%a "$case_root/private/hardware-qualification.json")" = 600
    check-jsonschema \
      --schemafile ${../provisioning/schemas/rpi5-hardware-qualification-v1alpha1.schema.json} \
      "$case_root/private/hardware-qualification.json"
    jq -e '.status == "passed" and .quarantine_required == false' \
      "$case_root/private/hardware-qualification.json" > /dev/null
    jq -e '
      .lane_id == "lane-1"
      and .media_id == "QUAL-MEDIA-1"
      and (.normal_boot_criterion | contains("QUAL-MEDIA-1"))
    ' "$success_session/operator-context.json" > /dev/null
    test "$(cat "$case_root/observer-count")" -eq 6
    grep -F 'Type UNCHANGED if the criterion passed identically' \
      "$case_root/terminal-transcript"
    ! grep -F 'synthetic_private_probe' "$case_root/terminal-transcript"

    {
      printf 'probe\t--profile\t%s\t--lane-id\tlane-1\t--usb-path\t1-2.3\n' \
        "$case_root/profile.json"
      printf 'probe\t--profile\t%s\t--lane-id\tlane-1\t--usb-path\t1-2.3\n' \
        "$case_root/profile.json"
      printf 'qualify\t--profile\t%s\t--first-result\t%s/probe-1.json\t--second-result\t%s/probe-2.json\t--source-revision\t%s\t--system-closure\t%s\t--power-cycle-confirmation\tcomplete\t--pre-probe-normal-boot\tconfirmed\t--normal-boot-confirmation\tpending\n' \
        "$case_root/profile.json" "$success_session" "$success_session" \
        0123456789012345678901234567890123456789 "$case_root/system-closure"
      printf 'qualify\t--profile\t%s\t--first-result\t%s/probe-1.json\t--second-result\t%s/probe-2.json\t--source-revision\t%s\t--system-closure\t%s\t--power-cycle-confirmation\tcomplete\t--pre-probe-normal-boot\tconfirmed\t--normal-boot-confirmation\tunchanged\n' \
        "$case_root/profile.json" "$success_session" "$success_session" \
        0123456789012345678901234567890123456789 "$case_root/system-closure"
    } > "$case_root/expected-invocations"
    diff -u "$case_root/expected-invocations" "$case_root/invocations"

    prepare_case preexisting
    export KAIBA_CEREMONY_SCENARIO=preexisting
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 0
    test "$(cat "$case_root/observer-count")" -eq 7

    prepare_case ambiguous
    export KAIBA_CEREMONY_SCENARIO=ambiguous
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 3
    test ! -e "$case_root/invocations"

    prepare_case wrong-bind
    export KAIBA_CEREMONY_SCENARIO=success
    run_ceremony "$wrong_bind_input"
    test "$ceremony_status" -eq 2
    test ! -e "$case_root/invocations"

    prepare_case probe-fail
    export KAIBA_CEREMONY_SCENARIO=probe-fail
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 3
    test "$(wc -l < "$case_root/invocations")" -eq 1
    ! grep -F 'synthetic acquisition failure' "$case_root/terminal-transcript"

    prepare_case mutation-fail
    export KAIBA_CEREMONY_SCENARIO=mutation-fail
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 6
    test "$(wc -l < "$case_root/invocations")" -eq 1

    prepare_case baseline-fail
    export KAIBA_CEREMONY_SCENARIO=baseline-fail
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 6
    test "$(wc -l < "$case_root/invocations")" -eq 1

    prepare_case wrong-reconnect
    export KAIBA_CEREMONY_SCENARIO=wrong-reconnect
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 3
    test "$(wc -l < "$case_root/invocations")" -eq 1
    wrong_session="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' -print -quit
    )"
    test "$(cat "$wrong_session/state")" = ABORTED

    prepare_case preflight-zero
    export KAIBA_CEREMONY_SCENARIO=preflight-zero
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 3
    test "$(wc -l < "$case_root/invocations")" -eq 3
    ! grep -F $'\tunchanged' "$case_root/invocations"
    test ! -e "$case_root/private/hardware-qualification.json"

    prepare_case invalid-preflight
    export KAIBA_CEREMONY_SCENARIO=invalid-preflight
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 3
    test "$(wc -l < "$case_root/invocations")" -eq 3
    test ! -e "$case_root/private/hardware-qualification.json"

    prepare_case final-six
    export KAIBA_CEREMONY_SCENARIO=final-six
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 6
    test "$(wc -l < "$case_root/invocations")" -eq 4
    jq -e '.status == "failed" and .quarantine_required == true' \
      "$case_root/private/hardware-qualification.json" > /dev/null
    final_six_session="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' -print -quit
    )"
    test "$(cat "$final_six_session/state")" = QUARANTINED

    prepare_case final-six-publish-fail
    export KAIBA_CEREMONY_SCENARIO=final-six-publish-fail
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 6
    test ! -e "$case_root/private/hardware-qualification.json"
    publish_fail_session="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' -print -quit
    )"
    test "$(cat "$publish_fail_session/state")" = QUARANTINED

    prepare_case operator-failed
    export KAIBA_CEREMONY_SCENARIO=success
    run_ceremony "$failed_input"
    test "$ceremony_status" -eq 6
    jq -e '
      .status == "failed"
      and .quarantine_required == true
      and (.findings | index("normal-boot-failed") != null)
    ' "$case_root/private/hardware-qualification.json" > /dev/null
    operator_failed_session="$(
      find "$case_root/private" -mindepth 1 -maxdepth 1 \
        -type d -name 'ceremony.*' -print -quit
    )"
    test "$(cat "$operator_failed_session/state")" = QUARANTINED

    prepare_case stale-partial
    touch "$case_root/private/.hardware-qualification.json.partial"
    export KAIBA_CEREMONY_SCENARIO=success
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 2
    test ! -e "$case_root/invocations"

    prepare_case stale-invalid-final
    printf '%s\n' '{}' > "$case_root/private/hardware-qualification.json"
    export KAIBA_CEREMONY_SCENARIO=success
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 2
    grep -F 'non-transferable stale final path exists' \
      "$case_root/terminal-transcript"
    test ! -e "$case_root/invocations"

    prepare_case readiness-fail
    export KAIBA_CEREMONY_SCENARIO=readiness-fail
    run_ceremony "$success_input"
    test "$ceremony_status" -eq 23
    test ! -e "$case_root/invocations"

    mkdir -p "$out"
    touch "$out/passed"
  ''
