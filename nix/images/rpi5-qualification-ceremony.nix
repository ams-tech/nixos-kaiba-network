{
  kaibaProvisionPackage,
  lib,
  listRPIBootPathsCommand,
  pkgs,
  qualificationReadyPackage,
}:

assert lib.assertMsg (lib.isDerivation kaibaProvisionPackage)
  "the qualification ceremony requires a fixed kaiba-provision package";
assert lib.assertMsg (lib.isDerivation qualificationReadyPackage)
  "the qualification ceremony requires a fixed readiness package";
assert lib.assertMsg (
  builtins.isString listRPIBootPathsCommand
  && lib.hasPrefix "${builtins.storeDir}/" listRPIBootPathsCommand
  && !(lib.hasInfix "\n" listRPIBootPathsCommand)
) "the qualification ceremony requires a fixed Nix-store RPIBOOT observer command";

let
  provisionCommand = "${kaibaProvisionPackage}/bin/kaiba-provision";
  readinessCommand = "${qualificationReadyPackage}/bin/kaiba-qualification-ready";
  schemaValidatorCommand = "${pkgs.check-jsonschema}/bin/check-jsonschema";
in
pkgs.writeShellApplication {
  name = "kaiba-qualification-ceremony";
  runtimeInputs = with pkgs; [
    coreutils
    diffutils
    jq
    util-linux
  ];
  text = ''
    readonly provision_command=${lib.escapeShellArg provisionCommand}
    readonly readiness_command=${lib.escapeShellArg readinessCommand}
    readonly list_rpiboot_paths_command=${lib.escapeShellArg listRPIBootPathsCommand}
    readonly schema_validator_command=${lib.escapeShellArg schemaValidatorCommand}

    lane_id=lane-1
    case "$#" in
      0)
        ;;
      1)
        if [[ "$1" == "--help" ]]; then
          printf '%s\n' 'usage: kaiba-qualification-ceremony [--lane-id ID]'
          exit 0
        fi
        printf '%s\n' 'usage: kaiba-qualification-ceremony [--lane-id ID]' >&2
        exit 2
        ;;
      2)
        if [[ "$1" != "--lane-id" ]]; then
          printf '%s\n' 'usage: kaiba-qualification-ceremony [--lane-id ID]' >&2
          exit 2
        fi
        lane_id="$2"
        ;;
      *)
        printf '%s\n' 'usage: kaiba-qualification-ceremony [--lane-id ID]' >&2
        exit 2
        ;;
    esac
    if [[ ! "$lane_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
      printf 'invalid lane ID: %s\n' "$lane_id" >&2
      exit 2
    fi
    readonly lane_id

    if ! exec 3</dev/tty 4>/dev/tty; then
      printf '%s\n' 'qualification ceremony requires an interactive terminal' >&2
      exit 2
    fi

    run_directory=
    state=NOT_STARTED
    quarantine_required=false
    SOURCE_REVISION=
    SYSTEM_CLOSURE=
    KAIBA_PROVISION=
    PROFILE=
    QUALIFICATION_SCHEMA=
    PRIVATE=
    media_id=
    normal_boot_criterion=
    declare -a observed_paths=()

    write_state() {
      local next_state="$1"
      state="$next_state"
      if [[ -n "$run_directory" ]]; then
        printf '%s\n' "$state" > "$run_directory/state.partial"
        chmod 0600 "$run_directory/state.partial"
        mv -f -- "$run_directory/state.partial" "$run_directory/state"
      fi
    }

    stop() {
      local exit_code="$1"
      local terminal_state="$2"
      local message="$3"
      if [[ "$terminal_state" == QUARANTINED ]]; then
        quarantine_required=true
      fi
      if [[ "$quarantine_required" == true ]]; then
        exit_code=6
        terminal_state=QUARANTINED
      fi
      write_state "$terminal_state"
      printf 'STOP: %s\n' "$message" >&4
      if [[ -n "$run_directory" ]]; then
        printf 'Private diagnostic session retained at %s\n' "$run_directory" >&4
      fi
      exit "$exit_code"
    }

    transition() {
      local expected="$1"
      local next="$2"
      if [[ "$state" != "$expected" ]]; then
        stop 1 INTERNAL_ERROR "internal state error: expected $expected, found $state"
      fi
      write_state "$next"
    }

    mark_quarantine() {
      quarantine_required=true
      write_state QUARANTINED
    }

    # Invoked indirectly by the signal traps below.
    # shellcheck disable=SC2329
    on_signal() {
      local signal_exit="$1"
      stop "$signal_exit" ABORTED 'ceremony interrupted; restart from probe 1'
    }

    # Invoked indirectly by the EXIT trap below.
    # shellcheck disable=SC2329
    on_exit() {
      local exit_code="$?"
      trap - EXIT
      if [[ -z "$run_directory" ]]; then
        return
      fi
      if [[ "$quarantine_required" == true ]]; then
        state=QUARANTINED
        {
          printf '%s\n' "$state" > "$run_directory/state.partial"
          chmod 0600 "$run_directory/state.partial"
          mv -f -- "$run_directory/state.partial" "$run_directory/state"
        } || true
        if (( exit_code != 6 )); then
          printf '%s\n' \
            'STOP: internal failure after quarantine became mandatory; quarantine the target' \
            "Private diagnostic session retained at $run_directory" >&4 || true
        fi
        exit 6
      fi
      if (( exit_code == 0 )); then
        return
      fi
      case "$state" in
        ABORTED | INTERNAL_ERROR | PASSED | QUARANTINED)
          return
          ;;
      esac
      state=INTERNAL_ERROR
      {
        printf '%s\n' "$state" > "$run_directory/state.partial"
        chmod 0600 "$run_directory/state.partial"
        mv -f -- "$run_directory/state.partial" "$run_directory/state"
      } || true
      printf '%s\n' \
        'STOP: unexpected internal failure; no new final record is transferable' \
        "Private diagnostic session retained at $run_directory" >&4 || true
    }
    trap 'on_signal 130' INT
    trap 'on_signal 143' TERM
    trap on_exit EXIT

    prompt_exact() {
      local message="$1"
      local expected="$2"
      local response
      printf '\n%s\nType %s and press Enter: ' "$message" "$expected" >&4
      if ! IFS= read -r response <&3; then
        stop 2 ABORTED 'operator input ended unexpectedly'
      fi
      if [[ "$response" != "$expected" ]]; then
        stop 2 ABORTED "confirmation did not match $expected"
      fi
    }

    prompt_enter() {
      local message="$1"
      local response
      printf '\n%s\nPress Enter when complete: ' "$message" >&4
      if ! IFS= read -r response <&3; then
        stop 2 ABORTED 'operator input ended unexpectedly'
      fi
      if [[ -n "$response" ]]; then
        stop 2 ABORTED 'expected an empty Enter confirmation'
      fi
    }

    prompt_media_id() {
      local response
      printf '\n%s\n%s' \
        'Enter the short identifier physically written on the known-good target boot media.' \
        'Allowed: letters, digits, dot, underscore, and hyphen: ' >&4
      if ! IFS= read -r response <&3; then
        stop 2 ABORTED 'operator input ended unexpectedly'
      fi
      if [[ ! "$response" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        stop 2 ABORTED 'boot-media identifier is invalid'
      fi
      media_id="$response"
    }

    refresh_observed_paths() {
      local observer_output
      local observer_diagnostics="$run_directory/observer.stderr"
      local path
      local -A seen_paths=()
      if observer_output="$("$list_rpiboot_paths_command" 2>> "$observer_diagnostics")"; then
        :
      else
        chmod 0600 "$observer_diagnostics"
        stop 3 ABORTED \
          "RPIBOOT topology observer failed; inspect $observer_diagnostics"
      fi
      chmod 0600 "$observer_diagnostics"
      observed_paths=()
      if [[ -n "$observer_output" ]]; then
        mapfile -t observed_paths <<< "$observer_output"
      fi
      for path in "''${observed_paths[@]}"; do
        if [[ ! "$path" =~ ^[0-9]+-[0-9]+(\.[0-9]+)*$ ]]; then
          stop 3 ABORTED "observer returned invalid USB topology path $path"
        fi
        if [[ -n "''${seen_paths[$path]+present}" ]]; then
          stop 3 ABORTED "observer returned duplicate USB topology path $path"
        fi
        seen_paths[$path]=1
      done
    }

    wait_for_target() {
      local expected_path="$1"
      local description="$2"
      local deadline=$((SECONDS + 120))
      while (( SECONDS < deadline )); do
        refresh_observed_paths
        case "''${#observed_paths[@]}" in
          0)
            sleep 1
            ;;
          1)
            if [[ -n "$expected_path" && "''${observed_paths[0]}" != "$expected_path" ]]; then
              stop 3 ABORTED \
                "RPIBOOT target reappeared at ''${observed_paths[0]}, expected $expected_path"
            fi
            if [[ -z "$expected_path" ]]; then
              usb_path="''${observed_paths[0]}"
            fi
            printf 'Bound %s at USB topology path %s.\n' \
              "$description" "''${observed_paths[0]}" >&4
            return
            ;;
          *)
            stop 3 ABORTED 'more than one eligible BCM2712 RPIBOOT target is attached'
            ;;
        esac
      done
      stop 3 ABORTED "timed out waiting for $description"
    }

    wait_for_absence() {
      local expected_path="$1"
      local deadline=$((SECONDS + 60))
      while (( SECONDS < deadline )); do
        refresh_observed_paths
        case "''${#observed_paths[@]}" in
          0)
            printf 'Observed complete RPIBOOT USB disappearance.\n' >&4
            return
            ;;
          1)
            if [[ -n "$expected_path" && "''${observed_paths[0]}" != "$expected_path" ]]; then
              stop 3 ABORTED \
                "unexpected RPIBOOT target appeared at ''${observed_paths[0]}"
            fi
            sleep 1
            ;;
          *)
            stop 3 ABORTED 'more than one eligible BCM2712 RPIBOOT target is attached'
            ;;
        esac
      done
      stop 3 ABORTED 'target did not disappear after full-power-removal confirmation'
    }

    note_private_diagnostics() {
      local diagnostic_file="$1"
      if [[ -s "$diagnostic_file" ]]; then
        printf 'Private command diagnostics retained at %s\n' "$diagnostic_file" >&4
      fi
    }

    validate_schema() {
      local candidate="$1"
      local label="$2"
      local diagnostics="''${3:-$candidate.schema-validation}"
      if "$schema_validator_command" \
        --schemafile "$QUALIFICATION_SCHEMA" \
        "$candidate" \
        > "$diagnostics" 2>&1
      then
        chmod 0600 "$diagnostics"
        return 0
      fi
      chmod 0600 "$diagnostics"
      printf '%s schema validation failed; inspect %s\n' \
        "$label" "$diagnostics" >&4
      return 1
    }

    run_probe() {
      local sequence="$1"
      local result="$run_directory/probe-$sequence.json"
      local partial="$result.partial"
      local diagnostics="$run_directory/probe-$sequence.stderr"
      local diagnostic_text
      local probe_exit
      if "$provision_command" probe \
        --profile "$PROFILE" \
        --lane-id "$lane_id" \
        --usb-path "$usb_path" \
        > "$partial" 2> "$diagnostics"
      then
        probe_exit=0
      else
        probe_exit=$?
      fi
      chmod 0600 "$partial" "$diagnostics"
      if (( probe_exit != 0 )); then
        note_private_diagnostics "$diagnostics"
        diagnostic_text="$(< "$diagnostics")"
        if [[ "$diagnostic_text" == *'probe safety violation: mutation success reported'* ]]; then
          stop 6 QUARANTINED "probe $sequence reported a mutation safety violation"
        fi
        if (( probe_exit == 5 )); then
          stop 6 QUARANTINED "probe $sequence rejected the observable fresh-device baseline"
        fi
        if (( probe_exit < 1 || probe_exit > 125 )); then
          probe_exit=1
        fi
        stop "$probe_exit" ABORTED "probe $sequence exited $probe_exit; do not continue"
      fi
      if ! jq -e 'type == "object"' "$partial" > /dev/null; then
        stop 3 ABORTED "probe $sequence emitted malformed JSON"
      fi
      mv -f -- "$partial" "$result"
      printf 'Probe %s passed.\n' "$sequence" >&4
    }

    qualification_exit=0
    qualification_partial=
    qualification_result=
    qualification_diagnostics=
    run_qualifier() {
      local normal_boot_confirmation="$1"
      local output_name="$2"
      qualification_result="$run_directory/$output_name"
      qualification_partial="$qualification_result.partial"
      qualification_diagnostics="$run_directory/$output_name.stderr"
      if "$provision_command" qualify \
        --profile "$PROFILE" \
        --first-result "$run_directory/probe-1.json" \
        --second-result "$run_directory/probe-2.json" \
        --source-revision "$SOURCE_REVISION" \
        --system-closure "$SYSTEM_CLOSURE" \
        --power-cycle-confirmation complete \
        --pre-probe-normal-boot confirmed \
        --normal-boot-confirmation "$normal_boot_confirmation" \
        > "$qualification_partial" 2> "$qualification_diagnostics"
      then
        qualification_exit=0
      else
        qualification_exit=$?
      fi
      if (( qualification_exit == 6 )); then
        mark_quarantine
      fi
      chmod 0600 "$qualification_partial" "$qualification_diagnostics"
    }

    publish_final() {
      local source_record="$1"
      local expected_status="$2"
      local final_record="$PRIVATE/hardware-qualification.json"
      local publication_partial="$PRIVATE/.hardware-qualification.json.partial"
      local publication_diagnostics="$run_directory/publication.schema-validation"

      if [[ -e "$publication_partial" || -L "$publication_partial" ]]; then
        stop 1 INTERNAL_ERROR \
          'an incomplete publication artifact already exists; no final record was published'
      fi
      if ! install -m 0600 -- \
        "$source_record" "$publication_partial"
      then
        stop 1 INTERNAL_ERROR 'failed to stage the final transferable record'
      fi
      if ! cmp -s -- "$source_record" "$publication_partial"; then
        stop 1 INTERNAL_ERROR 'staged final record differs from its validated source'
      fi
      if ! validate_schema \
        "$publication_partial" 'staged final record' "$publication_diagnostics"
      then
        stop 1 INTERNAL_ERROR 'staged final record failed schema revalidation'
      fi
      if ! jq -e --arg expected_status "$expected_status" \
        '.status == $expected_status' "$publication_partial" > /dev/null
      then
        stop 1 INTERNAL_ERROR 'staged final record has the wrong status'
      fi
      if [[ -e "$final_record" || -L "$final_record" ]]; then
        stop 1 INTERNAL_ERROR 'the final destination appeared during publication'
      fi
      if ! ln -- "$publication_partial" "$final_record"; then
        stop 1 INTERNAL_ERROR \
          'failed to atomically publish the final record without replacing a destination'
      fi
      if [[ ! -f "$final_record" || -L "$final_record" ]] \
        || ! cmp -s -- "$source_record" "$final_record"
      then
        stop 1 INTERNAL_ERROR 'published final path failed its regular-file or byte-equality postcondition'
      fi
      if ! rm -- "$publication_partial"; then
        stop 1 INTERNAL_ERROR 'final record is valid but its staging link could not be removed'
      fi
    }

    if ready_environment="$("$readiness_command")"; then
      :
    else
      readiness_exit=$?
      printf 'qualification readiness failed with exit %s\n' "$readiness_exit" >&4
      exit "$readiness_exit"
    fi
    eval "$ready_environment"
    unset ready_environment
    umask 077

    for required_name in \
      SOURCE_REVISION SYSTEM_CLOSURE KAIBA_PROVISION PROFILE QUALIFICATION_SCHEMA PRIVATE
    do
      if [[ -z "''${!required_name:-}" ]]; then
        stop 2 ABORTED "readiness omitted $required_name"
      fi
    done
    if [[ "$(readlink -f -- "$KAIBA_PROVISION")" != "$(readlink -f -- "$provision_command")" ]]; then
      stop 2 ABORTED 'readiness and ceremony resolve different kaiba-provision binaries'
    fi
    if [[ ! -r "$QUALIFICATION_SCHEMA" ]]; then
      stop 2 ABORTED 'the qualification schema is not readable'
    fi

    exec 9> "$PRIVATE/.ceremony.lock"
    if ! flock --nonblock 9; then
      stop 2 ABORTED 'another qualification ceremony is already running'
    fi
    final_record="$PRIVATE/hardware-qualification.json"
    publication_partial="$PRIVATE/.hardware-qualification.json.partial"
    if [[ -e "$publication_partial" || -L "$publication_partial" ]]; then
      stop 2 ABORTED \
        'an incomplete publication artifact exists; do not transfer it, and reboot to clear volatile evidence'
    fi
    if [[ -e "$final_record" || -L "$final_record" ]]; then
      if [[ -f "$final_record" && ! -L "$final_record" ]] \
        && "$schema_validator_command" \
          --schemafile "$QUALIFICATION_SCHEMA" "$final_record" \
          > /dev/null 2>&1 \
        && jq -e '.status == "passed" or .status == "failed"' \
          "$final_record" > /dev/null
      then
        stop 2 ABORTED \
          'a schema-valid final record exists; transfer and review it, then reboot before starting over'
      fi
      stop 2 ABORTED \
        'a non-transferable stale final path exists; do not transfer it, and reboot to clear volatile evidence'
    fi
    if run_directory="$(mktemp -d -- "$PRIVATE/ceremony.XXXXXXXX")"; then
      :
    else
      stop 1 INTERNAL_ERROR 'failed to create a private ceremony directory'
    fi
    chmod 0700 "$run_directory"
    readonly run_directory
    write_state READY

    printf '%s\n' \
      'Kaiba Raspberry Pi 5 hardware qualification' \
      "Private session: $run_directory" \
      "Frozen source revision: $SOURCE_REVISION" \
      "Station system closure: $SYSTEM_CLOSURE" \
      'This command never authorizes mutation and never runs through sudo.' \
      'Keep this station powered. Use a separate fresh, unfused sacrificial Pi 5 Model B.' >&4

    prompt_exact \
      'Confirm the frozen revision passed the required x86 and native AArch64 checks and this station passed its physical first-boot smoke test.' \
      STATION-QUALIFIED
    transition READY STATION_CONFIRMED

    prompt_enter 'Disconnect every RPIBOOT target from this station.'
    wait_for_absence ""
    transition STATION_CONFIRMED INITIAL_USB_CLEAR

    prompt_media_id
    readonly media_id
    normal_boot_criterion="target reaches its local console as a Raspberry Pi 5 Model B with boot storage labelled $media_id visible"
    readonly normal_boot_criterion
    if ! jq -n \
      --arg lane_id "$lane_id" \
      --arg media_id "$media_id" \
      --arg normal_boot_criterion "$normal_boot_criterion" \
      --arg source_revision "$SOURCE_REVISION" \
      --arg system_closure "$SYSTEM_CLOSURE" \
      '{
        lane_id: $lane_id,
        media_id: $media_id,
        normal_boot_criterion: $normal_boot_criterion,
        source_revision: $source_revision,
        system_closure: $system_closure
      }' > "$run_directory/operator-context.json.partial"
    then
      stop 1 INTERNAL_ERROR 'failed to record the private operator context'
    fi
    chmod 0600 "$run_directory/operator-context.json.partial"
    mv -f -- \
      "$run_directory/operator-context.json.partial" \
      "$run_directory/operator-context.json"

    prompt_exact \
      "Boot the target from media $media_id and verify: $normal_boot_criterion" \
      BASELINE-OK
    transition INITIAL_USB_CLEAR PREBOOT_CONFIRMED
    wait_for_absence ""

    prompt_enter \
      'Shut down the target, remove every power source, hold its power button, and attach USB-C to the labelled data lane in RPIBOOT mode.'
    usb_path=
    wait_for_target "" 'first RPIBOOT observation'
    readonly usb_path
    prompt_exact \
      "Confirm labelled lane $lane_id is physically connected to USB topology path $usb_path." \
      "BIND $lane_id $usb_path"
    transition PREBOOT_CONFIRMED RPIBOOT1_BOUND

    run_probe 1
    transition RPIBOOT1_BOUND PROBE1_PASSED

    prompt_enter 'Remove every target power source and leave the target disconnected.'
    wait_for_absence "$usb_path"
    transition PROBE1_PASSED TARGET_ABSENT

    prompt_enter \
      'Hold the target power button and reconnect the same target on the same labelled lane in RPIBOOT mode.'
    wait_for_target "$usb_path" 'second RPIBOOT observation'
    transition TARGET_ABSENT RPIBOOT2_BOUND

    run_probe 2
    transition RPIBOOT2_BOUND PROBE2_PASSED

    run_qualifier pending comparison-preflight.json
    if (( qualification_exit != 7 )); then
      note_private_diagnostics "$qualification_diagnostics"
      if (( qualification_exit == 6 )); then
        stop 6 QUARANTINED 'comparison preflight requires quarantine'
      fi
      stop 3 ABORTED "comparison preflight exited $qualification_exit instead of 7"
    fi
    if ! validate_schema "$qualification_partial" 'comparison preflight'; then
      stop 3 ABORTED 'comparison preflight did not satisfy the full qualification schema'
    fi
    if ! jq -e '
      .status == "incomplete"
      and .quarantine_required == false
      and .findings == []
      and ([.comparisons[].status] | all(. == "match" or . == "not_observed"))
    ' "$qualification_partial" > /dev/null
    then
      stop 6 QUARANTINED 'comparison preflight JSON violates the no-change contract'
    fi
    mv -f -- "$qualification_partial" "$qualification_result"
    transition PROBE2_PASSED PREFLIGHT_PASSED
    printf '%s\n' 'Two-probe comparison preflight passed.' >&4

    prompt_enter \
      "Disconnect RPIBOOT, boot the target from media $media_id, and repeat: $normal_boot_criterion"
    wait_for_absence "$usb_path"
    printf '%s' 'Type UNCHANGED if the criterion passed identically, or FAILED otherwise: ' >&4
    if ! IFS= read -r post_boot_result <&3; then
      stop 2 ABORTED 'operator input ended unexpectedly'
    fi
    case "$post_boot_result" in
      UNCHANGED)
        normal_boot_confirmation=unchanged
        ;;
      FAILED)
        normal_boot_confirmation=failed
        ;;
      *)
        stop 2 ABORTED 'normal-boot result must be exactly UNCHANGED or FAILED'
        ;;
    esac
    transition PREFLIGHT_PASSED POSTBOOT_CONFIRMED
    if [[ "$normal_boot_confirmation" == failed ]]; then
      mark_quarantine
    fi

    run_qualifier "$normal_boot_confirmation" hardware-qualification.json
    if [[ "$normal_boot_confirmation" == unchanged ]]; then
      if (( qualification_exit != 0 )); then
        note_private_diagnostics "$qualification_diagnostics"
        if (( qualification_exit == 6 )); then
          if ! validate_schema "$qualification_partial" 'failed final record'; then
            stop 6 QUARANTINED \
              'final qualifier rejected the target but emitted no transferable schema-valid record'
          fi
          if ! jq -e '.status == "failed" and .quarantine_required == true' \
            "$qualification_partial" > /dev/null
          then
            stop 6 QUARANTINED \
              'final qualifier rejected the target but violated the failed-record contract'
          fi
          mv -f -- "$qualification_partial" "$qualification_result"
          publish_final "$qualification_result" failed
          stop 6 QUARANTINED 'final qualifier rejected the target; transfer only the failed final record'
        fi
        stop 3 ABORTED "final qualifier exited $qualification_exit instead of 0"
      fi
      if ! validate_schema "$qualification_partial" 'passed final record'; then
        stop 3 ABORTED 'final qualifier emitted no transferable schema-valid passed record'
      fi
      if ! jq -e '
        .status == "passed"
        and .quarantine_required == false
        and .findings == []
        and ([.comparisons[].status] | all(. == "match" or . == "not_observed"))
      ' "$qualification_partial" > /dev/null
      then
        stop 3 ABORTED 'final qualifier JSON violates the passed-record contract'
      fi
      mv -f -- "$qualification_partial" "$qualification_result"
      publish_final "$qualification_result" passed
      transition POSTBOOT_CONFIRMED PASSED
      printf '\nQualification PASSED.\nTransfer only this schema-valid, whitelist-redacted record before shutdown:\n%s\n' \
        "$PRIVATE/hardware-qualification.json" >&4
      exit 0
    fi

    if (( qualification_exit != 6 )); then
      note_private_diagnostics "$qualification_diagnostics"
      stop 6 QUARANTINED \
        "normal boot failed and the qualifier exited $qualification_exit instead of 6; no record is transferable"
    fi
    if ! validate_schema "$qualification_partial" 'failed final record'; then
      stop 6 QUARANTINED \
        'normal boot failed but the qualifier emitted no transferable schema-valid record'
    fi
    if ! jq -e '
      .status == "failed"
      and .quarantine_required == true
      and (.findings | index("normal-boot-failed") != null)
    ' "$qualification_partial" > /dev/null
    then
      stop 6 QUARANTINED 'failed normal-boot qualifier violated the failed-record contract'
    fi
    mv -f -- "$qualification_partial" "$qualification_result"
    publish_final "$qualification_result" failed
    write_state QUARANTINED
    printf '\nQualification FAILED; quarantine the target.\nTransfer only this schema-valid, whitelist-redacted record:\n%s\n' \
      "$PRIVATE/hardware-qualification.json" >&4
    exit 6
  '';
  meta = {
    description = "Fail-closed interactive Raspberry Pi 5 hardware qualification ceremony";
    mainProgram = "kaiba-qualification-ceremony";
    platforms = lib.platforms.linux;
  };
}
