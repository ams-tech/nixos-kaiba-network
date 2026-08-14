{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
  provisioningTestResult,
  stationPages,
}:

let
  testPki = import ./test-pki.nix { inherit pkgs; };
  reportPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.jsonschema ]);
  raw = pkgs.testers.runNixOSTest (
    import ./topology.nix {
      inherit
        pkgs
        lib
        kaibaPackage
        kaibaModules
        testPki
        ;
    }
  );

  report =
    pkgs.runCommand "kaiba-dns-test-report"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        set -eu
        input="$TMPDIR/input"
        mkdir -p "$input"
        cp -R ${raw}/raw/. "$input/"
        if test -e "$input/evidence/provisioning"; then
          echo "raw DNS evidence uses the reserved provisioning namespace" >&2
          exit 1
        fi
        chmod u+w "$input/evidence"
        cp -R --no-dereference ${provisioningTestResult}/evidence/. "$input/evidence/"
        mkdir -p "$out"
        python3 ${../report/render.py} \
          --result "$input/result.json" \
          --events "$input/events.jsonl" \
          --evidence "$input/evidence" \
          --zones "$input/zones" \
          --topology ${../topology.json} \
          --schema ${../report/result.schema.json} \
          --provisioning ${provisioningTestResult}/report-input.json \
          --provisioning-schema ${../report/provisioning.schema.json} \
          --output "$out"
      '';

  gate =
    pkgs.runCommand "kaiba-dns-test-gate"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        set -eu
        python3 ${../report/gate.py} \
          --manifest ${../report/required-assertions.json} \
          --scope functional \
          ${report}/result.json
        mkdir -p "$out"
        cp ${report}/result.json "$out/result.json"
      '';

  schemaGate =
    pkgs.runCommand "kaiba-dns-schema-gate"
      {
        nativeBuildInputs = [ reportPython ];
      }
      ''
        set -eu
        python3 ${../report/schema_gate.py} \
          --schema ${report}/result.schema.json \
          --instance ${report}/result.json
        python3 ${../report/schema_gate.py} \
          --schema ${report}/provisioning.schema.json \
          --instance ${report}/provisioning.json
        mkdir -p "$out"
        cp ${report}/result.schema.json "$out/result.schema.json"
        cp ${report}/provisioning.schema.json "$out/provisioning.schema.json"
      '';

  securityGate =
    pkgs.runCommand "kaiba-dns-security-gate"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        set -eu
        python3 ${../report/gate.py} \
          --manifest ${../report/required-assertions.json} \
          --scope security \
          ${report}/result.json
        mkdir -p "$out"
        cp ${report}/result.json "$out/result.json"
      '';

  reportUnit =
    pkgs.runCommand "kaiba-dns-report-unit"
      {
        nativeBuildInputs = [
          pkgs.nodejs
          reportPython
        ];
      }
      ''
        set -eu
        export PYTHONDONTWRITEBYTECODE=1
        export KAIBA_STATION_PAGES=${stationPages}
        cd ${../..}
        node --check site/site.js
        python3 -m unittest discover -s tests/report -p 'test_*.py' -v
        python3 -m unittest discover -s tests/site -p 'test_*.py' -v
        mkdir -p "$out"
        printf '%s\n' 'report and site unit tests: pass' > "$out/results.txt"
      '';
in
{
  dns-test-raw = raw;
  dns-test-report = report;
  dns-test-gate = gate;
  dns-schema-gate = schemaGate;
  dns-security-gate = securityGate;
  report-unit = reportUnit;
  dns-test-driver = raw.driverInteractive;
}
