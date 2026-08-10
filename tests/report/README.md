# Deterministic DNS test reports

The integration test records structured observations; this directory turns
them into a stable, reviewable report without contacting the network. The
renderer uses only the Python standard library. Independent Draft 2020-12 schema
validation uses `jsonschema`, which the Nix `report-unit` and schema-gate
environments provide.

## Producer contract

Run:

```console
python3 tests/report/render.py \
  --result /path/to/result.json \
  --events /path/to/events.jsonl \
  --evidence /path/to/evidence \
  --zones /path/to/zone-snapshots \
  --topology tests/topology.json \
  --output /path/to/empty-output-directory
```

The schema defaults to `result.schema.json` beside the renderer. Packagers that
copy the script separately can pass `--schema /path/to/result.schema.json`
explicitly. `--zones` is optional, but the integration topology supplies it so
canonical snapshots appear under `zones/`.

`result.json` follows [`result.schema.json`](result.schema.json). Each exercised
claim cites one or more assertion IDs. Every evidence reference begins with
`evidence/` and must resolve to UTF-8 text under the input evidence directory.

Each non-empty line in `events.jsonl` is an object with exactly these fields:

```json
{
  "sequence": 1,
  "event": "delegation-checked",
  "phase": "delegation",
  "actor": "resolver",
  "summary": "The parent named only the public secondaries.",
  "evidence": ["evidence/delegation/dig-ns.txt"]
}
```

Sequences are contiguous from one. `actor` is a topology node ID or
`test-driver`. Collection code uses semantic phases and stable summaries rather
than clocks.

The renderer writes:

```text
result.json                 index.html
result.schema.json          index.md
events.jsonl                junit.xml
topology.json               topology.dot
topology.svg                evidence/
zones/                      manifest.sha256
```

Input ordering and line endings are canonicalized. The manifest covers every
output except itself.

## Diagnostics and enforcement

`nix build .#dns-test-report -L` accepts a consistent `overall: "failed"`
result and exits successfully so a complete diagnostic artifact survives a
functional failure. Enforcement is separate:

```console
python3 tests/report/schema_gate.py \
  --schema /path/to/report/result.schema.json \
  --instance /path/to/report/result.json
python3 tests/report/gate.py \
  --manifest tests/report/required-assertions.json \
  --scope functional \
  /path/to/report/result.json
```

The schema gate independently validates both the published Draft 2020-12 schema
and its canonical result. The functional gate compares the result with the
source-controlled assertion ID-to-phase contract, rejecting missing, extra,
misclassified, or failed assertions. The security scope independently enforces
the manifest's security subset. Gates exit zero for a passing suite, one for a
validation or assertion failure, and two for malformed input or schema.

The flake exposes these as `dns-schema-gate`, `dns-test-gate`, and
`dns-security-gate`; `nix flake check -L` runs all three as separate checks
after report rendering. It also runs `report-unit`.

## Reproducibility and safety

Canonical JSON keys and semantic collections are sorted. Evidence is normalized
to LF line endings with trailing whitespace removed. Symlinks and binary
evidence are rejected. Inputs are rejected when they contain credential fields
or common dynamic noise such as generation times, process IDs, elapsed times,
DNS transaction IDs, and ephemeral source ports. Fixed service ports and named
credential *identities* (for example a TSIG key name) remain part of the
topology.

Run the focused tests in their pinned Nix environment with:

```console
nix build .#report-unit -L
```

Or, with the `jsonschema` Python package available, run them directly:

```console
python3 -m unittest discover -s tests/report -p 'test_*.py'
```
