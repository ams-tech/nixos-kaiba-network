# Deterministic pilot validation reports

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
  --provisioning /path/to/provisioning.json \
  --provisioning-schema tests/report/provisioning.schema.json \
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

The provisioning input follows
[`provisioning.schema.json`](provisioning.schema.json). It records automated
checks per target system and a separate manual hardware-qualification state.
Automated checks may be `passed`, `failed`, or `not-observed`; their derived
overall state is respectively `passed`, `failed` if any check failed, or
`partial` if at least one check was not observed. Hardware qualification is
`pending`, `passed`, or `failed` and never changes the DNS or automated result.
Pending qualification has no evidence; a passed or failed qualification must
cite evidence. `mutation_eligible` is always false in this probe-only report.

CI can replace a platform's complete set of `not-observed` placeholders with a
strict, source-revision-bound receipt by repeating:

```console
--provisioning-platform-result /path/to/platform-result.json
```

Each receipt names exactly one supported system, a lowercase 40- or 64-hex
source revision, and every placeholder check for that system. Receipts cannot
add checks, replace already-observed checks, alter source-controlled check
descriptions, or combine different source revisions.

CI should bind all supplied receipts to its checked-out commit with
`--expected-source-revision <revision>`. Supplying this option without a receipt,
or supplying any receipt from another revision, is an error.

The native result intentionally has no source revision because Nix builds it
without ambient VCS metadata. Bind it at the CI boundary with the strict,
new-file-only receipt writer:

```console
python3 tests/report/platform_receipt.py \
  --input /path/to/platform.json \
  --source-revision <revision> \
  --output /new/path/to/platform-receipt.json
```

The writer rejects duplicate or unknown fields, malformed or oversized input,
unsupported result values, and non-canonical revision identifiers. The report
renderer still verifies the exact platform/check placeholder set and revision
before incorporating the receipt.

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
provisioning.json           provisioning.schema.json
events.jsonl                junit.xml
topology.json               topology.dot
topology.svg                evidence/
zones/                      manifest.sha256
```

Input ordering and line endings are canonicalized. The manifest covers every
output except itself.

JUnit contains the DNS assertions and automated provisioning checks;
`not-observed` checks are skipped. Manual hardware qualification is deliberately
excluded from JUnit. Automated checks do not execute physical recovery firmware
and do not establish device authentication, attestation, or a complete
unprovisioned state.

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
