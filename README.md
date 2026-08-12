# Kaiba DNS pilot

This repository is an executable pilot for publishing secure Kaiba devices at
stable DNS names without putting the DNS provider or origin topology into the
device protocol.

The pilot has one writable hidden origin (P0), one read-only hidden standby
(P1), and two public-secondary emulators. Devices submit their complete public
address set to a generation-conditional mTLS API. The controller commits
SQLite desired state; the publisher, running under a separate UID, owns the
TSIG credential and projects that state into DNS with authenticated RFC 2136
updates.

The integration environment is isolated. It uses `kaiba.test` and a simulated
parent authority; it never contacts Namecheap, changes `kaiba.network`, or
depends on Internet access while running.

- [Project homepage](https://ams-tech.github.io/nixos-kaiba-network/)
- [Latest main-branch test report](https://ams-tech.github.io/nixos-kaiba-network/reports/latest/)

## Commands

```console
nix flake check -L
nix build .#dns-test-report -L
nix run .#dns-test-driver
nix develop
```

`nix build .#dns-test-report` produces a report even if a functional assertion
fails. Its `result` output contains HTML, Markdown, JUnit XML, canonical JSON,
topology diagrams, normalized evidence and zone snapshots, and a SHA-256
manifest. `nix flake check -L` independently enforces the report schema,
required functional and security assertions, Go tests, report tests, and NixOS
module evaluation. The interactive driver is for topology debugging.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pull requests,
pushes to `main`, and manual dispatches. It separates the test workload into:

- x86 formatting, flake evaluation, Go tests, report and Pages site tests,
  workflow linting, and NixOS module evaluation;
- native ARM64 builds and tests for all four packaged binaries; and
- the complete seven-VM DNS topology with KVM acceleration when available.

The topology job uploads `kaiba-dns-test-report` for 14 days. On pushes or
manual runs of `main`, it also assembles and publishes the project homepage and
the latest verified report through the repository's `github-pages` environment.
The homepage is at the Pages root; the canonical report is at
`reports/latest/`. Report generation precedes the assertion gates and artifact
collection/upload runs unconditionally, so a functional or security failure
still preserves and publishes the normalized HTML, Markdown, JUnit, JSON,
topology, evidence, and zone data for diagnosis. Each Pages deployment replaces
the homepage and canonical report together; the retained Actions artifacts
provide per-run history.

Enable the site once in **Settings → Pages → Build and deployment** by selecting
**GitHub Actions** as the source. Pages can make the homepage, report, and its
normalized evidence public, including for some private-repository plans. All
referenced actions are pinned to immutable commit SHAs. Test jobs keep read-only
repository access; only the main-only deployment job receives Pages write and
OIDC token permissions.

## Device API

The authenticated certificate identity determines the device and hostname; for
example, `spiffe://kaiba.network/device/001` maps to
`pi-001.kaiba.network`. The request cannot supply a hostname, zone, TTL, or
record type. The [device identity and credential lifecycle](docs/device-identity.md)
defines the target production requirements for protecting, enrolling, rotating,
recovering, and retiring those credentials.

```http
PUT /v1/devices/self/endpoints
Idempotency-Key: <unique-key>
If-None-Match: *
Content-Type: application/json

{"addresses":[{"family":"ipv4","address":"203.0.113.42"}]}
```

The first write uses `If-None-Match: *`. Later writes use
`If-Match: "g-N"`, where the strong generation ETag comes from the preceding
response or `GET /v1/devices/self/status`. Exactly one precondition is required;
an unknown stale generation returns `412 Precondition Failed`.

`202 Accepted` means desired state and the idempotency result are durable, not
that public DNS has converged. A new generation progresses through `accepted`,
`origin-applied`, and `publicly-observed`. A key is bound to both the canonical
complete address set and its precondition. An exact retry returns the original
result even after later generations exist; reuse for another request returns
`409 Conflict`. The pilot retains accepted idempotency results indefinitely.

Production binaries are built for both `x86_64-linux` and `aarch64-linux`:

- `kaiba-agent`
- `kaiba-controller`
- `kaiba-publisher`
- `kaiba-provision`

`kaiba-provision probe` is an experimental, non-persistent Raspberry Pi 5
preflight slice. It can normalize imported OTP metadata or acquire it from one
lane-bound Pi 5 Model B using a digest-pinned metadata-only recovery bundle.
Its result is correlation and partial preflight evidence, never authentication,
attestation, or permission to mutate a target. See the
[Raspberry Pi 5 provisioning probe](docs/raspberry-pi-5-provisioning-probe.md)
for the safety boundary, station setup, command contract, and required hardware
qualification.

Reusable NixOS modules cover the device agent, update services, hidden P0,
hidden P1, and public-secondary role. The seven-VM QEMU topology and interactive
lab are `x86_64-linux` outputs.

See [the architecture notes](docs/architecture.md), the
[device identity lifecycle](docs/device-identity.md), and the
[provisioning station design](docs/provisioning-station.md) for trust
boundaries, credential and provisioning requirements, failure semantics, and
intentionally deferred work.
