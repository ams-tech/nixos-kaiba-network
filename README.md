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

The root flake remains the compatibility facade for the complete pilot:

```console
nix --accept-flake-config flake check -L
nix --accept-flake-config build .#dns-test-report -L
nix --accept-flake-config run .#dns-test-driver
nix --accept-flake-config develop
```

The DNS integration report and interactive driver are `x86_64-linux` outputs.

The provisioning and DNS functionality can also be evaluated independently:

```console
nix flake check ./nix/provisioning -L
nix build ./nix/provisioning#kaiba-provision -L

nix flake check ./nix/dns -L
nix build ./nix/dns#dns-test-report -L
nix run ./nix/dns#dns-test-driver
```

The Go implementation follows the same boundary. `dns` and `provisioning`
are independent modules, coordinated for local development by the root
`go.work` file:

```console
go test ./dns/...
go test ./provisioning/...
```

See the [DNS module guide](dns/README.md) and
[provisioning module guide](provisioning/README.md) for their commands,
packages, dependencies, and corresponding Nix flakes. Neither Go module
depends on the other; cross-domain report and site composition remains at the
repository integration layer.

On `x86_64-linux`, `nix build .#dns-test-report` produces a report even if a
functional DNS assertion fails. Its `result` output contains HTML, Markdown, JUnit XML,
canonical DNS and provisioning JSON, topology diagrams, normalized evidence
and zone snapshots, and a SHA-256 manifest. The local report records native
x86 provisioning checks and explicitly marks ARM64 as not observed. CI composes
the native ARM64 result only after binding it to the checked-out source
revision. Physical Pi 5 qualification remains a separate manual gate;
the checked redacted record now reports that gate as passed, while the
automated result never implies authentication, attestation, or permission to
mutate a device. On `x86_64-linux`, `nix flake check -L` independently
enforces the report schemas, required functional and security assertions, Go tests, report tests,
and both flakes' NixOS module evaluation. The equivalent leaf command is
`nix build ./nix/dns#dns-test-report -L`. The interactive driver is for
topology debugging.

The physical ceremony uses `kaiba-provision qualify` to validate and compare
two private live results and produce a deterministic redacted record. It does
not automate or prove the required full-power removal or normal-boot check;
those remain explicit operator confirmations. See the
[Pi 5 probe runbook](docs/raspberry-pi-5-provisioning-probe.md#sacrificial-device-operator-runbook).
The root flake also provides a hardened
[Pi 5 provisioning-station SD image](docs/raspberry-pi-5-provisioning-image.md):

```console
nix --accept-flake-config build -L \
  .#packages.aarch64-linux.rpi5-provisioning-sd-image
```

The first hardware-facing secure-boot foundation is intentionally a
development-cohort reference, not a complete deployment or production
enrollment path. It provides a deterministic Pi 5 target and dm-verity
artifact builder, external
approval-gated YubiKey PIV signing, independent control/audit services, and a
root-only physical lane guard. It stops at `security_applied`; native Pi secure
boot has no anti-rollback primitive, so `enrollment_ready` remains blocked.
See the [live implementation runbook](docs/raspberry-pi-5-live-provisioning.md).

## Flake layout and consumption

The repository has two independently consumable leaf flakes:

- `nix/provisioning` owns the Raspberry Pi probe, provisioning-station demo,
  device profile, provisioning result, and their NixOS modules and checks.
- `nix/dns` owns the device agent, controller, publisher, authoritative DNS
  roles, VM topology, validation report, and their NixOS modules and checks.

The DNS report deliberately includes the provisioning result, so that leaf has
an explicit one-way input on the provisioning leaf. The root `flake.nix`
composes both leaves and preserves the original package, check, app, module,
development-shell, and formatter attribute paths.

The same-repository nested input graph requires Nix 2.30 or newer. Each leaf
carries its own lock file for direct use, while the root lock makes both leaves follow
the root `nixpkgs` pin when they are composed.

New consumers that need only one boundary can address its repository
subdirectory directly. A consumer that uses both can share its `nixpkgs` and
provisioning inputs as follows:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";

    kaiba-provisioning = {
      url = "github:ams-tech/nixos-kaiba-network?dir=nix/provisioning";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    kaiba-dns = {
      url = "github:ams-tech/nixos-kaiba-network?dir=nix/dns";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.provisioning.follows = "kaiba-provisioning";
    };
  };
}
```

Consumers that want the complete compatibility surface can continue to use
`github:ams-tech/nixos-kaiba-network` without a `dir` query.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pull requests,
pushes to `main`, and manual dispatches. It separates the test workload into:

- x86 formatting, flake evaluation, Go tests, report and Pages site tests,
  workflow linting, and NixOS module evaluation;
- native ARM64 builds and tests for all five packaged binaries and a
  commit-bound provisioning result;
- a dedicated native ARM64 build of the Pi 5 provisioning-station SD image; and
- the complete seven-VM DNS topology with KVM acceleration when available,
  followed by deterministic composition of both architectures' provisioning
  results.

The topology job uploads `kaiba-dns-test-report` for 14 days. That artifact now
contains the DNS topology evidence, automated provisioning checks for x86_64
and AArch64, and the independent physical-hardware qualification state. On
pushes or manual runs of `main`, it also assembles and publishes the project
homepage and the latest verified report through the repository's
`github-pages` environment.
The homepage is at the Pages root, the canonical report is at
`reports/latest/`, and the browser-only provisioning-station simulation is at
`provisioning-demo/`. Report generation precedes the assertion gates and artifact
collection/upload runs unconditionally, so a functional or security failure
still preserves and publishes the normalized HTML, Markdown, JUnit, JSON,
topology, evidence, and zone data for diagnosis. Each Pages deployment replaces
the homepage, canonical report, and station simulation together; the retained
Actions artifacts provide per-run history.

Pushing a stable `vMAJOR.MINOR.PATCH` tag for a reviewed `main` commit runs
`.github/workflows/release.yml`. After confirming that the commit's main-branch
CI run succeeded, the workflow rebuilds the provisioning image from that exact
tag on native ARM64, verifies the compressed archive, and publishes the image
and its SHA-256 checksum in a GitHub release. See the [image release
procedure](docs/raspberry-pi-5-provisioning-image.md#release-the-image).

The Pages simulation and loopback station use the same HTML, CSS, controller,
and transport code. Their synthetic workflow walks the Raspberry Pi 5
secure-boot ceremony from station admission and deferred-baseline closure
through commit-time RPIBOOT target re-identification, an approval-gated,
one-shot OTP/EEPROM commit, post-recovery readback, separately approved and
journaled final controls with cold-restart readback, and the `enrollment_ready`
handoff. Owned terminal states have no reset path. Its finite transition graph
is generated from the Go mock state machine during the build; no second
JavaScript workflow is maintained. The only runtime difference is explicit
configuration: loopback mode calls the local HTTP API, while Pages mode
traverses the generated graph in memory. Neither mode has hardware, signing,
mutation, or provisioning authority.

Enable the site once in **Settings → Pages → Build and deployment** by selecting
**GitHub Actions** as the source. Pages can make the homepage, report, and its
normalized evidence public, including for some private-repository plans. All
referenced actions are pinned to immutable commit SHAs. Test jobs keep read-only
repository access; only the main-only deployment job receives Pages write and
OIDC token permissions, and only the isolated release-publication job receives
repository-contents write permission.

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

Packaged binaries are built for both `x86_64-linux` and `aarch64-linux`. The
DNS leaf provides:

- `kaiba-agent`
- `kaiba-controller`
- `kaiba-publisher`

The provisioning leaf provides:

- `kaiba-provision`
- `kaiba-provision-audit`
- `kaiba-provision-control`
- `kaiba-provision-lane-guard`
- `kaiba-provision-integrated-rehearsal`
- `kaiba-provision-media-stager`
- `kaiba-provision-rehearsal`
- `kaiba-provision-station`
- `kaiba-provision-station-demo`
- `kaiba-provision-unfused-compat`
- `kaiba-provision-unfused-evidence`
- fail-closed signer, signing-client, signing-gate, and YubiKey-wrapper
  foundations, configured only through the Nix library factories

`kaiba-provision probe` is an experimental, non-persistent Raspberry Pi 5
preflight slice. It can normalize imported OTP metadata or acquire it from one
lane-bound Pi 5 Model B using a digest-pinned metadata-only recovery bundle.
Its result is correlation and partial preflight evidence, never authentication,
attestation, or permission to mutate a target. See the
[Raspberry Pi 5 provisioning probe](docs/raspberry-pi-5-provisioning-probe.md)
for the safety boundary, station setup, command contract, and required hardware
qualification.

The [Raspberry Pi 5 secure-boot guide](docs/raspberry-pi-5-secure-boot.md)
documents the native BCM2712 chain of trust, its assurance limits, the required
artifacts and evidence, and the irreversible checklist from a qualified
candidate through ownership to enrollment readiness. The separate
[development live implementation](docs/raspberry-pi-5-live-provisioning.md)
provides the real fail-closed component boundaries. Its non-mutating probe has
passed hardware qualification, but the irreversible path remains unqualified
and cannot reach `enrollment_ready`. The
[secure-boot execution plan](docs/raspberry-pi-5-secure-boot-execution-plan.md)
tracks the remaining release, media-staging, enforcement, physical-lane,
rehearsal, and ceremony gates for one sacrificial development board.
The [non-fusing secure-boot prototype](docs/non-fusing-secure-boot-prototype.md)
is the runnable software-first path through durable control, audit, plan
binding, restart validation, signed capsule checks, media fixtures, and
optional unfused evidence without authorizing a one-time setting change.

`kaiba-provision-station-demo` is an unprivileged, loopback-only interface
prototype for an HDMI display and USB touchscreen. It renders deterministic
mock scenarios for the complete Pi 5 secure-boot ceremony through
`enrollment_ready`, including deferred-baseline closure, commit-time target
re-identification, approval, intent, one-shot mutation, authoritative readback,
positive and negative tests, repeated readback after recovery, and separate
approval, intent, one-shot application, cold restart, and direct readback for
final controls before affected retests. Failures after the simulated
irreversible boundary quarantine the owned target without offering reset. These
are synthetic display states, not physical evidence; the demo deliberately has
no USB, probe, authentication, attestation, secret-handling, signing, mutation,
or inventory authority. Device-identity enrollment remains a later workflow.
See the
[provisioning-station interface demo](docs/provisioning-station-kiosk.md) for
the NixOS module, systemd sandbox, operator-session Chromium example, shared
Pages build, and parity guarantees.

Reusable NixOS modules in the DNS leaf cover the device agent, update services,
hidden P0, hidden P1, and public-secondary role. The provisioning leaf provides
the probe, simulation, control, audit, signing-gate, physical-lane, and secure
target modules. The root facade re-exports all of them and retains a combined
default module. The seven-VM QEMU topology and interactive lab are
`x86_64-linux` DNS outputs.

See [the architecture notes](docs/architecture.md), the
[device identity lifecycle](docs/device-identity.md), and the
[provisioning station design](docs/provisioning-station.md) for trust
boundaries, credential and provisioning requirements, failure semantics, and
intentionally deferred work.
