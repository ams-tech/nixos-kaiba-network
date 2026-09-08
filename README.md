# Kaiba secure-device dynamic DNS

This repository contains the Kaiba dynamic DNS control-plane pilot. It gives
devices stable DNS names without placing registrar credentials or hidden-origin
topology on those devices.

Device software authenticates to the controller with mTLS and submits its
complete public address set. The controller commits desired state to SQLite. A
separate publisher projects that state to a writable hidden primary using
RFC 2136 and TSIG, then verifies the result through redundant public
authorities.

## Repository layout

- `dns/` contains the Go commands and private implementation packages.
- `nix/dns/` contains the standalone DNS flake and reusable NixOS modules.
- `tests/integration/` defines the seven-VM DNS topology.
- `tests/report/` renders and validates the deterministic evidence report.
- `site/` contains the static project site published with the latest report.
- `docs/` documents the DNS architecture and device-identity boundary.

## Development

```console
go test ./dns/...
nix --accept-flake-config fmt -- --ci
nix --accept-flake-config flake check --all-systems --no-build -L
nix flake check ./nix/dns --all-systems --no-build -L
```

Build the operator-facing DNS commands:

```console
nix build .#kaiba-agent
nix build .#kaiba-controller
nix build .#kaiba-publisher
```

Run or build the integration topology:

```console
nix run .#dns-test-driver
nix build .#dns-test-report -L
nix build .#dns-test-gate -L
```

## Flake interface

The root flake is a convenience facade over `nix/dns`. Both expose:

- packages: `kaiba-agent`, `kaiba-controller`, and `kaiba-publisher`;
- NixOS modules for the device agent, update services, hidden primaries,
  hidden standbys, and public secondaries;
- unit, module-evaluation, schema, security, topology, and report checks; and
- the interactive `dns-test-driver` app on x86_64 Linux.

See [the architecture](docs/architecture.md) for the control and data paths,
and [the device identity lifecycle](docs/device-identity.md) for the
platform-neutral credential contract.

## Related repository

Secure-device provisioning is maintained independently in
[PseudoDesign/kaiba-provisioning](https://github.com/PseudoDesign/kaiba-provisioning).
This DNS repository does not import, re-export, build, test, or release its
tools.
