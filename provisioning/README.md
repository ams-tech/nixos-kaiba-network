# Provisioning Go module

This module implements the experimental Raspberry Pi provisioning probe and
the provisioning-station interface simulation. It has no Go dependency on the
DNS module and currently uses only the Go standard library.

## Commands

- `kaiba-provision probe` performs the non-persistent device preflight.
- `kaiba-provision qualify` strictly compares two private live-probe results
  and emits deterministic whitelist-redacted hardware evidence.
- `kaiba-provision-station-demo` serves the loopback-only station simulation.
- `kaiba-provision-station-graph` generates the browser simulation graph.

Command entry points live under `cmd/`. Implementation packages and embedded
station assets live under `internal/`. Device-class profiles and their schema
live under `profiles/` and `schemas/`.

## Development

From this directory:

```console
go test ./...
go build ./cmd/...
```

From the repository root, the workspace supports:

```console
go test ./provisioning/...
```

From this directory, the corresponding Nix boundary is `../nix/provisioning`:

```console
nix flake check ../nix/provisioning -L
nix build ../nix/provisioning#kaiba-provision -L
```

See the [Raspberry Pi 5 probe](../docs/raspberry-pi-5-provisioning-probe.md),
[Raspberry Pi 5 secure-boot guide](../docs/raspberry-pi-5-secure-boot.md), and
[station kiosk](../docs/provisioning-station-kiosk.md) documentation for the
safety, lifecycle, and operator boundaries.
