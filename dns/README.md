# DNS Go module

This module implements the secure-device dynamic DNS pilot. It has no Go
dependency on the provisioning module.

## Commands

- `kaiba-agent` submits a device's complete public address set.
- `kaiba-controller` authenticates device updates and stores desired state.
- `kaiba-publisher` projects desired state into authoritative DNS.

Command entry points live under `cmd/`. Implementation packages live under
`internal/` and are private to this module.

## Development

From this directory:

```console
go test ./...
go build ./cmd/...
```

From the repository root, the workspace supports:

```console
go test ./dns/...
```

From this directory, the corresponding Nix boundary is `../nix/dns`:

```console
nix flake check ../nix/dns -L
nix build ../nix/dns#kaiba-agent -L
```

See [the architecture notes](../docs/architecture.md) and
[device identity lifecycle](../docs/device-identity.md) for the protocol and
trust boundaries.
