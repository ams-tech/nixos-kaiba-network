# Pilot architecture

## Data flow

```text
Pi agent --mTLS HTTPS--> controller --> desired-state store
                                             |
                                      single publisher
                                             | RFC 2136 + TSIG
                                             v
                                      P0 writable origin
                                             | IXFR/AXFR
                                             v
                                      P1 read-only standby
                                             |
                                 managed public secondaries
                                             |
                                      recursive clients
```

The public HTTPS request follows the DNS answer directly to the device. DNS
control traffic is not an application-traffic relay.

## Stable boundaries

- A device knows only its update endpoint, its
  [mTLS identity](device-identity.md), and its own addresses. It never knows P0,
  P1, or a DNS-provider API.
- The controller derives the DNS owner from the authenticated URI SAN, such as
  `spiffe://kaiba.network/device/001`. Request bodies cannot select a hostname,
  zone, TTL, or record type; a submission replaces the complete A/AAAA set.
- SQLite desired state is authoritative. DNS is a reconciled projection, so an
  accepted API request and public observation are separate states.
- The controller and publisher run under separate UIDs and private primary
  groups. A setgid `kaiba-state` directory is their only shared writable path;
  each service's sandbox masks the other service's credentials. A generation
  becomes `publicly-observed` only after at least two distinct configured
  public-authority endpoints agree.
- Only P0 accepts publisher updates. P1 and public secondaries are
  authoritative-only, non-recursive transfer replicas.
- Store, identity policy, publication leadership, and DNS mutation are Go
  interfaces. Their pilot implementations are replaceable without changing the
  device API.

## Write ordering and retries

`PUT /v1/devices/self/endpoints` requires an `Idempotency-Key` and exactly one
strong write precondition. A device with no state uses `If-None-Match: *`; an
existing device uses `If-Match: "g-N"`, obtained from the PUT response or
`GET /v1/devices/self/status`. A never-before-accepted request against an old
generation fails with HTTP 412, so delayed requests cannot overwrite newer
desired state.

The agent persists its pending key, payload hash, and precondition before
sending. Retrying that exact tuple returns the original `202` result even when
the current generation has advanced; it does not reapply the old address set.
A key reused with a different address set or precondition returns HTTP 409. The
pilot keeps accepted idempotency rows indefinitely, including across restarts.
This deliberately favors replay safety over bounded storage; retention and safe
compaction policy are later scale work.

## Lease and publication state

Production defaults are a 24-hour lease, six-hour renewal interval with agent
jitter, and a server-controlled 300-second DNS TTL. Before expiry, a fresh-key
renewal of an unchanged complete address set extends the lease without changing
its generation or the DNS zone. A changed set advances the generation. Expiry
advances the generation to an empty address set, and the publisher projects
deletion of both A and AAAA RRsets.

The VM topology shortens the lease and renewal policy and injects a controlled
clock so expiration can be exercised without waiting for production durations.

The controller returns `202 Accepted` after the desired-state transaction
commits. `GET /v1/devices/self/status` and PUT responses expose the generation
ETag and one of three projection states:

- `accepted`: durable desired state has not yet been applied to P0.
- `origin-applied`: the publisher's atomic TSIG update succeeded at P0.
- `publicly-observed`: every configured public authority agrees with that
  generation's address set.

The single publisher polls desired state, expires leases, replaces A/AAAA RRsets
at P0 atomically, and observes the public authorities. Its static leadership
implementation is an explicit replacement point, not an election mechanism.

## Failure semantics

A P0 outage does not stop the public secondaries from answering the last
published zone. P1 can continue to seed a fresh public secondary, but it is not
automatically promoted. If only DNS publication is unavailable, the controller
can durably accept intent and leave it pending; if the pilot host containing the
controller is down, the agent sees a retryable transport failure. Publication
resumes when the sole writer and publisher return.

Safe promotion is deliberately deferred. It requires fencing P0 before P1 can
become writable, monotonically continuing the zone serial, and preventing an
isolated former writer from rejoining with stale authority.

## Production boundary

Namecheap remains the registrar. In production, its CustomDNS delegation would
name a managed provider's public authoritative servers. P0 and P1 are hidden
transfer origins and do not appear in the delegation.

The VM test replaces the registry/registrar outcome with a parent authority for
`test.` and delegates only `kaiba.test` to two public-secondary emulators. Seven
dual-stack VMs separate public queries, transfers, and device updates across
three virtual networks. The report distinguishes this simulated topology and
registry relationship from exercised protocol and authorization observations.

The current modules require certificate keys and TSIG material at runtime paths
(the examples use `/run/credentials/...`) and order services after those
provisioning units. A future protected device key may instead be represented by
a signer handle, broker socket, or narrowly exposed hardware interface. The PKI
and TSIG fixtures generated by `tests/integration` deliberately enter the Nix
store and are named and scoped as test-only; they are unsuitable for
deployment.

The [device identity and credential lifecycle](device-identity.md) defines the
target, platform-neutral contract for device key protection, controlled
enrollment, rotation, revocation, recovery, and retirement. It is design
documentation, not an implemented production provisioning path. The current
agent still consumes a file-backed private key, and the current controller does
not maintain an authoritative active-credential inventory.

The [provisioning station design](provisioning-station.md) defines the dedicated
execution environment, control-service boundaries, station and lane fencing,
secret handling, recovery, and acceptance criteria for that future path. It is
also design documentation rather than an implemented station. The experimental
[Raspberry Pi 5 provisioning probe](raspberry-pi-5-provisioning-probe.md)
implements only target observation and partial baseline evaluation: it has no
transaction coordinator, mutation authority, key handling, enrollment, or
activation path.

The [provisioning-station interface demo](provisioning-station-kiosk.md) is a
separate loopback-only mock operator UI. Its service has no raw USB privilege
and does not connect the interface to the probe or implement any of the missing
production authorities.

The public GitHub Pages station simulation and the loopback service share the
same interface assets and transport implementation. Pages uses an in-memory
finite graph generated from the authoritative Go mock state machine; the local
service uses the HTTP mode of that same transport. Exhaustive transition tests
and byte comparisons prevent a separately maintained browser workflow or UI
from drifting from the station build. This is interface and simulated-workflow
parity, not an implementation of the future production orchestrator or its
hardware and authorization boundaries.

Deferred, rather than exercised: real Namecheap or provider changes and SLAs,
Internet/ISP/modem/NAT behavior, outside-in probes, public ACME, DNSSEC,
automatic promotion or fencing, redundant controllers or replicated desired
state, fleet-scale load and sharding, deployment, production enrollment and
credential rotation, production hardware-backed signing, attestation, and
monitoring.

The Raspberry Pi 5 development lane is no longer wholly deferred. The
repository contains reviewed read-only hardware-qualification evidence,
deterministic unsigned boot and dm-verity artifacts, an evaluated immutable
target, and development signing, control, audit, and lane-guard foundations.
It still lacks the complete signed release, authenticated control-to-guard
bridge, target-media writer, live-token evidence, and physical failure campaign
required before an irreversible ownership ceremony.
