# Self-hosted Forgejo and Hydra CI design

Status: design draft. This is a proposed build and release-control
architecture. It does not implement fleet deployment, grant signing authority,
or authorize device mutation. Nothing in this document is deployed by this
repository.

Drafted: 2026-09-06.

This document proposes a self-hosted source-control and continuous-integration
environment for Kaiba. The proposed core is
[Forgejo](https://forgejo.org/) for Git collaboration and
[Hydra](https://github.com/NixOS/hydra) for Nix evaluation and builds. A small,
separately authorized orchestration layer performs the few required
side-effecting operations that do not belong in a Nix build.

The design preserves the security properties of the current GitHub Actions
workflows. It does not make a CI system a signing authority, provisioning
authority, or fleet update controller. In particular, moving source and builds
on premises must not collapse the existing separation between untrusted source
evaluation, protected-branch cache publication, release verification, release
publication, approval-gated signing, and physical device mutation.

## Scope

This design covers:

- Git repository hosting, review, branch protection, tags, and release assets;
- pull-request and protected-branch continuous integration;
- native `x86_64-linux` and `aarch64-linux` Nix builds;
- the KVM-accelerated NixOS VM topology;
- build logs, reports, large image artifacts, and a Nix binary cache;
- protected static-site and release publication;
- service isolation, credentials, retention, backup, recovery, and monitoring;
  and
- a staged migration from GitHub without weakening an existing gate.

The following remain separate projects:

- production device enrollment and credential rotation;
- a fleet rollout controller, device cohorts, health reporting, and rollback;
- production boot- and software-signing ceremonies;
- physical provisioning-station implementation and qualification;
- automatic DNS-origin promotion and fencing; and
- replacing every upstream Internet dependency with an internal mirror.

Hydra builds artifacts that those systems may later consume. A successful
Hydra build is not authorization to publish, sign, install, activate, or mutate
anything.

## Existing requirements

The replacement must preserve the current observable behavior rather than
merely reproduce a green status badge.

The repository currently has these distinct workloads:

| Workload | Platform and capability | Required result |
| --- | --- | --- |
| Formatting, evaluation, Go tests, report tests, workflow policy, and module evaluation | `x86_64-linux` | Independent failures with useful logs |
| Production binaries and provisioning evidence | Native `aarch64-linux` | Result bound to the exact source revision |
| Provisioning-station SD image | Native `aarch64-linux` | Complete compressed image and digest |
| Seven-VM DNS topology | `x86_64-linux`, preferably KVM | Report retained even when a functional or security gate fails |
| Project site | Protected `main` only | Atomically published validated site |
| Signed target release verification | Native `aarch64-linux` | Archive digest, media digest, size, source, and tag binding |
| Release publication | Protected tag after successful source CI | Exact verified assets, without rebuilding or signing them |

The current report composes native ARM64 evidence with the x86 topology only
after binding it to the checked-out source revision. The replacement must not
silently substitute cross-compilation or emulation for that native observation.

The current release path also separates a source-reading validation job, a
no-checkout draft-asset fetch job, a native ARM64 verifier with no repository
token, and a narrowly authorized publisher. The self-hosted path must retain
equivalent or stronger isolation.

Release-sensitive flake outputs currently require a clean source with a usable
`self.rev`. A stable release tag is an annotated `vMAJOR.MINOR.PATCH` object
whose six-line message binds its peeled source revision, archive SHA-256,
decompressed-media SHA-256, and archive size. The release process separately
records the tag object's own Git identity. None of these fields may be inferred
from a mutable branch, Forgejo release title, asset name, or most-recent Hydra
result.

## Selected roles

The architecture assigns one bounded responsibility to each role.

| Role | Initial implementation | Authority |
| --- | --- | --- |
| Git forge | Forgejo | Repositories, users, pull requests, branch policy, tags, release records, and release assets |
| CI event bridge | Small stateless service or a restricted Woodpecker pipeline | Convert authenticated forge events into exact-revision Hydra evaluations and report statuses |
| Build controllers | Trust-separated Hydra instances on NixOS | Evaluate jobs, schedule derivations, retain build facts and logs, and expose read APIs without sharing PR and protected stores |
| Build workers | Dedicated NixOS x86 and ARM64 machines | Build only the derivations assigned for their declared system and features |
| Nix cache | Attic or a conventional signed HTTP/S3 Nix cache | Distribute approved store paths; no release or deployment decision |
| Object storage | S3-compatible service | Durable build products, reports, images, cache objects, and backups under separate buckets and policies |
| Report publisher | Restricted publication worker | Copy one validated site derivation to the public web origin |
| Release coordinator | Restricted workflow or purpose-built service | Verify release predicates, prove the pre-staged draft image, add its checksum, and publish the release |
| Infrastructure deployer | Operator-controlled `deploy-rs` or Colmena host | Update the forge, CI, cache, DNS, and other ordinary NixOS infrastructure |
| Fleet update controller | Future dedicated service | Select device cohorts and authorize installation of signed releases |

Forgejo and Hydra are the required core. The event bridge and protected
publication operations may initially use Woodpecker because it has a native
Forgejo integration, but Woodpecker must not become a second build authority.
Its jobs should trigger and read Hydra, validate immutable identifiers, and
perform narrowly scoped publication. A purpose-built bridge may replace it
later without changing the trust model.

Forgejo Actions is another possible bridge implementation. It should not be
chosen on the assumption that the existing GitHub Actions files are directly
portable: Forgejo documents its Actions syntax as familiar but not fully
compatible, and the current workflow depends on GitHub-specific Pages,
artifact, token-permission, environment, and release behavior.

Hydra also contains Gitea-oriented webhook and status plugins. Forgejo descends
from Gitea, but that ancestry is not a sufficient compatibility or security
contract. The built-in webhook matches enabled jobsets by repository URL; it
does not pin a jobset to the pushed ref and commit. The status plugin also has
gaps around flake jobset inputs, cache-hit events, and pull-request lifecycle
management. The initial design therefore uses the explicit bridge to pin the
commit, aggregate the protected required jobs, and publish one stable Forgejo
status. Branch protection must not depend directly on the built-in Gitea
plugin unless those cases gain equivalent tests.

## Logical architecture

```text
 developers and reviewers
            |
            | HTTPS / SSH
            v
+------------------------- public service zone -------------------------+
| Forgejo                                                               |
| - repositories and pull requests                                      |
| - protected branches and tags                                         |
| - commit statuses and release records                                 |
+------------------------------+----------------------------------------+
                               | authenticated webhook
                               v
+------------------------- CI control zone ------------------------------+
| CI event bridge                                                        |
|       |                         |                                       |
|       v                         v                                       |
| untrusted-PR Hydra          protected Hydra                             |
| separate DB and store       separate DB and store                      |
|       |                         |                                       |
+-------+-------------------------+---------------------------------------+
        | version-selected SSH or gRPC build protocol
        v                         v
+---------------------------+  +----------------------------------+
| disposable PR builders    |  | protected-main builders          |
| - x86, ARM64, and KVM     |  | - x86, ARM64, KVM, image verify |
| - no durable promotion    |  | - no production route           |
| - no production route     |  | - protected staging only        |
+---------------------------+  +----------------+-----------------+
                                                  |
                                                  | successful public paths
                                                  v
+---------------------- artifact distribution zone ---------------------+
| protected staging | trusted cache | reports | release stage            |
|                    S3-compatible object storage                        |
+------------------------------+----------------------------------------+
                               | exact build IDs and digests
                               v
+---------------------- protected publication zone ---------------------+
| report publisher | release coordinator | native release verifier      |
| scoped credentials; no general PR work; no signing private key        |
+------------------------------+----------------------------------------+
                               |
                               | signed metadata and immutable bytes
                               v
                    future fleet update service

 Offline roots, boot/software-signing keys, YubiKey authorization, the
 provisioning authority, and physical lane guards remain outside all CI
 zones.
```

The zones are security boundaries, not necessarily separate racks. An initial
deployment may place several control-plane services on one virtualization
cluster, but it must retain distinct service identities, storage credentials,
network policy, Unix users, databases, and backup material. Builders and
protected publication workers require stronger separation and should not share
a host with Forgejo or Hydra's database.

## Source-control plane

### Forgejo configuration

Forgejo should be the canonical Git remote only after migration acceptance has
passed. The production instance should:

- disable public registration;
- require individual accounts and strong second factors for administrators;
- keep routine repository administration distinct from instance
  administration;
- restrict SSH to managed user keys and disable password login at the host;
- protect `main` against direct pushes and history rewriting;
- require the complete CI status set and the configured reviewer count before
  merge;
- protect stable `vMAJOR.MINOR.PATCH` tags against creation, deletion, or
  movement by routine contributors;
- issue separate, least-privilege credentials to the CI bridge, status
  reporter, report publisher, and release publisher;
- use S3-backed attachment storage for Forgejo-managed release files rather
  than the forge root filesystem, or use digest-bound links to an external
  release-only bucket; and
- mirror repositories and release metadata to an independently administered
  recovery location.

Forgejo tag protection restricts who may create or change matching refs; it
does not prove that a tag is annotated or establish the tag message's shape.
The release coordinator, or a tested server-side pre-receive hook, must enforce
the repository's direct annotated-to-commit tag rule and exact six-line image
binding. That policy validates tag structure and identity; it does not imply
that Git tags are cryptographically signed.

Forgejo's generic package registry can hold ordinary build outputs, but it is
not a Nix binary cache and should not be made the authoritative store for Nix
closures. Large Pi images may be attached to Forgejo releases or stored in a
release bucket with the Forgejo release containing an immutable digest-bound
reference. The chosen behavior must be explicit because the existing flake
contains release URLs that are part of evaluated contracts.

### Repository identity

CI and release records must use the full Git object ID, never a mutable branch
name, as their source identity. The event bridge resolves a pull-request head,
branch update, or tag to a commit, fetches that exact object from Forgejo, and
passes an immutable flake reference to Hydra.

The bridge records at least:

- Forgejo instance and repository identity;
- event delivery ID and verified webhook key ID;
- pull-request number or protected ref;
- full commit object ID;
- tag object ID and peeled commit for a release tag;
- requested Hydra project and jobset policy; and
- the resulting Hydra evaluation ID.

Retries of the same event and source tuple must return the original evaluation
or create an explicitly linked retry. A delayed webhook must never cause a
newer protected-branch result to be attributed to an older commit.

### Mirroring upstream inputs

Moving this repository to Forgejo does not by itself remove GitHub as an input.
The root and leaf lock files currently resolve pinned GitHub-hosted inputs, and
some release contracts contain GitHub release URLs. The first deployment may
allow those exact, pinned upstream inputs through an egress allowlist.

A later disconnected profile can mirror upstream Git objects and release bytes
internally, but changing a locked source URL or a release URL changes evaluated
inputs and must pass the normal review and release process. A transparent
network redirect is not allowed to silently redefine an immutable source.

## Hydra build plane

### Version and builder transport

Hydra is under active development and its queue-runner architecture is
changing. At the time of this draft, the Hydra packaged by this repository's
[current root Nixpkgs pin](https://github.com/NixOS/nixpkgs/blob/70ce234312134a463ba7728e94da2486a1d237ac/pkgs/by-name/hy/hydra/package.nix)
is `0-unstable-2026-03-16` and uses the legacy queue runner with
controller-to-builder SSH/Nix connections. Newer upstream revisions include a
Rust queue runner and builders that connect outbound over gRPC. Their service
options, credential direction, firewall rules, health checks, and failure
behavior are not interchangeable. The new queue runner's upstream NixOS
options are still explicitly named as development interfaces.

The deployment must pin Hydra independently or take it from one reviewed
Nixpkgs pin, record which queue-runner generation it uses, and test that exact
combination. Do not copy current upstream development-module examples into the
older packaged NixOS module, or enable both builder transports accidentally.
An upgrade between generations is an architecture migration with a rollback
plan, not a routine package restart.

### Trust-separated Hydra domains

Use separate Hydra control, database, Nix-store, worker, cache, and service
identity domains for pull requests and protected refs. A pull-request output
must not already be present in the store used to establish a protected-main
build merely because both events evaluate to the same derivation path.

- The **untrusted domain** evaluates pull requests on disposable workers. It
  may retain logs and explicitly classified diagnostic products, but it has no
  route or credential that can add a substitutable path to protected staging.
- The **protected domain** accepts only commits that Forgejo independently
  confirms on protected `main`, plus exact stable-tag verification requests.
  It realizes required outputs in its own store and may write only to protected
  staging; a separate promoter still decides what enters the trusted cache.

This is easiest to audit as two Hydra deployments. They may share physical
virtualization hardware only if their VMs, networks, disks, databases, service
accounts, and backup credentials remain isolated. If the instance never
accepts external pull requests, a later review may choose a less expensive
layout, but merely marking jobsets with different names is not store or
credential isolation.

### Job definition

Hydra flake jobsets evaluate a `hydraJobs` output. They work well for the
protected-main and shadow-build cases. Hydra recursively schedules every
derivation below `hydraJobs`; nested attribute names organize jobs but do not
select an event class. The repository should expose all evaluated checks from
the root, provisioning, and DNS flakes on both supported systems. The current
coverage contract has no exclusions: every evaluated check attribute must be
enumerated and scheduled exactly once as a required job. Nix may still
deduplicate realization when two attributes resolve to the same derivation. A
machine-readable Hydra coverage gate must retain the attribute-level property.
Packages, images, reports, and other non-check outputs should use an explicit
allowlist. Some of those outputs are large, operational, hardware-facing, or
deliberately unusable without external public inputs; they must not become
routine jobs merely because a new flake attribute was added.

A conceptual layout is:

```nix
{
  # Candidate output for protected-main and shadow flake jobsets only.
  hydraJobs = {
    requiredChecks = {
      root = self.checks;
      provisioning = provisioning.checks;
      dns = dns.checks;
    };

    protectedProducts = {
      # Explicitly allowlisted packages, images, reports, and site outputs.
    };
  };
}
```

The actual output should reuse existing derivations instead of duplicating
their commands. Any check that exists only as a shell step in GitHub Actions
should be converted into a Nix derivation when practical. This makes local,
Hydra, and migration-parity execution share one implementation. Do not place
pull-request, protected-main, and release graphs under one `hydraJobs` tree and
expect Hydra to select one branch. Use separate jobsets and entry points: the
candidate flake output above for protected-main and shadow builds, a protected
wrapper for pull requests, and a protected release-validation entry point for
stable tags. The bridge selects among those protected policies only after it
has classified and resolved the event; the candidate source does not assign
itself to a more privileged event class.

Hydra evaluates flakes in restricted mode. `nix.settings.allowed-uris` must be
an explicit list of the required Forgejo, pinned upstream Git, and cache URI
prefixes. It must not be set to a broad value merely to make an evaluation
pass. The Hydra and Nix versions must also be pinned and qualified with the
repository's Nix 2.30-or-newer nested-flake requirement.

### Protected CI definition

A pull request can change its own `flake.nix`; therefore its `hydraJobs`
attribute cannot, by itself, define which checks are required for that pull
request. Otherwise a change could remove a job and then report success for the
smaller graph.

The required graph and commit-status mapping must come from a protected CI
control expression. That expression receives the candidate repository as a
separate immutable source input, evaluates the candidate's root and both leaf
flakes, and builds every required candidate check. At minimum it must:

- obtain its policy from a reviewed protected ref or separately deployed
  control repository, not from the candidate revision;
- bind the candidate input to the full Forgejo commit object ID;
- compare the evaluated root, provisioning, and DNS check inventory for both
  systems with the protected coverage policy;
- reject an omitted, duplicate, renamed, extra, or intentionally excluded
  check unless a separately reviewed policy transition authorizes it;
- select non-check packages from a protected explicit allowlist;
- emit the fixed required aggregate status even if candidate-controlled
  display names or attributes change; and
- record the policy revision beside the candidate revision in the evaluation
  result.

Candidate code necessarily defines the implementation being reviewed, but it
must not define the minimum evidence required to approve itself. A policy
change that intentionally adds, renames, or removes a required check needs a
staged transition so neither the old nor new source can pass through a missing
gate.

Hydra flake jobsets cannot also receive the ordinary named inputs used by a
legacy jobset. The initial required pull-request implementation should
therefore use one protected legacy entry point, for example a future
`ci/hydra-required.nix`, with the candidate Git checkout supplied as an exact
separate input. An alternative is for the bridge to create a complete wrapper
flake whose lock binds both the protected policy revision and candidate
revision. It must not pretend to combine flake-jobset and legacy-input behavior
that the pinned Hydra does not support.

### Jobsets and triggers

Use separate policies for three event classes:

1. **Pull request.** Evaluate the exact head commit in the untrusted policy.
   Results may satisfy merge checks but cannot write a protected cache, publish
   a site or release, or reach a privileged worker.
2. **Protected main.** After Forgejo confirms that the commit is the current
   protected `main` tip, evaluate the complete graph. Only a successful and
   still-current evaluation becomes eligible for cache and report promotion.
3. **Stable tag.** Resolve both the annotated tag object and its commit. A
   release evaluation verifies pure release predicates, but a separate release
   coordinator decides whether publication is allowed.

Hydra can poll a long-lived main jobset. Exact-revision pull requests need an
integration policy because Hydra is not itself a pull-request manager. The
bridge can maintain bounded, declaratively named jobsets such as
`pr-<number>-<short-revision>` and garbage-collect them only after their
retention period. It must validate identifiers before constructing a flake URI
and must not accept an arbitrary caller-supplied Nix expression or repository.

Webhook delivery should reduce latency, but periodic reconciliation remains
necessary. The bridge periodically compares open Forgejo pull requests,
protected refs, recorded event deliveries, Hydra jobsets, evaluations, and
commit statuses. Webhook loss must delay CI, not silently mark an untested
revision successful.

### Builder classes

The initial build farm needs at least these classes:

| Builder class | Nix system/features | Work admitted |
| --- | --- | --- |
| x86 ordinary | `x86_64-linux`, `big-parallel` | Evaluation products, unit tests, Go builds, schemas, and ordinary packages |
| x86 virtualized | `x86_64-linux`, `nixos-test`, `kvm`, `big-parallel` | NixOS VM tests and the seven-VM DNS topology |
| ARM64 ordinary | `aarch64-linux`, `big-parallel` | Native packages and provisioning evidence |
| ARM64 image | `aarch64-linux`, `big-parallel` | Pi images and native release verification inputs |

One physical machine may initially implement both classes for an architecture,
but the Hydra machine declarations should keep the labels distinct. This
allows a KVM worker or large-image worker to be isolated later without changing
job definitions.

Prefer server-class ARM64 capacity for routine throughput. A dedicated Pi 5
can provide useful same-class native evidence, but it should be treated as a
slow, replaceable builder and not as the only ARM64 capacity. Production fleet
devices must never join the build farm.

### Build isolation

All source under test is hostile, including repository-maintained Nix
expressions on a pull request. The threat is not limited to shell commands in a
generic workflow.

Required controls are:

- keep Nix sandboxing enabled and fail closed when a job requires an undeclared
  impurity;
- run Hydra evaluation in a dedicated service boundary with restricted URI
  access and no production credential paths;
- give builders no route to device, provisioning, signing, audit, DNS-control,
  or protected-publication networks;
- give pull-request builders no cache-write, Forgejo-write, object-storage
  write, deployment, or signing credentials;
- expose only the minimum read-only substituters required by the policy;
- use a distinct untrusted worker pool if external contributors are accepted;
- prevent the untrusted Hydra store and cache namespace from being a
  substituter for protected-main evaluation;
- reset or re-image workers periodically and after a suspected escape;
- limit CPU, memory, disk, process count, build time, log size, and concurrent
  jobs;
- prevent jobs from reaching the Hydra controller's administrative interface
  or builder SSH keys;
- do not mount a container engine's host socket into a build; and
- treat KVM access as additional attack surface and keep those workers
  disposable and network-isolated.

Hydra necessarily has authority to schedule work and the Nix daemon has strong
authority over its builders. A compromised Hydra controller can therefore
damage build workers or forge CI availability. Network separation and the
absence of release, signing, and fleet credentials limit that compromise from
becoming a production-device compromise.

### Cross-architecture report composition

The existing workflow transfers one digest-bound ARM64 JSON result into the x86
report job. Under Hydra, that relationship should become an explicit Nix build
graph edge:

```text
ARM64 platform-result derivation ----+
                                     +--> canonical report derivation
x86 topology/report derivation ------+              |
                                                    +--> independent gates
```

Hydra must finish the native ARM64 derivation before the composition derivation
can run. The composed report must record and check the source revision of both
inputs. The handoff must contain exactly one expected regular, non-symbolic-link
receipt and must verify its producer-recorded digest before composition. Merely
finding an ARM64 result with the same job name is insufficient.

Report production and report gating remain separate. The base topology job is
designed to emit diagnostic evidence even when a functional assertion fails;
independent schema, functional, and security jobs decide whether the
evaluation passes. Hydra retention must keep the report product for a failed
aggregate evaluation when the report derivation itself succeeded.

### Build products and retention

Derivations that produce human-facing files should declare Hydra build
products through `$out/nix-support/hydra-build-products`. At minimum, expose:

- the canonical HTML and Markdown reports;
- JUnit XML, normalized JSON, evidence, topology, and zone snapshots;
- the report SHA-256 manifest;
- ARM64 platform receipts;
- validated static-site trees; and
- compressed image archives and public checksums where policy permits.

Build products are convenience views over immutable outputs, not an authority
record. The durable record must retain the source revision, identities and
digests of all three flake lockfiles, derivation path, output store path or
content digest, builder identity, Hydra evaluation/build IDs, timestamps, and
gate results. The three locks are the root, `provisioning`, and `nix/dns`
lockfiles.

Set explicit retention classes rather than one global duration:

- ordinary pull-request logs and products: short-lived according to a recorded
  policy;
- every canonical per-run DNS report, including a report from a failed
  protected-main aggregate: at least the current 14 days;
- failed protected-main diagnostic reports: longer when incident policy or a
  release investigation requires it;
- successful protected-main evidence: release-policy duration;
- release inputs and published release evidence: retained for the supported
  life of the corresponding devices plus the audit period; and
- signing receipts and provisioning audit records: never delegated to Hydra
  retention in the first place.

## Nix binary-cache design

Successful construction and permission to serve a store path are different
decisions. Use three store/cache classes:

| Cache view | Writers | Readers | Purpose |
| --- | --- | --- | --- |
| Pull-request scratch | Untrusted Hydra domain | Same untrusted domain only | Optional short-lived reuse and diagnostics; never a protected substituter |
| Protected staging | Protected Hydra domain | Protected workers and cache promoter | Hold outputs realized for one exact protected-main evaluation |
| Protected main | Cache promoter only | Developers, CI, infrastructure, and permitted devices | Outputs from an accepted protected-main evaluation |

The promoter receives an exact manifest of store paths from an accepted Hydra
evaluation. Before copying paths, it confirms that:

- the Forgejo commit is still the accepted protected ref;
- every required Hydra job belongs to that exact evaluation and succeeded;
- report schema, functional, and security gates succeeded;
- the output paths and references were realized by the protected domain for
  that evaluation and exist in protected staging; and
- no signed target release image archive, secret-bearing, signing-authority, or
  hardware-mutation output is present.

The protected-cache signing key is available only to the cache service or
promoter, not to Hydra evaluators or workers. Cache signatures authenticate a
Nix store object for substitution; they do not replace the release manifest,
boot signature, media digest, source binding, or rollout authorization.

Attic is a reasonable first implementation because it supports self-hosting,
S3-compatible storage, deduplication, garbage collection, and scoped cache
access. Its upstream project still describes it as an early prototype, so the
deployment must pin a reviewed revision, test recovery and upgrades, and retain
the option of a simpler conventional HTTP/S3 Nix cache. The public cache URL
and key are release-relevant configuration and require controlled rotation.
Existing upstream substituter public keys remain pinned exactly until a
reviewed migration explicitly changes them.

## Protected publication

### Static reports and project site

The complete site should be a Nix output. A protected publisher receives only
an exact successful Hydra build ID and performs these steps:

1. Resolve the build through Hydra's authenticated read API.
2. Verify the project, jobset, evaluation, full source revision, derivation,
   store path, and expected product type.
3. Verify the site's manifest and required CI gates locally.
4. Verify that the tree contains the homepage, `reports/latest/`, and the
   generated `provisioning-demo/` from one accepted composition.
5. Copy that complete tree to a new immutable versioned object prefix.
6. Atomically change the public root pointer or reverse-proxy target so all
   three surfaces change together.
7. Record the old and new versions in an append-only publication log.

The public web server receives only read access to published prefixes. It has
no Forgejo, Hydra, object-store write, cache-write, or release credential.
The publisher never checks out or executes candidate repository code; it only
validates and copies the already-built static output. Rollback selects a
previously verified prefix; it does not rebuild the site.

### Release verification and publication

Hydra may build unsigned artifacts and perform public offline verification. It
must never receive a boot-signing key, YubiKey PIN, signing grant, approval
credential, or access to a signing broker.

The protected release coordinator reproduces the current authority split:

```text
tag validation
  - read source and protected-main state
  - verify annotated tag and immutable image binding
                 |
                 v
asset fetch/stage
  - may read one private draft asset
  - does not check out or execute repository code
  - writes only to a one-day unverified namespace
                 |
                 v
native ARM64 verification
  - no Forgejo write token and no signing authority
  - require one exact regular, non-symlink input file
  - verify name, zstd stream, archive digest, decompressed media digest, size
  - writes only the exact image and checksum to a one-day verified namespace
                 |
                 v
publication
  - recheck source and release-control CI, tag object, draft state, asset
    identity, exact file count, and digests
  - prove the existing remote draft image matches the verified staged image
    by name, size, and digest; do not replace or re-upload it
  - upload only the verified checksum and change the draft to published
  - read back the remote release, assets, tag, sizes, and digests
```

Each stage uses a different service identity and storage prefix. No stage may
replace its input by rebuilding from the tag. Publication is an explicit
operator action or protected-environment approval, not an automatic
consequence of tag creation. This preserves the current private-draft handoff:
the image remains the pre-staged draft asset, while the publisher proves its
identity, uploads only the checksum, changes the release state, and then reads
everything back. If Forgejo requires different transaction semantics, treat
that as a changed release contract and test it explicitly during migration.

Prefer short-lived workload identities accepted by Forgejo and object storage.
Where a static token is temporarily unavoidable, scope it to one repository
and operation, load it from a root-owned credential file, rotate it, and ensure
it is absent from environment dumps, command arguments, Nix derivations, logs,
and artifacts.

If Forgejo does not expose a trustworthy server-computed asset digest, the
publisher downloads the remote bytes after each write and computes the digest
itself. A successful upload or edit response is never proof of final state.
The GitHub-specific fixed `v0.1.15` recovery path, including its repository,
release, and asset IDs, remains a historical compatibility path unless a
separate review explicitly retires it. It must not be generalized into a
caller-selectable self-hosted recovery endpoint.

## Infrastructure deployment and fleet boundary

Use `deploy-rs` or Colmena from a dedicated administration host for the
self-hosted control plane. The deployer should build or fetch the reviewed
NixOS closure, activate one role at a time, verify health, and retain a tested
rollback. A CI result can identify the closure eligible for deployment, but CI
must not possess unrestricted root SSH access to every service.

Production Kaiba devices use a different model. Their device-side trust and
update flow is governed by the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md),
not by this CI design. Dynamic addresses and outbound authentication make a
pull protocol preferable to CI pushing over SSH. A future update controller should
publish delegated-signed, immutable channel metadata and fresh policy
authorizations. The customer-root-signed stable verifier must authenticate that
policy and the selected release before protected state opens; only then may the
device install into a recoverable layout, report boot health, and advance
through explicit canary cohorts. Hydra supplies candidate bytes and evidence
but has no device inventory, policy-freshness, cohort, activation, or rollback
authority.

Native Raspberry Pi secure boot does not provide the anti-rollback primitive
required by the current enrollment policy. Self-hosting CI does not change
that fact and must not cause `enrollment_ready` or production-rollout claims to
appear in build or deployment status.

## Credentials and authority matrix

| Credential or key | Forgejo | Bridge | Hydra | Builders | Publisher | Fleet device |
| --- | --- | --- | --- | --- | --- | --- |
| Developer SSH/signing key | Verifies public part | No | No | No | No | No |
| Webhook HMAC key | Sends | Verifies | No | No | No | No |
| Commit-status writer | No | Yes, status only | No | No | No | No |
| Builder transport credential | No | No | Selected controller or queue runner only | Selected SSH peer or outbound gRPC identity | No | No |
| Pull-request scratch-cache writer | No | No | Untrusted domain only | Prefer controller-mediated | No | No |
| Protected-staging writer | No | No | Protected domain only | Prefer controller-mediated | Cache promoter reads only | No |
| Protected-cache signing/promote key | No | No | No | No | Cache promoter only | Public verification key |
| Report publication credential | No | No | No | No | Report publisher only | No |
| Forgejo release writer | Validates | No | No | No | Release publisher only | No |
| Boot/software-signing private key | No | No | No | No | No | Public verification material only |
| Provisioning or fleet-control credential | No | No | No | No | No | Per-device operational identity only |

The words “No” mean the credential is absent, not merely that policy asks the
component not to use it.

## Network policy

Default-deny network policy should enforce these permitted flows:

- users to Forgejo over HTTPS and SSH;
- Forgejo to the event bridge over authenticated HTTPS;
- the bridge to the Forgejo read/status APIs and Hydra trigger/read APIs;
- Hydra to PostgreSQL, configured source endpoints, object storage, and build
  workers when using the legacy SSH transport;
- build workers to the queue-runner endpoint when using the newer outbound
  gRPC transport;
- builders to approved source fetch endpoints and read-only substituters;
- untrusted builders or their controller only to pull-request scratch storage;
- protected builders or their controller only to protected staging;
- cache promoters to protected Hydra read APIs, protected staging, and the
  trusted cache;
- protected publishers to exact read sources and their one write destination;
- monitoring collectors to read-only metrics endpoints; and
- backup workers to explicit database and object-storage backup endpoints.

There is no permitted CI-to-device, CI-to-provisioning-lane,
builder-to-production-DNS-control, or Hydra-to-signer flow. Public web ingress
terminates at a reverse proxy; PostgreSQL, Hydra administration, builder SSH,
cache administration, object-storage administration, and metrics endpoints are
not public.

## Availability, backup, and recovery

### Authoritative and reconstructible state

| State | Classification | Recovery requirement |
| --- | --- | --- |
| Git repositories, refs, reviews, branch policy, users, and release records | Authoritative | Database-consistent backup plus Git object verification and off-site mirror |
| Forgejo release objects | Authoritative published bytes | Versioned object storage, checksums, replication, and restore test |
| Hydra projects, jobsets, evaluations, build metadata, and logs | Operational evidence | PostgreSQL and log/object backup; retain release-relevant records |
| Nix build outputs | Usually reconstructible | Cache for availability; release-bound outputs retained by digest |
| Static site versions | Reconstructible publication history | Retain current and previous verified versions |
| Cache signing key | Trust anchor | Encrypted offline backup, documented rotation, and compromise procedure |
| Builder disks and scratch space | Disposable | Re-image from reviewed NixOS configuration |
| Signing receipts and provisioning audit | External authority | Must not depend on Forgejo, Hydra, or cache backup |

Backups are incomplete until restoration has been exercised into an isolated
environment. At least quarterly, restore Forgejo and Hydra metadata, verify Git
object connectivity, fetch a release asset by digest, substitute a protected
cache path, render a retained report, and demonstrate that no restored test
service can reach production credentials or devices.

Recovery order is:

1. identity, DNS, TLS, and object storage;
2. Forgejo and its database;
3. both Hydra domains, their databases, and read-only cache access;
4. clean builders;
5. cache promotion and report publication; and
6. release publication only after all earlier trust checks pass.

A CI outage blocks new releases but does not revoke or alter an existing
release. A cache outage may slow or block installations but must not cause a
device to accept an unsigned or unbound alternative.

## Monitoring and audit

Collect service and host metrics without placing secrets or private device
records in labels. Alert on:

- Forgejo authentication failures, administrative changes, protected-ref
  changes, mirror lag, and webhook backlog;
- Hydra evaluation delay, queue depth, job latency, failure rate, stale jobs,
  scheduler capacity, and database errors;
- builder reachability, architecture/feature capacity, disk pressure, Nix
  store growth, garbage collection, KVM availability, and unexpected egress;
- cache hit rate, upload failures, unsigned-path rejection, storage growth, and
  promoter failures;
- publication attempts, source/evaluation mismatches, digest failures, and
  rollback events;
- backup freshness, replication lag, restore-test age, certificate expiry, and
  credential-rotation age; and
- any denied path from a CI zone toward a production, signing, provisioning,
  or device network.

Audit records for protected operations include the authenticated actor or
service, request ID, exact source and tag objects, Hydra evaluation and build
IDs, derivation and output identities, artifact digests, policy version,
decision, and timestamp. Logs must not contain tokens, webhook secrets, private
keys, YubiKey authorization, private device evidence, or unpublished read
capabilities.

## Initial capacity profile

Capacity must be measured from the current workflows before purchasing
hardware. A reasonable first topology is:

- one small NixOS service VM for Forgejo and its database, with database and
  object data on separately backed-up volumes;
- separate NixOS CI-control VMs and stores for untrusted and protected Hydra,
  each with its own PostgreSQL database or database boundary;
- isolated untrusted x86_64/KVM and native ARM64 capacity when external pull
  requests are enabled;
- protected x86_64 builder capacity with hardware virtualization, enough
  memory for seven concurrent NixOS VMs, and a large replaceable `/nix` volume;
- protected native ARM64 capacity with sufficient disk for complete Pi image
  closures;
- one separately administered object-storage service or replicated appliance;
  and
- one small protected publication/verification host that executes no pull
  request code.

Do not size from repository checkout size. Record peak closure size, temporary
image space, VM memory, evaluator memory, build duration, cache transfer,
artifact growth, and restoration time for at least several complete cold and
warm runs. Keep enough free space for one full concurrent image build and a
failed build's diagnostics while garbage collection is paused.

## GitHub compatibility inventory

Migration is broader than moving Git objects and adding `hydraJobs`. The
following GitHub-specific behavior must be replaced, retained as a historical
dependency, or explicitly retired:

- `.github/workflows/ci.yml` and `.github/workflows/release.yml`, including
  their event, concurrency, dependency, permission, and environment semantics;
- immutable pins for GitHub Actions and the action-policy and Actionlint
  checks that inspect those workflow files;
- `GITHUB_TOKEN` permission scoping and the rule that credentials are not
  persisted by checkout;
- GitHub Actions artifact upload/download, cross-job handoff, retention, and
  failure-time collection behavior;
- GitHub Pages artifact assembly, environment approval, OIDC permission, and
  atomic deployment;
- `gh release` and Actions-runs API operations used by release validation and
  publication;
- server-reported GitHub asset IDs, states, sizes, and SHA-256 digests;
- the fixed GitHub repository, release, and asset identities in the
  `v0.1.15` recovery path;
- the current Cachix token, cache ownership check, public key, and rule that
  only protected-main jobs may publish reusable outputs;
- GitHub-hosted self-inputs in the root flake and lock files; and
- hard-coded GitHub release URLs that are already part of signed-image and
  recovery contracts.

An item does not disappear from this inventory just because an equivalent
Forgejo or Hydra feature has the same name. Parity requires a test of its
actual authorization, failure, retention, and readback semantics.

## Migration plan

Migration is additive until self-hosted results have demonstrated parity.

### Phase 0: freeze the contract

- Export the current required status checks, branch/tag protections, action
  pins, secrets inventory, Pages behavior, release permissions, artifact
  retention, cache key, and recovery workflow.
- Capture successful and intentionally failing reference runs for x86, ARM64,
  topology, report composition, Pages, and release validation.
- Define which results are byte-identical and which may differ only in
  transport metadata or timestamps.

### Phase 1: establish Forgejo as a recovery mirror

- Deploy Forgejo, PostgreSQL, TLS, backup, monitoring, and a read-only pull
  mirror from GitHub into Forgejo.
- Disable pushes and publication on the mirror.
- Restore it independently; verify that every ref resolves to the same commit
  or annotated-tag object ID and that every release attachment matches by
  name, size, and digest.
- Do not change flake URLs or the canonical developer remote yet.

### Phase 2: run Hydra in shadow mode

- Deploy trust-separated untrusted and protected Hydra controllers, stores,
  databases, and clean x86/ARM64 builders.
- Add the explicit protected-main `hydraJobs` graph and protected pull-request
  wrapper entry point.
- Add a machine-checked coverage manifest proving that every evaluated check
  from the root, provisioning, and DNS flakes is scheduled exactly once on
  both systems.
- Evaluate protected `main` revisions without reporting required statuses or
  publishing cache paths.
- Compare derivation paths, output digests, reports, test outcomes, durations,
  and failure evidence with GitHub Actions.

### Phase 3: add pull-request integration

- Enable authenticated Forgejo webhooks and the idempotent event bridge.
- Run exact-revision untrusted jobsets and report non-required statuses.
- Test force-push, close/reopen, duplicate delivery, stale delivery, bridge
  outage, Hydra outage, builder loss, and malicious job-name/ref inputs.
- Make statuses required only after reconciliation proves there are no
  success-attribution races.

### Phase 4: introduce the self-hosted cache and reports

- Populate pull-request scratch and protected staging separately first.
- Exercise protected-main promotion and verify that pull requests cannot write
  protected staging, be substituted into protected builds, or promote.
- Publish a non-canonical preview of the project site from an exact Hydra
  result.
- Verify manifests, atomic replacement, rollback, public content, retention,
  and cache-key recovery before changing the canonical URLs.

### Phase 5: rehearse releases without publishing

- Reproduce tag, main-ancestry, successful-source-CI, archive digest, media
  digest, size, exact file shape, remote asset readback, and native-ARM
  verification using existing immutable release fixtures.
- Require successful protected-main CI for both the release source revision
  and the revision that supplies the release-control implementation.
- Use separate fetch, verify, and publish identities and storage prefixes.
- Demonstrate that the rehearsal cannot sign, rebuild, change a tag, choose a
  different draft, select a different asset, or reach a device.
- Compare the proposed publication payload byte-for-byte with the existing
  release assets.

### Phase 6: change the canonical forge

- Schedule a short write freeze and final bidirectional object comparison.
- Make Forgejo canonical, update developer remotes and repository policy, and
  leave GitHub as a read-only outbound mirror during the rollback window.
- Change source and release URLs only through reviewed commits that preserve
  immutable object and digest bindings.
- Keep the GitHub workflows available but non-publishing until at least one
  ordinary release and one restore exercise complete successfully.

### Phase 7: retire redundant authority

- Revoke GitHub Actions cache and release credentials.
- Remove obsolete webhook keys and runner registrations.
- Preserve required GitHub release assets and redirects for already published
  immutable contracts.
- Record the final trust inventory, backup locations, recovery owners, and key
  rotation dates.

Fleet rollout remains a separate milestone after this migration. A working
self-hosted CI system is not evidence that production update safety is solved.

## Acceptance criteria

The self-hosted environment is not canonical until all of these hold:

- a clean clone can evaluate the root and both leaf flakes with the required
  Nix version;
- release-sensitive outputs reject a dirty or unknown source revision;
- a protected, machine-checked coverage manifest proves that every evaluated
  check attribute in the root, provisioning, and DNS flakes is enumerated and
  scheduled exactly once as a required job for both systems, with no
  unreviewed exclusions;
- required x86 and native ARM64 jobs run on the declared architectures;
- the seven-VM topology uses KVM when scheduled on the KVM class and its slower
  fallback is visible rather than misreported;
- cross-architecture report composition rejects a source-revision or digest
  mismatch;
- diagnostic reports remain available when an independent functional or
  security gate fails, and canonical per-run reports retain at least the
  current 14-day history;
- pull-request evaluation has no protected-cache, publication, release,
  signing, deployment, provisioning, DNS-control, or device credential;
- only an accepted, still-current protected-main evaluation can promote cache
  paths or the public report;
- the homepage, `reports/latest/`, and provisioning demo publish atomically as
  one validated tree;
- a stable release uses the exact annotated tag, source commit, pre-staged
  image, archive digest, media digest, and size and is verified natively on
  ARM64;
- the release verifier has no publication credential and the publisher cannot
  substitute a rebuilt asset;
- release publication also requires successful protected-main CI for the
  release-control implementation revision and reads back remote state after
  mutation;
- no CI component contains or can reach a boot/software-signing private key,
  YubiKey authorization secret, device private key, or provisioning mutation
  authority;
- branch and tag protection, individual authentication, service credential
  scope, and administrative audit have been tested;
- the recovery mirror preserves every Git ref's commit or annotated-tag object
  ID and every release attachment's name, size, and digest;
- negative tests reject spoofed and replayed webhooks, stale or foreign commit
  statuses, tag movement, unexpected or symbolic-link artifacts, wrong
  archive/media digests, and concurrent publication races;
- Forgejo, Hydra metadata, object storage, and the cache trust anchor have
  current backups and a successful isolated restoration;
- losing one builder, the cache, Hydra, or Forgejo fails closed and does not
  alter an already published release; and
- the GitHub fallback can be re-enabled during the migration rollback window
  without allowing two concurrent publishers.

## Open decisions

The implementation proposal must resolve these before Phase 3:

- whether the CI event bridge is a small dedicated service, restricted
  Woodpecker deployment, or restricted Forgejo Actions deployment;
- the exact Forgejo and Hydra versions and upgrade cadence;
- whether PostgreSQL is shared at the cluster level or isolated per service;
- Attic versus a conventional S3/HTTP Nix cache and the cache key-rotation
  process;
- object-storage implementation, replication target, immutability controls,
  quotas, and retention;
- whether external pull requests are accepted and therefore require a fully
  disposable untrusted builder pool;
- the trusted upstream URI and egress allowlists needed by all three flakes;
- how Forgejo protected environments or an external approval service authorize
  report and release publication;
- the canonical public URLs for Git, reports, release assets, and the Nix
  cache;
- the period for keeping GitHub as a read-only mirror and release-asset origin;
  and
- recovery objectives, on-call ownership, maintenance windows, and hardware
  capacity based on measured cold builds.

## Upstream references

- [Hydra repository and installation overview](https://github.com/NixOS/hydra)
- [Nix `hydraJobs` evaluation contract](https://github.com/NixOS/nix/blob/master/src/nix/flake-check.md)
- [Hydra API](https://github.com/NixOS/hydra/blob/master/hydra-api.yaml)
- [Hydra Gitea webhook behavior](https://github.com/NixOS/hydra/blob/9388ff6d526fe865efaae9dbf8506a5b7fba91ed/subprojects/hydra-manual/src/webhooks.md#L74-L88)
- [Hydra Gitea status plugin](https://github.com/NixOS/hydra/blob/9388ff6d526fe865efaae9dbf8506a5b7fba91ed/subprojects/hydra/lib/Hydra/Plugin/GiteaStatus.pm#L32-L93)
- [Current upstream Hydra queue-runner architecture](https://github.com/NixOS/hydra/blob/9388ff6d526fe865efaae9dbf8506a5b7fba91ed/subprojects/hydra-manual/src/architecture.md#L6-L57)
- [Hydra package at this repository's exact root Nixpkgs pin](https://github.com/NixOS/nixpkgs/blob/70ce234312134a463ba7728e94da2486a1d237ac/pkgs/by-name/hy/hydra/package.nix)
- [NixOS 26.05 Hydra package snapshot (`0-unstable-2026-03-13`)](https://github.com/NixOS/nixpkgs/blob/6713828a351efa628b025a1adf7f43cbf8597513/pkgs/by-name/hy/hydra/package.nix#L133-L143)
- [Nix distributed builds](https://nix.dev/tutorials/nixos/distributed-builds-setup.html)
- [Forgejo branch and tag protection](https://forgejo.org/docs/latest/user/repository/protection/)
- [Forgejo storage settings](https://forgejo.org/docs/latest/admin/setup/storage/)
- [Forgejo repository mirrors](https://forgejo.org/docs/latest/user/repo-mirror/)
- [Forgejo Actions overview and compatibility statement](https://forgejo.org/docs/latest/user/actions/overview/)
- [Forgejo Actions security model](https://forgejo.org/docs/latest/user/actions/security/)
- [Woodpecker supported agent platforms](https://woodpecker-ci.org/docs/next/administration/installation/supported-platforms)
- [Attic self-hosted Nix binary cache](https://github.com/zhaofengli/attic)
- [`deploy-rs`](https://github.com/serokell/deploy-rs)
- [Colmena](https://github.com/nix-community/colmena)
