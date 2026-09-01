# Ubuntu development signing ceremony for Raspberry Pi 5

This runbook completes the public, approval-gated signing ceremony for the
sacrificial Raspberry Pi 5 development profile on an Ubuntu 24.04 control
host. For each of five grants it creates one YubiKey-backed artifact signature
and one YubiKey-backed, domain-separated canonical receipt-attestation
signature. It then verifies all five v1alpha3 gate receipts and assembles one
verified release with exactly 18 artifact roles.

This is not a production ceremony. The checked-in signer is classified
`development-sacrificial`, is explicitly not production-approved, and retains
the documented development JTAG and boot-order posture. This runbook does not
write an NVMe device, boot a Raspberry Pi, run `rpiboot`, change EEPROM or OTP,
or otherwise mutate a target board. The failure-free path requires a minimum
of ten explicit private-key operations on the reviewed development YubiKey:
five artifact signatures and five receipt-attestation signatures. Ten is not
an upper bound if an attempt fails before its durable receipt is complete.

All commands below are templates for a **new post-merge annotated tag, clean
revision, and public release review**. Do not substitute `v0.1.3`: that tag
predates the integrated approval, receipt, Ubuntu deployment, and final release
path and cannot be reused. Run this only after these changes are merged, the
new main pipeline and release have passed, and the new tag and commit have been
recorded independently.

Automated tests for this workflow are software-only. Run tests with the token
removed; never add `ykman`, PC/SC enumeration, PKCS#11 signing, a PIN prompt, or
a token operation to a test command. The five live artifact requests below are
ceremony actions, not tests; each first-attempt completion invokes two ordered
token operations and therefore requires at least two touches.

## Roles and invariants

Use separate people or independently controlled accounts for these roles:

- the release preparer builds and inspects the public unsigned inputs;
- an independent reviewer authors the exact release approval and five grants;
- the signing operator installs the reviewed registry and performs at least ten
  token touches on a failure-free path, two for each first-attempt grant
  completion;
- an offline verifier checks the handoff and assembles the release.

For each v1alpha2 grant and request, the gate first signs the artifact digest
without changing the artifact-signature format. It then derives the receipt
metadata inside the gate and signs the exact domain-separated canonical
attestation bytes. No client supplies attestation fields. The gate returns a
v1alpha3 wire response with the resulting v1alpha3 receipt digest. Receipt
export and independent receipt-verification records use v1alpha2.

The independent signer review in
[`provisioning/signers/development-prototype`](../provisioning/signers/development-prototype/)
may be reused only while the exact token, slot, key, public-key fingerprint,
signer/cohort identity, and signer policy remain unchanged. The release
approval is never reusable: it binds one exact release intent and source
revision, and its grants expire no more than 24 hours after approval. A new
release, changed input, expired window, or changed signer posture requires the
corresponding new review work. Never edit an approval or registry to extend its
expiry.

The v1alpha1 approval is not cryptographically signed by the reviewer.
`reviewer_id` is attribution, and separation of duties is procedural and
out-of-band: the signing-host root/operator remains trusted and could install a
different registry. This is not production-grade cryptographic reviewer
authentication. The independently communicated approval and registry hashes
required below are therefore part of the authorization check, not an optional
transport convenience.

Every live signing output directory named below must be absent before its
authority-bearing command runs. The public-only helper may reopen an exact
completed phase only after re-evaluating its fixed Nix output and immutable
evidence; that is not permission to replay a signing request. Never retry a
completed signing operation merely because its terminal output was lost. On an
error or ambiguous result, stop the gate, preserve its durable
state and all outputs, remove the PIN source, and review the evidence before
deciding how to proceed. A retained incomplete intent permanently blocks that
grant from invoking the backend again; the gate has no same-grant retry path.
Recovery requires a new independently reviewed authorization and ceremony
attempt rather than an operator retry command. That authorization has new
approval and grant identities: sign all five release inputs again and never mix
old completed receipts with the new registry. The documented operation and
touch counts are successful-path minima, never an upper bound or permission to
repeat a request.

## Public-only ceremony automation

The root flake packages `kaiba-provision-signing-ceremony`, a resumable helper
for the deterministic transcript plumbing in this runbook. After pinning the
release in step 1, choose either the automated or manual branch in step 2; do
not mix their directory-initialization commands. `prepare-public` builds and
checks the public inputs without fetching, switching, or inferring the expected
commit. Later subcommands validate transferred authorization, derive the public
owned-recovery plan, authenticate the handoff and receipts, and assemble the
release. Each phase publishes fixed, private-mode evidence atomically without
replacing a different prior result. Assembly re-authenticates the exact handoff
against the previously verified immutable Nix-store snapshot before importing
the five factory inputs. An assembly failure records
`failed_preserve_evidence` and explicitly forbids repeating any signing
request.

Each account or host must run `prepare-public` into its own role-local 0700
ceremony directory. Do not copy or share a helper session: it binds the current
UID-owned directory, absolute checkout path, exact commit, and `git+file:`
reference. Transfer only the approval packet, live-result handoff, and
independently communicated digests called out below. The helper's versioned JSON
files are private orchestration state, not new cross-host interchange formats.
Keep the ceremony directory intact through final publication: indirect Nix GC
roots beneath `gc-roots/` retain the exact authorization and handoff snapshots
across human pauses and are revalidated on resume.

The helper deliberately has no approval-authoring, registry-installation,
`sudo`, service-control, PIN, PC/SC, PKCS#11, YubiKey, signing, transfer, retry,
or hardware operation. It always stops at the human boundaries in the role
model above. The detailed commands below remain the auditable reference and
the required path for those manual boundaries.

## 1. Pin the new release everywhere

Perform this check independently on each checkout used by the preparer,
reviewer, signing operator, and offline verifier. Replace the two quoted
values. `EXPECTED_COMMIT` must come from the approved, green post-merge release,
not from the local tag lookup alone.

```console
set -euo pipefail
umask 077

RELEASE_TAG='vREPLACE_WITH_NEW_POST_MERGE_TAG'
EXPECTED_COMMIT='REPLACE_WITH_40_HEX_POST_MERGE_COMMIT'

test "$RELEASE_TAG" != v0.1.3
test "${#EXPECTED_COMMIT}" -eq 40
test -z "${EXPECTED_COMMIT//[0-9a-f]/}"

git fetch upstream main --tags
test "$(git cat-file -t "refs/tags/$RELEASE_TAG")" = tag
test "$(git rev-parse "${RELEASE_TAG}^{commit}")" = "$EXPECTED_COMMIT"
git merge-base --is-ancestor "$EXPECTED_COMMIT" upstream/main

git switch --detach "$RELEASE_TAG"
test "$(git rev-parse HEAD)" = "$EXPECTED_COMMIT"
test -z "$(git status --porcelain=v1 --untracked-files=all)"

REPOSITORY_ROOT="$(pwd -P)"
KAIBA_FLAKE_REF="git+file:$REPOSITORY_ROOT?rev=$EXPECTED_COMMIT"
```

Revision-sensitive builds below deliberately use `git+file:`, not `path:.`.
Keep the checkout clean and use the same `KAIBA_FLAKE_REF` throughout.

Choose a private evidence directory outside the repository and replace this
example path before continuing. Leave it absent until selecting the automated
or manual branch in step 2:

```console
CEREMONY_DIR="/absolute/private/path/$RELEASE_TAG-signing-ceremony"
case "$CEREMONY_DIR" in /*) ;; *) exit 1 ;; esac
test ! -e "$CEREMONY_DIR"
```

## 2. Build and review the public inputs

These builds do not access a token, PIN, smartcard reader, block device, or
target hardware. An x86_64 host needs an AArch64 builder or emulation for the
unsigned target artifacts.

Choose exactly one branch.

### 2A. Automated public preparation

Build the helper from the exact pinned flake, not from ambient `PATH`, and let
it create the still-absent ceremony directory:

```console
CEREMONY_TOOL="$(
  nix --accept-flake-config build \
    "$KAIBA_FLAKE_REF#kaiba-provision-signing-ceremony" \
    --no-link --print-out-paths
)"
test -x "$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony"

"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" prepare-public \
  --repository "$REPOSITORY_ROOT" \
  --release-tag "$RELEASE_TAG" \
  --expected-commit "$EXPECTED_COMMIT" \
  --main-ref upstream/main \
  --ceremony-dir "$CEREMONY_DIR"
```

Review the emitted immutable inventory and the files named by it. Then skip the
manual build block below and continue at “Resolve every result link.” Keep
`CEREMONY_TOOL` for the later automated phase commands shown at the applicable
boundaries. Repeat steps 1 and 2A separately under every reviewer, signing, or
offline-verifier account that will use a later helper phase.

### 2B. Manual public preparation

Create the directory only when taking the manual branch:

```console
install -d -m 0700 "$CEREMONY_DIR"
install -d -m 0700 "$CEREMONY_DIR/public"
```

A manual session has no helper inventory or phase state. Continue with the
manual alternative at every later boundary; do not invoke a later helper phase
against this directory.

```console
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#packages.aarch64-linux.rpi5-prototype-unsigned-artifacts" \
  --out-link "$CEREMONY_DIR/public/unsigned-artifacts"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#rpi5-prototype-release-intent" \
  --out-link "$CEREMONY_DIR/public/release-intent"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#rpi5-prototype-signing-plan" \
  --out-link "$CEREMONY_DIR/public/boot-signing-plan"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#rpi5-prototype-eeprom-signing-plan" \
  --out-link "$CEREMONY_DIR/public/eeprom-signing-plan"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#rpi5-prototype-release-review" \
  --out-link "$CEREMONY_DIR/public/release-review"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#development-signing" \
  --out-link "$CEREMONY_DIR/public/development-signing"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#ubuntu-signing-gate-deployment" \
  --out-link "$CEREMONY_DIR/public/ubuntu-signing-gate-deployment"
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#kaiba-provision-signing-approval" \
  --out-link "$CEREMONY_DIR/public/signing-approval-tool"
```

Resolve every result link before using it in a live command:

```console
UNSIGNED_ARTIFACTS="$(readlink -e "$CEREMONY_DIR/public/unsigned-artifacts")"
RELEASE_INTENT="$(readlink -e "$CEREMONY_DIR/public/release-intent")"
BOOT_PLAN="$(readlink -e "$CEREMONY_DIR/public/boot-signing-plan")"
EEPROM_PLAN="$(readlink -e "$CEREMONY_DIR/public/eeprom-signing-plan")"
RELEASE_REVIEW="$(readlink -e "$CEREMONY_DIR/public/release-review")"
SIGNING_PACKAGE="$(readlink -e "$CEREMONY_DIR/public/development-signing")"
DEPLOYMENT="$(readlink -e "$CEREMONY_DIR/public/ubuntu-signing-gate-deployment")"
APPROVAL_TOOL="$(readlink -e "$CEREMONY_DIR/public/signing-approval-tool")"

nix-store --query --hash "$SIGNING_PACKAGE"
nix-store --verify-path "$SIGNING_PACKAGE"
nix-store --query --hash "$DEPLOYMENT"
nix-store --verify-path "$DEPLOYMENT"

jq -e --arg revision "$EXPECTED_COMMIT" '
  .status == "passed"
  and .source_revision == $revision
  and .scope == "public-unsigned-prototype"
  and .hardware_access == false
  and .mutation_capable == false
  and .one_time_setting_capable == false
  and .private_key_access == false
' "$RELEASE_REVIEW/review.json" >/dev/null

jq -e --arg revision "$EXPECTED_COMMIT" '
  .source_revision == $revision
  and .authorization_scope == "cohort_release"
  and (.signing_inputs | length == 5)
  and (.required_output_roles | length == 18)
' "$RELEASE_INTENT/release-intent.json" >/dev/null

cmp "$UNSIGNED_ARTIFACTS/unsigned/boot.img" "$BOOT_PLAN/boot.img"
cmp "$RELEASE_INTENT/release-intent.json" "$BOOT_PLAN/release-intent.json"
cmp "$RELEASE_INTENT/release-intent.json" "$EEPROM_PLAN/release-intent.json"
```

Inspect `review.json`, the release intent, both plans, the signer policy, and
the reviewed public-key fingerprint before proceeding. The detailed public
checks are described in
[`raspberry-pi-5-signed-boot-workflow.md`](raspberry-pi-5-signed-boot-workflow.md).

## 3. Install the inert Ubuntu 24.04 gate

On the dedicated Ubuntu 24.04 signing host, install the required host packages:

```console
sudo apt-get update
sudo apt-get install acl jq libccid pcscd polkitd
```

Install the deployment bundle against the exact configured signing package:

```console
sudo "$DEPLOYMENT/share/kaiba/ubuntu-signing-gate/install.sh" \
  --package "$SIGNING_PACKAGE"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static

test "$(systemctl show \
  --property=ActiveState \
  --value kaiba-provision-signing-gate.service)" = inactive
```

The installer creates the locked `kaiba-signing` service identity, host
policy, private state and runtime boundaries, and direct Nix GC roots for both
the signing package and deployment bundle. It does
not enable or start the gate, activate PC/SC, read a PIN, enumerate a token, or
submit a request. See the installed deployment documentation or
[`deploy/ubuntu-signing-gate/README.md`](../deploy/ubuntu-signing-gate/README.md)
for the exact file and permission boundary.

## 4. Have the independent reviewer author the approval

Do this only after all public builds and human review are complete, so the
grant window is not consumed by build time. The reviewer should independently
build the exact tagged release intent, release review, and approval tool as in
steps 1 and 2. They must compare the expected commit and public review through
an authenticated channel before approving.

The approval tool derives every role, digest, and size from the canonical
release intent. It does not accept caller-selected roles or digests and emits
exactly five grants. Set a canonical lower-case reviewer identity. The maximum
lifetime is 86,400 seconds (24 hours); choose less if the ceremony can finish
comfortably within a shorter window. Confirm the reviewer and signing host
clocks against the ceremony's trusted time source before recording approval;
the authoring command rejects a future or already-expired window according to
its host clock, and the gate and offline verifier enforce the recorded expiry.

```console
REVIEWER_ID='reviewer:replace-with-reviewed-identity'
GRANT_LIFETIME_SECONDS=86400
test "$GRANT_LIFETIME_SECONDS" -ge 1
test "$GRANT_LIFETIME_SECONDS" -le 86400

APPROVED_EPOCH="$(date --utc +%s)"
APPROVED_AT="$(date --utc --date="@$APPROVED_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
EXPIRES_AT="$(date --utc \
  --date="@$((APPROVED_EPOCH + GRANT_LIFETIME_SECONDS))" \
  +%Y-%m-%dT%H:%M:%SZ)"

AUTHORIZATION_DIR="$CEREMONY_DIR/reviewer-authorization"
test ! -e "$AUTHORIZATION_DIR"

"$APPROVAL_TOOL/bin/kaiba-provision-signing-approval" author \
  --release-intent "$RELEASE_INTENT/release-intent.json" \
  --reviewer-id "$REVIEWER_ID" \
  --approved-at "$APPROVED_AT" \
  --expires-at "$EXPIRES_AT" \
  --output "$AUTHORIZATION_DIR"

"$APPROVAL_TOOL/bin/kaiba-provision-signing-approval" validate \
  --release-intent "$RELEASE_INTENT/release-intent.json" \
  --approval "$AUTHORIZATION_DIR/approval.json" \
  --registry "$AUTHORIZATION_DIR/signing-grants.json"

jq -e '
  .decision == "approved"
  and (.signing_inputs | length == 5)
' "$AUTHORIZATION_DIR/approval.json" >/dev/null
jq -e '
  .schema_version == "kaiba.provisioning.signing-grant-registry/v1alpha2"
  and (.grants | length == 5)
' "$AUTHORIZATION_DIR/signing-grants.json" >/dev/null

(
  cd "$AUTHORIZATION_DIR"
  sha256sum approval.json signing-grants.json > SHA256SUMS
)
chmod 0600 "$AUTHORIZATION_DIR/SHA256SUMS"
cat "$AUTHORIZATION_DIR/SHA256SUMS"
```

The approval, registry, and checksums contain no PIN or private key, but they
are authority-bearing public records. Transfer them to the signing operator
through an authenticated channel or controlled removable medium. Communicate
the two SHA-256 values independently of that transfer. A content digest detects
change; the trusted channel is what authenticates the reviewer.

On the signing host, copy the received directory to a private, new path, then
verify it again against the locally rebuilt tagged release intent. Set the two
expected hashes from the values delivered through the separate authenticated
channel, not from the transferred `SHA256SUMS` file:

```console
RECEIVED_AUTHORIZATION=/absolute/private/path/received-reviewer-authorization
case "$RECEIVED_AUTHORIZATION" in /*) ;; *) exit 1 ;; esac
EXPECTED_APPROVAL_SHA256='REPLACE_WITH_INDEPENDENTLY_RECEIVED_64_HEX_DIGEST'
EXPECTED_REGISTRY_SHA256='REPLACE_WITH_INDEPENDENTLY_RECEIVED_64_HEX_DIGEST'

test "${#EXPECTED_APPROVAL_SHA256}" -eq 64
test -z "${EXPECTED_APPROVAL_SHA256//[0-9a-f]/}"
test "${#EXPECTED_REGISTRY_SHA256}" -eq 64
test -z "${EXPECTED_REGISTRY_SHA256//[0-9a-f]/}"

(
  cd "$RECEIVED_AUTHORIZATION"
  sha256sum --check SHA256SUMS
)
test "$(sha256sum "$RECEIVED_AUTHORIZATION/approval.json" \
  | cut -d ' ' -f 1)" = "$EXPECTED_APPROVAL_SHA256"
test "$(sha256sum "$RECEIVED_AUTHORIZATION/signing-grants.json" \
  | cut -d ' ' -f 1)" = "$EXPECTED_REGISTRY_SHA256"

"$APPROVAL_TOOL/bin/kaiba-provision-signing-approval" validate \
  --release-intent "$RELEASE_INTENT/release-intent.json" \
  --approval "$RECEIVED_AUTHORIZATION/approval.json" \
  --registry "$RECEIVED_AUTHORIZATION/signing-grants.json"

VALIDATED_AUTHORIZATION="$RECEIVED_AUTHORIZATION"
VALIDATED_APPROVAL="$VALIDATED_AUTHORIZATION/approval.json"
VALIDATED_REGISTRY="$VALIDATED_AUTHORIZATION/signing-grants.json"
```

When this signing-host account used automated preparation, replace the manual
verification block above with this phase. It snapshots the exact three-file
packet into the Nix store before validating it, so later root installation must
use the recorded snapshot rather than the mutable transfer directory:

```console
"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" verify-authorization \
  --ceremony-dir "$CEREMONY_DIR" \
  --received-authorization "$RECEIVED_AUTHORIZATION" \
  --expected-approval-sha256 "$EXPECTED_APPROVAL_SHA256" \
  --expected-registry-sha256 "$EXPECTED_REGISTRY_SHA256"

AUTHORIZATION_EVIDENCE="$CEREMONY_DIR/authorization-verification.json"
VALIDATED_AUTHORIZATION="$(jq --exit-status --raw-output \
  '.authorization_store' "$AUTHORIZATION_EVIDENCE")"
test "$(readlink -e "$(jq --exit-status --raw-output \
  '.authorization_gc_root' "$AUTHORIZATION_EVIDENCE")")" = \
  "$VALIDATED_AUTHORIZATION"
test "$(nix-store --query --hash "$VALIDATED_AUTHORIZATION")" = \
  "$(jq --exit-status --raw-output \
    '.authorization_store_nar_hash' "$AUTHORIZATION_EVIDENCE")"
VALIDATED_APPROVAL="$VALIDATED_AUTHORIZATION/approval.json"
VALIDATED_REGISTRY="$VALIDATED_AUTHORIZATION/signing-grants.json"
```

Do not proceed unless enough of the single approval window remains to finish
all five requests and their minimum ten token touches, including the phase-two
Nix verification between the fourth and fifth request. Reserve additional time
for fail-stop review; do not use that margin as advance authorization to retry.

## 5. Install the root-managed registry and provision the PIN

The gate must be inactive while authority changes. Do not overwrite an old
registry. If one exists, stop here and archive or retire it under separate
review before installing this release's registry.

```console
test "$(systemctl show \
  --property=ActiveState \
  --value kaiba-provision-signing-gate.service)" = inactive

RECEIVED_APPROVED_AT="$(jq --exit-status --raw-output \
  '.approved_at' "$VALIDATED_APPROVAL")"
RECEIVED_EXPIRES_AT="$(jq --exit-status --raw-output \
  '.expires_at' "$VALIDATED_APPROVAL")"
SIGNING_HOST_NOW="$(date --utc +%s)"
test "$SIGNING_HOST_NOW" -ge \
  "$(date --utc --date="$RECEIVED_APPROVED_AT" +%s)"
test "$SIGNING_HOST_NOW" -lt \
  "$(date --utc --date="$RECEIVED_EXPIRES_AT" +%s)"

sudo test ! -e /etc/kaiba-provisioning/signing-grants.json

sudo install -o root -g kaiba-signing -m 0440 \
  "$VALIDATED_REGISTRY" \
  /etc/kaiba-provisioning/signing-grants.json
sudo setfacl --remove-all -- \
  /etc/kaiba-provisioning/signing-grants.json
sudo cmp \
  "$VALIDATED_REGISTRY" \
  /etc/kaiba-provisioning/signing-grants.json
sudo stat --format='%U:%G:%a %n' \
  /etc/kaiba-provisioning/signing-grants.json

sudo systemctl enable --now pcscd.socket
sudo swapoff --all
swap_state="$(swapon --show --noheadings)"
test -z "$swap_state"
sudo /usr/local/sbin/kaiba-signing-gate-provision-pin
sudo /usr/local/sbin/kaiba-signing-gate-preflight
```

The PIN helper prompts twice on the controlling terminal without echo. It
refuses an active gate or active swap, then creates only the fixed root-owned
`0400` source under `/run`, which must be tmpfs. Never put the PIN in an
environment variable, command argument, pipe, shell history, persistent file,
log, Nix expression, or Nix store path.

Insert the reviewed development YubiKey only for the live part of the
ceremony, then recheck the signing-host authorization window immediately
before starting the gate. The current approval format has no `not_before`
field; this explicit lower-bound check prevents a signing-host clock behind
`approved_at` from silently weakening the procedural review boundary.

```console
SIGNING_HOST_NOW="$(date --utc +%s)"
test "$SIGNING_HOST_NOW" -ge \
  "$(date --utc --date="$RECEIVED_APPROVED_AT" +%s)"
test "$SIGNING_HOST_NOW" -lt \
  "$(date --utc --date="$RECEIVED_EXPIRES_AT" +%s)"

sudo systemctl start kaiba-provision-signing-gate.service
sudo /usr/local/sbin/kaiba-signing-gate-preflight
```

Starting the service validates its immutable configuration, registry, state,
credential, and private socket. It does not sign anything. Because the runtime
directory and socket are service-private, invoke the live adapters as the
locked `kaiba-signing` identity exactly as shown below; do not change socket
permissions or add a human to the service group.

## 6. Phase one: boot and fresh-EEPROM signatures and receipt attestations

Create a private service-owned ceremony directory outside the gate's durable
state. The deployment fixes the parent export path and its mode.

```console
LIVE_ROOT="/var/lib/kaiba-provision-signing-exports/$RELEASE_TAG-live"
sudo test ! -e "$LIVE_ROOT"
sudo install -d -o kaiba-signing -g kaiba-signing -m 0700 "$LIVE_ROOT"

test "$(sudo sed -n 's/^PACKAGE_PATH=//p' \
  /etc/kaiba-provisioning/signing-gate-deployment.conf)" = "$SIGNING_PACKAGE"
```

Artifact request 1 signs the reviewed boot image, then signs its derived
canonical receipt attestation. A successful first attempt requires at least
two touches in that order:

```console
sudo -u kaiba-signing -- \
  "$SIGNING_PACKAGE/bin/kaiba-provision-sign-boot" sign \
  --plan "$BOOT_PLAN" \
  --output "$LIVE_ROOT/boot-signed"
```

Artifact requests 2 through 4 sign the three fresh-board EEPROM inputs in the
fixed plan order: bootcode, bootsys, and configuration. Each artifact signature
is followed by its receipt-attestation signature, so successful first attempts
require at least six touches.
Despite its name, this command operates on files and the signing gate; it does
not open, inspect, or program a physical EEPROM device.

```console
sudo -u kaiba-signing -- \
  "$SIGNING_PACKAGE/bin/kaiba-provision-sign-eeprom" sign \
  --plan "$EEPROM_PLAN" \
  --output "$LIVE_ROOT/eeprom-signed"
```

Do not rerun either command. Verify only the expected result records appeared:

```console
sudo -u kaiba-signing -- test -f \
  "$LIVE_ROOT/boot-signed/signing-result.json"
sudo -u kaiba-signing -- test -f \
  "$LIVE_ROOT/eeprom-signed/result.json"
sudo -u kaiba-signing -- jq -e \
  '.signatures | length == 3' \
  "$LIVE_ROOT/eeprom-signed/result.json" >/dev/null
```

## 7. Derive the owned-recovery plan, then perform artifact request 5

The fifth input is not signed from the original EEPROM plan. First import the
fresh EEPROM result into the Nix store and let the exact tagged factory verify
it and derive the owned-recovery plan. This phase-transition build is public,
offline verification; it does not submit a gate request or touch the token.

```console
EEPROM_SIGNED_STORE="$(
  sudo /nix/var/nix/profiles/default/bin/nix store add-path \
    "$LIVE_ROOT/eeprom-signed"
)"
test -n "$EEPROM_SIGNED_STORE"
```

For an automated session, derive and review the exact public phase transition
with:

```console
"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" derive-owned-recovery \
  --ceremony-dir "$CEREMONY_DIR" \
  --eeprom-signed-store "$EEPROM_SIGNED_STORE"
OWNED_RECOVERY_PLAN="$(readlink -e \
  "$CEREMONY_DIR/public/owned-recovery-plan")"
```

Otherwise, use the manual factory call:

```console

OWNED_RECOVERY_PLAN="$(
  nix --accept-flake-config build -L \
    --impure \
    --out-link "$CEREMONY_DIR/public/owned-recovery-plan" \
    --print-out-paths \
    --expr "
      let
        kaiba = builtins.getFlake \"$KAIBA_FLAKE_REF\";
      in
      (kaiba.lib.mkRpi5PrototypeOwnedRecoveryPlan {
        eepromSignedOutput = builtins.storePath \"$EEPROM_SIGNED_STORE\";
      }).ownedRecoverySigningPlan
    "
)"
test -d "$OWNED_RECOVERY_PLAN"
test -f "$OWNED_RECOVERY_PLAN/plan.json"
```

Inspect the derived plan and confirm it extends the exact fresh EEPROM plan
and has one remaining role, `rpi5.owned_recovery_bootcode`. Artifact request 5
then signs that one new input and its derived receipt attestation. A successful
first attempt requires at least two touches:

```console
jq . "$OWNED_RECOVERY_PLAN/plan.json"

sudo -u kaiba-signing -- \
  "$SIGNING_PACKAGE/bin/kaiba-provision-sign-eeprom" sign-owned-recovery \
  --plan "$OWNED_RECOVERY_PLAN" \
  --output "$LIVE_ROOT/owned-recovery-signed"

sudo -u kaiba-signing -- test -f \
  "$LIVE_ROOT/owned-recovery-signed/result.json"
```

The owned-recovery adapter makes one new gate request. It reuses the three
already verified fresh-EEPROM signatures when replaying the pinned `-fr`
updater. The reused artifacts are not submitted as new gate requests, so this
phase does not intentionally create three additional artifact signatures or
three additional receipt attestations. The one new grant still has a minimum
of two touches on a successful first attempt. An incomplete intent blocks that
grant; only a new independently approved ceremony attempt may add more token
operations.

## 8. Capture and export all five authenticated receipts

First capture the five receipt digests directly from the three live result
records. This file is independent input to receipt verification; do not derive
it from the later export.

```console
RESULT_RECEIPT_DIGESTS="$CEREMONY_DIR/live-result-receipt-digests.txt"
test ! -e "$RESULT_RECEIPT_DIGESTS"

{
  sudo -u kaiba-signing -- jq --exit-status --raw-output \
    '.gate_receipt_digest | select(type == "string")' \
    "$LIVE_ROOT/boot-signed/signing-result.json"
  sudo -u kaiba-signing -- jq --exit-status --raw-output '
    .signatures
    | if length == 3 then .[].gate_receipt_digest
      else error("expected exactly three EEPROM receipts")
      end
  ' "$LIVE_ROOT/eeprom-signed/result.json"
  sudo -u kaiba-signing -- jq --exit-status --raw-output \
    '.signature.gate_receipt_digest | select(type == "string")' \
    "$LIVE_ROOT/owned-recovery-signed/result.json"
} > "$RESULT_RECEIPT_DIGESTS"

chmod 0600 "$RESULT_RECEIPT_DIGESTS"
test "$(wc -l < "$RESULT_RECEIPT_DIGESTS")" -eq 5
test "$(sort -u "$RESULT_RECEIPT_DIGESTS" | wc -l)" -eq 5
```

Export the complete gate state as `kaiba-signing`. The output must be a new
file in the fixed service-owned export directory, never inside
`/var/lib/kaiba-provision-signing`:

```console
RECEIPT_EXPORT="$LIVE_ROOT/signing-receipts.json"
sudo -u kaiba-signing -- test ! -e "$RECEIPT_EXPORT"

sudo -u kaiba-signing -- \
  "$SIGNING_PACKAGE/bin/kaiba-provision-signing-receipts" export \
  --registry /etc/kaiba-provisioning/signing-grants.json \
  --state-directory /var/lib/kaiba-provision-signing \
  --public-key "$BOOT_PLAN/public.pem" \
  --output "$RECEIPT_EXPORT"

sudo -u kaiba-signing -- jq -e '
  .schema_version == "kaiba.provisioning.signing-gate-receipt-export/v1alpha2"
  and (.receipts | length == 5)
  and all(.receipts[];
    .receipt.schema_version ==
      "kaiba.provisioning.signing-gate-receipt/v1alpha3")
' "$RECEIPT_EXPORT" >/dev/null
```

The exporter requires the root-owned registry, service-owned `0700` state,
all five completed grant records, and the reviewed public key. It verifies the
receipt digests, each artifact RSA signature, and each domain-separated
canonical receipt-attestation RSA signature before publishing the canonical
v1alpha2 export containing v1alpha3 receipts.

## 9. Stop the gate and remove the PIN source

No further private-key operation is required. Close the live boundary before
copying or verifying public outputs:

```console
sudo systemctl stop kaiba-provision-signing-gate.service
sudo rm -f -- /run/kaiba-provision-signing-credentials/yubikey-pin

test "$(systemctl show \
  --property=ActiveState \
  --value kaiba-provision-signing-gate.service)" = inactive
sudo test ! -e /run/kaiba-provision-signing-credentials/yubikey-pin
pin_entries="$(sudo find /run/kaiba-provision-signing-credentials \
  -mindepth 1 -maxdepth 1 -printf '%P\n')"
test -z "$pin_entries"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static
```

Remove the YubiKey and retain the gate state. The systemd credential copy and
private socket disappear when the unit stops. Do not delete or edit the durable
anti-replay state. Keep the dedicated signing host swap-free. Restoring swap,
if ever required, is a separately reviewed host-maintenance action after this
ceremony and is not part of this runbook.

## 10. Hand off and verify the public results offline

Stage a user-owned copy without changing the service state. `tar` reads the
three service-private output directories; the second process extracts them as
the current operator into a new private directory.

```console
HANDOFF_DIR="$CEREMONY_DIR/live-output-handoff"
test ! -e "$HANDOFF_DIR"
install -d -m 0700 "$HANDOFF_DIR"

sudo tar --create --file=- \
  --directory="$LIVE_ROOT" \
  boot-signed \
  eeprom-signed \
  owned-recovery-signed \
  signing-receipts.json \
  | tar --extract --file=- --directory="$HANDOFF_DIR"

sudo cat /etc/kaiba-provisioning/signing-grants.json \
  > "$HANDOFF_DIR/signing-grants.json"
install -m 0600 \
  "$VALIDATED_APPROVAL" \
  "$HANDOFF_DIR/approval.json"
install -m 0600 \
  "$RESULT_RECEIPT_DIGESTS" \
  "$HANDOFF_DIR/live-result-receipt-digests.txt"
install -m 0600 \
  "$RELEASE_INTENT/release-intent.json" \
  "$HANDOFF_DIR/release-intent.json"
chmod -R go-rwx "$HANDOFF_DIR"

HANDOFF_SUMS="$CEREMONY_DIR/live-output-handoff.sha256"
(
  cd "$HANDOFF_DIR"
  find . -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "$HANDOFF_SUMS"
chmod 0600 "$HANDOFF_SUMS"
sha256sum "$HANDOFF_SUMS"
```

Transfer the directory and checksum file to the independent/offline verifier
using an authenticated channel or controlled removable medium. Send the
checksum-file digest through a separate authenticated channel. On the offline
host, verify the packet, independently rebuild the exact new tag, and set
`HANDOFF_DIR`, `RELEASE_INTENT`, `BOOT_PLAN`, and `APPROVAL_TOOL` to that host's
absolute paths:

```console
EXPECTED_HANDOFF_MANIFEST_SHA256='REPLACE_WITH_INDEPENDENTLY_RECEIVED_64_HEX_DIGEST'
EXPECTED_APPROVAL_SHA256='REPLACE_WITH_REVIEWER_AUTHENTICATED_64_HEX_DIGEST'
EXPECTED_REGISTRY_SHA256='REPLACE_WITH_REVIEWER_AUTHENTICATED_64_HEX_DIGEST'
test "${#EXPECTED_HANDOFF_MANIFEST_SHA256}" -eq 64
test -z "${EXPECTED_HANDOFF_MANIFEST_SHA256//[0-9a-f]/}"
test "${#EXPECTED_APPROVAL_SHA256}" -eq 64
test -z "${EXPECTED_APPROVAL_SHA256//[0-9a-f]/}"
test "${#EXPECTED_REGISTRY_SHA256}" -eq 64
test -z "${EXPECTED_REGISTRY_SHA256//[0-9a-f]/}"
```

Obtain the approval and registry values directly from the reviewer-authenticated
channel used in step 4, not from the signing operator or handoff packet. The
handoff-manifest digest separately authenticates the signing operator's packet.

For an offline-verifier account with its own automated session, run this and
skip the two manual verification blocks below:

```console
"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" verify-handoff \
  --ceremony-dir "$CEREMONY_DIR" \
  --handoff-dir "$HANDOFF_DIR" \
  --checksum-manifest /absolute/path/live-output-handoff.sha256 \
  --expected-manifest-sha256 "$EXPECTED_HANDOFF_MANIFEST_SHA256" \
  --expected-approval-sha256 "$EXPECTED_APPROVAL_SHA256" \
  --expected-registry-sha256 "$EXPECTED_REGISTRY_SHA256"
```

For manual verification, authenticate the manifest itself before trusting any
entry in it:

```console
test "$(sha256sum /absolute/path/live-output-handoff.sha256 \
  | cut -d ' ' -f 1)" = "$EXPECTED_HANDOFF_MANIFEST_SHA256"
test "$(sha256sum "$HANDOFF_DIR/approval.json" \
  | cut -d ' ' -f 1)" = "$EXPECTED_APPROVAL_SHA256"
test "$(sha256sum "$HANDOFF_DIR/signing-grants.json" \
  | cut -d ' ' -f 1)" = "$EXPECTED_REGISTRY_SHA256"
(
  cd "$HANDOFF_DIR"
  sha256sum --check /absolute/path/live-output-handoff.sha256
)

cmp \
  "$HANDOFF_DIR/release-intent.json" \
  "$RELEASE_INTENT/release-intent.json"

"$APPROVAL_TOOL/bin/kaiba-provision-signing-approval" validate \
  --release-intent "$RELEASE_INTENT/release-intent.json" \
  --approval "$HANDOFF_DIR/approval.json" \
  --registry "$HANDOFF_DIR/signing-grants.json"
```

Build the standalone receipt verifier from the same pinned tag, load the five
independently captured digests, and verify the export:

```console
nix --accept-flake-config build -L \
  "$KAIBA_FLAKE_REF#kaiba-provision-signing-receipts" \
  --out-link "$CEREMONY_DIR/public/signing-receipts-tool"
RECEIPTS_TOOL="$(readlink -e \
  "$CEREMONY_DIR/public/signing-receipts-tool")"

mapfile -t RECEIPT_DIGESTS \
  < "$HANDOFF_DIR/live-result-receipt-digests.txt"
test "${#RECEIPT_DIGESTS[@]}" -eq 5
test "$(printf '%s\n' "${RECEIPT_DIGESTS[@]}" | sort -u | wc -l)" -eq 5

OFFLINE_RECEIPT_VERIFICATION="$CEREMONY_DIR/offline-receipt-verification.json"
test ! -e "$OFFLINE_RECEIPT_VERIFICATION"

"$RECEIPTS_TOOL/bin/kaiba-provision-signing-receipts" verify \
  --export "$HANDOFF_DIR/signing-receipts.json" \
  --registry "$HANDOFF_DIR/signing-grants.json" \
  --public-key "$BOOT_PLAN/public.pem" \
  --expected-receipt-digest "${RECEIPT_DIGESTS[0]}" \
  --expected-receipt-digest "${RECEIPT_DIGESTS[1]}" \
  --expected-receipt-digest "${RECEIPT_DIGESTS[2]}" \
  --expected-receipt-digest "${RECEIPT_DIGESTS[3]}" \
  --expected-receipt-digest "${RECEIPT_DIGESTS[4]}" \
  > "$OFFLINE_RECEIPT_VERIFICATION"
chmod 0600 "$OFFLINE_RECEIPT_VERIFICATION"

jq -e '
  .schema_version == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
  and .status == "valid"
  and (.receipt_digests | length == 5)
  and (.receipt_digests | unique | length == 5)
' "$OFFLINE_RECEIPT_VERIFICATION" >/dev/null
```

This verifies the registry and release-intent binding, every gate receipt
digest, every artifact RSA-2048 signature, and every domain-separated canonical
receipt-attestation RSA-2048 signature under the reviewed public key. The
attestation binds the full grant and request, request digest, backend identity,
artifact signature and digest, and `signed_at`; self-consistently rewriting
receipt metadata or its unkeyed receipt digest therefore fails verification.
The verifier also requires one backend and checks that each `signed_at`
preceded its grant expiry. `signed_at` is an authenticated reading of the
trusted gate clock, not proof from an external timestamp authority.

## 11. Import the live inputs and assemble the 18-role release

Import all three live signed-output directories, the exact reviewed registry,
and the authenticated receipt export into the Nix store. `nix store add-path`
copies public evidence; it does not contact the signing gate or hardware.

For an automated offline-verifier session, run the assembly phase and then skip
to the final publication inspection below:

```console
"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" assemble \
  --ceremony-dir "$CEREMONY_DIR" \
  --handoff-dir "$HANDOFF_DIR"
SIGNED_RELEASE="$(readlink -e "$CEREMONY_DIR/public/signed-release")"

"$CEREMONY_TOOL/bin/kaiba-provision-signing-ceremony" status \
  --ceremony-dir "$CEREMONY_DIR"
```

Otherwise, import and assemble manually:

```console
BOOT_SIGNED_STORE="$(nix store add-path "$HANDOFF_DIR/boot-signed")"
EEPROM_SIGNED_STORE="$(nix store add-path "$HANDOFF_DIR/eeprom-signed")"
OWNED_RECOVERY_SIGNED_STORE="$(
  nix store add-path "$HANDOFF_DIR/owned-recovery-signed"
)"
SIGNING_REGISTRY_STORE="$(
  nix store add-path "$HANDOFF_DIR/signing-grants.json"
)"
SIGNING_RECEIPT_EXPORT_STORE="$(
  nix store add-path "$HANDOFF_DIR/signing-receipts.json"
)"

for store_path in \
  "$BOOT_SIGNED_STORE" \
  "$EEPROM_SIGNED_STORE" \
  "$OWNED_RECOVERY_SIGNED_STORE" \
  "$SIGNING_REGISTRY_STORE" \
  "$SIGNING_RECEIPT_EXPORT_STORE"; do
  case "$store_path" in /nix/store/*) ;; *) exit 1 ;; esac
done
```

Call the exact tagged `mkRpi5PrototypeSignedRelease` factory. It independently
re-verifies the three result directories, reconstructs the same owned-recovery
plan, extracts the five result receipt digests, re-verifies the authenticated
export against the imported registry, builds the six RPIBOOT trees, and runs
the no-authority finalizer. Receipt verification is a build prerequisite; it
does not create a nineteenth artifact role.

```console
SIGNED_RELEASE="$(
  nix --accept-flake-config build -L \
    --impure \
    --out-link "$CEREMONY_DIR/public/signed-release" \
    --print-out-paths \
    --expr "
      let
        kaiba = builtins.getFlake \"$KAIBA_FLAKE_REF\";
      in
      (kaiba.lib.mkRpi5PrototypeSignedRelease {
        bootSignedOutput = builtins.storePath \"$BOOT_SIGNED_STORE\";
        eepromSignedOutput = builtins.storePath \"$EEPROM_SIGNED_STORE\";
        ownedRecoverySignedOutput = builtins.storePath \"$OWNED_RECOVERY_SIGNED_STORE\";
        signingGrantRegistry = builtins.storePath \"$SIGNING_REGISTRY_STORE\";
        signingReceiptExport = builtins.storePath \"$SIGNING_RECEIPT_EXPORT_STORE\";
      }).release
    "
)"

test -d "$SIGNED_RELEASE"
test "$(find "$SIGNED_RELEASE" -mindepth 1 -maxdepth 1 \
  -printf '%f\n' | sort)" = $'manifests\nobjects\npublication-digest\npublication.json\nrecords\ntree-records\ntrees'

jq -e --arg revision "$EXPECTED_COMMIT" '
  .schema_version == "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
  and .source_revision == $revision
  and (.artifacts | length == 18)
  and (.records | length == 9)
' "$SIGNED_RELEASE/publication.json" >/dev/null

MANIFEST_RELATIVE="$(jq --exit-status --raw-output \
  '.manifest_path' "$SIGNED_RELEASE/publication.json")"
case "$MANIFEST_RELATIVE" in manifests/sha256/*.json) ;; *) exit 1 ;; esac
jq -e '
  .schema_version == "kaiba.provisioning.rpi5-signed-release-manifest/v1alpha2"
  and (.artifacts | length == 18)
' "$SIGNED_RELEASE/$MANIFEST_RELATIVE" >/dev/null

jq -r '.artifacts[].role' "$SIGNED_RELEASE/publication.json"
cat "$SIGNED_RELEASE/publication-digest"
```

At this point the software-only ceremony is complete. Preserve the approval,
registry, live results, receipt digests, authenticated receipt export, offline
verification, publication digest, exact tag, and exact commit as the release
evidence set. Keep the automated ceremony directory, including its indirect GC
roots, until those records and the final release have been retained under the
reviewed evidence policy. The resulting release is ready for a separately authorized
sacrificial-board test plan; it is not authority to write NVMe, program EEPROM,
change OTP/JTAG posture, or promote the development signer to production.

## 12. Recovery from a software-only finalizer defect

If assembly writes `assembly-failure.json`, that ceremony is terminal. Preserve
the failure record, build log, handoff snapshot, verification records, and GC
roots. Do not remove the record, rerun `assemble`, repeat a signing request, or
move the original release tag.

A defect confined to the public, no-authority finalizer does not invalidate
already authenticated artifact signatures and receipt attestations. After the
fix has passed review and CI under a new immutable tooling tag, use
`lib.mkRpi5PrototypeSignedReleaseRecovery` in a new verifier-owned recovery
directory. The recovery factory evaluates the payload graph from the original
tag, then feeds that exact verified component graph to the fixed finalizer:

```nix
let
  payload = builtins.getFlake payloadFlakeRef;
  fixed = builtins.getFlake recoveryToolFlakeRef;
in
fixed.lib.mkRpi5PrototypeSignedReleaseRecovery {
  inherit
    bootSignedOutput
    eepromSignedOutput
    ownedRecoverySignedOutput
    signingGrantRegistry
    signingReceiptExport
    ;
  inherit payload;
  payloadSourceRevision = payloadCommit;
}
```

The five inputs must be independently imported from the already authenticated
handoff. Do not use the normal prototype factory from the new tag: it would
create a different payload revision that the existing signatures do not
authorize.

Retain a recovery record containing at least:

- the original payload tag and commit;
- the recovery-tool tag and commit;
- the original handoff-manifest, approval, registry, release-intent, receipt
  export, and assembly-failure digests;
- the fixed finalizer package NAR hash;
- the recovered signed-release NAR hash and publication digest.

Re-run the final publication inspection from section 11 and confirm that its
`source_revision` and release-intent digest still name the original payload.
Recovery remains software-only; it does not authorize media, EEPROM, OTP, JTAG,
or other hardware mutation.
