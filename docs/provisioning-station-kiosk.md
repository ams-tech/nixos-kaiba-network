# Provisioning-station interface demo

`kaiba-provision-station-demo` is a local, deterministic interface prototype
for evaluating the operator workflow on a provisioning-station display. It is
suitable for an HDMI display and USB touchscreen attached to an AArch64 or
x86_64 NixOS host.

The interface models the complete Raspberry Pi 5 secure-boot ceremony from
station admission and a qualified fresh candidate through the
`enrollment_ready` handoff defined by the
[Raspberry Pi 5 secure-boot guide](raspberry-pi-5-secure-boot.md). It covers the
irreversible path as deterministic display states, but it is not a provisioning
authority. It does not invoke `kaiba-provision`, enumerate USB devices, upload
recovery firmware, authenticate or attest a target, contact an external signer
or control service, handle device secrets, program OTP, update EEPROM, boot a
target, or reconcile inventory. The demo and the experimental live
[Raspberry Pi 5 probe](raspberry-pi-5-provisioning-probe.md) intentionally have
separate privilege boundaries.

The modeled happy path is:

1. pass station admission, create the transaction, acquire the claim, and bind
   exactly one target;
2. close the deferred baseline by checking the remaining OTP and protected-key
   rows, EEPROM posture, storage, inventory and prior transactions, firmware
   authenticity, and debug and alternate paths; then resolve the signed
   manifest, artifacts, recovery bundle, and all required policies;
3. bind independent commit approval to the exact target and plan, and establish
   both directions of initial trust; immediately before intent, re-identify the
   same zero-key target on the exclusively claimed and fenced RPIBOOT lane;
4. export durable intent, simulate one execution of the approved OTP/EEPROM
   commit, and reconcile authoritative readback;
5. simulate signed cold boot, the customer-counter-signed owned probe and
   recovery path, repeat the owned readback after recovery, and run rejection
   tests for altered, unsigned, and wrong-key inputs, persistent-root integrity,
   and anti-rollback enforcement;
6. separately approve final controls, record their durable intent, apply them
   once, cold restart, read them back directly, repeat affected tests, export
   audit, reconcile inventory, and enter `enrollment_ready`.

Failures before the simulated irreversible boundary may stop cleanly. An
uncertain result at or after that boundary, changed target, mismatched readback,
missing evidence, or failed acceptance test leaves the simulated device owned
and quarantined; the workflow never presents it as fresh again. Reaching
`enrollment_ready` does not create a device key, issue a certificate, activate a
credential, or authorize production use. Device-identity enrollment remains a
later, separately gated lifecycle transaction.

## NixOS service

The disabled-by-default module runs the HTTP server as a dynamically allocated,
unprivileged systemd identity. New configurations can consume only the
provisioning leaf:

```nix
inputs.kaiba-provisioning = {
  url = "github:ams-tech/nixos-kaiba-network?dir=nix/provisioning";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

Import its module and package in the station configuration. The module form
below assumes the surrounding `nixosSystem` passes
`specialArgs = { inherit inputs; };`:

```nix
{ inputs, pkgs, ... }:

{
  imports = [ inputs.kaiba-provisioning.nixosModules.provisioning-station-demo ];

  services.kaiba-provisioning-station-demo = {
    enable = true;
    package =
      inputs.kaiba-provisioning.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision-station-demo;
    listenAddress = "127.0.0.1";
    port = 8080;
    scenario = "happy-path";
  };
}
```

Keep the package assignment explicit so the source of the service binary is
visible. Existing configurations using the repository-root compatibility
input may keep `inputs.kaiba.nixosModules.provisioning-station-demo` and
`inputs.kaiba.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision-station-demo`.

From a checkout, evaluate the leaf or build either interface package directly:

```console
nix flake check ./nix/provisioning -L
nix build ./nix/provisioning#kaiba-provision-station-demo -L
nix build ./nix/provisioning#kaiba-provision-station-pages -L
```

`listenAddress` accepts only `127.0.0.1` or `::1`. The service has no
authentication layer, and the module refuses a non-loopback address rather
than opening a firewall port. The sandbox provides a read-only system image,
a private device namespace, a closed device policy, no Linux capabilities,
and network access limited to loopback. It creates no user or group, grants no
membership in `kaiba-provision`, and installs no udev rule. Enabling the
interface therefore does not grant raw access to an attached target.

The deterministic scenarios are:

- `happy-path`
- `class-mismatch`
- `baseline-failure`
- `multiple-targets`
- `acquisition-error`
- `target-replaced`
- `mutation-safety-violation`
- `boot-failure`
- `preparation-failure`
- `approval-failure`
- `trust-failure`
- `commit-uncertain`
- `commit-readback-mismatch`
- `signed-boot-failure`
- `owned-readback-mismatch`
- `recovery-failure`
- `negative-boot-failure`
- `root-integrity-failure`
- `rollback-failure`
- `finalization-failure`
- `final-retest-failure`
- `audit-failure`
- `deferred-baseline-failure`
- `precommit-target-replaced`
- `post-recovery-readback-mismatch`

They exercise display states only. A scenario labelled as successful means only
that the synthetic state machine reached `enrollment_ready`; it is not evidence
from live hardware and does not represent identity enrollment. A precommit
failure stops or aborts before the simulated one-way operation when the modeled
state is reusable. An uncertain commit or any post-OTP failure ends in
`owned_quarantined`. No reset is offered after the irreversible boundary;
exporting the record leaves the terminal state in place, and reloading starts
an independent synthetic run rather than presenting the owned target as fresh.

## Shared local and GitHub Pages interface

The loopback station and GitHub Pages simulation do not have separate user
interfaces. Both packages copy or embed the same canonical `index.html`,
`styles.css`, `transport.js`, and `app.js` files. Runtime selection is explicit
and fail-closed through a same-origin configuration document:

- the loopback service selects HTTP mode and the shared transport calls the
  local state and action endpoints; and
- the Pages package selects transition-graph mode and the same transport keeps
  the current node and monotonically increasing revision in browser memory.

There is no hostname detection, query-string switch, API probing, or fallback
from the HTTP service to the browser simulation. A missing or malformed runtime
configuration therefore leaves the connection error visible instead of
silently changing the interface's trust boundary.

The Pages graph is not a JavaScript reimplementation of the workflow. A build
tool explores every action exposed by the authoritative Go mock `Machine`,
removes only the runtime revision from each state template, and emits the
complete finite graph. The browser adapter validates the graph's schema,
closed transitions, and non-mutation safety fields before using it. Automated
tests traverse every generated edge and compare every resulting browser state
with its Go-generated state, byte-compare all four shared interface assets,
and reject an assembled site that weakens the simulation boundary.

After a main-branch Pages deployment, the public simulation is available at:

```text
https://ams-tech.github.io/nixos-kaiba-network/provisioning-demo/
```

The Pages version is public, unauthenticated, synthetic, and per-tab. Reloading
the page resets it to revision 1. It has no Go server, durable state, WebUSB,
device access, secrets, or provisioning authority. GitHub Pages also cannot
provide all of the response security headers used by the loopback service; a
restrictive HTML content-security policy is defense in depth, not an
equivalent station boundary.

This provides one common interface and one common simulated secure-boot
workflow today. The production provisioning orchestrator is still future work.
It should implement the same typed state/action contract behind the HTTP
transport; the browser graph must remain a public demonstration and must never
become a fallback for a live station.

## Local operator session

The module does not configure a graphical session, display manager, browser,
automatic login, or touchscreen calibration. Those are station-host policy and
hardware choices rather than properties of the demo service. After configuring
the host's display and input stack, a constrained local operator session can
launch Chromium explicitly, for example:

```console
chromium \
  --kiosk \
  --app=http://127.0.0.1:8080/ \
  --no-first-run \
  --disable-session-crashed-bubble
```

Chromium's kiosk switch removes ordinary browser chrome; it is not a security
boundary. A station image should separately restrict the operator account,
browser policy, navigation, downloads, extensions, developer tools, keyboard
escape paths, and access to a shell. The operator account should not be a
member of `kaiba-provision` merely because it displays this interface.

For a Raspberry Pi 5 display station, power the station independently and use
a labelled USB host port as the target lane. An attached USB touchscreen is
not an eligible probe target: the probe accepts exactly one device with the
BCM2712 RPIBOOT vendor/product identity at an explicitly selected sysfs path.

## Path to a hardware-backed interface

Do not evolve the HTTP demo into a process with direct USB privileges. A live
operator interface should submit typed requests to the future orchestrator and
privileged lane guard described by the
[provisioning-station design](provisioning-station.md). That boundary must own
the target handle, transaction continuity, approvals, journaling, fencing, and
postcondition checks. The UI should receive only structured, secret-free state
and should never accept arbitrary commands, executable paths, payload paths,
profiles, or device selectors from browser content.

The read-only Pi 5 hardware-qualification milestone now has reviewed evidence,
but it deliberately grants no mutation authority. Until the authenticated
control-to-guard bridge, complete signed release, remaining board-specific
baseline checks, and physical lane campaign exist, use the kiosk only to review
the modeled ceremony and use `kaiba-provision probe` separately for controlled,
non-persistent requalification. OTP and EEPROM mutation, owned-device
reconciliation, and identity enrollment remain disabled in the kiosk.
