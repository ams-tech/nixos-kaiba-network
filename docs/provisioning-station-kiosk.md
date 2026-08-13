# Provisioning-station interface demo

`kaiba-provision-station-demo` is a local, deterministic interface prototype
for evaluating the operator workflow on a provisioning-station display. It is
suitable for an HDMI display and USB touchscreen attached to an AArch64 or
x86_64 NixOS host.

This demo is not a provisioning authority. It renders simulated scenarios; it
does not invoke `kaiba-provision`, enumerate USB devices, upload recovery
firmware, authenticate or attest a target, handle device secrets, or authorize
a mutation. The demo and the experimental live
[Raspberry Pi 5 probe](raspberry-pi-5-provisioning-probe.md) intentionally have
separate privilege boundaries.

## NixOS service

The disabled-by-default module runs the HTTP server as a dynamically allocated,
unprivileged systemd identity:

```nix
{
  imports = [ inputs.kaiba.nixosModules.provisioning-station-demo ];

  services.kaiba-provisioning-station-demo = {
    enable = true;
    package = inputs.kaiba.packages.${pkgs.system}.kaiba-provision-station-demo;
    listenAddress = "127.0.0.1";
    port = 8080;
    scenario = "happy-path";
  };
}
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

They exercise display states only. A scenario labelled as successful is not
evidence from live hardware.

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

This provides one common interface and one common simulated workflow today.
The production provisioning orchestrator is still future work. It should
implement the same typed state/action contract behind the HTTP transport; the
browser graph must remain a public demonstration and must never become a
fallback for a live station.

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

Until those components exist and the sacrificial-device qualification is
complete, use the kiosk only to review interaction design and use
`kaiba-provision probe` separately for controlled, non-persistent hardware
qualification. Persistent provisioning remains disabled.
