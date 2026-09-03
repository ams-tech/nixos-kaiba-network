# Ubuntu development provisioning authority

This bundle installs the Kaiba control and append-only audit services on the
development Ubuntu authority host. Both services require mutual TLS, use
separate server trust roots, and share one client CA that issues two exact,
role-separated identities:

- `spiffe://kaiba.network/station/kaiba-rpi5-provisioner/lane/lane-1`
- `spiffe://kaiba.network/approver/verifier`

The deployment is deliberately inert. Installation creates neither service
state nor a systemd enablement link and never starts either service. It also
does not modify UFW or any other firewall policy. Starting the two disabled
units is a separate operator boundary.

The fixed listener is `192.168.8.249`, with control on TCP 8091 and audit on
TCP 8092. Before starting either service, determine the provisioning Pi's
current IPv4 address on the directly connected network and add source- and
interface-scoped UFW rules. Replace `<PROVISIONER_IPV4>` only after reading it
on that Pi; do not use a subnet-wide rule:

```console
$ sudo ufw allow in on enp4s0 from <PROVISIONER_IPV4> to 192.168.8.249 port 8091 proto tcp
$ sudo ufw allow in on enp4s0 from <PROVISIONER_IPV4> to 192.168.8.249 port 8092 proto tcp
$ sudo ufw status numbered
```

The development PKI generator unlinks all three CA private keys after issuing
the fixed certificates and does not retain them in the packet. Unlinking is not
a secure-erasure claim. For a live installation, generate the root-owned packet
directly beneath `/run`, which the installer verifies is tmpfs; do not copy a
mutable user-owned packet into a root installation. The output is suitable only
for this sacrificial development campaign, not production PKI.

Typical live-host sequence (from the immutable Nix deployment output):

```console
$ sudo kaiba-provision-authority-development-pki --output /run/kaiba-authority-pki-packet
$ sudo kaiba-ubuntu-provisioning-authority-install --pki-directory /run/kaiba-authority-pki-packet
$ sudo kaiba-provision-authority-preflight --static
```

The station packet deliberately contains two different private keys with the
same fixed station/lane URI identity:

- `station/bridge/` maps filename-for-filename to
  `/var/lib/kaiba-provisioning-credentials/bridge/` on the mutation image. Copy
  it as `root:root`, with the directory at `0700`, the key at `0400`, and the
  certificate/CAs and `SHA256SUMS` at `0444`. Only the systemd authority bridge
  reads this key. Its prerequisite admission unit rejects an inexact file set,
  a checksum mismatch, the wrong station URI, or a mismatched key pair.
- `station/lane-workflow/` maps filename-for-filename to
  `/home/provisioner/.config/kaiba-provisioning/lane-workflow/`. Copy it as
  `provisioner:provisioner`, with the directory at `0700` and every file at
  `0400`. The image's `kaiba-provision-lane-workflow` wrapper validates those
  ownership/mode/link constraints, the exact file set, `SHA256SUMS`, station
  URI, and key pair before supplying the fixed endpoints and paths.

Transfer these two station directories and `approver/` as separate private
packets over authenticated SSH. Each packet contains its own `SHA256SUMS`.
Before transfer, run `sha256sum --check --strict SHA256SUMS` inside each source
packet and record `sha256sum SHA256SUMS`; repeat both checks at the destination
and compare the recorded manifest digest. The approver private key must never
be copied to the station. Removing the authority host's
`/run/kaiba-authority-pki-packet` after independently verifying all deliveries
is a separate explicit operator step.

Do not enable the services. After credentials have been delivered to the
station and verifier, the exact UFW rules have been reviewed, and the final
operation has been reviewed, start and test the services explicitly:

```console
$ sudo systemctl start kaiba-provisioning-control.service kaiba-provisioning-audit.service
$ sudo kaiba-provision-authority-live-smoke --pki-directory /run/kaiba-authority-pki-packet
```

The smoke test performs only GET requests. It proves positive station mTLS,
negative unauthenticated and cross-CA handshakes, and station-versus-approver
role separation without creating a transaction or audit event. Do not proceed
if it fails. Neither service is enabled, so a reboot returns the authority to
its inert state.
