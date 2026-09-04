# Raspberry Pi 5 development secure-boot station

This image exists for one purpose: move the fixed sacrificial development Pi
from its verified blank state to the already-signed v0.1.6 secure-boot state,
then prove that the signed system boots.

It does not contain a signer, a signing credential, a remote authority bridge,
an approval workflow, or a background mutation service. The v0.1.6 signed
release, target fingerprint, RPIBOOT USB path, and receive-only UART path are
compiled into one local runner.

There is no service to activate and no root shell procedure. The installed
wrapper has permission to execute only the fixed runner, and the runner accepts
no artifact, target, USB-path, or UART-path overrides.

## Operator interface

Boot the station and run:

```console
kaiba-secure-boot run
```

The command walks through these physical transitions:

1. A read-only fresh-state observation on the fixed RPIBOOT lane.
2. A complete disconnect and a new RPIBOOT connection.
3. One explicit OTP/EEPROM commit using the fixed v0.1.6 signed payload.
4. A complete disconnect and a new owned readback connection.
5. A normal cold boot from the already-verified signed SD card while the
   command captures the receive-only UART.

The command succeeds only after it observes the expected customer-key hash,
rejects any conflicting EEPROM hash, and receives exactly one
`KAIBA_SECURE_BOOT_EVIDENCE=pass` record for the fixed boot-image digest with
the customer-key OTP bit set.

The read-only pre-observation and the commit never share an RPIBOOT session.
Metadata recovery consumes that session, so the operator is explicitly asked
to disconnect and reconnect the target before the one-time commit.

Durable progress and the final result are stored under:

```text
/var/lib/kaiba-development-secure-boot
```

Inspect progress with:

```console
kaiba-secure-boot status
```

If the commit command is interrupted after its durable `commit_started`
record, it is never repeated automatically. Establish the actual state with:

```console
kaiba-secure-boot reconcile
```

Reconciliation first tries the signed owned readback. If that cannot establish
the programmed state, it asks for a second physical reconnect and tries the
read-only fresh bundle. Only a complete, identity-matched blank observation
permits another explicit commit attempt; every other result remains stopped.

Then rerun `kaiba-secure-boot run` to finish the readback and signed UART boot.

`kaiba-secure-boot inventory` prints the compiled release and lane identity.
