#!/usr/bin/env python3
"""Generate the repository's deterministic, fixture-only RSA-2048 key.

The private key is reconstructed only in a Nix build's private temporary
directory.  It is never a source file or an output of a derivation.  This is
not a production key-generation mechanism.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import math
import os
from pathlib import Path


PUBLIC_EXPONENT = 65537
KEY_BITS = 2048
SEED = b"kaiba-rpi5-production-media-integration-fixture-v1"
SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
    257,
    263,
    269,
    271,
    277,
    281,
    283,
    293,
    307,
    311,
)


def deterministic_bytes(label: bytes, counter: int, length: int) -> bytes:
    material = SEED + b"\x00" + label + b"\x00" + counter.to_bytes(8, "big")
    return hashlib.shake_256(material).digest(length)


def probably_prime(candidate: int, label: bytes) -> bool:
    for prime in SMALL_PRIMES:
        if candidate % prime == 0:
            return candidate == prime

    odd = candidate - 1
    shifts = 0
    while odd % 2 == 0:
        shifts += 1
        odd //= 2
    for round_index in range(32):
        encoded = hashlib.sha256(
            SEED + b"\x00miller-rabin\x00" + label + round_index.to_bytes(4, "big")
        ).digest()
        base = 2 + int.from_bytes(encoded, "big") % (candidate - 3)
        value = pow(base, odd, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shifts - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def derive_prime(label: bytes) -> int:
    byte_count = KEY_BITS // 16
    for counter in range(1_000_000):
        candidate = int.from_bytes(deterministic_bytes(label, counter, byte_count), "big")
        candidate |= 1 << (KEY_BITS // 2 - 1)
        candidate |= 1
        if math.gcd(candidate - 1, PUBLIC_EXPONENT) != 1:
            continue
        if probably_prime(candidate, label + counter.to_bytes(8, "big")):
            return candidate
    raise RuntimeError("deterministic fixture prime search exhausted")


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big") or b"\x00"
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + der_length(len(encoded)) + encoded


def der_sequence(*values: bytes) -> bytes:
    payload = b"".join(values)
    return b"\x30" + der_length(len(payload)) + payload


def private_key_der() -> bytes:
    p = derive_prime(b"p")
    q = derive_prime(b"q")
    if p == q:
        raise RuntimeError("deterministic fixture primes unexpectedly collide")
    if p < q:
        p, q = q, p
    modulus = p * q
    if modulus.bit_length() != KEY_BITS:
        raise RuntimeError("deterministic fixture modulus is not RSA-2048")
    totient = (p - 1) * (q - 1)
    private_exponent = pow(PUBLIC_EXPONENT, -1, totient)
    return der_sequence(
        der_integer(0),
        der_integer(modulus),
        der_integer(PUBLIC_EXPONENT),
        der_integer(private_exponent),
        der_integer(p),
        der_integer(q),
        der_integer(private_exponent % (p - 1)),
        der_integer(private_exponent % (q - 1)),
        der_integer(pow(q, -1, p)),
    )


def pem(label: str, encoded: bytes) -> bytes:
    body = base64.b64encode(encoded)
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return (
        f"-----BEGIN {label}-----\n".encode()
        + b"\n".join(lines)
        + f"\n-----END {label}-----\n".encode()
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private", required=True, type=Path)
    args = parser.parse_args()
    args.private.write_bytes(pem("RSA PRIVATE KEY", private_key_der()))
    os.chmod(args.private, 0o600)


if __name__ == "__main__":
    main()
