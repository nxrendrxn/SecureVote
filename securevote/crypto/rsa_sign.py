"""
RSA key generation, PKCS#1 v1.5 (EMSA-PKCS1-v1_5) signatures with SHA-256.

Key generation:
  Choose distinct primes ``p, q`` (Miller–Rabin), ``n = pq``, ``φ = (p-1)(q-1)``,
  public exponent ``e = 65537``, private ``d = e^{-1} mod φ``.

Signing:
  ``H = SHA-256(message)``, build DER DigestInfo + ``H``, apply v1.5 padding to
  length ``k = ⌈log_2(n)/8⌉`` bytes, interpret as integer ``EM``, then
  ``s = EM^d mod n``.

Verification inverts with ``EM' = s^e mod n`` and compares to the same padded encoding.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Literal

from securevote.crypto.hashing import sha256_digest  # noqa: F401  (re-exported for tests)
from securevote.crypto.primes import random_prime

_PUBLIC_EXPONENT = 65537

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 / PKCS#1).
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True)
class RSAPublicKey:
    """RSA public key ``(n, e)``."""

    n: int
    e: int = _PUBLIC_EXPONENT


@dataclass(frozen=True)
class RSAKeyPair:
    """Full RSA key material for signing (educational storage; protect ``d``)."""

    public: RSAPublicKey
    d: int
    p: int
    q: int

    @property
    def n(self) -> int:
        return self.public.n

    @property
    def e(self) -> int:
        return self.public.e


def _modulus_bytes(n: int) -> int:
    """Byte length ``k`` of modulus ``n``."""
    return (n.bit_length() + 7) // 8


def emsa_pkcs1_v15_encode_sha256(message_hash: bytes, modulus_bits: int) -> int:
    """
    EMSA-PKCS1-v1_5 encode digest for RSA signature (SHA-256 DigestInfo).

    Output integer ``EM`` of bit length at most ``modulus_bits``.
    """
    if len(message_hash) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    t = _SHA256_DIGEST_INFO_PREFIX + message_hash
    k = (modulus_bits + 7) // 8
    if len(t) > k - 11:
        raise ValueError("encoded message too long for modulus")
    ps_len = k - len(t) - 3
    em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    return int.from_bytes(em, "big")


def generate_rsa_keypair(mode: Literal["test", "demo"] = "test") -> RSAKeyPair:
    """
    Generate RSA key pair.

    ``test`` → ~512-bit modulus (fast tests); ``demo`` → ~2048-bit modulus.
    """
    total_bits = 512 if mode == "test" else 2048
    half = total_bits // 2
    while True:
        p = random_prime(half)
        q = random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != total_bits:
            # Allow slight variation: require at least target - 8 bits for tests.
            if mode == "demo" and n.bit_length() < total_bits - 1:
                continue
            if mode == "test" and not (total_bits - 16 <= n.bit_length() <= total_bits):
                continue
        phi = (p - 1) * (q - 1)
        if phi % _PUBLIC_EXPONENT == 0:
            continue
        d = pow(_PUBLIC_EXPONENT, -1, phi)
        return RSAKeyPair(public=RSAPublicKey(n=n), d=d, p=p, q=q)


def sign_message(key: RSAKeyPair, message: bytes) -> int:
    """Return PKCS#1 v1.5 RSA signature ``s = EM^d mod n``."""
    digest = sha256_digest(message)
    em = emsa_pkcs1_v15_encode_sha256(digest, key.n.bit_length())
    if em >= key.n:
        raise ValueError("encoded message out of range")
    return pow(em, key.d, key.n)


def verify_signature(public_key: RSAPublicKey, message: bytes, signature: int) -> bool:
    """
    Verify PKCS#1 v1.5 RSA-SHA256 signature.

    Uses constant-time comparison on fixed-width encoded message bytes.
    """
    if not (0 <= signature < public_key.n):
        return False
    try:
        digest = sha256_digest(message)
        em_expected = emsa_pkcs1_v15_encode_sha256(digest, public_key.n.bit_length())
    except ValueError:
        return False
    em_received = pow(signature, public_key.e, public_key.n)
    k = _modulus_bytes(public_key.n)
    try:
        expected = em_expected.to_bytes(k, "big")
        received = em_received.to_bytes(k, "big")
    except OverflowError:
        return False
    return hmac.compare_digest(expected, received)


def signature_to_bytes(signature: int, modulus_n: int) -> bytes:
    """Fixed-width big-endian signature bytes for interop with external libraries."""
    k = _modulus_bytes(modulus_n)
    return signature.to_bytes(k, "big")


def signature_from_bytes(data: bytes) -> int:
    """Parse signature integer from bytes."""
    return int.from_bytes(data, "big")
