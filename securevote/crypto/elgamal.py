"""
Exponential ElGamal over an order-``q`` subgroup (multiplicative notation).

Key generation:
  private ``x ∈ Z_q``, public ``h = g^x mod p``.

Encryption of message ``m`` (small integer embedded as ``g^m``):
  ``(c1, c2) = (g^r, g^m · h^r)`` with random ``r ∈ Z_q``.

Homomorphic addition of plaintexts is ciphertext multiplication component-wise:
  ``Enc(m1) · Enc(m2)`` encrypts ``m1 + m2 (mod q)`` in the exponent.

Decryption recovers ``T = g^m mod p`` via ``T = c2 / c1^x``, then discrete
log search over ``0..max_m`` (demo scale).
"""

from __future__ import annotations

import secrets
from typing import Tuple

from securevote.crypto.params import GroupParams, validate_subgroup_element

Ciphertext = Tuple[int, int]
KeyPair = Tuple[int, int]  # (private x, public h)


def _random_exponent(params: GroupParams) -> int:
    """Uniform random non-zero exponent in ``Z_q`` (we allow zero r in encrypt)."""
    return secrets.randbelow(params.q)


def keygen(params: GroupParams) -> KeyPair:
    """
    Generate ElGamal key pair ``(x, h)`` with ``h = g^x mod p``.

    Returns private ``x`` and public ``h``.
    """
    x = secrets.randbelow(params.q)
    if x == 0:
        x = 1
    h = pow(params.g, x, params.p)
    validate_subgroup_element(params, h)
    return x, h


def encrypt(
    params: GroupParams,
    public_key: int,
    message: int,
    randomness: int | None = None,
) -> Ciphertext:
    """
    Encrypt integer message ``m`` as ``(g^r, g^m · h^r)``.

    ``message`` is treated as an integer exponent (typically 0 or 1 for ballots).
    """
    validate_subgroup_element(params, public_key)
    if not (0 <= message < params.q):
        raise ValueError("message exponent out of range")
    r = randomness if randomness is not None else _random_exponent(params)
    if not (0 <= r < params.q):
        raise ValueError("randomness out of range")
    c1 = pow(params.g, r, params.p)
    gm = pow(params.g, message, params.p)
    hr = pow(public_key, r, params.p)
    c2 = (gm * hr) % params.p
    validate_subgroup_element(params, c1)
    validate_subgroup_element(params, c2)
    return c1, c2


def homomorphic_add(c1: Ciphertext, c2: Ciphertext, p: int) -> Ciphertext:
    """
    Add encrypted plaintexts: ``Enc(m1) ⊗ Enc(m2) = Enc(m1 + m2)`` (exponent sum).

    Component-wise multiplication modulo ``p``.
    """
    a1, b1 = c1
    a2, b2 = c2
    return (a1 * a2) % p, (b1 * b2) % p


def decrypt_value(params: GroupParams, private_key: int, ciphertext: Ciphertext) -> int:
    """
    Recover ``T = g^m mod p`` from ciphertext using private key ``x``.

    ``T = c2 · (c1^x)^{-1} mod p``.
    """
    if not (0 <= private_key < params.q):
        raise ValueError("private key out of range")
    c1, c2 = ciphertext
    validate_subgroup_element(params, c1)
    validate_subgroup_element(params, c2)
    s = pow(c1, private_key, params.p)
    s_inv = pow(s, params.q - 1, params.p)  # Fermat: s^(q-1) ≡ s^{-1} when s^q ≡ 1
    t = (c2 * s_inv) % params.p
    # ``g^0 = 1`` is the identity (not in the strict subgroup check ``1 < y < p``).
    if t != 1:
        validate_subgroup_element(params, t)
    return t


def brute_force_discrete_log(params: GroupParams, target: int, max_m: int) -> int:
    """
    Find ``m`` in ``[0, max_m]`` such that ``g^m ≡ target (mod p)``.

    Raises ``ValueError`` if no such ``m`` exists (demo-scale tally recovery).
    """
    if max_m < 0:
        raise ValueError("max_m must be non-negative")
    if target == 1:
        return 0
    validate_subgroup_element(params, target)
    acc = 1
    for m in range(max_m + 1):
        if acc == target:
            return m
        acc = (acc * params.g) % params.p
    raise ValueError(
        f"discrete log not found in 0..{max_m}; ciphertext may be invalid or max_m too small"
    )


def decrypt(
    params: GroupParams,
    private_key: int,
    ciphertext: Ciphertext,
    max_m: int,
) -> int:
    """Decrypt to plaintext integer ``m`` via ``g^m`` recovery and brute-force search."""
    t = decrypt_value(params, private_key, ciphertext)
    return brute_force_discrete_log(params, t, max_m)
