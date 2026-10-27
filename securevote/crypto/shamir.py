"""
Shamir secret sharing over ``Z_q`` (threshold scheme).

A secret ``s`` (e.g. ElGamal private key ``x``) is embedded as ``f(0) = s`` for a
random polynomial ``f`` of degree ``k - 1``. Trustee ``i`` receives the share
``(i, f(i))``; any ``k`` distinct shares determine ``s`` via Lagrange
interpolation at 0:

  ``s = Σ_i y_i · λ_i(0)  (mod q)``,  ``λ_i(0) = Π_{j≠i} (-j)/(i-j)``.

Production tallying never reconstructs ``x``; trustees only use their share for
partial decryption (see ``threshold.py``). ``reconstruct_secret`` is provided
for tests and dealer sanity checks.
"""

from __future__ import annotations

import secrets
from typing import Dict, Iterable, List, Mapping, Tuple

Share = Tuple[int, int]  # (trustee_id, share_value in Z_q)


def _mod_inverse(a: int, q: int) -> int:
    """Multiplicative inverse of ``a`` modulo prime ``q``."""
    a %= q
    if a == 0:
        raise ValueError("cannot invert zero")
    return pow(a, -1, q)


def lagrange_coefficient_at_zero(trustee_id: int, peer_ids: Iterable[int], q: int) -> int:
    """
    Compute ``λ_i(0)`` for Lagrange interpolation over points ``peer_ids``.

    ``λ_i(0) = Π_{j≠i} (0 - j) / (i - j)  (mod q)``.
    """
    num = 1
    den = 1
    for j in peer_ids:
        if j == trustee_id:
            continue
        num = (num * (-j % q)) % q
        den = (den * ((trustee_id - j) % q)) % q
    return (num * _mod_inverse(den, q)) % q


def split_secret(secret: int, n: int, threshold: int, q: int) -> Dict[int, int]:
    """
    Split ``secret`` into ``n`` Shamir shares with threshold ``k``.

    Returns a map ``trustee_id -> f(trustee_id)`` for ids ``1..n``.
    """
    if not (1 <= threshold <= n):
        raise ValueError("threshold must satisfy 1 <= k <= n")
    if not (0 <= secret < q):
        raise ValueError("secret must lie in Z_q")

    coeffs = [secret]
    for _ in range(threshold - 1):
        coeffs.append(secrets.randbelow(q))

    shares: Dict[int, int] = {}
    for trustee_id in range(1, n + 1):
        x = trustee_id
        y = 0
        power = 1
        for coeff in coeffs:
            y = (y + coeff * power) % q
            power = (power * x) % q
        shares[trustee_id] = y
    return shares


def reconstruct_secret(shares: Mapping[int, int], q: int) -> int:
    """
    Reconstruct ``f(0)`` from at least ``deg+1`` shares (typically ``k`` shares).

    Raises ``ValueError`` if fewer than two distinct shares are supplied.
    """
    if len(shares) < 1:
        raise ValueError("no shares provided")
    ids = list(shares.keys())
    if len(ids) == 1:
        # Single share never determines a degree-(k-1) secret for k>1; still
        # return the Lagrange formula result (equals the share line at 0 only
        # when k=1).
        only_id = ids[0]
        return shares[only_id] % q

    secret = 0
    for i in ids:
        lam = lagrange_coefficient_at_zero(i, ids, q)
        secret = (secret + shares[i] * lam) % q
    return secret


def trustee_verification_key(params_g: int, share_value: int, p: int, q: int) -> int:
    """
    Public verification key ``h_i = g^{x_i} mod p`` for trustee share ``x_i``.

    Used later for Chaum–Pedersen partial-decryption proofs.
    """
    if not (0 <= share_value < q):
        raise ValueError("share value out of range")
    h = pow(params_g, share_value, p)
    if h == 1:
        raise ValueError("degenerate trustee verification key")
    if pow(h, q, p) != 1:
        raise ValueError("trustee verification key not in subgroup")
    return h
