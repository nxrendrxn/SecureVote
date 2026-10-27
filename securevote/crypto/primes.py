"""
Prime generation and Miller-Rabin primality testing.

Uses ``secrets`` for cryptographically strong randomness.
Educational code — not constant-time and not production-grade.
"""

from __future__ import annotations

import secrets
from typing import Iterable

# Miller-Rabin witnesses sufficient for n < 2^64 (deterministic for 64-bit tests).
_DETERMINISTIC_WITNESSES_64: tuple[int, ...] = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


def _rand_odd(bits: int) -> int:
    """Return a uniform random odd integer with exactly ``bits`` bits."""
    if bits < 2:
        raise ValueError("bits must be at least 2")
    n = secrets.randbits(bits - 1)
    return (1 << (bits - 1)) | n | 1


def miller_rabin(n: int, witnesses: Iterable[int] | None = None) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    For composite ``n``, returns False. For prime ``n``, may rarely return False
    if ``witnesses`` is a small random set; use ``_DETERMINISTIC_WITNESSES_64`` for
    64-bit ``n``.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as d * 2^s with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    if witnesses is None:
        witnesses = (secrets.randbelow(n - 3) + 2 for _ in range(16))

    for a in witnesses:
        if a < 2 or a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_probable_prime(n: int, bits_hint: int | None = None) -> bool:
    """Primality check with deterministic witnesses when ``n < 2^64``."""
    if n < 2**64:
        return miller_rabin(n, _DETERMINISTIC_WITNESSES_64)
    return miller_rabin(n)


def random_prime(bits: int, max_attempts: int = 10_000) -> int:
    """
    Generate a random probable prime of bit length ``bits``.

    Raises ``RuntimeError`` if no candidate is found within ``max_attempts``.
    """
    for _ in range(max_attempts):
        candidate = _rand_odd(bits)
        if is_probable_prime(candidate, bits):
            return candidate
    raise RuntimeError(f"failed to generate {bits}-bit prime after {max_attempts} attempts")


def random_safe_prime(bits: int, max_attempts: int = 10_000) -> tuple[int, int]:
    """
    Generate a safe prime ``p = 2q + 1`` where ``q`` is also prime.

    ``bits`` is the desired bit length of ``p``. Returns ``(p, q)``.
    """
    if bits < 6:
        raise ValueError("safe prime bit length too small")
    q_bits = bits - 1
    for _ in range(max_attempts):
        q = random_prime(q_bits)
        p = 2 * q + 1
        if p.bit_length() != bits:
            continue
        if is_probable_prime(p, bits):
            return p, q
    raise RuntimeError(f"failed to generate {bits}-bit safe prime after {max_attempts} attempts")
