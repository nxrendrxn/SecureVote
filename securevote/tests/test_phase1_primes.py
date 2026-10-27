"""Tests for Miller-Rabin and safe prime generation."""

from __future__ import annotations

from securevote.crypto.primes import is_probable_prime, miller_rabin, random_safe_prime


def test_miller_rabin_known_primes() -> None:
    assert miller_rabin(2)
    assert miller_rabin(3)
    assert miller_rabin(65537)
    assert not miller_rabin(561)  # Carmichael number


def test_random_safe_prime_structure() -> None:
    p, q = random_safe_prime(64)
    assert p == 2 * q + 1
    assert p.bit_length() == 64
    assert is_probable_prime(p)
    assert is_probable_prime(q)
