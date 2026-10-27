"""
Group parameters for exponential ElGamal over a order-``q`` subgroup of Z_p^*.

We use a safe prime ``p = 2q + 1`` so the unique subgroup of order ``q`` is
the set of quadratic residues (for demo/test generated params). Generator ``g``
must satisfy ``g != 1`` and ``g^q ≡ 1 (mod p)`` but ``g != 1``.
"""

from __future__ import annotations

from dataclasses import dataclass

from securevote.crypto.primes import random_safe_prime

# RFC 3526 MODP Group 14 (2048-bit). Used for ``demo`` mode per project spec.
_RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF",
    16,
)
_RFC3526_GROUP14_G = 2


@dataclass(frozen=True)
class GroupParams:
    """Parameters ``(p, q, g)`` for ElGamal in the order-``q`` subgroup."""

    p: int
    q: int
    g: int

    def __post_init__(self) -> None:
        if self.p <= 2 or self.q <= 1:
            raise ValueError("invalid p or q")
        if self.p != 2 * self.q + 1:
            raise ValueError("p must be safe prime 2q+1")
        if not (1 < self.g < self.p):
            raise ValueError("g out of range")
        if pow(self.g, self.q, self.p) != 1:
            raise ValueError("g is not in the order-q subgroup")
        if self.g == 1:
            raise ValueError("g must not be 1")


def _subgroup_generator(p: int, q: int, seed: int) -> int:
    """
    Find a generator ``g`` of the unique order-``q`` subgroup (``q`` prime).

    For safe primes ``p = 2q + 1``, squaring a non-residue often yields order
    ``q``. RFC MODP uses ``g = 2`` for the full group; we map into the
    order-``q`` subgroup with a few cheap trials (no large linear search).
    """
    trials = (seed, 3, 5, 7, 11)
    for base in trials:
        if base >= p:
            continue
        for h in (base, pow(base, 2, p)):
            if h != 1 and pow(h, q, p) == 1:
                return h
    raise ValueError("could not find order-q subgroup generator")


def load_demo_params() -> GroupParams:
    """RFC 3526 Group 14 with ``g`` in the order-``q`` subgroup."""
    p = _RFC3526_GROUP14_P
    q = (p - 1) // 2
    # Group 14 prime is a safe prime; q is prime.
    g = _subgroup_generator(p, q, _RFC3526_GROUP14_G)
    return GroupParams(p=p, q=q, g=g)


def load_test_params() -> GroupParams:
    """Small (~64-bit) safe prime for fast, hand-traceable unit tests."""
    p, q = random_safe_prime(64)
    g = _subgroup_generator(p, q, 2)
    return GroupParams(p=p, q=q, g=g)


def load_params(mode: str) -> GroupParams:
    """Load group parameters: ``demo`` or ``test``."""
    if mode == "demo":
        return load_demo_params()
    if mode == "test":
        return load_test_params()
    raise ValueError(f"unknown params mode: {mode!r}")


def validate_subgroup_element(params: GroupParams, y: int) -> None:
    """
    Ensure ``y`` is in the order-``q`` subgroup before use in protocols.

    Raises ``ValueError`` if ``y^q != 1 (mod p)`` or ``y`` is out of range.
    """
    if not (1 < y < params.p):
        raise ValueError("group element out of range")
    if pow(y, params.q, params.p) != 1:
        raise ValueError("element not in order-q subgroup")
