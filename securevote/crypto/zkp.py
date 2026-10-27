"""
Zero-knowledge proofs for SecureVote.

Two constructions are implemented:

1. **BitProof** — Cramer-Schoenmakers-Gennaro OR-proof (a.k.a. Chaum-Pedersen
   disjunctive proof) that an ElGamal ciphertext (c1, c2) encrypts either 0 or 1.
   Uses the Fiat-Shamir heuristic (ROM) to make it non-interactive.

2. **PartialDecryptionProof** — Chaum-Pedersen equality-of-discrete-logs proof
   that a trustee's partial decryption ``d_i = c1^{x_i}`` is consistent with the
   trustee's published verification key ``h_i = g^{x_i}``.  Proves
   ``log_g(h_i) = log_{c1}(d_i)`` without revealing ``x_i``.

All hash challenges are computed over sorted-key JSON with big-ints as decimal
strings, bound to an ``election_id`` string so proofs cannot be replayed across
elections.

References
----------
- Cramer, R., Gennaro, R., Schoenmakers, B. (1994). *A secure and optimally
  efficient multi-authority election scheme.*
- Chaum, D., Pedersen, T. P. (1992). *Wallet databases with observers.*
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Mapping

from securevote.crypto.elgamal import Ciphertext
from securevote.crypto.params import GroupParams, validate_subgroup_element

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_challenge(data: dict, params: GroupParams) -> int:
    """
    Compute a Fiat-Shamir challenge from a dictionary of field values.

    All values must be JSON-serialisable (ints serialised as decimal strings).
    The challenge is reduced modulo ``q``.
    """
    # Serialise big-ints as decimal strings so JSON handles arbitrary precision.
    canonical: dict[str, object] = {}
    for k in sorted(data.keys()):
        v = data[k]
        canonical[k] = str(v) if isinstance(v, int) else v
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest, "big") % params.q


def _mod_inverse(a: int, q: int) -> int:
    """Multiplicative inverse of ``a`` in ``Z_q`` (``q`` prime)."""
    return pow(a, -1, q)


# ---------------------------------------------------------------------------
# Part 4a — Ballot validity OR-proof  (BitProof)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BitProof:
    """
    Non-interactive Chaum-Pedersen disjunctive proof that a ciphertext encrypts
    0 or 1.

    Fields correspond to the two branches of the OR-proof:
    - ``a0, b0``: commitments for the branch claiming m=0
    - ``a1, b1``: commitments for the branch claiming m=1
    - ``e0, e1``: per-branch challenges (must satisfy e0+e1 ≡ e mod q)
    - ``z0, z1``: per-branch responses
    """

    a0: int
    b0: int
    a1: int
    b1: int
    e0: int
    e1: int
    z0: int
    z1: int


def _bit_challenge(
    election_id: str,
    h: int,
    ciphertext: Ciphertext,
    a0: int,
    b0: int,
    a1: int,
    b1: int,
    params: GroupParams,
) -> int:
    """
    Fiat-Shamir challenge for the BitProof, bound to ``election_id``.

    e = SHA-256(election_id || h || c1 || c2 || a0 || b0 || a1 || b1) mod q
    """
    c1, c2 = ciphertext
    return _sha256_challenge(
        {
            "election_id": election_id,
            "h": h,
            "c1": c1,
            "c2": c2,
            "a0": a0,
            "b0": b0,
            "a1": a1,
            "b1": b1,
        },
        params,
    )


def prove_bit(
    m: int,
    r: int,
    ciphertext: Ciphertext,
    h: int,
    params: GroupParams,
    election_id: str,
) -> BitProof:
    """
    Prove that ``ciphertext`` encrypts ``m ∈ {0, 1}`` under public key ``h``.

    Parameters
    ----------
    m:
        The actual plaintext (0 or 1).
    r:
        The ElGamal randomness used to produce ``ciphertext = (g^r, g^m * h^r)``.
    ciphertext:
        The ElGamal ciphertext ``(c1, c2)``.
    h:
        Election public key ``g^x mod p``.
    params:
        Group parameters ``(p, q, g)``.
    election_id:
        Unique election identifier bound into the Fiat-Shamir hash.

    Returns
    -------
    BitProof
        Non-interactive OR-proof ``(a0, b0, a1, b1, e0, e1, z0, z1)``.

    Raises
    ------
    ValueError
        If ``m`` is not 0 or 1.

    Notes
    -----
    Let j = m (the true branch) and s = 1 - j (the simulated branch).

    For branch i, define ``y_i = c2 * g^{-i} mod p`` so that
    ``(g, h, c1, y_i)`` is a DH-tuple iff m=i (both equal to exponent r).

    Simulate branch s:
      - pick random e_s, z_s ∈ Z_q
      - a_s = g^{z_s} * c1^{-e_s} mod p
      - b_s = h^{z_s} * y_s^{-e_s} mod p

    Commit to branch j:
      - pick random w ∈ Z_q (non-zero for safety)
      - a_j = g^w mod p
      - b_j = h^w mod p

    Fiat-Shamir: e = H(election_id, h, c1, c2, a0, b0, a1, b1) mod q
    Split: e_j = (e - e_s) mod q, z_j = (w + e_j * r) mod q
    """
    if m not in (0, 1):
        raise ValueError(f"message must be 0 or 1, got {m!r}")

    p, q, g = params.p, params.q, params.g
    c1, c2 = ciphertext
    validate_subgroup_element(params, h)
    validate_subgroup_element(params, c1)
    validate_subgroup_element(params, c2)

    j = m          # true branch
    s = 1 - j      # simulated branch

    # y_i = c2 / g^i mod p — the DH-tuple component for branch i.
    g_inv_0 = 1                              # g^0 = 1
    g_inv_1 = pow(g, q - 1, p)              # g^{-1} mod p (= g^{q-1} since g^q=1)
    y0 = (c2 * g_inv_0) % p                 # c2 / g^0 = c2
    y1 = (c2 * g_inv_1) % p                 # c2 / g^1 = c2 * g^{-1}

    y = [y0, y1]

    # ---- Simulate branch s ------------------------------------------------
    e_s = secrets.randbelow(q)
    z_s = secrets.randbelow(q)

    # c1^{-e_s} mod p = c1^{q - e_s} mod p  (Fermat, order divides q)
    c1_neg_es = pow(c1, (q - e_s) % q, p)
    # y_s^{-e_s} mod p
    ys_neg_es = pow(y[s], (q - e_s) % q, p)

    a_s = (pow(g, z_s, p) * c1_neg_es) % p
    b_s = (pow(h, z_s, p) * ys_neg_es) % p

    # ---- Real branch j (commit only) -------------------------------------
    w = secrets.randbelow(q)
    if w == 0:
        w = 1  # avoid degenerate commitment

    a_j = pow(g, w, p)
    b_j = pow(h, w, p)

    # ---- Assemble commitments in canonical order (0 first, 1 second) ------
    if j == 0:
        a0_val, b0_val = a_j, b_j
        a1_val, b1_val = a_s, b_s
    else:
        a0_val, b0_val = a_s, b_s
        a1_val, b1_val = a_j, b_j

    # ---- Fiat-Shamir challenge e -------------------------------------------
    e = _bit_challenge(election_id, h, ciphertext, a0_val, b0_val, a1_val, b1_val, params)

    # ---- Split challenge ---------------------------------------------------
    e_j = (e - e_s) % q
    z_j = (w + e_j * r) % q

    # ---- Assign per-branch values in canonical order ----------------------
    if j == 0:
        e0, e1 = e_j, e_s
        z0, z1 = z_j, z_s
    else:
        e0, e1 = e_s, e_j
        z0, z1 = z_s, z_j

    return BitProof(a0=a0_val, b0=b0_val, a1=a1_val, b1=b1_val, e0=e0, e1=e1, z0=z0, z1=z1)


def verify_bit(
    ciphertext: Ciphertext,
    proof: BitProof,
    h: int,
    params: GroupParams,
    election_id: str,
) -> bool:
    """
    Verify a BitProof OR-proof for ``ciphertext`` under public key ``h``.

    Returns ``True`` iff the proof is valid (ciphertext encrypts 0 or 1).

    Checks
    ------
    1. All eight proof components are valid group elements (in ``(1, p)`` and
       order divides ``q``).
    2. The Fiat-Shamir challenge is consistent: ``e0 + e1 ≡ e (mod q)`` where
       ``e = H(election_id, h, c1, c2, a0, b0, a1, b1)``.
    3. For each branch ``i ∈ {0, 1}``:
       - ``g^{z_i} ≡ a_i * c1^{e_i} (mod p)``
       - ``h^{z_i} ≡ b_i * y_i^{e_i} (mod p)``
    """
    p, q, g = params.p, params.q, params.g
    c1, c2 = ciphertext

    # 1. Validate all group elements in the proof.
    try:
        validate_subgroup_element(params, h)
        validate_subgroup_element(params, c1)
        validate_subgroup_element(params, c2)
        for val in (proof.a0, proof.b0, proof.a1, proof.b1):
            validate_subgroup_element(params, val)
    except ValueError:
        return False

    # Challenges and responses are integers in Z_q; validate range.
    if not all(0 <= x < q for x in (proof.e0, proof.e1, proof.z0, proof.z1)):
        return False

    # 2. Recompute and check global challenge.
    e = _bit_challenge(election_id, h, ciphertext, proof.a0, proof.b0, proof.a1, proof.b1, params)
    if (proof.e0 + proof.e1) % q != e % q:
        return False

    # 3. Verify both branches.
    # y_i = c2 * g^{-i} mod p
    y0 = c2 % p                             # c2 / g^0
    y1 = (c2 * pow(g, q - 1, p)) % p       # c2 / g^1

    y = [y0, y1]
    a = [proof.a0, proof.a1]
    b = [proof.b0, proof.b1]
    e_vals = [proof.e0, proof.e1]
    z_vals = [proof.z0, proof.z1]

    for i in range(2):
        # g^{z_i} == a_i * c1^{e_i}
        lhs_a = pow(g, z_vals[i], p)
        rhs_a = (a[i] * pow(c1, e_vals[i], p)) % p
        a_ok = hmac.compare_digest(
            lhs_a.to_bytes((lhs_a.bit_length() + 7) // 8 or 1, "big"),
            rhs_a.to_bytes((rhs_a.bit_length() + 7) // 8 or 1, "big"),
        )
        # h^{z_i} == b_i * y_i^{e_i}
        lhs_b = pow(h, z_vals[i], p)
        rhs_b = (b[i] * pow(y[i], e_vals[i], p)) % p
        b_ok = hmac.compare_digest(
            lhs_b.to_bytes((lhs_b.bit_length() + 7) // 8 or 1, "big"),
            rhs_b.to_bytes((rhs_b.bit_length() + 7) // 8 or 1, "big"),
        )
        if not (a_ok and b_ok):
            return False

    return True


# ---------------------------------------------------------------------------
# Part 4b — Partial-decryption Chaum-Pedersen proof
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PartialDecryptionProof:
    """
    Chaum-Pedersen proof of equality of discrete logarithms:
    ``log_g(h_i) = log_{c1}(d_i) = x_i``.

    Fields
    ------
    A:
        Commitment ``A = g^w mod p``.
    B:
        Commitment ``B = c1^w mod p``.
    e:
        Fiat-Shamir challenge ``e = H(g, c1, h_i, d_i, A, B) mod q``.
    z:
        Response ``z = (w + e * x_i) mod q``.
    """

    A: int
    B: int
    e: int
    z: int


def _pdp_challenge(
    g: int,
    c1: int,
    h_i: int,
    d_i: int,
    A: int,
    B: int,
    params: GroupParams,
) -> int:
    """
    Fiat-Shamir challenge for the partial-decryption proof.

    e = SHA-256(g || c1 || h_i || d_i || A || B) mod q
    """
    return _sha256_challenge(
        {"A": A, "B": B, "c1": c1, "d_i": d_i, "g": g, "h_i": h_i},
        params,
    )


def prove_partial_decryption(
    share_value: int,
    h_i: int,
    ciphertext: Ciphertext,
    params: GroupParams,
) -> PartialDecryptionProof:
    """
    Prove ``log_g(h_i) = log_{c1}(d_i)`` for trustee's share ``x_i``.

    Parameters
    ----------
    share_value:
        Trustee's Shamir share ``x_i`` (secret).
    h_i:
        Trustee's verification key ``g^{x_i} mod p`` (published).
    ciphertext:
        Aggregate ElGamal ciphertext ``(c1, c2)`` being partially decrypted.
    params:
        Group parameters.

    Returns
    -------
    PartialDecryptionProof
        ``(A, B, e, z)`` where ``d_i = c1^{x_i}`` can be verified externally.

    Notes
    -----
    Protocol:
      1. Pick random ``w ∈ Z_q``; ``A = g^w``, ``B = c1^w``.
      2. ``e = H(g, c1, h_i, d_i, A, B) mod q``.
      3. ``z = (w + e * x_i) mod q``.
    """
    p, q, g = params.p, params.q, params.g
    c1, _c2 = ciphertext
    validate_subgroup_element(params, c1)
    validate_subgroup_element(params, h_i)

    if not (0 < share_value < q):
        raise ValueError("share_value must be non-zero and in Z_q")

    # d_i = c1^{x_i} mod p
    d_i = pow(c1, share_value, p)
    validate_subgroup_element(params, d_i)

    # Commitment
    w = secrets.randbelow(q)
    if w == 0:
        w = 1
    A = pow(g, w, p)
    B = pow(c1, w, p)

    # Challenge
    e = _pdp_challenge(g, c1, h_i, d_i, A, B, params)

    # Response
    z = (w + e * share_value) % q

    return PartialDecryptionProof(A=A, B=B, e=e, z=z)


def verify_partial_decryption(
    d_i: int,
    h_i: int,
    ciphertext: Ciphertext,
    proof: PartialDecryptionProof,
    params: GroupParams,
) -> bool:
    """
    Verify a partial-decryption Chaum-Pedersen proof.

    Parameters
    ----------
    d_i:
        Claimed partial decryption ``c1^{x_i} mod p`` (trustee-supplied).
    h_i:
        Trustee verification key ``g^{x_i} mod p`` (public).
    ciphertext:
        Aggregate ciphertext ``(c1, c2)``.
    proof:
        The ``PartialDecryptionProof`` produced by ``prove_partial_decryption``.
    params:
        Group parameters.

    Returns
    -------
    bool
        ``True`` iff the proof is valid.

    Notes
    -----
    Verification equations:
      1. ``g^z ≡ A * h_i^e (mod p)``
      2. ``c1^z ≡ B * d_i^e (mod p)``
    """
    p, q, g = params.p, params.q, params.g
    c1, _c2 = ciphertext

    # Validate all group elements.
    try:
        validate_subgroup_element(params, c1)
        validate_subgroup_element(params, h_i)
        validate_subgroup_element(params, d_i)
        validate_subgroup_element(params, proof.A)
        validate_subgroup_element(params, proof.B)
    except ValueError:
        return False

    # Challenge and response in range.
    if not (0 <= proof.e < q and 0 <= proof.z < q):
        return False

    # Recompute challenge.
    e_check = _pdp_challenge(g, c1, h_i, d_i, proof.A, proof.B, params)
    if proof.e != e_check:
        return False

    # Equation 1: g^z == A * h_i^e
    lhs1 = pow(g, proof.z, p)
    rhs1 = (proof.A * pow(h_i, proof.e, p)) % p
    ok1 = hmac.compare_digest(
        lhs1.to_bytes((lhs1.bit_length() + 7) // 8 or 1, "big"),
        rhs1.to_bytes((rhs1.bit_length() + 7) // 8 or 1, "big"),
    )

    # Equation 2: c1^z == B * d_i^e
    lhs2 = pow(c1, proof.z, p)
    rhs2 = (proof.B * pow(d_i, proof.e, p)) % p
    ok2 = hmac.compare_digest(
        lhs2.to_bytes((lhs2.bit_length() + 7) // 8 or 1, "big"),
        rhs2.to_bytes((rhs2.bit_length() + 7) // 8 or 1, "big"),
    )

    return ok1 and ok2
