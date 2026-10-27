"""
Phase 4: Tests for zkp.py (BitProof OR-proof and Chaum-Pedersen partial-decryption proof).

Coverage
--------
BitProof (prove_bit / verify_bit):
  - Valid proof for m=0 verifies.
  - Valid proof for m=1 verifies.
  - Ciphertext encrypting m=2, m=5, m=-1 with an honestly-generated OR-proof rejected.
    (These are caught by prove_bit's ValueError guard; we also test that a proof
     built for m=0 does NOT verify against the ciphertext of m=5.)
  - Each of the 8 proof fields tampered individually → rejected.
  - Proof for ciphertext A fails when checked against ciphertext B.
  - Proof fails under a different election_id.
  - Simulated-branch indistinguishability: over many runs, both m=0 and m=1 proofs
    verify and have identical structural types (no branch leakage in the proof
    shape itself).

PartialDecryptionProof (prove_partial_decryption / verify_partial_decryption):
  - Valid proof accepted.
  - Wrong d_i (honest proof against a different partial) rejected.
  - Wrong h_i rejected.
  - Wrong share (proof built with a different share, wrong d_i) rejected.
  - Tampered proof fields rejected.

Threshold integration (combine_partial_decryptions with verification):
  - All-valid partials → correct tally.
  - One bad partial excluded, tally still correct with remaining honest trustees.
  - Fewer than k honest trustees after exclusion → ValueError.
"""

from __future__ import annotations

import dataclasses
import secrets

import pytest

from securevote.crypto import elgamal, threshold
from securevote.crypto.params import GroupParams, load_params
from securevote.crypto.shamir import split_secret
from securevote.crypto.zkp import (
    BitProof,
    PartialDecryptionProof,
    prove_bit,
    prove_partial_decryption,
    verify_bit,
    verify_partial_decryption,
)

ELECTION_ID = "election-2026-test"
ALT_ELECTION_ID = "election-2027-different"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def params() -> GroupParams:
    """Fresh ~64-bit safe-prime params for fast tests."""
    return load_params("test")


@pytest.fixture(scope="module")
def keypair(params: GroupParams):
    """ElGamal keypair ``(x, h)``."""
    return elgamal.keygen(params)


@pytest.fixture(scope="module")
def enc0(params: GroupParams, keypair):
    """Fresh encryption of m=0."""
    _x, h = keypair
    r = secrets.randbelow(params.q) or 1
    ct = elgamal.encrypt(params, h, 0, randomness=r)
    return ct, r


@pytest.fixture(scope="module")
def enc1(params: GroupParams, keypair):
    """Fresh encryption of m=1."""
    _x, h = keypair
    r = secrets.randbelow(params.q) or 1
    ct = elgamal.encrypt(params, h, 1, randomness=r)
    return ct, r


# ---------------------------------------------------------------------------
# Helper: build a valid (m=0) proof quickly
# ---------------------------------------------------------------------------


def _fresh_bit_proof(m: int, params: GroupParams, h: int, election_id: str = ELECTION_ID):
    """Return ``(ciphertext, proof)`` for a fresh encryption of ``m``."""
    r = secrets.randbelow(params.q) or 1
    ct = elgamal.encrypt(params, h, m, randomness=r)
    proof = prove_bit(m, r, ct, h, params, election_id)
    return ct, proof


# ===========================================================================
# BitProof — valid proof verifies
# ===========================================================================


def test_bit_proof_m0_verifies(params: GroupParams, keypair) -> None:
    """A valid OR-proof for m=0 must verify."""
    _x, h = keypair
    ct, proof = _fresh_bit_proof(0, params, h)
    assert verify_bit(ct, proof, h, params, ELECTION_ID), "proof for m=0 should verify"


def test_bit_proof_m1_verifies(params: GroupParams, keypair) -> None:
    """A valid OR-proof for m=1 must verify."""
    _x, h = keypair
    ct, proof = _fresh_bit_proof(1, params, h)
    assert verify_bit(ct, proof, h, params, ELECTION_ID), "proof for m=1 should verify"


# ===========================================================================
# BitProof — out-of-range messages rejected
# ===========================================================================


@pytest.mark.parametrize("bad_m", [2, 5, -1])
def test_prove_bit_rejects_out_of_range_message(
    params: GroupParams, keypair, bad_m: int
) -> None:
    """prove_bit must raise ValueError for m not in {0, 1}."""
    _x, h = keypair
    r = secrets.randbelow(params.q) or 1
    # m=-1 is negative; encrypt only accepts 0 <= m < q, so we skip the encrypt call
    # and just test prove_bit directly with a ciphertext of m=0.
    ct = elgamal.encrypt(params, h, 0, randomness=r)
    with pytest.raises(ValueError):
        prove_bit(bad_m, r, ct, h, params, ELECTION_ID)


def test_bit_proof_for_m0_fails_against_ciphertext_of_m5(
    params: GroupParams, keypair
) -> None:
    """
    An OR-proof built for m=0 must NOT verify against a ciphertext of m=5.
    (Ciphertext encrypts a different message; the verifier should reject.)
    """
    _x, h = keypair
    ct0, proof0 = _fresh_bit_proof(0, params, h)
    # Encrypt m=5 (valid ElGamal; just not a ballot value)
    r5 = secrets.randbelow(params.q) or 1
    ct5 = elgamal.encrypt(params, h, 5, randomness=r5)
    # Proof built for ct0 must not verify for ct5.
    assert not verify_bit(ct5, proof0, h, params, ELECTION_ID)


# ===========================================================================
# BitProof — tampered fields
# ===========================================================================


_BIT_PROOF_FIELDS = ["a0", "b0", "a1", "b1", "e0", "e1", "z0", "z1"]


@pytest.mark.parametrize("field", _BIT_PROOF_FIELDS)
def test_bit_proof_tampered_field_rejected(
    params: GroupParams, keypair, field: str
) -> None:
    """Flipping any single field in the 8-tuple must cause verification to fail."""
    _x, h = keypair
    ct, proof = _fresh_bit_proof(0, params, h)

    orig_val = getattr(proof, field)
    # Add 1 mod q for challenge/response scalars, mod p for group elements.
    # We just add 1 (mod the relevant group order) — deterministically wrong.
    delta = (orig_val + 1) % params.p
    tampered = dataclasses.replace(proof, **{field: delta})
    assert not verify_bit(ct, tampered, h, params, ELECTION_ID), (
        f"tampered field '{field}' should cause rejection"
    )


# ===========================================================================
# BitProof — wrong ciphertext
# ===========================================================================


def test_bit_proof_wrong_ciphertext_rejected(params: GroupParams, keypair) -> None:
    """A proof for ciphertext A must not verify against a different ciphertext B."""
    _x, h = keypair
    ctA, proofA = _fresh_bit_proof(0, params, h)
    ctB, _proofB = _fresh_bit_proof(0, params, h)
    # ctA != ctB (negligible collision probability)
    assert ctA != ctB
    assert not verify_bit(ctB, proofA, h, params, ELECTION_ID)


# ===========================================================================
# BitProof — wrong election_id
# ===========================================================================


def test_bit_proof_wrong_election_id_rejected(params: GroupParams, keypair) -> None:
    """A proof bound to election_id A must not verify under election_id B."""
    _x, h = keypair
    ct, proof = _fresh_bit_proof(0, params, h, election_id=ELECTION_ID)
    assert not verify_bit(ct, proof, h, params, ALT_ELECTION_ID)


# ===========================================================================
# BitProof — simulated-branch indistinguishability
# ===========================================================================


def test_bit_proof_structure_indistinguishable(params: GroupParams, keypair) -> None:
    """
    Over N trials, every m=0 and m=1 proof verifies and has the same field count.

    Structural indistinguishability: an observer cannot tell from the shape of the
    proof which branch was real — both branches produce the same 8-tuple type.
    """
    _x, h = keypair
    N = 20
    for _ in range(N):
        ct0, p0 = _fresh_bit_proof(0, params, h)
        ct1, p1 = _fresh_bit_proof(1, params, h)
        # Both proofs must verify.
        assert verify_bit(ct0, p0, h, params, ELECTION_ID)
        assert verify_bit(ct1, p1, h, params, ELECTION_ID)
        # Both have the same type / same number of fields.
        assert type(p0) is BitProof
        assert type(p1) is BitProof
        assert len(dataclasses.fields(p0)) == len(dataclasses.fields(p1))


# ===========================================================================
# PartialDecryptionProof — valid accepted
# ===========================================================================


def test_pdp_valid_proof_accepted(params: GroupParams, keypair) -> None:
    """A correctly generated Chaum-Pedersen partial-decryption proof must verify."""
    x, _h = keypair
    ct = elgamal.encrypt(params, _h, 1, randomness=secrets.randbelow(params.q) or 1)
    h_i = pow(params.g, x, params.p)
    d_i = pow(ct[0], x, params.p)
    proof = prove_partial_decryption(x, h_i, ct, params)
    assert verify_partial_decryption(d_i, h_i, ct, proof, params)


# ===========================================================================
# PartialDecryptionProof — wrong d_i rejected
# ===========================================================================


def test_pdp_wrong_d_i_rejected(params: GroupParams, keypair) -> None:
    """Supplying a wrong partial decryption value must cause verification to fail."""
    x, _h = keypair
    ct = elgamal.encrypt(params, _h, 1, randomness=secrets.randbelow(params.q) or 1)
    h_i = pow(params.g, x, params.p)
    d_i = pow(ct[0], x, params.p)
    proof = prove_partial_decryption(x, h_i, ct, params)

    # Generate a different x (a second trustee share) to produce a wrong d_i.
    x_wrong = (x + 1) % params.q or 1
    d_i_wrong = pow(ct[0], x_wrong, params.p)
    assert not verify_partial_decryption(d_i_wrong, h_i, ct, proof, params)


# ===========================================================================
# PartialDecryptionProof — wrong h_i rejected
# ===========================================================================


def test_pdp_wrong_h_i_rejected(params: GroupParams, keypair) -> None:
    """Supplying a wrong verification key must cause verification to fail."""
    x, _h = keypair
    ct = elgamal.encrypt(params, _h, 1, randomness=secrets.randbelow(params.q) or 1)
    h_i = pow(params.g, x, params.p)
    d_i = pow(ct[0], x, params.p)
    proof = prove_partial_decryption(x, h_i, ct, params)

    # Wrong h_i: g^(x+1).
    x_other = (x + 1) % params.q or 1
    h_i_wrong = pow(params.g, x_other, params.p)
    assert not verify_partial_decryption(d_i, h_i_wrong, ct, proof, params)


# ===========================================================================
# PartialDecryptionProof — wrong share (proof and d_i built with wrong share)
# ===========================================================================


def test_pdp_wrong_share_rejected(params: GroupParams, keypair) -> None:
    """
    A proof built with share x_wrong and published as trustee-i (with h_i = g^x)
    must be rejected because d_i will not match log_g(h_i).
    """
    x, _h = keypair
    ct = elgamal.encrypt(params, _h, 1, randomness=secrets.randbelow(params.q) or 1)
    h_i = pow(params.g, x, params.p)  # real h_i

    # A different, wrong share.
    x_wrong = (x * 7 + 3) % params.q or 1
    h_i_wrong = pow(params.g, x_wrong, params.p)
    d_i_wrong = pow(ct[0], x_wrong, params.p)

    # Build proof with wrong share / wrong h_i.
    proof_wrong = prove_partial_decryption(x_wrong, h_i_wrong, ct, params)

    # Verify against the REAL h_i: must fail because d_i was computed with x_wrong.
    assert not verify_partial_decryption(d_i_wrong, h_i, ct, proof_wrong, params)


# ===========================================================================
# PartialDecryptionProof — tampered proof fields
# ===========================================================================


_PDP_PROOF_FIELDS = ["A", "B", "e", "z"]


@pytest.mark.parametrize("field", _PDP_PROOF_FIELDS)
def test_pdp_tampered_field_rejected(params: GroupParams, keypair, field: str) -> None:
    """Flipping any single field in the PartialDecryptionProof must fail verification."""
    x, _h = keypair
    ct = elgamal.encrypt(params, _h, 1, randomness=secrets.randbelow(params.q) or 1)
    h_i = pow(params.g, x, params.p)
    d_i = pow(ct[0], x, params.p)
    proof = prove_partial_decryption(x, h_i, ct, params)

    orig_val = getattr(proof, field)
    delta = (orig_val + 1) % params.p
    tampered = dataclasses.replace(proof, **{field: delta})
    assert not verify_partial_decryption(d_i, h_i, ct, tampered, params), (
        f"tampered PDP field '{field}' should cause rejection"
    )


# ===========================================================================
# Threshold integration — verified combine
# ===========================================================================


@pytest.fixture(scope="module")
def threshold_setup(params: GroupParams):
    """5-of-3 threshold setup: shares, h_i, d_i, proofs, and aggregate ciphertext."""
    x, h = elgamal.keygen(params)
    n, k = 5, 3
    shares = split_secret(x, n, k, params.q)

    votes = [1, 0, 1, 1, 0]
    agg = None
    for v in votes:
        r = secrets.randbelow(params.q) or 1
        ct = elgamal.encrypt(params, h, v, randomness=r)
        agg = ct if agg is None else elgamal.homomorphic_add(agg, ct, params.p)
    assert agg is not None

    vkeys = threshold.verification_keys_from_shares(params, shares)
    partials = threshold.partials_from_shares(params, shares, agg)
    proofs_map = threshold.proofs_from_shares(params, shares, vkeys, agg)

    return {
        "params": params,
        "x": x,
        "h": h,
        "n": n,
        "k": k,
        "shares": shares,
        "agg": agg,
        "votes": votes,
        "vkeys": vkeys,
        "partials": partials,
        "proofs": proofs_map,
        "expected": sum(votes),
    }


def test_threshold_all_valid_partials(threshold_setup) -> None:
    """All-valid partials with proof verification → correct tally."""
    s = threshold_setup
    # Use trustees 1, 2, 3 (a subset of size k).
    active_partials = {i: s["partials"][i] for i in (1, 2, 3)}
    active_vkeys = {i: s["vkeys"][i] for i in (1, 2, 3)}
    active_proofs = {i: s["proofs"][i] for i in (1, 2, 3)}
    result = threshold.threshold_decrypt(
        s["params"],
        s["agg"],
        active_partials,
        s["k"],
        max_m=10,
        verification_keys=active_vkeys,
        proofs=active_proofs,
    )
    assert result == s["expected"]


def test_threshold_bad_partial_excluded(threshold_setup) -> None:
    """
    One trustee supplies a wrong partial (a random value that won't verify).
    The combine step must exclude that trustee and still produce the correct tally
    because there are enough honest trustees (4 valid out of k=3 needed).
    """
    s = threshold_setup
    params = s["params"]

    # Use trustees 1–4 (k=3, so 1 bad still leaves 3 good).
    active_partials = {i: s["partials"][i] for i in (1, 2, 3, 4)}
    active_vkeys = {i: s["vkeys"][i] for i in (1, 2, 3, 4)}
    active_proofs = {i: s["proofs"][i] for i in (1, 2, 3, 4)}

    # Corrupt trustee 4's partial so their proof won't match.
    corrupt_d4 = (s["partials"][4] + 1) % params.p
    active_partials[4] = corrupt_d4  # wrong d_4 — proof was built with correct d_4

    # Should warn about trustee 4 and still produce the correct result.
    result = threshold.threshold_decrypt(
        params,
        s["agg"],
        active_partials,
        s["k"],
        max_m=10,
        verification_keys=active_vkeys,
        proofs=active_proofs,
    )
    assert result == s["expected"]


def test_threshold_insufficient_valid_partials_raises(threshold_setup) -> None:
    """
    If all supplied partials are invalid, the combine must raise ValueError
    (not enough valid partials for the threshold).
    """
    s = threshold_setup
    params = s["params"]

    # Corrupt ALL three partials.
    active_partials = {i: (s["partials"][i] + 1) % params.p for i in (1, 2, 3)}
    active_vkeys = {i: s["vkeys"][i] for i in (1, 2, 3)}
    active_proofs = {i: s["proofs"][i] for i in (1, 2, 3)}

    with pytest.raises(ValueError, match="insufficient partial"):
        threshold.combine_partial_decryptions(
            params,
            active_partials,
            s["k"],
            verification_keys=active_vkeys,
            proofs=active_proofs,
            ciphertext=s["agg"],
        )
