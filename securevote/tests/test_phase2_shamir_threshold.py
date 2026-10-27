"""Phase 2: Shamir sharing and threshold partial decryption."""

from __future__ import annotations

import pytest

from securevote.crypto import elgamal, threshold
from securevote.crypto.params import load_params
from securevote.crypto.shamir import lagrange_coefficient_at_zero, reconstruct_secret, split_secret


@pytest.fixture(scope="module")
def params():
    return load_params("test")


def test_shamir_reconstruct_with_k_shares(params) -> None:
    q = params.q
    secret = 42
    n, k = 5, 3
    shares = split_secret(secret, n, k, q)
    subset = {i: shares[i] for i in (1, 3, 5)}
    assert reconstruct_secret(subset, q) == secret


def test_shamir_k_minus_one_shares_wrong_secret(params) -> None:
    q = params.q
    secret = 99
    n, k = 5, 3
    shares = split_secret(secret, n, k, q)
    subset = {1: shares[1], 2: shares[2]}
    wrong = reconstruct_secret(subset, q)
    assert wrong != secret


def test_threshold_decrypt_matches_full_decrypt(params) -> None:
    x, h = elgamal.keygen(params)
    n, k = 5, 3
    shares = split_secret(x, n, k, params.q)

    votes = [1, 1, 0, 1]
    agg = None
    for v in votes:
        ct = elgamal.encrypt(params, h, v, randomness=7 + v)
        agg = ct if agg is None else elgamal.homomorphic_add(agg, ct, params.p)

    assert agg is not None
    expected = sum(votes)
    direct = elgamal.decrypt(params, x, agg, max_m=10)

    partials = threshold.partials_from_shares(params, shares, agg)
    active = {i: partials[i] for i in (2, 4, 5)}
    tally = threshold.threshold_decrypt(params, agg, active, k, max_m=10)
    assert tally == expected == direct


def test_threshold_k_minus_one_partials_rejected(params) -> None:
    x, h = elgamal.keygen(params)
    shares = split_secret(x, 5, 3, params.q)
    ct = elgamal.encrypt(params, h, 1, randomness=3)
    partials = threshold.partials_from_shares(params, shares, ct)
    subset = {1: partials[1], 2: partials[2]}
    with pytest.raises(ValueError, match="insufficient partial"):
        threshold.combine_partial_decryptions(params, subset, threshold=3)


def test_k_minus_one_partials_give_wrong_plaintext(params) -> None:
    """If combination is forced with k-1 shares, recovered sum must not match."""
    x, h = elgamal.keygen(params)
    shares = split_secret(x, 5, 3, params.q)
    ct = elgamal.encrypt(params, h, 2, randomness=5)
    truth = elgamal.decrypt(params, x, ct, max_m=10)

    partials = threshold.partials_from_shares(params, shares, ct)
    # Force Lagrange combine on two shares (invalid for degree-2 polynomial).
    ids = [1, 2]
    mask = 1
    for i in ids:
        lam = lagrange_coefficient_at_zero(i, ids, params.q)
        mask = (mask * pow(partials[i], lam, params.p)) % params.p
    c1, c2 = ct
    mask_inv = pow(mask, params.q - 1, params.p)
    t = (c2 * mask_inv) % params.p
    try:
        got = elgamal.brute_force_discrete_log(params, t, max_m=10)
    except ValueError:
        got = None
    assert got != truth
