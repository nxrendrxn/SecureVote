"""Phase 1: ElGamal encrypt/decrypt and homomorphic addition."""

from __future__ import annotations

import pytest

from securevote.crypto import elgamal
from securevote.crypto.params import load_params, validate_subgroup_element


@pytest.fixture(scope="module")
def params():
    return load_params("test")


def test_demo_params_load() -> None:
    demo = load_params("demo")
    assert demo.p.bit_length() == 2048
    validate_subgroup_element(demo, demo.g)


@pytest.mark.parametrize("message", [0, 1, 2, 5])
def test_encrypt_decrypt_roundtrip(params, message: int) -> None:
    x, h = elgamal.keygen(params)
    ct = elgamal.encrypt(params, h, message, randomness=3)
    m = elgamal.decrypt(params, x, ct, max_m=10)
    assert m == message


def test_homomorphic_add_matches_sum(params) -> None:
    x, h = elgamal.keygen(params)
    m1, m2 = 1, 1
    ct1 = elgamal.encrypt(params, h, m1, randomness=11)
    ct2 = elgamal.encrypt(params, h, m2, randomness=22)
    agg = elgamal.homomorphic_add(ct1, ct2, params.p)
    total = elgamal.decrypt(params, x, agg, max_m=10)
    assert total == m1 + m2


def test_decrypt_fails_when_message_out_of_search_range(params) -> None:
    x, h = elgamal.keygen(params)
    ct = elgamal.encrypt(params, h, 15, randomness=7)
    with pytest.raises(ValueError, match="discrete log not found"):
        elgamal.decrypt(params, x, ct, max_m=10)


def test_invalid_subgroup_element_rejected(params) -> None:
    x, h = elgamal.keygen(params)
    c1, c2 = elgamal.encrypt(params, h, 1, randomness=5)
    bad_c1 = 2
    while bad_c1 < params.p and pow(bad_c1, params.q, params.p) == 1:
        bad_c1 += 1
    assert bad_c1 < params.p
    with pytest.raises(ValueError, match="subgroup"):
        elgamal.decrypt_value(params, x, (bad_c1, c2))
