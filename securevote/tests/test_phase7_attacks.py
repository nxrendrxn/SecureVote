"""
Phase 7: Full attack-scenario test coverage.

Each row from the spec table is covered by exactly one test function.

| # | Scenario                                    | Expected outcome                    |
|---|---------------------------------------------|-------------------------------------|
| 1 | valid ballot                                | accepted                            |
| 2 | double vote                                 | rejected: already_voted             |
| 3 | voter not on roll                           | rejected: not_registered            |
| 4 | signature altered                           | rejected: invalid_signature         |
| 5 | ciphertext modified after signing           | rejected: invalid_signature         |
| 6 | ballot encrypting m=5 with forged proof     | rejected: invalid_zkp               |
| 7 | ballot encrypting m=-1                      | rejected: invalid_zkp               |
| 8 | tally with k trustees                       | correct result                      |
| 9 | tally with k-1 trustees                     | fails (ValueError)                  |
|10 | trustee gives wrong partial decryption      | detected via proof; tally OK if ≥k  |
|11 | board entry deleted                         | chain fails, first bad index reported|
|12 | board entry edited                          | chain fails, first bad index reported|
|13 | published total altered                     | audit fails                         |

All tests use "test" params (~64-bit safe prime) for speed.
"""

from __future__ import annotations

import dataclasses
import secrets
from typing import Tuple

import pytest

from securevote.crypto import elgamal, threshold
from securevote.crypto.hashing import canonical_json
from securevote.crypto.params import GroupParams
from securevote.crypto.rsa_sign import sign_message
from securevote.crypto.zkp import BitProof, prove_bit
from securevote.election.authority import Authority, CastError
from securevote.election.board import verify_chain
from securevote.election.models import TallyResult
from securevote.election.verifier import Verifier

ELECTION_ID = "test-election-phase7"


# ---------------------------------------------------------------------------
# Shared fixture — one Authority with 5 voters, 3-of-5 threshold
# ---------------------------------------------------------------------------


@pytest.fixture
def auth() -> Authority:
    """
    Fresh Authority per test:
      - 5 voters, 5 trustees, threshold k=3
      - No votes cast yet; election is open
    """
    a = Authority(ELECTION_ID)
    a.setup(n_voters=5, n_trustees=5, threshold=3, params_mode="test")
    a.register(count=5)
    return a


def _vid(i: int) -> str:
    return f"voter-{i:03d}"


def _cast_all_yes(a: Authority, n: int = 5) -> None:
    for i in range(1, n + 1):
        a.cast(_vid(i), 1)


def _make_verifier(a: Authority, tally_override: TallyResult | None = None) -> Verifier:
    """Build a Verifier for a tallied Authority, optionally injecting a corrupt tally."""
    from securevote.crypto.params import GroupParams  # noqa: PLC0415
    config = a.config
    params = GroupParams(p=config.p, q=config.q, g=config.g)
    tally = tally_override if tally_override is not None else a.tally_result
    assert tally is not None

    agg_ct = (tally.agg_c1, tally.agg_c2)
    active_shares = {tid: a._shares[tid] for tid in a.tally_result.trustee_ids_used}  # noqa: SLF001
    active_vkeys = {tid: a._vkeys[tid] for tid in active_shares}  # noqa: SLF001
    partials = threshold.partials_from_shares(params, active_shares, agg_ct)
    proofs = threshold.proofs_from_shares(params, active_shares, active_vkeys, agg_ct)

    return Verifier(
        config=config,
        board=a.board,
        voter_roll=a.voter_roll,
        params=params,
        tally=tally,
        trustee_partials=partials,
        trustee_proofs=proofs,
    )


# ---------------------------------------------------------------------------
# Helpers that inject adversarial ballots
# ---------------------------------------------------------------------------


def _signed_ballot(
    a: Authority,
    voter_id: str,
    ciphertext: Tuple[int, int],
    proof: BitProof,
) -> int:
    """Sign a (ciphertext, proof) pair with voter_id's RSA private key."""
    kp = a.get_voter_private_key(voter_id)
    msg = a._ballot_message(ciphertext, proof)  # noqa: SLF001
    return sign_message(kp, msg)


# ===========================================================================
# 1. Valid ballot — accepted
# ===========================================================================


def test_01_valid_ballot_accepted(auth: Authority) -> None:
    """A correctly formed ballot for a registered voter must be accepted."""
    receipt = auth.cast(_vid(1), 1)
    assert isinstance(receipt, str) and len(receipt) == 64
    assert auth.board.has_voted(_vid(1))


# ===========================================================================
# 2. Double vote — rejected: already_voted
# ===========================================================================


def test_02_double_vote_rejected(auth: Authority) -> None:
    """A voter who has already cast a ballot must be rejected on the second attempt."""
    auth.cast(_vid(1), 1)
    with pytest.raises(CastError) as exc_info:
        auth.cast(_vid(1), 0)
    assert exc_info.value.reason == "already_voted"


# ===========================================================================
# 3. Voter not on roll — rejected: not_registered
# ===========================================================================


def test_03_unregistered_voter_rejected(auth: Authority) -> None:
    """Voter ID not in the roll must be rejected before any other check."""
    with pytest.raises(CastError) as exc_info:
        auth.cast("voter-999", 1)
    assert exc_info.value.reason == "not_registered"


# ===========================================================================
# 4. Signature altered — rejected: invalid_signature
# ===========================================================================


def test_04_altered_signature_rejected(auth: Authority) -> None:
    """
    Build a valid ballot, then flip one bit in the RSA signature.
    The authority must reject it as invalid_signature.
    """
    params = auth.params
    r = secrets.randbelow(params.q) or 1
    ct = elgamal.encrypt(params, auth.config.h, 1, randomness=r)
    proof = prove_bit(1, r, ct, auth.config.h, params, ELECTION_ID)
    good_sig = _signed_ballot(auth, _vid(1), ct, proof)
    bad_sig = good_sig ^ 1  # flip lowest bit

    with pytest.raises(CastError) as exc_info:
        auth.cast(_vid(1), 1, _ciphertext=ct, _proof=proof, _signature=bad_sig)
    assert exc_info.value.reason == "invalid_signature"


# ===========================================================================
# 5. Ciphertext modified after signing — rejected: invalid_signature
# ===========================================================================


def test_05_ciphertext_modified_after_signing_rejected(auth: Authority) -> None:
    """
    Adversary signs the original (ct, proof), then swaps in a different ct.
    The signature covers the original ct so the new ct's signature check fails.
    """
    params = auth.params
    r = secrets.randbelow(params.q) or 1
    ct_orig = elgamal.encrypt(params, auth.config.h, 1, randomness=r)
    proof = prove_bit(1, r, ct_orig, auth.config.h, params, ELECTION_ID)
    sig = _signed_ballot(auth, _vid(1), ct_orig, proof)

    # Alter c2 by adding 1 mod p — still a valid group element structurally,
    # but the signature won't verify against the modified ballot.
    bad_ct = (ct_orig[0], (ct_orig[1] + 1) % params.p)

    with pytest.raises(CastError) as exc_info:
        auth.cast(_vid(1), 1, _ciphertext=bad_ct, _proof=proof, _signature=sig)
    assert exc_info.value.reason == "invalid_signature"


# ===========================================================================
# 6. Ballot encrypting m=5 with forged proof — rejected: invalid_zkp
# ===========================================================================


def test_06_forged_zkp_m5_rejected(auth: Authority) -> None:
    """
    Adversary encrypts m=5 and submits with a proof for m=0 against a
    different (valid) ciphertext.  Signature covers (ct5, proof0) so it
    passes (a); the ZKP check must catch it.
    """
    params = auth.params
    r5 = secrets.randbelow(params.q) or 1
    ct5 = elgamal.encrypt(params, auth.config.h, 5, randomness=r5)

    r0 = secrets.randbelow(params.q) or 1
    ct0 = elgamal.encrypt(params, auth.config.h, 0, randomness=r0)
    proof0 = prove_bit(0, r0, ct0, auth.config.h, params, ELECTION_ID)

    # Sign the adversarial combination so the sig check passes.
    sig = _signed_ballot(auth, _vid(1), ct5, proof0)

    with pytest.raises(CastError) as exc_info:
        auth.cast(_vid(1), 0, _ciphertext=ct5, _proof=proof0, _signature=sig)
    assert exc_info.value.reason == "invalid_zkp"


# ===========================================================================
# 7. Ballot encrypting m=-1 — rejected: invalid_zkp
# ===========================================================================


def test_07_forged_zkp_neg1_rejected(auth: Authority) -> None:
    """
    Adversary constructs Enc(-1) = (g^r, g^{q-1} * h^r) — encrypts m = q-1.
    Submits with a proof for m=0; signature covers the pair.
    ZKP check must fail because the proof doesn't match the ciphertext.
    """
    params = auth.params
    r = secrets.randbelow(params.q) or 1
    c1 = pow(params.g, r, params.p)
    # g^{-1} = g^{q-1} since g^q ≡ 1; c2 = g^{-1} * h^r
    c2 = (pow(params.g, params.q - 1, params.p) * pow(auth.config.h, r, params.p)) % params.p
    bad_ct = (c1, c2)

    r0 = secrets.randbelow(params.q) or 1
    ct0 = elgamal.encrypt(params, auth.config.h, 0, randomness=r0)
    proof0 = prove_bit(0, r0, ct0, auth.config.h, params, ELECTION_ID)

    sig = _signed_ballot(auth, _vid(1), bad_ct, proof0)

    with pytest.raises(CastError) as exc_info:
        auth.cast(_vid(1), 0, _ciphertext=bad_ct, _proof=proof0, _signature=sig)
    assert exc_info.value.reason == "invalid_zkp"


# ===========================================================================
# 8. Tally with exactly k trustees — correct result
# ===========================================================================


def test_08_tally_with_k_trustees_correct(auth: Authority) -> None:
    """
    Cast 3 YES and 2 NO, close, tally with exactly k=3 trustees.
    Result must be total_yes == 3.
    """
    for i in range(1, 4):
        auth.cast(_vid(i), 1)   # YES
    for i in range(4, 6):
        auth.cast(_vid(i), 0)   # NO
    auth.close()
    result = auth.tally([1, 2, 3])
    assert result.total_yes == 3


# ===========================================================================
# 9. Tally with k-1 trustees — fails
# ===========================================================================


def test_09_tally_with_k_minus_1_trustees_fails(auth: Authority) -> None:
    """
    Providing only k-1=2 trustees must raise ValueError (insufficient shares).
    """
    _cast_all_yes(auth)
    auth.close()
    with pytest.raises(ValueError):
        auth.tally([1, 2])  # k=3, only 2 provided


# ===========================================================================
# 10. Trustee gives wrong partial decryption — detected via proof
# ===========================================================================


def test_10_wrong_partial_decryption_detected(auth: Authority) -> None:
    """
    Corrupt trustee 3's Shamir share so its partial won't verify.
    With 5 trustees and k=3, the bad one is excluded; the remaining
    4 honest trustees still produce the correct tally.
    """
    _cast_all_yes(auth)
    auth.close()

    # Corrupt trustee 3's share.
    auth._shares[3] = (auth._shares[3] + 1) % auth.params.q  # noqa: SLF001

    # Tally using trustees 1-4; trustee 3 will be excluded via its bad proof.
    result = auth.tally([1, 2, 3, 4])
    assert result.total_yes == 5


# ===========================================================================
# 11. Board entry deleted — chain fails, first bad index reported
# ===========================================================================


def test_11_board_entry_deleted_chain_fails(auth: Authority) -> None:
    """
    Delete entry at index 1.  verify_chain() must return a non-None index ≤ 1.
    """
    _cast_all_yes(auth)
    del auth.board._entries[1]  # noqa: SLF001
    bad_idx = verify_chain(auth.board)
    assert bad_idx is not None
    # The first bad index is the new position 1 (index mismatch or prev_hash mismatch).
    assert bad_idx <= 1


# ===========================================================================
# 12. Board entry edited — chain fails, first bad index reported
# ===========================================================================


def test_12_board_entry_edited_chain_fails(auth: Authority) -> None:
    """
    Edit entry 2 by changing its voter_id field.
    verify_chain() must return 2 (recomputed hash won't match).
    """
    _cast_all_yes(auth)
    raw = auth.board._entries  # noqa: SLF001
    tampered = dataclasses.replace(raw[2], voter_id="TAMPERED")
    raw[2] = tampered
    bad_idx = verify_chain(auth.board)
    assert bad_idx == 2


# ===========================================================================
# 13. Published total altered — audit fails
# ===========================================================================


def test_13_published_total_altered_audit_fails(auth: Authority) -> None:
    """
    Tally correctly, then change total_yes in the published TallyResult.
    The verifier's check_published_total must fail, and audit() must return
    passed == False.
    """
    _cast_all_yes(auth)
    auth.close()
    auth.tally([1, 2, 3])

    real_total = auth.tally_result.total_yes
    corrupt_tally = dataclasses.replace(auth.tally_result, total_yes=real_total + 99)

    verifier = _make_verifier(auth, tally_override=corrupt_tally)
    # Inject the corrupt tally into the verifier.
    verifier._tally = corrupt_tally  # noqa: SLF001

    r = verifier.check_published_total()
    assert not r.passed, f"expected failure but got: {r.detail}"

    result = verifier.audit()
    assert not result.passed
