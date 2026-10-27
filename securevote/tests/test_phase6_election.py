"""
Phase 6: Unit tests for election/authority.py and election/verifier.py.

Does NOT test the CLI (no subprocess, no disk I/O).

Coverage — Authority
--------------------
- Full happy-path: setup → register → cast(yes/no) → close → tally → correct total.
- cast() validation order: (a) not_registered before (b) already_voted.
- Rejection: voter not on roll → "not_registered".
- Rejection: bad RSA signature → "invalid_signature".
- Rejection: signature for modified ciphertext → "invalid_signature".
- Rejection: already voted → "already_voted" (not_registered checked first).
- Rejection: invalid ZKP (ciphertext swapped for one the proof was not built for) → "invalid_zkp".
- Rejection: ciphertext encrypting m=5, proof for m=0 → "invalid_zkp".
- close() prevents further cast.
- tally() with fewer than k trustees raises ValueError.
- tally() requires closed election.
- tally() with a corrupted partial → excluded via proof, still succeeds if enough remain.
- Models round-trip: ElectionConfig, VoterRecord, CastBallot, TallyResult to/from dict.

Coverage — Verifier
-------------------
- All checks pass on a clean election.
- check_signatures fails when a signature is corrupted.
- check_zkps fails when a ZKP field is tampered on the board.
- check_chain fails when a board entry is deleted.
- check_aggregate fails when tally aggregate is wrong.
- check_published_total fails when total_yes is altered.
- audit() returns AuditResult.passed == True on clean election.
- audit() returns AuditResult.passed == False when any check fails.
"""

from __future__ import annotations

import dataclasses
import secrets
from typing import Optional

import pytest

from securevote.crypto import elgamal
from securevote.crypto.hashing import canonical_json
from securevote.crypto.params import GroupParams, load_params
from securevote.crypto.rsa_sign import sign_message
from securevote.crypto.zkp import BitProof, prove_bit
from securevote.election.authority import Authority, CastError
from securevote.election.board import BulletinBoard
from securevote.election.models import (
    CastBallot,
    ElectionConfig,
    TallyResult,
    TrusteeInfo,
    VoterRecord,
)
from securevote.election.verifier import AuditResult, Verifier


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ELECTION_ID = "test-election-phase6"


@pytest.fixture(scope="module")
def auth_setup():
    """
    A fully set-up Authority with 5 voters and 3-of-3 threshold.
    Returns the Authority (pre-register, no votes cast yet).
    """
    auth = Authority(ELECTION_ID)
    auth.setup(n_voters=5, n_trustees=3, threshold=3, params_mode="test")
    auth.register(count=5)
    return auth


@pytest.fixture
def fresh_auth():
    """Fresh Authority per test — cheap because it's 'test' params."""
    auth = Authority(ELECTION_ID)
    auth.setup(n_voters=5, n_trustees=3, threshold=3, params_mode="test")
    auth.register(count=5)
    return auth


def _voter_id(i: int) -> str:
    return f"voter-{i:03d}"


def _cast_all_yes(auth: Authority, count: int = 5) -> list[str]:
    """Cast YES for voters 1..count and return receipts."""
    return [auth.cast(_voter_id(i), 1) for i in range(1, count + 1)]


def _cast_mix(auth: Authority) -> list[str]:
    """Cast yes for 1,2,3 and no for 4,5 → total_yes = 3."""
    receipts = []
    for i in range(1, 4):
        receipts.append(auth.cast(_voter_id(i), 1))
    for i in range(4, 6):
        receipts.append(auth.cast(_voter_id(i), 0))
    return receipts


# ---------------------------------------------------------------------------
# Authority — happy path
# ---------------------------------------------------------------------------


class TestAuthorityHappyPath:
    def test_setup_creates_config(self, fresh_auth: Authority) -> None:
        cfg = fresh_auth.config
        assert cfg.election_id == ELECTION_ID
        assert cfg.n_trustees == 3
        assert cfg.threshold == 3
        assert cfg.status == "open"
        assert cfg.h > 1

    def test_register_creates_voter_roll(self, fresh_auth: Authority) -> None:
        roll = fresh_auth.voter_roll
        assert len(roll) == 5
        assert all(f"voter-{i:03d}" in roll for i in range(1, 6))

    def test_cast_yes_returns_receipt(self, fresh_auth: Authority) -> None:
        receipt = fresh_auth.cast("voter-001", 1)
        assert isinstance(receipt, str) and len(receipt) == 64

    def test_full_flow_3_yes_2_no(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_mix(auth)
        auth.close()
        result = auth.tally([1, 2, 3])
        assert result.total_yes == 3

    def test_full_flow_all_yes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        result = auth.tally([1, 2, 3])
        assert result.total_yes == 5

    def test_full_flow_all_no(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        for i in range(1, 6):
            auth.cast(_voter_id(i), 0)
        auth.close()
        result = auth.tally([1, 2, 3])
        assert result.total_yes == 0

    def test_close_sets_status(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        assert auth.config.status == "closed"

    def test_tally_sets_status_tallied(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        assert auth.config.status == "tallied"

    def test_board_length_matches_cast_count(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_mix(auth)
        assert len(auth.board) == 5


# ---------------------------------------------------------------------------
# Authority — cast rejection paths
# ---------------------------------------------------------------------------


class TestAuthorityCastRejections:
    def test_reject_not_registered(self, fresh_auth: Authority) -> None:
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-999", 1)
        assert exc_info.value.reason == "not_registered"

    def test_reject_already_voted(self, fresh_auth: Authority) -> None:
        fresh_auth.cast("voter-001", 1)
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-001", 0)
        assert exc_info.value.reason == "already_voted"

    def test_not_registered_before_already_voted(self, fresh_auth: Authority) -> None:
        """
        Validation order spec: (a) on roll + sig, then (b) already voted.
        If voter is not on roll, we must get not_registered, never already_voted.
        """
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-999", 1)
        assert exc_info.value.reason == "not_registered"

    def test_reject_bad_signature_random(self, fresh_auth: Authority) -> None:
        """Injecting a random int as signature should be rejected."""
        params = fresh_auth.params
        r = secrets.randbelow(params.q) or 1
        ct = elgamal.encrypt(params, fresh_auth.config.h, 1, randomness=r)
        proof = prove_bit(1, r, ct, fresh_auth.config.h, params, ELECTION_ID)
        bad_sig = secrets.randbelow(2 ** 512)
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-001", 1, _ciphertext=ct, _proof=proof, _signature=bad_sig)
        assert exc_info.value.reason == "invalid_signature"

    def test_reject_signature_over_different_ciphertext(self, fresh_auth: Authority) -> None:
        """
        Signature produced for ct_A but submitted with ct_B → invalid_signature.
        (ciphertext modified after signing)
        """
        params = fresh_auth.params
        kp = fresh_auth.get_voter_private_key("voter-001")
        r = secrets.randbelow(params.q) or 1
        ct = elgamal.encrypt(params, fresh_auth.config.h, 1, randomness=r)
        proof = prove_bit(1, r, ct, fresh_auth.config.h, params, ELECTION_ID)
        # Sign ct, then swap to a different ciphertext.
        original_msg = fresh_auth._ballot_message(ct, proof)
        sig = sign_message(kp, original_msg)
        bad_ct = (ct[0], (ct[1] + 1) % params.p)
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-001", 1, _ciphertext=bad_ct, _proof=proof, _signature=sig)
        assert exc_info.value.reason == "invalid_signature"

    def test_reject_invalid_zkp_wrong_ciphertext(self, fresh_auth: Authority) -> None:
        """
        Proof built for ct_A but submitted with ct_B where sig covers ct_B+proof_A.
        Signature passes (covers the submitted combination) but ZKP must fail.
        """
        params = fresh_auth.params
        kp = fresh_auth.get_voter_private_key("voter-001")
        r0 = secrets.randbelow(params.q) or 1
        ct0 = elgamal.encrypt(params, fresh_auth.config.h, 0, randomness=r0)
        proof0 = prove_bit(0, r0, ct0, fresh_auth.config.h, params, ELECTION_ID)
        # Use a completely different ciphertext (m=1) with proof for m=0.
        r1 = secrets.randbelow(params.q) or 1
        ct1 = elgamal.encrypt(params, fresh_auth.config.h, 1, randomness=r1)
        # Sign (ct1, proof0) — sig is valid for this pair.
        msg = fresh_auth._ballot_message(ct1, proof0)
        sig = sign_message(kp, msg)
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-001", 0, _ciphertext=ct1, _proof=proof0, _signature=sig)
        assert exc_info.value.reason == "invalid_zkp"

    def test_reject_zkp_for_m5_ciphertext(self, fresh_auth: Authority) -> None:
        """
        Ciphertext encrypting m=5 submitted with a proof for m=0. ZKP must fail.
        """
        params = fresh_auth.params
        kp = fresh_auth.get_voter_private_key("voter-001")
        r5 = secrets.randbelow(params.q) or 1
        ct5 = elgamal.encrypt(params, fresh_auth.config.h, 5, randomness=r5)
        r0 = secrets.randbelow(params.q) or 1
        ct0 = elgamal.encrypt(params, fresh_auth.config.h, 0, randomness=r0)
        proof0 = prove_bit(0, r0, ct0, fresh_auth.config.h, params, ELECTION_ID)
        msg = fresh_auth._ballot_message(ct5, proof0)
        sig = sign_message(kp, msg)
        with pytest.raises(CastError) as exc_info:
            fresh_auth.cast("voter-001", 0, _ciphertext=ct5, _proof=proof0, _signature=sig)
        assert exc_info.value.reason == "invalid_zkp"

    def test_reject_cast_after_close(self, fresh_auth: Authority) -> None:
        fresh_auth.cast("voter-001", 1)
        fresh_auth.close()
        with pytest.raises(RuntimeError, match="closed"):
            fresh_auth.cast("voter-002", 1)


# ---------------------------------------------------------------------------
# Authority — tally edge cases
# ---------------------------------------------------------------------------


class TestAuthorityTally:
    def test_tally_requires_closed_election(self, fresh_auth: Authority) -> None:
        _cast_all_yes(fresh_auth)
        with pytest.raises(RuntimeError, match="closed"):
            fresh_auth.tally([1, 2, 3])

    def test_tally_insufficient_trustees_raises(self, fresh_auth: Authority) -> None:
        _cast_all_yes(fresh_auth)
        fresh_auth.close()
        with pytest.raises(ValueError):
            fresh_auth.tally([1, 2])  # need 3, only 2 provided

    def test_tally_no_ballots_raises(self) -> None:
        auth = Authority(ELECTION_ID)
        auth.setup(n_voters=3, n_trustees=3, threshold=3, params_mode="test")
        auth.register(count=3)
        auth.close()
        with pytest.raises(ValueError, match="no ballots"):
            auth.tally([1, 2, 3])

    def test_tally_with_corrupted_partial_still_succeeds(self) -> None:
        """
        5 trustees, k=3. Corrupt trustee 4's partial → excluded; 3 of remaining 4 used.
        """
        auth = Authority(ELECTION_ID)
        auth.setup(n_voters=3, n_trustees=5, threshold=3, params_mode="test")
        auth.register(count=3)
        for i in range(1, 4):
            auth.cast(_voter_id(i), 1)
        auth.close()

        # Corrupt share 4 so its partial won't verify.
        auth._shares[4] = (auth._shares[4] + 1) % auth.params.q

        # Tally using 4 trustees (3 valid + 1 bad = still enough).
        result = auth.tally([1, 2, 3, 4])
        assert result.total_yes == 3


# ---------------------------------------------------------------------------
# Models — JSON round-trips
# ---------------------------------------------------------------------------


class TestModelsRoundTrip:
    def test_election_config_roundtrip(self, auth_setup: Authority) -> None:
        cfg = auth_setup.config
        d = cfg.to_dict()
        cfg2 = ElectionConfig.from_dict(d)
        assert cfg2.election_id == cfg.election_id
        assert cfg2.p == cfg.p
        assert cfg2.h == cfg.h
        assert len(cfg2.trustees) == len(cfg.trustees)

    def test_voter_record_roundtrip(self, auth_setup: Authority) -> None:
        record = auth_setup.voter_roll["voter-001"]
        d = record.to_dict()
        r2 = VoterRecord.from_dict(d)
        assert r2.voter_id == record.voter_id
        assert r2.rsa_n == record.rsa_n

    def test_tally_result_roundtrip(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        result = auth.tally([1, 2, 3])
        d = result.to_dict()
        r2 = TallyResult.from_dict(d)
        assert r2.total_yes == result.total_yes
        assert r2.agg_c1 == result.agg_c1
        assert r2.trustee_ids_used == result.trustee_ids_used


# ---------------------------------------------------------------------------
# Verifier — happy path (all checks pass)
# ---------------------------------------------------------------------------


def _build_verifier(auth: Authority, corrupt_total: Optional[int] = None) -> Verifier:
    """Build a Verifier from a tallied Authority, optionally corrupting total_yes."""
    from securevote.crypto import threshold as thresh
    config = auth.config
    params = auth.params
    tally = auth.tally_result
    if tally is None:
        raise RuntimeError("call tally first")

    agg_ct = (tally.agg_c1, tally.agg_c2)
    active_shares = {tid: auth._shares[tid] for tid in tally.trustee_ids_used}
    active_vkeys = {tid: auth._vkeys[tid] for tid in active_shares}
    partials = thresh.partials_from_shares(params, active_shares, agg_ct)
    proofs = thresh.proofs_from_shares(params, active_shares, active_vkeys, agg_ct)

    tally_to_use = tally
    if corrupt_total is not None:
        tally_to_use = dataclasses.replace(tally, total_yes=corrupt_total)

    return Verifier(
        config=config,
        board=auth.board,
        voter_roll=auth.voter_roll,
        params=params,
        tally=tally_to_use,
        trustee_partials=partials,
        trustee_proofs=proofs,
    )


class TestVerifierHappyPath:
    def test_all_checks_pass(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_mix(auth)
        auth.close()
        auth.tally([1, 2, 3])
        verifier = _build_verifier(auth)
        result = verifier.audit()
        assert result.passed, repr(result)

    def test_signatures_check_passes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        r = _build_verifier(auth).check_signatures()
        assert r.passed

    def test_zkps_check_passes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        r = _build_verifier(auth).check_zkps()
        assert r.passed

    def test_chain_check_passes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        r = _build_verifier(auth).check_chain()
        assert r.passed

    def test_aggregate_check_passes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        r = _build_verifier(auth).check_aggregate()
        assert r.passed

    def test_published_total_check_passes(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])
        r = _build_verifier(auth).check_published_total()
        assert r.passed, r.detail


# ---------------------------------------------------------------------------
# Verifier — individual failure injection
# ---------------------------------------------------------------------------


class TestVerifierFailures:
    def test_check_signatures_detects_corrupted_sig(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        # Corrupt the first entry's signature directly in the board.
        raw = auth.board._entries
        bad_entry = dataclasses.replace(raw[0], signature=raw[0].signature + 1)
        raw[0] = bad_entry

        r = _build_verifier(auth).check_signatures()
        assert not r.passed

    def test_check_zkps_detects_tampered_proof_field(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        # Tamper e0 in the proof of entry 0.
        raw = auth.board._entries
        ballot = dict(raw[0].ballot)
        proof = dict(ballot["proof"])
        proof["e0"] = str(int(proof["e0"]) + 1)
        ballot["proof"] = proof
        raw[0] = dataclasses.replace(raw[0], ballot=ballot)

        r = _build_verifier(auth).check_zkps()
        assert not r.passed

    def test_check_chain_detects_deleted_entry(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        # Delete entry 1 from the board.
        del auth.board._entries[1]

        r = _build_verifier(auth).check_chain()
        assert not r.passed

    def test_check_aggregate_detects_wrong_aggregate(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        # Corrupt the published aggregate.
        tally = auth.tally_result
        bad_tally = dataclasses.replace(tally, agg_c2=tally.agg_c2 + 1)
        auth._tally = bad_tally

        verifier = _build_verifier(auth)
        verifier._tally = bad_tally
        r = verifier.check_aggregate()
        assert not r.passed

    def test_check_published_total_detects_wrong_total(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        verifier = _build_verifier(auth, corrupt_total=99)
        r = verifier.check_published_total()
        assert not r.passed

    def test_audit_overall_false_on_any_failure(self, fresh_auth: Authority) -> None:
        auth = fresh_auth
        _cast_all_yes(auth)
        auth.close()
        auth.tally([1, 2, 3])

        verifier = _build_verifier(auth, corrupt_total=99)
        result = verifier.audit()
        assert not result.passed
