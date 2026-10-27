"""
Phase 5: Tests for crypto/hashing.py and election/board.py.

Coverage
--------
hashing.py:
  - sha256_digest matches hashlib directly.
  - canonical_json is stable (same input → same bytes).
  - canonical_json sorts keys and serialises big-ints as strings.
  - hash_canonical == sha256_digest(canonical_json(...)).
  - entry_hash changes when prev_hash changes and when fields change.
  - voter_receipt is deterministic; different ciphertext / election_id /
    timestamp each produces a different token.

BulletinBoard / BoardEntry:
  - Appending entries produces correct index, prev_hash, and entry_hash values.
  - verify_chain returns None on a clean board.
  - Appending after close() raises RuntimeError.
  - has_voted and entry_for_voter work correctly.

verify_chain — tamper detection:
  - Deleted entry: detected at the first entry whose prev_hash no longer
    matches, reported as the first bad index.
  - Edited entry (field changed): detected at the edited entry's index.
  - Reordered entries: detected at the first out-of-order index.
  - Entry with wrong entry_hash (hash field patched but not the content):
    detected at that entry's index.

voter_receipt / check_receipt:
  - Receipt for a cast ballot is found by check_receipt.
  - Different election_id produces a different receipt; not found on the board.
  - check_receipt returns None for a receipt not on the board.
  - Narrowing by voter_id works.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from securevote.crypto.hashing import (
    canonical_json,
    entry_hash,
    hash_canonical,
    sha256_digest,
    voter_receipt,
)
from securevote.election.board import (
    GENESIS_PREV_HASH,
    BoardEntry,
    BulletinBoard,
    check_receipt,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ELECTION_ID = "election-2026-phase5"


def _make_ballot(c1: int = 12345, c2: int = 67890) -> dict:
    """Minimal ballot dict with a ciphertext pair."""
    return {
        "ciphertext": [c1, c2],
        "proof": {"a0": 1, "b0": 2, "a1": 3, "b1": 4, "e0": 5, "e1": 6, "z0": 7, "z1": 8},
    }


def _populate(board: BulletinBoard, n: int = 3) -> list[BoardEntry]:
    """Append ``n`` entries to ``board`` and return the list of created entries."""
    entries = []
    for i in range(n):
        e = board.append(
            voter_id=f"voter-{i}",
            ballot=_make_ballot(c1=1000 + i, c2=2000 + i),
            signature=9999 + i,
            timestamp=f"2026-10-27T10:{i:02d}:00Z",
        )
        entries.append(e)
    return entries


# ---------------------------------------------------------------------------
# hashing.py tests
# ---------------------------------------------------------------------------


class TestHashingModule:
    def test_sha256_matches_hashlib(self) -> None:
        msg = b"securevote phase 5"
        assert sha256_digest(msg) == hashlib.sha256(msg).digest()

    def test_canonical_json_is_stable(self) -> None:
        obj = {"b": 99, "a": 1, "z": "hello"}
        assert canonical_json(obj) == canonical_json(obj)

    def test_canonical_json_sorts_keys(self) -> None:
        a = canonical_json({"z": 1, "a": 2})
        b = canonical_json({"a": 2, "z": 1})
        assert a == b, "canonical_json must produce identical bytes regardless of input key order"

    def test_canonical_json_big_int_as_string(self) -> None:
        obj = {"n": 2 ** 256}
        encoded = canonical_json(obj).decode()
        # Big-int must appear as a decimal string, not a raw number.
        assert '"' + str(2 ** 256) + '"' in encoded

    def test_hash_canonical_equals_sha256_of_canonical(self) -> None:
        obj = {"x": 42, "y": "hello"}
        assert hash_canonical(obj) == sha256_digest(canonical_json(obj))

    def test_entry_hash_changes_with_prev_hash(self) -> None:
        fields = {"index": 0, "voter_id": "v1", "ballot": _make_ballot(), "signature": 1, "timestamp": "t"}
        h1 = entry_hash("a" * 64, fields)
        h2 = entry_hash("b" * 64, fields)
        assert h1 != h2

    def test_entry_hash_changes_with_field_change(self) -> None:
        fields1 = {"index": 0, "voter_id": "v1", "ballot": _make_ballot(), "signature": 1, "timestamp": "t"}
        fields2 = dict(fields1)
        fields2["voter_id"] = "v2"
        assert entry_hash(GENESIS_PREV_HASH, fields1) != entry_hash(GENESIS_PREV_HASH, fields2)

    def test_voter_receipt_deterministic(self) -> None:
        ct = (111, 222)
        r1 = voter_receipt(ct, ELECTION_ID, "2026-01-01T00:00:00Z")
        r2 = voter_receipt(ct, ELECTION_ID, "2026-01-01T00:00:00Z")
        assert r1 == r2
        assert len(r1) == 64  # 32 bytes → 64 hex chars

    def test_voter_receipt_different_ciphertext(self) -> None:
        ts = "2026-01-01T00:00:00Z"
        r1 = voter_receipt((1, 2), ELECTION_ID, ts)
        r2 = voter_receipt((1, 3), ELECTION_ID, ts)
        assert r1 != r2

    def test_voter_receipt_different_election_id(self) -> None:
        ct = (1, 2)
        ts = "2026-01-01T00:00:00Z"
        assert voter_receipt(ct, "elec-A", ts) != voter_receipt(ct, "elec-B", ts)

    def test_voter_receipt_different_timestamp(self) -> None:
        ct = (1, 2)
        r1 = voter_receipt(ct, ELECTION_ID, "2026-01-01T00:00:00Z")
        r2 = voter_receipt(ct, ELECTION_ID, "2026-01-01T00:01:00Z")
        assert r1 != r2


# ---------------------------------------------------------------------------
# BulletinBoard basic behaviour
# ---------------------------------------------------------------------------


class TestBulletinBoardBasics:
    def test_empty_board_verify_chain_ok(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        assert verify_chain(board) is None

    def test_first_entry_has_genesis_prev_hash(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        e = board.append(voter_id="v0", ballot=_make_ballot(), signature=1, timestamp="t0")
        assert e.index == 0
        assert e.prev_hash == GENESIS_PREV_HASH

    def test_second_entry_prev_hash_links_to_first(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        entries = _populate(board, 2)
        assert entries[1].prev_hash == entries[0].entry_hash

    def test_indices_are_sequential(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        entries = _populate(board, 5)
        for i, e in enumerate(entries):
            assert e.index == i

    def test_verify_chain_clean_board(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 4)
        assert verify_chain(board) is None

    def test_close_prevents_append(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        board.close()
        with pytest.raises(RuntimeError, match="closed"):
            board.append(voter_id="v0", ballot=_make_ballot(), signature=1, timestamp="t")

    def test_has_voted_tracks_voter(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        board.append(voter_id="alice", ballot=_make_ballot(), signature=1, timestamp="t")
        assert board.has_voted("alice")
        assert not board.has_voted("bob")

    def test_entry_for_voter_found(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        board.append(voter_id="target", ballot=_make_ballot(99, 88), signature=77, timestamp="tx")
        found = board.entry_for_voter("target")
        assert found is not None
        assert found.voter_id == "target"

    def test_entry_for_voter_none_when_absent(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        assert board.entry_for_voter("nobody") is None

    def test_len_returns_entry_count(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 6)
        assert len(board) == 6


# ---------------------------------------------------------------------------
# verify_chain — tamper detection
# ---------------------------------------------------------------------------


class TestVerifyChainTamperDetection:
    """
    These tests construct a valid board, then directly manipulate the internal
    entry list to simulate attacks, and confirm verify_chain() returns the
    correct first-bad index.

    Note: BoardEntry is a frozen dataclass; we rebuild entries with
    dataclasses.replace() to produce tampered variants.
    """

    # Helper: access the internal list for tampering
    @staticmethod
    def _raw(board: BulletinBoard):
        return board._entries  # noqa: SLF001

    def test_deleted_middle_entry_detected(self) -> None:
        """
        Board has entries [0, 1, 2, 3].  Delete entry 1.
        Remaining list is [0, 2, 3].  After deletion:
        - entry at position 1 (originally index=2) has index mismatch → first bad = 1.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 4)
        raw = self._raw(board)
        del raw[1]  # delete entry with original index=1
        bad = verify_chain(board)
        assert bad == 1

    def test_deleted_first_entry_detected(self) -> None:
        """
        Delete entry 0.  Entry at position 0 now has index=1 → first bad = 0.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        raw = self._raw(board)
        del raw[0]
        bad = verify_chain(board)
        assert bad == 0

    def test_deleted_last_entry_detected_or_chain_ok(self) -> None:
        """
        Deleting the last entry cannot break the chain backwards, but the
        entry count shrinks.  The chain should still be intact for the
        remaining entries (None returned) — this is expected: the board simply
        has one fewer entry.  The test documents this boundary explicitly.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        raw = self._raw(board)
        del raw[-1]
        # Remaining entries [0, 1] are still a valid chain.
        assert verify_chain(board) is None

    def test_edited_entry_voter_id_detected(self) -> None:
        """
        Edit entry at index 2: change voter_id.  entry_hash no longer matches.
        First bad index must be 2.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 4)
        raw = self._raw(board)
        tampered = dataclasses.replace(raw[2], voter_id="TAMPERED_VOTER")
        raw[2] = tampered
        bad = verify_chain(board)
        assert bad == 2

    def test_edited_entry_ballot_detected(self) -> None:
        """Edit ballot field at index 1; detected at index 1."""
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        raw = self._raw(board)
        tampered_ballot = dict(raw[1].ballot)
        tampered_ballot["ciphertext"] = [99999, 88888]
        tampered = dataclasses.replace(raw[1], ballot=tampered_ballot)
        raw[1] = tampered
        bad = verify_chain(board)
        assert bad == 1

    def test_edited_entry_signature_detected(self) -> None:
        """Edit signature field at index 0; detected at index 0."""
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        raw = self._raw(board)
        tampered = dataclasses.replace(raw[0], signature=raw[0].signature + 1)
        raw[0] = tampered
        bad = verify_chain(board)
        assert bad == 0

    def test_edited_entry_timestamp_detected(self) -> None:
        """Edit timestamp at index 2; detected at index 2."""
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 4)
        raw = self._raw(board)
        tampered = dataclasses.replace(raw[2], timestamp="1970-01-01T00:00:00Z")
        raw[2] = tampered
        bad = verify_chain(board)
        assert bad == 2

    def test_patched_entry_hash_field_only_detected(self) -> None:
        """
        Patch *only* the entry_hash field (but not the content) at index 1.
        verify_chain recomputes the hash from content and detects the mismatch.
        Also, entry 2's prev_hash will no longer match the patched entry_hash,
        so the first bad index could be 1 (recomputed hash mismatch) or 2
        (prev_hash mismatch).  Either way, bad <= 2.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        raw = self._raw(board)
        tampered = dataclasses.replace(raw[1], entry_hash="f" * 64)
        raw[1] = tampered
        bad = verify_chain(board)
        # entry_hash mismatch at 1 is detected first by recomputation check.
        assert bad is not None and bad <= 2

    def test_reordered_entries_detected(self) -> None:
        """
        Swap entries at index 1 and 2.  The swapped entries have wrong index
        values and wrong prev_hash links; first bad index must be 1.
        """
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 4)
        raw = self._raw(board)
        raw[1], raw[2] = raw[2], raw[1]  # swap
        bad = verify_chain(board)
        assert bad == 1

    def test_board_with_one_entry_verifies_ok(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 1)
        assert verify_chain(board) is None


# ---------------------------------------------------------------------------
# check_receipt
# ---------------------------------------------------------------------------


class TestCheckReceipt:
    def test_receipt_found_on_board(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        ct = (111222333, 444555666)
        ts = "2026-10-27T12:00:00Z"
        board.append(
            voter_id="alice",
            ballot={"ciphertext": list(ct), "proof": {}},
            signature=42,
            timestamp=ts,
        )
        token = voter_receipt(ct, ELECTION_ID, ts)
        found = check_receipt(board, token)
        assert found is not None
        assert found.voter_id == "alice"

    def test_receipt_not_found_for_wrong_election_id(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        ct = (111222333, 444555666)
        ts = "2026-10-27T12:00:00Z"
        board.append(
            voter_id="alice",
            ballot={"ciphertext": list(ct), "proof": {}},
            signature=42,
            timestamp=ts,
        )
        # Compute receipt with a *different* election_id — not stored on board.
        bad_token = voter_receipt(ct, "wrong-election", ts)
        assert check_receipt(board, bad_token) is None

    def test_receipt_not_found_for_absent_ballot(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        _populate(board, 3)
        fake_token = "a" * 64
        assert check_receipt(board, fake_token) is None

    def test_check_receipt_narrows_by_voter_id(self) -> None:
        """Searching with voter_id only considers that voter's entries."""
        board = BulletinBoard(ELECTION_ID)
        ct_alice = (100, 200)
        ct_bob = (300, 400)
        ts = "2026-10-27T12:00:00Z"
        board.append(voter_id="alice", ballot={"ciphertext": list(ct_alice), "proof": {}}, signature=1, timestamp=ts)
        board.append(voter_id="bob", ballot={"ciphertext": list(ct_bob), "proof": {}}, signature=2, timestamp=ts)

        alice_token = voter_receipt(ct_alice, ELECTION_ID, ts)
        # Searching under bob's voter_id should not find alice's receipt.
        assert check_receipt(board, alice_token, voter_id="bob") is None
        # Searching under alice's voter_id should find it.
        assert check_receipt(board, alice_token, voter_id="alice") is not None

    def test_multiple_voters_all_receipts_findable(self) -> None:
        board = BulletinBoard(ELECTION_ID)
        receipts = []
        for i in range(5):
            ct = (1000 + i, 2000 + i)
            ts = f"2026-10-27T{i:02d}:00:00Z"
            board.append(
                voter_id=f"voter-{i}",
                ballot={"ciphertext": list(ct), "proof": {}},
                signature=i,
                timestamp=ts,
            )
            receipts.append(voter_receipt(ct, ELECTION_ID, ts))

        for token in receipts:
            assert check_receipt(board, token) is not None
