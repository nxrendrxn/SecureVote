"""
Append-only bulletin board for SecureVote.

Every cast ballot is appended as a ``BoardEntry`` to the ``BulletinBoard``.
Entries are linked by a SHA-256 hash chain so that any deletion, edit, or
reordering is detectable.

Hash-chain construction
-----------------------
  genesis_prev_hash = "0" * 64  (64 hex zeros)

  entry_hash_i = SHA-256(
      UTF-8(prev_hash_hex_{i-1})  ||  canonical_json(entry_fields_i)
  )

where ``entry_fields_i`` contains everything *except* the two hash fields
(``prev_hash`` and ``entry_hash``); those are computed, not input.

Public API
----------
BoardEntry          Frozen dataclass for one board entry.
BulletinBoard       Append-only container; raises after ``close()``.
verify_chain(board) Check every link; return index of first broken link or None.
voter_receipt(...)  Compute a receipt token for a voter (re-exported from hashing).
check_receipt(...)  Check a receipt token against entries on the board.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from securevote.crypto.hashing import (
    entry_hash as _entry_hash,
    voter_receipt as _voter_receipt,
)

# The canonical prev_hash for the very first entry.
GENESIS_PREV_HASH: str = "0" * 64

# Re-export so callers only need to import from this module.
voter_receipt = _voter_receipt


# ---------------------------------------------------------------------------
# BoardEntry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoardEntry:
    """
    One immutable entry on the bulletin board.

    Fields
    ------
    index : int
        0-based position of this entry on the board (matches list index).
    voter_id : str
        Unique identifier for the voter.
    ballot : dict
        Serialisable ballot payload — must include at least ``ciphertext``
        (as a 2-element list ``[c1, c2]``) and ``proof`` (BitProof fields).
    signature : int
        RSA-PKCS1-v1_5 signature integer produced by the voter's key.
    timestamp : str
        ISO-8601 timestamp string set at cast time.
    prev_hash : str
        64-character hex string — the ``entry_hash`` of the preceding entry,
        or ``GENESIS_PREV_HASH`` for index 0.
    entry_hash : str
        SHA-256( UTF-8(prev_hash) || canonical_json(entry_fields) ) as 64-char hex.
        ``entry_fields`` includes index, voter_id, ballot, signature, timestamp
        (NOT prev_hash or entry_hash themselves).
    """

    index: int
    voter_id: str
    ballot: Dict[str, Any]
    signature: int
    timestamp: str
    prev_hash: str
    entry_hash: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _compute_entry_hash(
    index: int,
    voter_id: str,
    ballot: Dict[str, Any],
    signature: int,
    timestamp: str,
    prev_hash: str,
) -> str:
    """
    Compute the canonical ``entry_hash`` for an entry's fields.

    Only the content fields (not prev_hash / entry_hash) enter the inner
    canonical_json; prev_hash is prepended as raw UTF-8 bytes outside that
    JSON so it cannot be confused with a field value.
    """
    entry_fields: Dict[str, Any] = {
        "ballot": ballot,
        "index": index,
        "signature": signature,
        "timestamp": timestamp,
        "voter_id": voter_id,
    }
    return _entry_hash(prev_hash, entry_fields)


# ---------------------------------------------------------------------------
# BulletinBoard
# ---------------------------------------------------------------------------


class BulletinBoard:
    """
    Append-only bulletin board.

    Entries are stored in an internal list ordered by index.  Once ``close()``
    is called, no further appends are accepted (mimicking election close).

    Parameters
    ----------
    election_id : str
        Identifier embedded in voter receipts.

    Usage
    -----
    >>> board = BulletinBoard("election-2026")
    >>> entry = board.append(voter_id="v1", ballot={...}, signature=..., timestamp=...)
    >>> board.close()
    >>> broken = verify_chain(board)   # None → chain intact
    """

    def __init__(self, election_id: str) -> None:
        self._election_id: str = election_id
        self._entries: List[BoardEntry] = []
        self._closed: bool = False
        self._voter_set: set[str] = set()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def election_id(self) -> str:
        """The election identifier passed at construction."""
        return self._election_id

    @property
    def entries(self) -> List[BoardEntry]:
        """Read-only view of the entry list (a shallow copy)."""
        return list(self._entries)

    @property
    def is_closed(self) -> bool:
        """True after ``close()`` has been called."""
        return self._closed

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append(
        self,
        *,
        voter_id: str,
        ballot: Dict[str, Any],
        signature: int,
        timestamp: str,
    ) -> BoardEntry:
        """
        Append a new entry to the board and return the created ``BoardEntry``.

        Parameters
        ----------
        voter_id : str
            Voter identifier (duplicate detection is advisory here; the
            authority layer enforces uniqueness before calling append).
        ballot : dict
            Serialisable ballot payload.
        signature : int
            Voter's RSA signature integer.
        timestamp : str
            ISO-8601 timestamp string.

        Raises
        ------
        RuntimeError
            If the board has been closed.
        """
        if self._closed:
            raise RuntimeError("bulletin board is closed; no further entries accepted")

        index = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH

        eh = _compute_entry_hash(index, voter_id, ballot, signature, timestamp, prev_hash)

        entry = BoardEntry(
            index=index,
            voter_id=voter_id,
            ballot=ballot,
            signature=signature,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=eh,
        )
        self._entries.append(entry)
        self._voter_set.add(voter_id)
        return entry

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Freeze the board; subsequent ``append`` calls raise ``RuntimeError``."""
        self._closed = True

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------

    def has_voted(self, voter_id: str) -> bool:
        """Return True if ``voter_id`` already has an entry on the board."""
        return voter_id in self._voter_set

    def entry_for_voter(self, voter_id: str) -> Optional[BoardEntry]:
        """Return the first ``BoardEntry`` for ``voter_id``, or None."""
        for e in self._entries:
            if e.voter_id == voter_id:
                return e
        return None

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return (
            f"BulletinBoard(election_id={self._election_id!r}, "
            f"entries={len(self._entries)}, closed={self._closed})"
        )


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


def verify_chain(board: BulletinBoard) -> Optional[int]:
    """
    Walk every entry and verify the hash chain is intact.

    Checks for each entry ``i``:
    1. ``entry.prev_hash`` equals the previous entry's ``entry_hash``
       (or ``GENESIS_PREV_HASH`` for index 0).
    2. ``entry.entry_hash`` equals the value recomputed from the entry's fields.
    3. ``entry.index == i`` (catches reordering).

    Returns
    -------
    Optional[int]
        The 0-based index of the **first** broken entry, or ``None`` if the
        chain is fully intact.
    """
    entries = board.entries  # snapshot

    for i, entry in enumerate(entries):
        # 3. Index must match position.
        if entry.index != i:
            return i

        # 1. prev_hash must match predecessor.
        expected_prev = entries[i - 1].entry_hash if i > 0 else GENESIS_PREV_HASH
        if entry.prev_hash != expected_prev:
            return i

        # 2. entry_hash must be reproducible from content fields.
        recomputed = _compute_entry_hash(
            entry.index,
            entry.voter_id,
            entry.ballot,
            entry.signature,
            entry.timestamp,
            entry.prev_hash,
        )
        if entry.entry_hash != recomputed:
            return i

    return None  # chain intact


# ---------------------------------------------------------------------------
# check_receipt
# ---------------------------------------------------------------------------


def check_receipt(
    board: BulletinBoard,
    receipt_hex: str,
    voter_id: Optional[str] = None,
) -> Optional[BoardEntry]:
    """
    Verify that a voter receipt is present on the board.

    Searches all entries (or only entries for ``voter_id`` when supplied) for
    one whose receipt token matches ``receipt_hex``.

    Parameters
    ----------
    board : BulletinBoard
        The board to search.
    receipt_hex : str
        64-character hex receipt token as returned by ``voter_receipt()``.
    voter_id : str, optional
        Narrow the search to a specific voter's entries.

    Returns
    -------
    Optional[BoardEntry]
        The matching entry, or ``None`` if not found.
    """
    candidates = board.entries
    if voter_id is not None:
        candidates = [e for e in candidates if e.voter_id == voter_id]

    for entry in candidates:
        ct = entry.ballot.get("ciphertext")
        ts = entry.timestamp
        if ct is None:
            continue
        # Normalise: ciphertext may be stored as [c1, c2] list of ints or strings.
        try:
            c1 = int(ct[0])
            c2 = int(ct[1])
        except (TypeError, IndexError, ValueError):
            continue
        computed = _voter_receipt((c1, c2), board.election_id, ts)
        if computed == receipt_hex:
            return entry

    return None
