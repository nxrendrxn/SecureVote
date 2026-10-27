"""
Hashing utilities for SecureVote.

All cryptographic hashing in the project flows through this module so that
the hash algorithm can be changed in one place.  Current algorithm: SHA-256.

Public API
----------
sha256_digest(message: bytes) -> bytes
    Raw 32-byte SHA-256 digest.

canonical_json(obj: dict) -> bytes
    Deterministic UTF-8 JSON serialisation: sorted keys, big-ints as decimal
    strings, no extra whitespace.  Used wherever a dict must be hashed or
    signed deterministically.

hash_canonical(obj: dict) -> bytes
    SHA-256 of canonical_json(obj).  Convenience wrapper.

entry_hash(prev_hash_hex: str, entry_fields: dict) -> str
    SHA-256(prev_hash_hex_bytes || canonical_json(entry_fields)) returned as
    a 64-character lowercase hex string.  Used for the bulletin-board chain.

voter_receipt(ciphertext: tuple[int, int], election_id: str, timestamp: str) -> str
    SHA-256(canonical_json({ciphertext, election_id, timestamp})) as hex.
    Voters keep this to confirm their ballot is on the board.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


# ---------------------------------------------------------------------------
# Core digest
# ---------------------------------------------------------------------------


def sha256_digest(message: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of ``message``."""
    return hashlib.sha256(message).digest()


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------


def _make_serialisable(obj: Any) -> Any:
    """
    Recursively convert a value to something JSON-safe.

    Rules:
    - ``int``  → decimal string (avoids JSON precision issues with big ints)
    - ``bytes`` → lowercase hex string
    - ``tuple`` → list (JSON has no tuple)
    - ``dict``  → dict with same conversion on keys and values
    - ``list``  → list with same conversion on elements
    - Anything else (str, bool, None) → unchanged
    """
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (tuple, list)):
        return [_make_serialisable(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _make_serialisable(v) for k, v in obj.items()}
    return obj


def canonical_json(obj: dict) -> bytes:
    """
    Produce a deterministic, compact UTF-8 JSON encoding of ``obj``.

    - Keys are sorted lexicographically at every nesting level.
    - Integer values are encoded as decimal strings.
    - ``bytes`` values are encoded as lowercase hex strings.
    - No whitespace beyond what the JSON spec requires.

    Returns UTF-8 bytes suitable for hashing or signing.
    """
    safe = _make_serialisable(obj)
    return json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_canonical(obj: dict) -> bytes:
    """Return SHA-256(canonical_json(obj))."""
    return sha256_digest(canonical_json(obj))


# ---------------------------------------------------------------------------
# Bulletin-board chain helper
# ---------------------------------------------------------------------------


def entry_hash(prev_hash_hex: str, entry_fields: dict) -> str:
    """
    Compute the chain hash for one bulletin-board entry.

    Hash = SHA-256( UTF-8(prev_hash_hex) || canonical_json(entry_fields) )

    Returns a 64-character lowercase hex string.

    Parameters
    ----------
    prev_hash_hex:
        The ``entry_hash`` of the immediately preceding entry (or 64 zeros for
        the genesis entry).
    entry_fields:
        The entry's content dict (index, voter_id, ballot, signature,
        timestamp).  The ``prev_hash`` and ``entry_hash`` fields themselves
        must NOT be included — they are the input and output of this function.
    """
    data = prev_hash_hex.encode() + canonical_json(entry_fields)
    return sha256_digest(data).hex()


# ---------------------------------------------------------------------------
# Voter receipt
# ---------------------------------------------------------------------------


def voter_receipt(
    ciphertext: tuple[int, int],
    election_id: str,
    timestamp: str,
) -> str:
    """
    Compute the voter receipt token.

    receipt = SHA-256( canonical_json({
        "ciphertext": [c1, c2],
        "election_id": election_id,
        "timestamp":   timestamp,
    }) )

    Returns a 64-character lowercase hex string.  The voter keeps this value
    and can later verify it is present on the bulletin board by calling
    ``check_receipt()``.

    Parameters
    ----------
    ciphertext:
        ElGamal ciphertext ``(c1, c2)`` as a pair of ints.
    election_id:
        Unique string identifying the election.
    timestamp:
        ISO-8601 timestamp string recorded at cast time.
    """
    c1, c2 = ciphertext
    obj = {
        "ciphertext": [c1, c2],
        "election_id": election_id,
        "timestamp": timestamp,
    }
    return hash_canonical(obj).hex()
