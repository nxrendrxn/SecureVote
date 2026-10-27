"""
Data models for SecureVote elections.

All dataclasses are ``frozen=True`` so they can be used as dictionary keys
and are naturally immutable once created.  JSON serialisation converts big
integers to decimal strings (same convention as ``hashing.canonical_json``).

Public types
------------
ElectionConfig   Public election parameters (params, public key, trustees).
TrusteeInfo      A single trustee's public information (id, h_i).
VoterRecord      Registered voter (id, RSA public key).
CastBallot       A fully validated, board-appended ballot.
TallyResult      Final tally (aggregate ciphertext, vote total, partial decryptions).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers — big-int ↔ str conversion for JSON round-trips
# ---------------------------------------------------------------------------


def _to_json_safe(obj: Any) -> Any:
    """Recursively replace ``int`` with decimal string for JSON."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_json_safe(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    return obj


def _from_json_safe_ints(obj: Any, int_keys: set[str]) -> Any:
    """
    Recursively parse decimal strings back to ints for known int fields.

    ``int_keys`` is the set of dict keys whose values should be parsed as int.
    For nested structures (lists of 2-element tuples representing ciphertexts),
    callers must handle their own conversion.
    """
    if isinstance(obj, dict):
        result: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in int_keys and isinstance(v, str):
                result[k] = int(v)
            else:
                result[k] = _from_json_safe_ints(v, int_keys)
        return result
    if isinstance(obj, list):
        return [_from_json_safe_ints(v, int_keys) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# TrusteeInfo
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrusteeInfo:
    """
    Public information about one trustee.

    Attributes
    ----------
    trustee_id : int
        1-based trustee index (matches Shamir share index).
    h_i : int
        Verification key ``g^{x_i} mod p`` (published at setup).
    """

    trustee_id: int
    h_i: int

    def to_dict(self) -> Dict[str, Any]:
        return {"trustee_id": self.trustee_id, "h_i": str(self.h_i)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TrusteeInfo":
        return cls(trustee_id=int(d["trustee_id"]), h_i=int(d["h_i"]))


# ---------------------------------------------------------------------------
# ElectionConfig
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ElectionConfig:
    """
    Public election configuration stored in ``data/election.json``.

    Attributes
    ----------
    election_id : str
        Unique identifier for this election.
    params_mode : str
        ``"test"`` or ``"demo"`` — determines group parameters.
    p, q, g : int
        Group parameters.
    h : int
        Election public key ``g^x mod p``; ``x`` was wiped after splitting.
    n_trustees : int
        Total number of trustees.
    threshold : int
        Minimum trustees needed for tally (``k``).
    trustees : list[TrusteeInfo]
        Public info for each trustee.
    n_voters : int
        Number of registered voters.
    status : str
        ``"open"`` | ``"closed"`` | ``"tallied"``.
    tally : int | None
        Final vote count (set after tallying).
    """

    election_id: str
    params_mode: str
    p: int
    q: int
    g: int
    h: int
    n_trustees: int
    threshold: int
    trustees: Tuple[TrusteeInfo, ...]
    n_voters: int
    status: str = "open"
    tally: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "election_id": self.election_id,
            "params_mode": self.params_mode,
            "p": str(self.p),
            "q": str(self.q),
            "g": str(self.g),
            "h": str(self.h),
            "n_trustees": self.n_trustees,
            "threshold": self.threshold,
            "trustees": [t.to_dict() for t in self.trustees],
            "n_voters": self.n_voters,
            "status": self.status,
            "tally": self.tally,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ElectionConfig":
        trustees = tuple(TrusteeInfo.from_dict(t) for t in d["trustees"])
        return cls(
            election_id=d["election_id"],
            params_mode=d["params_mode"],
            p=int(d["p"]),
            q=int(d["q"]),
            g=int(d["g"]),
            h=int(d["h"]),
            n_trustees=int(d["n_trustees"]),
            threshold=int(d["threshold"]),
            trustees=trustees,
            n_voters=int(d["n_voters"]),
            status=d.get("status", "open"),
            tally=d.get("tally"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> "ElectionConfig":
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# VoterRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VoterRecord:
    """
    Registered voter on the voter roll.

    Attributes
    ----------
    voter_id : str
        Unique voter identifier (e.g. ``"voter-001"``).
    rsa_n : int
        RSA public-key modulus.
    rsa_e : int
        RSA public exponent (65537).
    """

    voter_id: str
    rsa_n: int
    rsa_e: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "voter_id": self.voter_id,
            "rsa_e": str(self.rsa_e),
            "rsa_n": str(self.rsa_n),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VoterRecord":
        return cls(
            voter_id=d["voter_id"],
            rsa_n=int(d["rsa_n"]),
            rsa_e=int(d["rsa_e"]),
        )


# ---------------------------------------------------------------------------
# CastBallot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CastBallot:
    """
    A fully validated ballot as stored on the bulletin board (and in ``data/``).

    Attributes
    ----------
    voter_id : str
        The voter who cast this ballot.
    c1, c2 : int
        ElGamal ciphertext components.
    proof : dict
        Serialised ``BitProof`` fields (a0, b0, a1, b1, e0, e1, z0, z1).
    signature : int
        RSA-PKCS1-v1_5 signature of the canonical ballot message.
    timestamp : str
        ISO-8601 timestamp of acceptance.
    receipt : str
        64-char hex voter receipt token.
    """

    voter_id: str
    c1: int
    c2: int
    proof: Dict[str, int]
    signature: int
    timestamp: str
    receipt: str

    # ------------------------------------------------------------------
    # Helpers to convert to/from the board's ballot dict format
    # ------------------------------------------------------------------

    def to_ballot_dict(self) -> Dict[str, Any]:
        """Convert to the format stored in ``BoardEntry.ballot``."""
        return {
            "ciphertext": [str(self.c1), str(self.c2)],
            "proof": {k: str(v) for k, v in self.proof.items()},
        }

    @classmethod
    def from_ballot_dict(
        cls,
        voter_id: str,
        ballot: Dict[str, Any],
        signature: int,
        timestamp: str,
        receipt: str,
    ) -> "CastBallot":
        ct = ballot["ciphertext"]
        proof_raw = ballot.get("proof", {})
        return cls(
            voter_id=voter_id,
            c1=int(ct[0]),
            c2=int(ct[1]),
            proof={k: int(v) for k, v in proof_raw.items()},
            signature=signature,
            timestamp=timestamp,
            receipt=receipt,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "c1": str(self.c1),
            "c2": str(self.c2),
            "proof": {k: str(v) for k, v in self.proof.items()},
            "receipt": self.receipt,
            "signature": str(self.signature),
            "timestamp": self.timestamp,
            "voter_id": self.voter_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CastBallot":
        return cls(
            voter_id=d["voter_id"],
            c1=int(d["c1"]),
            c2=int(d["c2"]),
            proof={k: int(v) for k, v in d["proof"].items()},
            signature=int(d["signature"]),
            timestamp=d["timestamp"],
            receipt=d["receipt"],
        )


# ---------------------------------------------------------------------------
# TallyResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TallyResult:
    """
    Published tally output.

    Attributes
    ----------
    agg_c1, agg_c2 : int
        Aggregate ElGamal ciphertext (product of all ballots).
    total_yes : int
        Recovered plaintext vote sum (number of YES votes).
    trustee_ids_used : tuple[int, ...]
        The trustee IDs whose partials were used in this tally.
    """

    agg_c1: int
    agg_c2: int
    total_yes: int
    trustee_ids_used: Tuple[int, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agg_c1": str(self.agg_c1),
            "agg_c2": str(self.agg_c2),
            "total_yes": self.total_yes,
            "trustee_ids_used": list(self.trustee_ids_used),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TallyResult":
        return cls(
            agg_c1=int(d["agg_c1"]),
            agg_c2=int(d["agg_c2"]),
            total_yes=int(d["total_yes"]),
            trustee_ids_used=tuple(int(i) for i in d["trustee_ids_used"]),
        )
