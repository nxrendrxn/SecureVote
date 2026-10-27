"""
Independent election verifier for SecureVote.

The ``Verifier`` class re-checks a completed election without access to any
secrets (private keys or Shamir shares).  It uses only public data:

  - ``ElectionConfig`` (public params, h, trustee h_i values)
  - ``BulletinBoard`` entries (ballots, signatures, hash chain)
  - The published ``TallyResult``

Checks performed
----------------
1. **Signature check**: for every board entry, re-verify the RSA-PKCS1-v1_5
   signature against the voter's public key from the roll.
2. **ZKP check**: re-verify the ``BitProof`` OR-proof for every ballot.
3. **Chain check**: call ``verify_chain()``; report first broken index.
4. **Aggregate check**: recompute the homomorphic product and compare to the
   published ``TallyResult.agg_c1/c2``.
5. **Total check**: verify the published ``total_yes`` is consistent with the
   aggregate ciphertext using the threshold ``d_i * h_i^{e_i}`` equations,
   OR re-run brute-force dlog with the known aggregate and published tally.
   Since we don't have Shamir shares, we verify the published total by checking
   ``g^{total_yes} * h^? == agg_c2 / agg_c1^x`` would hold — but without ``x``
   we can only re-verify that the aggregate AND the published tally are
   self-consistent in the sense that ``g^{total_yes}`` can be cross-checked
   against the decryption equation using the ``PartialDecryptionProof`` values
   that trustees published.

   For the independence check without secrets we verify:
   ``g^{total_yes} == agg_c2 * mask_inv mod p``  where mask = c1^x is
   reconstructed from published d_i and Lagrange weights — *the verifier
   must receive the (d_i, proof_i) pairs published by trustees at tally time*.

Result format
-------------
``AuditResult`` dataclass with a per-check dict and an overall ``passed`` bool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from securevote.crypto import elgamal
from securevote.crypto.hashing import canonical_json
from securevote.crypto.params import GroupParams
from securevote.crypto.rsa_sign import RSAPublicKey, verify_signature
from securevote.crypto.zkp import BitProof, verify_bit, verify_partial_decryption
from securevote.election.board import BulletinBoard, verify_chain
from securevote.election.models import ElectionConfig, TallyResult, VoterRecord


# ---------------------------------------------------------------------------
# AuditResult
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """One verifier check result."""

    name: str
    passed: bool
    detail: str = ""


@dataclass
class AuditResult:
    """Full audit result returned by ``Verifier.audit()``."""

    checks: List[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append(CheckResult(name=name, passed=passed, detail=detail))

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"AuditResult({status})"]
        for c in self.checks:
            mark = "✓" if c.passed else "✗"
            lines.append(f"  {mark} {c.name}" + (f": {c.detail}" if c.detail else ""))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class Verifier:
    """
    Independent election auditor.

    Parameters
    ----------
    config : ElectionConfig
        Public election configuration.
    board : BulletinBoard
        The bulletin board (may be read-only snapshot).
    voter_roll : dict[str, VoterRecord]
        The registered voter roll (public keys only).
    params : GroupParams
        Group parameters (reconstructed from config.p/q/g).
    tally : TallyResult, optional
        Published tally result; required for checks 4 and 5.
    trustee_partials : dict[int, int], optional
        Published partial decryptions ``trustee_id → d_i`` for total verification.
    trustee_proofs : dict[int, PartialDecryptionProof], optional
        Published Chaum-Pedersen proofs for each partial decryption.
    """

    def __init__(
        self,
        config: ElectionConfig,
        board: BulletinBoard,
        voter_roll: Dict[str, VoterRecord],
        params: GroupParams,
        tally: Optional[TallyResult] = None,
        trustee_partials: Optional[Dict[int, int]] = None,
        trustee_proofs: Optional[Dict[int, Any]] = None,
    ) -> None:
        self._config = config
        self._board = board
        self._voter_roll = voter_roll
        self._params = params
        self._tally = tally
        self._trustee_partials = trustee_partials or {}
        self._trustee_proofs = trustee_proofs or {}

    # ------------------------------------------------------------------
    # The canonical ballot message (must match Authority._ballot_message)
    # ------------------------------------------------------------------

    @staticmethod
    def _ballot_message(
        ciphertext: Tuple[int, int],
        proof: BitProof,
        election_id: str,
    ) -> bytes:
        c1, c2 = ciphertext
        obj = {
            "c1": c1,
            "c2": c2,
            "election_id": election_id,
            "proof": {
                "a0": proof.a0, "a1": proof.a1,
                "b0": proof.b0, "b1": proof.b1,
                "e0": proof.e0, "e1": proof.e1,
                "z0": proof.z0, "z1": proof.z1,
            },
        }
        return canonical_json(obj)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_signatures(self) -> CheckResult:
        """
        Re-verify RSA signatures for every board entry.

        Each entry's ``ballot_message`` is reconstructed from its payload
        and verified against the voter's public key from the roll.
        """
        entries = self._board.entries
        bad: List[str] = []

        for entry in entries:
            record = self._voter_roll.get(entry.voter_id)
            if record is None:
                bad.append(f"index={entry.index}: voter {entry.voter_id!r} not on roll")
                continue

            # Reconstruct proof object from stored dict.
            try:
                pd = entry.ballot["proof"]
                proof = BitProof(
                    a0=int(pd["a0"]), b0=int(pd["b0"]),
                    a1=int(pd["a1"]), b1=int(pd["b1"]),
                    e0=int(pd["e0"]), e1=int(pd["e1"]),
                    z0=int(pd["z0"]), z1=int(pd["z1"]),
                )
                ct_raw = entry.ballot["ciphertext"]
                ciphertext = (int(ct_raw[0]), int(ct_raw[1]))
            except (KeyError, ValueError) as exc:
                bad.append(f"index={entry.index}: malformed ballot ({exc})")
                continue

            msg = self._ballot_message(ciphertext, proof, self._config.election_id)
            pub = RSAPublicKey(n=record.rsa_n, e=record.rsa_e)
            if not verify_signature(pub, msg, entry.signature):
                bad.append(f"index={entry.index}: RSA signature INVALID for {entry.voter_id!r}")

        if bad:
            return CheckResult("signatures", False, "; ".join(bad))
        return CheckResult("signatures", True, f"{len(entries)} signatures OK")

    def check_zkps(self) -> CheckResult:
        """Re-verify the BitProof OR-proof for every board entry."""
        entries = self._board.entries
        params = self._params
        h = self._config.h
        bad: List[str] = []

        for entry in entries:
            try:
                pd = entry.ballot["proof"]
                proof = BitProof(
                    a0=int(pd["a0"]), b0=int(pd["b0"]),
                    a1=int(pd["a1"]), b1=int(pd["b1"]),
                    e0=int(pd["e0"]), e1=int(pd["e1"]),
                    z0=int(pd["z0"]), z1=int(pd["z1"]),
                )
                ct_raw = entry.ballot["ciphertext"]
                ciphertext = (int(ct_raw[0]), int(ct_raw[1]))
            except (KeyError, ValueError) as exc:
                bad.append(f"index={entry.index}: malformed ballot ({exc})")
                continue

            if not verify_bit(ciphertext, proof, h, params, self._config.election_id):
                bad.append(f"index={entry.index}: ZKP INVALID for {entry.voter_id!r}")

        if bad:
            return CheckResult("zkps", False, "; ".join(bad))
        return CheckResult("zkps", True, f"{len(entries)} ZKPs OK")

    def check_chain(self) -> CheckResult:
        """Verify the bulletin board hash chain; report first broken index."""
        broken = verify_chain(self._board)
        if broken is not None:
            return CheckResult("chain", False, f"chain broken at index {broken}")
        return CheckResult("chain", True, f"{len(self._board)} entries, chain intact")

    def check_aggregate(self) -> CheckResult:
        """
        Recompute the homomorphic product of all ciphertexts and compare to
        the published aggregate in ``TallyResult``.
        """
        if self._tally is None:
            return CheckResult("aggregate", False, "no tally result supplied")

        entries = self._board.entries
        if not entries:
            return CheckResult("aggregate", False, "no ballots on board")

        params = self._params
        agg: Optional[Tuple[int, int]] = None
        for entry in entries:
            ct_raw = entry.ballot["ciphertext"]
            ct = (int(ct_raw[0]), int(ct_raw[1]))
            agg = ct if agg is None else elgamal.homomorphic_add(agg, ct, params.p)

        assert agg is not None
        pub_c1 = self._tally.agg_c1
        pub_c2 = self._tally.agg_c2

        if agg[0] == pub_c1 and agg[1] == pub_c2:
            return CheckResult("aggregate", True, "aggregate ciphertext matches")
        return CheckResult(
            "aggregate",
            False,
            f"aggregate mismatch: computed ({agg[0]}, {agg[1]}) vs published ({pub_c1}, {pub_c2})",
        )

    def check_published_total(self) -> CheckResult:
        """
        Verify that the published ``total_yes`` is consistent with the aggregate
        ciphertext and the trustees' published partial decryptions and proofs.

        Requires ``trustee_partials`` and ``trustee_proofs`` to have been
        supplied to the constructor.  If they weren't, this check skips
        partial-decryption proof verification and falls back to checking that
        ``g^{total_yes}`` can be recovered from the aggregate ciphertext using
        just the partial d_i values (without re-verifying the proofs).
        """
        if self._tally is None:
            return CheckResult("published_total", False, "no tally result supplied")

        params = self._params
        agg = (self._tally.agg_c1, self._tally.agg_c2)
        k = self._config.threshold
        total_yes = self._tally.total_yes
        trustee_ids = list(self._tally.trustee_ids_used)

        # Need at least k partial decryptions.
        if not self._trustee_partials:
            return CheckResult(
                "published_total",
                False,
                "no trustee partials supplied for total verification",
            )

        available = {tid: self._trustee_partials[tid] for tid in trustee_ids if tid in self._trustee_partials}
        if len(available) < k:
            return CheckResult(
                "published_total",
                False,
                f"need {k} partials, only {len(available)} available",
            )

        # Optionally verify Chaum-Pedersen proofs for each partial.
        bad_proofs: List[int] = []
        if self._trustee_proofs:
            vkeys = {t.trustee_id: t.h_i for t in self._config.trustees}
            for tid, d_i in available.items():
                h_i = vkeys.get(tid)
                proof = self._trustee_proofs.get(tid)
                if h_i is None or proof is None:
                    bad_proofs.append(tid)
                    continue
                if not verify_partial_decryption(d_i, h_i, agg, proof, params):
                    bad_proofs.append(tid)

        # Lagrange-combine the valid partials.
        from securevote.crypto.shamir import lagrange_coefficient_at_zero  # noqa: PLC0415
        from securevote.crypto.params import validate_subgroup_element  # noqa: PLC0415

        active_ids = [tid for tid in sorted(available.keys())[:k] if tid not in bad_proofs]
        if len(active_ids) < k:
            return CheckResult(
                "published_total",
                False,
                f"insufficient valid partials after proof check (bad trustees: {bad_proofs})",
            )

        combined = 1
        for tid in active_ids:
            d_i = available[tid]
            lam = lagrange_coefficient_at_zero(tid, active_ids, params.q)
            combined = (combined * pow(d_i, lam, params.p)) % params.p

        # Recover g^m.
        mask_inv = pow(combined, params.q - 1, params.p)
        _, c2 = agg
        t = (c2 * mask_inv) % params.p

        # Verify g^{total_yes} == t.
        expected_t = pow(params.g, total_yes, params.p)
        if t == expected_t:
            detail = f"published total {total_yes} verified"
            if bad_proofs:
                detail += f" (trustees {bad_proofs} had invalid proofs but enough valid partials remained)"
            return CheckResult("published_total", True, detail)

        return CheckResult(
            "published_total",
            False,
            f"published total {total_yes} does not match recovered tally",
        )

    # ------------------------------------------------------------------
    # Full audit
    # ------------------------------------------------------------------

    def audit(self) -> AuditResult:
        """
        Run all checks and return an ``AuditResult``.

        Checks are run in order: signatures → zkps → chain → aggregate →
        published_total.  All checks are always run (no short-circuit), so the
        result contains a complete picture even when multiple things fail.
        """
        result = AuditResult()
        result.add(**_cr(self.check_signatures()))
        result.add(**_cr(self.check_zkps()))
        result.add(**_cr(self.check_chain()))
        result.add(**_cr(self.check_aggregate()))
        result.add(**_cr(self.check_published_total()))
        return result


def _cr(r: CheckResult) -> Dict[str, Any]:
    return {"name": r.name, "passed": r.passed, "detail": r.detail}
