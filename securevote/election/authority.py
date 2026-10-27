"""
Election Authority for SecureVote.

The ``Authority`` class manages one complete election lifecycle:

  setup → register → cast (×N) → close → tally

It owns an in-memory ``BulletinBoard`` and the ``ElectionConfig``, and
delegates all cryptographic work to the lower-level crypto modules.

Cast validation order (spec §6 step 3)
--------------------------------------
  (a) Voter is on the roll and RSA signature is valid.
  (b) Voter has not already cast a ballot.
  (c) ElGamal ciphertext ZKP (BitProof) is valid.

Any failure raises ``CastError`` with a descriptive ``reason`` attribute so
callers can print the exact rejection reason.

Tally
-----
  1. Multiply all ciphertexts homomorphically.
  2. Collect partial decryptions from the requested trustees.
  3. Verify each partial with a Chaum-Pedersen proof (exclude bad ones).
  4. Combine with Lagrange interpolation and brute-force dlog.
  5. Publish ``TallyResult``; freeze config status as ``"tallied"``.
"""

from __future__ import annotations

import datetime
import secrets
from dataclasses import replace
from typing import Dict, List, Mapping, Optional, Tuple

from securevote.crypto import elgamal, threshold
from securevote.crypto.hashing import canonical_json, voter_receipt
from securevote.crypto.params import GroupParams, load_params
from securevote.crypto.rsa_sign import (
    RSAKeyPair,
    RSAPublicKey,
    generate_rsa_keypair,
    sign_message,
    verify_signature,
)
from securevote.crypto.shamir import split_secret
from securevote.crypto.zkp import BitProof, prove_bit, verify_bit
from securevote.election.board import BulletinBoard, check_receipt, verify_chain
from securevote.election.models import (
    CastBallot,
    ElectionConfig,
    TallyResult,
    TrusteeInfo,
    VoterRecord,
)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class CastError(Exception):
    """
    Raised when a ballot is rejected during ``cast()``.

    Attributes
    ----------
    reason : str
        Machine-readable rejection code:
        ``"not_registered"`` | ``"invalid_signature"`` |
        ``"already_voted"`` | ``"invalid_zkp"``
    message : str
        Human-readable explanation.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------


class Authority:
    """
    Election authority — owns configuration, voter roll, board, and shares.

    Parameters
    ----------
    election_id : str
        Unique identifier for this election.

    The typical lifecycle::

        auth = Authority("election-2026")
        config = auth.setup(n_voters=10, n_trustees=5, threshold=3, params_mode="test")
        auth.register(count=10)
        receipt = auth.cast("voter-001", choice=1)
        auth.close()
        result = auth.tally(trustee_ids=[1, 2, 3])
    """

    def __init__(self, election_id: str) -> None:
        self._election_id = election_id

        # Set by setup()
        self._config: Optional[ElectionConfig] = None
        self._params: Optional[GroupParams] = None
        self._shares: Dict[int, int] = {}          # trustee_id → share_value (secret)
        self._vkeys: Dict[int, int] = {}            # trustee_id → h_i (public)

        # Set by register()
        self._voter_roll: Dict[str, VoterRecord] = {}
        self._voter_keys: Dict[str, RSAKeyPair] = {}  # private keys (in-process only)

        # Board
        self._board: Optional[BulletinBoard] = None

        # Tally result
        self._tally: Optional[TallyResult] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config(self) -> ElectionConfig:
        if self._config is None:
            raise RuntimeError("election not set up yet")
        return self._config

    @property
    def board(self) -> BulletinBoard:
        if self._board is None:
            raise RuntimeError("election not set up yet")
        return self._board

    @property
    def params(self) -> GroupParams:
        if self._params is None:
            raise RuntimeError("election not set up yet")
        return self._params

    @property
    def voter_roll(self) -> Dict[str, VoterRecord]:
        return dict(self._voter_roll)

    @property
    def tally_result(self) -> Optional[TallyResult]:
        return self._tally

    # ------------------------------------------------------------------
    # Step 1 — setup
    # ------------------------------------------------------------------

    def setup(
        self,
        n_voters: int,
        n_trustees: int,
        threshold: int,
        params_mode: str = "test",
    ) -> ElectionConfig:
        """
        Generate group parameters, election keypair, and Shamir shares.

        After splitting, the dealer's copy of ``x`` is discarded (set to 0
        and del'd) to simulate a trusted-dealer setup.  The shares stay
        in-process in ``self._shares``; the CLI saves them to ``data/trustees/``.

        Returns the public ``ElectionConfig``.
        """
        if self._config is not None:
            raise RuntimeError("election already set up")
        if not (1 <= threshold <= n_trustees):
            raise ValueError("threshold must satisfy 1 ≤ k ≤ n")

        params = load_params(params_mode)
        x, h = elgamal.keygen(params)

        # Shamir-split the election private key.
        shares = split_secret(x, n_trustees, threshold, params.q)
        vkeys = {tid: pow(params.g, sv, params.p) for tid, sv in shares.items()}

        trustees = tuple(TrusteeInfo(trustee_id=tid, h_i=vkeys[tid]) for tid in sorted(vkeys))

        config = ElectionConfig(
            election_id=self._election_id,
            params_mode=params_mode,
            p=params.p,
            q=params.q,
            g=params.g,
            h=h,
            n_trustees=n_trustees,
            threshold=threshold,
            trustees=trustees,
            n_voters=n_voters,
            status="open",
        )

        # Store
        self._params = params
        self._shares = shares
        self._vkeys = vkeys
        self._config = config
        self._board = BulletinBoard(self._election_id)

        # Wipe the dealer's private key.
        x = 0  # noqa: SIM910 (intentional zero-out)
        del x

        return config

    # ------------------------------------------------------------------
    # Step 2 — register
    # ------------------------------------------------------------------

    def register(self, count: int) -> List[VoterRecord]:
        """
        Generate RSA keypairs for ``count`` voters and add them to the roll.

        Voter IDs are ``"voter-001"``, ``"voter-002"``, etc. starting from
        the current roll size + 1.

        Returns the list of new ``VoterRecord`` objects (public keys only).
        """
        if self._config is None:
            raise RuntimeError("call setup() first")
        records = []
        base = len(self._voter_roll) + 1
        for i in range(count):
            voter_id = f"voter-{base + i:03d}"
            kp = generate_rsa_keypair("test")
            record = VoterRecord(voter_id=voter_id, rsa_n=kp.n, rsa_e=kp.e)
            self._voter_roll[voter_id] = record
            self._voter_keys[voter_id] = kp
            records.append(record)
        return records

    # ------------------------------------------------------------------
    # Step 3 — cast
    # ------------------------------------------------------------------

    def _ballot_message(self, ciphertext: Tuple[int, int], proof: BitProof) -> bytes:
        """
        Canonical byte string that the voter signs:
        SHA-256 canonical-JSON of ``{election_id, c1, c2, proof_fields}``.
        """
        c1, c2 = ciphertext
        obj = {
            "c1": c1,
            "c2": c2,
            "election_id": self._election_id,
            "proof": {
                "a0": proof.a0, "a1": proof.a1,
                "b0": proof.b0, "b1": proof.b1,
                "e0": proof.e0, "e1": proof.e1,
                "z0": proof.z0, "z1": proof.z1,
            },
        }
        return canonical_json(obj)

    def cast(
        self,
        voter_id: str,
        choice: int,
        *,
        # Allow tests to inject a pre-built ciphertext+proof+signature for attack simulation.
        _ciphertext: Optional[Tuple[int, int]] = None,
        _proof: Optional[BitProof] = None,
        _signature: Optional[int] = None,
    ) -> str:
        """
        Cast a ballot for ``voter_id`` with ``choice ∈ {0, 1}`` (1=yes, 0=no).

        Validation order (spec §6 step 3):
          (a) Voter is on the roll and signature is valid.
          (b) Voter has not already voted.
          (c) ZKP is valid.

        Returns the voter receipt (64-char hex string).

        Raises
        ------
        CastError
            With ``.reason`` in ``{"not_registered", "invalid_signature",
            "already_voted", "invalid_zkp"}``.
        RuntimeError
            If the election is not open.
        """
        config = self.config
        board = self.board
        params = self.params

        if config.status != "open":
            raise RuntimeError(f"election is {config.status!r}; cannot cast")

        # Build or accept ciphertext + proof.
        if _ciphertext is not None and _proof is not None:
            ciphertext = _ciphertext
            proof = _proof
            r_used = None  # We don't have r here; proof was pre-built.
        else:
            r_used = secrets.randbelow(params.q) or 1
            ciphertext = elgamal.encrypt(params, config.h, choice, randomness=r_used)
            proof = prove_bit(choice, r_used, ciphertext, config.h, params, self._election_id)

        msg = self._ballot_message(ciphertext, proof)

        # Build or accept signature.
        if _signature is not None:
            signature = _signature
        else:
            kp = self._voter_keys.get(voter_id)
            if kp is None:
                raise CastError("not_registered", f"voter {voter_id!r} is not registered")
            signature = sign_message(kp, msg)

        # ---- Validation (a): on roll and signature valid -----------------
        record = self._voter_roll.get(voter_id)
        if record is None:
            raise CastError("not_registered", f"voter {voter_id!r} is not on the roll")

        pub = RSAPublicKey(n=record.rsa_n, e=record.rsa_e)
        if not verify_signature(pub, msg, signature):
            raise CastError("invalid_signature", f"RSA signature invalid for voter {voter_id!r}")

        # ---- Validation (b): not already voted ---------------------------
        if board.has_voted(voter_id):
            raise CastError("already_voted", f"voter {voter_id!r} has already cast a ballot")

        # ---- Validation (c): ZKP valid -----------------------------------
        if not verify_bit(ciphertext, proof, config.h, params, self._election_id):
            raise CastError("invalid_zkp", f"ballot ZKP invalid for voter {voter_id!r}")

        # ---- Accept: append to board ------------------------------------
        timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        ballot_dict = {
            "ciphertext": [str(ciphertext[0]), str(ciphertext[1])],
            "proof": {
                "a0": str(proof.a0), "a1": str(proof.a1),
                "b0": str(proof.b0), "b1": str(proof.b1),
                "e0": str(proof.e0), "e1": str(proof.e1),
                "z0": str(proof.z0), "z1": str(proof.z1),
            },
        }
        board.append(
            voter_id=voter_id,
            ballot=ballot_dict,
            signature=signature,
            timestamp=timestamp,
        )
        receipt = voter_receipt(ciphertext, self._election_id, timestamp)
        return receipt

    # ------------------------------------------------------------------
    # Step 4 — close
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Freeze the bulletin board and mark the election closed."""
        self.board.close()
        self._config = replace(self._config, status="closed")  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Step 5 — tally
    # ------------------------------------------------------------------

    def tally(self, trustee_ids: List[int]) -> TallyResult:
        """
        Tally the election using the specified trustee IDs.

        Steps:
          1. Aggregate all ciphertexts homomorphically.
          2. Compute partial decryptions for the requested trustees.
          3. Verify each via Chaum-Pedersen; exclude bad ones.
          4. Combine with Lagrange interpolation.
          5. Recover plaintext via brute-force dlog.

        Parameters
        ----------
        trustee_ids : list[int]
            At least ``threshold`` trustee IDs from this election.

        Returns
        -------
        TallyResult

        Raises
        ------
        ValueError
            If fewer than ``threshold`` valid partials are available, or no
            ballots were cast.
        RuntimeError
            If the election is not closed.
        """
        config = self.config
        params = self.params
        board = self.board

        if config.status != "closed":
            raise RuntimeError("election must be closed before tallying")

        entries = board.entries
        if not entries:
            raise ValueError("no ballots cast")

        # 1. Aggregate ciphertexts.
        agg: Optional[Tuple[int, int]] = None
        for entry in entries:
            ct_raw = entry.ballot["ciphertext"]
            ct = (int(ct_raw[0]), int(ct_raw[1]))
            agg = ct if agg is None else elgamal.homomorphic_add(agg, ct, params.p)

        assert agg is not None

        # 2. Compute partial decryptions + proofs for the requested trustees.
        active_shares = {tid: self._shares[tid] for tid in trustee_ids if tid in self._shares}
        if len(active_shares) < config.threshold:
            available = sorted(active_shares.keys())
            raise ValueError(
                f"need {config.threshold} trustee shares, only have {available}"
            )

        partials = threshold.partials_from_shares(params, active_shares, agg)
        vkeys_active = {tid: self._vkeys[tid] for tid in active_shares}
        proofs = threshold.proofs_from_shares(params, active_shares, vkeys_active, agg)

        # 3 & 4. Combine with proof verification (bad trustees excluded).
        total_yes = threshold.threshold_decrypt(
            params,
            agg,
            partials,
            config.threshold,
            max_m=len(entries),
            verification_keys=vkeys_active,
            proofs=proofs,
        )

        result = TallyResult(
            agg_c1=agg[0],
            agg_c2=agg[1],
            total_yes=total_yes,
            trustee_ids_used=tuple(sorted(active_shares.keys())),
        )
        self._tally = result
        self._config = replace(self._config, status="tallied", tally=total_yes)  # type: ignore[arg-type]
        return result

    # ------------------------------------------------------------------
    # Helpers for tests / CLI
    # ------------------------------------------------------------------

    def get_share(self, trustee_id: int) -> int:
        """Return trustee ``trustee_id``'s Shamir share (for tests/CLI persistence)."""
        if trustee_id not in self._shares:
            raise KeyError(f"no share for trustee {trustee_id}")
        return self._shares[trustee_id]

    def get_voter_private_key(self, voter_id: str) -> RSAKeyPair:
        """Return the RSA keypair for ``voter_id`` (for tests / voter simulation)."""
        kp = self._voter_keys.get(voter_id)
        if kp is None:
            raise KeyError(f"no private key for voter {voter_id!r}")
        return kp
