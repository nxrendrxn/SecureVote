"""
SecureVote CLI — argparse entry point.

Usage
-----
  python -m securevote.cli setup   --voters 10 --trustees 5 --threshold 3 --params test
  python -m securevote.cli register --count 10
  python -m securevote.cli cast    --voter voter-001 --choice yes
  python -m securevote.cli close
  python -m securevote.cli tally   --trustees 1,2,3
  python -m securevote.cli audit
  python -m securevote.cli receipt --voter voter-001
  python -m securevote.cli attack  NAME
  python -m securevote.cli reset

State is persisted in ``data/`` relative to the current working directory:
  data/election.json          — ElectionConfig (public, written at setup)
  data/board.json             — BulletinBoard entries (written at every cast)
  data/roll.json              — voter roll (public keys)
  data/tally.json             — TallyResult (written after tally)
  data/trustees/<id>.json     — trustee share (secret; written at setup)
  data/voters/<id>.key.json   — voter RSA keypair (written at register)
  data/receipts/<id>.txt      — voter receipt (written at cast)

Attack scenarios (``attack NAME``):
  double_vote               voter-001 votes twice → "already_voted"
  unregistered_voter        voter-999 tries to vote → "not_registered"
  bad_signature             voter-001's sig corrupted → "invalid_signature"
  modified_ciphertext       ciphertext altered after signing → "invalid_signature"
  forged_zkp_m5             ballot encrypts 5 with fake proof → "invalid_zkp"
  forged_zkp_neg1           ballot encrypts -1 equivalent → "invalid_zkp"
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Rich / plain-text output helpers
# ---------------------------------------------------------------------------

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    _RICH = True
    _console = Console()
except ImportError:
    _RICH = False
    _console = None  # type: ignore[assignment]


def _print(msg: str, style: str = "") -> None:
    if _RICH and style:
        _console.print(msg, style=style)  # type: ignore[union-attr]
    else:
        print(msg)


def _ok(msg: str) -> None:
    _print(f"[bold green]PASS[/bold green]  {msg}" if _RICH else f"PASS  {msg}")


def _fail(msg: str) -> None:
    _print(f"[bold red]FAIL[/bold red]  {msg}" if _RICH else f"FAIL  {msg}")


def _info(msg: str) -> None:
    _print(f"[cyan]{msg}[/cyan]" if _RICH else msg)


def _warn(msg: str) -> None:
    _print(f"[yellow]WARN  {msg}[/yellow]" if _RICH else f"WARN  {msg}")


def _truncate_hex(n: int) -> str:
    """Show first 12 hex chars of a big integer + '...'"""
    h = format(n, "x")
    return h[:12] + "..." if len(h) > 12 else h


# ---------------------------------------------------------------------------
# Data directory helpers
# ---------------------------------------------------------------------------

DATA_DIR = Path("data")


def _ensure_dirs() -> None:
    for sub in ("", "trustees", "voters", "receipts"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Persistence helpers — serialize Authority state to/from data/
# ---------------------------------------------------------------------------

def _save_state(auth: "Authority") -> None:
    """Persist all authority state to data/."""
    from securevote.election.authority import Authority  # noqa: PLC0415
    _ensure_dirs()

    # Election config
    _write_json(DATA_DIR / "election.json", auth.config.to_dict())

    # Board
    entries_list = []
    for e in auth.board.entries:
        entries_list.append({
            "index": e.index,
            "voter_id": e.voter_id,
            "ballot": e.ballot,
            "signature": str(e.signature),
            "timestamp": e.timestamp,
            "prev_hash": e.prev_hash,
            "entry_hash": e.entry_hash,
        })
    _write_json(DATA_DIR / "board.json", {
        "election_id": auth.config.election_id,
        "closed": auth.board.is_closed,
        "entries": entries_list,
    })

    # Voter roll
    roll = {vid: r.to_dict() for vid, r in auth.voter_roll.items()}
    _write_json(DATA_DIR / "roll.json", roll)

    # Trustee shares
    for tid, share in auth._shares.items():  # noqa: SLF001
        _write_json(DATA_DIR / "trustees" / f"{tid}.json", {
            "trustee_id": tid,
            "share": str(share),
            "h_i": str(auth._vkeys[tid]),  # noqa: SLF001
        })

    # Voter private keys
    for voter_id, kp in auth._voter_keys.items():  # noqa: SLF001
        _write_json(DATA_DIR / "voters" / f"{voter_id}.key.json", {
            "voter_id": voter_id,
            "n": str(kp.n),
            "e": str(kp.e),
            "d": str(kp.d),
            "p": str(kp.p),
            "q": str(kp.q),
        })

    # Tally
    if auth.tally_result is not None:
        _write_json(DATA_DIR / "tally.json", auth.tally_result.to_dict())


def _load_state() -> "Authority":
    """Reconstruct an Authority from data/ files."""
    from securevote.election.authority import Authority  # noqa: PLC0415
    from securevote.election.models import ElectionConfig, VoterRecord  # noqa: PLC0415
    from securevote.crypto.params import GroupParams  # noqa: PLC0415
    from securevote.crypto.rsa_sign import RSAKeyPair, RSAPublicKey  # noqa: PLC0415
    from securevote.election.board import BulletinBoard, BoardEntry  # noqa: PLC0415

    if not (DATA_DIR / "election.json").exists():
        print("No election found in data/. Run 'setup' first.", file=sys.stderr)
        sys.exit(1)

    config = ElectionConfig.from_dict(_read_json(DATA_DIR / "election.json"))
    auth = Authority.__new__(Authority)
    auth._election_id = config.election_id  # noqa: SLF001
    auth._config = config  # noqa: SLF001
    auth._params = GroupParams(p=config.p, q=config.q, g=config.g)  # noqa: SLF001
    auth._tally = None  # noqa: SLF001

    # Load tally if present
    if (DATA_DIR / "tally.json").exists():
        from securevote.election.models import TallyResult  # noqa: PLC0415
        auth._tally = TallyResult.from_dict(_read_json(DATA_DIR / "tally.json"))  # noqa: SLF001

    # Load trustee shares
    shares: Dict[int, int] = {}
    vkeys: Dict[int, int] = {}
    for path in (DATA_DIR / "trustees").glob("*.json"):
        d = _read_json(path)
        tid = int(d["trustee_id"])
        shares[tid] = int(d["share"])
        vkeys[tid] = int(d["h_i"])
    auth._shares = shares  # noqa: SLF001
    auth._vkeys = vkeys  # noqa: SLF001

    # Load voter roll
    roll_data = _read_json(DATA_DIR / "roll.json") if (DATA_DIR / "roll.json").exists() else {}
    voter_roll: Dict[str, VoterRecord] = {
        vid: VoterRecord.from_dict(r) for vid, r in roll_data.items()
    }
    auth._voter_roll = voter_roll  # noqa: SLF001

    # Load voter private keys
    voter_keys = {}
    for path in (DATA_DIR / "voters").glob("*.key.json"):
        d = _read_json(path)
        pub = RSAPublicKey(n=int(d["n"]), e=int(d["e"]))
        kp = RSAKeyPair(public=pub, d=int(d["d"]), p=int(d["p"]), q=int(d["q"]))
        voter_keys[d["voter_id"]] = kp
    auth._voter_keys = voter_keys  # noqa: SLF001

    # Reconstruct board
    board_data = _read_json(DATA_DIR / "board.json") if (DATA_DIR / "board.json").exists() else {"election_id": config.election_id, "closed": False, "entries": []}
    board = BulletinBoard(board_data["election_id"])
    for e in board_data.get("entries", []):
        entry = BoardEntry(
            index=int(e["index"]),
            voter_id=e["voter_id"],
            ballot=e["ballot"],
            signature=int(e["signature"]),
            timestamp=e["timestamp"],
            prev_hash=e["prev_hash"],
            entry_hash=e["entry_hash"],
        )
        board._entries.append(entry)  # noqa: SLF001
        board._voter_set.add(e["voter_id"])  # noqa: SLF001
    if board_data.get("closed"):
        board._closed = True  # noqa: SLF001
    auth._board = board  # noqa: SLF001

    return auth


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_setup(args: argparse.Namespace) -> None:
    from securevote.election.authority import Authority  # noqa: PLC0415
    _ensure_dirs()
    election_id = f"election-{secrets.token_hex(4)}"
    auth = Authority(election_id)
    config = auth.setup(
        n_voters=args.voters,
        n_trustees=args.trustees,
        threshold=args.threshold,
        params_mode=args.params,
    )
    _save_state(auth)
    _info(f"Election ID : {election_id}")
    _info(f"Params mode : {args.params}")
    _info(f"Public key h: {_truncate_hex(config.h)}")
    _info(f"Trustees    : {args.trustees}, threshold k={args.threshold}")
    _ok("Setup complete. Shamir shares written to data/trustees/")


def cmd_register(args: argparse.Namespace) -> None:
    auth = _load_state()
    records = auth.register(args.count)
    _save_state(auth)
    _info(f"Registered {len(records)} voters:")
    for r in records:
        _info(f"  {r.voter_id}  n={_truncate_hex(r.rsa_n)}")
    _ok(f"Register complete. Keys written to data/voters/")


def cmd_cast(args: argparse.Namespace) -> None:
    auth = _load_state()
    choice = 1 if args.choice.lower() in ("yes", "1") else 0
    try:
        receipt = auth.cast(args.voter, choice)
        _save_state(auth)
        # Save receipt to file.
        receipt_path = DATA_DIR / "receipts" / f"{args.voter}.txt"
        receipt_path.write_text(receipt, encoding="utf-8")
        _ok(f"Ballot accepted for {args.voter}")
        _info(f"Receipt     : {receipt}")
    except Exception as exc:  # noqa: BLE001
        _fail(f"Cast rejected: {exc}")
        sys.exit(1)


def cmd_close(args: argparse.Namespace) -> None:
    auth = _load_state()
    auth.close()
    _save_state(auth)
    _ok(f"Election closed. {len(auth.board)} ballots on board.")


def cmd_tally(args: argparse.Namespace) -> None:
    auth = _load_state()
    trustee_ids = [int(t.strip()) for t in args.trustees.split(",")]
    try:
        result = auth.tally(trustee_ids)
        _save_state(auth)
        total = len(auth.board)
        _ok(f"Tally complete")
        _info(f"  YES votes : {result.total_yes}")
        _info(f"  NO  votes : {total - result.total_yes}")
        _info(f"  Total cast: {total}")
        _info(f"  Trustees  : {list(result.trustee_ids_used)}")
    except Exception as exc:  # noqa: BLE001
        _fail(f"Tally failed: {exc}")
        sys.exit(1)


def cmd_audit(args: argparse.Namespace) -> None:
    from securevote.election.verifier import Verifier  # noqa: PLC0415
    from securevote.crypto.params import GroupParams  # noqa: PLC0415
    from securevote.election.models import TallyResult  # noqa: PLC0415

    auth = _load_state()
    config = auth.config
    params = GroupParams(p=config.p, q=config.q, g=config.g)

    tally = auth.tally_result
    partials: Dict[int, int] = {}
    proofs: Dict[int, Any] = {}

    # If tally has been run, rebuild partials for verification.
    if tally is not None:
        from securevote.crypto import threshold as thresh  # noqa: PLC0415
        from securevote.election.board import BulletinBoard  # noqa: PLC0415
        agg_ct = (tally.agg_c1, tally.agg_c2)
        active_shares = {tid: auth._shares[tid] for tid in tally.trustee_ids_used if tid in auth._shares}  # noqa: SLF001
        active_vkeys = {tid: auth._vkeys[tid] for tid in active_shares}  # noqa: SLF001
        partials = thresh.partials_from_shares(params, active_shares, agg_ct)
        proofs = thresh.proofs_from_shares(params, active_shares, active_vkeys, agg_ct)

    verifier = Verifier(
        config=config,
        board=auth.board,
        voter_roll=auth.voter_roll,
        params=params,
        tally=tally,
        trustee_partials=partials,
        trustee_proofs=proofs,
    )

    result = verifier.audit()
    _info(f"\n{'─'*50}")
    _info("  AUDIT RESULTS")
    _info(f"{'─'*50}")
    for check in result.checks:
        label = f"  {check.name:<20}"
        detail = f"  {check.detail}" if check.detail else ""
        if check.passed:
            _ok(f"{label}{detail}")
        else:
            _fail(f"{label}{detail}")
    _info(f"{'─'*50}")
    overall = "PASS" if result.passed else "FAIL"
    if result.passed:
        _ok(f"Overall: {overall}")
    else:
        _fail(f"Overall: {overall}")
        sys.exit(1)


def cmd_receipt(args: argparse.Namespace) -> None:
    from securevote.election.board import check_receipt  # noqa: PLC0415
    auth = _load_state()
    receipt_path = DATA_DIR / "receipts" / f"{args.voter}.txt"
    if not receipt_path.exists():
        _fail(f"No receipt file found for {args.voter}")
        sys.exit(1)
    token = receipt_path.read_text(encoding="utf-8").strip()
    entry = check_receipt(auth.board, token, voter_id=args.voter)
    if entry is not None:
        _ok(f"Receipt verified for {args.voter} (board index {entry.index})")
        _info(f"  Token: {token}")
    else:
        _fail(f"Receipt NOT found on board for {args.voter}")
        sys.exit(1)


def cmd_attack(args: argparse.Namespace) -> None:
    """Run a named attack scenario."""
    name = args.name
    _info(f"\n[ATTACK] Scenario: {name}")
    _info("─" * 50)

    auth = _load_state()
    voters = sorted(auth.voter_roll.keys())
    if not voters:
        _fail("No voters registered. Run 'register' first.")
        sys.exit(1)
    victim = voters[0]

    # Make sure victim has cast a ballot for double-vote scenario.
    def _ensure_cast(voter_id: str) -> None:
        if not auth.board.has_voted(voter_id):
            if auth.config.status != "open":
                return
            try:
                auth.cast(voter_id, 1)
                _save_state(auth)
            except Exception:  # noqa: BLE001
                pass

    from securevote.election.authority import CastError  # noqa: PLC0415

    if name == "double_vote":
        _ensure_cast(victim)
        _reload = _load_state()
        try:
            _reload.cast(victim, 0)
            _fail("UNEXPECTED ACCEPT")
        except CastError as e:
            _ok(f"Rejected: {e.reason} — {e}")

    elif name == "unregistered_voter":
        auth2 = _load_state()
        try:
            auth2.cast("voter-999", 1)
            _fail("UNEXPECTED ACCEPT")
        except CastError as e:
            _ok(f"Rejected: {e.reason} — {e}")

    elif name == "bad_signature":
        from securevote.crypto import elgamal as eg  # noqa: PLC0415
        from securevote.crypto.zkp import prove_bit  # noqa: PLC0415
        auth2 = _load_state()
        params = auth2.params
        r = secrets.randbelow(params.q) or 1
        ct = eg.encrypt(params, auth2.config.h, 1, randomness=r)
        proof = prove_bit(1, r, ct, auth2.config.h, params, auth2.config.election_id)
        try:
            # Inject a wrong (random) signature.
            auth2.cast(victim, 1, _ciphertext=ct, _proof=proof, _signature=secrets.randbelow(2**512))
            _fail("UNEXPECTED ACCEPT")
        except CastError as e:
            _ok(f"Rejected: {e.reason} — {e}")

    elif name == "modified_ciphertext":
        from securevote.crypto import elgamal as eg  # noqa: PLC0415
        from securevote.crypto.zkp import prove_bit  # noqa: PLC0415
        from securevote.crypto.rsa_sign import sign_message  # noqa: PLC0415
        from securevote.crypto.hashing import canonical_json as cj  # noqa: PLC0415
        auth2 = _load_state()
        params = auth2.params
        kp = auth2._voter_keys.get(victim)  # noqa: SLF001
        if kp is None:
            _fail(f"No private key for {victim}")
            return
        r = secrets.randbelow(params.q) or 1
        ct = eg.encrypt(params, auth2.config.h, 1, randomness=r)
        proof = prove_bit(1, r, ct, auth2.config.h, params, auth2.config.election_id)
        # Sign the original message, then swap in a different ciphertext.
        original_msg = auth2._ballot_message(ct, proof)  # noqa: SLF001
        sig = sign_message(kp, original_msg)
        # Alter c2.
        bad_ct = (ct[0], (ct[1] + 1) % params.p)
        try:
            auth2.cast(victim, 1, _ciphertext=bad_ct, _proof=proof, _signature=sig)
            _fail("UNEXPECTED ACCEPT")
        except CastError as e:
            _ok(f"Rejected: {e.reason} — {e}")

    elif name == "forged_zkp_m5":
        from securevote.crypto import elgamal as eg  # noqa: PLC0415
        from securevote.crypto.zkp import prove_bit, BitProof  # noqa: PLC0415
        from securevote.crypto.rsa_sign import sign_message  # noqa: PLC0415
        auth2 = _load_state()
        params = auth2.params
        kp = auth2._voter_keys.get(victim)  # noqa: SLF001
        if kp is None:
            _fail(f"No private key for {victim}")
            return
        r = secrets.randbelow(params.q) or 1
        ct5 = eg.encrypt(params, auth2.config.h, 5, randomness=r)
        # Build a proof for m=0 but use ct5 as the ciphertext in the message.
        r0 = secrets.randbelow(params.q) or 1
        ct0 = eg.encrypt(params, auth2.config.h, 0, randomness=r0)
        proof0 = prove_bit(0, r0, ct0, auth2.config.h, params, auth2.config.election_id)
        msg = auth2._ballot_message(ct5, proof0)  # noqa: SLF001
        sig = sign_message(kp, msg)
        try:
            auth2.cast(victim, 5, _ciphertext=ct5, _proof=proof0, _signature=sig)
            _fail("UNEXPECTED ACCEPT")
        except (CastError, ValueError) as e:
            _ok(f"Rejected: {getattr(e, 'reason', 'error')} — {e}")

    elif name == "forged_zkp_neg1":
        # Encrypt g^{-1} = g^{q-1} as a "negative 1" ciphertext.
        from securevote.crypto import elgamal as eg  # noqa: PLC0415
        from securevote.crypto.zkp import prove_bit  # noqa: PLC0415
        from securevote.crypto.rsa_sign import sign_message  # noqa: PLC0415
        auth2 = _load_state()
        params = auth2.params
        kp = auth2._voter_keys.get(victim)  # noqa: SLF001
        if kp is None:
            _fail(f"No private key for {victim}")
            return
        # c2 = g^{q-1} * h^r (encrypts m = q-1 ≡ -1 mod q)
        r = secrets.randbelow(params.q) or 1
        c1 = pow(params.g, r, params.p)
        c2 = (pow(params.g, params.q - 1, params.p) * pow(auth2.config.h, r, params.p)) % params.p
        bad_ct = (c1, c2)
        r0 = secrets.randbelow(params.q) or 1
        ct0 = eg.encrypt(params, auth2.config.h, 0, randomness=r0)
        proof0 = prove_bit(0, r0, ct0, auth2.config.h, params, auth2.config.election_id)
        msg = auth2._ballot_message(bad_ct, proof0)  # noqa: SLF001
        sig = sign_message(kp, msg)
        try:
            auth2.cast(victim, 0, _ciphertext=bad_ct, _proof=proof0, _signature=sig)
            _fail("UNEXPECTED ACCEPT")
        except CastError as e:
            _ok(f"Rejected: {e.reason} — {e}")
    else:
        _fail(f"Unknown attack: {name!r}")
        _info("Available: double_vote, unregistered_voter, bad_signature, "
              "modified_ciphertext, forged_zkp_m5, forged_zkp_neg1")
        sys.exit(1)


def cmd_reset(args: argparse.Namespace) -> None:
    import shutil  # noqa: PLC0415
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    _ok("Reset complete. data/ directory removed.")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securevote",
        description="SecureVote — verifiable electronic voting system",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    p_setup = sub.add_parser("setup", help="Initialise a new election")
    p_setup.add_argument("--voters", type=int, default=10, metavar="N")
    p_setup.add_argument("--trustees", type=int, default=5, metavar="n")
    p_setup.add_argument("--threshold", type=int, default=3, metavar="k")
    p_setup.add_argument("--params", choices=["test", "demo"], default="test")

    # register
    p_reg = sub.add_parser("register", help="Register voters")
    p_reg.add_argument("--count", type=int, default=10, metavar="N")

    # cast
    p_cast = sub.add_parser("cast", help="Cast a ballot")
    p_cast.add_argument("--voter", required=True, metavar="ID")
    p_cast.add_argument("--choice", required=True, choices=["yes", "no", "1", "0"])

    # close
    sub.add_parser("close", help="Close the election")

    # tally
    p_tally = sub.add_parser("tally", help="Tally with specified trustees")
    p_tally.add_argument("--trustees", required=True, metavar="1,2,3",
                         help="Comma-separated trustee IDs")

    # audit
    sub.add_parser("audit", help="Independently audit the election")

    # receipt
    p_receipt = sub.add_parser("receipt", help="Verify a voter receipt")
    p_receipt.add_argument("--voter", required=True, metavar="ID")

    # attack
    p_attack = sub.add_parser("attack", help="Simulate an attack scenario")
    p_attack.add_argument("name", metavar="NAME",
                          help="double_vote | unregistered_voter | bad_signature | "
                               "modified_ciphertext | forged_zkp_m5 | forged_zkp_neg1")

    # reset
    sub.add_parser("reset", help="Remove all data/ state")

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "setup": cmd_setup,
        "register": cmd_register,
        "cast": cmd_cast,
        "close": cmd_close,
        "tally": cmd_tally,
        "audit": cmd_audit,
        "receipt": cmd_receipt,
        "attack": cmd_attack,
        "reset": cmd_reset,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
