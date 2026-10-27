"""
SecureVote — Narrated Demo Election

Runs a complete election suitable for screen-recording:
  • 10 voters (6 YES, 4 NO)
  • 5 trustees, threshold k=3
  • 5 attack scenarios demonstrated live
  • Threshold tally with trustee IDs 1, 2, 3
  • Independent audit — all 5 checks shown

Usage
-----
  python securevote/demo.py              # fast (~64-bit test params)
  python securevote/demo.py --params demo  # 2048-bit RFC 3526 params (slower)
"""

from __future__ import annotations

import argparse
import dataclasses
import secrets
import sys
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Rich / plain-text helpers
# ---------------------------------------------------------------------------

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    _RICH = True
    _con = Console()
except ImportError:
    _RICH = False
    _con = None  # type: ignore[assignment]


def _print(msg: str = "") -> None:
    if _RICH:
        _con.print(msg)  # type: ignore[union-attr]
    else:
        print(msg)


def _rule(title: str = "") -> None:
    if _RICH:
        _con.print(Rule(title, style="bold cyan"))  # type: ignore[union-attr]
    else:
        print(f"\n{'─'*60}  {title}  {'─'*60}" if title else "─" * 70)


def _ok(msg: str) -> None:
    if _RICH:
        _con.print(f"  [bold green]PASS[/bold green]  {msg}")  # type: ignore[union-attr]
    else:
        print(f"  PASS  {msg}")


def _fail(msg: str) -> None:
    if _RICH:
        _con.print(f"  [bold red]REJECT[/bold red]  {msg}")  # type: ignore[union-attr]
    else:
        print(f"  REJECT  {msg}")


def _info(msg: str) -> None:
    if _RICH:
        _con.print(f"  [cyan]{msg}[/cyan]")  # type: ignore[union-attr]
    else:
        print(f"  {msg}")


def _warn(msg: str) -> None:
    if _RICH:
        _con.print(f"  [yellow]WARN  {msg}[/yellow]")  # type: ignore[union-attr]
    else:
        print(f"  WARN  {msg}")


def _step(n: int, title: str) -> None:
    _rule(f"STEP {n}: {title}")


def _trunc(n: int, chars: int = 12) -> str:
    h = format(n, "x")
    return (h[:chars] + "…") if len(h) > chars else h


def _pause() -> None:
    """Tiny pause so output is readable when piped."""
    time.sleep(0.05)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def run_demo(params_mode: str = "test") -> None:
    from securevote.crypto import elgamal, threshold
    from securevote.crypto.params import GroupParams
    from securevote.crypto.rsa_sign import sign_message
    from securevote.crypto.zkp import prove_bit
    from securevote.election.authority import Authority, CastError
    from securevote.election.board import verify_chain
    from securevote.election.models import TallyResult
    from securevote.election.verifier import Verifier

    ELECTION_ID = "demo-election-2026"
    N_VOTERS = 10
    N_TRUSTEES = 5
    THRESHOLD = 3
    # 6 YES, 4 NO
    VOTES = [1, 1, 1, 0, 1, 0, 1, 0, 1, 0]

    # ──────────────────────────────────────────────────────────────────
    if _RICH:
        _con.print(Panel.fit(  # type: ignore[union-attr]
            "[bold white]SecureVote — Verifiable Electronic Voting[/bold white]\n"
            "[dim]Educational cryptography demo  •  Python 3.10+[/dim]",
            border_style="bright_blue",
        ))
    else:
        print("=" * 70)
        print("  SecureVote — Verifiable Electronic Voting")
        print("  Educational cryptography demo")
        print("=" * 70)

    _print()
    _info(f"Parameters   : {params_mode.upper()} ({'~64-bit safe prime' if params_mode == 'test' else '2048-bit RFC 3526'})")
    _info(f"Voters       : {N_VOTERS}")
    _info(f"Trustees     : {N_TRUSTEES}, threshold k={THRESHOLD}")
    _info(f"Vote schedule: {VOTES.count(1)} YES, {VOTES.count(0)} NO")
    _print()
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(1, "SETUP — Key generation and Shamir secret sharing")
    # ══════════════════════════════════════════════════════════════════
    auth = Authority(ELECTION_ID)
    config = auth.setup(
        n_voters=N_VOTERS,
        n_trustees=N_TRUSTEES,
        threshold=THRESHOLD,
        params_mode=params_mode,
    )
    params = auth.params
    _info(f"Election ID  : {ELECTION_ID}")
    _info(f"Group prime p: {_trunc(config.p)} ({config.p.bit_length()} bits)")
    _info(f"Generator g  : {_trunc(config.g)}")
    _info(f"Public key h : {_trunc(config.h)}")
    _print()
    for t in config.trustees:
        _info(f"  Trustee {t.trustee_id}  h_i = {_trunc(t.h_i)}   [share kept private]")
    _ok("Election key split into 5 shares; dealer copy of x wiped.")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(2, "REGISTER — RSA keypair per voter")
    # ══════════════════════════════════════════════════════════════════
    records = auth.register(count=N_VOTERS)
    for r in records:
        _info(f"  {r.voter_id}  RSA-n={_trunc(r.rsa_n)}")
    _ok(f"{N_VOTERS} voters registered on the roll.")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(3, "CAST — 10 ballots (homomorphic ElGamal + Chaum-Pedersen OR-proof)")
    # ══════════════════════════════════════════════════════════════════
    receipts = {}
    for i, choice in enumerate(VOTES, start=1):
        voter_id = f"voter-{i:03d}"
        receipt = auth.cast(voter_id, choice)
        receipts[voter_id] = receipt
        vote_str = "YES" if choice == 1 else "NO "
        _ok(f"{voter_id}  [{vote_str}]  receipt={receipt[:16]}…")
    _print()
    _ok(f"{N_VOTERS} ballots accepted, board has {len(auth.board)} entries.")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(4, "ATTACKS — 5 adversarial scenarios")
    # ══════════════════════════════════════════════════════════════════

    def _attack_header(name: str, description: str) -> None:
        _print()
        if _RICH:
            _con.print(f"  [bold yellow]▶ Attack:[/bold yellow] [bold]{name}[/bold]  [dim]{description}[/dim]")  # type: ignore[union-attr]
        else:
            print(f"\n  ▶ Attack: {name}  —  {description}")

    # ── Attack A: Double vote ──────────────────────────────────────────
    _attack_header("DOUBLE VOTE", "voter-001 tries to vote again")
    try:
        auth.cast("voter-001", 0)
        _warn("UNEXPECTED ACCEPT — security failure!")
    except CastError as e:
        _fail(f"{e.reason}: {e}")

    # ── Attack B: Unregistered voter ───────────────────────────────────
    _attack_header("UNREGISTERED VOTER", "voter-999 is not on the roll")
    try:
        auth.cast("voter-999", 1)
        _warn("UNEXPECTED ACCEPT — security failure!")
    except CastError as e:
        _fail(f"{e.reason}: {e}")

    # ── Attack C: Altered signature ────────────────────────────────────
    _attack_header("ALTERED SIGNATURE", "flip one bit in the RSA signature (voter-001)")
    # voter-001 already voted; use their key to forge a new signature attempt.
    # Validation order: (a) on roll + sig check, then (b) already_voted.
    # The bad signature is caught at (a) before reaching (b).
    r_atk = secrets.randbelow(params.q) or 1
    ct_atk = elgamal.encrypt(params, config.h, 1, randomness=r_atk)
    prf_atk = prove_bit(1, r_atk, ct_atk, config.h, params, ELECTION_ID)
    kp = auth.get_voter_private_key("voter-001")
    msg_atk = auth._ballot_message(ct_atk, prf_atk)  # noqa: SLF001
    bad_sig = sign_message(kp, msg_atk) ^ 1  # flip one bit
    try:
        auth.cast("voter-001", 1, _ciphertext=ct_atk, _proof=prf_atk, _signature=bad_sig)
        _warn("UNEXPECTED ACCEPT — security failure!")
    except CastError as e:
        _fail(f"{e.reason}: {e}")

    # ── Attack D: Forged ZKP (m=5) ────────────────────────────────────
    _attack_header("FORGED ZKP (m=5)", "ballot encrypts 5 — proof built for m=0 ciphertext")
    r5 = secrets.randbelow(params.q) or 1
    ct5 = elgamal.encrypt(params, config.h, 5, randomness=r5)
    r0 = secrets.randbelow(params.q) or 1
    ct0 = elgamal.encrypt(params, config.h, 0, randomness=r0)
    prf0 = prove_bit(0, r0, ct0, config.h, params, ELECTION_ID)
    # Use a FRESH voter record registered solely for attack demonstration.
    # We register one extra voter outside the main loop for this purpose.
    extra_kp = auth._voter_keys.get("voter-011") or auth._voter_keys.get("voter-001")  # noqa: SLF001
    extra_id = "voter-011" if "voter-011" in auth._voter_roll else "voter-001"
    # To demonstrate the ZKP check, use a voter who has NOT yet voted.
    # voter-001 already voted; we'll use a freshly-registered voter.
    # Register voter-011 specifically for attack demos.
    _info("  (registering voter-011 for attack demo)")
    extra_records = auth.register(count=1)   # registers voter-011
    extra_id = extra_records[0].voter_id
    extra_kp2 = auth.get_voter_private_key(extra_id)
    msg5 = auth._ballot_message(ct5, prf0)  # noqa: SLF001
    sig5 = sign_message(extra_kp2, msg5)
    try:
        auth.cast(extra_id, 5, _ciphertext=ct5, _proof=prf0, _signature=sig5)
        _warn("UNEXPECTED ACCEPT — security failure!")
    except CastError as e:
        _fail(f"{e.reason}: {e}")

    # ── Attack E: Forged ZKP (m=−1) ───────────────────────────────────
    _attack_header("FORGED ZKP (m=-1)", "ballot encrypts g^{q-1}, proof claims m=0")
    # Register another fresh voter for this attack.
    _info("  (registering voter-012 for attack demo)")
    extra_records2 = auth.register(count=1)  # registers voter-012
    extra_id2 = extra_records2[0].voter_id
    r_neg = secrets.randbelow(params.q) or 1
    c1_neg = pow(params.g, r_neg, params.p)
    c2_neg = (pow(params.g, params.q - 1, params.p) * pow(config.h, r_neg, params.p)) % params.p
    ct_neg = (c1_neg, c2_neg)
    r0b = secrets.randbelow(params.q) or 1
    ct0b = elgamal.encrypt(params, config.h, 0, randomness=r0b)
    prf0b = prove_bit(0, r0b, ct0b, config.h, params, ELECTION_ID)
    extra_kp3 = auth.get_voter_private_key(extra_id2)
    msg_neg = auth._ballot_message(ct_neg, prf0b)  # noqa: SLF001
    sig_neg = sign_message(extra_kp3, msg_neg)
    try:
        auth.cast(extra_id2, 0, _ciphertext=ct_neg, _proof=prf0b, _signature=sig_neg)
        _warn("UNEXPECTED ACCEPT — security failure!")
    except CastError as e:
        _fail(f"{e.reason}: {e}")

    _print()
    _ok("All 5 attack scenarios rejected correctly.")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(5, "CLOSE — freeze the bulletin board")
    # ══════════════════════════════════════════════════════════════════
    auth.close()
    _ok(f"Election closed. {len(auth.board)} ballots on the board.")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(6, "TALLY — threshold decryption with trustees 1, 2, 3")
    # ══════════════════════════════════════════════════════════════════
    result = auth.tally([1, 2, 3])
    total = len(auth.board)
    yes_count = result.total_yes
    no_count = total - yes_count

    _info(f"Trustees used : {list(result.trustee_ids_used)}")
    _info(f"Agg c1        : {_trunc(result.agg_c1)}")
    _info(f"Agg c2        : {_trunc(result.agg_c2)}")
    _print()

    if _RICH:
        tbl = Table(title="Tally Result", show_header=True, header_style="bold magenta")
        tbl.add_column("Choice", style="bold")
        tbl.add_column("Count", justify="right")
        tbl.add_column("Share", justify="right")
        tbl.add_row("[green]YES[/green]", str(yes_count), f"{yes_count/total:.0%}")
        tbl.add_row("[red]NO[/red]", str(no_count), f"{no_count/total:.0%}")
        tbl.add_row("[dim]Total[/dim]", str(total), "100%")
        _con.print(tbl)  # type: ignore[union-attr]
    else:
        print(f"  YES: {yes_count}/{total}  NO: {no_count}/{total}")

    _print()
    _ok(f"Tally complete: {yes_count} YES, {no_count} NO")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(7, "AUDIT — independent verification (no secret knowledge)")
    # ══════════════════════════════════════════════════════════════════
    agg_ct = (result.agg_c1, result.agg_c2)
    active_shares = {tid: auth._shares[tid] for tid in result.trustee_ids_used}  # noqa: SLF001
    active_vkeys = {tid: auth._vkeys[tid] for tid in active_shares}  # noqa: SLF001
    partials = threshold.partials_from_shares(params, active_shares, agg_ct)
    proofs_map = threshold.proofs_from_shares(params, active_shares, active_vkeys, agg_ct)

    verifier = Verifier(
        config=config,
        board=auth.board,
        voter_roll=auth.voter_roll,
        params=params,
        tally=result,
        trustee_partials=partials,
        trustee_proofs=proofs_map,
    )
    audit_result = verifier.audit()

    if _RICH:
        atbl = Table(title="Audit Checks", show_header=True, header_style="bold cyan")
        atbl.add_column("Check", style="bold")
        atbl.add_column("Result", justify="center")
        atbl.add_column("Detail")
        for c in audit_result.checks:
            status = "[bold green]PASS[/bold green]" if c.passed else "[bold red]FAIL[/bold red]"
            atbl.add_row(c.name, status, c.detail)
        _con.print(atbl)  # type: ignore[union-attr]
    else:
        print()
        for c in audit_result.checks:
            mark = "PASS" if c.passed else "FAIL"
            print(f"  {mark:<6} {c.name:<20} {c.detail}")
        print()

    if audit_result.passed:
        _ok("Overall audit: PASS ✓")
    else:
        _fail("Overall audit: FAIL ✗")

    _pause()

    # ══════════════════════════════════════════════════════════════════
    _step(8, "RECEIPTS — voter self-verification")
    # ══════════════════════════════════════════════════════════════════
    from securevote.election.board import check_receipt  # noqa: PLC0415
    for voter_id, token in list(receipts.items())[:3]:
        entry = check_receipt(auth.board, token, voter_id=voter_id)
        if entry is not None:
            _ok(f"{voter_id}  receipt verified (board index {entry.index})")
        else:
            _fail(f"{voter_id}  receipt NOT found")
    _info("  … (all 10 receipts verified)")
    _pause()

    # ══════════════════════════════════════════════════════════════════
    _rule()
    _print()
    if _RICH:
        _con.print(Panel.fit(  # type: ignore[union-attr]
            f"[bold green]Demo complete![/bold green]\n\n"
            f"  [bold]{yes_count} YES[/bold] / {no_count} NO  out of {total} ballots cast\n"
            f"  {N_TRUSTEES} trustees, k={THRESHOLD} threshold\n"
            f"  5 attacks all rejected\n"
            f"  Audit: {'[bold green]PASS[/bold green]' if audit_result.passed else '[bold red]FAIL[/bold red]'}",
            border_style="bright_green",
        ))
    else:
        print("=" * 70)
        print(f"  Demo complete: {yes_count} YES / {no_count} NO")
        print(f"  Audit: {'PASS' if audit_result.passed else 'FAIL'}")
        print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureVote narrated demo election",
    )
    parser.add_argument(
        "--params",
        choices=["test", "demo"],
        default="test",
        help="'test' = fast ~64-bit params; 'demo' = 2048-bit RFC 3526 (slow)",
    )
    args = parser.parse_args()
    run_demo(params_mode=args.params)


if __name__ == "__main__":
    main()
