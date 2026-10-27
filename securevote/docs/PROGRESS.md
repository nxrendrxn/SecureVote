# SecureVote — Project Progress

*Last updated: Phase 7 complete (2026-10-28). ALL PHASES DONE. 133 tests passing.*

---

## Observed Conventions

| Convention | Detail |
|---|---|
| **Python version** | 3.10 (runtime) — code uses 3.11+ type syntax (`int \| None`) guarded by `from __future__ import annotations` |
| **Randomness** | `secrets` everywhere; never `random` |
| **Group arithmetic** | `pow(a, b, p)` throughout; Fermat inverse `pow(x, q-1, p)` used on order-q elements |
| **Subgroup validation** | `validate_subgroup_element(params, y)` asserts `1 < y < p` and `pow(y, q, p) == 1`; called on every external element |
| **Canonical serialisation** | Sorted-key JSON, big-ints as decimal strings — used for hashing/signing |
| **Comparison** | `hmac.compare_digest` on byte strings; never `==` on digests/signatures |
| **Dataclasses** | `@dataclass(frozen=True)` for all public key/proof types |
| **Error handling** | Raise `ValueError` with a descriptive message; never silently swallow |
| **Type hints** | All public functions have full type annotations + docstrings |
| **Params fixture** | `scope="module"` fixture returning `load_params("test")` used in every test file |
| **Terminal output** | `rich` used if available for coloured output; plain `print` fallback |
| **Test speed** | All tests use `"test"` params (~64-bit safe prime); demo params only in a single smoke test |

---

## Phase 1 — Primes & Params & ElGamal ✅

### `crypto/primes.py`
| Symbol | Signature |
|---|---|
| `miller_rabin` | `(n, witnesses=None) -> bool` |
| `is_probable_prime` | `(n, bits_hint=None) -> bool` |
| `random_prime` | `(bits, max_attempts=10_000) -> int` |
| `random_safe_prime` | `(bits, max_attempts=10_000) -> tuple[int, int]` — returns `(p, q)` |

### `crypto/params.py`
| Symbol | Signature |
|---|---|
| `GroupParams` | `frozen dataclass(p, q, g)` — `__post_init__` validates safe-prime structure and subgroup membership |
| `validate_subgroup_element` | `(params, y) -> None` — raises `ValueError` |
| `load_params` | `(mode: "demo"\|"test") -> GroupParams` |
| `load_demo_params` | `() -> GroupParams` — RFC 3526 Group 14, 2048-bit |
| `load_test_params` | `() -> GroupParams` — fresh random ~64-bit safe prime each call |

### `crypto/elgamal.py`
| Symbol | Signature |
|---|---|
| `Ciphertext` | `tuple[int, int]` alias |
| `KeyPair` | `tuple[int, int]` alias — `(private_x, public_h)` |
| `keygen` | `(params) -> KeyPair` |
| `encrypt` | `(params, public_key, message, randomness=None) -> Ciphertext` |
| `homomorphic_add` | `(c1, c2, p) -> Ciphertext` |
| `decrypt_value` | `(params, private_key, ciphertext) -> int` — returns `g^m` |
| `decrypt` | `(params, private_key, ciphertext, max_m) -> int` |
| `brute_force_discrete_log` | `(params, target, max_m) -> int` |

### Tests (`tests/test_phase1_*.py`) — 10 tests ✅

---

## Phase 2 — Shamir & Threshold ✅

### `crypto/shamir.py`
| Symbol | Signature |
|---|---|
| `Share` | `tuple[int, int]` alias — `(trustee_id, share_value)` |
| `lagrange_coefficient_at_zero` | `(trustee_id, peer_ids, q) -> int` |
| `split_secret` | `(secret, n, threshold, q) -> dict[int, int]` — id→value |
| `reconstruct_secret` | `(shares: Mapping[int,int], q) -> int` |
| `trustee_verification_key` | `(params_g, share_value, p, q) -> int` — `h_i = g^{x_i}` |

### `crypto/threshold.py`
| Symbol | Signature |
|---|---|
| `PartialDecryption` | `tuple[int, int]` alias — `(trustee_id, d_i)` |
| `partial_decrypt` | `(params, share_value, ciphertext) -> int` — `d_i = c1^{x_i}` |
| `combine_partial_decryptions` | `(params, partials: Mapping[int,int], threshold) -> int` |
| `threshold_decrypt_value` | `(params, ciphertext, partials, threshold) -> int` — returns `g^m` |
| `threshold_decrypt` | `(params, ciphertext, partials, threshold, max_m) -> int` |
| `partials_from_shares` | `(params, shares, ciphertext) -> dict[int,int]` |

### Tests (`tests/test_phase2_shamir_threshold.py`) — 5 tests ✅

---

## Phase 3 — RSA Signatures ✅

### `crypto/rsa_sign.py`
| Symbol | Signature |
|---|---|
| `RSAPublicKey` | `frozen dataclass(n, e=65537)` |
| `RSAKeyPair` | `frozen dataclass(public, d, p, q)` with `.n`, `.e` properties |
| `sha256_digest` | `(message: bytes) -> bytes` — **temporary**, moves to `hashing.py` Phase 5 |
| `emsa_pkcs1_v15_encode_sha256` | `(message_hash: bytes, modulus_bits: int) -> int` |
| `generate_rsa_keypair` | `(mode: "test"\|"demo") -> RSAKeyPair` |
| `sign_message` | `(key, message: bytes) -> int` |
| `verify_signature` | `(public_key, message: bytes, signature: int) -> bool` |
| `signature_to_bytes` | `(signature, modulus_n) -> bytes` |
| `signature_from_bytes` | `(data: bytes) -> int` |

### Tests (`tests/test_phase3_rsa_sign.py`) — 5 tests ✅ (including pycryptodome cross-check)

---

## Phase 4 — ZKP (Chaum-Pedersen / Fiat-Shamir) ✅

### `crypto/zkp.py`
| Symbol | Signature |
|---|---|
| `BitProof` | `frozen dataclass(a0,b0,a1,b1,e0,e1,z0,z1)` |
| `prove_bit` | `(m, r, ciphertext, h, params, election_id) -> BitProof` |
| `verify_bit` | `(ciphertext, proof, h, params, election_id) -> bool` |
| `PartialDecryptionProof` | `frozen dataclass(A, B, e, z)` |
| `prove_partial_decryption` | `(share_value, h_i, ciphertext, params) -> PartialDecryptionProof` |
| `verify_partial_decryption` | `(d_i, h_i, ciphertext, proof, params) -> bool` |

### `crypto/threshold.py` (updated)
- `combine_partial_decryptions` now accepts optional `verification_keys: Mapping[int, int] | None`
- When `verification_keys` is supplied, each partial `d_i` is checked via Chaum-Pedersen before use; invalid trustees are excluded (logged) rather than crashing
- `threshold_decrypt` and `threshold_decrypt_value` accept the same `verification_keys` kwarg

### Tests (`tests/test_phase4_zkp.py`) — 16 tests ✅

---

## Phase 5 — Hashing & Bulletin Board ✅

### `crypto/hashing.py`
| Symbol | Signature |
|---|---|
| `sha256_digest` | `(message: bytes) -> bytes` — moved here from `rsa_sign.py` |
| `canonical_json` | `(obj: dict) -> bytes` — sorted-key JSON, ints as decimal strings |
| `hash_canonical` | `(obj: dict) -> bytes` — `sha256_digest(canonical_json(obj))` |
| `entry_hash` | `(prev_hash_hex: str, entry_fields: dict) -> str` — 64-char hex |
| `voter_receipt` | `(ciphertext: tuple[int,int], election_id: str, timestamp: str) -> str` — 64-char hex |

### `election/board.py`
| Symbol | Signature |
|---|---|
| `GENESIS_PREV_HASH` | `"0" * 64` — constant used for the first entry |
| `BoardEntry` | `frozen dataclass(index, voter_id, ballot, signature, timestamp, prev_hash, entry_hash)` |
| `BulletinBoard` | `__init__(election_id)` · `append(*, voter_id, ballot, signature, timestamp) -> BoardEntry` · `close()` · `has_voted(voter_id) -> bool` · `entry_for_voter(voter_id) -> BoardEntry\|None` · `entries` property · `is_closed` property |
| `verify_chain` | `(board) -> Optional[int]` — `None` if intact, else first broken index |
| `voter_receipt` | re-exported from `hashing` |
| `check_receipt` | `(board, receipt_hex, voter_id=None) -> Optional[BoardEntry]` |

### Tests (`tests/test_phase5_board.py`) — 36 tests ✅

---

## Phase 6 — Election Package & CLI ✅

### `election/models.py`
| Symbol | Signature |
|---|---|
| `TrusteeInfo` | `frozen dataclass(trustee_id, h_i)` · `to_dict/from_dict` |
| `ElectionConfig` | `frozen dataclass(election_id, params_mode, p, q, g, h, n_trustees, threshold, trustees, n_voters, status, tally)` · `to_dict/from_dict/to_json/from_json` |
| `VoterRecord` | `frozen dataclass(voter_id, rsa_n, rsa_e)` · `to_dict/from_dict` |
| `CastBallot` | `frozen dataclass(voter_id, c1, c2, proof, signature, timestamp, receipt)` · `to_ballot_dict/from_ballot_dict/to_dict/from_dict` |
| `TallyResult` | `frozen dataclass(agg_c1, agg_c2, total_yes, trustee_ids_used)` · `to_dict/from_dict` |

### `election/authority.py`
| Symbol | Signature |
|---|---|
| `CastError` | `Exception(reason, message)` — reason codes: `not_registered`, `invalid_signature`, `already_voted`, `invalid_zkp` |
| `Authority` | `__init__(election_id)` · `setup(n_voters, n_trustees, threshold, params_mode)` · `register(count)` · `cast(voter_id, choice, *, _ciphertext, _proof, _signature)` · `close()` · `tally(trustee_ids)` · `get_share(trustee_id)` · `get_voter_private_key(voter_id)` |

### `election/verifier.py`
| Symbol | Signature |
|---|---|
| `CheckResult` | `dataclass(name, passed, detail)` |
| `AuditResult` | `dataclass(checks)` · `passed` property · `add()` |
| `Verifier` | `__init__(config, board, voter_roll, params, tally, trustee_partials, trustee_proofs)` · `check_signatures()` · `check_zkps()` · `check_chain()` · `check_aggregate()` · `check_published_total()` · `audit()` |

### `cli.py`
9 subcommands: `setup`, `register`, `cast`, `close`, `tally`, `audit`, `receipt`, `attack`, `reset`.
State persisted as JSON in `data/` (election.json, board.json, roll.json, tally.json, trustees/<id>.json, voters/<id>.key.json, receipts/<id>.txt).

### Tests (`tests/test_phase6_election.py`) — 36 tests ✅

---

## Phase 7 — Attacks, Demo, README ✅

### `tests/test_phase7_attacks.py`
13 tests numbered `test_01_` … `test_13_`, one per row of the spec attack table:

| Test | Scenario | Expected |
|------|----------|----------|
| 01 | Valid ballot | accepted |
| 02 | Double vote | `CastError(already_voted)` |
| 03 | Voter not on roll | `CastError(not_registered)` |
| 04 | Signature altered (bit flip) | `CastError(invalid_signature)` |
| 05 | Ciphertext modified after signing | `CastError(invalid_signature)` |
| 06 | Ballot encrypts m=5 with forged proof | `CastError(invalid_zkp)` |
| 07 | Ballot encrypts m=−1 | `CastError(invalid_zkp)` |
| 08 | Tally with exactly k trustees | correct result |
| 09 | Tally with k−1 trustees | `ValueError` |
| 10 | Trustee gives wrong partial | excluded via Chaum-Pedersen; tally OK |
| 11 | Board entry deleted | `verify_chain()` returns first bad index |
| 12 | Board entry edited | `verify_chain()` returns that entry's index |
| 13 | Published total altered | `Verifier.check_published_total()` fails |

### `demo.py`
8-step narrated election script:
1. Setup (GroupParams, keygen, Shamir split, print h_i per trustee)
2. Register (10 voters, RSA keypairs)
3. Cast (10 ballots: 6 YES / 4 NO, print each receipt)
4. Attacks × 5 (double_vote, unregistered, bad_signature, forged_zkp_m5, forged_zkp_neg1)
5. Close
6. Tally (trustees 1,2,3, rich table: YES/NO/Total)
7. Audit (rich table: 5 checks, all PASS)
8. Receipts (spot-check 3 voters)

Run with: `python -m securevote.demo` (test params) or `python -m securevote.demo --params demo` (2048-bit).

### `README.md`
Located at `D:\Downloads\Desktop\Crypto-Project\README.md`:
- Mermaid `flowchart TD` architecture diagram
- Mermaid `sequenceDiagram` election flow
- Math summary (GroupParams, ElGamal, Shamir, OR-proof, Chaum-Pedersen, hash chain, receipt)
- Project structure tree
- Installation and usage (demo, CLI walkthrough, pytest)
- 13-row attack-scenario table
- Limitations section (anonymity, trusted dealer, coercion resistance, demo scale, no constant-time, single-candidate)

- [x] **Phase 4** — `crypto/zkp.py` + `threshold.py` update ✅

- [x] **Phase 5** — `hashing.py` + `election/board.py` ✅
  - `sha256_digest` moved to `hashing.py`; `rsa_sign.py` imports and re-exports it (Phase 3 tests unchanged)
  - `canonical_json`, `hash_canonical`, `entry_hash`, `voter_receipt` in `hashing.py`
  - `election/board.py`: `BoardEntry` frozen dataclass, `BulletinBoard` (append-only, closed-flag), `verify_chain()` (first broken index), `check_receipt()`, `voter_receipt` re-export
  - Tests: 36 new tests (hashing, board basics, deleted/edited/reordered tamper detection, receipt lookup)

- [x] **Phase 6** — `election/` package + `cli.py` ✅
  - `models.py`: `ElectionConfig`, `TrusteeInfo`, `VoterRecord`, `CastBallot`, `TallyResult` — frozen dataclasses with `to_dict`/`from_dict`
  - `authority.py`: `Authority` class — `setup/register/cast/close/tally`; `CastError` with reason codes; validation order (a)→(b)→(c); `_ciphertext/_proof/_signature` injection kwargs for attack simulation
  - `verifier.py`: `Verifier` class — `check_signatures/check_zkps/check_chain/check_aggregate/check_published_total/audit()`; `AuditResult`/`CheckResult` dataclasses; independent of authority secrets
  - `cli.py`: argparse with `setup/register/cast/close/tally/audit/receipt/attack/reset`; JSON persistence in `data/`; 6 attack scenarios
  - Tests: 36 new tests covering happy-path flow, all rejection reasons, model round-trips, and all 5 verifier checks

- [x] **Phase 7** — Attacks, demo, README ✅
  - `tests/test_phase7_attacks.py`: all 13 spec-table scenarios, one test per row, numbered `test_01_` … `test_13_`
  - `demo.py`: 8-step narrated election — setup → register → cast (10 voters, 6 YES / 4 NO) → 5 attacks → close → tally (trustees 1,2,3) → audit (5 checks) → receipt verification; `rich` tables when available
  - `README.md`: Mermaid architecture + sequence diagrams, full math summary, project structure, usage (demo + CLI + pytest), attack-scenario table, Limitations section
  - Tests: 13 new tests (133 total)

---

## Baseline Test Count

| Phase | Tests |
|---|---|
| 1 (Primes + ElGamal) | 10 |
| 2 (Shamir + Threshold) | 5 |
| 3 (RSA) | 5 |
| 4 (ZKP) | 28 |
| 5 (Hashing + Board) | 36 |
| 6 (Election + CLI) | 36 |
| 7 (Attacks) | 13 |
| **Total** | **133** |
