"""
Threshold partial decryption for exponential ElGamal tallying.

Given aggregated ciphertext ``(c1, c2)`` encrypting the sum of votes, trustee ``i``
holds Shamir share ``x_i`` of the election secret ``x`` and publishes

  ``d_i = c1^{x_i} mod p``.

Lagrange interpolation in the exponent yields

  ``c1^x = Π_i d_i^{λ_i(0)} mod p``,

using any ``k`` valid partials. Then ``g^m = c2 / c1^x mod p`` as in single-key
decrypt. Trustees never combine shares to recover ``x`` itself.

Phase 4 addition
----------------
``combine_partial_decryptions`` now accepts an optional ``verification_keys``
mapping (``trustee_id → h_i``).  When supplied, every partial ``d_i`` is
checked with a Chaum-Pedersen proof (``PartialDecryptionProof``) before being
used in the Lagrange combination.  Trustees whose proofs fail are **excluded and
reported** rather than raising an exception, so a single bad trustee does not
block the tally as long as at least ``threshold`` honest trustees remain.
"""

from __future__ import annotations

from typing import Dict, Mapping, Tuple

from securevote.crypto import elgamal
from securevote.crypto.elgamal import Ciphertext
from securevote.crypto.params import GroupParams, validate_subgroup_element
from securevote.crypto.shamir import lagrange_coefficient_at_zero

PartialDecryption = Tuple[int, int]  # (trustee_id, d_i)


def partial_decrypt(
    params: GroupParams,
    share_value: int,
    ciphertext: Ciphertext,
) -> int:
    """
    Trustee partial decryption: ``d_i = c1^{x_i} mod p``.

    ``share_value`` is the trustee's Shamir share of the election private key.
    """
    if not (0 <= share_value < params.q):
        raise ValueError("share value out of range")
    c1, _c2 = ciphertext
    validate_subgroup_element(params, c1)
    d_i = pow(c1, share_value, params.p)
    validate_subgroup_element(params, d_i)
    return d_i


def combine_partial_decryptions(
    params: GroupParams,
    partials: Mapping[int, int],
    threshold: int,
    *,
    verification_keys: Mapping[int, int] | None = None,
    proofs: Mapping[int, object] | None = None,
    ciphertext: Ciphertext | None = None,
) -> int:
    """
    Combine ``d_i`` into ``c1^x mod p`` using Lagrange weights at 0.

    Parameters
    ----------
    params:
        Group parameters.
    partials:
        Mapping ``trustee_id → d_i``.
    threshold:
        Minimum number of valid partials required.
    verification_keys:
        Optional mapping ``trustee_id → h_i = g^{x_i}``.  When provided
        together with ``proofs`` and ``ciphertext``, each partial is verified
        using Chaum-Pedersen before combination.  Invalid trustees are logged
        and excluded; if fewer than ``threshold`` valid partials remain the
        function raises ``ValueError``.
    proofs:
        Optional mapping ``trustee_id → PartialDecryptionProof``.
    ciphertext:
        The aggregate ciphertext ``(c1, c2)`` needed for proof verification.

    Returns
    -------
    int
        ``c1^x mod p``.

    Raises
    ------
    ValueError
        If fewer than ``threshold`` valid partials are available.
    """
    # Lazy import to avoid circular-import at module load time.
    from securevote.crypto.zkp import verify_partial_decryption  # noqa: PLC0415

    verify_enabled = (
        verification_keys is not None
        and proofs is not None
        and ciphertext is not None
    )

    # Build the active set, excluding any trustees that fail verification.
    active_partials: Dict[int, int] = {}
    bad_trustees: list[int] = []

    for trustee_id, d_i in partials.items():
        if verify_enabled:
            assert verification_keys is not None  # narrowing for mypy
            assert proofs is not None
            assert ciphertext is not None
            h_i = verification_keys.get(trustee_id)
            proof = proofs.get(trustee_id)
            if h_i is None or proof is None:
                # Missing key or proof — skip trustee.
                bad_trustees.append(trustee_id)
                continue
            valid = verify_partial_decryption(d_i, h_i, ciphertext, proof, params)  # type: ignore[arg-type]
            if not valid:
                bad_trustees.append(trustee_id)
                continue
        active_partials[trustee_id] = d_i

    if bad_trustees:
        # Report (not raise) so the caller knows which trustees were skipped.
        names = ", ".join(str(t) for t in sorted(bad_trustees))
        print(f"[threshold] WARNING: excluded trustee(s) {names} — invalid partial-decryption proof")

    if len(active_partials) < threshold:
        raise ValueError(
            f"insufficient partial decryptions: need {threshold}, got {len(active_partials)}"
        )

    ids = sorted(active_partials.keys())

    # Use exactly the first k ids in sorted order for deterministic combine when
    # more than k partials are provided (caller may pass a chosen subset).
    active = ids[:threshold] if len(ids) > threshold else ids
    if len(active) < threshold:
        raise ValueError("insufficient partial decryptions for threshold")

    combined = 1
    for i in active:
        d_i = active_partials[i]
        validate_subgroup_element(params, d_i)
        lam = lagrange_coefficient_at_zero(i, active, params.q)
        combined = (combined * pow(d_i, lam, params.p)) % params.p
    validate_subgroup_element(params, combined)
    return combined


def threshold_decrypt_value(
    params: GroupParams,
    ciphertext: Ciphertext,
    partials: Mapping[int, int],
    threshold: int,
    *,
    verification_keys: Mapping[int, int] | None = None,
    proofs: Mapping[int, object] | None = None,
) -> int:
    """
    Recover ``T = g^m mod p`` from aggregate ciphertext and ``k`` partials.

    ``T = c2 · (c1^x)^{-1}`` where ``c1^x`` is obtained from partial decryptions.
    Optionally verifies each partial via Chaum-Pedersen when ``verification_keys``
    and ``proofs`` are supplied.
    """
    c1, c2 = ciphertext
    validate_subgroup_element(params, c1)
    validate_subgroup_element(params, c2)
    mask = combine_partial_decryptions(
        params,
        partials,
        threshold,
        verification_keys=verification_keys,
        proofs=proofs,
        ciphertext=ciphertext,
    )
    mask_inv = pow(mask, params.q - 1, params.p)
    t = (c2 * mask_inv) % params.p
    if t != 1:
        validate_subgroup_element(params, t)
    return t


def threshold_decrypt(
    params: GroupParams,
    ciphertext: Ciphertext,
    partials: Mapping[int, int],
    threshold: int,
    max_m: int,
    *,
    verification_keys: Mapping[int, int] | None = None,
    proofs: Mapping[int, object] | None = None,
) -> int:
    """
    Threshold-decrypt aggregate ciphertext to plaintext vote sum ``m``.

    Optionally verifies each trustee partial via Chaum-Pedersen proof.
    """
    t = threshold_decrypt_value(
        params,
        ciphertext,
        partials,
        threshold,
        verification_keys=verification_keys,
        proofs=proofs,
    )
    return elgamal.brute_force_discrete_log(params, t, max_m)


def partials_from_shares(
    params: GroupParams,
    shares: Mapping[int, int],
    ciphertext: Ciphertext,
) -> Dict[int, int]:
    """Helper: compute ``d_i`` for each trustee share (simulates trustee role)."""
    return {
        trustee_id: partial_decrypt(params, share_value, ciphertext)
        for trustee_id, share_value in shares.items()
    }


def proofs_from_shares(
    params: GroupParams,
    shares: Mapping[int, int],
    verification_keys: Mapping[int, int],
    ciphertext: Ciphertext,
) -> Dict[int, object]:
    """
    Helper: compute a ``PartialDecryptionProof`` for every trustee share.

    Returns a mapping ``trustee_id → PartialDecryptionProof``.
    """
    from securevote.crypto.zkp import prove_partial_decryption  # noqa: PLC0415

    return {
        trustee_id: prove_partial_decryption(
            share_value,
            verification_keys[trustee_id],
            ciphertext,
            params,
        )
        for trustee_id, share_value in shares.items()
    }


def verification_keys_from_shares(
    params: GroupParams,
    shares: Mapping[int, int],
) -> Dict[int, int]:
    """
    Compute ``h_i = g^{x_i} mod p`` for every trustee share.

    These are published at setup time so partial-decryption proofs can be
    verified without access to the Shamir shares themselves.
    """
    return {
        trustee_id: pow(params.g, share_value, params.p)
        for trustee_id, share_value in shares.items()
    }
