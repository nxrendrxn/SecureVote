"""Phase 3: RSA-PKCS1-v1_5 signatures and pycryptodome cross-check."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from securevote.crypto.rsa_sign import (
    generate_rsa_keypair,
    sha256_digest,
    sign_message,
    signature_from_bytes,
    signature_to_bytes,
    verify_signature,
)


@pytest.fixture(scope="module")
def keypair():
    return generate_rsa_keypair("test")


def test_sign_verify_roundtrip(keypair) -> None:
    msg = b"election_id|ballot|voter-v03"
    sig = sign_message(keypair, msg)
    assert verify_signature(keypair.public, msg, sig)


def test_wrong_message_rejected(keypair) -> None:
    sig = sign_message(keypair, b"original")
    assert not verify_signature(keypair.public, b"tampered", sig)


def test_tampered_signature_rejected(keypair) -> None:
    msg = b"vote"
    sig = sign_message(keypair, msg)
    assert not verify_signature(keypair.public, msg, sig + 1)


def test_sha256_matches_hashlib() -> None:
    msg = b"hash cross-check payload"
    assert sha256_digest(msg) == hashlib.sha256(msg).digest()
    assert sha256_digest(msg) == SHA256.new(msg).digest()


def test_pycryptodome_sign_verify_crosscheck(keypair) -> None:
    """Our sign/verify must agree with pycryptodome for the same key material."""
    message = b"SecureVote phase 3 cross-check message"
    py_key = RSA.construct((keypair.n, keypair.e, keypair.d, keypair.p, keypair.q))

    h = SHA256.new(message)
    ref_sig = pkcs1_15.new(py_key).sign(h)

    our_sig = sign_message(keypair, message)
    our_bytes = signature_to_bytes(our_sig, keypair.n)
    assert hmac.compare_digest(ref_sig, our_bytes)

    pkcs1_15.new(py_key).verify(SHA256.new(message), our_bytes)
    assert verify_signature(keypair.public, message, signature_from_bytes(ref_sig))
