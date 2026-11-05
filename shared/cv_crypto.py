"""
CipherVault cryptographic primitives.

Responsibilities:
  - generate a fresh document key (DEK)
  - encrypt/decrypt PDF bytes under a DEK with AES-256-GCM,
    binding the container header and policy reference into AAD
  - wrap/unwrap the DEK under a server-held master key (KEK),
    binding document identity into the wrapping AAD

This module is used by both backend and desktop viewer. It performs no
I/O and touches no database — callers supply keys and bytes, receive bytes.
"""
from __future__ import annotations

import os
import secrets
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGO = "AES-256-GCM"
KEY_SIZE = 32          # bytes (AES-256)
NONCE_SIZE = 12        # bytes (GCM standard)
SALT_SIZE = 16         # bytes


class CryptoError(Exception):
    """Base class for all CipherVault crypto errors."""


class AuthenticationFailed(CryptoError):
    """Raised when GCM authentication fails: ciphertext, AAD, or key is wrong."""


class BadKeyError(CryptoError):
    """Raised when a key has the wrong length."""


# --------------------------------------------------------------------------
# Document key generation
# --------------------------------------------------------------------------

def generate_document_key() -> bytes:
    """32 bytes of cryptographic randomness."""
    return secrets.token_bytes(KEY_SIZE)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)


def _ensure_key(key: bytes, name: str = "key") -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise BadKeyError(f"{name} must be bytes")
    if len(key) != KEY_SIZE:
        raise BadKeyError(f"{name} must be {KEY_SIZE} bytes, got {len(key)}")


# --------------------------------------------------------------------------
# PDF body encryption / decryption
# --------------------------------------------------------------------------

def build_body_aad(
    header_bytes: bytes,
    policy_ref: bytes,
    app_aad: bytes,
) -> bytes:
    """
    Canonical AAD for the AES-GCM seal of the PDF ciphertext.

    Layout (all lengths are uint32 big-endian):
      b"CVAULT-BODY-AAD-v1"
      || uint32(len(header_bytes)) || header_bytes
      || uint32(len(policy_ref))   || policy_ref
      || uint32(len(app_aad))      || app_aad

    Prefixing with a version string keeps this separable from other AAD
    constructions in the system (e.g. key wrapping AAD).
    """
    prefix = b"CVAULT-BODY-AAD-v1"
    hdr_len = len(header_bytes).to_bytes(4, "big")
    pol_len = len(policy_ref).to_bytes(4, "big")
    app_len = len(app_aad).to_bytes(4, "big")
    return prefix + hdr_len + header_bytes + pol_len + policy_ref + app_len + app_aad


def encrypt_pdf(
    plaintext: bytes,
    document_key: bytes,
    *,
    header_bytes: bytes,
    policy_ref: str,
    app_aad: bytes = b"",
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt PDF bytes under document_key.

    Returns (aad, nonce, ciphertext) where ciphertext includes the GCM tag.
    `aad` is the canonical body AAD constructed by build_body_aad(); it must
    be stored in the container so decryption can reconstruct it.
    """
    _ensure_key(document_key, "document_key")
    if not isinstance(policy_ref, str):
        raise TypeError("policy_ref must be str")
    policy_b = policy_ref.encode("utf-8")
    aad = build_body_aad(header_bytes, policy_b, app_aad)
    nonce = generate_nonce()
    ciphertext = AESGCM(document_key).encrypt(nonce, plaintext, aad)
    return aad, nonce, ciphertext


def decrypt_pdf(
    ciphertext: bytes,
    document_key: bytes,
    *,
    aad: bytes,
    nonce: bytes,
) -> bytes:
    """
    Decrypt PDF bytes. Raises AuthenticationFailed if any part of the
    ciphertext, AAD, or nonce is invalid or the key is wrong.
    """
    _ensure_key(document_key, "document_key")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError(f"nonce must be {NONCE_SIZE} bytes")
    try:
        return AESGCM(document_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationFailed("GCM tag verification failed")


# --------------------------------------------------------------------------
# Key wrapping: DEK protected by the server master key (KEK)
# --------------------------------------------------------------------------

_WRAP_PREFIX = b"CVAULT-DEK-WRAP-v1"


def build_wrap_aad(document_id_hex: str, salt: bytes) -> bytes:
    """
    AAD for the DEK wrapping. Binds the wrapping to a specific document UUID
    and a random salt, so a wrapped DEK cannot be swapped onto another
    document's record.
    """
    if not isinstance(document_id_hex, str):
        raise TypeError("document_id_hex must be str")
    if len(salt) != SALT_SIZE:
        raise BadKeyError(f"salt must be {SALT_SIZE} bytes")
    doc_b = document_id_hex.encode("ascii")
    return (
        _WRAP_PREFIX
        + len(salt).to_bytes(4, "big") + salt
        + len(doc_b).to_bytes(4, "big") + doc_b
    )


def wrap_document_key(
    master_key: bytes,
    document_key: bytes,
    *,
    document_id_hex: str,
    salt: bytes,
) -> Tuple[bytes, bytes]:
    """
    Encrypt a document key under the master key.

    Returns (wrap_nonce, wrapped_ciphertext) — both go into the DB record.
    Never call this with a document key sourced from anywhere but
    generate_document_key().
    """
    _ensure_key(master_key, "master_key")
    _ensure_key(document_key, "document_key")
    aad = build_wrap_aad(document_id_hex, salt)
    nonce = generate_nonce()
    wrapped = AESGCM(master_key).encrypt(nonce, document_key, aad)
    return nonce, wrapped


def unwrap_document_key(
    master_key: bytes,
    wrap_nonce: bytes,
    wrapped_ciphertext: bytes,
    *,
    document_id_hex: str,
    salt: bytes,
) -> bytes:
    """
    Recover the document key. Raises AuthenticationFailed if the master key
    is wrong, the salt/UUID don't match, or the wrapped blob was tampered.
    """
    _ensure_key(master_key, "master_key")
    if len(wrap_nonce) != NONCE_SIZE:
        raise CryptoError(f"wrap_nonce must be {NONCE_SIZE} bytes")
    aad = build_wrap_aad(document_id_hex, salt)
    try:
        return AESGCM(master_key).decrypt(wrap_nonce, wrapped_ciphertext, aad)
    except InvalidTag:
        raise AuthenticationFailed("DEK unwrap failed (wrong master key or tampered blob)")


# --------------------------------------------------------------------------
# Master key loading (from environment)
# --------------------------------------------------------------------------

MASTER_KEY_ENV = "CIPHERVAULT_MASTER_KEY"


def load_master_key_from_env() -> bytes:
    """
    Load the 32-byte master key from $env:CIPHERVAULT_MASTER_KEY, hex-encoded.
    Raises RuntimeError with a clear message if missing or malformed — this
    must fail closed: if the key isn't configured, no crypto is performed.
    """
    raw = os.environ.get(MASTER_KEY_ENV)
    if not raw:
        raise RuntimeError(
            f"{MASTER_KEY_ENV} is not set. "
            f"Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError:
        raise RuntimeError(f"{MASTER_KEY_ENV} is not valid hex")
    if len(key) != KEY_SIZE:
        raise RuntimeError(
            f"{MASTER_KEY_ENV} must decode to {KEY_SIZE} bytes, got {len(key)}"
        )
    return key
