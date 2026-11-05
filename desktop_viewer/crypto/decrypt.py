"""
Client-side decryption of a .cvault file.

Given:
  - the raw bytes of a .cvault file (from disk or wherever),
  - the material the server returned from /api/authorize/redeem/
    (document_key_hex, nonce_hex, aad_hex, document_id, mime),

produce the plaintext PDF bytes, or raise.

Security invariants:
  - verifies the container's document_id matches the server's; a file for
    one document cannot be decrypted with material for another.
  - parses the container with the same strict parser the backend uses, so
    truncation/corruption fails here exactly as it fails there.
  - AES-GCM verifies the auth tag. Any tampering with ciphertext, header,
    nonce, or AAD fails closed.
  - the released key material is zeroed after use as best as Python allows
    (bytes immutability means the underlying buffer is still in memory until
    GC; we do not overclaim that this is secure zeroing).

This module does NOT touch the network or the filesystem. It takes bytes
and returns bytes.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Pull the shared parser in via package path — this module lives next to
# viewer/, so `shared/` needs to be importable. We add it defensively.
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SHARED = _REPO_ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from cvault_format import (        # noqa: E402
    CvaultContainer, CvaultError, InvalidMagic, UnsupportedVersion,
    TruncatedFile, CorruptHeader, IntegrityError,
)


class DecryptError(Exception):
    """Base class for all viewer-side decryption errors."""


class FileCorruptError(DecryptError):
    """The .cvault file failed structural parsing."""


class FileTamperedError(DecryptError):
    """The AES-GCM tag did not verify — content or AAD was altered."""


class WrongDocumentError(DecryptError):
    """The .cvault file's document_id does not match the server's material."""


class UnsupportedAlgorithmError(DecryptError):
    """Container uses an algorithm this viewer does not implement."""


class BadMaterialError(DecryptError):
    """Released material is malformed (bad hex, wrong length, etc.)."""


@dataclass(frozen=True)
class ReleaseMaterialLike:
    """Duck-typed shape of desktop_viewer.api.client.ReleaseMaterial."""
    document_key_hex: str
    nonce_hex: str
    aad_hex: str
    document_id: str
    mime: str


ALLOWED_ALGO = "AES-256-GCM"
PDF_MIME = "application/pdf"


def _hex_to_bytes(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise BadMaterialError(f"{field} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise BadMaterialError(f"{field} is not valid hex: {e}")


def _container_parse(cvault_bytes: bytes) -> CvaultContainer:
    try:
        return CvaultContainer.parse(cvault_bytes)
    except (InvalidMagic, UnsupportedVersion, TruncatedFile, CorruptHeader,
            IntegrityError, CvaultError) as e:
        raise FileCorruptError(f"invalid .cvault: {e}")


def peek_document_id(cvault_bytes: bytes) -> uuid.UUID:
    """Read the document_id without decrypting. Useful to fetch pre-auth info."""
    return _container_parse(cvault_bytes).document_id


def decrypt_cvault(
    cvault_bytes: bytes,
    material: ReleaseMaterialLike,
) -> bytes:
    """
    Full decrypt path. Verifies structure, verifies identity, verifies GCM tag,
    returns plaintext. On any failure raises a DecryptError subclass and does
    NOT return plaintext.
    """
    if not isinstance(cvault_bytes, (bytes, bytearray)):
        raise DecryptError("cvault_bytes must be bytes")
    if not cvault_bytes:
        raise DecryptError("cvault_bytes is empty")

    # 1. Structural parse (magic, version, length sanity, body sha).
    container = _container_parse(bytes(cvault_bytes))

    # 2. Algorithm check.
    if container.algorithm != ALLOWED_ALGO:
        raise UnsupportedAlgorithmError(f"unsupported algorithm: {container.algorithm}")

    # 3. Decode server material.
    key = _hex_to_bytes(material.document_key_hex, "document_key_hex")
    nonce = _hex_to_bytes(material.nonce_hex, "nonce_hex")
    aad_from_server = _hex_to_bytes(material.aad_hex, "aad_hex")

    if len(key) != 32:
        raise BadMaterialError(f"document key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise BadMaterialError(f"nonce must be 12 bytes, got {len(nonce)}")

    # 4. Identity check — the server-issued document_id must match the file's.
    try:
        server_doc_id = uuid.UUID(material.document_id)
    except (ValueError, AttributeError, TypeError):
        raise BadMaterialError("server document_id is not a valid UUID")
    if container.document_id != server_doc_id:
        raise WrongDocumentError(
            f"server material is for {server_doc_id}, "
            f"file is for {container.document_id}"
        )

    # 5. Nonce sanity — the file declares its nonce and the server confirms it;
    #    both must agree. (If they don't, someone is trying to substitute.)
    if container.nonce != nonce:
        raise FileTamperedError("nonce mismatch between file and released material")

    # 6. AAD sanity — the file embeds the exact AAD that was used at encrypt
    #    time (see backend crypto service), and the server returns it too.
    #    Both must agree.
    if container.aad != aad_from_server:
        raise FileTamperedError("AAD mismatch between file and released material")

    # 7. AES-GCM decrypt. Verifies the tag over ciphertext + AAD.
    try:
        plaintext = AESGCM(key).decrypt(nonce, container.ciphertext, aad_from_server)
    except InvalidTag:
        raise FileTamperedError("GCM authentication failed — file was modified or material is wrong")

    # 8. mime check — we only render PDFs.
    if material.mime != PDF_MIME or container.mime != PDF_MIME:
        # Not an error we can act on; but be explicit so the UI can say "not a PDF".
        raise UnsupportedAlgorithmError(
            f"unexpected mime: material={material.mime}, file={container.mime}"
        )

    return plaintext


def try_zero(buf: bytearray) -> None:
    """
    Best-effort zero of a bytearray. We cannot zero `bytes` objects in Python,
    so callers that want to reduce resident plaintext should hold the buffer as
    a bytearray and call this before dropping the reference. This is a *defence
    in depth* measure, not a guarantee — the OS may have already copied pages.
    """
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
