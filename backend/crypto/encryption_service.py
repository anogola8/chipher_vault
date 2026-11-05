"""
High-level protect/unprotect service.

Turns a PDF + policy into a .cvault bytes blob, and back.

This module does NOT touch the database and does NOT make authorization
decisions. It is the cryptography layer that the authorization layer will
call *after* it decides a recipient is allowed to open the document.
"""
from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass
from typing import Optional

# Make `shared/` importable from anywhere inside the repo.
# (Also done in tests via PYTHONPATH, but keeping this here prevents
# surprises when the module is imported by Django later.)
from pathlib import Path
_repo_root = Path(__file__).resolve().parents[2]
_shared_dir = _repo_root / "shared"
if str(_shared_dir) not in sys.path:
    sys.path.insert(0, str(_shared_dir))

from cvault_format import (                                   # noqa: E402
    CvaultContainer, build_container, CURRENT_VERSION,
)
from cv_crypto import (                                          # noqa: E402
    ALGO, CryptoError, AuthenticationFailed, BadKeyError,     # noqa: F401 re-export
    generate_document_key, generate_nonce, generate_salt,
    encrypt_pdf, decrypt_pdf,
    wrap_document_key, unwrap_document_key,
)


# Fixed MIME for MVP (PDF only).
PDF_MIME = "application/pdf"


@dataclass(frozen=True)
class ProtectedDocument:
    """
    Everything the backend must persist after protect_pdf().
    The key-material fields (`dek_wrap_nonce`, `dek_wrapped`, `dek_salt`)
    belong in a separate DB table from the document metadata.
    """
    cvault_bytes: bytes          # the whole file to serve to the user
    document_id: uuid.UUID
    policy_ref: str
    dek_wrap_nonce: bytes
    dek_wrapped: bytes
    dek_salt: bytes
    plaintext_sha256: bytes      # SHA-256 of the original PDF (for audit)


def protect_pdf(
    pdf_bytes: bytes,
    *,
    document_id: uuid.UUID,
    policy_ref: str,
    master_key: bytes,
    app_aad: bytes = b"",
) -> ProtectedDocument:
    """
    Encrypt a PDF and return the .cvault bytes plus the server-side key
    material needed to decrypt it later.

    Steps:
      1. Validate inputs.
      2. Generate a fresh document key (DEK) and salt.
      3. Build a container with a *placeholder* ciphertext so the header
         (which is included in the body AAD) is fixed, then encrypt the PDF,
         then rebuild the container with the real ciphertext.
      4. Wrap the DEK under the master key (KEK).
      5. Return bytes + wrapping metadata.

    The "encrypt twice" trick above is deliberate: the container's header
    contains `len(ciphertext)`, but AES-GCM's ciphertext length equals the
    plaintext length plus the 16-byte tag, so we can predict it exactly:
    `len(ciphertext) == len(plaintext) + 16`. That means we can build the
    final header in one pass, not two.
    """
    if not isinstance(pdf_bytes, (bytes, bytearray)):
        raise TypeError("pdf_bytes must be bytes")
    if not pdf_bytes:
        raise ValueError("pdf_bytes is empty")
    if not isinstance(document_id, uuid.UUID):
        raise TypeError("document_id must be uuid.UUID")
    if not isinstance(policy_ref, str) or not policy_ref:
        raise ValueError("policy_ref must be a non-empty str")
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
        raise BadKeyError("master_key must be 32 bytes")

    # 1. DEK + salt
    dek = generate_document_key()
    salt = generate_salt()

    # 2. Predict ciphertext length; build a placeholder container just to
    #    obtain its `header_bytes_for_aad()`.
    placeholder_ct = b"\x00" * (len(pdf_bytes) + 16)
    placeholder = build_container(
        document_id=document_id,
        nonce=generate_nonce(),            # overwritten below
        mime=PDF_MIME,
        algorithm=ALGO,
        policy_ref=policy_ref,
        aad=app_aad,
        ciphertext=placeholder_ct,
    )
    # 3. Encrypt with real nonce; body AAD binds the header bytes + policy.
    aad, nonce, ciphertext = encrypt_pdf(
        bytes(pdf_bytes),
        dek,
        header_bytes=placeholder.header_bytes_for_aad(),
        policy_ref=policy_ref,
        app_aad=app_aad,
    )

    # 4. Build the final container. `aad` returned by encrypt_pdf is the full
    #    body-AAD blob; store it in the container's `aad` field so the viewer
    #    can pass the same bytes to GCM decrypt without re-deriving them.
    #    The `app_aad` is embedded inside `aad` already.
    container = build_container(
        document_id=document_id,
        nonce=nonce,
        mime=PDF_MIME,
        algorithm=ALGO,
        policy_ref=policy_ref,
        aad=aad,
        ciphertext=ciphertext,
    )
    cvault_bytes = container.serialize()

    # 5. Wrap the DEK.
    wrap_nonce, wrapped = wrap_document_key(
        master_key, dek,
        document_id_hex=str(document_id),
        salt=salt,
    )

    # 6. Record plaintext SHA-256 for audit/tamper-detection of the *original*.
    import hashlib
    plaintext_sha = hashlib.sha256(pdf_bytes).digest()

    return ProtectedDocument(
        cvault_bytes=cvault_bytes,
        document_id=document_id,
        policy_ref=policy_ref,
        dek_wrap_nonce=wrap_nonce,
        dek_wrapped=wrapped,
        dek_salt=salt,
        plaintext_sha256=plaintext_sha,
    )


def unprotect_cvault(
    cvault_bytes: bytes,
    *,
    dek_wrap_nonce: bytes,
    dek_wrapped: bytes,
    dek_salt: bytes,
    master_key: bytes,
    expected_document_id: Optional[uuid.UUID] = None,
    expected_policy_ref: Optional[str] = None,
) -> bytes:
    """
    Recover the original PDF bytes.

    Order of checks (fail closed at every step):
      1. Parse the container. Raises on magic/version/truncation/body-SHA.
      2. If expected_document_id / expected_policy_ref were supplied (the
         caller — i.e. the authorization layer — must supply them), reject
         mismatches *before* attempting decryption. This defends against a
         scenario where an attacker got hold of a wrapped-DEK record and a
         different container.
      3. Unwrap the DEK.
      4. AES-GCM decrypt. Any tampering of header, policy_ref, or ciphertext
         fails here because all three are in the AAD / tag path.
    """
    if not isinstance(cvault_bytes, (bytes, bytearray)):
        raise TypeError("cvault_bytes must be bytes")
    if len(master_key) != 32:
        raise BadKeyError("master_key must be 32 bytes")

    # 1. Structural parse (fast pre-auth integrity).
    container = CvaultContainer.parse(bytes(cvault_bytes))

    # 2. Identity / policy cross-check.
    if expected_document_id is not None and container.document_id != expected_document_id:
        raise AuthenticationFailed(
            "container document_id does not match expected value"
        )
    if expected_policy_ref is not None and container.policy_ref != expected_policy_ref:
        raise AuthenticationFailed(
            "container policy_ref does not match expected value"
        )

    # 3. Unwrap DEK.
    dek = unwrap_document_key(
        master_key,
        dek_wrap_nonce,
        dek_wrapped,
        document_id_hex=str(container.document_id),
        salt=dek_salt,
    )

    # 4. GCM-decrypt; the container's `aad` field is the exact AAD used at
    #    encrypt time, so nothing needs to be re-derived.
    try:
        plaintext = decrypt_pdf(
            container.ciphertext,
            dek,
            aad=container.aad,
            nonce=container.nonce,
        )
    except AuthenticationFailed:
        raise

    return plaintext


def peek_document_id(cvault_bytes: bytes) -> uuid.UUID:
    """Extract the document UUID without decrypting. Used by the viewer."""
    return CvaultContainer.parse(bytes(cvault_bytes)).document_id


def peek_policy_ref(cvault_bytes: bytes) -> str:
    return CvaultContainer.parse(bytes(cvault_bytes)).policy_ref
