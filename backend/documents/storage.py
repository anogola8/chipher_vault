"""
Blob storage for encrypted .cvault files.

Design:
  - path derived from the document UUID (never user input)
  - sharded 2/2/rest hex to avoid huge single directories
  - write to .tmp, fsync, then atomic replace
  - no permissions work needed on Windows; the security boundary is that
    CV_BLOB_ROOT is *not* under STATIC_ROOT or MEDIA_ROOT and is never
    served by Django or a web server
"""
from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings


def blob_root() -> Path:
    root = Path(settings.CV_BLOB_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def blob_path_for(document_id) -> Path:
    hex_id = document_id.hex
    if len(hex_id) != 32:
        raise ValueError("document_id must be a UUID")
    root = blob_root()
    d1, d2 = hex_id[:2], hex_id[2:4]
    return root / d1 / d2 / f"{hex_id}.cvault"


def write_blob(document_id, data: bytes) -> str:
    """
    Write `data` atomically and return the storage path (relative to blob_root).
    Caller is responsible for calling delete_blob() if the DB write that
    references this blob fails.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if not data:
        raise ValueError("data is empty")

    full = blob_path_for(document_id)
    full.parent.mkdir(parents=True, exist_ok=True)
    tmp = full.with_suffix(full.suffix + ".tmp")

    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, full)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise

    # Return a path relative to blob_root so the DB row is portable across
    # blob_root relocations.
    return str(full.relative_to(blob_root()))


def read_blob(storage_path: str) -> bytes:
    full = blob_root() / storage_path
    # Reject any traversal attempt even though storage_path is generated
    # internally: defence in depth.
    try:
        full.resolve().relative_to(blob_root().resolve())
    except ValueError:
        raise ValueError("storage_path escapes blob_root")
    return full.read_bytes()


def delete_blob(storage_path: str) -> None:
    full = blob_root() / storage_path
    try:
        full.resolve().relative_to(blob_root().resolve())
    except ValueError:
        raise ValueError("storage_path escapes blob_root")
    try:
        full.unlink()
    except FileNotFoundError:
        pass
