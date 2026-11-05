"""
Audit service: append-only hash-linked ledger.

Public API:
  record(event_type, document_id=None, actor_id=None, metadata=None) -> AuditEvent

Invariants:
  - The write happens inside a transaction.atomic() block.
  - Concurrency is enforced by the DB, not by select_for_update():
      * SQLite: BEGIN IMMEDIATE (set in settings.py) takes a write lock
        at the start of each write transaction, so concurrent record()
        calls serialize automatically.
      * Postgres: select_for_update() takes an explicit row lock on the
        last event, which is what we want.
    We use `select_for_update()` only when the connection actually supports
    it. On SQLite it is a no-op or raises under savepoints; either way it
    buys us nothing there.
  - metadata must be a JSON-serializable dict of non-secret values.
  - The ledger is append-only by convention; verify_chain() detects
    external tampering.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone as _dt_tz

from django.db import connection, transaction

from audit.models import AuditEvent

log = logging.getLogger(__name__)

ZERO_HASH = b"\x00" * 32


def _canonical_metadata(metadata) -> bytes:
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise TypeError("audit metadata must be a dict")
    return json.dumps(
        metadata, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")


def _truncate_to_second(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt_tz.utc)
    else:
        dt = dt.astimezone(_dt_tz.utc)
    return dt.replace(microsecond=0)


def _encode_id(value, *, width: int, label: str) -> bytes:
    """
    Encode an identifier into a fixed-width byte string for hashing.

    Accepts None (encoded as `width` zero bytes), an int (fixed-width
    big-endian, unsigned), or an object with a .bytes attribute (UUIDs).
    Raises TypeError on anything else so we fail loudly, not silently.
    """
    if value is None:
        return b"\x00" * width
    if isinstance(value, bool):
        raise TypeError(f"{label}: bool is not a valid id")
    if isinstance(value, int):
        return value.to_bytes(width, "big", signed=False)
    b = getattr(value, "bytes", None)
    if isinstance(b, (bytes, bytearray)) and len(b) == width:
        return bytes(b)
    raise TypeError(
        f"{label}: expected int, UUID-like with .bytes of width {width}, or None; "
        f"got {type(value).__name__}"
    )


def _compute_hash(*, previous_hash, seq, event_type, document_id,
                  actor_id, occurred_at, metadata_bytes) -> bytes:
    occurred_at = _truncate_to_second(occurred_at)
    parts = [
        b"AUDIT-v1|",
        previous_hash,
        seq.to_bytes(8, "big", signed=False),
        event_type.encode("utf-8"),
        _encode_id(document_id, width=16, label="document_id"),
        _encode_id(actor_id, width=8, label="actor_id"),
        occurred_at.isoformat().encode("utf-8"),
        metadata_bytes,
    ]
    return hashlib.sha256(b"|".join(parts)).digest()


def _supports_select_for_update() -> bool:
    return connection.vendor != "sqlite"


def record(event_type: str, *, document_id=None, actor_id=None, metadata=None):
    if event_type not in AuditEvent.EventType.values:
        raise ValueError(f"unknown audit event type: {event_type!r}")

    metadata_bytes = _canonical_metadata(metadata)

    with transaction.atomic():
        if _supports_select_for_update():
            last = (
                AuditEvent.objects
                .select_for_update()
                .order_by("-seq")
                .first()
            )
        else:
            last = AuditEvent.objects.order_by("-seq").first()

        if last is None:
            previous_hash = ZERO_HASH
            next_seq = 1
        else:
            previous_hash = bytes(last.current_hash)
            next_seq = last.seq + 1

        occurred_at = _truncate_to_second(datetime.now(_dt_tz.utc))

        ev = AuditEvent(
            seq=next_seq,
            event_type=event_type,
            document_id=document_id,
            actor_id=actor_id,
            occurred_at=occurred_at,
            metadata=metadata or {},
            previous_hash=previous_hash,
            current_hash=b"\x00" * 32,
        )
        ev.save(force_insert=True)

        ev.current_hash = _compute_hash(
            previous_hash=previous_hash,
            seq=ev.seq,
            event_type=event_type,
            document_id=document_id,
            actor_id=actor_id,
            occurred_at=occurred_at,
            metadata_bytes=metadata_bytes,
        )
        ev.save(update_fields=["current_hash"])

    return ev
