"""
Audit chain verifier.

Walks the ledger in `seq` order and checks two things per row:
  1. `previous_hash` equals the `current_hash` of the row before it
     (or ZERO_HASH for the first row).
  2. `current_hash` recomputes correctly from the row's own fields.

If either fails, returns a report indicating the first divergent seq.
The verifier is read-only; it never repairs or mutates the ledger.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable

from audit.models import AuditEvent
from audit.service import (
    ZERO_HASH, _canonical_metadata, _compute_hash,
)


@dataclass
class VerifyResult:
    ok: bool
    total: int = 0
    first_bad_seq: int | None = None
    reason: str = ""
    detail: dict = field(default_factory=dict)


def verify_chain(events: Iterable[AuditEvent] | None = None) -> VerifyResult:
    if events is None:
        events = AuditEvent.objects.order_by("seq").iterator()

    expected_prev = ZERO_HASH
    expected_seq = 1
    total = 0

    for ev in events:
        total += 1

        if ev.seq != expected_seq:
            return VerifyResult(
                ok=False, total=total, first_bad_seq=ev.seq,
                reason=f"seq gap: expected {expected_seq}, got {ev.seq}",
            )

        if bytes(ev.previous_hash) != expected_prev:
            return VerifyResult(
                ok=False, total=total, first_bad_seq=ev.seq,
                reason="previous_hash does not match prior current_hash",
                detail={
                    "expected": expected_prev.hex(),
                    "actual": bytes(ev.previous_hash).hex(),
                },
            )

        # Recompute the hash using the canonical serialization.
        recomputed = _compute_hash(
            previous_hash=expected_prev,
            seq=ev.seq,
            event_type=ev.event_type,
            document_id=ev.document_id,
            actor_id=ev.actor_id,
            occurred_at=ev.occurred_at,
            metadata_bytes=_canonical_metadata(ev.metadata),
        )
        if recomputed != bytes(ev.current_hash):
            return VerifyResult(
                ok=False, total=total, first_bad_seq=ev.seq,
                reason="current_hash does not match row contents",
                detail={
                    "expected": recomputed.hex(),
                    "actual": bytes(ev.current_hash).hex(),
                },
            )

        expected_prev = bytes(ev.current_hash)
        expected_seq += 1

    return VerifyResult(ok=True, total=total)
