"""
Audit: SHA-256 hash-linked ledger.
"""
from __future__ import annotations

from django.db import models


class AuditEvent(models.Model):
    class EventType(models.TextChoices):
        DOC_UPLOADED = "doc.uploaded", "Document uploaded"
        DOC_ENCRYPTED = "doc.encrypted", "Document encrypted"
        DOC_DOWNLOADED = "doc.downloaded", "Protected file downloaded"
        DOC_POLICY_UPDATED = "doc.policy_updated", "Policy updated"
        RECIPIENT_ADDED = "recipient.added", "Recipient authorized"
        RECIPIENT_REMOVED = "recipient.removed", "Recipient deauthorized"
        OPEN_SUCCESS = "open.success", "Successful opening"
        OPEN_FAILED = "open.failed", "Failed opening"
        REVOKED = "doc.revoked", "Access revoked"
        EXPIRED = "doc.expired", "Document expired"
        EXHAUSTED = "doc.exhausted", "Opening allowance exhausted"
        INTEGRITY_FAIL = "integrity.failure", "Integrity verification failed"

    seq = models.BigAutoField(primary_key=True)

    event_type = models.CharField(max_length=32, choices=EventType.choices, db_index=True)
    document_id = models.UUIDField(null=True, blank=True, db_index=True)
    actor_id = models.BigIntegerField(null=True, blank=True, db_index=True)

    occurred_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    previous_hash = models.BinaryField(max_length=32)
    current_hash = models.BinaryField(max_length=32, unique=True)

    class Meta:
        ordering = ("seq",)
        indexes = [
            models.Index(fields=["event_type", "-occurred_at"]),
            models.Index(fields=["document_id", "seq"]),
        ]

    def __str__(self) -> str:
        return f"#{self.seq} {self.event_type} @ {self.occurred_at}"
