"""
Policies: per-document opening allowance and recipient authorization.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class DocumentPolicy(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        EXPIRED = "expired", "Expired"
        EXHAUSTED = "exhausted", "Exhausted"
        REVOKED = "revoked", "Revoked"

    document = models.OneToOneField(
        "documents.Document",
        on_delete=models.PROTECT,
        primary_key=True,
        related_name="policy",
    )
    policy_ref = models.CharField(max_length=64, unique=True, db_index=True)

    max_total_openings = models.PositiveIntegerField(default=10)
    max_openings_per_recipient = models.PositiveIntegerField(default=3)
    max_recipients = models.PositiveIntegerField(default=10)
    expires_at = models.DateTimeField(null=True, blank=True)

    total_openings_used = models.PositiveIntegerField(default=0)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "document policies"

    def __str__(self) -> str:
        return f"policy {self.policy_ref}"

    def derived_status(self) -> str:
        if self.revoked:
            return self.Status.REVOKED
        if self.expires_at and timezone.now() >= self.expires_at:
            return self.Status.EXPIRED
        if self.total_openings_used >= self.max_total_openings:
            return self.Status.EXHAUSTED
        return self.Status.ACTIVE


class DocumentRecipient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        "documents.Document",
        on_delete=models.CASCADE,
        related_name="recipients",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="authorized_documents",
    )
    openings_used = models.PositiveIntegerField(default=0)
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="grants_made",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["document", "user"], name="uniq_doc_recipient",
            ),
        ]
        indexes = [models.Index(fields=["document", "user"])]

    def __str__(self) -> str:
        return f"{self.user_id} on {self.document_id}"


class RevocationRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        "documents.Document",
        on_delete=models.PROTECT,
        related_name="revocations",
    )
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="revocations_made",
    )
    reason = models.CharField(max_length=255, blank=True)
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-revoked_at",)

    def __str__(self) -> str:
        return f"revoke {self.document_id} at {self.revoked_at}"
