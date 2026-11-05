"""
Authorization: viewing sessions and one-time access tokens.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class ViewingSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        "documents.Document",
        on_delete=models.PROTECT,
        related_name="viewing_sessions",
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="viewing_sessions",
    )
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    client_info = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-started_at",)
        indexes = [
            models.Index(fields=["document", "-started_at"]),
            models.Index(fields=["recipient", "-started_at"]),
        ]


class AccessToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.OneToOneField(
        ViewingSession,
        on_delete=models.CASCADE,
        related_name="token",
    )
    token_sha256 = models.BinaryField(max_length=32, unique=True)
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["expires_at"])]

    def is_live(self) -> bool:
        return self.used_at is None and timezone.now() < self.expires_at
