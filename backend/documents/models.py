"""
Documents: logical document + wrapped key material (separate table).
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="owned_documents",
    )
    title = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255)

    mime_type = models.CharField(max_length=64, default="application/pdf")
    source_mime = models.CharField(max_length=128, default="application/pdf")
    converted_to_pdf = models.BooleanField(default=False)
    original_size = models.PositiveBigIntegerField()
    plaintext_sha256 = models.BinaryField(max_length=32)

    storage_path = models.CharField(max_length=512)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=["owner", "-created_at"])]

    def __str__(self) -> str:
        return f"{self.title} ({self.id})"


class DocumentKey(models.Model):
    document = models.OneToOneField(
        Document,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="key",
    )
    dek_wrap_nonce = models.BinaryField(max_length=12)
    dek_wrapped = models.BinaryField()
    dek_salt = models.BinaryField(max_length=16)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"key for {self.document_id}"
