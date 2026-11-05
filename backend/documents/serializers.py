"""
Document serializers.

Upload happens in the view, not in the serializer, because it needs to
coordinate with policies + crypto + storage atomically. Serializers here
only validate top-level policy fields from the request body and render
responses.
"""
from __future__ import annotations

from rest_framework import serializers

from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    title = serializers.CharField(min_length=1, max_length=255)
    file = serializers.FileField()   # presence validated; size validated in view

    max_total_openings = serializers.IntegerField(min_value=1, max_value=10_000, default=10)
    max_openings_per_recipient = serializers.IntegerField(min_value=1, max_value=10_000, default=3)
    max_recipients = serializers.IntegerField(min_value=1, max_value=10_000, default=10)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)


class DocumentSerializer(serializers.ModelSerializer):
    policy_ref = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = (
            "id",
            "title",
            "original_filename",
            "mime_type",
            "source_mime",
            "converted_to_pdf",
            "original_size",
            "created_at",
            "policy_ref",
        )
        read_only_fields = fields

    def get_policy_ref(self, obj) -> str:
        try:
            return obj.policy.policy_ref
        except Exception:
            return ""


class RecipientAddSerializer(serializers.Serializer):
    email = serializers.EmailField()
