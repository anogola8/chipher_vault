from __future__ import annotations

import uuid
from rest_framework import serializers


class AuthorizeRequestSerializer(serializers.Serializer):
    document_id = serializers.UUIDField()


class RedeemRequestSerializer(serializers.Serializer):
    document_id = serializers.UUIDField()
    token = serializers.CharField(min_length=20, max_length=100)


class RevokeRequestSerializer(serializers.Serializer):
    reason = serializers.CharField(required=False, allow_blank=True, max_length=255)
