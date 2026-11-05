"""
Accounts serializers: registration and self-info.

Note: registration is open in the MVP. In production you would gate it
behind owner invitations or admin approval.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=10, max_length=128)
    display_name = serializers.CharField(required=False, allow_blank=True, max_length=120)

    def validate_email(self, value: str) -> str:
        value = value.strip().lower()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value

    def validate_password(self, value: str) -> str:
        # Run Django's configured validators. Raises serializers.ValidationError
        # if any fail.
        validate_password(value)
        return value

    def create(self, validated_data):
        return User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            display_name=validated_data.get("display_name", ""),
        )


class UserSelfSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "email", "display_name", "is_owner", "is_recipient", "date_joined")
        read_only_fields = fields
