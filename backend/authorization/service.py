"""
Authorization service: policy enforcement, token issue, token redeem.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from accounts.models import User
from documents.models import Document, DocumentKey
from policies.models import DocumentPolicy, DocumentRecipient
from authorization.models import AccessToken, ViewingSession


TOKEN_TTL_SECONDS = 90


class AuthorizationDenied(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class IssuedToken:
    token: str
    expires_at: str
    session_id: uuid.UUID
    document_id: uuid.UUID
    document_title: str
    remaining_total: int
    remaining_recipient: int
    policy_expires_at: str | None
    watermark_text: str


@dataclass(frozen=True)
class ReleasedMaterial:
    document_key_hex: str
    nonce_hex: str
    aad_hex: str
    document_id: uuid.UUID
    mime: str


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def issue_authorization(*, recipient: User, document_id: uuid.UUID) -> IssuedToken:
    token = secrets.token_urlsafe(32)
    token_sha = _hash_token(token)
    now = timezone.now()
    expires_at = now + timedelta(seconds=TOKEN_TTL_SECONDS)

    with transaction.atomic():
        try:
            doc = Document.objects.select_for_update().get(id=document_id)
        except Document.DoesNotExist:
            raise AuthorizationDenied("document not found")

        try:
            policy = DocumentPolicy.objects.select_for_update().get(document=doc)
        except DocumentPolicy.DoesNotExist:
            raise AuthorizationDenied("document has no policy")

        if policy.revoked:
            raise AuthorizationDenied("access has been revoked")

        if policy.expires_at and now >= policy.expires_at:
            raise AuthorizationDenied("document has expired")

        if policy.total_openings_used >= policy.max_total_openings:
            raise AuthorizationDenied("total opening allowance exhausted")

        try:
            recip = DocumentRecipient.objects.select_for_update().get(
                document=doc, user=recipient,
            )
        except DocumentRecipient.DoesNotExist:
            raise AuthorizationDenied("you are not authorized for this document")

        if recip.openings_used >= policy.max_openings_per_recipient:
            raise AuthorizationDenied("your opening allowance for this document is exhausted")

        policy.total_openings_used += 1
        recip.openings_used += 1
        policy.save(update_fields=["total_openings_used", "updated_at"])
        recip.save(update_fields=["openings_used"])

        session = ViewingSession.objects.create(document=doc, recipient=recipient)
        AccessToken.objects.create(
            session=session,
            token_sha256=token_sha,
            expires_at=expires_at,
        )

        remaining_total = policy.max_total_openings - policy.total_openings_used
        remaining_recipient = policy.max_openings_per_recipient - recip.openings_used
        expires_iso = policy.expires_at.isoformat() if policy.expires_at else None
        title = doc.title

    watermark = f"{recipient.email} | {now.strftime('%Y-%m-%d %H:%M UTC')}"
    return IssuedToken(
        token=token,
        expires_at=expires_at.isoformat(),
        session_id=session.id,
        document_id=doc.id,
        document_title=title,
        remaining_total=remaining_total,
        remaining_recipient=remaining_recipient,
        policy_expires_at=expires_iso,
        watermark_text=watermark,
    )


def redeem_authorization(*, recipient: User, document_id: uuid.UUID, token: str) -> ReleasedMaterial:
    token_sha = _hash_token(token)

    with transaction.atomic():
        try:
            access = AccessToken.objects.select_for_update().select_related(
                "session__document", "session__recipient",
            ).get(token_sha256=token_sha)
        except AccessToken.DoesNotExist:
            raise AuthorizationDenied("invalid or unknown token")

        if access.used_at is not None:
            raise AuthorizationDenied("token has already been used")
        if timezone.now() >= access.expires_at:
            raise AuthorizationDenied("token has expired")

        session = access.session
        if session.recipient_id != recipient.id:
            raise AuthorizationDenied("token belongs to a different recipient")
        if session.document_id != document_id:
            raise AuthorizationDenied("token is for a different document")

        try:
            policy = DocumentPolicy.objects.select_for_update().get(document=session.document)
        except DocumentPolicy.DoesNotExist:
            raise AuthorizationDenied("document has no policy")
        if policy.revoked:
            raise AuthorizationDenied("access has been revoked")
        if policy.expires_at and timezone.now() >= policy.expires_at:
            raise AuthorizationDenied("document has expired")

        try:
            key_row = DocumentKey.objects.get(document=session.document)
        except DocumentKey.DoesNotExist:
            raise AuthorizationDenied("document key not found")

        from documents import storage
        from cvault_format import CvaultContainer
        from django.conf import settings
        from cv_crypto import unwrap_document_key

        blob = storage.read_blob(session.document.storage_path)
        container = CvaultContainer.parse(blob)

        dek = unwrap_document_key(
            settings.CV_MASTER_KEY,
            key_row.dek_wrap_nonce,
            key_row.dek_wrapped,
            document_id_hex=str(session.document_id),
            salt=key_row.dek_salt,
        )

        access.used_at = timezone.now()
        access.save(update_fields=["used_at"])
        session.ended_at = timezone.now()
        session.save(update_fields=["ended_at"])

        return ReleasedMaterial(
            document_key_hex=dek.hex(),
            nonce_hex=container.nonce.hex(),
            aad_hex=container.aad.hex(),
            document_id=session.document_id,
            mime=container.mime,
        )
