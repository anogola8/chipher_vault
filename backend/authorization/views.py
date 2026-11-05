from __future__ import annotations

import uuid

from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from documents.models import Document
from policies.models import DocumentPolicy, RevocationRecord
from authorization.models import ViewingSession
from authorization.service import (
    issue_authorization, redeem_authorization, AuthorizationDenied,
)
from audit.service import record as record_audit
from audit.models import AuditEvent
from authorization.serializers import (
    AuthorizeRequestSerializer, RedeemRequestSerializer, RevokeRequestSerializer,
)


class AuthorizeView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "authorize"

    def post(self, request):
        ser = AuthorizeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            issued = issue_authorization(
                recipient=request.user,
                document_id=ser.validated_data["document_id"],
            )
        except AuthorizationDenied as e:
            try:
                record_audit(
                    AuditEvent.EventType.OPEN_FAILED,
                    document_id=ser.validated_data['document_id'],
                    actor_id=request.user.id,
                    metadata={'phase': 'authorize', 'reason': e.reason},
                )
            except Exception:
                pass
            return Response({'detail': e.reason}, status=status.HTTP_403_FORBIDDEN)

        return Response({
            "token": issued.token,
            "expires_at": issued.expires_at,
            "session_id": str(issued.session_id),
            "document_id": str(issued.document_id),
            "document_title": issued.document_title,
            "remaining_total": issued.remaining_total,
            "remaining_recipient": issued.remaining_recipient,
            "policy_expires_at": issued.policy_expires_at,
            "watermark_text": issued.watermark_text,
        })


class RedeemView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "authorize"

    def post(self, request):
        ser = RedeemRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            material = redeem_authorization(
                recipient=request.user,
                document_id=ser.validated_data["document_id"],
                token=ser.validated_data["token"],
            )
        except AuthorizationDenied as e:
            return Response({"detail": e.reason}, status=status.HTTP_403_FORBIDDEN)

        # The redeem succeeded; the DEK is in the response. We record the
        # open event AFTER the token has been consumed (inside the redeem
        # service, which marked used_at). This event is the audit-side
        # confirmation of a real open.
        try:
            record_audit(
                AuditEvent.EventType.OPEN_SUCCESS,
                document_id=material.document_id,
                actor_id=request.user.id,
                metadata={'phase': 'redeem'},
            )
        except Exception:
            pass
        return Response({
            'document_key_hex': material.document_key_hex,
            'nonce_hex': material.nonce_hex,
            'aad_hex': material.aad_hex,
            'document_id': str(material.document_id),
            'mime': material.mime,
        })


class RevokeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, document_id: uuid.UUID):
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        ser = RevokeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        policy = doc.policy
        if not policy.revoked:
            policy.revoked = True
            policy.revoked_at = timezone.now()
            policy.save(update_fields=["revoked", "revoked_at", "updated_at"])
            RevocationRecord.objects.create(
                document=doc,
                revoked_by=request.user,
                reason=ser.validated_data.get('reason', ''),
            )
            record_audit(
                AuditEvent.EventType.REVOKED,
                document_id=doc.id,
                actor_id=request.user.id,
                metadata={'reason': ser.validated_data.get('reason', '')},
            )

        return Response({
            "document_id": str(doc.id),
            "revoked": True,
            "revoked_at": policy.revoked_at.isoformat() if policy.revoked_at else None,
        })


class ActivityView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, document_id: uuid.UUID):
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        policy = doc.policy
        sessions = ViewingSession.objects.filter(document=doc).order_by("-started_at")[:50]
        return Response({
            "document_id": str(doc.id),
            "policy": {
                "status": policy.derived_status(),
                "max_total_openings": policy.max_total_openings,
                "total_openings_used": policy.total_openings_used,
                "max_openings_per_recipient": policy.max_openings_per_recipient,
                "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                "revoked": policy.revoked,
            },
            "sessions": [
                {
                    "recipient_email": s.recipient.email,
                    "started_at": s.started_at.isoformat(),
                    "ended_at": s.ended_at.isoformat() if s.ended_at else None,
                }
                for s in sessions
            ],
        })
