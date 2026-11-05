"""
Document upload / download / recipient management.

Authorization invariants enforced here:
  - only the owner can upload, list-owned, view-owned, download, or manage
    recipients of a document
  - recipients never access endpoints in this module; recipient-side flows
    live in the authorization app
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.db import transaction

from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from documents.models import Document, DocumentKey
from documents import storage
from documents.converter import (
    convert_to_pdf, UnsupportedFormat, ConversionFailed,
    ConversionTimeout, LibreOfficeNotFound,
)
from documents.serializers import (
    DocumentUploadSerializer, DocumentSerializer, RecipientAddSerializer,
)
from policies.models import DocumentPolicy, DocumentRecipient
from audit.service import record as record_audit
from audit.models import AuditEvent
from backend_crypto import service as crypto_service  # thin wrapper, see Block 4

User = get_user_model()

PDF_MAGIC = b"%PDF-"


def _validate_pdf_or_400(f) -> bytes:
    """Return the file bytes after validating size, MIME hint, and magic bytes."""
    max_bytes = int(settings.CV_MAX_UPLOAD_BYTES)
    if f.size > max_bytes:
        raise ValueError(f"file exceeds maximum size of {max_bytes} bytes")

    head = f.read(8)
    f.seek(0)
    if not head.startswith(PDF_MAGIC):
        raise ValueError("file does not appear to be a PDF (missing %PDF- magic)")

    data = f.read()
    if not data:
        raise ValueError("file is empty")
    return data


def _safe_title(original: str, fallback: str) -> str:
    # Title is stored as-is (length-limited by serializer); we don't use it
    # to derive paths, so no sanitization needed beyond length.
    return (original or fallback)[:255]


class DocumentUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        ser = DocumentUploadSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        uploaded = ser.validated_data["file"]
        title = ser.validated_data["title"]

        # Enforce size limit before doing anything else.
        max_bytes = int(settings.CV_MAX_UPLOAD_BYTES)
        if uploaded.size > max_bytes:
            return Response(
                {"detail": f"file exceeds maximum size of {max_bytes} bytes"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Read the raw bytes and convert (or passthrough) to PDF.
        raw = uploaded.read()
        try:
            conv = convert_to_pdf(filename=uploaded.name, data=raw)
        except UnsupportedFormat as e:
            return Response(
                {"detail": f"unsupported file: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ConversionTimeout as e:
            return Response(
                {"detail": f"conversion timed out: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except LibreOfficeNotFound as e:
            return Response(
                {"detail": f"backend conversion unavailable: {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except ConversionFailed as e:
            return Response(
                {"detail": f"conversion failed: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        pdf_bytes = conv.pdf_bytes

        document_id = uuid.uuid4()
        policy_ref = f"pol-{uuid.uuid4().hex[:20]}"

        # 1. Encrypt
        protected = crypto_service.protect_pdf(
            pdf_bytes,
            document_id=document_id,
            policy_ref=policy_ref,
            master_key=settings.CV_MASTER_KEY,
        )

        # 2. Write blob. If this fails, nothing is created in the DB.
        try:
            storage_path = storage.write_blob(document_id, protected.cvault_bytes)
        except Exception as e:
            return Response(
                {"detail": f"failed to store encrypted file: {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # 3. Create DB rows. If this fails, remove the orphan blob.
        created_doc = None
        try:
            with transaction.atomic():
                doc = Document.objects.create(
                    id=document_id,
                    owner=request.user,
                    title=_safe_title(title, uploaded.name),
                    original_filename=uploaded.name[:255],
                    original_size=len(raw),
                    plaintext_sha256=protected.plaintext_sha256,
                    storage_path=storage_path,
                    source_mime=conv.source_mime,
                    converted_to_pdf=conv.was_converted,
                )
                DocumentKey.objects.create(
                    document=doc,
                    dek_wrap_nonce=protected.dek_wrap_nonce,
                    dek_wrapped=protected.dek_wrapped,
                    dek_salt=protected.dek_salt,
                )
                DocumentPolicy.objects.create(
                    document=doc,
                    policy_ref=policy_ref,
                    max_total_openings=ser.validated_data["max_total_openings"],
                    max_openings_per_recipient=ser.validated_data["max_openings_per_recipient"],
                    max_recipients=ser.validated_data["max_recipients"],
                    expires_at=ser.validated_data.get("expires_at"),
                )
                record_audit(
                    AuditEvent.EventType.DOC_UPLOADED,
                    document_id=doc.id,
                    actor_id=request.user.id,
                    metadata={
                        'title': doc.title,
                        'size': doc.original_size,
                        'policy_ref': policy_ref,
                    },
                )
                created_doc = doc
        except Exception:
            storage.delete_blob(storage_path)
            raise

        return Response(
            DocumentSerializer(created_doc).data,
            status=status.HTTP_201_CREATED,
        )


class DocumentListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Owner-side only for Phase 6. Recipient-side listing arrives with
        # authorization in Phase 7.
        qs = Document.objects.filter(owner=request.user).order_by("-created_at")
        return Response([DocumentSerializer(d).data for d in qs])


class DocumentDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, document_id: uuid.UUID):
        # IDOR: filter on owner unconditionally.
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        return Response(DocumentSerializer(doc).data)


class DocumentDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, document_id: uuid.UUID):
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        try:
            blob = storage.read_blob(doc.storage_path)
        except FileNotFoundError:
            return Response(
                {"detail": "stored file missing"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        response = HttpResponse(blob, content_type="application/octet-stream")
        safe_name = (doc.title or "document").replace('"', "_")[:200]
        response["Content-Disposition"] = f'attachment; filename="{safe_name}.cvault"'
        response["Content-Length"] = str(len(blob))
        return response


class DocumentRecipientAddView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, document_id: uuid.UUID):
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        ser = RecipientAddSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        email = ser.validated_data["email"].lower()

        try:
            recipient = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "no account with that email; the recipient must register first"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            policy = DocumentPolicy.objects.select_for_update().get(document=doc)
            current = DocumentRecipient.objects.filter(document=doc).count()
            if current >= policy.max_recipients:
                return Response(
                    {"detail": f"policy limits recipients to {policy.max_recipients}"},
                    status=status.HTTP_409_CONFLICT,
                )
            obj, created = DocumentRecipient.objects.get_or_create(
                document=doc, user=recipient,
                defaults={"added_by": request.user},
            )
            if not created:
                return Response(
                    {'detail': 'recipient already authorized'},
                    status=status.HTTP_200_OK,
                )
            record_audit(
                AuditEvent.EventType.RECIPIENT_ADDED,
                document_id=doc.id,
                actor_id=request.user.id,
                metadata={'recipient_email': recipient.email},
            )

        return Response(
            {
                "email": recipient.email,
                "added_at": obj.added_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class DocumentRecipientRemoveView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, document_id: uuid.UUID, email: str):
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        qs = DocumentRecipient.objects.filter(
            document=doc, user__email__iexact=email,
        )
        deleted, _ = qs.delete()
        if not deleted:
            return Response(
                {'detail': 'recipient not found on this document'},
                status=status.HTTP_404_NOT_FOUND,
            )
        record_audit(
            AuditEvent.EventType.RECIPIENT_REMOVED,
            document_id=doc.id,
            actor_id=request.user.id,
            metadata={'recipient_email': email},
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
