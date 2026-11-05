"""
Phase 6 document endpoint tests: upload → encrypt → download → recipients.
"""
import io
import uuid

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import User
from documents.models import Document, DocumentKey
from policies.models import DocumentPolicy, DocumentRecipient


def _pdf_bytes(payload=b"HELLO-PDF-BODY" * 32) -> bytes:
    # A byte blob with a valid PDF magic prefix. Our validation only checks
    # the magic bytes and (later) GCM tag integrity; PDF structural parsing
    # is the desktop viewer's job.
    return b"%PDF-1.7\n" + payload


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def owner(db):
    u = User.objects.create_user("owner@example.com", "owner-strong-password-1")
    return u


@pytest.fixture
def recipient(db):
    return User.objects.create_user("recipient@example.com", "recipient-strong-password-1")


@pytest.fixture
def logged_in(client, owner):
    client.force_authenticate(user=owner)
    return client


def _upload(client, *, title="Test", data=None, name="test.pdf", content_type="application/pdf", **fields):
    if data is None:
        data = _pdf_bytes()
    payload = {
        "title": title,
        "file": io.BytesIO(data),
        **fields,
    }
    # FileField requires the filename; DRF reads it from the file object.
    payload["file"].name = name
    return client.post(reverse("documents:upload"), data=payload, format="multipart")


# ---------- upload ----------

def test_upload_creates_document_and_key_and_policy(logged_in, owner):
    r = _upload(logged_in, title="Report")
    assert r.status_code == 201, r.content
    body = r.json()
    doc = Document.objects.get(id=body["id"])
    assert doc.owner == owner
    assert doc.title == "Report"
    assert doc.original_size > 0
    assert DocumentKey.objects.filter(document=doc).exists()
    assert DocumentPolicy.objects.filter(document=doc).exists()
    assert body["policy_ref"].startswith("pol-")


def test_upload_stores_encrypted_blob_not_plaintext(logged_in):
    plaintext = b"%PDF-1.7\nSECRET_CANARY_STRING_XYZ"
    r = _upload(logged_in, data=plaintext)
    assert r.status_code == 201, r.content
    doc = Document.objects.get(id=r.json()["id"])

    # Read the blob back through storage and assert the canary does not appear.
    from documents import storage
    blob = storage.read_blob(doc.storage_path)
    assert b"SECRET_CANARY_STRING_XYZ" not in blob
    assert b"CVAULT" in blob[:8]


def test_upload_rejects_non_pdf_magic(logged_in):
    r = _upload(logged_in, data=b"NOT A PDF AT ALL")
    assert r.status_code == 400
    assert "PDF" in r.json()["detail"]


def test_upload_rejects_oversized_file(logged_in, settings):
    settings.CV_MAX_UPLOAD_BYTES = 1024
    r = _upload(logged_in, data=_pdf_bytes(payload=b"X" * 4096))
    assert r.status_code == 400
    assert "maximum size" in r.json()["detail"]


def test_upload_requires_auth(client):
    r = _upload(client)
    # Unauthenticated -> 401 or 403 depending on DRF version.
    assert r.status_code in (401, 403)


# ---------- list / detail ----------

def test_list_returns_only_mine(logged_in, owner, recipient):
    # Give recipient a document of their own
    other_client = APIClient()
    other_client.force_authenticate(user=recipient)
    _upload(other_client, title="Other")
    _upload(logged_in, title="Mine")

    r = logged_in.get(reverse("documents:list"))
    assert r.status_code == 200
    titles = [d["title"] for d in r.json()]
    assert "Mine" in titles
    assert "Other" not in titles


def test_detail_idor_rejects_other_owner(logged_in, recipient):
    other_client = APIClient()
    other_client.force_authenticate(user=recipient)
    up = _upload(other_client, title="Not Yours").json()

    r = logged_in.get(reverse("documents:detail", args=[up["id"]]))
    assert r.status_code == 404


# ---------- download ----------

def test_download_returns_bytes(logged_in):
    up = _upload(logged_in).json()
    r = logged_in.get(reverse("documents:download", args=[up["id"]]))
    assert r.status_code == 200
    assert r["Content-Type"] == "application/octet-stream"
    assert ".cvault" in r["Content-Disposition"]
    assert r.content[:6] == b"CVAULT"


def test_download_idor_rejects_other_owner(logged_in, recipient):
    other_client = APIClient()
    other_client.force_authenticate(user=recipient)
    up = _upload(other_client).json()

    r = logged_in.get(reverse("documents:download", args=[up["id"]]))
    assert r.status_code == 404


# ---------- recipients ----------

def test_add_recipient_success(logged_in, recipient):
    up = _upload(logged_in).json()
    r = logged_in.post(
        reverse("documents:recipient_add", args=[up["id"]]),
        data={"email": recipient.email},
        format="json",
    )
    assert r.status_code == 201, r.content
    assert DocumentRecipient.objects.filter(document_id=up["id"]).count() == 1


def test_add_recipient_unknown_email_400(logged_in):
    up = _upload(logged_in).json()
    r = logged_in.post(
        reverse("documents:recipient_add", args=[up["id"]]),
        data={"email": "nobody@example.com"},
        format="json",
    )
    assert r.status_code == 400


def test_add_recipient_respects_max_recipients(logged_in, recipient):
    up = _upload(logged_in, max_recipients=1).json()
    r1 = logged_in.post(
        reverse("documents:recipient_add", args=[up["id"]]),
        data={"email": recipient.email},
        format="json",
    )
    assert r1.status_code == 201

    second = User.objects.create_user("second@example.com", "another-strong-pass-1")
    r2 = logged_in.post(
        reverse("documents:recipient_add", args=[up["id"]]),
        data={"email": second.email},
        format="json",
    )
    assert r2.status_code == 409


def test_remove_recipient(logged_in, recipient):
    up = _upload(logged_in).json()
    logged_in.post(
        reverse("documents:recipient_add", args=[up["id"]]),
        data={"email": recipient.email},
        format="json",
    )
    r = logged_in.delete(
        reverse("documents:recipient_remove", args=[up["id"], recipient.email]),
    )
    assert r.status_code == 204
    assert DocumentRecipient.objects.filter(document_id=up["id"]).count() == 0


def test_remove_recipient_idor(logged_in, recipient):
    other_client = APIClient()
    other_client.force_authenticate(user=recipient)
    up = _upload(other_client).json()

    r = logged_in.delete(
        reverse("documents:recipient_remove", args=[up["id"], recipient.email]),
    )
    assert r.status_code == 404
