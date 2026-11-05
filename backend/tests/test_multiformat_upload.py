"""
Multi-format upload tests.

Verifies that .txt and .rtf convert to PDF and get encrypted as .cvault,
PDF passes through unchanged, and bad inputs are rejected at the
format-check layer.
"""
import io

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import User
from documents.models import Document


@pytest.fixture
def owner(db):
    return User.objects.create_user("mf_owner@example.com", "owner-strong-password-1")


@pytest.fixture
def client(owner):
    c = APIClient()
    c.force_authenticate(user=owner)
    return c


def _upload(client, *, filename: str, data: bytes, title="Test"):
    payload = {
        "title": title,
        "file": io.BytesIO(data),
        "max_total_openings": 5,
        "max_openings_per_recipient": 3,
        "max_recipients": 5,
    }
    payload["file"].name = filename
    return client.post(reverse("documents:upload"), data=payload, format="multipart")


def _minimal_pdf():
    return b"%PDF-1.7\n% mini\n" + b"x" * 100


def test_pdf_passthrough(client):
    r = _upload(client, filename="doc.pdf", data=_minimal_pdf())
    assert r.status_code == 201, r.content
    body = r.json()
    assert body["source_mime"] == "application/pdf"
    assert body["converted_to_pdf"] is False


def test_txt_converted_to_pdf(client):
    r = _upload(client, filename="note.txt", data=b"hello world\nline two\n")
    assert r.status_code == 201, r.content
    body = r.json()
    assert body["converted_to_pdf"] is True
    assert body["source_mime"] == "text/plain"

    from documents import storage
    doc = Document.objects.get(id=body["id"])
    blob = storage.read_blob(doc.storage_path)
    assert blob[:6] == b"CVAULT"


def test_rtf_converted_to_pdf(client):
    rtf = b"{\\rtf1\\ansi\\deff0 Hello from RTF}"
    r = _upload(client, filename="doc.rtf", data=rtf)
    assert r.status_code == 201, r.content
    body = r.json()
    assert body["converted_to_pdf"] is True
    assert body["source_mime"] == "application/rtf"


def test_exe_rejected(client):
    r = _upload(client, filename="malware.exe", data=b"MZ\x90\x00")
    assert r.status_code == 400
    assert "unsupported" in r.json()["detail"].lower()


def test_fake_docx_rejected(client):
    r = _upload(client, filename="fake.docx", data=b"just text")
    assert r.status_code == 400
    assert "not a valid Office ZIP" in r.json()["detail"]


def test_pdf_extension_without_magic_rejected(client):
    r = _upload(client, filename="fake.pdf", data=b"not a pdf")
    assert r.status_code == 400
    assert "does not look like a PDF" in r.json()["detail"]


def test_oversized_rejected(client, settings):
    settings.CV_MAX_UPLOAD_BYTES = 100
    r = _upload(client, filename="note.txt", data=b"x" * 200)
    assert r.status_code == 400
    assert "exceeds maximum size" in r.json()["detail"]


def test_upload_response_includes_new_fields(client):
    r = _upload(client, filename="note.txt", data=b"hi\n")
    assert r.status_code == 201
    body = r.json()
    for key in ("id", "title", "source_mime", "converted_to_pdf", "policy_ref"):
        assert key in body
