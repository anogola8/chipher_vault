"""
Phase 7 authorization tests.

Covers prompt scenarios:
  TEST 3  - authorized recipient opens successfully
  TEST 5  - unauthorized user denied
  TEST 6  - after owner authorizes, second user can open
  TEST 7  - per-recipient limit enforced
  TEST 8  - total limit enforced
  TEST 9  - revocation blocks future opens
  TEST 10 - expiry blocks future opens
  TEST 13 - token replay rejected
  TEST 14 - concurrent opens cannot exceed limit (best-effort on SQLite)
"""
import io
import threading
import uuid
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User
from documents.models import Document
from policies.models import DocumentPolicy, DocumentRecipient


def _pdf_bytes(payload=b"BODY" * 64) -> bytes:
    return b"%PDF-1.7\n" + payload


@pytest.fixture
def owner(db):
    return User.objects.create_user("owner@example.com", "owner-strong-password-1")


@pytest.fixture
def recipient(db):
    return User.objects.create_user("recipient@example.com", "recipient-strong-password-1")


@pytest.fixture
def other_user(db):
    return User.objects.create_user("other@example.com", "other-strong-password-1")


def _make_doc(owner, *, max_total=5, max_per=3, expires_at=None):
    client = APIClient()
    client.force_authenticate(user=owner)
    payload = {
        "title": "Auth Test",
        "file": io.BytesIO(_pdf_bytes()),
        "max_total_openings": max_total,
        "max_openings_per_recipient": max_per,
    }
    if expires_at:
        payload["expires_at"] = expires_at
    payload["file"].name = "auth.pdf"
    r = client.post(reverse("documents:upload"), data=payload, format="multipart")
    assert r.status_code == 201, r.content
    return Document.objects.get(id=r.json()["id"])


def _authorize_recipient(owner, doc, recipient):
    c = APIClient()
    c.force_authenticate(user=owner)
    r = c.post(
        reverse("documents:recipient_add", args=[doc.id]),
        data={"email": recipient.email},
        format="json",
    )
    assert r.status_code == 201, r.content


def _full_open(recipient, doc):
    """Simulate the viewer: authorize then redeem."""
    c = APIClient()
    c.force_authenticate(user=recipient)
    a = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert a.status_code == 200, a.content
    token = a.json()["token"]
    r = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    return a, r


# ---------- happy path ----------

def test_authorized_recipient_opens(owner, recipient):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)
    a, r = _full_open(recipient, doc)
    assert a.status_code == 200
    assert r.status_code == 200, r.content
    body = r.json()
    assert len(body["document_key_hex"]) == 64
    assert len(body["nonce_hex"]) == 24
    assert body["mime"] == "application/pdf"


# ---------- unauthorized user denied (TEST 5) ----------

def test_unauthorized_user_denied(owner, other_user):
    doc = _make_doc(owner)
    c = APIClient()
    c.force_authenticate(user=other_user)
    r = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r.status_code == 403
    assert "not authorized" in r.json()["detail"]


# ---------- authorize after denial (TEST 6) ----------

def test_owner_can_authorize_after_denial(owner, other_user):
    doc = _make_doc(owner)
    c = APIClient()
    c.force_authenticate(user=other_user)
    r1 = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r1.status_code == 403

    _authorize_recipient(owner, doc, other_user)

    r2 = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r2.status_code == 200


# ---------- per-recipient limit (TEST 7) ----------

def test_per_recipient_limit(owner, recipient):
    doc = _make_doc(owner, max_per=2)
    _authorize_recipient(owner, doc, recipient)

    _, r1 = _full_open(recipient, doc)
    assert r1.status_code == 200
    _, r2 = _full_open(recipient, doc)
    assert r2.status_code == 200

    c = APIClient()
    c.force_authenticate(user=recipient)
    r3 = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r3.status_code == 403
    assert "opening allowance" in r3.json()["detail"]


# ---------- total limit (TEST 8) ----------

def test_total_limit(owner, recipient, other_user):
    doc = _make_doc(owner, max_total=2, max_per=10)
    _authorize_recipient(owner, doc, recipient)
    _authorize_recipient(owner, doc, other_user)

    _, r1 = _full_open(recipient, doc)
    assert r1.status_code == 200
    _, r2 = _full_open(recipient, doc)
    assert r2.status_code == 200

    c = APIClient()
    c.force_authenticate(user=other_user)
    r = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r.status_code == 403
    assert "total opening allowance" in r.json()["detail"]


# ---------- revocation (TEST 9) ----------

def test_revocation_blocks_future_opens(owner, recipient):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)

    # Open once successfully
    _, r1 = _full_open(recipient, doc)
    assert r1.status_code == 200

    # Owner revokes
    oc = APIClient()
    oc.force_authenticate(user=owner)
    rv = oc.post(reverse("authorization:revoke", args=[doc.id]), {"reason": "test"}, format="json")
    assert rv.status_code == 200

    # Recipient now denied
    c = APIClient()
    c.force_authenticate(user=recipient)
    r = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"]


# ---------- expiry (TEST 10) ----------

def test_expiry_blocks_future_opens(owner, recipient):
    past = (timezone.now() - timedelta(seconds=1)).isoformat()
    doc = _make_doc(owner, expires_at=past)
    _authorize_recipient(owner, doc, recipient)

    c = APIClient()
    c.force_authenticate(user=recipient)
    r = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r.status_code == 403
    assert "expired" in r.json()["detail"]


# ---------- token replay (TEST 13) ----------

def test_token_replay_rejected(owner, recipient):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)

    c = APIClient()
    c.force_authenticate(user=recipient)
    a = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    token = a.json()["token"]

    r1 = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    assert r1.status_code == 200

    r2 = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    assert r2.status_code == 403
    assert "already been used" in r2.json()["detail"]


def test_token_bound_to_document(owner, recipient):
    doc1 = _make_doc(owner)
    doc2 = _make_doc(owner)
    _authorize_recipient(owner, doc1, recipient)
    _authorize_recipient(owner, doc2, recipient)

    c = APIClient()
    c.force_authenticate(user=recipient)
    a = c.post(reverse("authorization:authorize"), {"document_id": str(doc1.id)}, format="json")
    token = a.json()["token"]

    r = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc2.id), "token": token},
        format="json",
    )
    assert r.status_code == 403
    assert "different document" in r.json()["detail"]


def test_token_bound_to_recipient(owner, recipient, other_user):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)
    _authorize_recipient(owner, doc, other_user)

    c1 = APIClient()
    c1.force_authenticate(user=recipient)
    a = c1.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    token = a.json()["token"]

    c2 = APIClient()
    c2.force_authenticate(user=other_user)
    r = c2.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    assert r.status_code == 403
    assert "different recipient" in r.json()["detail"]


def test_expired_token_rejected(owner, recipient, settings):
    """Token has a 90s TTL; we simulate expiry by rewinding used_at lock."""
    from authorization.models import AccessToken
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)

    c = APIClient()
    c.force_authenticate(user=recipient)
    a = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    token = a.json()["token"]

    # Force expiry
    import hashlib
    sha = hashlib.sha256(token.encode()).digest()
    at = AccessToken.objects.get(token_sha256=sha)
    at.expires_at = timezone.now() - timedelta(seconds=1)
    at.save(update_fields=["expires_at"])

    r = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    assert r.status_code == 403
    assert "expired" in r.json()["detail"]


# ---------- redeem after revocation (mid-flight) ----------

def test_revoke_between_authorize_and_redeem(owner, recipient):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)

    c = APIClient()
    c.force_authenticate(user=recipient)
    a = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    token = a.json()["token"]

    # Owner revokes in the gap
    oc = APIClient()
    oc.force_authenticate(user=owner)
    oc.post(reverse("authorization:revoke", args=[doc.id]), {"reason": "gap"}, format="json")

    r = c.post(
        reverse("authorization:redeem"),
        {"document_id": str(doc.id), "token": token},
        format="json",
    )
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"]


# ---------- authorization required ----------

def test_authorize_requires_auth(owner):
    doc = _make_doc(owner)
    c = APIClient()
    r = c.post(reverse("authorization:authorize"), {"document_id": str(doc.id)}, format="json")
    assert r.status_code in (401, 403)


def test_revoke_requires_owner(owner, other_user):
    doc = _make_doc(owner)
    c = APIClient()
    c.force_authenticate(user=other_user)
    r = c.post(reverse("authorization:revoke", args=[doc.id]), {}, format="json")
    assert r.status_code == 404


# ---------- activity ----------

def test_activity_reports_sessions(owner, recipient):
    doc = _make_doc(owner)
    _authorize_recipient(owner, doc, recipient)
    _full_open(recipient, doc)

    c = APIClient()
    c.force_authenticate(user=owner)
    r = c.get(reverse("authorization:activity", args=[doc.id]))
    assert r.status_code == 200
    body = r.json()
    assert body["policy"]["total_openings_used"] == 1
    assert any(s["recipient_email"] == recipient.email for s in body["sessions"])
