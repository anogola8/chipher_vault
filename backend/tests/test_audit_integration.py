"""
Integration tests: audit events land in the ledger from real API calls.

These complement the pure-primitive audit tests. They prove that when the
HTTP layer says a thing happened, the ledger says the same thing, in the
same order.
"""
import io

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import User
from audit.models import AuditEvent
from audit.verify import verify_chain


def _pdf():
    return b"%PDF-1.7\n" + b"BODY" * 32


@pytest.fixture
def owner(db):
    return User.objects.create_user("ao@example.com", "owner-strong-password-1")


@pytest.fixture
def recipient(db):
    return User.objects.create_user("ar@example.com", "recipient-strong-password-1")


@pytest.fixture
def clean_audit(db):
    AuditEvent.objects.all().delete()
    yield
    AuditEvent.objects.all().delete()


def _upload(client, title="Test"):
    payload = {
        "title": title,
        "file": io.BytesIO(_pdf()),
        "max_total_openings": 3,
        "max_openings_per_recipient": 2,
    }
    payload["file"].name = "t.pdf"
    r = client.post(reverse("documents:upload"), data=payload, format="multipart")
    assert r.status_code == 201, r.content
    return r.json()["id"]


def test_upload_records_audit(clean_audit, owner):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)

    events = list(AuditEvent.objects.order_by("seq"))
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == AuditEvent.EventType.DOC_UPLOADED
    assert str(ev.document_id) == doc_id
    assert ev.actor_id == owner.id
    assert verify_chain().ok


def test_recipient_add_records_audit(clean_audit, owner, recipient):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)
    c.post(
        reverse("documents:recipient_add", args=[doc_id]),
        {"email": recipient.email},
        format="json",
    )
    events = list(AuditEvent.objects.order_by("seq"))
    types = [e.event_type for e in events]
    assert AuditEvent.EventType.DOC_UPLOADED in types
    assert AuditEvent.EventType.RECIPIENT_ADDED in types
    assert verify_chain().ok


def test_authorize_fail_records_open_failed(clean_audit, owner, recipient):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)
    # recipient NOT authorized -> try to open
    rc = APIClient()
    rc.force_authenticate(user=recipient)
    r = rc.post(reverse("authorization:authorize"),
                {"document_id": doc_id}, format="json")
    assert r.status_code == 403

    events = list(AuditEvent.objects.order_by("seq"))
    open_failed = [e for e in events if e.event_type == AuditEvent.EventType.OPEN_FAILED]
    assert len(open_failed) == 1
    assert open_failed[0].metadata.get("phase") == "authorize"
    assert verify_chain().ok


def test_open_success_records_open(clean_audit, owner, recipient):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)
    c.post(reverse("documents:recipient_add", args=[doc_id]),
           {"email": recipient.email}, format="json")

    rc = APIClient()
    rc.force_authenticate(user=recipient)
    a = rc.post(reverse("authorization:authorize"), {"document_id": doc_id}, format="json")
    assert a.status_code == 200
    token = a.json()["token"]
    r = rc.post(reverse("authorization:redeem"),
                {"document_id": doc_id, "token": token}, format="json")
    assert r.status_code == 200

    types = [e.event_type for e in AuditEvent.objects.order_by("seq")]
    assert AuditEvent.EventType.OPEN_SUCCESS in types
    assert verify_chain().ok


def test_revoke_records_audit(clean_audit, owner):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)
    r = c.post(reverse("authorization:revoke", args=[doc_id]), {}, format="json")
    assert r.status_code == 200

    types = [e.event_type for e in AuditEvent.objects.order_by("seq")]
    assert AuditEvent.EventType.REVOKED in types
    assert verify_chain().ok


def test_ledger_remains_valid_after_full_flow(clean_audit, owner, recipient):
    c = APIClient()
    c.force_authenticate(user=owner)
    doc_id = _upload(c)
    c.post(reverse("documents:recipient_add", args=[doc_id]),
           {"email": recipient.email}, format="json")

    rc = APIClient()
    rc.force_authenticate(user=recipient)
    a = rc.post(reverse("authorization:authorize"), {"document_id": doc_id}, format="json")
    token = a.json()["token"]
    rc.post(reverse("authorization:redeem"),
            {"document_id": doc_id, "token": token}, format="json")

    c.post(reverse("authorization:revoke", args=[doc_id]), {}, format="json")

    final = verify_chain()
    assert final.ok, final.reason
    assert final.total >= 4
