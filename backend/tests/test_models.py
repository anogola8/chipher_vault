"""
Phase 4 model tests: schema, constraints, and cross-app relations.

No HTTP, no auth flows, no crypto here — those come in later phases.
"""
import uuid

import pytest
from django.db import IntegrityError

from accounts.models import User
from documents.models import Document, DocumentKey
from policies.models import DocumentPolicy, DocumentRecipient, RevocationRecord
from authorization.models import ViewingSession, AccessToken
from audit.models import AuditEvent


@pytest.fixture
def owner(db):
    return User.objects.create_user("owner@example.com", "correct-horse-battery")


@pytest.fixture
def recipient(db):
    return User.objects.create_user("recipient@example.com", "another-long-pass-1")


@pytest.fixture
def document(owner):
    return Document.objects.create(
        owner=owner,
        title="Test Doc",
        original_filename="test.pdf",
        original_size=1024,
        plaintext_sha256=b"\x00" * 32,
        storage_path="blobs/xx/xx/xx/test.cvault",
    )


@pytest.fixture
def policy(document):
    return DocumentPolicy.objects.create(
        document=document,
        policy_ref="pol-" + uuid.uuid4().hex[:8],
    )


def test_user_email_is_unique(db):
    User.objects.create_user("a@b.co", "long-enough-pw-1")
    with pytest.raises(IntegrityError):
        User.objects.create_user("a@b.co", "long-enough-pw-2")


def test_user_email_is_lowercased(owner):
    u = User.objects.create_user("MiXeD@Example.COM", "long-enough-pw-1")
    assert u.email == "mixed@example.com"


def test_document_key_is_one_to_one(document):
    DocumentKey.objects.create(
        document=document,
        dek_wrap_nonce=b"\x00" * 12,
        dek_wrapped=b"\x11" * 48,
        dek_salt=b"\x22" * 16,
    )
    with pytest.raises(IntegrityError):
        DocumentKey.objects.create(
            document=document,
            dek_wrap_nonce=b"\x00" * 12,
            dek_wrapped=b"\x11" * 48,
            dek_salt=b"\x22" * 16,
        )


def test_policy_ref_is_unique(document):
    DocumentPolicy.objects.create(document=document, policy_ref="dup-ref")
    doc2 = Document.objects.create(
        owner=document.owner,
        title="Doc2",
        original_filename="d2.pdf",
        original_size=1,
        plaintext_sha256=b"\x00" * 32,
        storage_path="blobs/d2.cvault",
    )
    with pytest.raises(IntegrityError):
        DocumentPolicy.objects.create(document=doc2, policy_ref="dup-ref")


def test_recipient_unique_per_document(document, recipient, owner):
    DocumentRecipient.objects.create(
        document=document, user=recipient, added_by=owner,
    )
    with pytest.raises(IntegrityError):
        DocumentRecipient.objects.create(
            document=document, user=recipient, added_by=owner,
        )


def test_policy_derived_status_active(policy):
    assert policy.derived_status() == DocumentPolicy.Status.ACTIVE


def test_policy_derived_status_exhausted(policy):
    policy.total_openings_used = policy.max_total_openings
    policy.save()
    assert policy.derived_status() == DocumentPolicy.Status.EXHAUSTED


def test_policy_derived_status_revoked(policy):
    policy.revoked = True
    policy.save()
    assert policy.derived_status() == DocumentPolicy.Status.REVOKED


def test_policy_derived_status_expired(policy):
    from django.utils import timezone
    from datetime import timedelta
    policy.expires_at = timezone.now() - timedelta(seconds=1)
    policy.save()
    assert policy.derived_status() == DocumentPolicy.Status.EXPIRED


def test_revocation_record_links(policy, owner):
    r = RevocationRecord.objects.create(
        document=policy.document, revoked_by=owner, reason="test",
    )
    assert r.document_id == policy.document_id


def test_viewing_session_and_token(policy, recipient):
    session = ViewingSession.objects.create(
        document=policy.document, recipient=recipient,
    )
    from django.utils import timezone
    from datetime import timedelta
    token = AccessToken.objects.create(
        session=session,
        token_sha256=b"\x33" * 32,
        expires_at=timezone.now() + timedelta(minutes=5),
    )
    assert token.is_live() is True
    token.used_at = timezone.now()
    token.save()
    assert token.is_live() is False


def test_audit_event_hashes_required(policy):
    ev = AuditEvent.objects.create(
        event_type=AuditEvent.EventType.DOC_UPLOADED,
        document_id=policy.document_id,
        actor_id=policy.document.owner_id,
        metadata={"title": "Test Doc"},
        previous_hash=b"\x00" * 32,
        current_hash=b"\x01" * 32,
    )
    assert ev.seq > 0
    assert ev.metadata["title"] == "Test Doc"


def test_user_string(owner):
    assert str(owner) == "owner@example.com"


def test_document_string(document):
    s = str(document)
    assert "Test Doc" in s and str(document.id) in s
