"""
Audit ledger tests.

Covers prompt TEST 15: modified/reordered/deleted audit rows are detected.
"""
import uuid

import pytest
from django.db import connection

from audit.models import AuditEvent
from audit.service import record
from audit.verify import verify_chain


@pytest.fixture
def clean_audit(db):
    AuditEvent.objects.all().delete()
    yield
    AuditEvent.objects.all().delete()


def _record_n(n: int, event_type: str = AuditEvent.EventType.DOC_UPLOADED):
    for i in range(n):
        record(event_type, metadata={"i": i})


def test_empty_chain_is_valid(clean_audit):
    r = verify_chain()
    assert r.ok
    assert r.total == 0


def test_single_event_chain_valid(clean_audit):
    record(AuditEvent.EventType.DOC_UPLOADED, metadata={"a": 1})
    r = verify_chain()
    assert r.ok
    assert r.total == 1


def test_ten_events_chain_valid(clean_audit):
    _record_n(10)
    r = verify_chain()
    assert r.ok
    assert r.total == 10


def test_metadata_tamper_detected(clean_audit):
    _record_n(5)
    ev = AuditEvent.objects.order_by("seq")[2]
    ev.metadata = {"i": 999}
    ev.save(update_fields=["metadata"])

    r = verify_chain()
    assert not r.ok
    assert r.first_bad_seq == 3
    assert "current_hash" in r.reason


def test_hash_tamper_detected(clean_audit):
    _record_n(5)
    ev = AuditEvent.objects.order_by("seq")[1]
    bad = bytearray(bytes(ev.current_hash))
    bad[0] ^= 0xFF
    ev.current_hash = bytes(bad)
    ev.save(update_fields=["current_hash"])

    r = verify_chain()
    assert not r.ok
    assert r.first_bad_seq == 2


def test_missing_middle_row_detected(clean_audit):
    _record_n(5)
    AuditEvent.objects.filter(seq=3).delete()

    r = verify_chain()
    assert not r.ok
    assert r.first_bad_seq == 4


def test_reorder_detected(clean_audit):
    _record_n(3)
    with connection.cursor() as c:
        c.execute("UPDATE audit_auditevent SET seq = -1 WHERE seq = 1")
        c.execute("UPDATE audit_auditevent SET seq = 1 WHERE seq = 3")
        c.execute("UPDATE audit_auditevent SET seq = 3 WHERE seq = -1")

    r = verify_chain()
    assert not r.ok


def test_metadata_does_not_contain_secrets(clean_audit):
    ev = record(
        AuditEvent.EventType.OPEN_SUCCESS,
        document_id=uuid.uuid4(),
        actor_id=1,
        metadata={"reason": "ok"},
    )
    assert ev.metadata == {"reason": "ok"}


def test_sequential_events_have_increasing_seq(clean_audit):
    _record_n(4)
    seqs = list(AuditEvent.objects.order_by("seq").values_list("seq", flat=True))
    assert seqs == [1, 2, 3, 4]


def test_hash_chain_starts_from_zero(clean_audit):
    record(AuditEvent.EventType.DOC_UPLOADED)
    ev = AuditEvent.objects.get(seq=1)
    assert bytes(ev.previous_hash) == b"\x00" * 32


def test_hash_uses_canonical_metadata(clean_audit):
    record(AuditEvent.EventType.DOC_UPLOADED, metadata={"a": 1, "b": 2})
    ev = AuditEvent.objects.get(seq=1)
    ev.metadata = {"b": 2, "a": 1}
    ev.save(update_fields=["metadata"])
    r = verify_chain()
    assert r.ok
